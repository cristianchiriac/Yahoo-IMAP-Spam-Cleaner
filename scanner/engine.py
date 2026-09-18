"""Scan orchestration: ties IMAP client, checkpointing, and detection together."""
from __future__ import annotations

import email
import imaplib
import time
import uuid
from dataclasses import dataclass

from . import imap_client
from .backoff import compute_backoff_seconds
from .checkpoint import CheckpointStore
from .config import ScanConfig
from .detection import Finding, evaluate_message
from .vt import make_vt_lookup

# Transient errors a dropped/rate-limited IMAP connection surfaces as. Yahoo
# (and other providers) will actively close the connection ("Server logging
# out") if a session sends commands too quickly or for too long -- these are
# not fatal to the scan, they mean "reconnect and keep going".
_TRANSIENT_CONNECTION_ERRORS = (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError, ConnectionError)


class UidValidityChanged(Exception):
    """Raised when a reconnect discovers the folder's UIDVALIDITY changed
    mid-scan -- the remaining UIDs from the original listing can no longer be
    trusted, so the caller must stop and let the next run rescan safely."""


@dataclass
class ScanOutcome:
    scan_id: str
    findings: list[Finding]
    skipped: int
    incomplete_retried: int
    applied_moves: list[str]
    apply_errors: list[str]
    mail: object = None
    """The live IMAP connection at the end of the scan -- may differ from the
    one passed in if a mid-scan reconnect occurred. Callers scanning multiple
    folders in sequence, or logging out afterwards, must use this one rather
    than their original reference, which may now be a dead/closed socket."""


class _Connection:
    """Mutable holder so a reconnect inside a retry loop can swap out the
    live IMAP connection object without every caller needing to thread a new
    reference through."""

    def __init__(self, mail):
        self.mail = mail


def _reconnect_and_reselect(conn: _Connection, cfg: ScanConfig, folder: str, apply: bool,
                             expected_uidvalidity: int, log) -> None:
    log("Reconnecting to IMAP server...")
    conn.mail = imap_client.connect_imap(
        cfg.imap_server, cfg.email, cfg.app_password,
        retries=1, backoff_base=cfg.backoff_base_seconds, backoff_max=cfg.backoff_max_seconds,
    )
    info = imap_client.open_folder(conn.mail, folder, readonly=not apply)
    if info.uidvalidity != expected_uidvalidity:
        raise UidValidityChanged(
            f"UIDVALIDITY changed from {expected_uidvalidity} to {info.uidvalidity} after reconnect"
        )


def _call_with_reconnect(conn: _Connection, cfg: ScanConfig, folder: str, apply: bool,
                          uidvalidity: int, log, fn):
    """Runs fn(conn.mail), retrying with reconnect-and-reselect on a transient
    connection failure (e.g. the provider closing the session under rate
    pressure). Raises UidValidityChanged if a reconnect finds the folder was
    reset server-side; re-raises the last transient error if retries are
    exhausted."""
    last_exc: Exception | None = None
    for attempt in range(cfg.max_retries + 1):
        try:
            return fn(conn.mail)
        except _TRANSIENT_CONNECTION_ERRORS as exc:
            last_exc = exc
            if attempt >= cfg.max_retries:
                break
            delay = compute_backoff_seconds(attempt, cfg.backoff_base_seconds, cfg.backoff_max_seconds)
            log(f"⚠️ Connection issue ({exc}); reconnecting in {delay:.0f}s "
                f"(attempt {attempt + 1}/{cfg.max_retries})...")
            time.sleep(delay)
            _reconnect_and_reselect(conn, cfg, folder, apply, uidvalidity, log)
    raise last_exc


def _open_folder_with_retry(conn: _Connection, cfg: ScanConfig, folder: str, apply: bool, log):
    """Retries the initial folder open with reconnects. There's no prior
    UIDVALIDITY to compare against here (we're establishing it), so this is
    a simpler bounded retry than _call_with_reconnect."""
    last_exc: Exception | None = None
    for attempt in range(cfg.max_retries + 1):
        try:
            return imap_client.open_folder(conn.mail, folder, readonly=not apply)
        except _TRANSIENT_CONNECTION_ERRORS as exc:
            last_exc = exc
            if attempt >= cfg.max_retries:
                break
            delay = compute_backoff_seconds(attempt, cfg.backoff_base_seconds, cfg.backoff_max_seconds)
            log(f"⚠️ Could not open folder ({exc}); reconnecting in {delay:.0f}s "
                f"(attempt {attempt + 1}/{cfg.max_retries})...")
            time.sleep(delay)
            try:
                conn.mail = imap_client.connect_imap(
                    cfg.imap_server, cfg.email, cfg.app_password,
                    retries=1, backoff_base=cfg.backoff_base_seconds, backoff_max=cfg.backoff_max_seconds,
                )
            except Exception as reconnect_exc:  # noqa: BLE001
                last_exc = reconnect_exc
    raise last_exc


def scan_folder(
    mail,
    cfg: ScanConfig,
    folder: str,
    store: CheckpointStore,
    apply: bool = False,
    recheck: bool = False,
    only_spam: bool = False,
    scan_id: str | None = None,
    on_finding=None,
    on_log=None,
) -> ScanOutcome:
    """Scan one folder. `apply` gates whether MOVE actions are performed.
    Dry-run (apply=False) always opens the folder read-only (EXAMINE) and
    fetches via BODY.PEEK, guaranteeing no \\Seen flags are set and nothing
    is moved. `on_log(message)` is an optional callable for live progress
    lines (e.g. for a console/log UI); it never receives credentials or
    email bodies, only short status text.

    If the IMAP connection drops mid-scan (a common symptom of provider
    rate-limiting -- "Server logging out"), this reconnects and resumes from
    the current message rather than aborting the whole scan. If the folder's
    UIDVALIDITY changes across a reconnect, the remaining UIDs can no longer
    be trusted, so the scan stops early and returns what it found so far;
    the checkpoint store safely invalidates and rescans that folder next run."""
    scan_id = scan_id or str(uuid.uuid4())
    account = cfg.email
    conn = _Connection(mail)

    def log(message: str) -> None:
        if on_log:
            on_log(message)

    log(f"Opening folder '{folder}' ({'EXAMINE read-only' if not apply else 'SELECT (apply mode)'})...")
    folder_info = _open_folder_with_retry(conn, cfg, folder, apply, log)
    uidvalidity = folder_info.uidvalidity
    log(f"Folder opened. UIDVALIDITY={uidvalidity}")

    last_checkpoint = None if recheck else store.get_checkpoint(account, folder, uidvalidity)
    if last_checkpoint:
        log(f"Resuming from checkpoint after UID {last_checkpoint}")
    elif recheck:
        log("Rescanning from the start (--recheck / checkpoint ignored)")

    uids = imap_client.search_all_uids(conn.mail)
    if last_checkpoint:
        try:
            uids = [u for u in uids if int(u) > int(last_checkpoint)]
        except ValueError:
            pass
    log(f"{len(uids)} message(s) to evaluate in '{folder}'")

    vt_lookup = None
    if cfg.virustotal_enabled and cfg.vt_api_key:
        vt_lookup = make_vt_lookup(cfg.vt_api_key, cfg.vt_min_malicious_votes)
        log("VirusTotal enrichment is ENABLED — suspicious URLs may be sent to VirusTotal.")

    findings: list[Finding] = []
    skipped = 0
    incomplete_retried = 0
    applied_moves: list[str] = []
    apply_errors: list[str] = []

    move_supported = imap_client.supports_move(conn.mail) if apply else None
    if apply and not move_supported:
        msg_text = (
            "Server does not support UID MOVE; refusing to apply any changes for this folder "
            "(failing closed, no destructive fallback used)."
        )
        apply_errors.append(msg_text)
        log(f"⚠️ {msg_text}")

    connection_cycle_count = 0

    for idx, uid in enumerate(uids, start=1):
        # Provider rate-limit protection: no cap on how many messages are
        # scanned, but pace requests so large mailboxes don't trigger the
        # provider's own throttling/temporary-block thresholds. Periodically
        # cycling the connection (rather than just pausing on the same one)
        # avoids long-lived sessions that some providers kill outright.
        if cfg.request_delay_seconds > 0:
            time.sleep(cfg.request_delay_seconds)
        if cfg.pause_every_messages > 0 and idx > 1 and (idx - 1) % cfg.pause_every_messages == 0:
            log(f"Processed {idx - 1} messages -- pausing {cfg.pause_seconds:.0f}s and cycling the "
                f"connection to respect provider rate limits...")
            time.sleep(cfg.pause_seconds)
            connection_cycle_count += 1
            try:
                _reconnect_and_reselect(conn, cfg, folder, apply, uidvalidity, log)
            except UidValidityChanged as exc:
                log(f"⚠️ {exc}. Stopping this folder's scan early; it will be safely rescanned next run.")
                break
            except Exception as exc:  # noqa: BLE001
                log(f"⚠️ Proactive connection cycle failed ({exc}); continuing on the existing connection.")

        log(f"[{idx}/{len(uids)}] Fetching uid {uid} (BODY.PEEK, not marking as read)...")
        try:
            raw = _call_with_reconnect(
                conn, cfg, folder, apply, uidvalidity, log,
                lambda m, u=uid: imap_client.fetch_message_peek(m, u),
            )
        except UidValidityChanged as exc:
            log(f"⚠️ {exc}. Stopping this folder's scan early; it will be safely rescanned next run.")
            break
        except _TRANSIENT_CONNECTION_ERRORS as exc:
            skipped += 1
            log(f"[{idx}/{len(uids)}] uid {uid}: giving up after repeated connection failures ({exc}), skipping")
            continue

        if raw is None:
            skipped += 1
            log(f"[{idx}/{len(uids)}] uid {uid}: could not fetch, skipping")
            continue

        msg = email.message_from_bytes(raw)
        finding = evaluate_message(msg, uid, cfg, vt_lookup=vt_lookup)
        finding.folder = folder

        if finding.verdict == "incomplete":
            retries = store.increment_retry(account, folder, uidvalidity, uid)
            incomplete_retried += 1
            log(f"[{idx}/{len(uids)}] uid {uid}: INCOMPLETE (retry {retries}/{cfg.max_retries})")
            if retries < cfg.max_retries:
                store.save_checkpoint(account, folder, uidvalidity, uid)
                continue
            # Exceeded retry budget: permanently mark incomplete, move on.

        store.record_result(
            account, folder, uidvalidity, uid, finding.verdict, finding.score,
            subject=finding.subject, store_subject=cfg.store_subject_in_checkpoint,
        )
        store.save_checkpoint(account, folder, uidvalidity, uid)

        signal_names = ", ".join(s.name for s in finding.signals) or "none"
        log(f"[{idx}/{len(uids)}] uid {uid}: {finding.verdict.upper()} (score={finding.score}) "
            f"signals tried: {signal_names}")

        if not only_spam or finding.verdict == "spam":
            findings.append(finding)
            if on_finding:
                on_finding(finding)

        if apply and finding.verdict == "spam" and move_supported:
            try:
                _call_with_reconnect(
                    conn, cfg, folder, apply, uidvalidity, log,
                    lambda m, u=uid: imap_client.ensure_folder_exists(m, cfg.quarantine_folder) or
                    imap_client.apply_move(m, u, cfg.quarantine_folder),
                )
                applied_moves.append(uid)
                log(f"[{idx}/{len(uids)}] uid {uid}: moved to '{cfg.quarantine_folder}'")
            except UidValidityChanged as exc:
                log(f"⚠️ {exc}. Stopping this folder's scan early; it will be safely rescanned next run.")
                break
            except Exception as exc:  # noqa: BLE001
                apply_errors.append(f"uid {uid}: {exc}")
                log(f"[{idx}/{len(uids)}] uid {uid}: APPLY ERROR: {exc}")

    log(f"Done scanning '{folder}': {len(findings)} reported, {skipped} skipped, "
        f"{incomplete_retried} incomplete-retry event(s), {len(applied_moves)} moved, "
        f"{connection_cycle_count} connection cycle(s).")

    return ScanOutcome(
        scan_id=scan_id,
        findings=findings,
        skipped=skipped,
        incomplete_retried=incomplete_retried,
        applied_moves=applied_moves,
        apply_errors=apply_errors,
        mail=conn.mail,
    )
