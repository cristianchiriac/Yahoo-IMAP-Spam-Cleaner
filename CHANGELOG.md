# Changelog

## Unreleased

### Security (script injection via email headers in the web UI and HTML report)
- HTML report: findings were embedded with `json.dumps` inside a `<script>` block, so a subject containing
  `</script>` closed it and ran the rest as script. `<` is now emitted as `\u003c`. All finding fields the
  report renders (`detail`, `name`, `matched_hard_rule`, subject, sender, ...) now go through an escape
  helper, and folder/scan id are HTML-escaped in the static markup.
- Web UI: the Whitelist / Block & delete buttons built `onclick="blockAndDelete(..., '<sender>')"` with
  HTML-entity escaping, which the browser decodes before running the handler, so a `'` in the From header
  broke out of the JS string. The buttons now carry only a numeric `data-i`, and one delegated listener
  looks the finding up. Verified in the browser: the old pattern executes an injected From header, the new
  one sends the exact sender to the API and runs nothing.
- New tests: `tests/test_reports.py`.

### Fixed (apply mode read and moved from the wrong mailbox)
`ensure_folder_exists` checked for the quarantine folder with `SELECT ... readonly=True`, which switched
the session's selected mailbox to the quarantine folder (or, when it was missing, left none selected).
The following `UID MOVE` then ran against the read-only quarantine folder, and later fetches read from it.
It now checks with `LIST` (no effect on the selected mailbox) and raises if `CREATE` fails. The scan
engine prepares the quarantine folder once per source folder instead of before every move. New stateful
IMAP fake in `tests/test_quarantine_mailbox_state.py` tracks the selected mailbox and read-only state,
which the previous `MagicMock`-based tests could not catch.

### Fixed (detection ignored RFC 2047-encoded headers and non-UTF-8 bodies)
Messages are parsed with the compat32 policy, which leaves `=?UTF-8?B?...?=` headers encoded, so keyword,
brand-name and spoofed-sender checks never matched a non-ASCII subject or display name. Subject and the
From display name are now decoded (`decode_header_value` / `normalize_from_header`); the address itself
is still taken from the raw header, so a display name that decodes to `Name <other@domain>` cannot
replace it. Body parts are decoded with their declared charset (e.g. iso-8859-2) with a UTF-8 fallback.
New tests: `tests/test_encoded_headers.py`.

### Added ("Don't show this again" for the permanent-delete confirmation)
Replaced the native `confirm()` dialog for "Block address/domain & delete" with a custom modal (styled to
match the app), since a browser-native confirm can't host a checkbox. It offers a "Don't show this again"
option; checking it and clicking "Delete permanently" stores a `localStorage` flag so future block-and-delete
actions skip straight to deleting without asking again. Clicking Cancel never sets the flag, even if the
checkbox is checked, so a cancelled action can't silently disable the warning. Verified end-to-end: modal
opens with clear irreversibility wording, Cancel leaves the flag unset, confirming with the box checked
persists it, and a subsequent call resolves immediately without showing the modal.

### Fixed ("Scan error: command: UID => IMAP4rev1 Server logging out" crashed the whole scan)
Root cause: `scan_folder` had no reconnect logic at all for the per-message loop. If the provider (commonly
Yahoo, under rate pressure) actively closed the IMAP session mid-scan, the exception propagated uncaught and
killed the entire job, even though the checkpoint store already had everything needed to resume safely.
- Added reconnect-with-backoff around every IMAP operation in the scan loop (initial folder open, each
  message fetch, each apply-mode move). On a transient connection failure (`IMAP4.abort`, `IMAP4.error`,
  `OSError`), it waits with exponential backoff, reconnects, re-selects the folder, and resumes from the
  current message -- it does not restart the whole folder.
- If a reconnect discovers the folder's `UIDVALIDITY` changed, the remaining UIDs from the original listing
  can no longer be trusted, so the scan stops cleanly there and returns what it found; the checkpoint store's
  existing UIDVALIDITY-based invalidation safely rescans that folder from scratch on the next run.
- Added **proactive connection cycling**: at each `pause_every_messages` interval, the connection is now
  closed and reopened (not just paused on the same socket), which avoids the long-lived-session pattern that
  triggers many providers' "log out this session" behavior in the first place, rather than only reacting to
  it after the fact.
- If a single message's fetch/move still fails after exhausting retries, only that message is skipped (not
  the whole scan).
- `scan_folder` now returns the live connection it ended with (which may differ from the one passed in, if a
  reconnect occurred); CLI and web callers use it for subsequent folders and final logout instead of a
  potentially dead reference.
- 4 new tests simulating a dropped connection mid-fetch, a UIDVALIDITY change on reconnect, exhausted
  retries, and proactive connection cycling.

### Added (block sender/domain — with an explicit, scoped exception to "never delete")
The scanner's default behavior everywhere (dry-run, normal `--apply`) remains exactly as before: detected
spam is moved to the quarantine folder via `UID MOVE`, never deleted. Per explicit user request, a new,
separate, opt-in action was added for the one case where permanent removal was specifically wanted:
- New "Block address & delete" / "Block domain & delete" buttons on each finding. These (1) add the sender's
  exact address or domain to a new `blocked_senders`/`blocked_domains` list so future scans hard-match it as
  spam, and (2) **permanently delete only that one message** right now.
- Deletion uses `UID STORE +Deleted` followed by a **targeted `UID EXPUNGE` naming only that UID** (RFC 4315
  UIDPLUS) -- never a blanket `EXPUNGE`, which could also permanently remove other unrelated messages already
  flagged `\Deleted` for any reason. If the server doesn't support UIDPLUS, this fails closed
  (`PermanentDeleteNotSupported`) with no fallback, same fail-closed philosophy as `apply_move`.
- Requires `confirm_delete: true` from an explicit, clearly-worded confirmation dialog stating the action is
  irreversible and is not a quarantine move. There is no way to trigger this accidentally from a normal scan.
- New `blocked_sender` hard-match detection signal (exact address, case-insensitive) alongside the existing
  `blocked_domain` one.
- 14 new tests (signal detection, endpoint confirmation gating, fail-closed UIDPLUS behavior, targeted vs.
  blanket expunge).

### Fixed (analytics dashboard required a manual refresh to reflect an in-progress scan)
Findings were written to the local history DB live (via the `on_finding` callback in `web/state.py`), so
`/api/analytics` always reflected the latest data — but the frontend only ever called `loadDashboard()` when
the scan finished or failed, not while it was running. The dashboard now polls `/api/analytics` every 2s
while a scan is active (only when there's actually new data since the last poll), stops polling as soon as
the scan ends, and still does one final refresh on completion/error. Verified end-to-end with a simulated
SSE stream: the dashboard updates automatically after the first finding arrives, well before the scan
finishes.

### Added (multi-folder scans, whitelisting, pagination, provider rate-limit safety)
- **Scan all folders in one run**: new "Scan all folders" toggle in the web UI (and `--all-folders` on the
  CLI) discovers every folder on the account and scans them all in a single job/report, automatically
  excluding the configured quarantine folder as a source. `POST /api/scans` now accepts `all_folders: true`
  in place of a single `folder`.
- **Quick domain whitelisting**: each finding card now has a "Whitelist &lt;domain&gt;" button that adds the
  sender's domain to `safe_domains` for the current session via `POST /api/config/whitelist-domain`, without
  needing to resubmit credentials or the full config form. `safe_domains` was already configurable; this just
  makes it a one-click action from a finding instead of hand-editing the advanced-settings textarea.
- **Reset analytics to zero**: dedicated "Reset to zero" button in the Analytics panel (`POST
  /api/analytics/reset`, requires `confirm: true`). Functionally the same underlying action as clearing scan
  history (analytics are computed from it) but framed as its own explicit control since that's how the
  dashboard presents it. Never touches IMAP resume checkpoints.
- **Findings pagination**: the findings list now paginates at 25 per page instead of rendering an
  ever-growing single list that forces continuous scrolling on large scans.
- **No artificial scan-size limit** (confirmed/documented — this was already true, `scan_folder` never sliced
  the UID list) **plus provider rate-limit protection**: added a configurable small per-message delay
  (`request_delay_seconds`, default 0.2s) and a periodic longer pause (`pause_every_messages` /
  `pause_seconds`, default: 30s every 200 messages) so scanning a very large mailbox doesn't trigger Yahoo's
  (or another provider's) own throttling/temporary account block. All configurable via `config.example.json`
  or the web UI.
- 19 new tests covering multi-folder job orchestration, the new endpoints, and rate-limit pacing.

### Fixed (folder names with spaces were silently unusable, e.g. Yahoo's "Bulk Mail")
Root cause of "the scanner can't find my spam folder": `imaplib` does **not** quote mailbox names for you --
it sends them as a bare IMAP atom. Any mailbox name containing a space (Yahoo's classic spam folder,
literally named `Bulk Mail`; the configured quarantine folder `Scanner Quarantine`) produced an invalid
`SELECT`/`CREATE`/`MOVE` command that most servers reject, even though folder *discovery* correctly listed
the name.
- Added `_quote_mailbox()` and applied it everywhere a folder name is sent as a command argument:
  `open_folder` (SELECT/EXAMINE), `ensure_folder_exists` (SELECT + CREATE), `apply_move` (UID MOVE
  destination). This means the "Scanner Quarantine" apply-mode destination itself was very likely also
  silently failing for any account whose quarantine folder name contains a space.
- `list_folders` previously parsed the IMAP `LIST` response by splitting on a hardcoded `' "/" '` delimiter
  string. Rewrote it to parse the actual `(flags) "delimiter" name` grammar (RFC 3501), so a server using a
  different hierarchy separator (or `NIL`) no longer has every one of its folders silently dropped from
  discovery.
- 8 new tests covering folder-name quoting (`open_folder`, `ensure_folder_exists`, `apply_move`) and
  delimiter-agnostic `list_folders` parsing.

### Fixed (detection accuracy, from real spam samples)
User-supplied real Yahoo spam samples showed the detection engine was both missing real phishing and
drowning in false positives from its own signals. Root causes and fixes:
- **`return_path_mismatch` / `reply_to_mismatch` false-positived on ~80% of all mail.** The check used strict
  string inequality between domains, so any legitimate ESP bounce subdomain (e.g.
  `bounce.email.example.com` vs `From: @example.com`) was flagged as a "mismatch" even though that's normal
  VERP bounce routing. Fixed to use subdomain-aware comparison (`_domains_related`) — only flags domains that
  share no common root at all.
- **`suspicious_url` flagged nearly every email (445/449 in the user's sample)** because it treated any link
  not on the global `safe_domains` list as suspicious, including links back to the sender's own domain (which
  every legitimate newsletter has). Now excludes URLs whose domain is related to the sending domain, and its
  weight was reduced (15→10) since it remains a weak, supporting signal.
- **No detection at all for brand impersonation via Return-Path/Reply-To.** A real sample had
  `Return-Path: <contact@amazon.com>` with `SPF fail` while the message actually came from (and was
  DKIM/DMARC-valid for) an unrelated domain — a classic scam pattern the engine didn't recognize. Added
  `check_brand_impersonation` (new hard-match signal `brand_impersonation`) against a configurable
  `protected_brand_domains` list (defaults to a small set of commonly-impersonated domains: Amazon, PayPal,
  major banks, USPS/FedEx/UPS, etc. — exposed in the web UI's advanced settings).
- **No detection for brand names mentioned in content without forged headers** — increasingly common in 2026:
  attackers use entirely legitimate ESP infrastructure (their own domain, valid SPF/DKIM/DMARC) and simply
  name a trusted brand in the display name or subject. Added `check_brand_name_mismatch` (scored, not hard —
  legitimate resellers can mention a brand).
- **No detection for auto-generated gibberish sender local-parts** (e.g.
  `ThermalConductivityGasDetectorWheatstoneBridge@...`, `XenolithsHideInGnaniteSlabs@...`) — a strong tell for
  bulk-spam infrastructure. Added `check_gibberish_localpart`.
- **No detection for subject whitespace obfuscation** (e.g. `Drive      &       Save            Up   To  50%`),
  a filter-evasion technique. Added `check_subject_obfuscation`.
- **`check_email_auth` missed the common bare-value `Received-SPF` format** (`none (domain of ... does not
  designate ...)` with no `spf:` label), silently failing to score `auth_missing`/`auth_soft_fail` for
  providers that only set this header without `Authentication-Results`. Fixed to recognize the bare result
  word at the start of the header value too.
- Malformed `Reply-To` headers with a bare domain and no `@`/angle brackets (seen in a real sample,
  `Reply-To: mmiandassociates.com`) are now parsed correctly instead of being silently ignored.
- Rebalanced score weights so these signals combine to cross the default threshold (60) on real spam without
  needing any hard match: `auth_missing` 10→15, `gibberish_localpart` 25→40 (new), `subject_obfuscation` 30
  (new), `brand_name_mismatch` 30 (new), `suspicious_url` 15→10.
- Web UI: "Only show flagged messages" now defaults to on, so the findings list shows malicious messages by
  default rather than clean mail mixed in.
- 9 new regression tests built directly from the reported real spam samples (`tests/test_real_spam_samples.py`).

### Changed (UI refresh)
- Replaced `web/static/index.html` with a redesigned frontend (sidebar navigation, readiness checklist,
  advanced detection settings exposed in the UI — score threshold, blocked/safe domains, keywords, regex
  rules, spoof identifiers —, findings search/filter, scan history list, toast notifications). No backend
  changes were needed: it targets the exact same API surface already in place (`/api/config`,
  `/api/test-connection`, `/api/folders`, `/api/scans`, SSE `status`/`log`/`finding`/`done`/`scanerror`
  events, `/api/analytics`, `/api/history`, `/api/checkpoints/reset`).
- Verified live in-browser against real Yahoo IMAP (invalid test credentials): config save, dry-run scan
  start/stop UI state, live console streaming, and the real authentication-failure message surfacing
  correctly end-to-end.
- Fixed one small gap found during that verification: the analytics dashboard only auto-refreshed after a
  successful scan, not after a failed one; it now refreshes on both `done` and `scanerror`.

### Fixed (P0 safety)
- Dry-run is now the default; only `--apply` (with confirmation) can modify a mailbox.
- Scanning now uses `EXAMINE` + `BODY.PEEK[]` instead of `SELECT` + `FETCH RFC822`, so messages are never
  marked `\Seen` just by being scanned.
- Replaced the destructive `COPY` → `STORE \Deleted` → `EXPUNGE` quarantine path (which risked permanently
  deleting other flagged messages via `EXPUNGE`) with server-side `UID MOVE` to a dedicated
  `Scanner Quarantine` folder. If `MOVE` isn't supported, apply now fails closed instead of falling back to
  a destructive alternative.
- Removed hardcoded credential placeholders from source; `EMAIL`/`APP_PASSWORD`/`IMAP_SERVER`/`VT_API_KEY`
  are now loaded from environment variables and/or a config file (env takes precedence).
- VirusTotal is now opt-in (`virustotal_enabled: true` + API key required); previously it ran whenever a key
  was set. Failed/timed-out/rate-limited VT lookups are now marked "incomplete" instead of silently passing
  as clean.
- Fixed docs claiming "exponential backoff" when the previous implementation was linear; backoff is now
  genuinely exponential (`base * 2**attempt`, capped).

### Added
- Restructured into a reusable `scanner/` package (`config`, `detection`, `checkpoint`, `imap_client`, `vt`,
  `reports`, `engine`) with `spam_filter.py` as a thin CLI entrypoint, so a future web backend can import the
  same engine.
- Explainable, layered scoring: every finding lists the named signals that contributed and their weights,
  plus a distinct "hard match" path for high-confidence rules (blocked domain, spoofing, blocked/malicious
  URL) that bypasses the score threshold.
- SQLite-backed resumable checkpoints, namespaced by (account, folder, UIDVALIDITY), auto-invalidated on
  UIDVALIDITY change. Bounded retry counting for "incomplete" results to avoid endless rescan loops.
- CLI flags: `--config`, `--apply`, `--yes`, `--recheck`, `--only-spam`, `--json-report`, `--html-report`,
  `--list-folders`, `--folders`.
- JSON and self-contained HTML reports generated from a single shared data structure.
- 55 pytest tests covering scoring, spoof detection, URL parsing, config validation, checkpoint/resume,
  dry-run guarantees, UID MOVE success/fail-closed behavior, and VirusTotal disabled/failure handling. All
  IMAP/network calls are mocked.
- `config.example.json`, updated `.gitignore` (`state.db`, `config.local.json`, `reports/`, etc).

### Added (Phase 2 — local web app)
- FastAPI backend (`web/app.py`) served entirely from `127.0.0.1:8765` via `python run_web.py`; binds
  localhost only, never `0.0.0.0`.
- Frontend is a self-contained vanilla-JS page served by FastAPI itself (deliberate deviation from the
  originally discussed React stack, to avoid a separate build toolchain/dev server for a single-user local
  app); covers onboarding, connection testing, folder discovery, scan start, live progress, findings review,
  dry-run/apply, and reports/retention controls end-to-end.
- Live scan progress via Server-Sent Events, using one `scan_id` shared consistently across the engine,
  backend, event stream, history DB, and frontend.
- Credentials submitted through the web UI are held only in an in-memory session object for the running
  process — never persisted to the history database or any file, never echoed back by any API response.
- Apply mode requires an explicit `confirm_apply: true` from the frontend's confirmation dialog before the
  backend will start a mutating scan; the quarantine folder name comes from the single shared `ScanConfig`,
  so the UI and engine can never disagree about the destination.
- Localhost hardening middleware: rejects requests with an unrecognized `Host` header, rejects state-changing
  requests with a mismatched `Origin`, and requires a per-process CSRF token on all mutating API calls.
- Separate `scan_history.db` (scan/report history) from `state.db` (IMAP resume checkpoints): `DELETE
  /api/history` never touches checkpoints; `POST /api/checkpoints/reset` is a distinct, explicit action.
- 10 additional tests covering CSRF/Host/Origin enforcement and history/checkpoint separation (65 total).
- Manually verified in a real browser against live Yahoo IMAP (invalid test credentials): config save stays
  in-memory, connection-test failure is reported cleanly without crashing, and the CSRF/localhost checks hold.

### Added (live console + analytics dashboard)
- `scanner.engine.scan_folder` now takes an `on_log(message)` callback emitting granular, non-sensitive
  progress lines (folder opened/UIDVALIDITY, checkpoint resume, per-message fetch/verdict/signals-tried,
  apply/move results, end-of-folder summary). The CLI exposes this via `--verbose`; the web app streams it
  live over SSE into a terminal-style "Live console" panel during a scan.
- New `/api/analytics` endpoint + `HistoryStore.get_analytics()`: verdict breakdown, most-triggered signals,
  top flagged sender domains, score distribution, and total scan count, all aggregated from local scan
  history (read-only, no effect on checkpoints). Rendered as a dependency-free CSS bar-chart dashboard.
- Fixed a real bug found while manually verifying this in the browser: the app-level `error` SSE event name
  collided with `EventSource`'s built-in connection-error event, so a real scan failure only ever surfaced as
  a generic "Scan error." in the UI. Renamed the application event to `scanerror`; the console and status
  line now show the actual failure message.
- 6 new tests for analytics aggregation, 1 new test asserting `on_log` progress lines are emitted correctly.

### Not yet implemented (tracked for a later phase)
- Packaging (PyInstaller/.exe/installer).
- A dedicated React frontend, if still desired over the current vanilla-JS page.
