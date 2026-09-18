"""Tests for mid-scan reconnect resilience: Yahoo (and other providers) can
actively close ('log out') an IMAP session under rate pressure. The scan
must reconnect and resume rather than crash the whole job."""
import email
import imaplib
from unittest.mock import MagicMock, patch

from scanner.checkpoint import CheckpointStore
from scanner.config import ScanConfig
from scanner.engine import scan_folder


def make_raw_email(from_="spammer@blocked.com", subject="hi", body="hi"):
    msg = email.message.EmailMessage()
    msg["From"] = from_
    msg["Subject"] = subject
    msg.set_content(body)
    return msg.as_bytes()


def make_mail(uidvalidity=111, move_supported=False, uid_side_effect=None):
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("OK", [str(uidvalidity).encode()])
    mail.capability.return_value = ("OK", [b"MOVE"] if move_supported else [b"UIDPLUS"])
    if uid_side_effect:
        mail.uid.side_effect = uid_side_effect
    return mail


def base_cfg(**overrides):
    return ScanConfig(
        email="me@yahoo.com", app_password="x", request_delay_seconds=0,
        backoff_base_seconds=0.001, backoff_max_seconds=0.01, max_retries=2,
        **overrides,
    )


def test_transient_fetch_failure_reconnects_and_resumes(tmp_path):
    """Simulates 'Server logging out' on the first FETCH: the scan must
    reconnect, re-select the folder, and keep processing (not crash)."""
    good_raw = make_raw_email(from_="friend@safe.com", subject="hi", body="hi")

    call_count = {"fetch": 0}

    def mail1_uid(command, *args):
        if command == "SEARCH":
            return ("OK", [b"1"])
        if command == "FETCH":
            call_count["fetch"] += 1
            raise imaplib.IMAP4.abort("Server logging out")
        return ("OK", [])

    mail1 = make_mail(uidvalidity=111, uid_side_effect=mail1_uid)

    def mail2_uid(command, *args):
        if command == "FETCH":
            u = args[0]
            return ("OK", [(f"{u} (BODY.PEEK[] {{1}}".encode(), good_raw)])
        return ("OK", [])

    mail2 = make_mail(uidvalidity=111, uid_side_effect=mail2_uid)

    cfg = base_cfg()
    store = CheckpointStore(tmp_path / "state.db")

    with patch("scanner.imap_client.connect_imap", return_value=mail2) as mock_connect:
        outcome = scan_folder(mail1, cfg, "INBOX", store, apply=False)

    assert mock_connect.called
    assert len(outcome.findings) == 1
    assert outcome.findings[0].verdict == "clean"
    assert outcome.mail is mail2
    store.close()


def test_uidvalidity_change_on_reconnect_stops_scan_safely(tmp_path):
    """If the folder's UIDVALIDITY changed by the time we reconnect, the
    remaining UIDs from the original listing can't be trusted -- the scan
    must stop cleanly instead of processing UIDs that may now mean something
    else entirely."""
    def mail1_uid(command, *args):
        if command == "SEARCH":
            return ("OK", [b"1 2"])
        if command == "FETCH":
            raise imaplib.IMAP4.abort("Server logging out")
        return ("OK", [])

    mail1 = make_mail(uidvalidity=111, uid_side_effect=mail1_uid)
    mail2 = make_mail(uidvalidity=222)  # different UIDVALIDITY after reconnect

    cfg = base_cfg()
    store = CheckpointStore(tmp_path / "state.db")

    logs = []
    with patch("scanner.imap_client.connect_imap", return_value=mail2):
        outcome = scan_folder(mail1, cfg, "INBOX", store, apply=False, on_log=logs.append)

    assert outcome.findings == []
    assert any("UIDVALIDITY changed" in line for line in logs)
    store.close()


def test_reconnect_exhausts_retries_and_skips_message(tmp_path):
    """If every reconnect attempt still fails to fetch, that single message
    is skipped (not the whole scan) once retries are exhausted."""
    def always_fails(command, *args):
        if command == "SEARCH":
            return ("OK", [b"1"])
        raise imaplib.IMAP4.abort("still down")

    mail1 = make_mail(uidvalidity=111, uid_side_effect=always_fails)
    cfg = ScanConfig(
        email="me@yahoo.com", app_password="x", request_delay_seconds=0,
        backoff_base_seconds=0.001, backoff_max_seconds=0.01, max_retries=1,
    )
    store = CheckpointStore(tmp_path / "state.db")

    with patch("scanner.imap_client.connect_imap", side_effect=lambda *a, **k: make_mail(
        uidvalidity=111, uid_side_effect=always_fails,
    )):
        outcome = scan_folder(mail1, cfg, "INBOX", store, apply=False)

    assert outcome.findings == []
    assert outcome.skipped == 1
    store.close()


def test_periodic_connection_cycling_replaces_connection(tmp_path):
    good_raw = make_raw_email(from_="friend@safe.com", subject="hi", body="hi")

    def uid_side_effect(command, *args):
        if command == "SEARCH":
            return ("OK", [b"1 2 3"])
        if command == "FETCH":
            u = args[0]
            return ("OK", [(f"{u} (BODY.PEEK[] {{1}}".encode(), good_raw)])
        return ("OK", [])

    mail1 = make_mail(uidvalidity=111, uid_side_effect=uid_side_effect)
    mail2 = make_mail(uidvalidity=111, uid_side_effect=uid_side_effect)

    cfg = base_cfg(pause_every_messages=1, pause_seconds=0)
    store = CheckpointStore(tmp_path / "state.db")

    with patch("scanner.imap_client.connect_imap", return_value=mail2) as mock_connect:
        outcome = scan_folder(mail1, cfg, "INBOX", store, apply=False)

    assert mock_connect.called
    assert len(outcome.findings) == 3
    store.close()
