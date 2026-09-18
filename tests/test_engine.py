import email
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


def make_mail_mock(uids, raw_by_uid, uidvalidity=111, move_supported=False):
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("OK", [str(uidvalidity).encode()])
    mail.capability.return_value = ("OK", [b"MOVE"] if move_supported else [b"UIDPLUS"])

    def uid_side_effect(command, *args):
        if command == "SEARCH":
            return ("OK", [" ".join(uids).encode()])
        if command == "FETCH":
            u = args[0]
            raw = raw_by_uid.get(u)
            if raw is None:
                return ("OK", [])
            return ("OK", [(f"{u} (BODY.PEEK[] {{1}}".encode(), raw)])
        if command == "MOVE":
            return ("OK", [b"done"])
        return ("OK", [])

    mail.uid.side_effect = uid_side_effect
    return mail


def test_dry_run_never_calls_move_or_store(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0, blocked_domains={"blocked.com"})
    raw = make_raw_email()
    mail = make_mail_mock(["1"], {"1": raw})
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=False)

    assert outcome.findings[0].verdict == "spam"
    assert outcome.applied_moves == []
    # apply=False must never invoke UID MOVE.
    for call in mail.uid.call_args_list:
        assert call.args[0] != "MOVE"
    mail.select.assert_called_once_with('"INBOX"', readonly=True)
    store.close()


def test_apply_true_moves_detected_spam_to_configured_quarantine(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0, blocked_domains={"blocked.com"},
                      quarantine_folder="Scanner Quarantine")
    raw = make_raw_email()
    mail = make_mail_mock(["1"], {"1": raw}, move_supported=True)
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=True)

    assert outcome.applied_moves == ["1"]
    move_calls = [c for c in mail.uid.call_args_list if c.args[0] == "MOVE"]
    assert len(move_calls) == 1
    assert move_calls[0].args[2] == '"Scanner Quarantine"'
    mail.select.assert_any_call('"INBOX"', readonly=False)
    store.close()


def test_apply_true_fails_closed_when_move_unsupported(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0, blocked_domains={"blocked.com"})
    raw = make_raw_email()
    mail = make_mail_mock(["1"], {"1": raw}, move_supported=False)
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=True)

    assert outcome.applied_moves == []
    assert outcome.apply_errors  # should report the refusal
    for call in mail.uid.call_args_list:
        assert call.args[0] != "MOVE"
    mail.copy.assert_not_called()
    mail.expunge.assert_not_called()
    store.close()


def test_clean_message_not_moved_even_in_apply_mode(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0)
    raw = make_raw_email(from_="friend@safe.com", subject="lunch?", body="want to grab lunch?")
    mail = make_mail_mock(["1"], {"1": raw}, move_supported=True)
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=True)

    assert outcome.findings[0].verdict == "clean"
    assert outcome.applied_moves == []
    store.close()


def test_recheck_ignores_existing_checkpoint(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0)
    raw = make_raw_email(from_="friend@safe.com")
    mail = make_mail_mock(["1"], {"1": raw})
    store = CheckpointStore(tmp_path / "state.db")
    store.save_checkpoint("me@yahoo.com", "INBOX", 111, "1")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=False, recheck=True)
    assert len(outcome.findings) == 1
    store.close()


def test_on_log_receives_progress_lines(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0, blocked_domains={"blocked.com"})
    raw = make_raw_email()
    mail = make_mail_mock(["1"], {"1": raw})
    store = CheckpointStore(tmp_path / "state.db")
    logs = []

    scan_folder(mail, cfg, "INBOX", store, apply=False, on_log=logs.append)

    assert any("Opening folder" in line for line in logs)
    assert any("uid 1" in line and "SPAM" in line for line in logs)
    assert any("Done scanning" in line for line in logs)
    store.close()


def test_pause_every_messages_pauses_and_logs(tmp_path):
    """No cap on scan size, but for large mailboxes a periodic pause
    protects against provider-side rate limiting."""
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0,
                      pause_every_messages=2, pause_seconds=0.01)
    raw = make_raw_email(from_="friend@safe.com", subject="hi", body="hi")
    mail = make_mail_mock(["1", "2", "3"], {"1": raw, "2": raw, "3": raw})
    store = CheckpointStore(tmp_path / "state.db")
    logs = []

    with patch("scanner.engine.time.sleep") as mock_sleep:
        scan_folder(mail, cfg, "INBOX", store, apply=False, on_log=logs.append)

    assert any("pausing" in line for line in logs)
    # request_delay_seconds=0 means no per-message sleep(0) calls should have been made,
    # only the periodic pause_seconds sleep.
    mock_sleep.assert_any_call(0.01)
    store.close()


def test_no_pause_when_pause_every_messages_disabled(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0,
                      pause_every_messages=0)
    raw = make_raw_email(from_="friend@safe.com", subject="hi", body="hi")
    mail = make_mail_mock(["1", "2", "3"], {"1": raw, "2": raw, "3": raw})
    store = CheckpointStore(tmp_path / "state.db")
    logs = []

    scan_folder(mail, cfg, "INBOX", store, apply=False, on_log=logs.append)

    assert not any("pausing" in line for line in logs)
    store.close()


def test_only_spam_filters_clean_findings(tmp_path):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0, blocked_domains={"blocked.com"})
    raw_spam = make_raw_email(from_="a@blocked.com")
    raw_clean = make_raw_email(from_="b@safe.com", subject="hey", body="hey")
    mail = make_mail_mock(["1", "2"], {"1": raw_spam, "2": raw_clean})
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=False, only_spam=True)
    assert len(outcome.findings) == 1
    assert outcome.findings[0].verdict == "spam"
    store.close()
