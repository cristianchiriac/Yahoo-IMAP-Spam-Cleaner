from email.message import EmailMessage

from scanner.config import ScanConfig
from scanner.detection import check_blocked_sender, evaluate_message


def make_msg(from_="sender@example.com", subject="hi", body="hi"):
    msg = EmailMessage()
    msg["From"] = from_
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def test_check_blocked_sender_hard_match():
    sig = check_blocked_sender("spammer@evil.com", {"spammer@evil.com"})
    assert sig is not None
    assert sig.hard_match


def test_check_blocked_sender_case_insensitive():
    sig = check_blocked_sender("Spammer@Evil.com", {"spammer@evil.com"})
    assert sig is not None


def test_check_blocked_sender_no_match():
    assert check_blocked_sender("friend@good.com", {"spammer@evil.com"}) is None


def test_evaluate_message_blocked_sender_forces_spam():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", blocked_senders={"spammer@evil.com"})
    finding = evaluate_message(make_msg(from_="spammer@evil.com"), "1", cfg)
    assert finding.verdict == "spam"
    assert finding.matched_hard_rule == "blocked_sender"
