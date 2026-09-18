from email.message import EmailMessage

from scanner.config import ScanConfig
from scanner.detection import (
    analyze_urls,
    check_blocked_domain,
    check_email_auth,
    check_spoofed_sender,
    evaluate_message,
    normalize_text,
)


def make_msg(from_="sender@example.com", subject="Hello", body="hi there", extra_headers=None):
    msg = EmailMessage()
    msg["From"] = from_
    msg["Subject"] = subject
    msg.set_content(body)
    if extra_headers:
        for k, v in extra_headers.items():
            msg[k] = v
    return msg


def base_config(**overrides):
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", **overrides)
    return cfg


def test_spoofed_sender_detected():
    sig = check_spoofed_sender('"Me" <fake@evil.com>', ["me"], "me@yahoo.com")
    assert sig is not None
    assert sig.hard_match


def test_spoofed_sender_not_flagged_for_real_self():
    sig = check_spoofed_sender('"Me" <me@yahoo.com>', ["me"], "me@yahoo.com")
    assert sig is None


def test_blocked_domain_exact_and_subdomain():
    assert check_blocked_domain("x@spam.com", {"spam.com"}) is not None
    assert check_blocked_domain("x@mail.spam.com", {"spam.com"}) is not None
    assert check_blocked_domain("x@notspam.com", {"spam.com"}) is None


def test_auth_hard_fail_detected():
    msg = make_msg(extra_headers={"Authentication-Results": "dmarc=fail"})
    sig = check_email_auth(msg)
    assert sig is not None
    assert sig.name == "auth_hard_fail"


def test_auth_none_when_absent():
    msg = make_msg()
    assert check_email_auth(msg) is None


def test_normalize_text_strips_diacritics_and_collapses_ws():
    assert normalize_text("Café   Mööse") == "Cafe Moose"


def test_analyze_urls_blocked_domain_short_circuits():
    sig, suspicious = analyze_urls("visit http://evil.com/x", {"evil.com"}, set())
    assert sig.name == "blocked_url"
    assert sig.hard_match
    assert suspicious == []


def test_analyze_urls_safe_domain_not_suspicious():
    sig, suspicious = analyze_urls("see http://google.com/x", set(), {"google.com"})
    assert sig is None
    assert suspicious == []


def test_analyze_urls_unknown_domain_is_suspicious():
    sig, suspicious = analyze_urls("see http://random-site.xyz/x", set(), {"google.com"})
    assert sig is not None
    assert suspicious


def test_evaluate_message_clean():
    cfg = base_config()
    msg = make_msg(subject="Meeting notes", body="see you at 3pm")
    finding = evaluate_message(msg, "1", cfg)
    assert finding.verdict == "clean"


def test_evaluate_message_hard_match_blocked_domain_forces_spam():
    cfg = base_config(blocked_domains={"spammer.com"})
    msg = make_msg(from_="a@spammer.com", subject="hi", body="hi")
    finding = evaluate_message(msg, "2", cfg)
    assert finding.verdict == "spam"
    assert finding.matched_hard_rule == "blocked_domain"


def test_evaluate_message_empty_subject_contributes_but_not_hard():
    cfg = base_config(score_threshold=999)
    msg = make_msg(subject="", body="hi")
    finding = evaluate_message(msg, "3", cfg)
    assert finding.verdict == "clean"
    assert any(s.name == "empty_subject" for s in finding.signals)


def test_evaluate_message_keyword_threshold_crossed():
    cfg = base_config(spam_keywords=["free money"], score_threshold=10)
    msg = make_msg(subject="FREE MONEY now", body="hi")
    finding = evaluate_message(msg, "4", cfg)
    assert finding.verdict == "spam"
    assert finding.matched_hard_rule is None


def test_evaluate_message_never_marked_clean_when_vt_incomplete_and_no_other_signal():
    cfg = base_config(virustotal_enabled=True, vt_api_key="k", score_threshold=999)
    msg = make_msg(subject="hi", body="check http://unknown-domain.example/page")

    def vt_lookup(url):
        return "incomplete"

    finding = evaluate_message(msg, "5", cfg, vt_lookup=vt_lookup)
    assert finding.verdict == "incomplete"


def test_reply_to_mismatch_detected():
    from scanner.detection import check_reply_to_return_path

    msg = make_msg(from_="a@good.com", extra_headers={"Reply-To": "b@bad.com"})
    signals = check_reply_to_return_path(msg, "a@good.com")
    assert any(s.name == "reply_to_mismatch" for s in signals)
