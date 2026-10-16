"""Messages as the engine actually receives them: raw bytes parsed with
email.message_from_bytes (compat32), where RFC 2047 encoded-words in headers
are NOT decoded automatically and body parts may use a non-UTF-8 charset."""
import base64
import email

from scanner.config import ScanConfig
from scanner.detection import evaluate_message


def b64_word(text: str) -> str:
    return "=?UTF-8?B?" + base64.b64encode(text.encode("utf-8")).decode() + "?="


def parse(raw: bytes):
    return email.message_from_bytes(raw)


def cfg(**overrides):
    return ScanConfig(email="me@yahoo.com", app_password="x", **overrides)


def test_keyword_found_in_rfc2047_encoded_subject():
    raw = (f"From: shop@example.org\r\nSubject: {b64_word('Câștigă premiul acum!')}\r\n\r\nhello\r\n").encode()
    finding = evaluate_message(parse(raw), "1", cfg(spam_keywords=["premiul"]))
    assert finding.subject == "Câștigă premiul acum!"
    assert "keyword_subject" in [s.name for s in finding.signals]


def test_brand_name_detected_in_encoded_display_name():
    raw = (f"From: {b64_word('Amazon Support')} <x@evil-shop.biz>\r\nSubject: hi\r\n\r\nhello\r\n").encode()
    finding = evaluate_message(parse(raw), "1", cfg())
    assert "brand_name_mismatch" in [s.name for s in finding.signals]
    assert "Amazon Support" in finding.sender
    assert "x@evil-shop.biz" in finding.sender


def test_spoofed_own_name_detected_in_encoded_display_name():
    raw = (f"From: {b64_word('me (Yahoo)')} <x@evil.biz>\r\nSubject: hi\r\n\r\nhello\r\n").encode()
    finding = evaluate_message(parse(raw), "1", cfg(spoof_identifiers=["me"]))
    assert finding.matched_hard_rule == "spoofed_sender"


def test_encoded_display_name_cannot_smuggle_a_different_address():
    """A display name that DECODES to 'Name <someone@trusted.com>' must not
    replace the real address: blocking/whitelisting works on the address
    from the raw header."""
    raw = (f"From: {b64_word('PayPal <service@paypal.com>')} <x@blocked.com>\r\n"
           f"Subject: hi\r\n\r\nhello\r\n").encode()
    finding = evaluate_message(parse(raw), "1", cfg(blocked_domains={"blocked.com"}))
    assert finding.matched_hard_rule == "blocked_domain"
    assert finding.sender.endswith("<x@blocked.com>")


def test_body_keyword_found_in_non_utf8_charset():
    body = "Aţi câştigat un premiu".encode("iso-8859-2")
    raw = (b"From: shop@example.org\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: text/plain; charset=iso-8859-2\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body + b"\r\n")
    finding = evaluate_message(parse(raw), "1", cfg(spam_keywords=["castigat"]))
    assert "keyword_body" in [s.name for s in finding.signals]


def test_malformed_encoded_word_falls_back_to_raw_text():
    raw = b"From: a@b.com\r\nSubject: =?UTF-8?B?not-base64!!?=\r\n\r\nhello\r\n"
    finding = evaluate_message(parse(raw), "1", cfg())
    assert finding.verdict in ("clean", "spam")
    assert finding.subject


def test_unknown_charset_falls_back_without_crashing():
    raw = (b"From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain; charset=x-made-up\r\n\r\n"
           b"premiul\r\n")
    finding = evaluate_message(parse(raw), "1", cfg(spam_keywords=["premiul"]))
    assert "keyword_body" in [s.name for s in finding.signals]
