"""Regression tests built from real spam samples that previously slipped
through undetected (reported by the user). These pin the fixes for:
- return_path/reply_to mismatch false-positiving on legitimate ESP bounce
  subdomains (was flagging ~80% of all mail regardless of maliciousness)
- suspicious_url flagging links to the sender's own domain
- no detection at all for brand-impersonation via Return-Path/Reply-To
- no detection for auto-generated gibberish sender local-parts
- no detection for subject whitespace obfuscation
"""
import email

from scanner.config import ScanConfig
from scanner.detection import evaluate_message


def parse(raw: str):
    return email.message_from_string(raw)


def test_esp_bounce_subdomain_is_not_a_return_path_mismatch():
    """bounce.email.mmiandassociates.com vs From @mmiandassociates.com is
    normal VERP bounce routing for a legitimate ESP, not a red flag."""
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "Return-Path: <bounce-xyz@bounce.email.mmiandassociates.com>\n"
        "From: Legit Sender <hello@mmiandassociates.com>\n"
        "Reply-To: hello@mmiandassociates.com\n"
        "Subject: Newsletter\n"
        "Content-Type: text/plain\n\n"
        "Hi there, check out https://mmiandassociates.com/offer\n"
    )
    finding = evaluate_message(parse(raw), "1", cfg)
    signal_names = [s.name for s in finding.signals]
    assert "return_path_mismatch" not in signal_names
    assert "reply_to_mismatch" not in signal_names


def test_amazon_return_path_impersonation_is_hard_match_spam():
    """Real sample: Return-Path claims contact@amazon.com, SPF fails for
    amazon.com, but the message actually comes from (and is DKIM/DMARC
    valid for) an unrelated domain -- classic brand-impersonation scam."""
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "Return-Path: <contact@amazon.com>\n"
        "Received-SPF: fail (domain of amazon.com does not designate 52.13.210.174 as permitted sender)\n"
        "Authentication-Results: mta.yahoo.com; dkim=pass header.i=@mmiandassociates.com; "
        "spf=fail smtp.mailfrom=amazon.com; dmarc=pass(p=REJECT) header.from=mmiandassociates.com;\n"
        'From: "Auto - Insurance" <XenolithsHideInGnaniteSlabs@mmiandassociates.com>\n'
        "Reply-To: mmiandassociates.com\n"
        "Subject: Drivers Save   An  Average    Of  $134/Month* After Switching\n"
        "Content-Type: text/plain\n\n"
        "Get a quote today.\n"
    )
    finding = evaluate_message(parse(raw), "2", cfg)
    assert finding.verdict == "spam"
    assert finding.matched_hard_rule == "brand_impersonation"


def test_gibberish_localpart_detected():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: AspireRewards <ThermalConductivityGasDetectorWheatstoneBridge@goldencopyreader.com>\n"
        "Return-Path: <bounce+abc@mg-d0.goldencopyreader.com>\n"
        "Reply-To: <ThermalConductivityGasDetectorWheatstoneBridge@goldencopyreader.com>\n"
        "Received-SPF: none (domain of mg-d0.goldencopyreader.com does not designate permitted sender hosts)\n"
        "Subject: Up to a $1,000 Credit Limit. Up to 3% Cash Back Rewards.\n"
        "Content-Type: text/html\n\n"
        '<a href="https://www.martialartsacademymba.info/abc">click</a>'
        '<a href="https://www.martialartsacademymba.info/def">click2</a>\n'
    )
    finding = evaluate_message(parse(raw), "3", cfg)
    signal_names = [s.name for s in finding.signals]
    assert "gibberish_localpart" in signal_names
    assert "suspicious_url" in signal_names
    # No mismatch false-positive: Return-Path/Reply-To share the same root domain as From.
    assert "return_path_mismatch" not in signal_names
    assert "reply_to_mismatch" not in signal_names
    assert finding.verdict == "spam"


def test_subject_obfuscation_detected():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: sender@example.com\n"
        "Subject: Drive      &       Save            Up             To             50%\n"
        "Content-Type: text/plain\n\n"
        "body\n"
    )
    finding = evaluate_message(parse(raw), "4", cfg)
    assert any(s.name == "subject_obfuscation" for s in finding.signals)


def test_suspicious_url_excludes_senders_own_domain():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: sender@example.com\n"
        "Subject: hi\n"
        "Content-Type: text/plain\n\n"
        "Visit https://example.com/promo and https://sub.example.com/x\n"
    )
    finding = evaluate_message(parse(raw), "5", cfg)
    assert not any(s.name == "suspicious_url" for s in finding.signals)


def test_suspicious_url_still_flags_unrelated_domain():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: sender@example.com\n"
        "Subject: hi\n"
        "Content-Type: text/plain\n\n"
        "Visit https://totally-unrelated-domain.info/x\n"
    )
    finding = evaluate_message(parse(raw), "6", cfg)
    assert any(s.name == "suspicious_url" for s in finding.signals)


def test_brand_name_mentioned_with_unrelated_sending_domain():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: Microsoft Support <support@totally-unrelated.example>\n"
        "Subject: Your Microsoft account needs verification\n"
        "Content-Type: text/plain\n\n"
        "body\n"
    )
    finding = evaluate_message(parse(raw), "7", cfg)
    assert any(s.name == "brand_name_mismatch" for s in finding.signals)


def test_third_real_sample_auto_insurance_combo_scores_as_spam():
    """Real sample: SPF none, malformed bare-domain Reply-To (related to
    From, so no false mismatch), gibberish local-part, and whitespace-
    obfuscated subject -- none individually a hard match, but together
    they should cross the score threshold."""
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "Return-Path: <bounce-xyz@bounce.email.mmiandassociates.com>\n"
        "Received-SPF: none (domain of bounce.email.mmiandassociates.com does not designate permitted sender hosts)\n"
        'From: Your Auto   Quote    Team <SponesGenminateNeanMoistSunfaces@mmiandassociates.com>\n'
        "Reply-To: mmiandassociates.com\n"
        "Subject: Drivers Save   An  Average    Of  $134/Month* After Switching\n"
        "Content-Type: text/plain\n\n"
        "Get a quote today.\n"
    )
    finding = evaluate_message(parse(raw), "9", cfg)
    signal_names = [s.name for s in finding.signals]
    assert "return_path_mismatch" not in signal_names
    assert "reply_to_mismatch" not in signal_names
    assert "gibberish_localpart" in signal_names
    assert "subject_obfuscation" in signal_names
    assert finding.verdict == "spam"


def test_legit_brand_domain_not_flagged_for_its_own_name():
    cfg = ScanConfig(email="me@yahoo.com", app_password="x")
    raw = (
        "From: Amazon <ship-confirm@amazon.com>\n"
        "Subject: Your Amazon order has shipped\n"
        "Content-Type: text/plain\n\n"
        "body\n"
    )
    finding = evaluate_message(parse(raw), "8", cfg)
    assert not any(s.name == "brand_name_mismatch" for s in finding.signals)
    assert not any(s.name == "brand_impersonation" for s in finding.signals)
