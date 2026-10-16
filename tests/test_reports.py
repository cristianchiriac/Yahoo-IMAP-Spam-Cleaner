import re

from scanner.detection import Finding, Signal
from scanner.reports import build_html_report, build_report_data


def make_finding(subject="hi", sender="a@b.com", detail="x"):
    return Finding(
        uid="1", subject=subject, sender=sender, score=10, verdict="clean", matched_hard_rule=None,
        signals=[Signal("reply_to_mismatch", 20, detail)], folder="INBOX",
    )


def test_subject_cannot_close_the_embedded_script_block():
    """The report embeds findings as JSON inside a <script> block. json.dumps
    does not escape '</', so a subject containing '</script>' used to end the
    block early and let the rest of the subject run as a new script."""
    payload = "</script><script>window.PWNED=1</script>"
    html = build_html_report(build_report_data([make_finding(subject=payload)], "id", "dry-run", "INBOX"))
    assert html.count("<script>") == 1
    assert html.count("</script>") == 1
    assert "window.PWNED" in html  # still present as data, just not executable markup


def test_embedded_json_still_round_trips():
    import json
    data = build_report_data([make_finding(subject="</b> & <i>")], "id", "dry-run", "INBOX")
    html = build_html_report(data)
    embedded = re.search(r"const REPORT = (.*);\n", html).group(1)
    assert json.loads(embedded)["findings"][0]["subject"] == "</b> & <i>"


def test_folder_and_scan_id_are_html_escaped_in_static_markup():
    data = build_report_data([], "<b>id</b>", "dry-run", '<img src=x onerror="alert(1)">')
    html = build_html_report(data)
    assert "<img src=x" not in html
    assert "<b>id</b>" not in html
    assert "&lt;img src=x" in html


def test_dynamic_fields_are_rendered_through_the_escape_helper():
    """Signal details carry attacker-controlled header values (Reply-To,
    From, ...), so every finding field the template interpolates into
    innerHTML must go through esc()."""
    html = build_html_report(build_report_data([make_finding()], "id", "dry-run", "INBOX"))
    for field in ("s.detail", "s.name", "f.matched_hard_rule", "f.subject", "f.sender", "f.uid", "f.verdict"):
        assert re.search(r"esc\(\(?" + re.escape(field), html), f"{field} is not escaped"
