"""Optional VirusTotal URL lookup. Disabled unless explicitly configured+enabled.

Never call anything here unless cfg.virustotal_enabled is True. A failed,
timed-out, or rate-limited lookup returns "incomplete" -- never "clean" --
so a message is never falsely cleared just because the API didn't answer.
"""
from __future__ import annotations

import base64

import requests

from .detection import Signal


def check_url_virustotal(url: str, api_key: str, min_malicious_votes: int = 2, timeout: float = 10.0):
    """Returns a Signal on a positive verdict, "incomplete" on any failure/
    ambiguous result, or None if the URL is clean."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(vt_url, headers=headers, timeout=timeout)
    except requests.RequestException:
        return "incomplete"

    if response.status_code == 429:
        return "incomplete"
    if response.status_code != 200:
        return "incomplete"

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError, TypeError):
        return "incomplete"

    total_bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
    if total_bad >= min_malicious_votes:
        return Signal("virustotal_malicious", 0, f"VirusTotal: {total_bad} engines flagged this URL", hard_match=True)
    return None


def make_vt_lookup(api_key: str, min_malicious_votes: int = 2):
    """Factory producing a `vt_lookup(url)` callable for detection.evaluate_message."""
    def _lookup(url: str):
        return check_url_virustotal(url, api_key, min_malicious_votes)
    return _lookup
