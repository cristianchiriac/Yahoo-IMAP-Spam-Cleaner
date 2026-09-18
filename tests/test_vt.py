from unittest.mock import MagicMock, patch

from scanner.vt import check_url_virustotal, make_vt_lookup


def test_vt_disabled_by_default_config():
    from scanner.config import ScanConfig
    cfg = ScanConfig(email="a@b.com", app_password="x")
    assert cfg.virustotal_enabled is False


@patch("scanner.vt.requests.get")
def test_vt_timeout_returns_incomplete(mock_get):
    import requests
    mock_get.side_effect = requests.Timeout()
    result = check_url_virustotal("http://example.com", "key")
    assert result == "incomplete"


@patch("scanner.vt.requests.get")
def test_vt_rate_limited_returns_incomplete(mock_get):
    mock_get.return_value = MagicMock(status_code=429)
    result = check_url_virustotal("http://example.com", "key")
    assert result == "incomplete"


@patch("scanner.vt.requests.get")
def test_vt_malformed_response_returns_incomplete(mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {"unexpected": "shape"})
    result = check_url_virustotal("http://example.com", "key")
    assert result == "incomplete"


@patch("scanner.vt.requests.get")
def test_vt_malicious_verdict_is_hard_match(mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}
    })
    result = check_url_virustotal("http://example.com", "key", min_malicious_votes=2)
    assert result.name == "virustotal_malicious"
    assert result.hard_match


@patch("scanner.vt.requests.get")
def test_vt_below_threshold_is_clean_none(mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 1}}}
    })
    result = check_url_virustotal("http://example.com", "key", min_malicious_votes=2)
    assert result is None


def test_make_vt_lookup_factory():
    lookup = make_vt_lookup("key", 2)
    assert callable(lookup)
