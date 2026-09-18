from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from web.app import app, configure_security
from web.security import CSRF_TOKEN
from web.state import session_state

configure_security(8765)
client = TestClient(app, base_url="http://127.0.0.1:8765")
AUTH = {"X-CSRF-Token": CSRF_TOKEN}


def setup_function():
    client.post("/api/config", json={"email": "a@b.com", "app_password": "x"}, headers=AUTH)


def test_whitelist_domain_adds_to_safe_domains():
    resp = client.post("/api/config/whitelist-domain", json={"domain": "example.com"}, headers=AUTH)
    assert resp.status_code == 200
    assert "example.com" in resp.json()["safe_domains"]


def test_whitelist_domain_rejects_invalid_domain():
    resp = client.post("/api/config/whitelist-domain", json={"domain": "not a domain"}, headers=AUTH)
    assert resp.status_code == 400


def test_whitelist_domain_strips_at_sign():
    resp = client.post("/api/config/whitelist-domain", json={"domain": "@Example.COM"}, headers=AUTH)
    assert resp.status_code == 200
    assert "example.com" in resp.json()["safe_domains"]


def test_reset_analytics_requires_confirm():
    resp = client.post("/api/analytics/reset", json={"confirm": False}, headers=AUTH)
    assert resp.status_code == 400


def test_reset_analytics_clears_history_not_checkpoints():
    session_state.history.start_scan("s1", "INBOX", "dry-run")
    resp = client.post("/api/analytics/reset", json={"confirm": True}, headers=AUTH)
    assert resp.status_code == 200
    assert session_state.history.list_scans() == []


@patch("web.state.connect_imap")
def test_scan_all_folders_discovers_and_excludes_quarantine(mock_connect):
    from web import app as app_module

    mock_connect.return_value = MagicMock()
    with patch.object(session_state, "discover_folders", return_value=["INBOX", "Bulk Mail", "Scanner Quarantine"]):
        with patch.object(session_state, "start_scan", return_value="scan-123") as mock_start:
            resp = client.post(
                "/api/scans",
                json={"all_folders": True, "apply": False},
                headers=AUTH,
            )
    assert resp.status_code == 200
    assert resp.json()["folders"] == ["INBOX", "Bulk Mail"]
    mock_start.assert_called_once()
    assert mock_start.call_args.args[0] == ["INBOX", "Bulk Mail"]


def test_scan_requires_folder_or_all_folders():
    resp = client.post("/api/scans", json={"apply": False}, headers=AUTH)
    assert resp.status_code == 400
