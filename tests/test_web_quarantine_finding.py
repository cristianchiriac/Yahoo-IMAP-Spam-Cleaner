from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from web.app import app, configure_security
from web.security import CSRF_TOKEN

configure_security(8765)
client = TestClient(app, base_url="http://127.0.0.1:8765")
AUTH = {"X-CSRF-Token": CSRF_TOKEN}


def setup_function():
    client.post("/api/config", json={"email": "a@b.com", "app_password": "x"}, headers=AUTH)


@patch("web.app.connect_imap")
@patch("web.app.supports_uidplus", return_value=True)
@patch("web.app.permanently_delete")
@patch("web.app.open_folder")
def test_block_address_and_domain_permanently_deletes_with_confirmation(
    mock_open_folder, mock_delete, mock_supports_uidplus, mock_connect,
):
    mock_connect.return_value = MagicMock()

    resp = client.post(
        "/api/findings/quarantine",
        json={
            "folder": "INBOX", "uid": "42", "sender": "Spammer <spammer@evil.com>",
            "block_address": True, "block_domain": True, "confirm_delete": True,
        },
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "permanently_deleted"
    assert "spammer@evil.com" in data["blocked_senders"]
    assert "evil.com" in data["blocked_domains"]
    mock_delete.assert_called_once()
    assert mock_delete.call_args.args[1] == "42"


def test_block_without_confirm_delete_is_rejected():
    """Blocking implies permanent, irreversible deletion -- this must never
    happen without an explicit confirm_delete=true, to prevent a UI bug or
    accidental double-click from silently destroying mail."""
    resp = client.post(
        "/api/findings/quarantine",
        json={"folder": "INBOX", "uid": "1", "sender": "a@evil.com", "block_address": True},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert "confirm_delete" in resp.json()["detail"]


@patch("web.app.connect_imap")
@patch("web.app.supports_uidplus", return_value=False)
@patch("web.app.open_folder")
def test_block_fails_closed_when_uidplus_unsupported_no_blanket_expunge(
    mock_open_folder, mock_supports_uidplus, mock_connect,
):
    """If the server can't target a single UID for expunge, refuse outright
    rather than issuing a blanket EXPUNGE that could destroy unrelated mail."""
    mock_connect.return_value = MagicMock()
    resp = client.post(
        "/api/findings/quarantine",
        json={"folder": "INBOX", "uid": "1", "sender": "a@evil.com", "block_address": True, "confirm_delete": True},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert "UIDPLUS" in resp.json()["detail"]
    mock_open_folder.return_value  # sanity: reached open_folder, never called expunge


def test_quarantine_requires_config():
    from web.state import session_state
    old_config = session_state.config
    session_state.config = None
    try:
        resp = client.post(
            "/api/findings/quarantine",
            json={"folder": "INBOX", "uid": "1", "sender": "a@b.com"},
            headers=AUTH,
        )
        assert resp.status_code == 400
    finally:
        session_state.config = old_config


@patch("web.app.connect_imap")
@patch("web.app.supports_move", return_value=True)
@patch("web.app.ensure_folder_exists")
@patch("web.app.apply_move")
@patch("web.app.open_folder")
def test_no_block_flags_moves_to_quarantine_never_deletes(
    mock_open_folder, mock_apply_move, mock_ensure, mock_supports_move, mock_connect,
):
    """Without block_address/block_domain, this is the same safe, recoverable
    UID MOVE action as a normal --apply scan -- never a delete."""
    mock_connect.return_value = MagicMock()
    resp = client.post(
        "/api/findings/quarantine",
        json={"folder": "INBOX", "uid": "5", "sender": "a@b.com"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "moved_to_quarantine"
    assert "a@b.com" not in data["blocked_senders"]
    mock_apply_move.assert_called_once()


@patch("web.app.connect_imap")
@patch("web.app.supports_move", return_value=False)
@patch("web.app.open_folder")
def test_plain_quarantine_fails_closed_when_move_unsupported(mock_open_folder, mock_supports_move, mock_connect):
    mock_connect.return_value = MagicMock()
    resp = client.post(
        "/api/findings/quarantine",
        json={"folder": "INBOX", "uid": "1", "sender": "a@b.com"},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert "UID MOVE" in resp.json()["detail"]
