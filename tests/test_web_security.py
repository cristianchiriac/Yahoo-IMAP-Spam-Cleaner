from fastapi.testclient import TestClient

from web.app import app, configure_security
from web.security import CSRF_TOKEN

configure_security(8765)
client = TestClient(app, base_url="http://127.0.0.1:8765")


def test_bad_host_rejected():
    resp = client.get("/api/csrf-token", headers={"Host": "evil.com"})
    assert resp.status_code == 400


def test_good_host_allowed():
    resp = client.get("/api/csrf-token", headers={"Host": "127.0.0.1:8765"})
    assert resp.status_code == 200


def test_post_without_csrf_token_rejected():
    resp = client.post("/api/config", json={"email": "a@b.com", "app_password": "x"})
    assert resp.status_code == 403


def test_post_with_wrong_csrf_token_rejected():
    resp = client.post(
        "/api/config",
        json={"email": "a@b.com", "app_password": "x"},
        headers={"X-CSRF-Token": "wrong"},
    )
    assert resp.status_code == 403


def test_post_with_correct_csrf_token_allowed():
    resp = client.post(
        "/api/config",
        json={"email": "a@b.com", "app_password": "x"},
        headers={"X-CSRF-Token": CSRF_TOKEN},
    )
    assert resp.status_code == 200


def test_cross_origin_post_rejected():
    resp = client.post(
        "/api/config",
        json={"email": "a@b.com", "app_password": "x"},
        headers={"X-CSRF-Token": CSRF_TOKEN, "Origin": "http://evil.com"},
    )
    assert resp.status_code == 403


def test_same_origin_post_allowed():
    resp = client.post(
        "/api/config",
        json={"email": "a@b.com", "app_password": "x"},
        headers={"X-CSRF-Token": CSRF_TOKEN, "Origin": "http://127.0.0.1:8765"},
    )
    assert resp.status_code == 200
