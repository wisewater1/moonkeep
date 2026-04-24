"""Tests for the authentication system (core/auth.py + /auth/* routes)."""

import time
import jwt
import pytest
from core.auth import SECRET_KEY, ALGORITHM


# ── Login ────────────────────────────────────────────────────────

def test_login_success(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["username"] == "admin"
    assert data["role"] == "admin"


def test_login_wrong_password(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


def test_login_nonexistent_user(client):
    resp = client.post("/auth/login", json={"username": "ghost", "password": "nope"})
    assert resp.status_code == 401


# ── Protected endpoints ──────────────────────────────────────────

def test_protected_endpoint_without_token(client):
    resp = client.get("/plugins")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_protected_endpoint_with_valid_token(client, auth_headers):
    resp = client.get("/plugins", headers=auth_headers)
    assert resp.status_code == 200


def test_protected_endpoint_with_expired_token(client):
    """Forge a token that expired in the past and verify rejection."""
    expired_payload = {
        "sub": "admin",
        "role": "admin",
        "exp": time.time() - 60,   # expired 60 s ago
        "iat": time.time() - 120,
    }
    expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
    resp = client.get("/plugins", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401


# ── Registration ─────────────────────────────────────────────────

def test_register_new_user(client, auth_headers):
    resp = client.post(
        "/auth/register",
        json={"username": "operator1", "password": "secret123", "role": "operator"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "operator1"


def test_register_without_admin(client):
    """Registration requires admin role; an unauthenticated call should 401."""
    resp = client.post(
        "/auth/register",
        json={"username": "hacker", "password": "lol", "role": "operator"},
    )
    assert resp.status_code == 401


# ── Password change ──────────────────────────────────────────────

def test_change_password(client, auth_headers):
    # First register a temp user
    client.post(
        "/auth/register",
        json={"username": "pwchange_user", "password": "old_pass", "role": "operator"},
        headers=auth_headers,
    )
    # Log in as that user
    login_resp = client.post("/auth/login", json={"username": "pwchange_user", "password": "old_pass"})
    assert login_resp.status_code == 200
    user_token = login_resp.json()["token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # Change the password
    resp = client.post(
        "/auth/change_password",
        json={"old_password": "old_pass", "new_password": "new_pass"},
        headers=user_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "password changed"

    # Verify old password no longer works
    resp2 = client.post("/auth/login", json={"username": "pwchange_user", "password": "old_pass"})
    assert resp2.status_code == 401

    # Verify new password works
    resp3 = client.post("/auth/login", json={"username": "pwchange_user", "password": "new_pass"})
    assert resp3.status_code == 200


# ── Audit log ────────────────────────────────────────────────────

def test_audit_log_records_actions(client, auth_headers):
    """After a login, the audit log should contain at least one LOGIN_SUCCESS entry."""
    resp = client.get("/admin/audit?limit=50", headers=auth_headers)
    assert resp.status_code == 200
    entries = resp.json()
    assert isinstance(entries, list)
    actions = [e["action"] for e in entries]
    assert "LOGIN_SUCCESS" in actions


# ── Auth status & me ────────────────────────────────────────────

def test_auth_status(client):
    resp = client.get("/auth/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["auth_enabled"] is True
    assert "version" in data


def test_auth_me(client, auth_headers):
    resp = client.get("/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "admin"
    assert data["role"] == "admin"


# ── Admin endpoints ─────────────────────────────────────────────

def test_admin_list_users(client, auth_headers):
    resp = client.get("/admin/users", headers=auth_headers)
    assert resp.status_code == 200
    users = resp.json()
    assert isinstance(users, list)
    usernames = [u["username"] for u in users]
    assert "admin" in usernames


def test_admin_delete_user(client, auth_headers):
    client.post(
        "/auth/register",
        json={"username": "to_delete", "password": "pass123", "role": "operator"},
        headers=auth_headers,
    )
    resp = client.delete("/admin/users/to_delete", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"
    login = client.post("/auth/login", json={"username": "to_delete", "password": "pass123"})
    assert login.status_code == 401


def test_admin_cannot_delete_self(client, auth_headers):
    resp = client.delete("/admin/users/admin", headers=auth_headers)
    assert resp.status_code == 400
    assert "Cannot delete yourself" in resp.json()["detail"]


# ── Edge cases ──────────────────────────────────────────────────

def test_login_empty_body(client):
    resp = client.post("/auth/login", content=b"", headers={"Content-Type": "application/json"})
    assert resp.status_code == 422


def test_login_missing_fields(client):
    resp = client.post("/auth/login", json={"username": "admin"})
    assert resp.status_code == 422


def test_login_sql_injection_username(client):
    resp = client.post("/auth/login", json={"username": "'; DROP TABLE users; --", "password": "test"})
    assert resp.status_code == 401
    users_resp = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert users_resp.status_code == 200


def test_tampered_token_signature(client):
    from core.auth import create_token
    token = create_token("admin", "admin")
    tampered = token[:-4] + "XXXX"
    resp = client.get("/plugins", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


def test_register_operator_cannot_register(client, auth_headers):
    client.post(
        "/auth/register",
        json={"username": "op_user", "password": "pass", "role": "operator"},
        headers=auth_headers,
    )
    login = client.post("/auth/login", json={"username": "op_user", "password": "pass"})
    if login.status_code == 200:
        op_headers = {"Authorization": f"Bearer {login.json()['token']}"}
        resp = client.post(
            "/auth/register",
            json={"username": "sneaky", "password": "hack", "role": "operator"},
            headers=op_headers,
        )
        assert resp.status_code == 403
