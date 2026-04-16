"""Tests for the main API endpoints (main.py routes)."""

import pytest


# ── Plugins ──────────────────────────────────────────────────────

def test_list_plugins(client, auth_headers):
    resp = client.get("/plugins", headers=auth_headers)
    assert resp.status_code == 200
    plugins = resp.json()
    assert isinstance(plugins, list)
    assert len(plugins) == 13
    # Each entry should have name + description
    for p in plugins:
        assert "name" in p
        assert "description" in p


# ── Bettercap (NativeCapEngine) ──────────────────────────────────

def test_bettercap_status(client, auth_headers):
    resp = client.get("/bettercap/status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["installed"] is True
    assert data["running"] is True
    assert "active_modules" in data


def test_bettercap_command(client, auth_headers):
    resp = client.post("/bettercap/command", json={"cmd": "help"}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "MOONKEEP" in data["output"]


# ── Campaigns ────────────────────────────────────────────────────

def test_list_campaigns(client, auth_headers):
    resp = client.get("/campaigns", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_create_campaign(client, auth_headers):
    payload = {
        "id": "test_camp_api",
        "name": "API Test Campaign",
        "description": "Created by pytest",
        "scope": "10.0.0.0/8",
    }
    resp = client.post("/campaigns", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "test_camp_api"


def test_activate_campaign(client, auth_headers):
    # Ensure campaign exists
    client.post(
        "/campaigns",
        json={"id": "activate_me", "name": "Activate", "description": "test", "scope": "10.0.0.0/8"},
        headers=auth_headers,
    )
    resp = client.put("/campaigns/activate_me/activate", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["active"] == "activate_me"

    # Re-activate "default" so we don't interfere with other tests
    client.put("/campaigns/default/activate", headers=auth_headers)


def test_export_report_markdown(client, auth_headers):
    resp = client.get("/campaigns/default/report?fmt=markdown", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "markdown"
    assert "Moonkeep" in data["report"]


def test_export_report_json(client, auth_headers):
    resp = client.get("/campaigns/default/report?fmt=json", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "json"
    # The report field is a JSON string
    import json
    parsed = json.loads(data["report"])
    assert "campaign" in parsed


def test_export_report_csv(client, auth_headers):
    resp = client.get("/campaigns/default/report?fmt=csv", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "csv"
    assert "Section" in data["report"]


# ── Scan validation ──────────────────────────────────────────────

def test_scan_invalid_target(client, auth_headers):
    resp = client.get("/scan?target=not-a-valid-ip!", headers=auth_headers)
    assert resp.status_code == 400
    assert "Invalid target" in resp.json()["detail"]


# ── Graph ────────────────────────────────────────────────────────

def test_graph_endpoint(client, auth_headers):
    resp = client.get("/graph", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "links" in data


# ── Interfaces ───────────────────────────────────────────────────

def test_interfaces_endpoint(client, auth_headers):
    resp = client.get("/interfaces", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ── Fuzzer ───────────────────────────────────────────────────────

def test_fuzzer_stats(client, auth_headers):
    resp = client.get("/fuzzer/stats", headers=auth_headers)
    assert resp.status_code == 200


# ── Cyber Strike ─────────────────────────────────────────────────

def test_cyber_strike_status(client, auth_headers):
    resp = client.get("/cyber_strike/status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "log" in data
