"""Tests for the main API endpoints (main.py routes)."""

import pytest


# ── Plugins ──────────────────────────────────────────────────────

def test_list_plugins(client, auth_headers):
    resp = client.get("/plugins", headers=auth_headers)
    assert resp.status_code == 200
    plugins = resp.json()
    assert isinstance(plugins, list)
    # The plugin set grows over time; lock in a floor instead of an exact count.
    assert len(plugins) >= 13
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


# ── Bettercap start/stop/session ────────────────────────────────

def test_bettercap_start(client, auth_headers):
    resp = client.post("/bettercap/start", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_bettercap_stop(client, auth_headers):
    resp = client.post("/bettercap/stop", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_bettercap_session(client, auth_headers):
    resp = client.get("/bettercap/session", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


# ── WiFi Scan ───────────────────────────────────────────────────

def test_wifi_scan(client, auth_headers):
    resp = client.get("/wifi_scan", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "networks" in data
    assert isinstance(data["networks"], list)


# ── WiFi strike endpoints ──────────────────────────────────────

def test_wifi_deauth(client, auth_headers):
    resp = client.post("/wifi/deauth", json={"target": "ff:ff:ff:ff:ff:ff", "ap": "AA:BB:CC:DD:EE:FF"}, headers=auth_headers)
    assert resp.status_code == 200


def test_wifi_capture_passive(client, auth_headers):
    resp = client.post("/wifi/capture_passive", json={"bssid": "AA:BB:CC:DD:EE:FF"}, headers=auth_headers)
    assert resp.status_code == 200
    assert "Listening" in resp.json()["message"]


def test_wifi_handshakes(client, auth_headers):
    resp = client.get("/wifi/handshakes", headers=auth_headers)
    assert resp.status_code in (200, 404)


# ── Secret Hunter ───────────────────────────────────────────────

def test_secret_hunter_hunt(client, auth_headers):
    resp = client.post("/secret_hunter/hunt", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data


def test_secret_hunter_results(client, auth_headers):
    resp = client.get("/secret_hunter/results", headers=auth_headers)
    assert resp.status_code == 200
    assert "findings" in resp.json()


# ── Cyber Strike start/stop ─────────────────────────────────────

def test_cyber_strike_start(client, auth_headers):
    resp = client.post("/cyber_strike/start", json={"role": "Shadow"}, headers=auth_headers)
    assert resp.status_code == 200
    assert "Shadow" in resp.json()["status"]


def test_cyber_strike_stop(client, auth_headers):
    resp = client.post("/cyber_strike/stop", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "Stopped"


# ── AI Orchestrator ─────────────────────────────────────────────

def test_ai_command(client, auth_headers):
    resp = client.post("/ai/command", json={"instruction": "scan the network"}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "plan" in data


def test_ai_execute(client, auth_headers):
    resp = client.post("/ai/execute", json={"plan": []}, headers=auth_headers)
    assert resp.status_code == 200
    assert "Executing" in resp.json()["status"]


def test_ai_analyze(client, auth_headers):
    resp = client.post("/ai/analyze", headers=auth_headers)
    assert resp.status_code == 200
    assert "insights" in resp.json()


# ── Post-Exploit ────────────────────────────────────────────────

def test_post_exploit_persistence(client, auth_headers):
    resp = client.get("/post_exploit/persistence?os_type=linux", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["os"] == "linux"
    assert "payloads" in data
    assert len(data["payloads"]) > 0


def test_post_exploit_persistence_windows(client, auth_headers):
    resp = client.get("/post_exploit/persistence?os_type=windows", headers=auth_headers)
    assert resp.status_code == 200
    for p in resp.json()["payloads"]:
        assert "technique" in p
        assert "method" in p


def test_post_exploit_exfiltrate(client, auth_headers):
    resp = client.post("/post_exploit/exfiltrate", json={"target_session_id": "192.168.1.100"}, headers=auth_headers)
    assert resp.status_code == 200
    assert "Exfiltration" in resp.json()["status"]


# ── Fuzzer endpoints ────────────────────────────────────────────

def test_fuzzer_snmp(client, auth_headers):
    resp = client.post("/fuzzer/snmp", json={"ip": "192.168.1.1"}, headers=auth_headers)
    assert resp.status_code == 200


def test_fuzzer_mdns(client, auth_headers):
    resp = client.post("/fuzzer/mdns", json={"ip": "192.168.1.1"}, headers=auth_headers)
    assert resp.status_code == 200


def test_fuzzer_upnp(client, auth_headers):
    resp = client.post("/fuzzer/upnp", json={"ip": "192.168.1.1"}, headers=auth_headers)
    assert resp.status_code == 200


# ── Sniffer endpoints ──────────────────────────────────────────

def test_sniffer_credentials(client, auth_headers):
    resp = client.get("/sniffer/credentials", headers=auth_headers)
    assert resp.status_code == 200
    assert "credentials" in resp.json()


def test_sniffer_dns(client, auth_headers):
    resp = client.get("/sniffer/dns", headers=auth_headers)
    assert resp.status_code == 200
    assert "dns_log" in resp.json()


def test_sniffer_start(client, auth_headers):
    resp = client.post("/sniffer/start", headers=auth_headers)
    assert resp.status_code == 200


def test_sniffer_stop(client, auth_headers):
    resp = client.post("/sniffer/stop", headers=auth_headers)
    assert resp.status_code == 200


# ── HID-BLE ─────────────────────────────────────────────────────

def test_hid_ble_scan(client, auth_headers):
    resp = client.get("/hid_ble/scan", headers=auth_headers)
    assert resp.status_code == 200


# ── Proxy/Spoofer ───────────────────────────────────────────────

def test_proxy_start(client, auth_headers):
    resp = client.post("/proxy/start", json={"port": 8080}, headers=auth_headers)
    assert resp.status_code == 200


def test_proxy_stop(client, auth_headers):
    resp = client.post("/proxy/stop", headers=auth_headers)
    assert resp.status_code == 200


def test_spoofer_start(client, auth_headers):
    resp = client.post("/spoofer/start", json={"targets": ["192.168.1.100"]}, headers=auth_headers)
    assert resp.status_code == 200


def test_spoofer_stop(client, auth_headers):
    resp = client.post("/spoofer/stop", headers=auth_headers)
    assert resp.status_code == 200


# ── Vuln Scanner ────────────────────────────────────────────────

def test_vuln_scan_with_target(client, auth_headers):
    resp = client.get("/vuln_scan?target=192.168.1.1", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "target" in data
    assert data["target"] == "192.168.1.1"


def test_vuln_scan_invalid_target(client, auth_headers):
    resp = client.get("/vuln_scan?target=not-an-ip", headers=auth_headers)
    assert resp.status_code == 400


# ── Campaign edge cases ────────────────────────────────────────

def test_activate_nonexistent_campaign(client, auth_headers):
    resp = client.put("/campaigns/does_not_exist/activate", headers=auth_headers)
    assert resp.status_code == 404


def test_export_invalid_format(client, auth_headers):
    resp = client.get("/campaigns/default/report?fmt=xml", headers=auth_headers)
    assert resp.status_code == 400


def test_export_nonexistent_campaign(client, auth_headers):
    resp = client.get("/campaigns/ghost_campaign/report", headers=auth_headers)
    assert resp.status_code == 404
