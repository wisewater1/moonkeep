"""Unit tests for CampaignManager (core/campaign_manager.py)."""

import json
import sqlite3
import pytest
from core.campaign_manager import CampaignManager


# ── Campaign CRUD ────────────────────────────────────────────────

def test_create_campaign(campaign_manager):
    result = campaign_manager.create_campaign("c1", "Campaign One", "Testing", "192.168.1.0/24")
    assert result["id"] == "c1"
    assert result["name"] == "Campaign One"
    assert result["scope"] == "192.168.1.0/24"
    assert result["created_at"] is not None


def test_get_campaign_not_found(campaign_manager):
    assert campaign_manager.get_campaign("nonexistent") is None


def test_list_campaigns(campaign_manager):
    campaign_manager.create_campaign("a1", "Alpha", "first", "10.0.0.0/8")
    campaign_manager.create_campaign("b2", "Bravo", "second", "172.16.0.0/12")
    campaigns = campaign_manager.list_campaigns()
    ids = [c["id"] for c in campaigns]
    assert "a1" in ids
    assert "b2" in ids


# ── Devices ──────────────────────────────────────────────────────

def test_save_and_load_devices(campaign_manager):
    campaign_manager.create_campaign("dev_test", "Devices", "", "0.0.0.0/0")
    device = {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "TestCo", "hostname": "host1"}
    campaign_manager.save_device("dev_test", device)
    devices = campaign_manager.load_devices("dev_test")
    assert len(devices) == 1
    assert devices[0]["ip"] == "192.168.1.10"
    assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"


# ── Networks ─────────────────────────────────────────────────────

def test_save_and_load_networks(campaign_manager):
    campaign_manager.create_campaign("net_test", "Networks", "", "0.0.0.0/0")
    net = {"bssid": "00:11:22:33:44:55", "ssid": "TestNet", "channel": 6, "encryption": "WPA2", "signal": -45}
    campaign_manager.save_network("net_test", net)
    networks = campaign_manager.load_networks("net_test")
    assert len(networks) == 1
    assert networks[0]["ssid"] == "TestNet"
    assert networks[0]["channel"] == 6


# ── Credentials ──────────────────────────────────────────────────

def test_save_and_load_credentials(campaign_manager):
    campaign_manager.create_campaign("cred_test", "Creds", "", "0.0.0.0/0")
    campaign_manager.save_credential("cred_test", "Sniffer", "admin:password123")
    creds = campaign_manager.load_credentials("cred_test")
    assert len(creds) == 1
    assert creds[0]["plugin"] == "Sniffer"
    assert creds[0]["content"] == "admin:password123"


# ── Report exports ───────────────────────────────────────────────

def test_export_markdown(campaign_manager):
    campaign_manager.create_campaign("rpt", "Report Test", "desc", "10.0.0.0/8")
    campaign_manager.save_device("rpt", {"ip": "10.0.0.1", "mac": "AA:BB:CC:DD:EE:01", "vendor": "V", "hostname": "h"})
    report = campaign_manager.export_report("rpt", fmt="markdown")
    assert "# Moonkeep Engagement Report" in report
    assert "10.0.0.1" in report


def test_export_json(campaign_manager):
    campaign_manager.create_campaign("rptj", "JSON Report", "desc", "10.0.0.0/8")
    report_str = campaign_manager.export_report("rptj", fmt="json")
    parsed = json.loads(report_str)
    assert "campaign" in parsed
    assert parsed["campaign"]["id"] == "rptj"


def test_export_csv(campaign_manager):
    campaign_manager.create_campaign("rptc", "CSV Report", "desc", "10.0.0.0/8")
    campaign_manager.save_device("rptc", {"ip": "10.0.0.2", "mac": "AA:BB:CC:DD:EE:02", "vendor": "V", "hostname": "h"})
    report = campaign_manager.export_report("rptc", fmt="csv")
    assert "Section" in report
    assert "10.0.0.2" in report


# ── XSS sanitisation ────────────────────────────────────────────

def test_sanitize_xss(campaign_manager):
    campaign_manager.create_campaign(
        "xss_test",
        "<script>alert(1)</script>",
        '<img onerror="hack">',
        "10.0.0.0/8",
    )
    c = campaign_manager.get_campaign("xss_test")
    assert "<script>" not in c["name"]
    assert "&lt;script&gt;" in c["name"]
    assert 'onerror="hack"' not in c["description"]


# ── WAL mode ─────────────────────────────────────────────────────

def test_wal_mode_enabled(campaign_manager):
    conn = sqlite3.connect(campaign_manager.db_path)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode == "wal"
