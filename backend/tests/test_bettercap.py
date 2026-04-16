"""Tests for the NativeCapEngine (core/bettercap_adapter.py)."""

import pytest
from core.bettercap_adapter import NativeCapEngine


@pytest.fixture()
def engine():
    """A fresh NativeCapEngine with no plugin manager wired in."""
    return NativeCapEngine()


# ── Help ─────────────────────────────────────────────────────────

def test_help_command(engine):
    result = engine.run_command("help")
    assert result["status"] == "ok"
    assert "MOONKEEP" in result["output"]
    assert "net.probe" in result["output"]


# ── Set / Get ────────────────────────────────────────────────────

def test_set_and_get(engine):
    engine.run_command("set arp.spoof.targets 192.168.1.100")
    result = engine.run_command("get arp.spoof.targets")
    assert result["status"] == "ok"
    assert "192.168.1.100" in result["output"]


def test_get_wildcard(engine):
    result = engine.run_command("get wifi.*")
    assert result["status"] == "ok"
    assert "wifi." in result["output"]


# ── Shell allowlist ──────────────────────────────────────────────

def test_shell_allowlist_blocks(engine):
    result = engine.run_command("! rm -rf /")
    assert result["status"] == "error"
    assert "Blocked" in result["output"]


def test_shell_allowlist_allows(engine):
    result = engine.run_command("! whoami")
    assert result["status"] == "ok"
    # Should return the current username (non-empty)
    assert len(result["output"]) > 0


# ── Net probe on / off ───────────────────────────────────────────

def test_net_probe_on_off(engine):
    on = engine.run_command("net.probe on")
    assert on["status"] == "ok"
    assert "net.probe" in engine.active_modules

    off = engine.run_command("net.probe off")
    assert off["status"] == "ok"
    assert "net.probe" not in engine.active_modules


# ── WiFi recon on / off ─────────────────────────────────────────

def test_wifi_recon_on_off(engine):
    on = engine.run_command("wifi.recon on")
    assert on["status"] == "ok"
    assert "wifi.recon" in engine.active_modules

    off = engine.run_command("wifi.recon off")
    assert off["status"] == "ok"
    assert "wifi.recon" not in engine.active_modules


# ── Show command ─────────────────────────────────────────────────

def test_show_command(engine):
    result = engine.run_command("show")
    assert result["status"] == "ok"
    assert "MOONKEEP" in result["output"]


# ── Active modules ───────────────────────────────────────────────

def test_active_modules(engine):
    engine.run_command("net.probe on")
    engine.run_command("wifi.recon on")
    result = engine.run_command("active")
    assert result["status"] == "ok"
    assert "net.probe" in result["output"]
    assert "wifi.recon" in result["output"]


# ── Unknown command ──────────────────────────────────────────────

def test_unknown_command(engine):
    result = engine.run_command("totallyFakeCommand")
    assert result["status"] == "error"
    assert "Unknown command" in result["output"]


# ── Clear command ────────────────────────────────────────────────

def test_clear_command(engine):
    result = engine.run_command("clear")
    assert result["status"] == "ok"
    assert "__CLEAR__" in result["output"]


# ── Semicolon multi-command ──────────────────────────────────────

def test_semicolon_multi_command(engine):
    result = engine.run_command("net.probe on; wifi.recon on")
    assert result["status"] == "ok"
    assert "net.probe" in engine.active_modules
    assert "wifi.recon" in engine.active_modules


# ── Alias ────────────────────────────────────────────────────────

def test_alias(engine):
    result = engine.run_command("alias AA:BB:CC:DD:EE:FF MyRouter")
    assert result["status"] == "ok"
    assert engine.aliases.get("AA:BB:CC:DD:EE:FF") == "MyRouter"
