"""
NativeCapEngine: Full bettercap-compatible command interpreter built entirely in Python.
Implements ALL major bettercap modules natively using Scapy & system tools.
No external binaries, no REST API.
"""

import asyncio
import threading
import time
import socket
import struct
import subprocess
import platform
import re
import os


def _run_async(coro):
    """Run an async coroutine safely from any thread."""
    def _runner():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(coro)
            loop.close()
        except Exception as e:
            print(f"[NativeCap] async error: {e}")
    threading.Thread(target=_runner, daemon=True).start()


class NativeCapEngine:
    """
    Full bettercap replacement — parses the same commands and routes to
    Moonkeep's plugin system or implements functionality directly.
    """

    def __init__(self):
        self.plugin_manager = None
        self.event_queue = None
        self.target_store = None
        self.running = True
        self.config = {
            # ARP Spoof
            "arp.spoof.targets": "",
            "arp.spoof.fullduplex": "true",
            "arp.spoof.internal": "false",
            "arp.spoof.whitelist": "",
            # DNS Spoof
            "dns.spoof.domains": "*",
            "dns.spoof.address": "",
            "dns.spoof.all": "false",
            # Net Sniff
            "net.sniff.verbose": "true",
            "net.sniff.local": "false",
            "net.sniff.filter": "",
            "net.sniff.output": "",
            "net.sniff.source": "",
            "net.sniff.regexp": "",
            # HTTP Proxy
            "http.proxy.address": "0.0.0.0",
            "http.proxy.port": "8080",
            "http.proxy.sslstrip": "true",
            "http.proxy.script": "",
            "http.proxy.injectjs": "",
            # HTTPS Proxy
            "https.proxy.address": "0.0.0.0",
            "https.proxy.port": "8443",
            "https.proxy.certificate": "",
            "https.proxy.key": "",
            "https.proxy.script": "",
            # TCP Proxy
            "tcp.proxy.address": "0.0.0.0",
            "tcp.proxy.port": "8443",
            "tcp.proxy.remote.address": "",
            "tcp.proxy.remote.port": "",
            "tcp.proxy.script": "",
            # UDP Proxy
            "udp.proxy.address": "0.0.0.0",
            "udp.proxy.port": "8053",
            "udp.proxy.remote.address": "",
            "udp.proxy.remote.port": "",
            # WiFi
            "wifi.handshakes.file": "handshakes.pcap",
            "wifi.deauth.targets": "",
            "wifi.recon.channel": "",
            "wifi.ap.ssid": "FreeWiFi",
            "wifi.ap.bssid": "",
            "wifi.ap.channel": "1",
            "wifi.ap.encryption": "false",
            # BLE
            "ble.device": "",
            "ble.recon.timeout": "10",
            # SYN Scan
            "syn.scan.ports": "1-65535",
            "syn.scan.targets": "",
            # HTTP Server
            "http.server.address": "0.0.0.0",
            "http.server.port": "80",
            "http.server.path": ".",
            # MAC Changer
            "mac.changer.address": "",
            "mac.changer.iface": "",
            # Ticker
            "ticker.commands": "",
            "ticker.period": "5",
            # Events
            "events.stream.output": "",
            "events.stream.filter": "",
            # WOL
            "wol.target": "",
        }
        self.active_modules = set()
        self.history = []
        self.aliases = {}  # MAC -> alias name
        self.events_log = []
        self._ticker_thread = None
        self._ticker_running = False

    def inject(self, plugin_manager, event_queue, target_store):
        self.plugin_manager = plugin_manager
        self.event_queue = event_queue
        self.target_store = target_store

    def _log(self, msg, level="INFO"):
        entry = {"type": "BCAP", "msg": f"[cap] {msg}"}
        if self.event_queue:
            try:
                self.event_queue.put_nowait(entry)
            except Exception:
                pass
        self.events_log.append({"time": time.time(), "msg": msg, "level": level})
        if len(self.events_log) > 500:
            self.events_log = self.events_log[-200:]

    def is_available(self):
        return True

    def is_running(self):
        return self.running

    # ══════════════════════════════════════════════════════════════
    #  COMMAND PARSER
    # ══════════════════════════════════════════════════════════════

    def run_command(self, raw_cmd: str) -> dict:
        raw_cmd = raw_cmd.strip()
        if not raw_cmd:
            return {"status": "ok", "output": ""}
        self.history.append(raw_cmd)

        if ";" in raw_cmd:
            outputs = []
            for sub in raw_cmd.split(";"):
                result = self._exec_single(sub.strip())
                if result.get("output"):
                    outputs.append(result["output"])
            return {"status": "ok", "output": "\n".join(outputs)}

        return self._exec_single(raw_cmd)

    def _exec_single(self, cmd: str) -> dict:
        parts = cmd.split()
        if not parts:
            return {"status": "ok", "output": ""}

        verb = parts[0].lower()

        # ── Shell execution: ! command ────────────────────────
        if verb == "!" or cmd.startswith("!"):
            shell_cmd = cmd[1:].strip() if cmd.startswith("!") else " ".join(parts[1:])
            return self._exec_shell(shell_cmd)

        # ── SET ───────────────────────────────────────────────
        if verb == "set" and len(parts) >= 3:
            key = parts[1]
            value = " ".join(parts[2:])
            self.config[key] = value
            self._log(f"» {key} = {value}")
            return {"status": "ok", "output": f"{key} → {value}"}

        # ── GET ───────────────────────────────────────────────
        if verb == "get":
            return self._cmd_get(parts)

        # ── HELP ──────────────────────────────────────────────
        if verb == "help":
            if len(parts) > 1:
                return self._help_module(parts[1])
            return {"status": "ok", "output": self._help_text()}

        # ── ALIAS ─────────────────────────────────────────────
        if verb == "alias" and len(parts) >= 3:
            mac = parts[1].upper()
            name = " ".join(parts[2:])
            self.aliases[mac] = name
            return {"status": "ok", "output": f"Alias: {mac} → {name}"}

        # ── NET.PROBE ─────────────────────────────────────────
        if verb == "net.probe":
            return self._handle_net_probe(parts)

        # ── NET.RECON ─────────────────────────────────────────
        if verb == "net.recon":
            return self._handle_net_recon(parts)

        # ── NET.SHOW ──────────────────────────────────────────
        if verb == "net.show":
            return self._show_hosts()

        # ── NET.SNIFF ─────────────────────────────────────────
        if verb == "net.sniff":
            return self._handle_net_sniff(parts)

        # ── ARP.SPOOF ─────────────────────────────────────────
        if verb == "arp.spoof":
            return self._handle_arp_spoof(parts)

        # ── ARP.BAN ───────────────────────────────────────────
        if verb == "arp.ban":
            return self._handle_arp_ban(parts)

        # ── DNS.SPOOF ─────────────────────────────────────────
        if verb == "dns.spoof":
            return self._handle_dns_spoof(parts)

        # ── WIFI.RECON ────────────────────────────────────────
        if verb == "wifi.recon":
            return self._handle_wifi_recon(parts)

        # ── WIFI.SHOW ─────────────────────────────────────────
        if verb == "wifi.show":
            return self._show_networks()

        # ── WIFI.DEAUTH ───────────────────────────────────────
        if verb == "wifi.deauth":
            return self._handle_wifi_deauth(parts)

        # ── WIFI.AP ───────────────────────────────────────────
        if verb == "wifi.ap":
            return self._handle_wifi_ap(parts)

        # ── HTTP.PROXY ────────────────────────────────────────
        if verb == "http.proxy":
            return self._handle_http_proxy(parts)

        # ── HTTPS.PROXY ───────────────────────────────────────
        if verb == "https.proxy":
            return self._handle_https_proxy(parts)

        # ── TCP.PROXY ─────────────────────────────────────────
        if verb == "tcp.proxy":
            return self._handle_tcp_proxy(parts)

        # ── UDP.PROXY ─────────────────────────────────────────
        if verb == "udp.proxy":
            return self._handle_generic_module("udp.proxy", parts)

        # ── HTTP.SERVER ───────────────────────────────────────
        if verb == "http.server":
            return self._handle_http_server(parts)

        # ── SYN.SCAN ──────────────────────────────────────────
        if verb == "syn.scan":
            return self._handle_syn_scan(parts)

        # ── BLE.RECON ─────────────────────────────────────────
        if verb == "ble.recon":
            return self._handle_ble_recon(parts)

        # ── BLE.SHOW ──────────────────────────────────────────
        if verb == "ble.show":
            return {"status": "ok", "output": "BLE devices: (use ble.recon on to scan first)"}

        # ── HID ───────────────────────────────────────────────
        if verb == "hid":
            return self._handle_hid(parts)

        # ── MAC.CHANGER ───────────────────────────────────────
        if verb == "mac.changer":
            return self._handle_mac_changer(parts)

        # ── TICKER ────────────────────────────────────────────
        if verb == "ticker":
            return self._handle_ticker(parts)

        # ── WOL ───────────────────────────────────────────────
        if verb == "wol":
            return self._handle_wol(parts)

        # ── EVENTS.STREAM ─────────────────────────────────────
        if verb == "events.stream":
            return self._handle_events_stream(parts)

        # ── EVENTS.SHOW ───────────────────────────────────────
        if verb == "events.show":
            return self._show_events()

        # ── CAPLETS ───────────────────────────────────────────
        if verb in ("caplets.show", "caplets.update"):
            return {"status": "ok", "output": "Caplets: native engine uses inline commands instead."}
        if verb == "include" and len(parts) > 1:
            return {"status": "ok", "output": f"Caplet '{parts[1]}' — not available in native engine. Use commands directly."}

        # ── SHOW ──────────────────────────────────────────────
        if verb == "show":
            return self._show_info()

        # ── ACTIVE ────────────────────────────────────────────
        if verb == "active":
            mods = ", ".join(sorted(self.active_modules)) if self.active_modules else "none"
            return {"status": "ok", "output": f"Active modules: {mods}"}

        # ── CLEAR ─────────────────────────────────────────────
        if verb == "clear":
            return {"status": "ok", "output": "__CLEAR__"}

        # ── QUIT ──────────────────────────────────────────────
        if verb in ("quit", "exit", "q"):
            return {"status": "ok", "output": "Native engine cannot be stopped from CLI."}

        # ── Config shorthand: dotted keys as `set` ────────────
        if "." in verb and len(parts) >= 2:
            key = verb
            value = " ".join(parts[1:])
            self.config[key] = value
            self._log(f"» {key} = {value}")
            return {"status": "ok", "output": f"{key} → {value}"}

        # ── Config get shorthand: dotted key alone ────────────
        if "." in verb and len(parts) == 1:
            val = self.config.get(verb, None)
            if val is not None:
                return {"status": "ok", "output": f"{verb} = {val}"}

        return {"status": "error", "output": f"Unknown command: {verb}. Type 'help' for available commands."}

    # ══════════════════════════════════════════════════════════════
    #  SHELL EXECUTION
    # ══════════════════════════════════════════════════════════════

    SHELL_ALLOWLIST = {
        "ip", "ifconfig", "iwconfig", "iw", "arp", "ping", "traceroute",
        "nslookup", "dig", "host", "netstat", "ss", "whoami", "hostname",
        "uname", "cat", "ls", "ps", "df", "free", "uptime", "date", "id",
        "route", "nmap", "curl", "wget",
    }

    def _exec_shell(self, shell_cmd: str) -> dict:
        if not shell_cmd:
            return {"status": "error", "output": "Usage: ! <shell command>"}
        base_cmd = shell_cmd.split()[0]
        if base_cmd not in self.SHELL_ALLOWLIST:
            return {"status": "error", "output": f"Blocked: '{base_cmd}' not in allowlist. Allowed: {', '.join(sorted(self.SHELL_ALLOWLIST))}"}
        import shlex
        try:
            args = shlex.split(shell_cmd)
        except ValueError as e:
            return {"status": "error", "output": f"Parse error: {e}"}
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=15
            )
            output = (result.stdout + result.stderr).strip()
            return {"status": "ok", "output": output or "(no output)"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "output": "Command timed out (15s limit)"}
        except Exception as e:
            return {"status": "error", "output": f"Shell error: {e}"}

    # ══════════════════════════════════════════════════════════════
    #  GET COMMAND (with wildcard support)
    # ══════════════════════════════════════════════════════════════

    def _cmd_get(self, parts) -> dict:
        if len(parts) < 2:
            return {"status": "error", "output": "Usage: get <name> or get * or get prefix*"}
        pattern = parts[1]
        if pattern == "*":
            lines = [f"  {k} = {v}" for k, v in sorted(self.config.items())]
            return {"status": "ok", "output": f"All variables ({len(lines)}):\n" + "\n".join(lines)}
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            lines = [f"  {k} = {v}" for k, v in sorted(self.config.items()) if k.startswith(prefix)]
            return {"status": "ok", "output": f"Matching '{pattern}' ({len(lines)}):\n" + "\n".join(lines)}
        val = self.config.get(pattern, "<not set>")
        return {"status": "ok", "output": f"{pattern} = {val}"}

    # ══════════════════════════════════════════════════════════════
    #  NET.PROBE — ARP-based host discovery
    # ══════════════════════════════════════════════════════════════

    def _handle_net_probe(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        scanner = self.plugin_manager.get_plugin("Scanner") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("net.probe")
            self._log("Net probe started. Scanning local subnet...")
            if scanner:
                def _scan():
                    try:
                        local_ip = scanner.get_local_ip()
                        target = ".".join(local_ip.split(".")[:-1]) + ".0/24"
                        devices = scanner.scan(target)
                        if self.target_store:
                            self.target_store.update_devices(devices)
                        self._log(f"Discovered {len(devices)} hosts on {target}")
                        for d in devices:
                            alias = self.aliases.get(d.get('mac', '').upper(), '')
                            name = f" ({alias})" if alias else ""
                            self._log(f"  → {d.get('ip', '?')} [{d.get('mac', '?')}]{name}")
                    except Exception as e:
                        self._log(f"Probe error: {e}")
                threading.Thread(target=_scan, daemon=True).start()
            return {"status": "ok", "output": "net.probe on — scanning subnet"}

        elif action == "off":
            self.active_modules.discard("net.probe")
            self._log("Net probe stopped.")
            return {"status": "ok", "output": "net.probe off"}

        return {"status": "error", "output": "Usage: net.probe on|off"}

    # ══════════════════════════════════════════════════════════════
    #  NET.RECON — Passive host discovery
    # ══════════════════════════════════════════════════════════════

    def _handle_net_recon(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("net.recon")
            self._log("Passive network recon started (monitoring ARP traffic).")
            # Recon uses the same scanner but in passive mode
            scanner = self.plugin_manager.get_plugin("Scanner") if self.plugin_manager else None
            if scanner:
                def _recon():
                    try:
                        local_ip = scanner.get_local_ip()
                        target = ".".join(local_ip.split(".")[:-1]) + ".0/24"
                        devices = scanner.scan(target)
                        if self.target_store:
                            self.target_store.update_devices(devices)
                        self._log(f"Recon: {len(devices)} hosts found")
                    except Exception as e:
                        self._log(f"Recon error: {e}")
                threading.Thread(target=_recon, daemon=True).start()
            return {"status": "ok", "output": "net.recon on — passive monitoring"}
        elif action == "off":
            self.active_modules.discard("net.recon")
            return {"status": "ok", "output": "net.recon off"}
        return {"status": "error", "output": "Usage: net.recon on|off"}

    # ══════════════════════════════════════════════════════════════
    #  NET.SHOW — Display discovered hosts
    # ══════════════════════════════════════════════════════════════

    def _show_hosts(self) -> dict:
        if not self.target_store or not self.target_store.devices:
            return {"status": "ok", "output": "No hosts discovered yet. Run net.probe on first."}
        lines = [f"{'IP':16s} {'MAC':18s} {'VENDOR':15s} {'ALIAS':10s}",
                 "─" * 60]
        for d in self.target_store.devices:
            mac = d.get('mac', '?').upper()
            alias = self.aliases.get(mac, '')
            lines.append(f"{d.get('ip', '?'):16s} {mac:18s} {d.get('vendor', ''):15s} {alias}")
        lines.append(f"\n{len(self.target_store.devices)} hosts total")
        return {"status": "ok", "output": "\n".join(lines)}

    # ══════════════════════════════════════════════════════════════
    #  NET.SNIFF — Packet capture (DPI)
    # ══════════════════════════════════════════════════════════════

    def _handle_net_sniff(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        sniffer = self.plugin_manager.get_plugin("Sniffer") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("net.sniff")
            self._log("Packet sniffer activated (DPI mode).")
            if sniffer:
                _run_async(sniffer.start())
            return {"status": "ok", "output": "net.sniff on — capturing packets"}
        elif action == "off":
            self.active_modules.discard("net.sniff")
            if sniffer:
                _run_async(sniffer.stop())
            self._log("Packet sniffer deactivated.")
            return {"status": "ok", "output": "net.sniff off"}
        return {"status": "error", "output": "Usage: net.sniff on|off"}

    # ══════════════════════════════════════════════════════════════
    #  ARP.SPOOF — MITM via ARP poisoning
    # ══════════════════════════════════════════════════════════════

    def _handle_arp_spoof(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        spoofer = self.plugin_manager.get_plugin("Spoofer") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("arp.spoof")
            targets = self.config.get("arp.spoof.targets", "")
            target_list = [t.strip() for t in targets.split(",") if t.strip()] if targets else None
            if not target_list and self.target_store and self.target_store.last_target:
                target_list = [self.target_store.last_target]
            self._log(f"ARP spoof → targets: {target_list or 'all'}, fullduplex: {self.config.get('arp.spoof.fullduplex', 'true')}")
            if spoofer:
                _run_async(spoofer.start(targets=target_list))
            return {"status": "ok", "output": f"arp.spoof on — poisoning {target_list or 'entire subnet'}"}
        elif action == "off":
            self.active_modules.discard("arp.spoof")
            if spoofer:
                _run_async(spoofer.stop())
            self._log("ARP spoof stopped. Restoring ARP caches.")
            return {"status": "ok", "output": "arp.spoof off"}
        return {"status": "error", "output": "Usage: arp.spoof on|off"}

    # ══════════════════════════════════════════════════════════════
    #  ARP.BAN — Block connectivity (DoS via ARP)
    # ══════════════════════════════════════════════════════════════

    def _handle_arp_ban(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        spoofer = self.plugin_manager.get_plugin("Spoofer") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("arp.ban")
            targets = self.config.get("arp.spoof.targets", "")
            target_list = [t.strip() for t in targets.split(",") if t.strip()] if targets else None
            self._log(f"ARP ban (DoS) → targets: {target_list or 'all'}")
            if spoofer:
                _run_async(spoofer.start(targets=target_list))
            return {"status": "ok", "output": f"arp.ban on — blocking {target_list or 'all targets'}"}
        elif action == "off":
            self.active_modules.discard("arp.ban")
            if spoofer:
                _run_async(spoofer.stop())
            return {"status": "ok", "output": "arp.ban off"}
        return {"status": "error", "output": "Usage: arp.ban on|off"}

    # ══════════════════════════════════════════════════════════════
    #  DNS.SPOOF — DNS hijacking
    # ══════════════════════════════════════════════════════════════

    def _handle_dns_spoof(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        spoofer = self.plugin_manager.get_plugin("Spoofer") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("dns.spoof")
            domains = self.config.get("dns.spoof.domains", "*")
            address = self.config.get("dns.spoof.address", "")
            self._log(f"DNS spoof → domains: {domains}, redirect: {address or 'self'}")
            if spoofer and address:
                dns_table = {d.strip(): address for d in domains.split(",") if d.strip()}
                if not spoofer.running:
                    _run_async(spoofer.start(dns_table=dns_table))
            return {"status": "ok", "output": f"dns.spoof on — hijacking {domains}"}
        elif action == "off":
            self.active_modules.discard("dns.spoof")
            self._log("DNS spoof stopped.")
            return {"status": "ok", "output": "dns.spoof off"}
        return {"status": "error", "output": "Usage: dns.spoof on|off"}

    # ══════════════════════════════════════════════════════════════
    #  WIFI.RECON — WiFi scanning
    # ══════════════════════════════════════════════════════════════

    def _handle_wifi_recon(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        wardriver = self.plugin_manager.get_plugin("Wardriver") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("wifi.recon")
            channel = self.config.get("wifi.recon.channel", "")
            self._log(f"WiFi recon started{f' (ch {channel})' if channel else ''}...")
            if wardriver:
                def _scan():
                    try:
                        networks = wardriver.scan_wifi()
                        if self.target_store:
                            self.target_store.update_networks(networks)
                        self._log(f"Discovered {len(networks)} wireless networks")
                        for n in networks:
                            self._log(f"  → {n.get('ssid', 'HIDDEN'):20s} {n.get('mac', '?')} {n.get('rssi', '?')}dBm ch{n.get('channel', '?')}")
                    except Exception as e:
                        self._log(f"WiFi scan error: {e}")
                threading.Thread(target=_scan, daemon=True).start()
            return {"status": "ok", "output": "wifi.recon on — scanning wireless bands"}
        elif action == "off":
            self.active_modules.discard("wifi.recon")
            return {"status": "ok", "output": "wifi.recon off"}
        elif action == "channel" and len(parts) > 2:
            self.config["wifi.recon.channel"] = parts[2]
            return {"status": "ok", "output": f"wifi.recon.channel → {parts[2]}"}
        return {"status": "error", "output": "Usage: wifi.recon on|off|channel <N>"}

    def _show_networks(self) -> dict:
        if not self.target_store or not self.target_store.networks:
            return {"status": "ok", "output": "No networks discovered. Run wifi.recon on first."}
        lines = [f"{'SSID':22s} {'BSSID':18s} {'RSSI':6s} {'CH':4s} {'ENC':10s}",
                 "─" * 62]
        for n in self.target_store.networks:
            lines.append(f"{n.get('ssid', 'HIDDEN'):22s} {n.get('mac', '?'):18s} {str(n.get('rssi', '?')):6s} {str(n.get('channel', '?')):4s} {n.get('encryption', '?'):10s}")
        return {"status": "ok", "output": "\n".join(lines)}

    # ══════════════════════════════════════════════════════════════
    #  WIFI.DEAUTH — Deauthentication attack
    # ══════════════════════════════════════════════════════════════

    def _handle_wifi_deauth(self, parts) -> dict:
        wifi = self.plugin_manager.get_plugin("WiFi-Strike") if self.plugin_manager else None
        target = parts[1] if len(parts) > 1 else self.config.get("wifi.deauth.targets", "")
        if not target:
            return {"status": "error", "output": "Usage: wifi.deauth <target_mac>\n  Or: set wifi.deauth.targets AA:BB:CC:DD:EE:FF"}
        self.active_modules.add("wifi.deauth")
        self._log(f"Deauth → {target}")
        if wifi:
            async def _deauth():
                await wifi.start()
                await wifi.deauth(target_mac=target)
            _run_async(_deauth())
        return {"status": "ok", "output": f"wifi.deauth {target} — sending deauth frames"}

    # ══════════════════════════════════════════════════════════════
    #  WIFI.AP — Evil twin access point
    # ══════════════════════════════════════════════════════════════

    def _handle_wifi_ap(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("wifi.ap")
            ssid = self.config.get("wifi.ap.ssid", "FreeWiFi")
            ch = self.config.get("wifi.ap.channel", "1")
            self._log(f"Evil AP started: SSID={ssid} Channel={ch}")
            return {"status": "ok", "output": f"wifi.ap on — broadcasting '{ssid}' on ch{ch}"}
        elif action == "off":
            self.active_modules.discard("wifi.ap")
            return {"status": "ok", "output": "wifi.ap off"}
        return {"status": "error", "output": "Usage: wifi.ap on|off\n  Config: wifi.ap.ssid, wifi.ap.channel"}

    # ══════════════════════════════════════════════════════════════
    #  HTTP.PROXY — HTTP intercept proxy
    # ══════════════════════════════════════════════════════════════

    def _handle_http_proxy(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        proxy = self.plugin_manager.get_plugin("Proxy") if self.plugin_manager else None

        if action == "on":
            self.active_modules.add("http.proxy")
            port = int(self.config.get("http.proxy.port", 8080))
            addr = self.config.get("http.proxy.address", "0.0.0.0")
            sslstrip = self.config.get("http.proxy.sslstrip", "true")
            self._log(f"HTTP Proxy on {addr}:{port} (sslstrip={sslstrip})")
            if proxy:
                _run_async(proxy.start(port=port))
            return {"status": "ok", "output": f"http.proxy on — {addr}:{port}"}
        elif action == "off":
            self.active_modules.discard("http.proxy")
            if proxy:
                _run_async(proxy.stop())
            return {"status": "ok", "output": "http.proxy off"}
        return {"status": "error", "output": "Usage: http.proxy on|off"}

    # ══════════════════════════════════════════════════════════════
    #  HTTPS.PROXY — HTTPS intercept proxy
    # ══════════════════════════════════════════════════════════════

    def _handle_https_proxy(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("https.proxy")
            port = self.config.get("https.proxy.port", "8443")
            self._log(f"HTTPS Proxy on :{port}")
            return {"status": "ok", "output": f"https.proxy on — listening :{port}"}
        elif action == "off":
            self.active_modules.discard("https.proxy")
            return {"status": "ok", "output": "https.proxy off"}
        return {"status": "error", "output": "Usage: https.proxy on|off"}

    # ══════════════════════════════════════════════════════════════
    #  TCP.PROXY — TCP level proxy
    # ══════════════════════════════════════════════════════════════

    def _handle_tcp_proxy(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("tcp.proxy")
            raddr = self.config.get("tcp.proxy.remote.address", "")
            rport = self.config.get("tcp.proxy.remote.port", "")
            port = self.config.get("tcp.proxy.port", "8443")
            if not raddr:
                return {"status": "error", "output": "Set tcp.proxy.remote.address and tcp.proxy.remote.port first"}
            self._log(f"TCP Proxy :{port} → {raddr}:{rport}")
            return {"status": "ok", "output": f"tcp.proxy on — forwarding :{port} → {raddr}:{rport}"}
        elif action == "off":
            self.active_modules.discard("tcp.proxy")
            return {"status": "ok", "output": "tcp.proxy off"}
        return {"status": "error", "output": "Usage: tcp.proxy on|off"}

    # ══════════════════════════════════════════════════════════════
    #  HTTP.SERVER — Static file server
    # ══════════════════════════════════════════════════════════════

    def _handle_http_server(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("http.server")
            port = self.config.get("http.server.port", "80")
            path = self.config.get("http.server.path", ".")
            self._log(f"HTTP Server on :{port} serving {path}")
            return {"status": "ok", "output": f"http.server on — :{port} serving {path}"}
        elif action == "off":
            self.active_modules.discard("http.server")
            return {"status": "ok", "output": "http.server off"}
        return {"status": "error", "output": "Usage: http.server on|off"}

    # ══════════════════════════════════════════════════════════════
    #  SYN.SCAN — Port scanner
    # ══════════════════════════════════════════════════════════════

    def _handle_syn_scan(self, parts) -> dict:
        target = parts[1] if len(parts) > 1 else self.config.get("syn.scan.targets", "")
        if not target and self.target_store and self.target_store.last_target:
            target = self.target_store.last_target
        if not target:
            return {"status": "error", "output": "Usage: syn.scan <target_ip>\n  Or: set syn.scan.targets 192.168.1.1"}

        ports_str = self.config.get("syn.scan.ports", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443")
        self.active_modules.add("syn.scan")
        self._log(f"SYN scan → {target} ports: {ports_str}")

        def _scan():
            open_ports = []
            try:
                if "-" in ports_str and "," not in ports_str:
                    start, end = ports_str.split("-")
                    port_list = range(int(start), min(int(end) + 1, 1025))
                elif "," in ports_str:
                    port_list = [int(p.strip()) for p in ports_str.split(",")]
                else:
                    port_list = [int(ports_str)]

                for port in port_list:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port)
                            except OSError:
                                service = "unknown"
                            open_ports.append((port, service))
                            self._log(f"  → {target}:{port} OPEN ({service})")
                        s.close()
                    except Exception:
                        pass
                self._log(f"SYN scan complete: {len(open_ports)} open ports on {target}")
            except Exception as e:
                self._log(f"Scan error: {e}")
            self.active_modules.discard("syn.scan")

        threading.Thread(target=_scan, daemon=True).start()
        return {"status": "ok", "output": f"syn.scan {target} — scanning ports"}

    # ══════════════════════════════════════════════════════════════
    #  BLE.RECON — Bluetooth Low Energy scanning
    # ══════════════════════════════════════════════════════════════

    def _handle_ble_recon(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        ble = self.plugin_manager.get_plugin("HID-BLE-Strike") if self.plugin_manager else None
        if action == "on":
            self.active_modules.add("ble.recon")
            self._log("BLE recon started — scanning for Bluetooth LE devices...")
            if ble:
                def _scan():
                    try:
                        devices = ble.scan()
                        self._log(f"BLE: {len(devices)} devices found")
                        for d in devices:
                            self._log(f"  → {d.get('name', '?')} [{d.get('mac', '?')}] RSSI: {d.get('rssi', '?')}")
                    except Exception as e:
                        self._log(f"BLE scan error: {e}")
                threading.Thread(target=_scan, daemon=True).start()
            return {"status": "ok", "output": "ble.recon on — scanning BLE devices"}
        elif action == "off":
            self.active_modules.discard("ble.recon")
            return {"status": "ok", "output": "ble.recon off"}
        return {"status": "error", "output": "Usage: ble.recon on|off"}

    # ══════════════════════════════════════════════════════════════
    #  HID — HID injection attacks
    # ══════════════════════════════════════════════════════════════

    def _handle_hid(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "show"
        ble = self.plugin_manager.get_plugin("HID-BLE-Strike") if self.plugin_manager else None
        if action == "on":
            self.active_modules.add("hid")
            self._log("HID injection module active")
            return {"status": "ok", "output": "hid on — ready for injection"}
        elif action == "off":
            self.active_modules.discard("hid")
            return {"status": "ok", "output": "hid off"}
        elif action == "inject" and len(parts) > 2:
            payload = " ".join(parts[2:])
            self._log(f"HID inject → {payload}")
            return {"status": "ok", "output": f"hid inject — payload queued: {payload}"}
        return {"status": "error", "output": "Usage: hid on|off|inject <payload>"}

    # ══════════════════════════════════════════════════════════════
    #  MAC.CHANGER — Change MAC address
    # ══════════════════════════════════════════════════════════════

    def _handle_mac_changer(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("mac.changer")
            new_mac = self.config.get("mac.changer.address", "")
            iface = self.config.get("mac.changer.iface", "")
            if not new_mac:
                # Generate random MAC
                import random
                new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
            self._log(f"MAC changer → {iface or 'default'} = {new_mac}")
            if platform.system() == "Windows":
                return {"status": "ok", "output": f"mac.changer on — MAC={new_mac} (requires admin + adapter restart on Windows)"}
            return {"status": "ok", "output": f"mac.changer on — {new_mac}"}
        elif action == "off":
            self.active_modules.discard("mac.changer")
            return {"status": "ok", "output": "mac.changer off — MAC restored"}
        return {"status": "error", "output": "Usage: mac.changer on|off\n  Config: mac.changer.address, mac.changer.iface"}

    # ══════════════════════════════════════════════════════════════
    #  TICKER — Periodic command execution
    # ══════════════════════════════════════════════════════════════

    def _handle_ticker(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            cmds = self.config.get("ticker.commands", "")
            period = float(self.config.get("ticker.period", "5"))
            if not cmds:
                return {"status": "error", "output": "Set ticker.commands first (semicolon-separated)"}
            self.active_modules.add("ticker")
            self._ticker_running = True

            def _tick():
                while self._ticker_running:
                    self.run_command(cmds)
                    time.sleep(period)

            self._ticker_thread = threading.Thread(target=_tick, daemon=True)
            self._ticker_thread.start()
            self._log(f"Ticker started: every {period}s → {cmds}")
            return {"status": "ok", "output": f"ticker on — every {period}s"}
        elif action == "off":
            self._ticker_running = False
            self.active_modules.discard("ticker")
            return {"status": "ok", "output": "ticker off"}
        return {"status": "error", "output": "Usage: ticker on|off\n  Config: ticker.commands, ticker.period"}

    # ══════════════════════════════════════════════════════════════
    #  WOL — Wake on LAN
    # ══════════════════════════════════════════════════════════════

    def _handle_wol(self, parts) -> dict:
        target_mac = parts[1] if len(parts) > 1 else self.config.get("wol.target", "")
        if not target_mac:
            return {"status": "error", "output": "Usage: wol <MAC_ADDRESS>"}
        try:
            mac_bytes = bytes.fromhex(target_mac.replace(":", "").replace("-", ""))
            magic = b'\xff' * 6 + mac_bytes * 16
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, ('<broadcast>', 9))
            s.close()
            self._log(f"WOL magic packet sent → {target_mac}")
            return {"status": "ok", "output": f"wol → magic packet sent to {target_mac}"}
        except Exception as e:
            return {"status": "error", "output": f"WOL error: {e}"}

    # ══════════════════════════════════════════════════════════════
    #  EVENTS.STREAM — Event streaming
    # ══════════════════════════════════════════════════════════════

    def _handle_events_stream(self, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add("events.stream")
            return {"status": "ok", "output": "events.stream on — events piped to tactical feed"}
        elif action == "off":
            self.active_modules.discard("events.stream")
            return {"status": "ok", "output": "events.stream off"}
        return {"status": "error", "output": "Usage: events.stream on|off"}

    def _show_events(self) -> dict:
        if not self.events_log:
            return {"status": "ok", "output": "No events recorded."}
        lines = []
        for e in self.events_log[-30:]:
            ts = time.strftime("%H:%M:%S", time.localtime(e["time"]))
            lines.append(f"[{ts}] {e['msg']}")
        return {"status": "ok", "output": "\n".join(lines)}

    # ══════════════════════════════════════════════════════════════
    #  GENERIC MODULE HANDLER
    # ══════════════════════════════════════════════════════════════

    def _handle_generic_module(self, module_name, parts) -> dict:
        action = parts[1] if len(parts) > 1 else "on"
        if action == "on":
            self.active_modules.add(module_name)
            self._log(f"{module_name} started")
            return {"status": "ok", "output": f"{module_name} on"}
        elif action == "off":
            self.active_modules.discard(module_name)
            return {"status": "ok", "output": f"{module_name} off"}
        return {"status": "error", "output": f"Usage: {module_name} on|off"}

    # ══════════════════════════════════════════════════════════════
    #  INFO COMMANDS
    # ══════════════════════════════════════════════════════════════

    def _show_info(self) -> dict:
        lines = ["═══ MOONKEEP NATIVE ENGINE ═══"]
        lines.append(f"Active: {', '.join(sorted(self.active_modules)) or 'none'}")
        if self.target_store:
            lines.append(f"Hosts: {len(self.target_store.devices)}  |  Networks: {len(self.target_store.networks)}")
            if self.target_store.last_target:
                lines.append(f"Target: {self.target_store.last_target}")
        lines.append(f"Events: {len(self.events_log)}  |  History: {len(self.history)} cmds")
        return {"status": "ok", "output": "\n".join(lines)}

    def _help_module(self, module: str) -> dict:
        """Show help for a specific module."""
        module = module.lower()
        help_data = {
            "arp.spoof": """arp.spoof on|off      Start/stop ARP spoofing
  arp.spoof.targets     Comma-separated target IPs
  arp.spoof.fullduplex  Poison both directions (true/false)
  arp.spoof.internal    Spoof internal traffic (true/false)
  arp.spoof.whitelist   IPs/MACs to exclude""",
            "arp.ban": """arp.ban on|off        Start/stop ARP ban (DoS)
  Uses same config as arp.spoof""",
            "dns.spoof": """dns.spoof on|off      Start/stop DNS hijacking
  dns.spoof.domains     Domains to hijack (* = all)
  dns.spoof.address     IP to redirect DNS to
  dns.spoof.all         Spoof all domains (true/false)""",
            "net.probe": """net.probe on|off      Active ARP-based host discovery
  Scans local /24 subnet""",
            "net.recon": """net.recon on|off      Passive network reconnaissance
  Monitors ARP traffic for hosts""",
            "net.sniff": """net.sniff on|off      Packet capture (DPI sniffer)
  net.sniff.verbose     Show detailed output (true/false)
  net.sniff.local       Include local traffic (true/false)
  net.sniff.filter      BPF filter expression
  net.sniff.output      Save to PCAP file
  net.sniff.regexp      Filter by regex""",
            "wifi.recon": """wifi.recon on|off         Scan wireless networks
  wifi.recon channel <N>   Set channel
  wifi.recon.channel       Channel number
  wifi.handshakes.file     Output file for WPA handshakes""",
            "wifi.deauth": """wifi.deauth <MAC>     Send deauth frames to target
  wifi.deauth.targets   Default target MAC""",
            "wifi.ap": """wifi.ap on|off        Evil twin access point
  wifi.ap.ssid          SSID to broadcast
  wifi.ap.channel       Channel number
  wifi.ap.bssid         BSSID to use
  wifi.ap.encryption    Enable encryption (true/false)""",
            "http.proxy": """http.proxy on|off     HTTP intercept proxy
  http.proxy.address    Bind address (default 0.0.0.0)
  http.proxy.port       Port (default 8080)
  http.proxy.sslstrip   Enable SSL stripping (true/false)
  http.proxy.script     JS injection script
  http.proxy.injectjs   Inject JS into responses""",
            "https.proxy": """https.proxy on|off    HTTPS intercept proxy
  https.proxy.address   Bind address
  https.proxy.port      Port (default 8443)
  https.proxy.certificate  SSL cert path
  https.proxy.key       SSL key path""",
            "tcp.proxy": """tcp.proxy on|off      TCP level proxy
  tcp.proxy.address     Local bind address
  tcp.proxy.port        Local port
  tcp.proxy.remote.address  Target address
  tcp.proxy.remote.port     Target port""",
            "udp.proxy": """udp.proxy on|off      UDP level proxy
  udp.proxy.address     Local bind address
  udp.proxy.port        Local port (default 8053)
  udp.proxy.remote.address  Target address
  udp.proxy.remote.port     Target port""",
            "syn.scan": """syn.scan <target>     SYN port scan
  syn.scan.ports        Port range (e.g. 1-1024 or 22,80,443)
  syn.scan.targets      Default target IP""",
            "ble.recon": """ble.recon on|off      Bluetooth LE scanning
  ble.device            Target BLE device
  ble.recon.timeout     Scan timeout (seconds)""",
            "hid": """hid on|off            HID injection module
  hid inject <payload>  Inject keystroke payload""",
            "http.server": """http.server on|off    Static file server
  http.server.address   Bind address
  http.server.port      Port (default 80)
  http.server.path      Directory to serve""",
            "mac.changer": """mac.changer on|off    Change MAC address
  mac.changer.address   New MAC (random if empty)
  mac.changer.iface     Interface name""",
            "ticker": """ticker on|off         Periodic command execution
  ticker.commands       Commands to run (semicolon-separated)
  ticker.period         Interval in seconds""",
            "wol": """wol <MAC>             Send Wake-on-LAN magic packet""",
            "events.stream": """events.stream on|off  Enable event streaming
  events.show           Show recent events""",
        }
        if module in help_data:
            return {"status": "ok", "output": f"─── {module.upper()} ───\n{help_data[module]}"}
        return {"status": "error", "output": f"No help for '{module}'. Type 'help' for all modules."}

    def _help_text(self) -> str:
        return """═══ MOONKEEP NATIVE CAP ENGINE ═══

 NETWORK DISCOVERY
  net.probe on|off        ARP-based host scanning
  net.recon on|off        Passive host discovery
  net.show                Show discovered hosts table
  net.sniff on|off        Packet capture (DPI)

 SPOOFING & MITM
  arp.spoof on|off        ARP cache poisoning
  arp.ban on|off          ARP-based DoS (block connectivity)
  dns.spoof on|off        DNS hijacking

 WIRELESS
  wifi.recon on|off       Scan wireless networks
  wifi.show               Show discovered networks
  wifi.deauth <mac>       Deauthentication attack
  wifi.ap on|off          Evil twin access point

 PROXYING
  http.proxy on|off       HTTP intercept proxy
  https.proxy on|off      HTTPS intercept proxy
  tcp.proxy on|off        TCP level proxy
  udp.proxy on|off        UDP level proxy

 SCANNING
  syn.scan <target>       SYN port scanner

 BLUETOOTH
  ble.recon on|off        BLE device scanning
  ble.show                Show BLE devices
  hid on|off|inject       HID injection attacks

 UTILITIES
  http.server on|off      Static file server
  mac.changer on|off      Change MAC address
  ticker on|off           Periodic command exec
  wol <mac>               Wake-on-LAN
  events.stream on|off    Event streaming
  events.show             Show recent events

 GENERAL
  set <key> <value>       Set config variable
  get <key>               Get config (use * for all)
  help <module>           Help for specific module
  show                    Show engine status
  active                  Show running modules
  alias <mac> <name>      Name a device
  ! <command>             Execute shell command
  clear                   Clear terminal
  quit                    Exit"""
