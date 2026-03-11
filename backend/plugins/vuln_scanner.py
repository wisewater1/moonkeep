from core.plugin_manager import BasePlugin
import socket
import asyncio

class VulnScannerPlugin(BasePlugin):
    def __init__(self):
        self.vulns_db = {
            "SSH": {"port": 22, "id": "CVE-2024-6387", "name": "regreSSHion"},
            "SMB": {"port": 445, "id": "CVE-2017-0144", "name": "EternalBlue"},
            "HTTP": {"port": 80, "id": "CVE-2021-41773", "name": "Apache Path Traversal"}
        }

    @property
    def name(self) -> str:
        return "Vuln-Scanner"

    @property
    def description(self) -> str:
        return "Deep Vulnerability & CVE Assessment"

    async def start(self):
        print("Vuln Scanner initialized.")

    async def stop(self):
        print("Vuln Scanner suspended.")

    async def scan_target(self, ip):
        results = []
        for service, info in self.vulns_db.items():
            port = info["port"]
            if await self._check_port(ip, port):
                results.append({
                    "service": service,
                    "cve": info["id"],
                    "name": info["name"],
                    "severity": "HIGH" if service in ["SMB", "SSH"] else "MEDIUM"
                })
        return results

    async def _check_port(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
