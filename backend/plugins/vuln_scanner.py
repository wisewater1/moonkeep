from core.plugin_manager import BasePlugin
import asyncio


class VulnScannerPlugin(BasePlugin):
    def __init__(self):
        self.vulns_db = {
            "SSH":           {"port": 22,    "id": "CVE-2024-6387",  "name": "regreSSHion",                          "cvss": 8.1},
            "SSH_FORWARD":   {"port": 22,    "id": "CVE-2014-9278",  "name": "OpenSSH Forced Command Bypass",        "cvss": 4.0},
            "SMB":           {"port": 445,   "id": "CVE-2017-0144",  "name": "EternalBlue",                          "cvss": 9.8},
            "HTTP":          {"port": 80,    "id": "CVE-2021-41773", "name": "Apache Path Traversal",                "cvss": 7.5},
            "HTTP2":         {"port": 80,    "id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset DoS",               "cvss": 7.5},
            "HTTPS":         {"port": 443,   "id": "CVE-2021-22205", "name": "GitLab Unauthenticated RCE via Exif",  "cvss": 10.0},
            "PHP":           {"port": 80,    "id": "CVE-2012-1823",  "name": "PHP-CGI Argument Injection",           "cvss": 7.5},
            "FTP":           {"port": 21,    "id": "CVE-2011-2523",  "name": "vsftpd 2.3.4 Backdoor",               "cvss": 10.0},
            "TELNET":        {"port": 23,    "id": "CVE-2023-27898", "name": "Telnet Cleartext Credential Exposure", "cvss": 7.5},
            "SMTP":          {"port": 25,    "id": "CVE-2010-4479",  "name": "Postfix SMTP Open Relay",              "cvss": 5.0},
            "DNS":           {"port": 53,    "id": "CVE-2008-1447",  "name": "DNS Cache Poisoning (Kaminsky)",       "cvss": 6.8},
            "RDP":           {"port": 3389,  "id": "CVE-2019-0708",  "name": "BlueKeep RCE",                        "cvss": 9.8},
            "MYSQL":         {"port": 3306,  "id": "CVE-2019-12840", "name": "MySQL User-Defined Function RCE",      "cvss": 8.8},
            "POSTGRESQL":    {"port": 5432,  "id": "CVE-2019-9193",  "name": "PostgreSQL COPY TO/FROM PROGRAM",      "cvss": 7.2},
            "REDIS":         {"port": 6379,  "id": "CVE-2021-32648", "name": "Redis Unauthenticated Access",         "cvss": 9.8},
            "MONGODB":       {"port": 27017, "id": "CVE-2021-25735", "name": "MongoDB Exposed Without Auth",         "cvss": 7.5},
            "ELASTICSEARCH": {"port": 9200,  "id": "CVE-2021-22144", "name": "Elasticsearch Unauth Info Disclosure", "cvss": 6.5},
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

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        return "LOW"

    async def scan_target(self, ip):
        results = []
        for service, info in self.vulns_db.items():
            if await self._check_port(ip, info["port"]):
                cvss = info["cvss"]
                results.append({
                    "service":  service,
                    "cve":      info["id"],
                    "name":     info["name"],
                    "cvss":     cvss,
                    "severity": self._cvss_to_severity(cvss),
                })
        return results

    async def _check_port(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
