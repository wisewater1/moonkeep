from core.plugin_manager import BasePlugin
import socket
import asyncio
import re
import ssl

class VulnScannerPlugin(BasePlugin):
    def __init__(self):
        # Expanded CVE database with version-based matching
        self.vulns_db = {
            "SSH": [
                {"port": 22, "cve": "CVE-2024-6387", "name": "regreSSHion", "severity": "CRITICAL",
                 "pattern": r"OpenSSH[_ ]([89]\.\d)", "desc": "Race condition in sshd signal handler allows unauthenticated RCE"},
                {"port": 22, "cve": "CVE-2023-38408", "name": "SSH Agent Forwarding RCE", "severity": "HIGH",
                 "pattern": r"OpenSSH", "desc": "Remote code execution via forwarded agent socket"},
            ],
            "SMB": [
                {"port": 445, "cve": "CVE-2017-0144", "name": "EternalBlue", "severity": "CRITICAL",
                 "pattern": None, "desc": "SMBv1 remote code execution (WannaCry/NotPetya)"},
                {"port": 445, "cve": "CVE-2020-0796", "name": "SMBGhost", "severity": "CRITICAL",
                 "pattern": None, "desc": "SMBv3 compression buffer overflow — pre-auth RCE"},
            ],
            "HTTP": [
                {"port": 80, "cve": "CVE-2021-41773", "name": "Apache Path Traversal", "severity": "CRITICAL",
                 "pattern": r"Apache/2\.4\.(49|50)", "desc": "Path traversal and RCE in Apache 2.4.49-50"},
                {"port": 80, "cve": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset", "severity": "HIGH",
                 "pattern": None, "desc": "HTTP/2 protocol DoS via rapid stream reset"},
                {"port": 80, "cve": "CVE-2024-27198", "name": "JetBrains TeamCity Auth Bypass", "severity": "CRITICAL",
                 "pattern": r"TeamCity", "desc": "Authentication bypass leading to full server compromise"},
            ],
            "HTTPS": [
                {"port": 443, "cve": "CVE-2014-0160", "name": "Heartbleed", "severity": "CRITICAL",
                 "pattern": None, "desc": "OpenSSL TLS heartbeat buffer over-read"},
                {"port": 443, "cve": "CVE-2022-1388", "name": "F5 BIG-IP Auth Bypass", "severity": "CRITICAL",
                 "pattern": r"BIG-IP", "desc": "iControl REST authentication bypass — unauthenticated RCE"},
            ],
            "RDP": [
                {"port": 3389, "cve": "CVE-2019-0708", "name": "BlueKeep", "severity": "CRITICAL",
                 "pattern": None, "desc": "Pre-auth RCE in RDP — wormable"},
            ],
            "MySQL": [
                {"port": 3306, "cve": "CVE-2012-2122", "name": "MySQL Auth Bypass", "severity": "HIGH",
                 "pattern": r"5\.[0-5]\.", "desc": "Authentication bypass via timing attack (~1/256 chance per attempt)"},
            ],
            "Redis": [
                {"port": 6379, "cve": "CVE-2022-0543", "name": "Redis Lua Sandbox Escape", "severity": "CRITICAL",
                 "pattern": None, "desc": "Lua sandbox escape leading to RCE on Debian-based Redis"},
            ],
            "FTP": [
                {"port": 21, "cve": "CVE-2015-3306", "name": "ProFTPD mod_copy RCE", "severity": "CRITICAL",
                 "pattern": r"ProFTPD", "desc": "Arbitrary file copy leading to remote code execution"},
                {"port": 21, "cve": "CVE-2011-2523", "name": "vsftpd 2.3.4 Backdoor", "severity": "CRITICAL",
                 "pattern": r"vsftpd 2\.3\.4", "desc": "Intentional backdoor — trigger with :) in username"},
            ],
            "Telnet": [
                {"port": 23, "cve": "MOONKEEP-001", "name": "Cleartext Telnet", "severity": "HIGH",
                 "pattern": None, "desc": "Telnet transmits credentials in cleartext — trivial to intercept"},
            ],
            "DNS": [
                {"port": 53, "cve": "CVE-2020-1350", "name": "SIGRed", "severity": "CRITICAL",
                 "pattern": None, "desc": "Windows DNS Server RCE via malformed SIG record (wormable)"},
            ],
            "LDAP": [
                {"port": 389, "cve": "CVE-2021-44228", "name": "Log4Shell", "severity": "CRITICAL",
                 "pattern": None, "desc": "JNDI injection via LDAP — unauthenticated RCE in Java apps"},
            ],
        }
        self.results = []

    @property
    def name(self) -> str:
        return "Vuln-Scanner"

    @property
    def description(self) -> str:
        return "Deep Vulnerability & CVE Assessment"

    async def start(self):
        self.results = []
        self.emit("INFO", {"msg": "Vulnerability scanner initialized with extended CVE database"})

    async def stop(self):
        pass

    async def scan_target(self, ip):
        """Full vulnerability scan with banner grabbing and version detection."""
        self.results = []
        self.emit("INFO", {"msg": f"Deep scanning {ip} across {sum(len(v) for v in self.vulns_db.values())} CVE signatures..."})

        tasks = []
        for service, vulns in self.vulns_db.items():
            for vuln in vulns:
                tasks.append(self._check_vuln(ip, service, vuln))

        findings = await asyncio.gather(*tasks)
        self.results = [f for f in findings if f is not None]

        # Emit each finding as a WebSocket event
        for r in self.results:
            self.emit("VULN_RESULT", {
                "cve": r["cve"], "severity": r["severity"],
                "desc": f"{r['name']}: {r['desc']}", "service": r["service"],
                "port": r["port"], "banner": r.get("banner", "")
            })

        self.emit("SUCCESS", {"msg": f"Scan complete: {len(self.results)} potential vulnerabilities on {ip}"})
        return self.results

    async def _check_vuln(self, ip, service, vuln):
        """Check if a specific port is open and grab its banner for version matching."""
        port = vuln["port"]
        try:
            if service == "HTTPS":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                conn = asyncio.open_connection(ip, port, ssl=ssl_ctx)
            else:
                conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)

            banner = ""
            try:
                if service in ("HTTP", "HTTPS"):
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    await writer.drain()
                elif service == "FTP":
                    pass
                elif service == "SMTP":
                    pass

                banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except (asyncio.TimeoutError, Exception):
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            # Version matching
            matched = True
            if vuln.get("pattern") and banner:
                matched = bool(re.search(vuln["pattern"], banner, re.IGNORECASE))
            elif vuln.get("pattern") and not banner:
                matched = True  # Can't confirm version — report as potential

            if matched:
                return {
                    "service": service,
                    "port": port,
                    "cve": vuln["cve"],
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "desc": vuln["desc"],
                    "banner": banner[:200] if banner else "Port open, no banner",
                    "confirmed": bool(banner and vuln.get("pattern") and re.search(vuln["pattern"], banner, re.IGNORECASE))
                }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception:
            return None

    async def quick_scan(self, ip, ports=None):
        """Quick port sweep — returns open ports without CVE matching."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443,
                     445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
                     8080, 8443, 9200, 27017]
        open_ports = []
        tasks = [self._check_port(ip, p) for p in ports]
        results = await asyncio.gather(*tasks)
        for port, is_open in zip(ports, results):
            if is_open:
                open_ports.append(port)
        return open_ports

    async def _check_port(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def get_results(self):
        return self.results
