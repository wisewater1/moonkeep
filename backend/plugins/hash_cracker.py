from core.plugin_manager import BasePlugin
import asyncio
import os
import re
import subprocess


_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/john/password.lst",
    "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
]

_HASH_SIGNATURES = {
    r"^\$6\$.{8,}\$.{86}$":    "sha512crypt",
    r"^\$5\$.{8,}\$.{43}$":    "sha256crypt",
    r"^\$1\$.{8,}\$.{22}$":    "md5crypt",
    r"^\$2[aby]\$\d{2}\$.{53}$": "bcrypt",
    r"^[0-9a-fA-F]{32}$":      "ntlm",   # or md5 — hashcat handles both
    r"^[0-9a-fA-F]{40}$":      "sha1",
    r"^[0-9a-fA-F]{64}$":      "sha256",
    r"^[0-9a-fA-F]{128}$":     "sha512",
    r"^[0-9a-fA-F]{16}$":      "lm",
}

_HASHCAT_MODES = {
    "ntlm":        1000,
    "md5":         0,
    "sha1":        100,
    "sha256":      1400,
    "sha512":      1700,
    "sha512crypt": 1800,
    "sha256crypt": 7400,
    "md5crypt":    500,
    "bcrypt":      3200,
    "lm":          3000,
    "wpa2":        2500,   # for .hccapx
    "wpa2_pmkid":  22000,  # for .hc22000
}


class HashCrackerPlugin(BasePlugin):
    def __init__(self):
        self.results: list[dict] = []
        self._queue: list[dict] = []  # pending crack jobs

    @property
    def name(self) -> str:
        return "Hash-Cracker"

    @property
    def description(self) -> str:
        return "Multi-Format Hash & WPA2 Cracker (hashcat/john)"

    async def start(self):
        print("Hash-Cracker: initialized.")

    async def stop(self):
        pass

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def crack_hash(self, hash_str: str, hint: str = "") -> dict | None:
        """Crack a single hash string. hint='ntlm'|'sha1'|... overrides auto-detect."""
        hash_type = hint or self._detect_type(hash_str)
        if not hash_type:
            self.emit("WARN", {"msg": f"Hash-Cracker: unknown hash format: {hash_str[:20]}"})
            return None
        result = await asyncio.to_thread(self._crack_with_hashcat, hash_str, hash_type)
        if result is None:
            result = await asyncio.to_thread(self._crack_with_john, hash_str, hash_type)
        if result:
            entry = {"hash": hash_str[:60], "type": hash_type, "password": result}
            self.results.append(entry)
            self.emit("HASH_CRACKED", entry)
            if self.target_store:
                self.target_store.save_credential("Hash-Cracker", result)
            return entry
        self.emit("HASH_UNCRACKED", {"hash": hash_str[:60], "type": hash_type})
        return None

    async def crack_shadow(self, shadow_path: str) -> list[dict]:
        """Parse /etc/shadow and crack all non-locked hashes."""
        cracked = []
        try:
            with open(shadow_path, "r", errors="ignore") as fh:
                for line in fh:
                    parts = line.strip().split(":")
                    if len(parts) < 2:
                        continue
                    user, hash_str = parts[0], parts[1]
                    if not hash_str or hash_str in ("*", "!", "x", ""):
                        continue
                    result = await self.crack_hash(hash_str)
                    if result:
                        result["user"] = user
                        cracked.append(result)
        except Exception as exc:
            self.emit("ERROR", {"msg": f"Hash-Cracker shadow read: {exc}"})
        return cracked

    async def crack_pcap(self, pcap_path: str, bssid: str = "") -> dict | None:
        """Convert WPA2 pcap to hashcat format and crack."""
        if not os.path.exists(pcap_path):
            return None
        hc22000 = pcap_path + ".hc22000"
        converted = await asyncio.to_thread(self._convert_pcap, pcap_path, hc22000)
        if not converted:
            # Try legacy .hccapx via cap2hccapx
            hccapx = pcap_path + ".hccapx"
            converted = await asyncio.to_thread(self._convert_pcap_legacy, pcap_path, hccapx)
            if not converted:
                return None
            result = await asyncio.to_thread(self._crack_with_hashcat, hccapx, "wpa2")
        else:
            result = await asyncio.to_thread(self._crack_with_hashcat, hc22000, "wpa2_pmkid")

        if result:
            entry = {"pcap": pcap_path, "bssid": bssid, "type": "wpa2", "password": result}
            self.results.append(entry)
            self.emit("HASH_CRACKED", entry)
            if self.target_store:
                self.target_store.save_credential("Hash-Cracker:WPA2", f"{bssid}:{result}")
            return entry
        return None

    # ------------------------------------------------------------------
    # Hash type detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_type(h: str) -> str | None:
        h = h.strip()
        for pattern, htype in _HASH_SIGNATURES.items():
            if re.match(pattern, h):
                return htype
        return None

    # ------------------------------------------------------------------
    # Cracking backends
    # ------------------------------------------------------------------

    def _crack_with_hashcat(self, target: str, hash_type: str) -> str | None:
        if not self._cmd_exists("hashcat"):
            return None
        mode = _HASHCAT_MODES.get(hash_type)
        if mode is None:
            return None
        for wordlist in _WORDLISTS:
            if not os.path.exists(wordlist):
                continue
            try:
                result = subprocess.run(
                    ["hashcat", "-m", str(mode), "-a", "0",
                     "--quiet", "--potfile-disable",
                     target, wordlist],
                    capture_output=True, text=True, timeout=300,
                )
                # Parse cracked line: hash:password
                for line in result.stdout.splitlines():
                    if ":" in line and not line.startswith("["):
                        parts = line.rsplit(":", 1)
                        if len(parts) == 2:
                            return parts[1]
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        return None

    def _crack_with_john(self, target: str, hash_type: str) -> str | None:
        if not self._cmd_exists("john"):
            return None
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as tmp:
            tmp.write(target + "\n")
            tmp_path = tmp.name
        try:
            for wordlist in _WORDLISTS:
                if not os.path.exists(wordlist):
                    continue
                try:
                    subprocess.run(
                        ["john", f"--wordlist={wordlist}", tmp_path],
                        capture_output=True, timeout=180,
                    )
                    show = subprocess.run(
                        ["john", "--show", tmp_path],
                        capture_output=True, text=True, timeout=10,
                    )
                    for line in show.stdout.splitlines():
                        if ":" in line:
                            parts = line.split(":", 1)
                            if len(parts) == 2 and parts[1]:
                                return parts[1]
                except subprocess.TimeoutExpired:
                    pass
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return None

    @staticmethod
    def _convert_pcap(pcap: str, out: str) -> bool:
        """Convert .pcap to hashcat 22000 format via hcxtools."""
        if not HashCrackerPlugin._cmd_exists("hcxpcapngtool"):
            return False
        try:
            r = subprocess.run(
                ["hcxpcapngtool", "-o", out, pcap],
                capture_output=True, timeout=30,
            )
            return r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0
        except Exception:
            return False

    @staticmethod
    def _convert_pcap_legacy(pcap: str, out: str) -> bool:
        if not HashCrackerPlugin._cmd_exists("cap2hccapx"):
            return False
        try:
            r = subprocess.run(
                ["cap2hccapx", pcap, out],
                capture_output=True, timeout=30,
            )
            return r.returncode == 0 and os.path.exists(out)
        except Exception:
            return False

    @staticmethod
    def _cmd_exists(cmd: str) -> bool:
        import shutil
        return shutil.which(cmd) is not None
