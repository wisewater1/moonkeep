from core.plugin_manager import BasePlugin
import asyncio
import re
import socket
import ssl
import subprocess


class VulnScannerPlugin(BasePlugin):
    def __init__(self):
        self.vulns: list = []
        self.vulns_db = {
            "SSH": {
                "port": 22, "id": "CVE-2024-6387", "name": "regreSSHion", "cvss": 8.1,
                "banner_re": r"OpenSSH[_ ]([\d.p]+)",
                "affected_re": r"^(8\.[5-9]|9\.[0-7])",
            },
            "SSH_FORWARD": {
                "port": 22, "id": "CVE-2014-9278", "name": "OpenSSH Forced Command Bypass", "cvss": 4.0,
                "banner_re": r"OpenSSH[_ ]([\d.p]+)",
                "affected_re": r"^([1-5]\.|6\.[0-3])",
            },
            "SMB": {
                "port": 445, "id": "CVE-2017-0144", "name": "EternalBlue", "cvss": 9.8,
                "banner_re": None, "affected_re": None,
            },
            "HTTP": {
                "port": 80, "id": "CVE-2021-41773", "name": "Apache Path Traversal", "cvss": 7.5,
                "banner_re": r"Apache/([\d.]+)",
                "affected_re": r"^2\.4\.49$",
            },
            "HTTP2": {
                "port": 80, "id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset DoS", "cvss": 7.5,
                "banner_re": r"Apache/([\d.]+)|nginx/([\d.]+)|Server: ([\w/. ]+)",
                "affected_re": None,
            },
            "HTTPS": {
                "port": 443, "id": "CVE-2021-22205", "name": "GitLab Unauthenticated RCE via Exif", "cvss": 10.0,
                "banner_re": None, "affected_re": None,
            },
            "PHP": {
                "port": 80, "id": "CVE-2012-1823", "name": "PHP-CGI Argument Injection", "cvss": 7.5,
                "banner_re": r"PHP/([\d.]+)",
                "affected_re": r"^[567]\.",
            },
            "FTP": {
                "port": 21, "id": "CVE-2011-2523", "name": "vsftpd 2.3.4 Backdoor", "cvss": 10.0,
                "banner_re": r"vsftpd ([\d.]+)",
                "affected_re": r"^2\.3\.4$",
            },
            "TELNET": {
                "port": 23, "id": "CVE-2023-27898", "name": "Telnet Cleartext Credential Exposure", "cvss": 7.5,
                "banner_re": None, "affected_re": None,
            },
            "SMTP": {
                "port": 25, "id": "CVE-2010-4479", "name": "Postfix SMTP Open Relay", "cvss": 5.0,
                "banner_re": r"Postfix|ESMTP ([\w.]+)",
                "affected_re": None,
            },
            "DNS": {
                "port": 53, "id": "CVE-2008-1447", "name": "DNS Cache Poisoning (Kaminsky)", "cvss": 6.8,
                "banner_re": None, "affected_re": None,
            },
            "RDP": {
                "port": 3389, "id": "CVE-2019-0708", "name": "BlueKeep RCE", "cvss": 9.8,
                "banner_re": None, "affected_re": None,
            },
            "MYSQL": {
                "port": 3306, "id": "CVE-2019-12840", "name": "MySQL User-Defined Function RCE", "cvss": 8.8,
                "banner_re": r"([\d.]+)-MySQL|mysql_([\d.]+)",
                "affected_re": None,
            },
            "POSTGRESQL": {
                "port": 5432, "id": "CVE-2019-9193", "name": "PostgreSQL COPY TO/FROM PROGRAM", "cvss": 7.2,
                "banner_re": None, "affected_re": None,
            },
            "REDIS": {
                "port": 6379, "id": "CVE-2021-32648", "name": "Redis Unauthenticated Access", "cvss": 9.8,
                "banner_re": r"redis_version:([\d.]+)",
                "affected_re": None,
            },
            "MONGODB": {
                "port": 27017, "id": "CVE-2021-25735", "name": "MongoDB Exposed Without Auth", "cvss": 7.5,
                "banner_re": None, "affected_re": None,
            },
            "ELASTICSEARCH": {
                "port": 9200, "id": "CVE-2021-22144", "name": "Elasticsearch Unauth Info Disclosure", "cvss": 6.5,
                "banner_re": None, "affected_re": None,
            },
        }
        self.results = []

    @property
    def name(self) -> str:
        return "Vuln-Scanner"

    @property
    def description(self) -> str:
        return "Deep Vulnerability & CVE Assessment"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def category(self) -> str:
        return "recon"

    async def start(self):
        self.results = []
        self.emit("INFO", {"msg": "Vulnerability scanner initialized with extended CVE database"})

    async def stop(self):
        pass

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        return "LOW"

    async def _probe_port(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Returns 'open', 'closed', or 'filtered'."""
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except (asyncio.TimeoutError, OSError):
            return "filtered"

    async def _check_port(self, ip: str, port: int) -> bool:
        return await self._probe_port(ip, port) == "open"

    @staticmethod
    def _get_probe(service: str) -> bytes | None:
        probes = {
            "HTTP":  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            "HTTP2": b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            "PHP":   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            "REDIS": b"INFO server\r\n",
        }
        return probes.get(service)

    async def _grab_banner(self, ip: str, port: int, probe: bytes | None = None,
                           timeout: float = 2.0) -> str:
        """Connect, optionally send probe, return first 1 KB of response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    @staticmethod
    def _parse_version(banner: str, banner_re: str | None) -> str | None:
        if not banner:
            return None
        if banner_re:
            m = re.search(banner_re, banner)
            if m:
                # Return first non-None group
                return next((g for g in m.groups() if g), None) if m.lastindex else m.group(0)
        # Generic fallbacks
        for pat in (r"/([\d]+\.[\d]+\.[\d]+)", r"v([\d]+\.[\d]+\.[\d]+)", r"([\d]+\.[\d]+\.[\d]+)"):
            m = re.search(pat, banner)
            if m:
                return m.group(1)
        return None

    async def _fingerprint_os(self, ip: str) -> dict:
        """TTL-based OS guess via ICMP ping."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
            ttl_match = re.search(r"ttl=(\d+)", stdout.decode("utf-8", errors="replace"), re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return {"os": "Linux/macOS", "ttl": ttl, "confidence": "medium"}
                elif ttl <= 128:
                    return {"os": "Windows", "ttl": ttl, "confidence": "medium"}
                else:
                    return {"os": "Network Device (Cisco/HP)", "ttl": ttl, "confidence": "low"}
        except Exception:
            pass
        return {"os": "Unknown", "ttl": None, "confidence": "none"}

    async def _analyze_ssl(self, ip: str, port: int = 443) -> dict:
        """Inspect TLS: protocol, cipher, cert metadata, weak config flags."""
        def _connect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=3)
            wrapped = ctx.wrap_socket(raw, server_hostname=ip)
            cert   = wrapped.getpeercert()
            cipher = wrapped.cipher()
            proto  = wrapped.version()
            wrapped.close()
            return cert, cipher, proto

        try:
            cert, cipher, proto = await asyncio.to_thread(_connect)
            subject = dict(x[0] for x in (cert.get("subject") or []))
            issuer  = dict(x[0] for x in (cert.get("issuer")  or []))
            san     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            cipher_name = cipher[0] if cipher else ""
            return {
                "tls":           True,
                "protocol":      proto,
                "cipher_name":   cipher_name,
                "cipher_bits":   cipher[2] if cipher else None,
                "subject":       subject,
                "issuer":        issuer,
                "not_after":     cert.get("notAfter"),
                "san":           san,
                "weak_protocol": proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"),
                "weak_cipher":   any(w in cipher_name for w in ("RC4", "NULL", "EXPORT", "DES")),
            }
        except Exception as exc:
            return {"tls": False, "error": str(exc)}

    @staticmethod
    def _snmp_get(ip: str, oid_bytes: bytes, community: str = "public", timeout: float = 2.0) -> str | None:
        """Build and send a raw SNMPv1 GET; return value string or None."""
        comm = community.encode()

        # VarBind: OID TLV + Null
        null     = b"\x05\x00"
        varbind  = b"\x30" + bytes([len(oid_bytes) + len(null)]) + oid_bytes + null
        varbinds = b"\x30" + bytes([len(varbind)]) + varbind

        # GetRequest PDU (0xa0)
        req_id   = b"\x02\x04\x00\x00\x00\x01"
        err_s    = b"\x02\x01\x00"
        err_i    = b"\x02\x01\x00"
        pdu_body = req_id + err_s + err_i + varbinds
        pdu      = b"\xa0" + bytes([len(pdu_body)]) + pdu_body

        # Message
        version  = b"\x02\x01\x00"
        comm_tlv = b"\x04" + bytes([len(comm)]) + comm
        msg_body = version + comm_tlv + pdu
        msg      = b"\x30" + bytes([len(msg_body)]) + msg_body

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(msg, (ip, 161))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            # Find OID in response, read the immediately following TLV
            idx = resp.find(oid_bytes)
            if idx != -1:
                idx += len(oid_bytes)
                if idx + 2 <= len(resp):
                    vtype  = resp[idx]
                    vlen   = resp[idx + 1]
                    vval   = resp[idx + 2: idx + 2 + vlen]
                    if vtype == 0x04:                    # OctetString
                        return vval.decode("utf-8", errors="replace")
                    elif vtype == 0x02:                  # Integer
                        result = 0
                        for b in vval:
                            result = (result << 8) | b
                        return str(result)
        except Exception:
            pass
        return None

    async def snmp_enumerate(self, ip: str) -> dict:
        """Walk key SNMP OIDs; try 'public' then 'private' community strings."""
        oids = {
            "sysDescr":    b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00",
            "sysName":     b"\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00",
            "sysLocation": b"\x06\x08\x2b\x06\x01\x02\x01\x01\x06\x00",
        }
        results = {}
        for field, oid in oids.items():
            for community in ("public", "private"):
                val = await asyncio.to_thread(self._snmp_get, ip, oid, community)
                if val:
                    results[field] = val.strip()
                    break
        return results

    async def scan_target(self, ip: str) -> list:
        results = []
        os_info = await self._fingerprint_os(ip)

        for service, info in self.vulns_db.items():
            port  = info["port"]
            state = await self._probe_port(ip, port)

            if state == "filtered":
                results.append({
                    "service": service, "port": port, "state": "filtered",
                    "cve": None, "name": "Port filtered (firewall/ACL)",
                    "cvss": 0.0, "severity": "INFO",
                    "banner": None, "version": None,
                    "version_matched_cve": False, "os_fingerprint": os_info,
                })
                continue
            if state == "closed":
                continue

            # Open — grab banner and detect version
            probe   = self._get_probe(service)
            banner  = await self._grab_banner(ip, port, probe=probe)
            version = self._parse_version(banner, info.get("banner_re"))

            # SSL inspection on HTTPS ports
            ssl_data = {}
            if port in (443, 8443) or service == "HTTPS":
                ssl_data = await self._analyze_ssl(ip, port)

            # CVE applies only if version matches affected range (when pattern exists)
            affected_re   = info.get("affected_re")
            version_match = True
            if affected_re and version:
                version_match = bool(re.search(affected_re, version))
            elif affected_re and not version:
                version_match = False   # can't confirm — don't false-positive

            cvss     = info["cvss"] if version_match else 0.0
            severity = self._cvss_to_severity(cvss) if version_match else "INFO"

            result = {
                "service":           service,
                "port":              port,
                "state":             "open",
                "cve":               info["id"] if version_match else None,
                "name":              info["name"] if version_match else f"{service} service detected (version unconfirmed)",
                "cvss":              cvss,
                "severity":          severity,
                "banner":            banner[:200] if banner else None,
                "version":           version,
                "version_matched_cve": version_match,
                "os_fingerprint":    os_info,
            }
            if ssl_data:
                result["ssl"] = ssl_data
            results.append(result)

        # SNMP enumeration (separate from TCP port loop)
        snmp_data = await self.snmp_enumerate(ip)
        if snmp_data:
            results.append({
                "service": "SNMP", "port": 161, "state": "open",
                "cve": "CVE-2008-0960", "name": "SNMP Unauthenticated Information Disclosure",
                "cvss": 10.0, "severity": "CRITICAL",
                "banner": str(snmp_data)[:200], "version": snmp_data.get("sysDescr", "")[:100],
                "version_matched_cve": True, "os_fingerprint": os_info,
                "snmp_data": snmp_data,
            })

        if results:
            existing = {(v.get("ip",""), v.get("cve"), v.get("port")) for v in self.vulns}
            for v in results:
                v["ip"] = ip
                if (ip, v.get("cve"), v.get("port")) not in existing:
                    self.vulns.append(v)
                    existing.add((ip, v.get("cve"), v.get("port")))
            self.emit("VULN_RESULT", {"ip": ip, "count": len(results), "findings": results})
            if self.target_store and self.target_store.active_campaign:
                for v in results:
                    if v.get("cvss", 0) >= 7.0:
                        self.target_store.cm.save_finding(
                            self.target_store.active_campaign,
                            "VULNERABILITY", ip,
                            f"{v['cve']} — {v['name']} (CVSS {v['cvss']}, {v['severity']})"
                        )
        return results
