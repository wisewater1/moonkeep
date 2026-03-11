from core.plugin_manager import BasePlugin
import socket
import threading
import select

class ProxyPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.port = 8080
        self.server: socket.socket | None = None
        self.script: str | None = None

    @property
    def name(self) -> str:
        return "Proxy"

    @property
    def description(self) -> str:
        return "Scriptable HTTP/HTTPS Proxy"

    async def start(self, port=8080, script=None):
        if self.running:
            return
        
        self.port = port
        self.script = script
        self.running = True
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', self.port))
        self.server.listen(100)
        
        thread = threading.Thread(target=self._run_server)
        thread.daemon = True
        thread.start()
        print(f"Proxy started on port {self.port}")

    async def stop(self):
        self.running = False
        if self.server:
            self.server.close()
        print("Proxy stopped")

    def _run_server(self):
        while self.running and self.server:
            try:
                client_sock, addr = self.server.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,)).start()
            except:
                break

    def _handle_client(self, client_sock):
        try:
            request = client_sock.recv(4096)
            if not request:
                client_sock.close()
                return

            # Basic parsing to find host
            lines = request.decode('utf-8', errors='ignore').split('\n')
            host = ""
            for line in lines:
                if line.startswith("Host:"):
                    host = line.split(":")[1].strip()
                    break
            
            if not host:
                client_sock.close()
                return

            # Connect to remote server
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.connect((host, 80))
            remote_sock.sendall(request)

            # Simple relay
            while self.running:
                r, w, x = select.select([client_sock, remote_sock], [], [], 1)
                if client_sock in r:
                    data = client_sock.recv(4096)
                    if not data: break
                    remote_sock.sendall(data)
                if remote_sock in r:
                    data = remote_sock.recv(4096)
                    if not data: break
                    # Potential for script manipulation here
                    if self.script:
                        data = self._apply_script(data)
                    client_sock.sendall(data)

        except Exception as e:
            print(f"Proxy error: {e}")
        finally:
            client_sock.close()
            try: remote_sock.close()
            except: pass

    def _apply_script(self, data):
        # Placeholder for scripting logic
        return data
