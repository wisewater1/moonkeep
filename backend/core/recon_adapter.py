import asyncio
import subprocess
import os
import threading
import time

class ReconAdapter:
    def __init__(self):
        self.process = None
        self.output_queue = asyncio.Queue()
        self.loop = asyncio.get_event_loop()
        self.is_running = False

    def start(self):
        if self.process and self.process.poll() is None:
            return  # Already running

        # Path to Python in the virtual environment
        python_exe = os.path.join(os.getcwd(), 'venv', 'Scripts', 'python.exe')
        recon_ng_path = os.path.join(os.getcwd(), 'recon-ng', 'recon-ng')

        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'

        self.process = subprocess.Popen(
            [python_exe, recon_ng_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            bufsize=0, # Unbuffered
            universal_newlines=False # Read bytes so we don't mess up ANSI codes
        )
        self.is_running = True

        # Start thread to read output
        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()

    def _read_output(self):
        while self.is_running and self.process and self.process.poll() is None:
            try:
                # Read raw chunks of bytes straight from the FD to avoid Python line buffering
                fd = self.process.stdout.fileno()
                chunk = os.read(fd, 1024)
                if chunk:
                    # xterm needs \r\n to line feed and carriage return properly.
                    # replace lone \n with \r\n
                    text = chunk.decode('utf-8', 'ignore')
                    text = text.replace('\r\n', '\n').replace('\n', '\r\n')
                    
                    self.loop.call_soon_threadsafe(self.output_queue.put_nowait, text.encode('utf-8'))
                else:
                    time.sleep(0.01)
            except Exception as e:
                print(f"[ReconAdapter] Read error: {e}")
                break
        self.is_running = False

    async def get_output(self):
        """Yields output from recon-ng as it becomes available."""
        while self.is_running:
            try:
                chunk = await asyncio.wait_for(self.output_queue.get(), timeout=1.0)
                yield chunk
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    def send_input(self, data: str):
        """Sends input to recon-ng."""
        if self.process and self.process.poll() is None:
            try:
                # Map xterm.js \r (enter key) to \n for python subprocess readline()
                data = data.replace('\r', '\n')
                self.process.stdin.write(data.encode('utf-8'))
                self.process.stdin.flush()
            except Exception as e:
                print(f"[ReconAdapter] Write error: {e}")

    def stop(self):
        self.is_running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

recon_adapter = ReconAdapter()
