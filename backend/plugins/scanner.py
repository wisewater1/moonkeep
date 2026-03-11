from core.plugin_manager import BasePlugin
from scapy.all import ARP, Ether, srp
import socket
import subprocess
import re

class ScannerPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Scanner"

    @property
    def description(self) -> str:
        return "Network Discovery via ARP Requests"

    async def start(self) -> None:
        print("Scanner started")

    async def stop(self) -> None:
        print("Scanner stopped")

    def scan(self, target_ip: str = "192.168.1.0/24") -> list[dict[str, str]]:
        """Perform ARP scan of the target subnet.

        Returns a list of dictionaries with ``ip`` and ``mac`` keys.
        """
        print(f"Scanning target: {target_ip}")
        devices: list[dict[str, str]] = []
        # Primary ARP scan using Scapy
        devices.extend(self._arp_scan(target_ip))
        # Fallback to OS ARP cache if needed
        if not devices:
            devices.extend(self._os_arp_fallback(target_ip))
        # Deduplicate by IP
        unique_devices = {d['ip']: d for d in devices}.values()
        return list(unique_devices)

    def _arp_scan(self, target_ip: str) -> list[dict[str, str]]:
        """Use Scapy to send ARP requests and collect responses."""
        try:
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=0)[0]
            return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for _, rcv in result]
        except Exception as e:
            print(f"Scapy ARP scan failed (admin rights?): {e}")
            return []

    def _os_arp_fallback(self, target_ip: str) -> list[dict[str, str]]:
        """Parse the OS ``arp -a`` output as a fallback method."""
        try:
            output = subprocess.check_output(["arp", "-a"], text=True)
            devices: list[dict[str, str]] = []
            for line in output.split("\n"):
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})", line)
                if match:
                    ip, mac = match.groups()
                    if ip.split('.')[:-1] == target_ip.split('.')[:-1]:
                        devices.append({'ip': ip, 'mac': mac.replace('-', ':')})
            return devices
        except Exception as e:
            print(f"OS ARP fallback failed: {e}")
            return []

    def get_local_ip(self) -> str:
        """Return the local IP address of the default interface."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
