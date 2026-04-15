from core.plugin_manager import BasePlugin
from scapy.all import ARP, Ether, srp, conf
import socket
import subprocess
import re
import struct

# Compact OUI prefix table — top vendors seen in pentests
OUI_TABLE = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox", "00:15:5d": "Hyper-V",
    "00:03:93": "Apple", "3c:22:fb": "Apple", "f0:18:98": "Apple",
    "a4:83:e7": "Apple", "14:98:77": "Apple", "d0:03:4b": "Apple",
    "ac:de:48": "Apple", "88:66:a5": "Apple", "78:7b:8a": "Apple",
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "30:ae:a4": "Espressif", "24:0a:c4": "Espressif", "a4:cf:12": "Espressif",
    "cc:50:e3": "Espressif", "10:52:1c": "Espressif", "7c:df:a1": "Espressif",
    "48:3f:da": "Espressif", "c8:c9:a3": "Espressif",
    "b0:be:76": "TP-Link", "60:32:b1": "TP-Link", "50:c7:bf": "TP-Link",
    "00:1a:2b": "Cisco", "00:1b:54": "Cisco", "00:26:cb": "Cisco",
    "f8:4d:89": "Hewlett-Packard", "00:25:b3": "Hewlett-Packard",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM",
    "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Apple",
    "44:38:39": "Cumulus Networks", "00:16:3e": "Xen",
    "9c:b6:d0": "Rivet Networks", "74:d4:35": "Giga-Byte",
    "00:0d:b9": "PC Engines", "00:1e:06": "Wibrain",
    "00:1c:b3": "Apple", "a8:20:66": "Apple",
    "18:fe:34": "Espressif", "68:c6:3a": "Espressif",
    "ac:67:b2": "Espressif", "bc:dd:c2": "Espressif",
    "00:1f:f3": "Apple", "00:23:12": "Apple",
    "00:14:22": "Dell", "18:03:73": "Dell",
    "00:0f:20": "Hewlett-Packard",
    "00:25:00": "Apple", "34:15:9e": "Apple",
    "28:6a:ba": "Samsung", "a8:f2:74": "Samsung",
    "d0:17:c2": "ASUSTek", "ac:9e:17": "ASUSTek",
    "b4:2e:99": "Giga-Byte", "00:23:24": "Apple",
}

class ScannerPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Scanner"

    @property
    def description(self) -> str:
        return "Network Discovery via ARP Requests"

    async def start(self) -> None:
        self.emit("INFO", {"msg": "Scanner initialized with OUI database"})

    async def stop(self) -> None:
        pass

    def scan(self, target_ip: str = "192.168.1.0/24") -> list[dict[str, str]]:
        """Perform ARP scan with vendor identification and hostname resolution."""
        self.emit("INFO", {"msg": f"Scanning {target_ip}..."})
        devices: list[dict[str, str]] = []
        devices.extend(self._arp_scan(target_ip))
        if not devices:
            devices.extend(self._os_arp_fallback(target_ip))

        # Enrich with vendor + hostname
        for d in devices:
            d['vendor'] = self._lookup_vendor(d.get('mac', ''))
            d['hostname'] = self._resolve_hostname(d.get('ip', ''))

        unique_devices = {d['ip']: d for d in devices}.values()
        result = list(unique_devices)
        self.emit("SUCCESS", {"msg": f"Discovered {len(result)} hosts on {target_ip}"})
        return result

    def _arp_scan(self, target_ip: str) -> list[dict[str, str]]:
        """Use Scapy to send ARP requests and collect responses."""
        try:
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for _, rcv in result]
        except Exception as e:
            print(f"Scapy ARP scan failed: {e}")
            return []

    def _os_arp_fallback(self, target_ip: str) -> list[dict[str, str]]:
        """Parse the OS ``arp -a`` output as a fallback method."""
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=10)
            devices: list[dict[str, str]] = []
            for line in output.split("\n"):
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})", line)
                if match:
                    ip, mac = match.groups()
                    devices.append({'ip': ip, 'mac': mac.replace('-', ':')})
            return devices
        except Exception as e:
            print(f"OS ARP fallback failed: {e}")
            return []

    def _lookup_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC OUI prefix."""
        if not mac or len(mac) < 8:
            return "Unknown"
        prefix = mac[:8].lower()
        # Try exact match first
        for oui_prefix, vendor in OUI_TABLE.items():
            if prefix == oui_prefix.lower():
                return vendor
        return "Unknown"

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup with timeout."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""

    def get_local_ip(self) -> str:
        """Return the local IP address of the default interface."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
