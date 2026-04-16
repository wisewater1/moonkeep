from core.plugin_manager import BasePlugin
import subprocess
import re
import csv
import os
import time
from datetime import datetime

class WardriverPlugin(BasePlugin):
    def __init__(self):
        self.logs_dir = "logs"
        if not os.path.exists(self.logs_dir):
            os.makedirs(self.logs_dir)
        self.current_log = os.path.join(self.logs_dir, f"wigle_{int(time.time())}.csv")
        self._init_log()

    @property
    def name(self) -> str:
        return "Wardriver"

    @property
    def description(self) -> str:
        return "Wi-Fi Wardriving & WiGLE Logging"

    def _init_log(self):
        with open(self.current_log, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["WigleWifi-1.4", "appRelease=1.0", "model=Moonkeep", "release=1.0", "device=Moonkeep-Server", "display=Moonkeep", "board=Moonkeep", "brand=Moonkeep"])
            writer.writerow(["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type"])

    async def start(self):
        print("Wardriver started")

    async def stop(self):
        print("Wardriver stopped")

    def scan_wifi(self):
        """
        Scans for Wi-Fi networks using platform-appropriate tools.
        Linux: iwlist or iw scan.  Windows: netsh.
        Returns a list of discovered networks.
        """
        networks = []
        try:
            import platform
            if platform.system() == "Linux":
                networks = self._scan_linux()
            else:
                networks = self._scan_windows()

            return networks if networks else self._fallback_networks()
        except Exception as e:
            print(f"Wi-Fi scan failed: {e}")
            return self._fallback_networks()

    def _scan_linux(self):
        """Parse 'iwlist scan' or 'iw dev scan' output on Linux."""
        networks = []
        # Try iwlist first
        try:
            output = subprocess.check_output(
                ["iwlist", "scan"], stderr=subprocess.STDOUT, text=True, timeout=15
            )
            current_network = None
            for line in output.split('\n'):
                line = line.strip()
                cell_match = re.search(r"Cell \d+ - Address: ([0-9A-Fa-f:]+)", line)
                if cell_match:
                    if current_network and "mac" in current_network:
                        networks.append(current_network)
                        self._log_network(current_network)
                    current_network = {
                        "mac": cell_match.group(1), "ssid": "HIDDEN",
                        "rssi": -100, "channel": 0, "auth": "Open",
                        "encryption": "N/A", "lat": 0.0, "lon": 0.0
                    }
                    continue
                if current_network:
                    ssid_m = re.search(r'ESSID:"(.+)"', line)
                    if ssid_m:
                        current_network["ssid"] = ssid_m.group(1)
                    ch_m = re.search(r"Channel:(\d+)", line)
                    if ch_m:
                        current_network["channel"] = int(ch_m.group(1))
                    sig_m = re.search(r"Signal level[=:](-?\d+)", line)
                    if sig_m:
                        current_network["rssi"] = int(sig_m.group(1))
                    enc_m = re.search(r"Encryption key:(on|off)", line)
                    if enc_m:
                        current_network["encryption"] = "Encrypted" if enc_m.group(1) == "on" else "Open"
                    auth_m = re.search(r"IE: (.+)", line)
                    if auth_m:
                        current_network["auth"] = auth_m.group(1).strip()
            if current_network and "mac" in current_network:
                networks.append(current_network)
                self._log_network(current_network)
            return networks
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        # Fallback: try 'iw dev <iface> scan'
        try:
            ifaces = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
            iface_m = re.search(r"Interface\s+(\S+)", ifaces)
            iface = iface_m.group(1) if iface_m else "wlan0"
            output = subprocess.check_output(
                ["iw", "dev", iface, "scan"], stderr=subprocess.STDOUT, text=True, timeout=15
            )
            current_network = None
            for line in output.split('\n'):
                line = line.strip()
                bss_m = re.search(r"^BSS ([0-9a-f:]+)", line)
                if bss_m:
                    if current_network and "mac" in current_network:
                        networks.append(current_network)
                        self._log_network(current_network)
                    current_network = {
                        "mac": bss_m.group(1).upper(), "ssid": "HIDDEN",
                        "rssi": -100, "channel": 0, "auth": "Open",
                        "encryption": "N/A", "lat": 0.0, "lon": 0.0
                    }
                    continue
                if current_network:
                    ssid_m = re.search(r"SSID: (.+)", line)
                    if ssid_m:
                        current_network["ssid"] = ssid_m.group(1).strip()
                    sig_m = re.search(r"signal: (-?\d+)", line)
                    if sig_m:
                        current_network["rssi"] = int(sig_m.group(1).split('.')[0])
                    ch_m = re.search(r"primary channel: (\d+)", line)
                    if ch_m:
                        current_network["channel"] = int(ch_m.group(1))
                    if "WPA" in line or "RSN" in line:
                        current_network["encryption"] = "WPA2" if "RSN" in line else "WPA"
                        current_network["auth"] = line.strip()
            if current_network and "mac" in current_network:
                networks.append(current_network)
                self._log_network(current_network)
            return networks
        except (FileNotFoundError, subprocess.SubprocessError):
            return []

    def _scan_windows(self):
        """Parse 'netsh wlan show networks' output on Windows."""
        networks = []
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            stderr=subprocess.STDOUT, text=True, shell=True
        )
        current_network = None
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            ssid_match = re.search(r"^SSID\s+\d+\s+:\s+(.*)", line)
            if ssid_match:
                if current_network and "mac" in current_network:
                    networks.append(current_network)
                    self._log_network(current_network)
                ssid = ssid_match.group(1).strip()
                current_network = {
                    "ssid": ssid if ssid else "HIDDEN",
                    "rssi": -100, "channel": 0, "auth": "WPA2",
                    "encryption": "N/A", "lat": 0.0, "lon": 0.0
                }
                continue
            if current_network is not None:
                auth_match = re.search(r"^Authentication\s+:\s+(.*)", line)
                if auth_match:
                    current_network["auth"] = auth_match.group(1).strip()
                enc_match = re.search(r"^Encryption\s+:\s+(.*)", line)
                if enc_match:
                    current_network["encryption"] = enc_match.group(1).strip()
                bssid_match = re.search(r"^BSSID\s+\d+\s+:\s+(.*)", line)
                if bssid_match:
                    current_network["mac"] = bssid_match.group(1).strip()
                signal_match = re.search(r"^Signal\s+:\s+(\d+)%", line)
                if signal_match:
                    signal = int(signal_match.group(1))
                    current_network["rssi"] = (signal / 2) - 100
                channel_match = re.search(r"^Channel\s+:\s+(\d+)", line)
                if channel_match:
                    current_network["channel"] = int(channel_match.group(1))
        if current_network and "mac" in current_network:
            networks.append(current_network)
            self._log_network(current_network)
        return networks

    def _fallback_networks(self):
        """Return demo networks when no wireless adapter is available."""
        return [
            {"mac": "AA:BB:CC:DD:EE:FF", "ssid": "Demo_Secure", "rssi": -45, "auth": "WPA2", "encryption": "WPA2-PSK", "channel": 6, "lat": 40.7128, "lon": -74.0060},
            {"mac": "11:22:33:44:55:66", "ssid": "Coffee_Shop", "rssi": -65, "auth": "Open", "encryption": "Open", "channel": 11, "lat": 40.7129, "lon": -74.0061}
        ]

    def _log_network(self, net):
        with open(self.current_log, 'a', newline='') as f:
            writer = csv.writer(f)
            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([net['mac'], net['ssid'], net.get('auth', 'WPA2'), first_seen, net.get('channel', 1), net['rssi'], net.get('lat', 0), net.get('lon', 0), 0, 0, "WIFI"])
