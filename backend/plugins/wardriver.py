from core.plugin_manager import BasePlugin
import subprocess
import re
import csv
import os
import sys
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

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def category(self) -> str:
        return "wireless"

    def _init_log(self):
        with open(self.current_log, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["WigleWifi-1.4", "appRelease=1.0", "model=Moonkeep",
                             "release=1.0", "device=Moonkeep-Server",
                             "display=Moonkeep", "board=Moonkeep", "brand=Moonkeep"])
            writer.writerow(["MAC", "SSID", "AuthMode", "FirstSeen", "Channel",
                             "RSSI", "CurrentLatitude", "CurrentLongitude",
                             "AltitudeMeters", "AccuracyMeters", "Type"])

    async def start(self):
        print("Wardriver started")

    async def stop(self):
        print("Wardriver stopped")

    # ------------------------------------------------------------------
    # Public entry point — dispatch by OS
    # ------------------------------------------------------------------

    def scan_wifi(self) -> list:
        platform = sys.platform
        if platform.startswith("linux"):
            return self._scan_linux()
        elif platform == "darwin":
            return self._scan_macos()
        elif platform == "win32":
            return self._scan_windows()
        else:
            print(f"Wardriver: unsupported platform '{platform}'")
            return []

    # ------------------------------------------------------------------
    # Linux — iwlist or iw
    # ------------------------------------------------------------------

    def _get_wireless_iface(self) -> str | None:
        """Return first wireless interface name found via /proc/net/wireless."""
        try:
            with open("/proc/net/wireless") as fh:
                for line in fh:
                    m = re.match(r"^\s*(\w+):", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        # fallback: look for wlan* or wlp* in /sys/class/net
        try:
            for iface in os.listdir("/sys/class/net"):
                if iface.startswith(("wlan", "wlp", "wlx")):
                    return iface
        except Exception:
            pass
        return None

    def _scan_linux(self) -> list:
        iface = self._get_wireless_iface()
        if not iface:
            print("Wardriver: no wireless interface found on this Linux host")
            return []

        # Try iwlist first, then iw
        try:
            out = subprocess.check_output(
                ["iwlist", iface, "scan"],
                stderr=subprocess.DEVNULL, text=True, timeout=15
            )
            return self._parse_iwlist(out)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        try:
            out = subprocess.check_output(
                ["iw", "dev", iface, "scan"],
                stderr=subprocess.DEVNULL, text=True, timeout=15
            )
            return self._parse_iw(out)
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            print(f"Wardriver: iw scan failed — {exc}")
            return []

    def _parse_iwlist(self, output: str) -> list:
        networks = []
        current: dict | None = None

        for line in output.splitlines():
            line = line.strip()

            m = re.match(r"Cell \d+ - Address:\s+([0-9A-Fa-f:]+)", line)
            if m:
                if current:
                    networks.append(current)
                    self._log_network(current)
                current = {"mac": m.group(1), "ssid": "HIDDEN", "rssi": -100,
                           "channel": 0, "auth": "Unknown", "lat": 0.0, "lon": 0.0}
                continue

            if current is None:
                continue

            m = re.search(r'ESSID:"(.*?)"', line)
            if m:
                current["ssid"] = m.group(1) or "HIDDEN"

            m = re.search(r"Channel:(\d+)", line)
            if m:
                current["channel"] = int(m.group(1))

            m = re.search(r"Signal level=(-?\d+)\s*dBm", line)
            if m:
                current["rssi"] = int(m.group(1))
            else:
                m = re.search(r"Signal level=(\d+)/100", line)
                if m:
                    current["rssi"] = int(m.group(1)) - 100

            if "WPA2" in line:
                current["auth"] = "WPA2"
            elif "WPA" in line:
                current["auth"] = "WPA"
            elif "WEP" in line:
                current["auth"] = "WEP"
            elif "open" in line.lower():
                current["auth"] = "Open"

        if current:
            networks.append(current)
            self._log_network(current)

        return networks

    def _parse_iw(self, output: str) -> list:
        networks = []
        current: dict | None = None

        for line in output.splitlines():
            line = line.strip()

            m = re.match(r"BSS ([0-9A-Fa-f:]+)", line)
            if m:
                if current:
                    networks.append(current)
                    self._log_network(current)
                current = {"mac": m.group(1), "ssid": "HIDDEN", "rssi": -100,
                           "channel": 0, "auth": "Unknown", "lat": 0.0, "lon": 0.0}
                continue

            if current is None:
                continue

            m = re.search(r"SSID:\s*(.*)", line)
            if m:
                current["ssid"] = m.group(1).strip() or "HIDDEN"

            m = re.search(r"DS Parameter set: channel (\d+)", line)
            if m:
                current["channel"] = int(m.group(1))

            m = re.search(r"signal:\s*(-[\d.]+)\s*dBm", line)
            if m:
                current["rssi"] = int(float(m.group(1)))

            if "WPA2" in line:
                current["auth"] = "WPA2"
            elif "WPA" in line and current["auth"] != "WPA2":
                current["auth"] = "WPA"
            elif "WEP" in line and current["auth"] == "Unknown":
                current["auth"] = "WEP"

        if current:
            networks.append(current)
            self._log_network(current)

        return networks

    # ------------------------------------------------------------------
    # macOS — airport
    # ------------------------------------------------------------------

    _AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    def _scan_macos(self) -> list:
        try:
            out = subprocess.check_output(
                [self._AIRPORT, "-s"],
                stderr=subprocess.DEVNULL, text=True, timeout=15
            )
            return self._parse_airport(out)
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            print(f"Wardriver: airport scan failed — {exc}")
            return []

    def _parse_airport(self, output: str) -> list:
        networks = []
        # Header line: SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            # SSID can have spaces; BSSID is XX:XX:XX:XX:XX:XX
            # Find BSSID (first MAC-like token)
            bssid_idx = next(
                (i for i, p in enumerate(parts) if re.match(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", p)),
                None
            )
            if bssid_idx is None:
                continue
            ssid = " ".join(parts[:bssid_idx]) or "HIDDEN"
            try:
                rssi = int(parts[bssid_idx + 1])
            except (IndexError, ValueError):
                rssi = -100
            try:
                channel = int(parts[bssid_idx + 2].split(",")[0])
            except (IndexError, ValueError):
                channel = 0
            security = " ".join(parts[bssid_idx + 4:]) if bssid_idx + 4 < len(parts) else "Unknown"
            net = {
                "mac": parts[bssid_idx],
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
                "auth": security or "Open",
                "lat": 0.0,
                "lon": 0.0,
            }
            networks.append(net)
            self._log_network(net)
        return networks

    # ------------------------------------------------------------------
    # Windows — netsh
    # ------------------------------------------------------------------

    def _scan_windows(self) -> list:
        networks = []
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.STDOUT, text=True, timeout=15
            )
            current = None
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                m = re.search(r"^SSID\s+\d+\s+:\s+(.*)", line)
                if m:
                    if current and "mac" in current:
                        networks.append(current)
                        self._log_network(current)
                    ssid = m.group(1).strip()
                    current = {"ssid": ssid or "HIDDEN", "rssi": -100,
                               "channel": 0, "auth": "WPA2", "lat": 0.0, "lon": 0.0}
                    continue
                if current is None:
                    continue
                m = re.search(r"^Authentication\s+:\s+(.*)", line)
                if m:
                    current["auth"] = m.group(1).strip()
                m = re.search(r"^BSSID\s+\d+\s+:\s+(.*)", line)
                if m:
                    current["mac"] = m.group(1).strip()
                m = re.search(r"^Signal\s+:\s+(\d+)%", line)
                if m:
                    current["rssi"] = int(m.group(1)) // 2 - 100
                m = re.search(r"^Channel\s+:\s+(\d+)", line)
                if m:
                    current["channel"] = int(m.group(1))
            if current and "mac" in current:
                networks.append(current)
                self._log_network(current)
        except Exception as exc:
            print(f"Wardriver: netsh scan failed — {exc}")
        return networks

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_network(self, net: dict):
        with open(self.current_log, 'a', newline='') as f:
            writer = csv.writer(f)
            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                net.get("mac", ""),
                net.get("ssid", ""),
                net.get("auth", ""),
                first_seen,
                net.get("channel", 0),
                net.get("rssi", -100),
                net.get("lat", 0.0),
                net.get("lon", 0.0),
                0, 0, "WIFI",
            ])
