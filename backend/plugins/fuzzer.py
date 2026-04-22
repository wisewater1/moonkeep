from core.plugin_manager import BasePlugin
from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, send, Raw
import threading
import time

class FuzzerPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.targets = []

    @property
    def name(self) -> str:
        return "Fuzzer"

    @property
    def description(self) -> str:
        return "Multi-Protocol Service Fuzzer (SNMP/MDNS/UPnP)"

    async def start(self):
        self.running = True
        print("Fuzzer: Initializing protocol mutation engine...")

    async def stop(self):
        self.running = False

    async def fuzz_snmp(self, target_ip, community="public"):
        """
        Fuzz SNMP GET requests with long OIDs and malformed values.
        """
        print(f"Fuzzer: Launching SNMP mutation against {target_ip}...")
        def _run():
            for i in range(100):
                if not self.running: break
                # Mutated OID
                long_oid = "1.3.6.1.2.1.1." + "1." * (i % 50)
                pkt = IP(dst=target_ip)/UDP(sport=161, dport=161)/SNMP(community=community, PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(long_oid))]))
                send(pkt, verbose=False)
                time.sleep(0.05)
        
        threading.Thread(target=_run, daemon=True).start()
        return {"status": "SNMP Fuzzing Active"}

    async def fuzz_mdns(self, target_ip="224.0.0.251"):
        """
        Broadcast malformed mDNS queries to stress local service discovery.
        Sends mutations: oversized names, null bytes, max-label boundaries,
        and service-discovery probes to the mDNS multicast group.
        """
        print(f"Fuzzer: Flooding mDNS multicast with malformed discovery frames -> {target_ip}")
        from scapy.all import DNS, DNSQR

        mutations = [
            "A" * 200 + ".local",
            "\x00\xff.local",
            "x" * 63 + "." + "y" * 63 + ".local",
            "_services._dns-sd._udp.local",
            "\xff\xfe.local",
            "." * 10 + "local",
        ]

        def _run():
            for i in range(60):
                if not self.running:
                    break
                name = mutations[i % len(mutations)]
                try:
                    pkt = (IP(dst="224.0.0.251") /
                           UDP(sport=5353, dport=5353) /
                           DNS(id=i & 0xFFFF, qr=0, qdcount=1,
                               qd=DNSQR(qname=name, qtype="PTR")))
                    send(pkt, verbose=False)
                except Exception:
                    pass
                time.sleep(0.05)

        threading.Thread(target=_run, daemon=True).start()
        return {"status": "MDNS Fuzzing Active", "target": target_ip, "mutations": len(mutations)}
