from core.plugin_manager import BasePlugin
from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, send, Raw, DNS, DNSQR, RandShort
import asyncio
import struct
import os

class FuzzerPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.targets = []
        self.stats = {"snmp_sent": 0, "mdns_sent": 0, "upnp_sent": 0, "errors": 0}

    @property
    def name(self) -> str:
        return "Fuzzer"

    @property
    def description(self) -> str:
        return "Multi-Protocol Service Fuzzer (SNMP/MDNS/UPnP)"

    @property
    def version(self) -> str:
        return "1.5.0"

    @property
    def category(self) -> str:
        return "offensive"

    async def start(self):
        self.running = True
        self.stats = {"snmp_sent": 0, "mdns_sent": 0, "upnp_sent": 0, "errors": 0}
        print("Fuzzer: Initializing protocol mutation engine...")

    async def stop(self):
        self.running = False

    async def fuzz_snmp(self, target_ip, community="public", iterations=200):
        """
        Fuzz SNMP with long OIDs, malformed community strings,
        overflow values, and type confusion payloads.
        """
        self.running = True
        self.emit("INFO", {"msg": f"SNMP fuzzer targeting {target_ip} ({iterations} iterations)"})

        async def _fuzz_async():
            mutations = [
                # Long OID traversal
                lambda i: "1.3.6.1.2.1.1." + "1." * (i % 80),
                # Negative OID components
                lambda i: f"1.3.6.1.2.1.{-i}.{i*999}",
                # Maximum integer OID
                lambda i: f"1.3.6.1.2.1.1.{2**31 - 1}.{i}",
                # Deep nesting
                lambda i: ".".join(["1"] * min(i + 10, 128)),
                # Zero-length components
                lambda i: f"1.3.6.1...{i}.0",
            ]
            communities = [
                community, "A" * 256, "", "\x00" * 64,
                "public\x00private", "../../../etc/passwd",
            ]
            for i in range(iterations):
                if not self.running:
                    break
                try:
                    oid = mutations[i % len(mutations)](i)
                    comm = communities[i % len(communities)]
                    pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=161) / SNMP(
                        community=comm,
                        PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
                    )
                    await asyncio.to_thread(send, pkt, verbose=False)
                    self.stats["snmp_sent"] += 1
                    if i % 50 == 0:
                        self.emit("INFO", {"msg": f"SNMP fuzz progress: {i}/{iterations} packets"})
                    await asyncio.sleep(0.03)
                except Exception as e:
                    self.stats["errors"] += 1
            self.emit("SUCCESS", {"msg": f"SNMP fuzzing complete: {self.stats['snmp_sent']} sent, {self.stats['errors']} errors"})

        asyncio.create_task(_fuzz_async())
        return {"status": "SNMP Fuzzing Active", "target": target_ip, "iterations": iterations}

    async def fuzz_mdns(self, target_ip="224.0.0.251", iterations=150):
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
