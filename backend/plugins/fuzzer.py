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
        Broadcast malformed MDNS queries to stress local service discovery.
        Targets mDNS responders with oversized names, type confusion, and pointer loops.
        """
        self.running = True
        self.emit("INFO", {"msg": f"MDNS fuzzer broadcasting to {target_ip} ({iterations} iterations)"})

        async def _fuzz_async():
            query_mutations = [
                # Oversized service name
                lambda i: f"{'A' * min(i + 10, 250)}._tcp.local.",
                # Null bytes in query
                lambda i: f"_http._tcp\x00\x00.local.",
                # Deep subdomain nesting
                lambda i: ".".join(["sub"] * min(i + 2, 60)) + "._tcp.local.",
                # Unicode / high-byte chars
                lambda i: f"\xff\xfe{'X' * (i % 40)}._udp.local.",
                # Known Apple/Bonjour services
                lambda i: ["_airplay._tcp.local.", "_raop._tcp.local.", "_companion-link._tcp.local.",
                           "_homekit._tcp.local.", "_ipp._tcp.local.", "_smb._tcp.local."][i % 6],
                # Wildcard enumeration
                lambda i: f"_services._dns-sd._udp.local.",
            ]
            qtypes = [255, 12, 28, 33, 16, 1]  # ANY, PTR, AAAA, SRV, TXT, A

            for i in range(iterations):
                if not self.running:
                    break
                try:
                    qname = query_mutations[i % len(query_mutations)](i)
                    qtype = qtypes[i % len(qtypes)]
                    pkt = IP(dst=target_ip, ttl=255) / UDP(sport=5353, dport=5353) / DNS(
                        rd=0, qd=DNSQR(qname=qname, qtype=qtype, qclass=0x8001)
                    )
                    await asyncio.to_thread(send, pkt, verbose=False)
                    self.stats["mdns_sent"] += 1
                    if i % 30 == 0:
                        self.emit("INFO", {"msg": f"MDNS fuzz progress: {i}/{iterations} queries"})
                    await asyncio.sleep(0.04)
                except Exception as e:
                    self.stats["errors"] += 1
            self.emit("SUCCESS", {"msg": f"MDNS fuzzing complete: {self.stats['mdns_sent']} sent, {self.stats['errors']} errors"})

        asyncio.create_task(_fuzz_async())
        return {"status": "MDNS Fuzzing Active", "target": target_ip, "iterations": iterations}

    async def fuzz_upnp(self, target_ip="239.255.255.250", iterations=100):
        """
        Fuzz UPnP SSDP with malformed M-SEARCH and NOTIFY payloads.
        """
        self.running = True
        self.emit("INFO", {"msg": f"UPnP SSDP fuzzer targeting {target_ip}"})

        async def _fuzz_async():
            ssdp_mutations = [
                # Standard discovery
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n",
                # Oversized MAN header
                f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"{'A' * 2000}\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n",
                # Negative MX
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: -1\r\nST: ssdp:all\r\n\r\n",
                # Huge MX value
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 999999\r\nST: upnp:rootdevice\r\n\r\n",
                # Malformed HTTP version
                "M-SEARCH * HTTP/9.9\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n",
                # NOTIFY instead of M-SEARCH
                "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nLOCATION: http://127.0.0.1:1337/evil.xml\r\n\r\n",
                # Header injection
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\nX-Evil: \r\nTransfer-Encoding: chunked\r\n\r\n",
            ]
            for i in range(iterations):
                if not self.running:
                    break
                try:
                    payload = ssdp_mutations[i % len(ssdp_mutations)]
                    pkt = IP(dst=target_ip, ttl=4) / UDP(sport=RandShort(), dport=1900) / Raw(load=payload.encode())
                    await asyncio.to_thread(send, pkt, verbose=False)
                    self.stats["upnp_sent"] += 1
                    if i % 25 == 0:
                        self.emit("INFO", {"msg": f"UPnP fuzz progress: {i}/{iterations}"})
                    await asyncio.sleep(0.05)
                except Exception as e:
                    self.stats["errors"] += 1
            self.emit("SUCCESS", {"msg": f"UPnP fuzzing complete: {self.stats['upnp_sent']} sent"})

        asyncio.create_task(_fuzz_async())
        return {"status": "UPnP SSDP Fuzzing Active", "target": target_ip}

    def get_stats(self):
        return self.stats
