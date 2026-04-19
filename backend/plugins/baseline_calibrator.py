from core.plugin_manager import BasePlugin
from scapy.all import sniff, ARP, DNS, IP, TCP
import asyncio
import collections
import threading
import time


class BaselineCalibratorPlugin(BasePlugin):
    """
    Network behavioral baseline measurement for noise-floor attack calibration.

    Phase 1 — Observe (passive):
      Silently measures real network traffic rates:
        - ARP gratuitous announcements per minute
        - DNS queries per minute
        - TCP SYN rate (new connections per minute)
        - Average packet size

    Phase 2 — Calibrate:
      Exposes safe_delay_s values for each attack type so that other
      plugins (ARP spoofing, credential spray, DNS hijacking) can time
      their injections to stay statistically indistinguishable from
      baseline traffic.  Rate-based and anomaly-based IDS systems that
      look for bursts will see nothing abnormal.
    """

    def __init__(self):
        self.running = False
        self.baseline: dict = {}
        self._lock = threading.Lock()
        self._window: list[dict] = []

    @property
    def name(self) -> str:
        return "Baseline-Calibrator"

    @property
    def description(self) -> str:
        return "Noise-floor attack calibration via passive behavioral baseline measurement"

    async def start(self, interface: str | None = None, observe_secs: int = 60):
        self.running = True
        asyncio.create_task(self._observe(interface, observe_secs))
        self.log_event(f"Passive baseline observation started ({observe_secs}s window)", "START")

    async def stop(self):
        self.running = False

    async def _observe(self, interface: str | None, observe_secs: int):
        done = threading.Event()
        start_ts = time.time()
        counters: dict[str, int] = collections.defaultdict(int)
        sizes: list[int] = []
        tcp_seen: set = set()

        def _pkt(pkt):
            ts = time.time()
            if ts - start_ts >= observe_secs:
                done.set()
                return
            sizes.append(len(pkt))

            if ARP in pkt:
                counters["arp"] += 1
                with self._lock:
                    self._window.append({"t": "arp", "ts": ts})

            if IP in pkt:
                if pkt.haslayer(DNS):
                    counters["dns"] += 1
                    with self._lock:
                        self._window.append({"t": "dns", "ts": ts})
                if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN
                    k = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                    if k not in tcp_seen:
                        tcp_seen.add(k)
                        counters["syn"] += 1
                        with self._lock:
                            self._window.append({"t": "syn", "ts": ts})

        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=interface,
                prn=_pkt,
                stop_filter=lambda _: done.is_set() or not self.running,
                timeout=observe_secs + 5,
            ),
            daemon=True,
        )
        sniff_thread.start()
        await asyncio.to_thread(done.wait, observe_secs + 5)

        elapsed = max(1.0, min(observe_secs, time.time() - start_ts))
        arp_pm  = counters["arp"] / elapsed * 60
        dns_pm  = counters["dns"] / elapsed * 60
        syn_pm  = counters["syn"] / elapsed * 60

        self.baseline = {
            "observed_seconds": round(elapsed),
            "arp_per_min":      round(arp_pm,  1),
            "dns_per_min":      round(dns_pm,  1),
            "syn_per_min":      round(syn_pm,  1),
            "avg_packet_bytes": round(sum(sizes) / len(sizes)) if sizes else 0,
            # Safe inter-injection delay: inject at most at the observed rate
            "safe_arp_delay_s": round(60 / max(arp_pm, 0.1), 2),
            "safe_dns_delay_s": round(60 / max(dns_pm, 0.1), 2),
            "safe_syn_delay_s": round(60 / max(syn_pm, 0.1), 2),
            "raw_counts": dict(counters),
        }

        self.log_event(
            f"Baseline ready — ARP {arp_pm:.1f}/min  DNS {dns_pm:.1f}/min  SYN {syn_pm:.1f}/min",
            "DONE",
        )
        self.emit("BASELINE_READY", self.baseline)

    def get_safe_delay(self, attack_type: str) -> float:
        """Return minimum inter-packet delay (seconds) to stay within observed baseline."""
        mapping = {
            "arp":  "safe_arp_delay_s",
            "dns":  "safe_dns_delay_s",
            "tcp":  "safe_syn_delay_s",
            "spray":"safe_syn_delay_s",
            "scan": "safe_syn_delay_s",
        }
        key = mapping.get(attack_type.lower(), "safe_syn_delay_s")
        return self.baseline.get(key, 1.0)

    async def get_status(self) -> dict:
        return {
            "ready": bool(self.baseline),
            "baseline": self.baseline,
        }
