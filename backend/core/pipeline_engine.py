"""
PipelineEngine — Event-driven synergy coordinator.

Listens to every event emitted by plugins and fires follow-up actions
automatically based on configurable trigger rules.  This turns the plugin
collection into a single organism rather than isolated tools.

Event flow (default rules):
  SCAN_COMPLETE      → OSINT-Enricher.enrich_batch()
                       Vuln-Scanner.scan_target() per host
  VULN_RESULT        → Exploit-Mapper.map_cves()
                       AI-Orchestrator.ingest_vuln_results()
  CREDENTIAL_FOUND   → Cred-Spray.add_credential()
                       Cred-Spray.spray_target() if targets known
  HASH_CRACKED       → Cred-Spray.add_credential(password)
  HANDSHAKE_CAPTURED → Hash-Cracker.crack_pcap()
  EXFIL_COMPLETE     → Hash-Cracker.crack_shadow() for readable /etc/shadow
                       Secret-Hunter.hunt() over exfil paths
  SPOOF_ACTIVE       → Proxy.start()  +  Sniffer.start()
  ACCESS_GAINED      → Post-Exploit.pivot_scan()
                       Post-Exploit.generate_persistence()
  WEB_VULN_FOUND     → (persisted automatically by web_scanner)
  OSINT_ENRICHED     → AI-Orchestrator knowledge-graph node update
  WEB_TRAFFIC        → Web-Scanner.analyze_traffic() (passive XSS/error/reflected input detection)
"""

import asyncio
import time


class PipelineEngine:
    def __init__(self):
        self._pm   = None   # PluginManager
        self._ts   = None   # TargetStore
        self._eq   = None   # event_queue (for emitting back onto the bus)

        # Toggle individual rules on/off at runtime
        self.rules: dict[str, bool] = {
            "scan_complete→osint":          True,
            "scan_complete→vuln_scan":      True,
            "vuln_result→exploit_map":      True,
            "vuln_result→ingest_graph":     True,
            "credential_found→spray":       True,
            "hash_cracked→spray":           True,
            "handshake_captured→crack":     True,
            "exfil_complete→crack_shadow":  True,
            "exfil_complete→secret_hunt":   True,
            "spoof_active→mitm_chain":      True,
            "access_gained→post_exploit":   True,
            "traffic→web_passive":          True,
        }

        # Short-circuit: avoid re-scanning an IP we just scanned
        self._scanned_ips: set[str] = set()

    def inject(self, plugin_manager, target_store, event_queue: asyncio.Queue):
        self._pm = plugin_manager
        self._ts = target_store
        self._eq = event_queue

    # ------------------------------------------------------------------
    # Called from broadcast_events() for every event on the bus
    # ------------------------------------------------------------------

    async def process_event(self, event: dict):
        etype = event.get("type", "")
        data  = event.get("data", {})

        try:
            if etype == "SCAN_COMPLETE":
                await self._on_scan_complete(data)
            elif etype == "VULN_RESULT":
                await self._on_vuln_result(data)
            elif etype == "CREDENTIAL_FOUND":
                await self._on_credential_found(data)
            elif etype == "HASH_CRACKED":
                await self._on_hash_cracked(data)
            elif etype == "HANDSHAKE_CAPTURED":
                await self._on_handshake_captured(data)
            elif etype == "EXFIL_COMPLETE":
                await self._on_exfil_complete(data)
            elif etype == "SPOOF_ACTIVE":
                await self._on_spoof_active(data)
            elif etype == "ACCESS_GAINED" or etype == "CREDENTIAL_VALID":
                await self._on_access_gained(data)
            elif etype == "WEB_TRAFFIC":
                await self._on_web_traffic(data)
            elif etype == "OSINT_ENRICHED":
                await self._on_osint_enriched(data)
        except Exception as exc:
            self._emit("PIPELINE_ERROR", {"trigger": etype, "error": str(exc)})

    # ------------------------------------------------------------------
    # Trigger handlers
    # ------------------------------------------------------------------

    async def _on_scan_complete(self, data: dict):
        devices = data.get("devices", [])
        if not devices:
            return

        # Register targets in Cred-Spray
        spray = self._plugin("Cred-Spray")
        if spray:
            for d in devices:
                ip = d.get("ip")
                if ip:
                    spray.add_target(ip, [22, 21, 80, 443, 8080, 3306, 5432, 6379])

        if self.rules.get("scan_complete→osint"):
            enricher = self._plugin("OSINT-Enricher")
            if enricher:
                asyncio.create_task(enricher.enrich_batch(devices))
                self._emit("PIPELINE_TRIGGERED", {"rule": "scan_complete→osint",
                                                   "count": len(devices)})

        if self.rules.get("scan_complete→vuln_scan"):
            vs = self._plugin("Vuln-Scanner")
            if vs:
                for d in devices:
                    ip = d.get("ip")
                    if ip and ip not in self._scanned_ips:
                        self._scanned_ips.add(ip)
                        asyncio.create_task(self._vuln_scan_and_ingest(ip, vs))
                self._emit("PIPELINE_TRIGGERED", {"rule": "scan_complete→vuln_scan",
                                                   "hosts": len(devices)})

    async def _vuln_scan_and_ingest(self, ip: str, vs):
        try:
            results = await vs.scan_target(ip)
            if results:
                ai = self._plugin("AI-Orchestrator")
                if ai and self.rules.get("vuln_result→ingest_graph"):
                    ai.ingest_vuln_results(ip, results)
                em = self._plugin("Exploit-Mapper")
                if em and self.rules.get("vuln_result→exploit_map"):
                    for r in results:
                        r["ip"] = ip
                    em.map_cves(results)
                # Feed open ports to cred sprayer
                spray = self._plugin("Cred-Spray")
                if spray:
                    open_ports = [r["port"] for r in results if r.get("state") == "open" and r.get("port")]
                    if open_ports:
                        spray.add_target(ip, open_ports)
        except Exception as exc:
            self._emit("PIPELINE_ERROR", {"rule": "vuln_scan_task", "ip": ip, "error": str(exc)})

    async def _on_vuln_result(self, data: dict):
        ip       = data.get("ip", "")
        findings = data.get("findings", [])
        if not findings:
            return

        if self.rules.get("vuln_result→ingest_graph"):
            ai = self._plugin("AI-Orchestrator")
            if ai:
                ai.ingest_vuln_results(ip, findings)

        if self.rules.get("vuln_result→exploit_map"):
            em = self._plugin("Exploit-Mapper")
            if em:
                for f in findings:
                    f["ip"] = ip
                em.map_cves(findings)
                self._emit("PIPELINE_TRIGGERED", {"rule": "vuln_result→exploit_map", "ip": ip})

    async def _on_credential_found(self, data: dict):
        raw_cred = data.get("cred") or data.get("msg", "")
        if not raw_cred or not self.rules.get("credential_found→spray"):
            return
        spray = self._plugin("Cred-Spray")
        if not spray:
            return
        spray.add_credential(raw_cred)
        # If we already know targets, fire spray immediately in background
        if spray._targets:
            asyncio.create_task(spray.run_spray())
            self._emit("PIPELINE_TRIGGERED", {"rule": "credential_found→spray",
                                               "cred_preview": raw_cred[:30]})

    async def _on_hash_cracked(self, data: dict):
        password = data.get("password")
        if not password or not self.rules.get("hash_cracked→spray"):
            return
        spray = self._plugin("Cred-Spray")
        if spray:
            spray.add_credential(f"admin:{password}")
            spray.add_credential(f"root:{password}")
            spray.add_credential(f"user:{password}")
            if spray._targets:
                asyncio.create_task(spray.run_spray())
            self._emit("PIPELINE_TRIGGERED", {"rule": "hash_cracked→spray",
                                               "password_len": len(password)})

    async def _on_handshake_captured(self, data: dict):
        if not self.rules.get("handshake_captured→crack"):
            return
        pcap = data.get("file")
        bssid = data.get("bssid", "")
        if not pcap:
            return
        hc = self._plugin("Hash-Cracker")
        if hc:
            asyncio.create_task(hc.crack_pcap(pcap, bssid))
            self._emit("PIPELINE_TRIGGERED", {"rule": "handshake_captured→crack",
                                               "bssid": bssid})

    async def _on_exfil_complete(self, data: dict):
        files = data.get("files", [])

        if self.rules.get("exfil_complete→crack_shadow"):
            hc = self._plugin("Hash-Cracker")
            if hc:
                for f in files:
                    path = f if isinstance(f, str) else f.get("path", "")
                    if path.endswith("/shadow") or path == "/etc/shadow":
                        asyncio.create_task(hc.crack_shadow(path))
                        self._emit("PIPELINE_TRIGGERED", {"rule": "exfil_complete→crack_shadow",
                                                           "path": path})

        if self.rules.get("exfil_complete→secret_hunt"):
            sh = self._plugin("Secret-Hunter")
            if sh:
                for f in files:
                    path = f if isinstance(f, str) else f.get("path", "")
                    if path and isinstance(path, str):
                        asyncio.create_task(sh.hunt(path))
                self._emit("PIPELINE_TRIGGERED", {"rule": "exfil_complete→secret_hunt"})

    async def _on_spoof_active(self, _data: dict):
        if not self.rules.get("spoof_active→mitm_chain"):
            return
        proxy = self._plugin("Proxy")
        if proxy and not proxy.running:
            await proxy.start(port=8080)
            self._emit("PIPELINE_TRIGGERED", {"rule": "spoof_active→mitm_chain:proxy"})
        sniffer = self._plugin("Sniffer")
        if sniffer and not sniffer.sniffer:
            await sniffer.start()
            self._emit("PIPELINE_TRIGGERED", {"rule": "spoof_active→mitm_chain:sniffer"})

    async def _on_access_gained(self, data: dict):
        if not self.rules.get("access_gained→post_exploit"):
            return
        ip = data.get("ip") or data.get("target")
        if not ip:
            return
        pe = self._plugin("Post-Exploit")
        if pe:
            asyncio.create_task(pe.pivot_scan(ip))
            asyncio.create_task(pe.exfiltrate_secrets(f"session_{ip.replace('.','_')}"))
            self._emit("PIPELINE_TRIGGERED", {"rule": "access_gained→post_exploit", "ip": ip})

    async def _on_web_traffic(self, data: dict):
        if not self.rules.get("traffic→web_passive"):
            return
        ws = self._plugin("Web-Scanner")
        if not ws:
            return
        host = data.get("host", "")
        req  = data.get("request", b"")
        resp = data.get("response", b"")
        if host and (req or resp):
            ws.analyze_traffic(host, req, resp)

    async def _on_osint_enriched(self, data: dict):
        ip     = data.get("ip", "")
        osint  = data.get("data", {})
        shodan = osint.get("shodan", {})
        extra_ports = shodan.get("ports", [])
        extra_vulns = shodan.get("vulns", [])

        # Feed Shodan-discovered ports into cred-spray targets
        spray = self._plugin("Cred-Spray")
        if spray and extra_ports:
            spray.add_target(ip, extra_ports)

        # Feed Shodan-discovered CVEs into exploit mapper
        if extra_vulns:
            em = self._plugin("Exploit-Mapper")
            if em:
                shodan_findings = [
                    {"cve": cve, "cvss": 0.0, "severity": "UNKNOWN",
                     "ip": ip, "port": None, "service": "shodan",
                     "version": None, "state": "open"}
                    for cve in extra_vulns
                ]
                em.map_cves(shodan_findings)
                self._emit("PIPELINE_TRIGGERED", {
                    "rule": "osint_enriched→exploit_map",
                    "ip": ip, "shodan_vulns": extra_vulns
                })

    # ------------------------------------------------------------------
    # Rule management (exposed via API)
    # ------------------------------------------------------------------

    def set_rule(self, rule: str, enabled: bool):
        if rule in self.rules:
            self.rules[rule] = enabled
            return True
        return False

    def get_status(self) -> dict:
        return {
            "rules":        self.rules,
            "scanned_ips":  list(self._scanned_ips),
            "active":       self._pm is not None,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _plugin(self, name: str):
        if not self._pm:
            return None
        return self._pm.get_plugin(name)

    def _emit(self, etype: str, data: dict):
        if self._eq:
            try:
                self._eq.put_nowait({
                    "ts":     time.time(),
                    "plugin": "Pipeline-Engine",
                    "type":   etype,
                    "data":   data,
                })
            except Exception:
                pass
