from core.plugin_manager import BasePlugin
import sqlite3
import asyncio


class AIOrchestratorPlugin(BasePlugin):
    VENDOR_MAP = {
        "cisco":        "Cisco router/switch. Check default credentials and IOS vulnerabilities.",
        "netgear":      "Netgear device. Check PSV advisory list and default admin:password.",
        "tp-link":      "TP-Link device. Prone to CSRF and default credential exposure.",
        "d-link":       "D-Link device. Multiple RCE CVEs in older firmware.",
        "samsung":      "Samsung device. Evaluate SmartThings and IoT attack surface.",
        "raspberry pi": "Raspberry Pi. Default pi:raspberry credentials likely active.",
        "espressif":    "Espressif IoT device. High default credential probability.",
        "apple":        "Apple device. Assess mDNS/AirPlay/Bonjour exposure.",
        "amazon":       "Amazon/Echo device. Alexa skill abuse and SSRF vectors.",
        "huawei":       "Huawei device. Known backdoor history; check admin panels.",
        "zyxel":        "Zyxel device. CVE-2023-28771 command injection is widespread.",
    }

    VENDOR_SCORES = {
        "cisco": 8.0, "netgear": 6.5, "tp-link": 5.5, "d-link": 5.5,
        "samsung": 5.0, "raspberry pi": 7.0, "espressif": 8.5,
        "apple": 4.0, "amazon": 5.5, "huawei": 7.0, "zyxel": 6.5,
    }

    def __init__(self):
        self.running = False
        self.db_path = "moonkeep_graph.db"
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS nodes
                     (id TEXT PRIMARY KEY, type TEXT, data TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS edges
                     (source TEXT, target TEXT, type TEXT, weight REAL DEFAULT 1.0)''')
        conn.commit()
        # Migration: add weight column to pre-existing edges tables that lack it
        c.execute("PRAGMA table_info('edges')")
        existing_cols = [row[1] for row in c.fetchall()]
        if 'weight' not in existing_cols:
            c.execute("ALTER TABLE edges ADD COLUMN weight REAL DEFAULT 1.0")
            conn.commit()
        conn.close()

    @property
    def name(self) -> str:
        return "AI-Orchestrator"

    @property
    def description(self) -> str:
        return "Autonomous Neural Security Engine"

    @property
    def version(self) -> str:
        return "2.2.0"

    @property
    def category(self) -> str:
        return "ai"

    async def start(self):
        self.running = True
        print("AI-Orchestrator: Thinking engine online. Knowledge graph synchronized.")

    async def stop(self):
        self.running = False

    def score_device(self, device: dict) -> float:
        """Return a 0.0-10.0 risk score based on vendor and IP heuristics."""
        score = 3.0
        vendor = device.get("vendor", "").lower()
        for key, vscore in self.VENDOR_SCORES.items():
            if key in vendor:
                score = vscore
                break
        ip = device.get("ip", "")
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                first  = int(parts[0])
                second = int(parts[1])
                last   = int(parts[3])
                if last == 255:
                    return 0.5
                if last == 1 or last == 254:
                    score = min(10.0, score + 3.0)
                is_rfc1918 = (
                    first == 10
                    or (first == 172 and 16 <= second <= 31)
                    or (first == 192 and second == 168)
                )
                if is_rfc1918:
                    score = min(10.0, score + 0.5)
            except ValueError:
                pass
        return round(min(10.0, max(0.0, score)), 2)

    def ingest_vuln_results(self, ip: str, vulns: list):
        """Add CVE nodes and CVSS-weighted edges to the knowledge graph."""
        if not vulns:
            return
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for vuln in vulns:
            cve_id = vuln['cve']
            cvss   = vuln.get('cvss', 5.0)
            c.execute("INSERT OR REPLACE INTO nodes VALUES (?, ?, ?)",
                      (cve_id, "CVE", str(vuln)))
            # Edge weight = normalized CVSS (0.0–1.0); higher = more dangerous path
            weight = round(cvss / 10.0, 2)
            c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?)",
                      (ip, cve_id, "VULNERABLE_TO", weight))
        conn.commit()
        conn.close()
        self.emit("GRAPH_UPDATE", {"ip": ip, "vulns_added": len(vulns)})

    async def analyze_devices(self, devices):
        """Update Knowledge Graph and provide strategic insights."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        insights = []
        campaign_id = self.target_store.active_campaign if self.target_store else None

        for d in devices:
            ip = d.get("ip")
            if not ip:
                continue
            c.execute("INSERT OR REPLACE INTO nodes VALUES (?, ?, ?)",
                      (ip, "DEVICE", str(d)))
            risk = self.score_device(d)
            vendor = d.get("vendor", "").lower()
            matched_vendor = False
            for key, insight_msg in self.VENDOR_MAP.items():
                if key in vendor:
                    insights.append(f"Node {ip} [risk={risk}]: {insight_msg}")
                    c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?)",
                              (ip, f"vuln_{ip}", "HAS_VULN", 1.0))
                    matched_vendor = True
                    break
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    first  = int(parts[0])
                    second = int(parts[1])
                    last   = int(parts[3])
                    if last == 1 or last == 254:
                        insights.append(
                            f"Node {ip} [risk={risk}]: Likely gateway/router. "
                            "Priority target for credential spray and config extraction."
                        )
                        c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?)",
                                  (ip, "GATEWAY", "IS_GATEWAY", 1.0))
                    elif last == 255:
                        insights.append(f"Node {ip}: Broadcast address — skipping attack surface.")
                    else:
                        is_rfc1918 = (
                            first == 10
                            or (first == 172 and 16 <= second <= 31)
                            or (first == 192 and second == 168)
                        )
                        if is_rfc1918 and not matched_vendor:
                            insights.append(
                                f"Node {ip} [risk={risk}]: RFC1918 internal host. "
                                "Suggesting deep port scan and service enumeration."
                            )
                            c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?)",
                                      (ip, f"vuln_{ip}", "HAS_VULN", 1.0))
                except ValueError:
                    pass
            # Legacy pattern preserved for backward compatibility
            if not matched_vendor and ".155" in ip:
                insights.append(
                    f"Node {ip} [risk={risk}]: Identified as high-value target. "
                    "Suggesting deep port scan."
                )
                c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?)",
                          (ip, f"vuln_{ip}", "HAS_VULN", 1.0))
            # Persist risk score as a campaign finding for report visibility
            if campaign_id and self.target_store:
                self.target_store.cm.save_finding(
                    campaign_id, "DEVICE_RISK", ip,
                    f"risk={risk} vendor={d.get('vendor', 'unknown')} mac={d.get('mac', 'unknown')}"
                )

        conn.commit()
        conn.close()
        return insights

    async def plan_attack(self, instruction: str, context: dict):
        self.emit("INFO", {"msg": f"Generating attack plan for: {instruction}"})
        plan = []
        instr = instruction.lower()

        if "full" in instr or "chain" in instr or "complete" in instr or ("all" in instr and len(instr) < 20):
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "OSINT-Enricher", "action": "enrich",      "params": {}})
            plan.append({"step": 3, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 4, "plugin": "Exploit-Mapper", "action": "map",         "params": {}})
            plan.append({"step": 5, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 6, "plugin": "Cred-Spray",     "action": "spray",       "params": {}})
            plan.append({"step": 7, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
            plan.append({"step": 8, "plugin": "Report-Builder", "action": "report",      "params": {}})
        elif "pivot" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 3, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
        elif "fuzz" in instr:
            plan.append({"step": 1, "plugin": "Fuzzer",         "action": "fuzz_mdns",   "params": {}})
            plan.append({"step": 2, "plugin": "Fuzzer",         "action": "fuzz_snmp",   "params": {}})
        elif "web" in instr or "webapp" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Web-Scanner",    "action": "web_scan",    "params": {}})
            plan.append({"step": 3, "plugin": "Exploit-Mapper", "action": "map",         "params": {}})
        elif "scan" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "OSINT-Enricher", "action": "enrich",      "params": {}})
            plan.append({"step": 3, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 4, "plugin": "Exploit-Mapper", "action": "map",         "params": {}})
            plan.append({"step": 5, "plugin": "AI-Orchestrator","action": "analyze",     "params": {}})
        elif "exploit" in instr:
            plan.append({"step": 1, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 2, "plugin": "Exploit-Mapper", "action": "map",         "params": {}})
            plan.append({"step": 3, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
            plan.append({"step": 4, "plugin": "Post-Exploit",   "action": "persistence", "params": {}})
        elif "exfil" in instr:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Post-Exploit",   "action": "exfiltrate",  "params": {}})
            plan.append({"step": 3, "plugin": "Hash-Cracker",   "action": "crack",       "params": {}})
            plan.append({"step": 4, "plugin": "Sniffer",        "action": "sniff_start", "params": {}})
        elif "credential" in instr or "spray" in instr:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Sniffer",        "action": "sniff_start", "params": {}})
            plan.append({"step": 3, "plugin": "Cred-Spray",     "action": "spray",       "params": {}})
            plan.append({"step": 4, "plugin": "AI-Orchestrator","action": "analyze",     "params": {}})
        elif "crack" in instr or "hash" in instr:
            plan.append({"step": 1, "plugin": "Post-Exploit",   "action": "exfiltrate",  "params": {}})
            plan.append({"step": 2, "plugin": "Hash-Cracker",   "action": "crack",       "params": {}})
            plan.append({"step": 3, "plugin": "Cred-Spray",     "action": "spray",       "params": {}})
        elif "lateral" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
            plan.append({"step": 3, "plugin": "Spoofer",        "action": "spoof",       "params": {}})
        elif "report" in instr:
            plan.append({"step": 1, "plugin": "Report-Builder", "action": "report",      "params": {}})
        elif "osint" in instr or "enrich" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "OSINT-Enricher", "action": "enrich",      "params": {}})
        else:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Scanner",        "action": "scan",        "params": {}})

        return plan

    async def execute_plan(self, plan: list, plugin_manager):
        """Drive the attack plan as a real data pipeline, piping results between steps."""
        self.emit("INFO", {"msg": f"Executing {len(plan)}-step attack sequence..."})
        ctx = {}  # shared state flows forward between steps

        for step in plan:
            plugin_name = step['plugin']
            action      = step['action']
            params      = step.get('params', {})
            self.emit("INFO", {"msg": f"Step {step['step']}: {plugin_name} [{action}]"})

            plugin = plugin_manager.get_plugin(plugin_name)
            if not plugin:
                self.emit("WARN", {"msg": f"{plugin_name} unavailable — skipping step {step['step']}."})
                continue

            try:
                if plugin_name == "Scanner" and action == "scan":
                    subnet  = params.get('subnet', '192.168.1.0/24')
                    # scanner.scan() is synchronous (Scapy/ARP); run in thread to avoid blocking
                    devices = await asyncio.to_thread(plugin.scan, subnet)
                    ctx['devices'] = devices
                    if devices and self.target_store:
                        self.target_store.update_devices(devices)
                    insights = await self.analyze_devices(devices)
                    ctx['insights'] = insights
                    self.emit("SCAN_COMPLETE", {"count": len(devices), "devices": devices})

                elif plugin_name == "Vuln-Scanner" and action == "vuln_scan":
                    devices = ctx.get('devices', [])
                    # Fall back to last known target if scanner hasn't run yet
                    if not devices and self.target_store and self.target_store.last_target:
                        devices = [{"ip": self.target_store.last_target}]
                    all_vulns = {}
                    campaign_id = self.target_store.active_campaign if self.target_store else None
                    for d in devices:
                        ip = d.get('ip')
                        if not ip:
                            continue
                        vulns = await plugin.scan_target(ip)
                        if vulns:
                            all_vulns[ip] = vulns
                            self.ingest_vuln_results(ip, vulns)
                            # vuln_scanner already persists HIGH/CRITICAL via target_store;
                            # persist all findings here under the active campaign
                            if campaign_id and self.target_store:
                                for v in vulns:
                                    self.target_store.cm.save_finding(
                                        campaign_id, "VULNERABILITY", ip,
                                        f"{v['cve']} — {v['name']} (CVSS {v['cvss']}, {v['severity']})"
                                    )
                    ctx['vulns'] = all_vulns
                    total = sum(len(v) for v in all_vulns.values())
                    self.emit("VULN_COMPLETE", {"hosts": len(all_vulns), "total": total, "results": all_vulns})

                elif plugin_name == "Secret-Hunter" and action == "hunt":
                    findings = await plugin.hunt()
                    ctx['secrets'] = findings
                    self.emit("HUNT_COMPLETE", {"count": len(findings)})

                elif plugin_name == "Post-Exploit" and action == "pe_pivot":
                    target_ip = params.get('target_ip')
                    if target_ip == "AUTO":
                        # Choose highest-vuln-count host from context, else last known target
                        vulns = ctx.get('vulns', {})
                        target_ip = max(vulns, key=lambda ip: len(vulns[ip]), default=None)
                        if not target_ip and self.target_store:
                            target_ip = self.target_store.last_target
                    if target_ip:
                        result = await plugin.pivot_scan(target_ip)
                        ctx['pivot'] = result
                        self.emit("PIVOT_RESULT", {"ip": target_ip, "result": result})

                elif plugin_name == "Post-Exploit" and action == "persistence":
                    result = await plugin.generate_persistence()
                    ctx['persistence'] = result
                    self.emit("PERSISTENCE_RESULT", {"result": result})

                elif plugin_name == "Post-Exploit" and action == "exfiltrate":
                    session_id = ctx.get('pivot', {}).get('session_id', 'unknown')
                    paths = await plugin.exfiltrate_secrets(session_id)
                    ctx['exfil_paths'] = paths
                    self.emit("EXFIL_COMPLETE", {"session": session_id, "files": paths})

                elif plugin_name == "OSINT-Enricher" and action == "enrich":
                    devices = ctx.get('devices', [])
                    if not devices and self.target_store:
                        devices = self.target_store.devices
                    if devices:
                        enrichments = await plugin.enrich_batch(devices)
                        ctx['osint'] = enrichments

                elif plugin_name == "Exploit-Mapper" and action == "map":
                    all_vulns = ctx.get('vulns', {})
                    all_findings = []
                    for ip, findings_list in all_vulns.items():
                        for f in findings_list:
                            f['ip'] = ip
                            all_findings.append(f)
                    if all_findings:
                        suggestions = plugin.map_cves(all_findings)
                        ctx['exploits'] = suggestions

                elif plugin_name == "Cred-Spray" and action == "spray":
                    # Feed secrets found by Secret-Hunter into pool
                    secrets = ctx.get('secrets', [])
                    for s in secrets:
                        preview = s.get('preview', '')
                        if preview:
                            plugin.add_credential(preview)
                    # Register targets
                    for d in ctx.get('devices', []):
                        ip = d.get('ip')
                        if ip:
                            plugin.add_target(ip, [22, 21, 80, 443, 8080, 3306, 5432])
                    hits = await plugin.run_spray()
                    ctx['spray_hits'] = hits

                elif plugin_name == "Hash-Cracker" and action == "crack":
                    exfil_paths = ctx.get('exfil_paths', [])
                    for f in exfil_paths:
                        path = f if isinstance(f, str) else f.get('path', '')
                        if '/shadow' in path and f.get('readable', True):
                            await plugin.crack_shadow(path)

                elif plugin_name == "Web-Scanner" and action == "web_scan":
                    devices = ctx.get('devices', [])
                    all_web = []
                    for d in devices:
                        ip = d.get('ip')
                        if not ip:
                            continue
                        # Check if port 80 or 443 was open from vuln scan
                        vulns = ctx.get('vulns', {}).get(ip, [])
                        http_ports = [v['port'] for v in vulns
                                      if v.get('state') == 'open' and v.get('port') in (80, 8080, 443, 8443)]
                        if not http_ports:
                            http_ports = [80]
                        for port in http_ports:
                            findings = await plugin.scan(ip, port=port, https=(port in (443, 8443)))
                            all_web.extend(findings)
                    ctx['web_findings'] = all_web

                elif plugin_name == "Report-Builder" and action == "report":
                    result = await plugin.generate()
                    ctx['report'] = result
                    self.emit("REPORT_GENERATED", result)

                else:
                    await asyncio.sleep(1.5)
                    self.emit("INFO", {"msg": f"Step {step['step']} component active."})

            except Exception as e:
                self.emit("ERROR", {"msg": f"Step {step['step']} failed: {str(e)}"})

        summary = {
            "devices_found":  len(ctx.get('devices', [])),
            "vulns_found":    sum(len(v) for v in ctx.get('vulns', {}).values()),
            "secrets_found":  len(ctx.get('secrets', [])),
            "exploits_found": len(ctx.get('exploits', [])),
            "spray_hits":     len(ctx.get('spray_hits', [])),
            "web_findings":   len(ctx.get('web_findings', [])),
            "report":         ctx.get('report', {}).get('html_path'),
        }
        self.emit("SUCCESS", {"msg": "Strike plan execution completed.", **summary})

    def get_graph_data(self):
        """Return graph for D3.js visualization."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, type FROM nodes")
        nodes = [{"id": row[0], "type": row[1]} for row in c.fetchall()]
        c.execute("SELECT source, target, type, weight FROM edges")
        links = [{"source": row[0], "target": row[1], "type": row[2], "weight": row[3]}
                 for row in c.fetchall()]
        conn.close()
        return {"nodes": nodes, "links": links}
