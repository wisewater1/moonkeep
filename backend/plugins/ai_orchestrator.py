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

    async def analyze_devices(self, devices):
        """Update Knowledge Graph and provide strategic insights."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        insights = []
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
        conn.commit()
        conn.close()
        return insights

    async def plan_attack(self, instruction: str, context: dict):
        self.emit("INFO", {"msg": f"Generating attack plan for: {instruction}"})
        plan = []
        instr = instruction.lower()

        if "pivot" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 3, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
        elif "fuzz" in instr:
            plan.append({"step": 1, "plugin": "Fuzzer",         "action": "fuzz_mdns",   "params": {}})
        elif "scan" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 3, "plugin": "AI-Orchestrator","action": "analyze",     "params": {}})
        elif "exploit" in instr:
            plan.append({"step": 1, "plugin": "Vuln-Scanner",   "action": "vuln_scan",   "params": {}})
            plan.append({"step": 2, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
            plan.append({"step": 3, "plugin": "Post-Exploit",   "action": "persistence", "params": {}})
        elif "exfil" in instr:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Post-Exploit",   "action": "exfiltrate",  "params": {}})
            plan.append({"step": 3, "plugin": "Sniffer",        "action": "sniff_start", "params": {}})
        elif "credential" in instr:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Sniffer",        "action": "sniff_start", "params": {}})
            plan.append({"step": 3, "plugin": "AI-Orchestrator","action": "analyze",     "params": {}})
        elif "lateral" in instr:
            plan.append({"step": 1, "plugin": "Scanner",        "action": "scan",        "params": {}})
            plan.append({"step": 2, "plugin": "Post-Exploit",   "action": "pe_pivot",    "params": {"target_ip": "AUTO"}})
            plan.append({"step": 3, "plugin": "Spoofer",        "action": "spoof",       "params": {}})
        else:
            plan.append({"step": 1, "plugin": "Secret-Hunter",  "action": "hunt",        "params": {}})
            plan.append({"step": 2, "plugin": "Scanner",        "action": "scan",        "params": {}})

        return plan

    async def execute_plan(self, plan: list, plugin_manager):
        self.emit("INFO", {"msg": f"Executing {len(plan)}-step attack sequence..."})
        for step in plan:
            self.emit("INFO", {"msg": f"Running Step {step['step']}: {step['plugin']} [{step['action']}]"})
            await asyncio.sleep(1.5)
            plugin = plugin_manager.get_plugin(step['plugin'])
            if plugin:
                self.emit("INFO", {"msg": f"Step {step['step']} component active. Awaiting results..."})
        self.emit("SUCCESS", {"msg": "Autonomous strike plan execution completed."})

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
