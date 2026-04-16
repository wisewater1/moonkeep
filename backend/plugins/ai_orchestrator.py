from core.plugin_manager import BasePlugin
import sqlite3
import os
import asyncio

class AIOrchestratorPlugin(BasePlugin):
    def __init__(self):
        self.running = False
        self.db_path = "moonkeep_graph.db"
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, type TEXT, data TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS edges (source TEXT, target TEXT, type TEXT)''')
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

    async def analyze_devices(self, devices):
        """
        Update Knowledge Graph and provide strategic insights.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        insights = []
        for d in devices:
            ip = d.get("ip")
            if ip:
                c.execute("INSERT OR REPLACE INTO nodes VALUES (?, ?, ?)", (ip, "DEVICE", str(d)))
                
                if ".155" in ip or "192.168" in ip:
                    insights.append(f"Node {ip}: Identified as high-value target. Suggesting deep port scan.")
                    c.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?)", (ip, f"vuln_{ip}", "HAS_VULN"))
                
                vendor = (d.get("vendor") or "").lower()
                if "apple" in vendor:
                    insights.append(f"Node {ip}: Apple device detected. Analyzing for MDNS/AirPlay vulnerabilities.")
                elif "espressif" in vendor:
                    insights.append(f"Node {ip}: IoT Device (Espressif). High probability of default credentials.")
        
        conn.commit()
        conn.close()
        return insights

    async def plan_attack(self, instruction: str, context: dict):
        self.emit("INFO", {"msg": f"Generating attack plan for: {instruction}"})
        plan = []
        inst = instruction.lower()

        # Build plan based on keywords in the instruction
        if "pivot" in inst or "lateral" in inst:
            plan.append({"step": 1, "plugin": "Scanner", "action": "scan", "params": {}})
            plan.append({"step": 2, "plugin": "Vuln-Scanner", "action": "scan_target", "params": {}})
            plan.append({"step": 3, "plugin": "Post-Exploit", "action": "pivot_scan", "params": {}})
        elif "fuzz" in inst:
            plan.append({"step": 1, "plugin": "Fuzzer", "action": "fuzz_snmp", "params": {}})
            plan.append({"step": 2, "plugin": "Fuzzer", "action": "fuzz_mdns", "params": {}})
            plan.append({"step": 3, "plugin": "Fuzzer", "action": "fuzz_upnp", "params": {}})
        elif "wifi" in inst or "wireless" in inst:
            plan.append({"step": 1, "plugin": "Wardriver", "action": "scan_wifi", "params": {}})
            plan.append({"step": 2, "plugin": "WiFi-Strike", "action": "start", "params": {}})
        elif "mitm" in inst or "intercept" in inst or "poison" in inst:
            plan.append({"step": 1, "plugin": "Scanner", "action": "scan", "params": {}})
            plan.append({"step": 2, "plugin": "Spoofer", "action": "start", "params": {}})
            plan.append({"step": 3, "plugin": "Sniffer", "action": "start", "params": {}})
        elif "secret" in inst or "credential" in inst or "key" in inst:
            plan.append({"step": 1, "plugin": "Secret-Hunter", "action": "hunt", "params": {}})
        elif "full" in inst or "killchain" in inst or "everything" in inst:
            plan.append({"step": 1, "plugin": "Scanner", "action": "scan", "params": {}})
            plan.append({"step": 2, "plugin": "Secret-Hunter", "action": "hunt", "params": {}})
            plan.append({"step": 3, "plugin": "Vuln-Scanner", "action": "scan_target", "params": {}})
            plan.append({"step": 4, "plugin": "Spoofer", "action": "start", "params": {}})
            plan.append({"step": 5, "plugin": "Sniffer", "action": "start", "params": {}})
        else:
            plan.append({"step": 1, "plugin": "Scanner", "action": "scan", "params": {}})
            plan.append({"step": 2, "plugin": "Secret-Hunter", "action": "hunt", "params": {}})
            plan.append({"step": 3, "plugin": "Vuln-Scanner", "action": "scan_target", "params": {}})

        return plan

    async def execute_plan(self, plan: list, plugin_manager):
        """Execute a generated attack plan by invoking real plugin methods."""
        self.emit("INFO", {"msg": f"Executing {len(plan)}-step attack sequence..."})
        completed = 0

        for step in plan:
            step_num = step.get('step', completed + 1)
            plugin_name = step['plugin']
            action = step['action']
            self.emit("INFO", {"msg": f"Step {step_num}: {plugin_name} → {action}"})

            plugin = plugin_manager.get_plugin(plugin_name)
            if not plugin:
                self.emit("ERROR", {"msg": f"Step {step_num}: {plugin_name} not found, skipping"})
                continue

            try:
                method = getattr(plugin, action, None)
                if not method or not callable(method):
                    self.emit("ERROR", {"msg": f"Step {step_num}: {plugin_name} has no method '{action}'"})
                    continue

                # Route to the right invocation based on action name
                if action == "scan":
                    target_ip = ""
                    if hasattr(self, 'target_store') and self.target_store.last_target:
                        base = self.target_store.last_target.rsplit('.', 1)[0]
                        target_ip = f"{base}.0/24"
                    result = await asyncio.get_running_loop().run_in_executor(None, plugin.scan, target_ip)
                    if result and hasattr(self, 'target_store'):
                        self.target_store.update_devices(result)
                    self.emit("INFO", {"msg": f"Step {step_num}: Discovered {len(result) if result else 0} hosts"})
                elif action == "scan_target":
                    target = self.target_store.last_target if hasattr(self, 'target_store') else None
                    if target:
                        results = await plugin.scan_target(target)
                        self.emit("INFO", {"msg": f"Step {step_num}: Found {len(results)} vulnerabilities"})
                    else:
                        self.emit("INFO", {"msg": f"Step {step_num}: No target for vuln scan"})
                elif action == "hunt":
                    findings = await plugin.hunt()
                    self.emit("INFO", {"msg": f"Step {step_num}: Found {len(findings)} secrets"})
                elif action == "pivot_scan":
                    target = self.target_store.last_target if hasattr(self, 'target_store') else None
                    if target:
                        result = await plugin.pivot_scan(target)
                        self.emit("INFO", {"msg": f"Step {step_num}: Pivot scan: {result}"})
                elif action == "scan_wifi":
                    networks = plugin.scan_wifi()
                    self.emit("INFO", {"msg": f"Step {step_num}: Found {len(networks)} networks"})
                elif action in ("start", "fuzz_snmp", "fuzz_mdns", "fuzz_upnp"):
                    if asyncio.iscoroutinefunction(method):
                        await method()
                    else:
                        method()
                    self.emit("INFO", {"msg": f"Step {step_num}: {plugin_name} activated"})
                else:
                    if asyncio.iscoroutinefunction(method):
                        await method()
                    else:
                        method()
                    self.emit("INFO", {"msg": f"Step {step_num}: {plugin_name}.{action} executed"})

                completed += 1
            except Exception as e:
                self.emit("ERROR", {"msg": f"Step {step_num}: {plugin_name} error: {str(e)[:80]}"})

        self.emit("SUCCESS", {"msg": f"Attack sequence complete: {completed}/{len(plan)} steps executed"})

    def get_graph_data(self):
        """
        Return graph for D3.js visualization.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, type FROM nodes")
        nodes = [{"id": row[0], "type": row[1]} for row in c.fetchall()]
        c.execute("SELECT source, target, type FROM edges")
        links = [{"source": row[0], "target": row[1], "type": row[2]} for row in c.fetchall()]
        conn.close()
        return {"nodes": nodes, "links": links}
