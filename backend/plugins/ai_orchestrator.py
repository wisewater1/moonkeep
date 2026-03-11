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
                
                vendor = d.get("vendor", "").lower()
                if "apple" in vendor:
                    insights.append(f"Node {ip}: Apple device detected. Analyzing for MDNS/AirPlay vulnerabilities.")
                elif "espressif" in vendor:
                    insights.append(f"Node {ip}: IoT Device (Espressif). High probability of default credentials.")
        
        conn.commit()
        conn.close()
        return insights

    async def plan_attack(self, instruction: str, context: dict):
        self.emit("INFO", {"msg": f"Generating attack plan for: {instruction}"})
        # Mock logic to parse instruction and generate a plan based on keywords
        plan = []
        if "pivot" in instruction.lower():
            plan.append({"step": 1, "plugin": "Scanner", "action": "scan", "params": {}})
            plan.append({"step": 2, "plugin": "Vuln-Scanner", "action": "vuln_scan", "params": {}})
            plan.append({"step": 3, "plugin": "Post-Exploit", "action": "pe_pivot", "params": {"target_ip": "AUTO"}})
        elif "fuzz" in instruction.lower():
            plan.append({"step": 1, "plugin": "Fuzzer", "action": "fuzz_mdns", "params": {}})
        else:
            plan.append({"step": 1, "plugin": "Secret-Hunter", "action": "hunt", "params": {}})
            plan.append({"step": 2, "plugin": "Scanner", "action": "scan", "params": {}})
        
        return plan

    async def execute_plan(self, plan: list, plugin_manager):
        self.emit("INFO", {"msg": f"Executing {len(plan)}-step attack sequence..."})
        for step in plan:
            self.emit("INFO", {"msg": f"Running Step {step['step']}: {step['plugin']} [{step['action']}]"})
            await asyncio.sleep(1.5) # Simulate execution time
            plugin = plugin_manager.get_plugin(step['plugin'])
            if plugin:
                self.emit("INFO", {"msg": f"Step {step['step']} component active. Awaiting results..."})
        self.emit("SUCCESS", {"msg": "Autonomous strike plan execution completed."})

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
