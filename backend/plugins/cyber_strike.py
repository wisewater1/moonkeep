from core.plugin_manager import BasePlugin
import asyncio
import time

class CyberStrikePlugin(BasePlugin):
    def __init__(self):
        self.roles = {
            "Shadow": {
                "priority": "Stealth Recon",
                "sequence": [
                    ("Scanner", "scan", "Probing network topology..."),
                    ("AI-Orchestrator", "analyze_devices", "Reasoning over discovered targets..."),
                    ("Secret-Hunter", "hunt", "Hunting exposed secrets across file systems..."),
                    ("Vuln-Scanner", "scan_target", "Cross-referencing CVE database..."),
                ],
            },
            "Infiltrator": {
                "priority": "MITM Strike",
                "sequence": [
                    ("Scanner", "scan", "Mapping attack surface..."),
                    ("Spoofer", "start", "Poisoning ARP tables..."),
                    ("Sniffer", "start", "Activating deep packet inspection..."),
                    ("Proxy", "start", "HTTP intercept proxy engaged..."),
                ],
            },
            "Ghost": {
                "priority": "Signal Ghost",
                "sequence": [
                    ("Wardriver", "scan_wifi", "Scanning wireless spectrum..."),
                    ("WiFi-Strike", "start", "Initializing wireless interface..."),
                    ("Sniffer", "start", "Passive traffic capture active..."),
                ],
            },
            "Reaper": {
                "priority": "Full Killchain",
                "sequence": [
                    ("Scanner", "scan", "Phase 1: Network reconnaissance..."),
                    ("Vuln-Scanner", "scan_target", "Phase 2: Vulnerability assessment..."),
                    ("AI-Orchestrator", "analyze_devices", "Phase 3: AI target prioritization..."),
                    ("Spoofer", "start", "Phase 4: MITM positioning..."),
                    ("Sniffer", "start", "Phase 5: Credential harvesting..."),
                    ("Post-Exploit", "pivot_scan", "Phase 6: Lateral movement..."),
                ],
            },
        }
        self.active_role = None
        self.status = "IDLE"
        self.log = []
        self._running = False

    @property
    def name(self) -> str:
        return "Cyber-Strike"

    @property
    def description(self) -> str:
        return "Autonomous Role-Based Strike Engine"

    async def start(self, role="Shadow", plugin_manager=None):
        self.active_role = role
        self._running = True
        self.status = f"EXECUTING {role.upper()}"
        self.log = [f"[*] Engaging {role} protocol..."]
        self.emit("INFO", {"msg": f"Cyber-Strike: {role} protocol engaged"})

        if not plugin_manager:
            self.emit("ERROR", {"msg": "No plugin manager — cannot execute sequence"})
            return

        sequence = self.roles.get(role, {}).get("sequence", [])
        completed = 0

        for plugin_name, action, description in sequence:
            if not self._running:
                self.log.append("[!] Sequence aborted by operator")
                self.emit("INFO", {"msg": "Cyber-Strike: Sequence aborted"})
                break

            self.log.append(f"[>] {description}")
            self.emit("INFO", {"msg": f"Cyber-Strike: {description}"})
            await asyncio.sleep(0.5)

            plugin = plugin_manager.get_plugin(plugin_name)
            if not plugin:
                self.log.append(f"[!] {plugin_name} not found — skipping")
                self.emit("INFO", {"msg": f"Cyber-Strike: {plugin_name} unavailable, skipping"})
                continue

            try:
                method = getattr(plugin, action, None)
                if method and callable(method):
                    # Prepare arguments based on action type
                    if action == "scan":
                        target_ip = "192.168.1.0/24"
                        if hasattr(self, 'target_store') and self.target_store and self.target_store.last_target:
                            base = self.target_store.last_target.rsplit('.', 1)[0]
                            target_ip = f"{base}.0/24"
                        result = await asyncio.get_running_loop().run_in_executor(None, plugin.scan, target_ip)
                        if result and hasattr(self, 'target_store'):
                            self.target_store.update_devices(result)
                        self.log.append(f"[+] Discovered {len(result) if result else 0} hosts")
                    elif action == "analyze_devices":
                        devices = self.target_store.devices if hasattr(self, 'target_store') else []
                        insights = await plugin.analyze_devices(devices)
                        self.log.append(f"[+] AI generated {len(insights)} insights")
                        for insight in insights[:3]:
                            self.log.append(f"    {insight}")
                    elif action == "scan_target":
                        target = self.target_store.last_target if hasattr(self, 'target_store') else None
                        if target:
                            results = await plugin.scan_target(target)
                            self.log.append(f"[+] Found {len(results)} potential vulnerabilities on {target}")
                        else:
                            self.log.append("[!] No target available for vuln scan")
                    elif action == "scan_wifi":
                        networks = plugin.scan_wifi()
                        self.log.append(f"[+] Detected {len(networks)} wireless networks")
                    elif action == "hunt":
                        await plugin.hunt()
                        self.log.append("[+] Secret hunter sweep complete")
                    elif action == "pivot_scan":
                        target = self.target_store.last_target if hasattr(self, 'target_store') else None
                        if target:
                            result = await plugin.pivot_scan(target)
                            self.log.append(f"[+] Pivot scan results: {result}")
                    elif action == "start":
                        await plugin.start()
                        self.log.append(f"[+] {plugin_name} activated")
                    else:
                        if asyncio.iscoroutinefunction(method):
                            await method()
                        else:
                            method()
                        self.log.append(f"[+] {plugin_name}.{action} executed")

                    completed += 1
                    self.emit("INFO", {"msg": f"Cyber-Strike: Step {completed}/{len(sequence)} complete"})
                else:
                    self.log.append(f"[!] {plugin_name} has no method '{action}'")
            except Exception as e:
                self.log.append(f"[!] {plugin_name} error: {str(e)[:80]}")
                self.emit("ERROR", {"msg": f"Cyber-Strike: {plugin_name} failed — {str(e)[:60]}"})

        self.status = "COMPLETE" if self._running else "ABORTED"
        self.log.append(f"[*] {role} protocol {'complete' if self._running else 'aborted'}: {completed}/{len(sequence)} steps executed")
        self.emit("SUCCESS", {"msg": f"Cyber-Strike: {role} protocol finished ({completed}/{len(sequence)} steps)"})

    async def stop(self):
        self._running = False
        self.status = "IDLE"
        self.log.append("[*] Protocol terminated by operator")
        self.emit("INFO", {"msg": "Cyber-Strike: Protocol terminated"})

    def get_status(self):
        return {
            "status": self.status,
            "role": self.active_role,
            "log": self.log,
            "config": self.roles.get(self.active_role, {}),
            "available_roles": list(self.roles.keys()),
        }
