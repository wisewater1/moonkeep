from core.plugin_manager import BasePlugin
import asyncio


class CyberStrikePlugin(BasePlugin):
    def __init__(self):
        self.roles = {
            "Shadow":      {"priority": "Stealth Recon",  "sequence": ["Scanner", "AI-Orchestrator"]},
            "Infiltrator": {"priority": "MITM Strike",    "sequence": ["Spoofer", "Proxy"]},
            "Ghost":       {"priority": "Signal Ghost",   "sequence": ["Wardriver", "Sniffer"]},
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
