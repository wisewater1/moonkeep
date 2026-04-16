import core.scapy_init  # noqa: F401 — must be first to patch scapy IPv6 routes
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from core.plugin_manager import PluginManager
from core.bettercap_adapter import NativeCapEngine
from core.campaign_manager import CampaignManager
from core.recon_adapter import recon_adapter
import os
import time
import socket
import asyncio
import sys
import json
import ipaddress
from pydantic import BaseModel
from typing import Optional

# Global State Management
class TargetStore:
    def __init__(self, cm: CampaignManager):
        self.cm = cm
        self.active_campaign = "default"
        if not self.cm.get_campaign("default"):
            self.cm.create_campaign("default", "Default Workspace", "Standard session limits", "192.168.0.0/16")
            
        self.devices = self.cm.load_devices("default")
        self.networks = self.cm.load_networks("default")
        self.credentials = self.cm.load_credentials("default")
        self.last_target = self.devices[0].get('ip') if self.devices else None
        self.active_interface = None

    def set_campaign(self, campaign_id: str):
        if not self.cm.get_campaign(campaign_id):
            return False
        self.active_campaign = campaign_id
        self.devices = self.cm.load_devices(campaign_id)
        self.networks = self.cm.load_networks(campaign_id)
        self.credentials = self.cm.load_credentials(campaign_id)
        self.last_target = self.devices[0].get('ip') if self.devices else None
        return True

    def update_devices(self, devices):
        self.devices = devices
        if devices: self.last_target = devices[0].get('ip')
        for d in devices: self.cm.save_device(self.active_campaign, d)

    def update_networks(self, networks):
        self.networks = networks
        for n in networks: self.cm.save_network(self.active_campaign, n)

    def save_credential(self, plugin: str, content: str):
        self.credentials.append({"plugin": plugin, "content": content, "ts": time.time()})
        self.cm.save_credential(self.active_campaign, plugin, content)

campaign_manager = CampaignManager()
target_store = TargetStore(campaign_manager)
event_queue = asyncio.Queue(maxsize=1000)


def _emit(event):
    """Non-blocking event emit with backpressure — drops when full."""
    try:
        event_queue.put_nowait(event)
    except asyncio.QueueFull:
        pass
cap_engine = NativeCapEngine()
connected_clients: set[WebSocket] = set()

async def broadcast_events():
    while True:
        event = await event_queue.get()
        dead_clients = set()
        for client in connected_clients:
            try:
                await client.send_json(event)
            except Exception:
                dead_clients.add(client)
        for dead in dead_clients:
            connected_clients.discard(dead)


# Force discovery of all Elite modules
try:
    import plugins.spoofer
    import plugins.wifi_strike
    import plugins.post_exploit
    import plugins.fuzzer
    import plugins.hid_ble
    print("Elite modules discovered successfully")
except Exception as e:
    print(f"Elite module discovery error: {e}")

app = FastAPI(title="Moonkeep Elite API")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_events())

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Plugin Manager
PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "plugins")
plugin_manager = PluginManager(PLUGINS_DIR)
plugin_manager.load_plugins()

# Inject state into all plugins for real-time telemetry and persistence
for plugin in plugin_manager.plugins.values():
    plugin.event_queue = event_queue
    plugin.target_store = target_store
    plugin.bettercap = cap_engine

# Wire the native engine to the plugin system
cap_engine.inject(plugin_manager, event_queue, target_store)
print("NativeCapEngine online — type 'help' in the CLI")

@app.get("/interfaces")
def list_interfaces():
    from scapy.all import conf
    ifaces = []
    for iface in conf.ifaces.values():
        ifaces.append({
            "name": iface.name,
            "description": iface.description,
            "ip": iface.ip
        })
    return ifaces

@app.get("/plugins")
def list_plugins():
    return plugin_manager.list_plugins()

# ─── CAMPAIGN ENDPOINTS ──────────────────────────────────────────

@app.get("/campaigns")
async def list_campaigns():
    return campaign_manager.list_campaigns()

class CampaignCreate(BaseModel):
    id: str
    name: str
    description: str
    scope: str

@app.post("/campaigns")
async def create_campaign(c: CampaignCreate):
    return campaign_manager.create_campaign(c.id, c.name, c.description, c.scope)

@app.put("/campaigns/{campaign_id}/activate")
async def activate_campaign(campaign_id: str):
    if target_store.set_campaign(campaign_id):
        _emit({"type": "INFO", "msg": f"[SYSTEM] Workspace switched to {campaign_id}"})
        return {"status": "ok", "active": campaign_id}
    raise HTTPException(status_code=404, detail="Campaign not found")

@app.get("/campaigns/{campaign_id}/report")
async def export_report(campaign_id: str, fmt: str = "markdown"):
    if fmt not in ("markdown", "json", "csv"):
        raise HTTPException(status_code=400, detail="Format must be markdown, json, or csv")
    campaign = campaign_manager.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    report = campaign_manager.export_report(campaign_id, fmt=fmt)
    return {"report": report, "format": fmt}

# ─── NATIVE CAP ENGINE CLI ────────────────────────────────────────
class CapCmd(BaseModel):
    cmd: str

@app.get("/bettercap/status")
def cap_status():
    return {
        "installed": True,
        "running": cap_engine.is_running(),
        "api_url": "native://moonkeep",
        "active_modules": list(cap_engine.active_modules)
    }

@app.post("/bettercap/start")
def cap_start():
    return {"status": "ok", "msg": "Native engine is always running."}

@app.post("/bettercap/stop")
def cap_stop():
    return {"status": "ok", "msg": "Native engine cannot be stopped."}

@app.post("/bettercap/command")
def cap_command(body: CapCmd):
    result = cap_engine.run_command(body.cmd)
    return result

@app.get("/bettercap/session")
def cap_session():
    return cap_engine._show_info()

@app.get("/graph")
def get_attack_graph():
    ai = plugin_manager.get_plugin("AI-Orchestrator")
    if not ai:
        return {"nodes": [], "links": []}
    return ai.get_graph_data()

@app.get("/scan")
async def perform_scan(target: str = ""):
    scanner = plugin_manager.get_plugin("Scanner")
    if not scanner:
        raise HTTPException(status_code=404, detail="Scanner plugin not found")

    if not target:
        if target_store.devices:
            return {"target": "CACHED", "devices": target_store.devices}
        local_ip = scanner.get_local_ip()
        target = ".".join(local_ip.split(".")[:-1]) + ".0/24"

    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid target: {target}. Use IP or CIDR notation.")

    try:
        devices = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, scanner.scan, target),
            timeout=120.0
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out (120s limit)")
    target_store.update_devices(devices)
    return {"target": target, "devices": devices}

@app.get("/wifi_scan")
async def perform_wifi_scan():
    # Automatically turn on wifi.recon 
    cap_engine.run_command("wifi.recon on")
    await asyncio.sleep(2)

    wardriver = plugin_manager.get_plugin("Wardriver")
    networks = []
    if wardriver:
        networks = wardriver.scan_wifi()
        target_store.update_networks(networks) # PERSIST TO GLOBAL STORE
    return {"networks": networks}

class WifiDeauthBody(BaseModel):
    target: str = "ff:ff:ff:ff:ff:ff"
    ap: str

@app.post("/wifi/deauth")
async def wifi_deauth(body: WifiDeauthBody):
    res = cap_engine.run_command(f"wifi.deauth {body.target}")
    return res

class WifiBSSIDBody(BaseModel):
    bssid: str

@app.post("/wifi/capture_passive")
async def wifi_capture_passive(body: WifiBSSIDBody):
    cap_engine.run_command("wifi.recon on")
    return {"status": "ok", "message": f"Listening for handshakes from {body.bssid} (check logs folder)"}

# SECRET HUNTER ELITE ENDPOINTS
@app.post("/secret_hunter/hunt")
async def secret_hunter_start():
    plugin = plugin_manager.get_plugin("Secret-Hunter")
    if not plugin: raise HTTPException(status_code=404)
    findings = await plugin.hunt()
    return {"status": "Hunt complete", "findings": findings}

@app.get("/secret_hunter/results")
async def secret_hunter_results():
    plugin = plugin_manager.get_plugin("Secret-Hunter")
    if not plugin: raise HTTPException(status_code=404)
    return {"findings": getattr(plugin, 'last_findings', [])}

@app.get("/vuln_scan")
async def vulnerability_scan(target: str = None):
    if not target:
        target = target_store.last_target
    if not target:
        # Auto-discover local subnet target
        scanner = plugin_manager.get_plugin("Scanner")
        if scanner:
            local_ip = scanner.get_local_ip()
            target = local_ip
        else:
            raise HTTPException(status_code=400, detail="No target specified. Run /scan first or provide ?target=X.X.X.X")
    # Validate IP
    try:
        socket.inet_aton(target)
    except socket.error:
        raise HTTPException(status_code=400, detail=f"Invalid target IP: {target}")
    vuln_plugin = plugin_manager.get_plugin("Vuln-Scanner")
    if not vuln_plugin:
        raise HTTPException(status_code=404, detail="Vuln-Scanner plugin not found")
    _emit({"ts": time.time(), "plugin": "Vuln-Scanner", "type": "INFO", "data": {"msg": f"Initiating deep audit on {target}"}})
    asyncio.create_task(vuln_plugin.scan_target(target))
    return {"status": "Analysis in progress", "target": target}

# CYBER STRIKE ENDPOINTS
class CyberStrikeBody(BaseModel):
    role: str

@app.post("/cyber_strike/start")
async def cyber_strike_start(body: CyberStrikeBody):
    plugin = plugin_manager.get_plugin("Cyber-Strike")
    if plugin:
        asyncio.create_task(plugin.start(role=body.role, plugin_manager=plugin_manager))
    return {"status": f"Invoked {body.role}"}

@app.post("/cyber_strike/stop")
async def cyber_strike_stop():
    plugin = plugin_manager.get_plugin("Cyber-Strike")
    if plugin: await plugin.stop()
    return {"status": "Stopped"}

@app.get("/cyber_strike/status")
async def cyber_strike_status():
    plugin = plugin_manager.get_plugin("Cyber-Strike")
    return {"status": plugin.status if plugin else "IDLE", "log": getattr(plugin, 'log', [])}

# AI ORCHESTRATOR ENDPOINTS
class AIAnalyzeBody(BaseModel):
    instruction: str

@app.post("/ai/command")
async def ai_command(body: AIAnalyzeBody):
    plugin = plugin_manager.get_plugin("AI-Orchestrator")
    if plugin:
        context = {"devices": target_store.devices}
        plan = await plugin.plan_attack(body.instruction, context)
        return {"status": "Command parsed", "plan": plan}
    return {"status": "Error", "plan": []}

class AIExecuteBody(BaseModel):
    plan: list

@app.post("/ai/execute")
async def ai_execute(body: AIExecuteBody):
    plugin = plugin_manager.get_plugin("AI-Orchestrator")
    if plugin:
        asyncio.create_task(plugin.execute_plan(body.plan, plugin_manager))
    return {"status": "Executing Sequence"}

@app.post("/ai/analyze")
async def ai_analyze():
    plugin = plugin_manager.get_plugin("AI-Orchestrator")
    if plugin:
        insights = await plugin.analyze_devices(target_store.devices)
        return {"insights": insights}
    return {"insights": []}

# POST-EXPLOIT ELITE ENDPOINTS
class PivotBody(BaseModel):
    target_ip: str

@app.post("/post_exploit/pivot")
async def pe_pivot(body: PivotBody):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin: raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
    return await plugin.pivot_scan(body.target_ip)

class ExfilBody(BaseModel):
    target_session_id: Optional[str] = None

@app.post("/post_exploit/exfiltrate")
async def pe_exfiltrate(body: ExfilBody):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin: raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
    target = body.target_session_id or (target_store.devices[0].get('ip') if target_store.devices else '192.168.1.1')
    _emit({"ts": time.time(), "plugin": "Post-Exploit", "type": "INFO", "data": {"msg": f"Harvesting data from session: {target}"}})
    return {"status": "Exfiltration initiated", "target": target}

@app.get("/post_exploit/persistence")
async def pe_persistence(os_type: str = "windows"):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin: raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
    return await plugin.generate_persistence(os_type)

class FuzzerTargetBody(BaseModel):
    ip: Optional[str] = None

@app.post("/fuzzer/mdns")
async def fuzz_mdns(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin: raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_mdns(target_ip)

@app.post("/fuzzer/snmp")
async def fuzz_snmp(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin: raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_snmp(target_ip)

@app.post("/fuzzer/upnp")
async def fuzz_upnp(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin: raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_upnp(target_ip)

@app.get("/fuzzer/stats")
async def fuzzer_stats():
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin: raise HTTPException(status_code=404)
    return plugin.get_stats()

# WIFI HANDSHAKES
@app.get("/wifi/handshakes")
async def wifi_handshakes():
    plugin = plugin_manager.get_plugin("WiFi-Strike")
    if not plugin: raise HTTPException(status_code=404)
    return {"handshakes": plugin.get_handshakes()}

@app.post("/wifi/pmkid")
async def wifi_pmkid(body: WifiBSSIDBody):
    plugin = plugin_manager.get_plugin("WiFi-Strike")
    if not plugin: raise HTTPException(status_code=404)
    return await plugin.pmkid_capture(body.bssid)

# DNS LOG FROM SNIFFER
@app.get("/sniffer/dns")
async def sniffer_dns_log():
    plugin = plugin_manager.get_plugin("Sniffer")
    if not plugin: raise HTTPException(status_code=404)
    return {"dns_log": plugin.get_dns_log()}

# HID-BLE ELITE ENDPOINTS
@app.get("/hid_ble/scan")
async def hid_ble_scan():
    plugin = plugin_manager.get_plugin("HID-BLE-Strike")
    if not plugin: raise HTTPException(status_code=404, detail="HID-BLE plugin not found")
    return await plugin.scan_ble()

class HIDInjectBody(BaseModel):
    target_mac: str

@app.post("/hid_ble/inject")
async def hid_ble_inject(body: HIDInjectBody):
    plugin = plugin_manager.get_plugin("HID-BLE-Strike")
    if not plugin: raise HTTPException(status_code=404)
    return await plugin.mousejack_inject(body.target_mac)

# SNIFFER ELITE ENDPOINTS
@app.get("/sniffer/credentials")
async def get_captured_credentials():
    plugin = plugin_manager.get_plugin("Sniffer")
    if not plugin: raise HTTPException(status_code=404, detail="Sniffer plugin not found")
    return {"credentials": plugin.credentials}

@app.post("/sniffer/start")
async def sniffer_start():
    return cap_engine.run_command("net.sniff on")

@app.post("/sniffer/stop")
async def sniffer_stop():
    return cap_engine.run_command("net.sniff off")

class ProxyStartBody(BaseModel):
    port: Optional[int] = 8080

# PROXY ELITE ENDPOINTS
@app.post("/proxy/start")
async def proxy_start(body: ProxyStartBody = None):
    port = body.port if body else 8080
    plugin = plugin_manager.get_plugin("Proxy")
    if plugin:
        await plugin.start(port=port)
    return cap_engine.run_command("http.proxy on")

@app.post("/proxy/stop")
async def proxy_stop():
    return cap_engine.run_command("http.proxy off")

# (removed legacy GET /cyber_strike/start — POST /cyber_strike/start is the canonical route)

# SPOOFER ELITE ENDPOINTS
class SpooferStartBody(BaseModel):
    targets: Optional[list[str]] = None

@app.post("/spoofer/start")
async def spoofer_start(body: SpooferStartBody = None):
    plugin = plugin_manager.get_plugin("Spoofer")
    targets = body.targets if body else None
    if plugin:
        await plugin.start(targets=targets, gateway=None)
    if targets:
        cap_engine.run_command(f"set arp.spoof.targets {','.join(targets)}")
    return cap_engine.run_command("arp.spoof on")

@app.post("/spoofer/stop")
async def spoofer_stop():
    return cap_engine.run_command("arp.spoof off")

# WIFI ELITE ENDPOINTS
class WifiCaptureBody(BaseModel):
    bssid: str

@app.post("/wifi/capture")
async def wifi_capture(body: WifiCaptureBody):
    p = plugin_manager.get_plugin("WiFi-Strike")
    if not p: raise HTTPException(status_code=404)
    return await p.capture_handshake(body.bssid)

@app.websocket("/ws/recon")
async def recon_websocket(websocket: WebSocket):
    await websocket.accept()
    recon_adapter.start()

    async def recv_from_ws():
        try:
            while True:
                data = await websocket.receive_text()
                recon_adapter.send_input(data)
        except WebSocketDisconnect:
            pass

    async def send_to_ws():
        try:
            async for chunk in recon_adapter.get_output():
                await websocket.send_bytes(chunk)
        except Exception:
            pass

    task1 = asyncio.create_task(recv_from_ws())
    task2 = asyncio.create_task(send_to_ws())
    try:
        done, pending = await asyncio.wait(
            [task1, task2],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        recon_adapter.stop()
        try:
            await websocket.close()
        except Exception:
            pass
        print("[Recon WS] Client disconnected, recon-ng process cleaned up")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        print("Client disconnected")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
