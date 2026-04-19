from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from core.plugin_manager import PluginManager
from core.bettercap_adapter import NativeCapEngine
from core.campaign_manager import CampaignManager
from core.recon_adapter import recon_adapter
from core.pipeline_engine import PipelineEngine
import os
import time
import socket
import asyncio
import sys
import json
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
event_queue = asyncio.Queue()
cap_engine = NativeCapEngine()
connected_clients: set[WebSocket] = set()
pipeline_engine = PipelineEngine()

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
        # Forward every event to the pipeline engine for automated chaining
        asyncio.create_task(pipeline_engine.process_event(event))


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
    pipeline_engine.inject(plugin_manager, target_store, event_queue)

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
        event_queue.put_nowait({"type": "INFO", "msg": f"[SYSTEM] Workspace switched to {campaign_id}"})
        return {"status": "ok", "active": campaign_id}
    raise HTTPException(status_code=404, detail="Campaign not found")

@app.get("/campaigns/{campaign_id}/report")
async def export_report(campaign_id: str):
    report = campaign_manager.export_report(campaign_id)
    if report == "Campaign not found.":
        raise HTTPException(status_code=404)
    return {"report": report}

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
        if target_store.devices: # Hydrate from store if exists
            return {"target": "CACHED", "devices": target_store.devices}
        local_ip = scanner.get_local_ip()
        target = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, scanner.scan, target)
    target_store.update_devices(devices) # PERSIST TO GLOBAL STORE
    return {"target": target, "devices": devices}

@app.get("/wifi_scan")
async def perform_wifi_scan():
    # Automatically turn on wifi.recon 
    engine2 = cap_engine
    engine2.run_command("wifi.recon on")
    await asyncio.sleep(2) # brief pause to let it scan

    wardriver = plugin_manager.get_plugin("Wardriver")
    networks = []
    if wardriver:
        networks = wardriver.scan_wifi()
        target_store.update_networks(networks) # PERSIST TO GLOBAL STORE
    return {"networks": networks}

@app.post("/wifi/deauth")
async def wifi_deauth(payload: dict):
    engine2 = cap_engine
    # Expecting {"target": "...", "ap": "..."} in the JSON body
    ap = payload.get("ap")
    target = payload.get("target", "ff:ff:ff:ff:ff:ff")
    if not ap:
        raise HTTPException(status_code=400, detail="AP MAC is required")
    # Native bettercap engine: wifi.deauth <target> (it automatically manages the AP based on what it sees, but we can just use the target mac)
    # The actual bettercap usually targets a specific client MAC, but broadcast is fine.
    res = engine2.run_command(f"wifi.deauth {target}")
    return res

@app.get("/ai/analyze")
async def trigger_ai_analysis():
    orchestrator = plugin_manager.get_plugin("AI-Orchestrator")
    if not orchestrator:
        raise HTTPException(status_code=404, detail="AI Orchestrator not found")
    
    devices = target_store.devices
    if not devices:
        scanner = plugin_manager.get_plugin("Scanner")
        if scanner:
            local_ip = scanner.get_local_ip()
            target = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            devices = scanner.scan(target)
            target_store.update_devices(devices)
    
    insights = await orchestrator.analyze_devices(devices)
    return {"insights": insights}

# SECRET HUNTER ELITE ENDPOINTS
@app.post("/secret_hunter/hunt")
async def secret_hunter_start():
    plugin = plugin_manager.get_plugin("Secret-Hunter")
    if not plugin: raise HTTPException(status_code=404)
    asyncio.create_task(plugin.hunt())
    return {"status": "Hunting secrets in background"}

@app.get("/vuln_scan")
async def vulnerability_scan(target: str = None):
    if not target: target = target_store.last_target
    if not target: raise HTTPException(status_code=400, detail="No target specified")
    plugin = plugin_manager.get_plugin("Vuln-Scanner")
    if not plugin: raise HTTPException(status_code=404, detail="Vuln-Scanner not available")
    orchestrator = plugin_manager.get_plugin("AI-Orchestrator")

    async def _scan_and_ingest():
        results = await plugin.scan_target(target)
        if orchestrator and results:
            orchestrator.ingest_vuln_results(target, results)

    asyncio.create_task(_scan_and_ingest())
    return {"status": "Vulnerability scan launched", "target": target}

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
    session_id = body.target_session_id or (
        f"session_{target_store.devices[0].get('ip', '').replace('.', '_')}"
        if target_store.devices else "local"
    )
    asyncio.create_task(plugin.exfiltrate_secrets(session_id))
    return {"status": "exfiltration_launched", "session_id": session_id}

@app.get("/post_exploit/persistence")
async def pe_persistence(os: str = "windows"):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin: raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
    return await plugin.generate_persistence(os)

@app.post("/fuzzer/mdns")
async def fuzz_mdns(ip: str = "224.0.0.251"):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin: raise HTTPException(status_code=404)
    return await plugin.fuzz_mdns(ip)

# HID-BLE ELITE ENDPOINTS
@app.get("/hid_ble/scan")
async def hid_ble_scan():
    plugin = plugin_manager.get_plugin("HID-BLE-Strike")
    if not plugin: raise HTTPException(status_code=404, detail="HID-BLE plugin not found")
    return await plugin.scan_ble()

@app.post("/hid_ble/inject")
async def hid_ble_inject(target_mac: str):
    plugin = plugin_manager.get_plugin("HID-BLE-Strike")
    if not plugin: raise HTTPException(status_code=404)
    return await plugin.mousejack_inject(target_mac)

# SNIFFER ELITE ENDPOINTS
@app.get("/sniffer/credentials")
async def get_captured_credentials():
    plugin = plugin_manager.get_plugin("Sniffer")
    if not plugin: raise HTTPException(status_code=404, detail="Sniffer plugin not found")
    return {"credentials": plugin.credentials}

@app.post("/sniffer/start")
async def sniffer_start():
    plugin = plugin_manager.get_plugin("Sniffer")
    if plugin:
        await plugin.start()
        return {"status": "sniffer_active", "mode": "DPI"}
    return cap_engine.run_command("net.sniff on")

@app.post("/sniffer/stop")
async def sniffer_stop():
    plugin = plugin_manager.get_plugin("Sniffer")
    if plugin:
        await plugin.stop()
        return {"status": "sniffer_stopped"}
    return cap_engine.run_command("net.sniff off")

# PROXY ELITE ENDPOINTS
class ProxyStartBody(BaseModel):
    port: int = 8080
    script: Optional[str] = None

@app.post("/proxy/start")
async def proxy_start(body: ProxyStartBody = ProxyStartBody()):
    plugin = plugin_manager.get_plugin("Proxy")
    if plugin:
        await plugin.start(port=body.port, script=body.script)
        return {"status": "proxy_active", "port": body.port,
                "ca_cert": getattr(plugin, "_ca_cert", None)}
    return cap_engine.run_command("http.proxy on")

@app.post("/proxy/stop")
async def proxy_stop():
    plugin = plugin_manager.get_plugin("Proxy")
    if plugin:
        await plugin.stop()
        return {"status": "proxy_stopped"}
    return cap_engine.run_command("http.proxy off")

# (removed legacy GET /cyber_strike/start — POST /cyber_strike/start is the canonical route)

# SPOOFER ELITE ENDPOINTS
class SpooferStartBody(BaseModel):
    targets: Optional[list[str]] = None
    gateway: Optional[str] = None
    dns_table: Optional[dict] = None

@app.post("/spoofer/start")
async def spoofer_start(body: SpooferStartBody = SpooferStartBody()):
    plugin = plugin_manager.get_plugin("Spoofer")
    if plugin:
        await plugin.start(
            targets=body.targets,
            gateway=body.gateway,
            dns_table=body.dns_table,
        )
        return {"status": "spoofer_active",
                "targets": body.targets,
                "gateway": body.gateway}
    # cap_engine fallback
    if body.targets:
        cap_engine.run_command(f"set arp.spoof.targets {','.join(body.targets)}")
    return cap_engine.run_command("arp.spoof on")

@app.post("/spoofer/stop")
async def spoofer_stop():
    plugin = plugin_manager.get_plugin("Spoofer")
    if plugin:
        await plugin.stop()
        return {"status": "spoofer_stopped"}
    return cap_engine.run_command("arp.spoof off")

# WIFI ELITE ENDPOINTS
@app.post("/wifi/capture")
async def wifi_capture(bssid: str):
    p = plugin_manager.get_plugin("WiFi-Strike")
    if not p: raise HTTPException(status_code=404)
    return await p.capture_handshake(bssid)

# ─── CRED SPRAY ──────────────────────────────────────────────────────
class SprayBody(BaseModel):
    target_ip: Optional[str] = None
    credential: Optional[str] = None

@app.post("/cred_spray/run")
async def cred_spray_run(body: SprayBody):
    plugin = plugin_manager.get_plugin("Cred-Spray")
    if not plugin: raise HTTPException(status_code=404, detail="Cred-Spray not found")
    if body.credential:
        plugin.add_credential(body.credential)
    if body.target_ip:
        plugin.add_target(body.target_ip, [22, 21, 80, 443, 8080, 3306, 5432, 6379])
    asyncio.create_task(plugin.run_spray())
    return {"status": "spray_launched",
            "credentials": len(plugin._credential_pool),
            "targets": len(plugin._targets)}

@app.get("/cred_spray/results")
async def cred_spray_results():
    plugin = plugin_manager.get_plugin("Cred-Spray")
    if not plugin: raise HTTPException(status_code=404)
    return {"results": plugin.results,
            "pool_size": len(plugin._credential_pool),
            "target_count": len(plugin._targets)}

# ─── EXPLOIT MAPPER ───────────────────────────────────────────────────
@app.post("/exploit_mapper/map")
async def exploit_map(target: str = None):
    plugin = plugin_manager.get_plugin("Exploit-Mapper")
    vs     = plugin_manager.get_plugin("Vuln-Scanner")
    if not plugin: raise HTTPException(status_code=404, detail="Exploit-Mapper not found")
    ip = target or target_store.last_target
    if not ip: raise HTTPException(status_code=400, detail="No target")
    vuln_results = []
    if vs:
        vuln_results = await vs.scan_target(ip)
        for v in vuln_results:
            v["ip"] = ip
    suggestions = plugin.map_cves(vuln_results)
    return {"ip": ip, "suggestions": suggestions, "msf_commands": plugin.get_msf_commands(ip)}

@app.get("/exploit_mapper/mappings")
async def exploit_mappings():
    plugin = plugin_manager.get_plugin("Exploit-Mapper")
    if not plugin: raise HTTPException(status_code=404)
    return {"mappings": plugin.mappings}

# ─── WEB SCANNER ─────────────────────────────────────────────────────
class WebScanBody(BaseModel):
    host: str
    port: int = 80
    https: bool = False

@app.post("/web_scanner/scan")
async def web_scan(body: WebScanBody):
    plugin = plugin_manager.get_plugin("Web-Scanner")
    if not plugin: raise HTTPException(status_code=404, detail="Web-Scanner not found")
    asyncio.create_task(plugin.scan(body.host, body.port, body.https))
    return {"status": "scan_launched", "host": body.host, "port": body.port}

@app.get("/web_scanner/findings")
async def web_findings():
    plugin = plugin_manager.get_plugin("Web-Scanner")
    if not plugin: raise HTTPException(status_code=404)
    return {"findings": plugin.findings}

# ─── HASH CRACKER ────────────────────────────────────────────────────
class CrackBody(BaseModel):
    hash: Optional[str] = None
    shadow_path: Optional[str] = None
    pcap_path: Optional[str] = None
    bssid: Optional[str] = ""

@app.post("/hash_cracker/crack")
async def hash_crack(body: CrackBody):
    plugin = plugin_manager.get_plugin("Hash-Cracker")
    if not plugin: raise HTTPException(status_code=404, detail="Hash-Cracker not found")
    if body.hash:
        asyncio.create_task(plugin.crack_hash(body.hash))
    elif body.shadow_path:
        asyncio.create_task(plugin.crack_shadow(body.shadow_path))
    elif body.pcap_path:
        asyncio.create_task(plugin.crack_pcap(body.pcap_path, body.bssid or ""))
    else:
        raise HTTPException(status_code=400, detail="Provide hash, shadow_path, or pcap_path")
    return {"status": "crack_launched"}

@app.get("/hash_cracker/results")
async def hash_results():
    plugin = plugin_manager.get_plugin("Hash-Cracker")
    if not plugin: raise HTTPException(status_code=404)
    return {"results": plugin.results}

# ─── OSINT ENRICHER ──────────────────────────────────────────────────
@app.get("/osint/enrich")
async def osint_enrich(ip: str):
    plugin = plugin_manager.get_plugin("OSINT-Enricher")
    if not plugin: raise HTTPException(status_code=404, detail="OSINT-Enricher not found")
    result = await plugin.enrich(ip)
    return result

@app.post("/osint/enrich_all")
async def osint_enrich_all():
    plugin = plugin_manager.get_plugin("OSINT-Enricher")
    if not plugin: raise HTTPException(status_code=404)
    asyncio.create_task(plugin.enrich_batch(target_store.devices))
    return {"status": "enrichment_launched", "hosts": len(target_store.devices)}

# ─── REPORT BUILDER ──────────────────────────────────────────────────
@app.post("/report/generate")
async def generate_report(campaign_id: str = None):
    plugin = plugin_manager.get_plugin("Report-Builder")
    if not plugin: raise HTTPException(status_code=404, detail="Report-Builder not found")
    result = await plugin.generate(campaign_id)
    return result

@app.get("/report/{campaign_id}/html")
async def get_report_html(campaign_id: str):
    from fastapi.responses import FileResponse
    plugin = plugin_manager.get_plugin("Report-Builder")
    if not plugin: raise HTTPException(status_code=404)
    result = await plugin.generate(campaign_id)
    html_path = result.get("html_path")
    if not html_path or not os.path.exists(html_path):
        raise HTTPException(status_code=500, detail="Report generation failed")
    return FileResponse(html_path, media_type="text/html")

# ─── PIPELINE ENGINE ─────────────────────────────────────────────────
class PipelineRuleBody(BaseModel):
    rule: str
    enabled: bool

@app.get("/pipeline/status")
async def pipeline_status():
    return pipeline_engine.get_status()

@app.post("/pipeline/rule")
async def pipeline_set_rule(body: PipelineRuleBody):
    ok = pipeline_engine.set_rule(body.rule, body.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Rule '{body.rule}' not found")
    return {"rule": body.rule, "enabled": body.enabled}

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

    # Run both tasks concurrently
    task1 = asyncio.create_task(recv_from_ws())
    task2 = asyncio.create_task(send_to_ws())
    
    done, pending = await asyncio.wait(
        [task1, task2],
        return_when=asyncio.FIRST_COMPLETED
    )
    
    for task in pending:
        task.cancel()
    
    print("[Recon WS] Client disconnected")

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
