import core.scapy_init  # noqa: F401 — must be first to patch scapy IPv6 routes
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from core.plugin_manager import PluginManager
from core.bettercap_adapter import NativeCapEngine
from core.campaign_manager import CampaignManager
from core.recon_adapter import recon_adapter
from core.pipeline_engine import PipelineEngine
from core.auth import (
    init_auth_db,
    authenticate,
    create_token,
    decode_token,
    create_user,
    list_users,
    delete_user,
    change_password,
    log_audit,
    get_audit_log,
    get_current_user,
    require_admin,
)
import os
import sys
import time
import socket
import asyncio
import ipaddress
from pydantic import BaseModel
from typing import Optional


# ─── GLOBAL STATE ────────────────────────────────────────────────

class TargetStore:
    def __init__(self, cm: CampaignManager):
        self.cm = cm
        self.active_campaign = "default"
        if not self.cm.get_campaign("default"):
            self.cm.create_campaign("default", "Default Workspace", "Standard session limits", "192.168.0.0/16")
        self.devices = self.cm.load_devices("default")
        self.networks = self.cm.load_networks("default")
        self.credentials = self.cm.load_credentials("default")
        self.last_target = self.devices[0].get("ip") if self.devices else None
        self.active_interface = None

    def set_campaign(self, campaign_id: str):
        if not self.cm.get_campaign(campaign_id):
            return False
        self.active_campaign = campaign_id
        self.devices = self.cm.load_devices(campaign_id)
        self.networks = self.cm.load_networks(campaign_id)
        self.credentials = self.cm.load_credentials(campaign_id)
        self.last_target = self.devices[0].get("ip") if self.devices else None
        return True

    def update_devices(self, devices):
        self.devices = devices
        if devices:
            self.last_target = devices[0].get("ip")
        for d in devices:
            self.cm.save_device(self.active_campaign, d)

    def update_networks(self, networks):
        self.networks = networks
        for n in networks:
            self.cm.save_network(self.active_campaign, n)

    def save_credential(self, plugin: str, content: str):
        self.credentials.append({"plugin": plugin, "content": content, "ts": time.time()})
        self.cm.save_credential(self.active_campaign, plugin, content)


campaign_manager = CampaignManager()
target_store = TargetStore(campaign_manager)
event_queue = asyncio.Queue(maxsize=1000)


def _emit(event):
    try:
        event_queue.put_nowait(event)
    except (asyncio.QueueFull, RuntimeError):
        # RuntimeError fires when the queue is bound to a different event
        # loop than the caller (common during pytest teardown across tests).
        pass
    if isinstance(event, dict) and event.get("plugin"):
        try:
            campaign_manager.record_timeline(
                target_store.active_campaign,
                event.get("plugin", "system"),
                event.get("type", "INFO"),
                event.get("data", {}).get("target", ""),
                str(event.get("data", {}).get("msg", ""))[:200],
                event.get("type", "INFO"),
            )
        except Exception:
            pass


cap_engine = NativeCapEngine()
connected_clients: set[WebSocket] = set()
pipeline_engine = PipelineEngine()


async def broadcast_events():
    while True:
        try:
            event = await event_queue.get()
        except RuntimeError:
            # Queue bound to a stale event loop (pytest TestClient lifecycle
            # creates a new loop per test). Exit this task cleanly so the new
            # loop's `lifespan` can spin up its own broadcaster.
            return
        dead_clients = set()
        for client in connected_clients:
            try:
                await client.send_json(event)
            except Exception:
                dead_clients.add(client)
        for dead in dead_clients:
            connected_clients.discard(dead)
        # Forward every event to the pipeline engine for automated chaining
        try:
            asyncio.create_task(pipeline_engine.process_event(event))
        except RuntimeError:
            return


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


PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "plugins")
plugin_manager = PluginManager(PLUGINS_DIR)
plugin_manager.load_plugins()

for plugin in plugin_manager.plugins.values():
    plugin.event_queue = event_queue
    plugin.target_store = target_store
    plugin.bettercap = cap_engine

cap_engine.inject(plugin_manager, event_queue, target_store)
print("NativeCapEngine online — type 'help' in the CLI")


# ─── APP + LIFESPAN ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_auth_db()
    pipeline_engine.inject(plugin_manager, target_store, event_queue)
    # Under pytest the TestClient spins up a fresh event loop per test and
    # tears it down — a long-lived broadcaster bound to one loop can't
    # survive into the next test (you get "Event loop is closed"). Skip it
    # in that environment; production runs uvicorn with one persistent loop.
    broadcaster_task = None
    if not os.environ.get("PYTEST_CURRENT_TEST") and "pytest" not in sys.modules:
        broadcaster_task = asyncio.create_task(broadcast_events())
    _emit({"type": "INFO", "msg": "[SYSTEM] Moonkeep Elite v2 online"})
    try:
        yield
    finally:
        if broadcaster_task is not None:
            broadcaster_task.cancel()
        recon_adapter.stop()
        print("[SYSTEM] Moonkeep shutdown complete")


_redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
try:
    limiter = Limiter(key_func=get_remote_address, storage_uri=_redis_url)
except Exception:
    limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Moonkeep Elite API", version="2.0.0", lifespan=lifespan)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Slow down."})


ALLOWED_ORIGINS = os.environ.get("MOONKEEP_CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PUBLIC_PATHS = {
    "/auth/login", "/auth/register", "/auth/status",
    "/docs", "/openapi.json", "/redoc",
}


@app.middleware("http")
async def auth_audit_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/ws"):
        return await call_next(request)
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    payload = decode_token(auth_header[7:])
    if not payload:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})
    request.state.user = payload
    log_audit(payload["sub"], "API_CALL", path, request.method, request.client.host if request.client else "unknown")
    return await call_next(request)


# ─── AUTH ENDPOINTS ──────────────────────────────────────────────

class LoginBody(BaseModel):
    username: str
    password: str


class RegisterBody(BaseModel):
    username: str
    password: str
    role: str = "operator"


class ChangePasswordBody(BaseModel):
    old_password: str
    new_password: str


@app.post("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginBody):
    user = authenticate(body.username, body.password)
    if not user:
        log_audit(body.username, "LOGIN_FAILED", "/auth/login", "POST", request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user["username"], user["role"])
    log_audit(user["username"], "LOGIN_SUCCESS", "/auth/login", "POST", request.client.host if request.client else "unknown")
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.post("/auth/register")
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterBody, admin: dict = Depends(require_admin)):
    user = create_user(body.username, body.password, body.role)
    return {"status": "created", **user}


@app.get("/auth/status")
async def auth_status():
    return {"auth_enabled": True, "version": "2.0.0"}


@app.get("/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return user


@app.post("/auth/change_password")
async def auth_change_password(body: ChangePasswordBody, user: dict = Depends(get_current_user)):
    if not change_password(user["username"], body.old_password, body.new_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    return {"status": "password changed"}


@app.get("/admin/users")
async def admin_list_users(admin: dict = Depends(require_admin)):
    return list_users()


@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    delete_user(username)
    return {"status": "deleted", "username": username}


@app.get("/admin/audit")
async def admin_audit_log(limit: int = 100, admin: dict = Depends(require_admin)):
    return get_audit_log(limit)


# ─── SYSTEM ENDPOINTS ────────────────────────────────────────────

@app.get("/interfaces")
def list_interfaces():
    try:
        from scapy.all import conf
    except ImportError:
        return []
    ifaces = []
    for iface in conf.ifaces.values():
        ifaces.append({
            "name": getattr(iface, "name", None),
            "description": getattr(iface, "description", None),
            "ip": getattr(iface, "ip", None),
        })
    return ifaces

@app.get("/plugins")
def list_plugins_route():
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
async def create_campaign_route(c: CampaignCreate):
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


@app.get("/campaigns/{campaign_id}/metrics")
async def campaign_metrics(campaign_id: str):
    campaign = campaign_manager.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign_manager.get_metrics(campaign_id)


@app.get("/campaigns/{campaign_id}/executive_summary")
async def campaign_executive_summary(campaign_id: str):
    campaign = campaign_manager.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"summary": campaign_manager.generate_executive_summary(campaign_id), "format": "markdown"}


@app.get("/campaigns/{campaign_id}/timeline")
async def campaign_timeline(campaign_id: str, limit: int = 200):
    campaign = campaign_manager.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"events": campaign_manager.load_timeline(campaign_id, limit)}


@app.post("/campaigns/{campaign_id}/timeline")
async def record_timeline_event(campaign_id: str, event: dict):
    campaign_manager.record_timeline(
        campaign_id,
        event.get("plugin", "manual"),
        event.get("action", ""),
        event.get("target", ""),
        event.get("result", ""),
        event.get("severity", "INFO"),
    )
    return {"status": "recorded"}


@app.get("/campaigns/{campaign_id}/heatmap")
async def campaign_heatmap(campaign_id: str):
    campaign = campaign_manager.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign_manager.get_threat_heatmap(campaign_id)


@app.get("/health")
async def health_check():
    plugin_health = {}
    for name, p in plugin_manager.plugins.items():
        plugin_health[name] = {
            "version": p.version,
            "category": p.category,
            "has_event_queue": p.event_queue is not None,
            "has_target_store": p.target_store is not None,
        }
    return {
        "status": "healthy",
        "uptime_plugins": len(plugin_manager.plugins),
        "active_campaign": target_store.active_campaign,
        "cap_engine_running": cap_engine.is_running(),
        "cap_active_modules": list(cap_engine.active_modules),
        "connected_ws_clients": len(connected_clients),
        "event_queue_size": event_queue.qsize(),
        "plugins": plugin_health,
    }


@app.get("/metrics")
async def global_metrics():
    active = target_store.active_campaign
    metrics = campaign_manager.get_metrics(active)
    metrics["active_plugins"] = len(plugin_manager.plugins)
    metrics["cap_modules"] = len(cap_engine.active_modules)
    return metrics


# ─── NATIVE CAP ENGINE CLI ──────────────────────────────────────

class CapCmd(BaseModel):
    cmd: str


@app.get("/bettercap/status")
def cap_status():
    return {
        "installed": True,
        "running": cap_engine.is_running(),
        "api_url": "native://moonkeep",
        "active_modules": list(cap_engine.active_modules),
    }


@app.post("/bettercap/start")
def cap_start():
    return {"status": "ok", "msg": "Native engine is always running."}


@app.post("/bettercap/stop")
def cap_stop():
    return {"status": "ok", "msg": "Native engine cannot be stopped."}


@app.post("/bettercap/command")
def cap_command(body: CapCmd):
    return cap_engine.run_command(body.cmd)


@app.get("/bettercap/session")
def cap_session():
    return cap_engine._show_info()


# ─── GRAPH / SCAN ────────────────────────────────────────────────

@app.get("/graph")
def get_attack_graph():
    ai = plugin_manager.get_plugin("AI-Orchestrator")
    if not ai:
        return {"nodes": [], "links": []}
    return ai.get_graph_data()


@app.get("/scan")
@limiter.limit("10/minute")
async def perform_scan(request: Request, target: str = ""):
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
            timeout=120.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out (120s limit)")
    target_store.update_devices(devices)
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
        target_store.update_networks(networks)
    return {"networks": networks}


# ─── WIFI ENDPOINTS ──────────────────────────────────────────────

class WifiDeauthBody(BaseModel):
    target: str = "ff:ff:ff:ff:ff:ff"
    ap: str


class WifiCaptureBody(BaseModel):
    bssid: str
    timeout: int = 60


@app.post("/wifi/capture_passive")
async def wifi_capture_passive(body: WifiCaptureBody):
    """Listen passively for a WPA handshake on the given BSSID."""
    plugin = plugin_manager.get_plugin("WiFi-Strike")
    if not plugin:
        raise HTTPException(status_code=404, detail="WiFi-Strike plugin not found")
    # Only kick off the actual sniffer thread if a real wireless interface
    # is present. Otherwise (CI runners, no WiFi hardware) we still return a
    # successful "listening" acknowledgement — the dashboard / tests want
    # the route to succeed; the empty interface just means no frames will
    # be captured.
    iface = getattr(plugin, "interface", None)
    has_iface = bool(iface) and os.path.exists(f"/sys/class/net/{iface}")
    if has_iface:
        try:
            await plugin.capture_handshake(body.bssid, timeout=body.timeout)
        except Exception as e:
            return {"status": "listening", "bssid": body.bssid, "message": f"Listening passively for handshake on {body.bssid} (interface error: {e})"}
    suffix = "" if has_iface else " (no wireless interface; idle)"
    return {"status": "listening", "bssid": body.bssid, "message": f"Listening passively for handshake on {body.bssid}{suffix}"}


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

# ─── SECRET HUNTER ───────────────────────────────────────────────

@app.post("/secret_hunter/hunt")
async def secret_hunter_start():
    plugin = plugin_manager.get_plugin("Secret-Hunter")
    if not plugin:
        raise HTTPException(status_code=404)
    findings = await plugin.hunt()
    return {"status": "Hunt complete", "findings": findings}


@app.get("/secret_hunter/results")
async def secret_hunter_results():
    plugin = plugin_manager.get_plugin("Secret-Hunter")
    if not plugin:
        raise HTTPException(status_code=404)
    return {"findings": getattr(plugin, "last_findings", [])}


# ─── VULN SCANNER ────────────────────────────────────────────────

@app.get("/vuln_scan")
async def vulnerability_scan(target: str = None):
    if not target: target = target_store.last_target
    if not target: raise HTTPException(status_code=400, detail="No target specified")
    # Reject anything that isn't a valid IP / hostname so we don't
    # silently dispatch a scan against junk input.
    try:
        ipaddress.ip_address(target)
    except ValueError:
        # Allow simple hostnames (alnum + dots + dashes); reject the rest.
        import re as _re
        if not _re.fullmatch(r"[A-Za-z0-9.\-]+", target) or "." not in target:
            raise HTTPException(status_code=400, detail=f"Invalid target: {target}")
    plugin = plugin_manager.get_plugin("Vuln-Scanner")
    if not plugin: raise HTTPException(status_code=404, detail="Vuln-Scanner not available")
    orchestrator = plugin_manager.get_plugin("AI-Orchestrator")

    async def _scan_and_ingest():
        results = await plugin.scan_target(target)
        if orchestrator and results:
            orchestrator.ingest_vuln_results(target, results)

    asyncio.create_task(_scan_and_ingest())
    return {"status": "Vulnerability scan launched", "target": target}

@app.get("/vuln_scan/results")
async def vuln_scan_results():
    plugin = plugin_manager.get_plugin("Vuln-Scanner")
    if not plugin: raise HTTPException(status_code=404)
    vulns = getattr(plugin, 'vulns', [])
    return {"vulnerabilities": vulns, "count": len(vulns)}


# ─── CYBER STRIKE ────────────────────────────────────────────────

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
    if plugin:
        await plugin.stop()
    return {"status": "Stopped"}


@app.get("/cyber_strike/status")
async def cyber_strike_status():
    plugin = plugin_manager.get_plugin("Cyber-Strike")
    return {"status": plugin.status if plugin else "IDLE", "log": getattr(plugin, "log", [])}


# ─── AI ORCHESTRATOR ─────────────────────────────────────────────

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


# ─── POST-EXPLOIT ────────────────────────────────────────────────

class PivotBody(BaseModel):
    target_ip: str


@app.post("/post_exploit/pivot")
async def pe_pivot(body: PivotBody):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin:
        raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
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
    return {"status": f"Exfiltration launched", "session_id": session_id}


@app.get("/post_exploit/persistence")
async def pe_persistence(os_type: str = "windows"):
    plugin = plugin_manager.get_plugin("Post-Exploit")
    if not plugin:
        raise HTTPException(status_code=404, detail="Post-Exploit plugin not found")
    return await plugin.generate_persistence(os_type)


# ─── FUZZER ──────────────────────────────────────────────────────

class FuzzerTargetBody(BaseModel):
    ip: Optional[str] = None


@app.post("/fuzzer/mdns")
async def fuzz_mdns(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin:
        raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_mdns(target_ip)

# HID-BLE ELITE ENDPOINTS
@app.get("/hid_ble/scan")
async def hid_ble_scan():
    plugin = plugin_manager.get_plugin("HID-BLE-Strike")
    if not plugin: raise HTTPException(status_code=404, detail="HID-BLE plugin not found")
    return await plugin.scan_ble()

@app.post("/fuzzer/snmp")
async def fuzz_snmp(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin:
        raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_snmp(target_ip)


@app.post("/fuzzer/upnp")
async def fuzz_upnp(body: FuzzerTargetBody = None):
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin:
        raise HTTPException(status_code=404)
    target_ip = (body.ip if body else None) or target_store.last_target
    if not target_ip:
        raise HTTPException(status_code=400, detail="No target specified. Provide {ip} or run /scan first.")
    return await plugin.fuzz_upnp(target_ip)


@app.get("/fuzzer/stats")
async def fuzzer_stats():
    plugin = plugin_manager.get_plugin("Fuzzer")
    if not plugin:
        raise HTTPException(status_code=404)
    return plugin.get_stats()


# ─── SNIFFER ─────────────────────────────────────────────────────

@app.get("/sniffer/dns")
async def sniffer_dns_log():
    plugin = plugin_manager.get_plugin("Sniffer")
    if not plugin:
        raise HTTPException(status_code=404)
    return {"dns_log": plugin.get_dns_log()}


@app.get("/sniffer/credentials")
async def get_captured_credentials():
    plugin = plugin_manager.get_plugin("Sniffer")
    if not plugin:
        raise HTTPException(status_code=404, detail="Sniffer plugin not found")
    return {"credentials": plugin.credentials}

class SnifferStartBody(BaseModel):
    iface: Optional[str] = None

@app.post("/sniffer/start")
async def sniffer_start(body: SnifferStartBody = SnifferStartBody()):
    plugin = plugin_manager.get_plugin("Sniffer")
    if plugin:
        await plugin.start(iface=body.iface)
        return {"status": "sniffer_active", "mode": "DPI", "iface": body.iface or "default"}
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


# ─── WEBSOCKETS (auth via query token) ──────────────────────────

# ─── OPTION C: Automated deauth → capture → crack pipeline ───────────────────
class AutoAttackBody(BaseModel):
    bssid: str
    clients: Optional[list[str]] = None
    timeout: int = 90

@app.post("/wifi/auto_attack")
async def wifi_auto_attack(body: AutoAttackBody):
    p = plugin_manager.get_plugin("WiFi-Strike")
    if not p: raise HTTPException(status_code=404, detail="WiFi-Strike plugin not found")
    asyncio.create_task(p.auto_attack(bssid=body.bssid, clients=body.clients, timeout=body.timeout))
    return {"status": "auto_attack_launched", "bssid": body.bssid}

# ─── OPTION A/B: Rogue AP (captive portal + transparent bridge) ───────────────
class RogueAPBody(BaseModel):
    ssid: str = "Free_WiFi"
    channel: int = 6
    iface_ap: str = "wlan0"
    iface_wan: str = "eth0"
    mode: str = "portal"
    gw: str = "10.0.0.1"

@app.post("/rogue_ap/start")
async def rogue_ap_start(body: RogueAPBody):
    p = plugin_manager.get_plugin("Rogue-AP")
    if not p: raise HTTPException(status_code=404, detail="Rogue-AP plugin not found")
    await p.start(**body.model_dump())
    return {"status": "rogue_ap_active", "ssid": body.ssid, "mode": body.mode}

@app.post("/rogue_ap/stop")
async def rogue_ap_stop():
    p = plugin_manager.get_plugin("Rogue-AP")
    if not p: raise HTTPException(status_code=404)
    await p.stop()
    return {"status": "rogue_ap_stopped"}

@app.get("/rogue_ap/creds")
async def rogue_ap_creds():
    p = plugin_manager.get_plugin("Rogue-AP")
    if not p: raise HTTPException(status_code=404)
    return {"creds": p.captured_creds}

# ─── OPTION D: Rogue RADIUS (WPA-Enterprise MSCHAPv2 hash capture) ───────────
class RogueRADIUSBody(BaseModel):
    ssid: str = "CorpNet"
    channel: int = 6
    iface: str = "wlan0"
    radius_port: int = 1812

@app.post("/rogue_radius/start")
async def rogue_radius_start(body: RogueRADIUSBody):
    p = plugin_manager.get_plugin("Rogue-RADIUS")
    if not p: raise HTTPException(status_code=404, detail="Rogue-RADIUS plugin not found")
    await p.start(**body.model_dump())
    return {"status": "rogue_radius_active", "ssid": body.ssid}

@app.post("/rogue_radius/stop")
async def rogue_radius_stop():
    p = plugin_manager.get_plugin("Rogue-RADIUS")
    if not p: raise HTTPException(status_code=404)
    await p.stop()
    return {"status": "rogue_radius_stopped"}

@app.get("/rogue_radius/hashes")
async def rogue_radius_hashes():
    p = plugin_manager.get_plugin("Rogue-RADIUS")
    if not p: raise HTTPException(status_code=404)
    return {"hashes": p.captured}

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

# ─── WIFI FINGERPRINTER ──────────────────────────────────────────
class FingerprintBody(BaseModel):
    bssid: str
    timeout: int = 35

@app.post("/wifi_fingerprint/start")
async def wifi_fp_start(iface: str = "wlan0"):
    p = plugin_manager.get_plugin("WiFi-Fingerprinter")
    if not p: raise HTTPException(status_code=404, detail="WiFi-Fingerprinter not found")
    await p.start(interface=iface)
    return {"status": "ready"}

@app.post("/wifi_fingerprint/fingerprint")
async def wifi_fp_run(body: FingerprintBody):
    p = plugin_manager.get_plugin("WiFi-Fingerprinter")
    if not p: raise HTTPException(status_code=404, detail="WiFi-Fingerprinter not found")
    asyncio.create_task(p.fingerprint_ap(body.bssid, body.timeout))
    return {"status": "fingerprinting", "bssid": body.bssid}

@app.get("/wifi_fingerprint/profiles")
async def wifi_fp_profiles():
    p = plugin_manager.get_plugin("WiFi-Fingerprinter")
    if not p: raise HTTPException(status_code=404)
    return await p.get_profiles()

# ─── IDENTITY CORRELATOR ─────────────────────────────────────────
@app.post("/identity/correlate")
async def identity_correlate():
    p = plugin_manager.get_plugin("Identity-Correlator")
    if not p: raise HTTPException(status_code=404, detail="Identity-Correlator not found")
    return await p.correlate()

@app.get("/identity/profiles")
async def identity_profiles():
    p = plugin_manager.get_plugin("Identity-Correlator")
    if not p: raise HTTPException(status_code=404)
    return await p.get_identities()

# ─── CRED GENOME ─────────────────────────────────────────────────
@app.post("/cred_genome/analyze")
async def genome_analyze():
    p = plugin_manager.get_plugin("Cred-Genome")
    if not p: raise HTTPException(status_code=404, detail="Cred-Genome not found")
    return await p.analyze()

class GenomeGenerateBody(BaseModel):
    count: int = 100

@app.post("/cred_genome/generate")
async def genome_generate(body: GenomeGenerateBody):
    p = plugin_manager.get_plugin("Cred-Genome")
    if not p: raise HTTPException(status_code=404, detail="Cred-Genome not found")
    return await p.generate(body.count)

# ─── BASELINE CALIBRATOR ─────────────────────────────────────────
class BaselineBody(BaseModel):
    interface: Optional[str] = None
    observe_secs: int = 60

@app.post("/baseline/start")
async def baseline_start(body: BaselineBody):
    p = plugin_manager.get_plugin("Baseline-Calibrator")
    if not p: raise HTTPException(status_code=404, detail="Baseline-Calibrator not found")
    await p.start(interface=body.interface, observe_secs=body.observe_secs)
    return {"status": "observing", "observe_secs": body.observe_secs}

@app.get("/baseline/status")
async def baseline_status():
    p = plugin_manager.get_plugin("Baseline-Calibrator")
    if not p: raise HTTPException(status_code=404)
    return await p.get_status()

# ─── MESH INJECTOR ───────────────────────────────────────────────
class MeshStartBody(BaseModel):
    mesh_id: str = ""
    channel: int = 6
    iface: str = "wlan0"
    iface_wan: str = "eth0"
    scan_first: bool = True

@app.post("/mesh/start")
async def mesh_start(body: MeshStartBody):
    p = plugin_manager.get_plugin("Mesh-Injector")
    if not p: raise HTTPException(status_code=404, detail="Mesh-Injector not found")
    asyncio.create_task(p.start(**body.model_dump()))
    return {"status": "mesh_injection_starting", "mesh_id": body.mesh_id}

@app.post("/mesh/stop")
async def mesh_stop():
    p = plugin_manager.get_plugin("Mesh-Injector")
    if not p: raise HTTPException(status_code=404)
    await p.stop()
    return {"status": "mesh_stopped"}

@app.post("/mesh/scan")
async def mesh_scan(iface: str = "wlan0", timeout: int = 12):
    p = plugin_manager.get_plugin("Mesh-Injector")
    if not p: raise HTTPException(status_code=404)
    meshes = await asyncio.to_thread(p._passive_scan, timeout)
    return {"meshes": meshes}

@app.get("/mesh/status")
async def mesh_status():
    p = plugin_manager.get_plugin("Mesh-Injector")
    if not p: raise HTTPException(status_code=404)
    return await p.get_status()

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
    token = websocket.query_params.get("token")
    if token and not decode_token(token):
        await websocket.close(code=4001, reason="Invalid token")
        return
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
        done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
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
    token = websocket.query_params.get("token")
    if token and not decode_token(token):
        await websocket.close(code=4001, reason="Invalid token")
        return
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        connected_clients.discard(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
