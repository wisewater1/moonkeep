from core.plugin_manager import BasePlugin
import re
import time


class IdentityCorrelatorPlugin(BasePlugin):
    """
    Cross-protocol identity deanonymization engine.

    Fuses identity signals from every active plugin into unified human profiles:
      - Rogue-RADIUS  → Active Directory DOMAIN\\username
      - Portal harvest → email / cleartext password
      - Sniffer       → HTTP Basic/Form credentials
      - Device store  → hostname patterns (jsmith-laptop → jsmith)
      - WiFi probes   → previous SSID history (home networks, hotels)

    Returns ranked identity profiles with a confidence score and
    all corroborating evidence per source.
    """

    def __init__(self):
        self.running = False
        self.identities: dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "Identity-Correlator"

    @property
    def description(self) -> str:
        return "Cross-protocol identity correlation: RADIUS + portal + sniffer + hostnames"

    async def start(self):
        self.running = True

    async def stop(self):
        self.running = False

    async def correlate(self) -> dict:
        if not self.target_store:
            return {"identities": [], "error": "No target store available"}

        self.log_event("Running cross-protocol identity correlation", "START")
        profiles: dict[str, dict] = {}

        # ── Source 1: Rogue-RADIUS (Active Directory usernames) ───────────────
        for cred in self.target_store.credentials:
            plugin = cred.get("plugin", "")
            if not plugin.startswith("Rogue-RADIUS"):
                continue
            content = cred.get("content", "")
            identity = content.split("::::")[0] if "::::" in content else content.split(":")[0]
            domain, username = None, identity
            if "\\" in identity:
                domain, username = identity.split("\\", 1)
            elif "@" in identity:
                username, domain = identity.rsplit("@", 1)
            key = username.lower()
            p = profiles.setdefault(key, _empty(key))
            p["ad_username"] = identity
            p["domain"] = domain
            p["ntlm_hash"] = content
            p["sources"].add("RADIUS")

        # ── Source 2: Captive portal credentials ──────────────────────────────
        for cred in self.target_store.credentials:
            if not cred.get("plugin", "").startswith("RogueAP:Portal"):
                continue
            content = cred.get("content", "")
            if ":" not in content:
                continue
            user_part, pw = content.split(":", 1)
            username = user_part.split("@")[0].lower() if "@" in user_part else user_part.lower()
            key = username or "unknown"
            p = profiles.setdefault(key, _empty(key))
            if "@" in user_part:
                p["email"] = user_part
            p["portal_credential"] = content
            p["sources"].add("Portal")

        # ── Source 3: Sniffer plaintext credentials ───────────────────────────
        for cred in self.target_store.credentials:
            if not cred.get("plugin", "").startswith("Sniffer"):
                continue
            content = cred.get("content", "")
            if ":" not in content:
                continue
            user_part = content.split(":")[0].lower()
            username = user_part.split("@")[0] if "@" in user_part else user_part
            key = username or "unknown"
            p = profiles.setdefault(key, _empty(key))
            p["sniffer_creds"].append(content)
            p["sources"].add("Sniffer")

        # ── Source 4: Device hostnames ────────────────────────────────────────
        for device in self.target_store.devices:
            hostname = device.get("hostname", "") or ""
            mac = device.get("mac", "")
            ip = device.get("ip", "")
            vendor = device.get("vendor", "")
            ssid_history = device.get("ssid_history", [])

            possible_user = _user_from_hostname(hostname)
            if possible_user:
                key = possible_user
                p = profiles.setdefault(key, _empty(key))
                p["device_mac"] = mac
                p["device_ip"] = ip
                p["device_vendor"] = vendor
                p["hostname"] = hostname
                p["ssid_history"] = ssid_history
                p["sources"].add("Hostname")

        # ── Finalise scores ───────────────────────────────────────────────────
        for p in profiles.values():
            p["sources"] = sorted(p["sources"])
            p["confidence"] = _confidence(p)

        self.identities = profiles
        ranked = sorted(profiles.values(), key=lambda x: x["confidence"], reverse=True)

        self.log_event(f"Correlation complete: {len(ranked)} identities resolved", "DONE")
        self.emit("IDENTITIES_CORRELATED", {"count": len(ranked)})
        return {"identities": ranked}

    async def get_identities(self) -> dict:
        return {"identities": sorted(self.identities.values(), key=lambda x: x["confidence"], reverse=True)}


# ── helpers ──────────────────────────────────────────────────────────────────

def _empty(username: str) -> dict:
    return {
        "username": username,
        "ad_username": None,
        "domain": None,
        "email": None,
        "portal_credential": None,
        "ntlm_hash": None,
        "device_mac": None,
        "device_ip": None,
        "device_vendor": None,
        "hostname": None,
        "ssid_history": [],
        "sniffer_creds": [],
        "sources": set(),
        "confidence": 0.0,
    }


def _user_from_hostname(hostname: str) -> str | None:
    h = hostname.lower()
    for pattern in [
        r"^([a-z][a-z0-9]{1,15})\.(laptop|desktop|pc|mac|mbp|work|home)$",
        r"^([a-z][a-z0-9]{1,15})[-_](laptop|desktop|pc|mac|mbp|wks|work)\d*$",
        r"^(?:corp|work|win|mac|lab)[-_]([a-z][a-z0-9]{1,15})(?:[-_]\d+)?$",
        r"^([a-z]{2,4}\.[a-z]{2,15})[-_]",   # firstname.lastname-
    ]:
        m = re.search(pattern, h)
        if m:
            return m.group(1)
    return None


def _confidence(p: dict) -> float:
    s = set(p.get("sources", []))
    score = 0.0
    if "RADIUS"   in s: score += 0.40
    if "Portal"   in s: score += 0.30
    if "Hostname" in s: score += 0.20
    if "Sniffer"  in s: score += 0.15
    if p.get("ad_username") and p.get("email"):
        score += 0.10
    return min(1.0, round(score, 2))
