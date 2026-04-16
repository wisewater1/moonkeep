import sqlite3
import os
import time
import json
import html
from typing import List, Dict, Any, Optional


class CampaignManager:
    def __init__(self, db_path="moonkeep_campaigns.db"):
        self.db_path = db_path
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                target_scope TEXT,
                created_at REAL
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS devices (
                campaign_id TEXT,
                ip TEXT,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                last_seen REAL,
                PRIMARY KEY(campaign_id, mac)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS networks (
                campaign_id TEXT,
                bssid TEXT,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                signal INTEGER,
                last_seen REAL,
                PRIMARY KEY(campaign_id, bssid)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                type TEXT,
                target TEXT,
                data TEXT,
                timestamp REAL
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                plugin TEXT,
                content TEXT,
                timestamp REAL
            )''')

    def _sanitize(self, text: str) -> str:
        if not text:
            return ""
        return html.escape(str(text))

    def create_campaign(self, campaign_id: str, name: str, desc: str, scope: str):
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO campaigns VALUES (?, ?, ?, ?, ?)",
                         (campaign_id, self._sanitize(name), self._sanitize(desc), self._sanitize(scope), time.time()))
        return self.get_campaign(campaign_id)

    def get_campaign(self, campaign_id: str):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if row:
            return {"id": row[0], "name": row[1], "description": row[2], "scope": row[3], "created_at": row[4]}
        return None

    def list_campaigns(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
        return [{"id": r[0], "name": r[1], "description": r[2], "scope": r[3], "created_at": r[4]} for r in rows]

    def save_device(self, campaign_id: str, device: Dict):
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                         (campaign_id, device.get("ip"), device.get("mac"), device.get("vendor"), device.get("hostname"), time.time()))

    def load_devices(self, campaign_id: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT ip, mac, vendor, hostname FROM devices WHERE campaign_id=?", (campaign_id,)).fetchall()
        return [{"ip": r[0], "mac": r[1], "vendor": r[2], "hostname": r[3]} for r in rows]

    def save_network(self, campaign_id: str, net: Dict):
        bssid = net.get("bssid") or net.get("mac")
        signal = net.get("signal") or net.get("rssi")
        encryption = net.get("encryption") or net.get("auth")
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO networks VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (campaign_id, bssid, net.get("ssid"), net.get("channel"), encryption, signal, time.time()))

    def load_networks(self, campaign_id: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT bssid, ssid, channel, encryption, signal FROM networks WHERE campaign_id=?", (campaign_id,)).fetchall()
        return [{"bssid": r[0], "ssid": r[1], "channel": r[2], "encryption": r[3], "signal": r[4]} for r in rows]

    def save_credential(self, campaign_id: str, plugin: str, content: str):
        with self._conn() as conn:
            conn.execute("INSERT INTO credentials (campaign_id, plugin, content, timestamp) VALUES (?, ?, ?, ?)",
                         (campaign_id, plugin, content, time.time()))

    def load_credentials(self, campaign_id: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT plugin, content, timestamp FROM credentials WHERE campaign_id=?", (campaign_id,)).fetchall()
        return [{"plugin": r[0], "content": r[1], "ts": r[2]} for r in rows]

    def export_report(self, campaign_id: str, fmt: str = "markdown") -> Any:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return "Campaign not found."

        devices = self.load_devices(campaign_id)
        networks = self.load_networks(campaign_id)
        creds = self.load_credentials(campaign_id)

        if fmt == "json":
            return json.dumps({
                "campaign": campaign,
                "devices": devices,
                "networks": networks,
                "credentials": creds,
            }, indent=2)

        if fmt == "csv":
            import csv
            import io
            output = io.StringIO()
            w = csv.writer(output)
            w.writerow(["Section", "Field1", "Field2", "Field3", "Field4"])
            for d in devices:
                w.writerow(["Device", d["ip"], d["mac"], d["vendor"], d["hostname"]])
            for n in networks:
                w.writerow(["Network", n["ssid"], n["bssid"], n.get("channel", ""), n.get("encryption", "")])
            for c in creds:
                w.writerow(["Credential", c["plugin"], c["content"], "", ""])
            return output.getvalue()

        md = f"# Moonkeep Engagement Report\n## {campaign['name']}\n"
        md += f"**Scope:** {campaign['scope']}\n**Description:** {campaign['description']}\n\n"

        md += f"### Discovered Devices ({len(devices)})\n"
        for d in devices:
            md += f"- `{d['ip']}` | {d['mac']} | {d['vendor']}\n"

        md += f"\n### Discovered Wireless Networks ({len(networks)})\n"
        for n in networks:
            md += f"- `{n['ssid']}` ({n['bssid']}) - Ch {n['channel']} [{n['encryption']}]\n"

        md += f"\n### Captured Loot ({len(creds)})\n"
        for c in creds:
            md += f"- **{c['plugin']}**: `{c['content']}`\n"

        return md
