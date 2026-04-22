import sqlite3
import os
import time
import json
from collections import Counter
from typing import List, Dict, Any, Optional

class CampaignManager:
    def __init__(self, db_path="moonkeep_campaigns.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
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
        conn.commit()
        conn.close()

    def create_campaign(self, campaign_id: str, name: str, desc: str, scope: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO campaigns VALUES (?, ?, ?, ?, ?)", 
                  (campaign_id, name, desc, scope, time.time()))
        conn.commit()
        conn.close()
        return self.get_campaign(campaign_id)

    def get_campaign(self, campaign_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return {"id": row[0], "name": row[1], "description": row[2], "scope": row[3], "created_at": row[4]}
        return None

    def list_campaigns(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM campaigns ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "description": r[2], "scope": r[3], "created_at": r[4]} for r in rows]
        
    def save_device(self, campaign_id: str, device: Dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                  (campaign_id, device.get("ip"), device.get("mac"), device.get("vendor"), device.get("hostname"), time.time()))
        conn.commit()
        conn.close()

    def load_devices(self, campaign_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT ip, mac, vendor, hostname FROM devices WHERE campaign_id=?", (campaign_id,))
        rows = c.fetchall()
        conn.close()
        return [{"ip": r[0], "mac": r[1], "vendor": r[2], "hostname": r[3]} for r in rows]

    def save_network(self, campaign_id: str, net: Dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO networks VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (campaign_id, net.get("bssid"), net.get("ssid"), net.get("channel"), net.get("encryption"), net.get("signal"), time.time()))
        conn.commit()
        conn.close()

    def load_networks(self, campaign_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT bssid, ssid, channel, encryption, signal FROM networks WHERE campaign_id=?", (campaign_id,))
        rows = c.fetchall()
        conn.close()
        return [{"bssid": r[0], "ssid": r[1], "channel": r[2], "encryption": r[3], "signal": r[4]} for r in rows]

    def save_credential(self, campaign_id: str, plugin: str, content: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO credentials (campaign_id, plugin, content, timestamp) VALUES (?, ?, ?, ?)",
                  (campaign_id, plugin, content, time.time()))
        conn.commit()
        conn.close()

    def save_finding(self, campaign_id: str, type: str, target: str, data: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO findings (campaign_id, type, target, data, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (campaign_id, type, target, data, time.time()))
        conn.commit()
        conn.close()

    def load_findings(self, campaign_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT type, target, data, timestamp FROM findings WHERE campaign_id=? ORDER BY timestamp DESC", (campaign_id,))
        rows = c.fetchall()
        conn.close()
        return [{"type": r[0], "target": r[1], "data": r[2], "ts": r[3]} for r in rows]

    def load_credentials(self, campaign_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT plugin, content, timestamp FROM credentials WHERE campaign_id=?", (campaign_id,))
        rows = c.fetchall()
        conn.close()
        return [{"plugin": r[0], "content": r[1], "ts": r[2]} for r in rows]

    def export_report(self, campaign_id: str) -> str:
        campaign = self.get_campaign(campaign_id)
        if not campaign: return "Campaign not found."
        
        md = f"# Moonkeep Engagement Report\n## {campaign['name']}\n"
        md += f"**Scope:** {campaign['scope']}\n**Description:** {campaign['description']}\n\n"
        
        devices = self.load_devices(campaign_id)
        md += f"### Discovered Devices ({len(devices)})\n\n"
        if devices:
            md += "| IP Address | MAC Address | Vendor | Hostname |\n"
            md += "|------------|-------------|--------|----------|\n"
            for d in devices:
                ip       = d.get('ip')       or ''
                mac      = d.get('mac')      or ''
                vendor   = d.get('vendor')   or ''
                hostname = d.get('hostname') or ''
                md += f"| `{ip}` | {mac} | {vendor} | {hostname} |\n"
            md += "\n"
        else:
            md += "_No devices discovered._\n\n"

        networks = self.load_networks(campaign_id)
        md += f"### Discovered Wireless Networks ({len(networks)})\n"
        for n in networks:
            md += f"- `{n['ssid']}` ({n['bssid']}) - Ch {n['channel']} [{n['encryption']}]\n"

        creds = self.load_credentials(campaign_id)
        md += f"\n### Captured Credentials ({len(creds)} total)\n\n"
        if creds:
            freq = Counter((c['plugin'], c['content']) for c in creds)
            top_creds = freq.most_common(10)
            md += "| Plugin | Credential | Occurrences |\n"
            md += "|--------|-----------|-------------|\n"
            for (plugin, content), count in top_creds:
                display = content if len(content) <= 60 else content[:57] + "..."
                md += f"| {plugin} | `{display}` | {count} |\n"
            md += "\n"
        else:
            md += "_No credentials captured._\n\n"

        findings = self.load_findings(campaign_id)
        md += f"### Findings ({len(findings)} total)\n\n"
        if findings:
            md += "| Type | Target | Detail |\n"
            md += "|------|--------|--------|\n"
            for f in findings[:50]:
                detail = f['data'] if len(f['data']) <= 80 else f['data'][:77] + "..."
                md += f"| {f['type']} | `{f['target']}` | {detail} |\n"
            if len(findings) > 50:
                md += f"\n_...and {len(findings) - 50} more findings._\n"
            md += "\n"
        else:
            md += "_No findings recorded._\n\n"

        return md
