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
            c.execute('''CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                plugin TEXT,
                action TEXT,
                target TEXT,
                result TEXT,
                severity TEXT DEFAULT 'INFO',
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

    def record_timeline(self, campaign_id: str, plugin: str, action: str,
                        target: str = "", result: str = "", severity: str = "INFO"):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO timeline (campaign_id, plugin, action, target, result, severity, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (campaign_id, plugin, action, target, result, severity, time.time()))

    def load_timeline(self, campaign_id: str, limit: int = 200) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT plugin, action, target, result, severity, timestamp FROM timeline WHERE campaign_id=? ORDER BY timestamp DESC LIMIT ?",
                (campaign_id, limit)).fetchall()
        return [{"plugin": r[0], "action": r[1], "target": r[2], "result": r[3], "severity": r[4], "ts": r[5]} for r in rows]

    def get_threat_heatmap(self, campaign_id: str) -> Dict:
        devices = self.load_devices(campaign_id)
        creds = self.load_credentials(campaign_id)
        with self._conn() as conn:
            timeline = conn.execute(
                "SELECT target, severity, COUNT(*) FROM timeline WHERE campaign_id=? GROUP BY target, severity",
                (campaign_id,)).fetchall()
        heatmap = {}
        for d in devices:
            ip = d.get("ip", "unknown")
            heatmap[ip] = {"vendor": d.get("vendor", ""), "risk_score": 0, "events": {}}
        for target, severity, count in timeline:
            if target not in heatmap:
                heatmap[target] = {"vendor": "", "risk_score": 0, "events": {}}
            heatmap[target]["events"][severity] = heatmap[target]["events"].get(severity, 0) + count
            weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            heatmap[target]["risk_score"] += weights.get(severity, 0) * count
        cred_targets = {}
        for c in creds:
            src = c.get("plugin", "unknown")
            cred_targets[src] = cred_targets.get(src, 0) + 1
        return {"hosts": heatmap, "credential_sources": cred_targets}

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
        with self._conn() as conn:
            rows = conn.execute("SELECT plugin, content, timestamp FROM credentials WHERE campaign_id=?", (campaign_id,)).fetchall()
        return [{"plugin": r[0], "content": r[1], "ts": r[2]} for r in rows]

    def get_metrics(self, campaign_id: str) -> Dict:
        devices = self.load_devices(campaign_id)
        networks = self.load_networks(campaign_id)
        creds = self.load_credentials(campaign_id)
        with self._conn() as conn:
            findings_count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE campaign_id=?", (campaign_id,)
            ).fetchone()[0]

        vendor_dist = {}
        for d in devices:
            v = d.get("vendor") or "Unknown"
            vendor_dist[v] = vendor_dist.get(v, 0) + 1

        enc_dist = {}
        for n in networks:
            e = n.get("encryption") or "Unknown"
            enc_dist[e] = enc_dist.get(e, 0) + 1

        plugin_dist = {}
        for c in creds:
            p = c.get("plugin") or "Unknown"
            plugin_dist[p] = plugin_dist.get(p, 0) + 1

        return {
            "campaign_id": campaign_id,
            "hosts": len(devices),
            "networks": len(networks),
            "credentials": len(creds),
            "findings": findings_count,
            "vendor_distribution": vendor_dist,
            "encryption_distribution": enc_dist,
            "credential_sources": plugin_dist,
        }

    def generate_executive_summary(self, campaign_id: str) -> str:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return "Campaign not found."
        metrics = self.get_metrics(campaign_id)
        devices = self.load_devices(campaign_id)
        creds = self.load_credentials(campaign_id)

        risk = "LOW"
        if metrics["credentials"] > 0:
            risk = "CRITICAL"
        elif metrics["findings"] > 5:
            risk = "HIGH"
        elif metrics["hosts"] > 10:
            risk = "MEDIUM"

        summary = f"# Executive Summary: {campaign['name']}\n\n"
        summary += f"**Scope:** {campaign['scope']}  \n"
        summary += f"**Overall Risk Assessment:** {risk}\n\n"
        summary += "## Key Findings\n\n"
        summary += f"- **{metrics['hosts']}** hosts discovered on the target network\n"
        summary += f"- **{metrics['networks']}** wireless networks detected\n"
        summary += f"- **{metrics['credentials']}** credentials captured\n"
        summary += f"- **{metrics['findings']}** additional findings recorded\n\n"

        if metrics["credentials"] > 0:
            summary += "### Critical: Credential Exposure\n\n"
            summary += f"{metrics['credentials']} credential(s) were intercepted during the engagement. "
            summary += "This indicates weak authentication controls or unencrypted protocols in use.\n\n"
            summary += "**Sources:** " + ", ".join(
                f"{src} ({cnt})" for src, cnt in metrics["credential_sources"].items()
            ) + "\n\n"

        if metrics["hosts"] > 0:
            summary += "### Network Surface\n\n"
            summary += "| Vendor | Count |\n|--------|-------|\n"
            for vendor, count in sorted(metrics["vendor_distribution"].items(), key=lambda x: -x[1]):
                summary += f"| {vendor} | {count} |\n"
            summary += "\n"

        if metrics["networks"] > 0:
            summary += "### Wireless Posture\n\n"
            for enc, count in metrics["encryption_distribution"].items():
                if enc in ("WEP", "Open", "NONE", ""):
                    summary += f"- **WARNING:** {count} network(s) using weak encryption ({enc})\n"
                else:
                    summary += f"- {count} network(s) using {enc}\n"
            summary += "\n"

        summary += "## Recommendations\n\n"
        if metrics["credentials"] > 0:
            summary += "1. **Enforce encrypted protocols** — Disable HTTP, Telnet, FTP in favor of HTTPS, SSH, SFTP\n"
            summary += "2. **Implement network segmentation** — Isolate sensitive systems from general access\n"
        if any(e in ("WEP", "Open", "NONE") for e in metrics.get("encryption_distribution", {})):
            summary += "3. **Upgrade wireless encryption** — Migrate all networks to WPA3 or WPA2-Enterprise\n"
        summary += f"4. **Conduct follow-up assessment** — Re-test after remediating the {metrics['findings'] + metrics['credentials']} identified issues\n"

        return summary

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
