from core.plugin_manager import BasePlugin
import asyncio
import os
import time


_CSS = """
body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 1100px; margin: 0 auto; padding: 24px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 12px; }
h2 { color: #58a6ff; margin-top: 32px; }
h3 { color: #79c0ff; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
th { background: #161b22; color: #8b949e; border: 1px solid #30363d; padding: 8px 10px; text-align: left; }
td { border: 1px solid #21262d; padding: 6px 10px; }
tr:nth-child(even) td { background: #161b22; }
.CRITICAL { color: #ff7b72; font-weight: bold; }
.HIGH     { color: #ffa657; font-weight: bold; }
.MEDIUM   { color: #e3b341; }
.LOW      { color: #56d364; }
.INFO     { color: #8b949e; }
code { background: #161b22; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
.stat-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.stat-num { font-size: 32px; font-weight: bold; color: #58a6ff; }
.stat-label { color: #8b949e; font-size: 12px; margin-top: 4px; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; background: #21262d; }
"""


def _severity_class(sev: str) -> str:
    return sev.upper() if sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class ReportBuilderPlugin(BasePlugin):
    def __init__(self):
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    @property
    def name(self) -> str:
        return "Report-Builder"

    @property
    def description(self) -> str:
        return "Pentest HTML/PDF Report Generator"

    async def start(self):
        print("Report-Builder: initialized.")

    async def stop(self):
        pass

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def generate(self, campaign_id: str | None = None) -> dict:
        if not self.target_store:
            return {"error": "no target_store"}
        cid = campaign_id or self.target_store.active_campaign
        cm  = self.target_store.cm
        campaign = cm.get_campaign(cid)
        if not campaign:
            return {"error": f"campaign {cid} not found"}

        html = await asyncio.to_thread(self._build_html, campaign, cm)
        ts = int(time.time())
        html_path = os.path.join(self.reports_dir, f"report_{cid}_{ts}.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        pdf_path = await asyncio.to_thread(self._render_pdf, html_path)
        result = {
            "campaign_id": cid,
            "html_path":   html_path,
            "pdf_path":    pdf_path,
        }
        self.emit("REPORT_GENERATED", result)
        return result

    # ------------------------------------------------------------------
    # HTML construction
    # ------------------------------------------------------------------

    def _build_html(self, campaign: dict, cm) -> str:
        cid      = campaign["id"]
        devices  = cm.load_devices(cid)
        networks = cm.load_networks(cid)
        creds    = cm.load_credentials(cid)
        findings = cm.load_findings(cid)

        # Aggregate stats
        vuln_findings = [f for f in findings if f["type"] in ("VULNERABILITY", "WEB:SQL_INJECTION",
                         "WEB:XSS_REFLECTED", "WEB:LFI", "WEB:SSRF", "WEB:SENSITIVE_FILE_EXPOSED")]
        crit_count = sum(1 for f in findings if "CRITICAL" in f.get("data", ""))
        high_count = sum(1 for f in findings if "HIGH" in f.get("data", "") and "CRITICAL" not in f.get("data", ""))
        exploit_paths = [f for f in findings if f["type"] == "EXPLOIT_PATH"]
        osint_data    = [f for f in findings if f["type"] == "OSINT"]

        now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        h = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>Moonkeep Report — {_html_escape(campaign['name'])}</title>
<style>{_CSS}</style>
</head><body>
<h1>Moonkeep Engagement Report</h1>
<p><strong>Campaign:</strong> {_html_escape(campaign['name'])} &nbsp;|&nbsp;
   <strong>Scope:</strong> {_html_escape(campaign.get('scope', ''))} &nbsp;|&nbsp;
   <strong>Generated:</strong> {now}</p>

<div class="stat-grid">
  <div class="stat-box"><div class="stat-num">{len(devices)}</div><div class="stat-label">Hosts</div></div>
  <div class="stat-box"><div class="stat-num">{len(vuln_findings)}</div><div class="stat-label">Vulnerabilities</div></div>
  <div class="stat-box"><div class="stat-num">{len(creds)}</div><div class="stat-label">Credentials</div></div>
  <div class="stat-box"><div class="stat-num"><span class="CRITICAL">{crit_count}</span> / <span class="HIGH">{high_count}</span></div><div class="stat-label">Crit / High</div></div>
</div>
"""
        # Devices
        h += f"<h2>Discovered Hosts ({len(devices)})</h2>"
        if devices:
            h += "<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th></tr>"
            for d in devices:
                h += (f"<tr><td><code>{_html_escape(d.get('ip',''))}</code></td>"
                      f"<td>{_html_escape(d.get('mac',''))}</td>"
                      f"<td>{_html_escape(d.get('vendor',''))}</td>"
                      f"<td>{_html_escape(d.get('hostname',''))}</td></tr>")
            h += "</table>"

        # Vulnerabilities
        h += f"<h2>Vulnerability Findings ({len(vuln_findings)})</h2>"
        if vuln_findings:
            h += "<table><tr><th>Severity</th><th>Target</th><th>Detail</th></tr>"
            for f in vuln_findings:
                data = _html_escape(f["data"][:120])
                sev  = "CRITICAL" if "CRITICAL" in f["data"] else \
                       "HIGH"     if "HIGH"     in f["data"] else \
                       "MEDIUM"   if "MEDIUM"   in f["data"] else "LOW"
                h += (f"<tr><td><span class='{sev}'>{sev}</span></td>"
                      f"<td><code>{_html_escape(f['target'])}</code></td>"
                      f"<td>{data}</td></tr>")
            h += "</table>"

        # Exploit paths
        if exploit_paths:
            h += f"<h2>Exploit Paths ({len(exploit_paths)})</h2>"
            h += "<table><tr><th>Target</th><th>Module / Path</th></tr>"
            for f in exploit_paths:
                h += (f"<tr><td><code>{_html_escape(f['target'])}</code></td>"
                      f"<td>{_html_escape(f['data'][:160])}</td></tr>")
            h += "</table>"

        # WiFi networks
        if networks:
            h += f"<h2>Wireless Networks ({len(networks)})</h2>"
            h += "<table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Encryption</th><th>Signal</th></tr>"
            for n in networks:
                h += (f"<tr><td>{_html_escape(n.get('ssid',''))}</td>"
                      f"<td><code>{_html_escape(n.get('bssid',''))}</code></td>"
                      f"<td>{n.get('channel','')}</td>"
                      f"<td>{_html_escape(n.get('encryption',''))}</td>"
                      f"<td>{n.get('signal','')}</td></tr>")
            h += "</table>"

        # OSINT
        if osint_data:
            h += f"<h2>OSINT Enrichment ({len(osint_data)} IPs)</h2>"
            h += "<table><tr><th>IP</th><th>Intel</th></tr>"
            for f in osint_data:
                h += (f"<tr><td><code>{_html_escape(f['target'])}</code></td>"
                      f"<td>{_html_escape(f['data'][:200])}</td></tr>")
            h += "</table>"

        # Credentials
        if creds:
            from collections import Counter
            freq = Counter((c["plugin"], c["content"]) for c in creds)
            top = freq.most_common(20)
            h += f"<h2>Captured Credentials ({len(creds)} total, top 20)</h2>"
            h += "<table><tr><th>Source</th><th>Credential</th><th>Count</th></tr>"
            for (plugin, content), count in top:
                display = _html_escape(content[:80] + ("..." if len(content) > 80 else ""))
                h += f"<tr><td>{_html_escape(plugin)}</td><td><code>{display}</code></td><td>{count}</td></tr>"
            h += "</table>"

        # All findings table
        other = [f for f in findings if f not in vuln_findings and f not in exploit_paths and f not in osint_data]
        if other:
            h += f"<h2>Other Findings ({len(other)})</h2>"
            h += "<table><tr><th>Type</th><th>Target</th><th>Detail</th></tr>"
            for f in other[:100]:
                h += (f"<tr><td>{_html_escape(f['type'])}</td>"
                      f"<td><code>{_html_escape(f['target'])}</code></td>"
                      f"<td>{_html_escape(f['data'][:120])}</td></tr>")
            h += "</table>"

        h += "<hr><p style='color:#8b949e;font-size:12px'>Generated by Moonkeep — Confidential Engagement Report</p></body></html>"
        return h

    # ------------------------------------------------------------------
    # PDF rendering (weasyprint optional)
    # ------------------------------------------------------------------

    @staticmethod
    def _render_pdf(html_path: str) -> str | None:
        pdf_path = html_path.replace(".html", ".pdf")
        try:
            from weasyprint import HTML as WP
            WP(filename=html_path).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            pass
        except Exception:
            pass
        # Fallback: wkhtmltopdf
        try:
            import subprocess, shutil
            if shutil.which("wkhtmltopdf"):
                subprocess.run(["wkhtmltopdf", html_path, pdf_path],
                               capture_output=True, timeout=60)
                if os.path.exists(pdf_path):
                    return pdf_path
        except Exception:
            pass
        return None
