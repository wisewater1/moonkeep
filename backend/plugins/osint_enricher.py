from core.plugin_manager import BasePlugin
import asyncio
import json
import re
import socket
import subprocess
import urllib.request
import urllib.error


class OSINTEnricherPlugin(BasePlugin):
    def __init__(self):
        self.cache: dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "OSINT-Enricher"

    @property
    def description(self) -> str:
        return "IP Enrichment: rDNS, whois, GeoIP, ASN, Shodan"

    async def start(self):
        print("OSINT-Enricher: initialized.")

    async def stop(self):
        pass

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def enrich(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]

        rdns, whois_data, geo, shodan = await asyncio.gather(
            asyncio.to_thread(self._reverse_dns, ip),
            asyncio.to_thread(self._whois, ip),
            asyncio.to_thread(self._geoip, ip),
            asyncio.to_thread(self._shodan_free, ip),
        )

        result = {
            "ip":       ip,
            "rdns":     rdns,
            "whois":    whois_data,
            "geo":      geo,
            "shodan":   shodan,
        }
        self.cache[ip] = result
        self.emit("OSINT_ENRICHED", {"ip": ip, "data": result})

        # Push enrichment into the knowledge graph
        if self.target_store:
            summary_parts = []
            if rdns:
                summary_parts.append(f"rdns={rdns}")
            if geo.get("country"):
                summary_parts.append(f"country={geo['country']}")
            if geo.get("org"):
                summary_parts.append(f"org={geo['org']}")
            if shodan.get("ports"):
                summary_parts.append(f"shodan_ports={','.join(str(p) for p in shodan['ports'][:10])}")
            if summary_parts:
                self.target_store.cm.save_finding(
                    self.target_store.active_campaign,
                    "OSINT",
                    ip,
                    " | ".join(summary_parts),
                )
        return result

    async def enrich_batch(self, devices: list[dict]) -> list[dict]:
        tasks = [self.enrich(d["ip"]) for d in devices if d.get("ip")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        enrichments = [r for r in results if isinstance(r, dict)]
        self.emit("OSINT_BATCH_COMPLETE", {"count": len(enrichments)})
        return enrichments

    # ------------------------------------------------------------------
    # Reverse DNS
    # ------------------------------------------------------------------

    @staticmethod
    def _reverse_dns(ip: str) -> str | None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Whois (subprocess)
    # ------------------------------------------------------------------

    @staticmethod
    def _whois(ip: str) -> dict:
        data: dict = {}
        try:
            result = subprocess.run(
                ["whois", ip],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                for key in ("OrgName", "org-name", "netname", "descr",
                            "country", "Country", "CIDR", "inetnum",
                            "abuse-mailbox", "OrgAbuseEmail"):
                    if line.lower().startswith(key.lower() + ":"):
                        val = line.split(":", 1)[1].strip()
                        if val:
                            data[key.lower().replace("-", "_")] = val
        except Exception:
            pass
        return data

    # ------------------------------------------------------------------
    # GeoIP via ip-api.com (free, no key)
    # ------------------------------------------------------------------

    @staticmethod
    def _geoip(ip: str) -> dict:
        # Skip RFC1918
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                f, s = int(parts[0]), int(parts[1])
                if f == 10 or f == 127 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168):
                    return {"private": True}
            except ValueError:
                pass
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,org,as,isp,timezone"
            req = urllib.request.Request(url, headers={"User-Agent": "Moonkeep/1.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            return json.loads(resp.read().decode())
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Shodan InternetDB (free, no key — exposes open ports/CVEs/tags)
    # ------------------------------------------------------------------

    @staticmethod
    def _shodan_free(ip: str) -> dict:
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                f, s = int(parts[0]), int(parts[1])
                if f == 10 or f == 127 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168):
                    return {}
            except ValueError:
                pass
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Moonkeep/1.0"})
            resp = urllib.request.urlopen(req, timeout=6)
            data = json.loads(resp.read().decode())
            return {
                "ports":     data.get("ports", []),
                "cpes":      data.get("cpes", []),
                "tags":      data.get("tags", []),
                "vulns":     data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
            }
        except Exception:
            return {}
