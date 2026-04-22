from core.plugin_manager import BasePlugin
import collections
import re
import time


class CredGenomePlugin(BasePlugin):
    """
    Statistical password policy inference and targeted credential generation.

    Analyzes all captured plaintext passwords (portal, sniffer, cred-spray)
    to infer the target organisation's password grammar:
      - Length distribution
      - Character-set requirements (upper/lower/digit/special)
      - Structural patterns  (Word+Year, Name+Number+Special, etc.)
      - Common vocabulary    (company-specific words, common suffixes)

    Then generates a ranked list of candidate credentials that obey the
    inferred grammar, using Active Directory usernames captured from
    Rogue-RADIUS as the username source.  These can be piped directly
    into Cred-Spray for a targeted second-pass attack.
    """

    def __init__(self):
        self.running = False
        self.policy: dict = {}
        self.generated: list[dict] = []

    @property
    def name(self) -> str:
        return "Cred-Genome"

    @property
    def description(self) -> str:
        return "Password policy inference + statistically targeted credential generation"

    async def start(self):
        self.running = True

    async def stop(self):
        self.running = False

    async def analyze(self) -> dict:
        """Analyze captured passwords to infer organisational policy grammar."""
        if not self.target_store:
            return {"error": "No target store"}

        passwords = _collect_passwords(self.target_store.credentials)
        if not passwords:
            return {"error": "No plaintext passwords captured yet", "policy": {}}

        self.policy = _analyze(passwords)
        self.log_event(f"Genome analyzed from {len(passwords)} samples", "DONE")
        self.emit("GENOME_ANALYZED", {"sample_count": len(passwords), "policy": self.policy.get("summary", {})})
        return {"policy": self.policy, "sample_count": len(passwords)}

    async def generate(self, count: int = 100) -> dict:
        """Generate candidate credentials using inferred grammar + AD usernames."""
        if not self.policy:
            await self.analyze()
        if not self.policy or self.policy.get("error"):
            return {"credentials": [], "error": "Insufficient data for generation"}

        usernames = _collect_ad_usernames(self.target_store.credentials if self.target_store else [])
        candidates = _generate(self.policy, usernames, count)
        self.generated = candidates

        self.log_event(f"Generated {len(candidates)} targeted credential pairs", "DONE")
        self.emit("GENOME_GENERATED", {"count": len(candidates)})
        return {"credentials": candidates, "policy_summary": self.policy.get("summary", {})}


# ── analysis ─────────────────────────────────────────────────────────────────

def _collect_passwords(creds: list[dict]) -> list[str]:
    passwords = []
    for c in creds:
        content = c.get("content", "")
        # Skip NTLM hash lines (contain ::::)
        if "::::" in content:
            continue
        if ":" in content:
            pw = content.split(":", 1)[1].strip()
            if 4 <= len(pw) <= 64:
                passwords.append(pw)
    return passwords


def _collect_ad_usernames(creds: list[dict]) -> list[str]:
    seen, result = set(), []
    for c in creds:
        if not c.get("plugin", "").startswith("Rogue-RADIUS"):
            continue
        identity = c.get("content", "").split("::::")[0]
        username = identity.split("\\")[-1].split("@")[0]
        if username and username not in seen:
            seen.add(username)
            result.append(username)
    return result or ["admin", "user", "svc"]


def _analyze(passwords: list[str]) -> dict:
    lengths = [len(p) for p in passwords]
    has_upper   = [bool(re.search(r"[A-Z]",      p)) for p in passwords]
    has_lower   = [bool(re.search(r"[a-z]",      p)) for p in passwords]
    has_digit   = [bool(re.search(r"\d",          p)) for p in passwords]
    has_special = [bool(re.search(r"[^a-zA-Z0-9]", p)) for p in passwords]

    years = [m.group() for p in passwords for m in [re.search(r"(19|20)\d{2}", p)] if m]

    words = []
    for p in passwords:
        words.extend(w.lower() for w in re.findall(r"[a-zA-Z]{3,}", p))
    word_freq = [w for w, _ in collections.Counter(words).most_common(10)]

    # Structural signature: replace chars with type tokens
    patterns = []
    for p in passwords:
        sig = re.sub(r"[A-Z]+", "U", re.sub(r"[a-z]+", "l", re.sub(r"\d+", "N", re.sub(r"[^a-zA-Z0-9]+", "S", p))))
        patterns.append(sig)
    top_patterns = [p for p, _ in collections.Counter(patterns).most_common(5)]

    endings = [p[-3:] for p in passwords if len(p) >= 3]
    common_endings = [e for e, _ in collections.Counter(endings).most_common(5)]

    n = len(passwords)
    summary = {
        "sample_count": n,
        "min_length": min(lengths),
        "max_length": max(lengths),
        "avg_length": round(sum(lengths) / n, 1),
        "req_upper":   sum(has_upper)   / n > 0.55,
        "req_lower":   sum(has_lower)   / n > 0.55,
        "req_digit":   sum(has_digit)   / n > 0.50,
        "req_special": sum(has_special) / n > 0.40,
        "common_years":    list(dict.fromkeys(years))[:5],
        "common_words":    word_freq,
        "top_patterns":    top_patterns,
        "common_endings":  common_endings,
    }
    return {"summary": summary}


# ── generation ────────────────────────────────────────────────────────────────

def _generate(policy: dict, usernames: list[str], count: int) -> list[dict]:
    s = policy.get("summary", {})
    words    = s.get("common_words", ["corp", "admin", "secure"])
    years    = s.get("common_years", ["2024", "2023", "2025"])
    endings  = s.get("common_endings", ["!", "@", "1", "123", "!1"])
    req_up   = s.get("req_upper", True)
    req_sp   = s.get("req_special", True)
    specials = endings if req_sp else [""]

    def cap(w): return w.capitalize() if req_up else w

    candidates: list[tuple[str, float]] = []

    # Pattern 1: Word + Year + Special
    for w in words:
        for y in years:
            for sp in specials:
                candidates.append((cap(w) + y + sp, 0.7))

    # Pattern 2: Username + Year + Special
    for u in usernames:
        for y in years:
            for sp in specials:
                candidates.append((cap(u) + y + sp, 0.65))
        # Pattern 2b: Username + common ending only
        for sp in specials:
            candidates.append((cap(u) + sp, 0.45))

    # Pattern 3: Word + Number
    for w in words:
        for n in ["1", "01", "12", "123"]:
            for sp in (specials[:2] if req_sp else [""]):
                candidates.append((cap(w) + n + sp, 0.50))

    # Pattern 4: Year-only based (Summer2024!)
    seasons = ["Spring", "Summer", "Fall", "Winter", "Winter"] if req_up else ["spring", "summer", "fall", "winter"]
    for season in seasons:
        for y in years:
            for sp in specials[:2]:
                candidates.append((season + y + sp, 0.55))

    # Deduplicate, pair with usernames, rank
    seen: set[str] = set()
    results: list[dict] = []
    for pw, conf in sorted(candidates, key=lambda x: -x[1]):
        if pw in seen:
            continue
        seen.add(pw)
        for u in usernames:
            results.append({
                "username": u,
                "password": pw,
                "confidence": round(conf, 2),
            })
            if len(results) >= count:
                return results
    return results
