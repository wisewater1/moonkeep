from core.plugin_manager import BasePlugin
import math
import os
import re


class SecretHunterPlugin(BasePlugin):
    ENTROPY_THRESHOLDS = {
        "OpenAI Key":     4.5,
        "AWS Access Key": 3.8,
        "AWS Secret Key": 4.0,
        "Stripe API Key": 4.0,
        "GitHub Token":   4.0,
        "Private Key":    0.0,
        "Env Variable":   3.5,
    }
    MAX_ENTROPY = 6.0

    def __init__(self):
        self.patterns = {
            "OpenAI Key":     r"sk-[a-zA-Z0-9]{48}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+=]{40}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "GitHub Token":   r"ghp_[a-zA-Z0-9]{36}",
            "Private Key":    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "Env Variable":   r"(?i)(api_key|password|secret|token|credential)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        }

    @property
    def name(self) -> str:
        return "Secret-Hunter"

    @property
    def description(self) -> str:
        return "Zero-Mock Repository Secret Discovery"

    async def start(self):
        print("Secret Hunter: Initializing entropy engines.")

    async def stop(self):
        print("Secret Hunter: Suspending engines.")

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((count / n) * math.log2(count / n) for count in freq.values())

    @staticmethod
    def _extract_secret_value(pattern_name: str, match) -> str:
        if pattern_name == "Env Variable":
            if match.lastindex and match.lastindex >= 2:
                return match.group(2)
        return match.group(0)

    @classmethod
    def _compute_confidence(cls, entropy: float, threshold: float) -> float:
        if entropy < threshold:
            return 0.0
        span = cls.MAX_ENTROPY - threshold
        if span <= 0:
            return 1.0
        return round(min(1.0, (entropy - threshold) / span), 4)

    async def hunt(self, target_path=".."):
        """Perform deep scan on project workspace."""
        findings = []
        abs_target = os.path.abspath(target_path)
        print(f"Secret Hunter: Scanning {abs_target}")

        for root, dirs, files in os.walk(abs_target):
            if any(x in root for x in ["venv", ".git", "node_modules", "__pycache__", "dist"]):
                continue
            for file in files:
                if file.endswith((".py", ".js", ".jsx", ".ts", ".tsx",
                                  ".env", ".json", ".yaml", ".yml")):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        for name, pattern in self.patterns.items():
                            for match in re.finditer(pattern, content):
                                secret_val = self._extract_secret_value(name, match)
                                entropy    = self._shannon_entropy(secret_val)
                                threshold  = self.ENTROPY_THRESHOLDS.get(name, 3.0)
                                if entropy < threshold:
                                    continue
                                confidence = self._compute_confidence(entropy, threshold)
                                finding = {
                                    "file":       os.path.relpath(path, abs_target),
                                    "type":       name,
                                    "preview":    f"...{content[max(0, match.start()-15):min(len(content), match.end()+15)]}...",
                                    "entropy":    round(entropy, 4),
                                    "confidence": confidence,
                                }
                                findings.append(finding)
                                self.emit("SECRET_FINDING", finding)
                    except Exception:
                        pass

        findings.sort(key=lambda x: x['file'])
        return findings
