from core.plugin_manager import BasePlugin
import asyncio
import os
import re
import math
from datetime import datetime

class SecretHunterPlugin(BasePlugin):
    def __init__(self):
        self.patterns = {
            "OpenAI Key": r"sk-[a-zA-Z0-9]{20,}",
            "Anthropic Key": r"sk-ant-[a-zA-Z0-9_-]{20,}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws[_\s]*secret[_\s]*(?:access)?[_\s]*key['\"\s:=]+([0-9a-zA-Z/+=]{30,})",
            "Stripe API Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
            "Stripe Publishable": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
            "GitHub Token": r"gh[ps]_[a-zA-Z0-9]{36,}",
            "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
            "GitLab Token": r"glpat-[a-zA-Z0-9_-]{20,}",
            "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+",
            "Discord Bot Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
            "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
            "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "Twilio Account SID": r"AC[a-zA-Z0-9]{32}",
            "Twilio Auth Token": r"(?i)twilio[_\s]*auth[_\s]*token['\"\s:=]+([a-zA-Z0-9]{32})",
            "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
            "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Password in Config": r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
            "Database URL": r"(?i)(?:postgres|mysql|mongodb|redis|sqlite)://[^\s'\"]+",
            "Connection String": r"(?i)(?:server|data source)=[^;]+;.*(?:password|pwd)=[^;]+",
            "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_-]{20,}",
            "Basic Auth": r"(?i)basic\s+[a-zA-Z0-9+/=]{10,}",
            "S3 Bucket URL": r"(?:s3://[a-zA-Z0-9._-]+|https?://[a-zA-Z0-9._-]+\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d\.amazonaws\.com)",
            "NPM Token": r"//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9_-]+",
            "Docker Auth": r'"auth"\s*:\s*"[a-zA-Z0-9+/=]{20,}"',
            "Env Variable": r"(?i)(?:api_key|api_secret|access_key|secret_key|auth_token|client_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        }
        self.last_findings = []
        self.file_extensions = (
            ".py", ".js", ".jsx", ".ts", ".tsx", ".env", ".json", ".yaml", ".yml",
            ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties", ".sh", ".bash",
            ".zsh", ".dockerfile", ".docker-compose", ".tf", ".tfvars", ".go",
            ".rb", ".php", ".java", ".cs", ".rs", ".sql", ".md", ".txt",
        )
        self.exclude_dirs = {
            "venv", ".venv", ".git", "node_modules", "__pycache__", "dist",
            "build", ".tox", ".pytest_cache", ".mypy_cache", "egg-info",
            ".eggs", "vendor", "bower_components", ".next", ".nuxt",
        }

    @property
    def name(self) -> str:
        return "Secret-Hunter"

    @property
    def description(self) -> str:
        return "Zero-Mock Repository Secret Discovery"

    @property
    def version(self) -> str:
        return "1.5.0"

    @property
    def category(self) -> str:
        return "recon"

    async def start(self):
        self.emit("INFO", {"msg": "Secret Hunter initialized with 30+ detection patterns"})

    async def stop(self):
        pass

    def _entropy(self, s):
        """Calculate Shannon entropy of a string — high entropy = likely secret."""
        if not s:
            return 0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def _read_file(self, path):
        """Synchronous file read helper — called via asyncio.to_thread()."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

    async def hunt(self, target_path=".."):
        """Deep filesystem scan for exposed secrets, API keys, tokens, and credentials."""
        findings = []
        abs_target = os.path.abspath(target_path)
        self.emit("INFO", {"msg": f"Scanning {abs_target} for secrets..."})
        files_scanned = 0

        for root, dirs, files in os.walk(abs_target):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.')]

            for file in files:
                if not file.endswith(self.file_extensions) and file not in (".env", ".env.local", ".env.production", "Dockerfile", "docker-compose.yml"):
                    continue

                path = os.path.join(root, file)
                # Skip large files
                try:
                    if os.path.getsize(path) > 2 * 1024 * 1024:  # 2MB limit
                        continue
                except OSError:
                    continue

                try:
                    content = await asyncio.to_thread(self._read_file, path)
                    files_scanned += 1

                    for name, pattern in self.patterns.items():
                        for match in re.finditer(pattern, content):
                            matched_text = match.group(0)
                            # Filter low-entropy matches (reduces false positives)
                            if len(matched_text) > 12 and self._entropy(matched_text) < 2.5:
                                continue

                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            rel_path = os.path.relpath(path, abs_target)

                            # Mask the middle of the secret for safety
                            preview_raw = content[max(0, match.start()-10):min(len(content), match.end()+10)]
                            if len(matched_text) > 8:
                                masked = matched_text[:4] + "*" * min(len(matched_text) - 8, 20) + matched_text[-4:]
                            else:
                                masked = matched_text

                            finding = {
                                "file": rel_path,
                                "line": line_num,
                                "type": name,
                                "preview": f"...{masked}...",
                                "entropy": round(self._entropy(matched_text), 2),
                                "severity": "CRITICAL" if name in ("Private Key", "SSH Private Key", "AWS Secret Key", "Database URL") else "HIGH",
                            }
                            findings.append(finding)

                            # Emit each finding as a WebSocket event
                            self.emit("SECRET_FOUND", finding)

                except Exception:
                    pass

        findings.sort(key=lambda x: (x['severity'], x['file']))
        self.last_findings = findings
        self.emit("SUCCESS", {"msg": f"Hunt complete: {len(findings)} secrets in {files_scanned} files"})

        # Persist to campaign
        if hasattr(self, 'target_store') and findings:
            for f in findings[:20]:  # Store top 20
                self.target_store.save_credential("Secret-Hunter", f"[{f['type']}] {f['file']}:{f['line']} — {f['preview']}")

        return findings
