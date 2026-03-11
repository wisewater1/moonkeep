from core.plugin_manager import BasePlugin
import os
import re

class SecretHunterPlugin(BasePlugin):
    def __init__(self):
        self.patterns = {
            "OpenAI Key": r"sk-[a-zA-Z0-9]{48}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+=]{40}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
            "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "Env Variable": r"(?i)(api_key|password|secret|token|credential)\s*[:=]\s*['\"]([^'\"]+)['\"]"
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

    async def hunt(self, target_path=".."):
        """Perform deep scan on project workspace."""
        findings = []
        # Normalizing path for Windows
        abs_target = os.path.abspath(target_path)
        print(f"Secret Hunter: Scanning {abs_target}")
        
        for root, dirs, files in os.walk(abs_target):
            # Exclude noisy directories
            if any(x in root for x in ["venv", ".git", "node_modules", "__pycache__", "dist"]):
                continue
            
            for file in files:
                # Target relevant files
                if file.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".env", ".json", ".yaml", ".yml")):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for name, pattern in self.patterns.items():
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    findings.append({
                                        "file": os.path.relpath(path, abs_target),
                                        "type": name,
                                        "preview": f"...{content[max(0, match.start()-15):min(len(content), match.end()+15)]}..."
                                    })
                    except Exception as e:
                        pass
        
        # Sort by file name
        findings.sort(key=lambda x: x['file'])
        return findings
