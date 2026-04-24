#!/bin/sh
# Moonkeep iPhone bootstrap — safe to run inside iSH / a-Shell / Blink.
# This does NOT try to install Scapy / libpcap on the phone. It stages
# the PWA assets and prints the remaining manual steps.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

echo "[moonkeep] staging iPhone admin assets..."

# Ensure the manifest exists in the frontend public dir (idempotent).
if [ -d "$ROOT/frontend/public" ]; then
  cp "$HERE/manifest.webmanifest" "$ROOT/frontend/public/manifest.webmanifest"
  cp "$HERE/apple-touch-icon.svg" "$ROOT/frontend/public/apple-touch-icon.svg" 2>/dev/null || true
  echo "  ✓ manifest + apple-touch-icon copied to frontend/public/"
else
  echo "  ! frontend/public not found — run this from a full Moonkeep clone."
fi

# Stage env.local if the user has not yet configured one.
if [ ! -f "$ROOT/frontend/.env.local" ]; then
  cp "$HERE/env.template" "$ROOT/frontend/.env.local"
  echo "  ✓ wrote frontend/.env.local (edit to point at your backend)"
else
  echo "  · frontend/.env.local already present — left untouched"
fi

cat <<'EOF'

[moonkeep] next steps (from the iPhone):
  1. Make sure the backend is reachable — usually by SSHing into your
     Moonkeep host and running `./dev.sh`.
  2. Open Safari → http://<host>:5173  (or your tunnel URL).
  3. Log in as admin.
  4. Share → Add to Home Screen.
  5. Launch "Moonkeep" from the home screen. Hamburger (☰) opens the
     module drawer; every plugin is operable via touch.

You are the admin. There is no victim-side mode in this build.
EOF
