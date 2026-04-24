#!/bin/sh
# Moonkeep mobile bootstrap — safe to run inside iSH / a-Shell / Blink
# (iOS) or Termux / UserLAnd (Android). This does NOT try to install
# Scapy / libpcap on the phone. It stages the PWA assets and prints the
# remaining manual steps.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

echo "[moonkeep] staging mobile admin assets..."

# Ensure the manifest + icon + service worker exist in frontend/public (idempotent).
if [ -d "$ROOT/frontend/public" ]; then
  cp "$HERE/manifest.webmanifest" "$ROOT/frontend/public/manifest.webmanifest"
  cp "$HERE/apple-touch-icon.svg" "$ROOT/frontend/public/apple-touch-icon.svg" 2>/dev/null || true
  echo "  ✓ manifest + apple-touch-icon copied to frontend/public/"
  # sw.js already ships in the main repo; leave it alone if present.
  if [ ! -f "$ROOT/frontend/public/sw.js" ]; then
    echo "  ! frontend/public/sw.js missing — Android install prompt won't appear. Re-clone the repo."
  fi
else
  echo "  ! frontend/public not found — run this from a full Moonkeep clone."
fi

# Stage env.local if the user has not yet configured one.
if [ ! -f "$ROOT/frontend/.env.local" ]; then
  cp "$HERE/env.template" "$ROOT/frontend/.env.local"
  echo "  ✓ wrote frontend/.env.local (edit to point at your backend, or leave blank to use the in-app server switcher)"
else
  echo "  · frontend/.env.local already present — left untouched"
fi

cat <<'EOF'

[moonkeep] next steps (from the phone):
  1. Make sure the backend is reachable — usually by SSHing into your
     Moonkeep host and running `./dev.sh`. On a cellular network,
     front it with Tailscale or Cloudflare Tunnel so the phone can
     reach it on port 443.
  2. Open the browser → http://<host>:5173  (or your tunnel URL).
  3. Log in as admin.
  4. iPhone (Safari): Share → Add to Home Screen.
     Android (Chrome / Edge): ⋮ menu → Install app (or tap the install
                              banner at the bottom of the page).
  5. Launch "Moonkeep" from the home screen. Hamburger (☰) opens the
     module drawer; every plugin is operable via touch.
  6. If the backend isn't reachable, tap the cyan origin label in the
     sidebar footer and paste a new backend URL — no rebuild needed.

You are the admin. There is no victim-side mode in this build.
EOF
