# Moonkeep on iPhone — Admin Console

This folder turns Moonkeep into an **iPhone-native-feeling admin console**.
You are the **operator / admin**, not the target. Every module (Scanner,
Wi-Fi Strike, Cyber Strike, Post-Exploit, Proxy, AI-Orchestrator, etc.) is
reachable from the phone UI.

Two supported deployment shapes:

1. **PWA (recommended)** — install the React dashboard to the iPhone home
   screen. Full-screen, no Safari chrome, safe-area-aware.
2. **On-device shell (iSH / Blink / a-Shell)** — clone the repo straight to
   the phone and drive the backend via SSH into a remote Moonkeep host, or
   run a slimmed CLI locally.

---

## 1 · PWA install (fastest path)

Prereqs: Moonkeep backend (port 8001) and the Vite frontend are reachable
from your phone — either on the same LAN or over Tailscale / WireGuard /
Cloudflare Tunnel.

1. On the host, run `./dev.sh` (backend on `:8001`, frontend on `:5173`).
2. From the iPhone, open Safari and navigate to
   `http://<host-ip>:5173` (or your tunnel URL).
3. Log in as admin via the existing login screen.
4. Tap **Share → Add to Home Screen**.
5. Launch from the home screen. It opens **full-screen, no URL bar**,
   with a hamburger drawer for all modules.

The app is responsive down to iPhone SE width. On phones the left sidebar
becomes a slide-in drawer (tap ☰), the split-pane view stacks vertically,
and all buttons are bumped to ≥40px touch targets. iOS safe-area insets
are respected so the notch/home indicator don't overlap controls.

### Environment pointer

If your frontend is served from a different origin than the backend, drop
this in `frontend/.env.local` **before** building:

```
VITE_API_URL=https://moonkeep.mytunnel.ts.net
VITE_WS_URL=wss://moonkeep.mytunnel.ts.net
```

A template lives at [`iphone/env.template`](./env.template).

---

## 2 · Copy-paste onto the phone

If you literally want the repo on the phone (iSH / a-Shell / Working Copy):

```sh
# from iSH / a-Shell / Blink
git clone https://github.com/wisewater1/moonkeep
cd moonkeep
cp -r iphone/* .            # drops the mobile manifest + helpers in place
sh iphone/install.sh        # prints next-step guidance for the phone
```

The on-device shell cannot run Scapy / raw sockets, so treat it as a
**control plane only** — it SSHes into the remote Moonkeep host where the
real engine lives:

```sh
# on the phone, from iSH
ssh admin@moonkeep-host
cd moonkeep && ./dev.sh backend
```

Then open Safari to `http://moonkeep-host:5173` and use the PWA as in §1.

---

## 3 · What changed in the main app for iPhone support

- `frontend/index.html`
    - `viewport-fit=cover`, `user-scalable=no`
    - `apple-mobile-web-app-capable`, `apple-mobile-web-app-status-bar-style=black-translucent`
    - `theme-color=#000`, apple-touch-icon, manifest link
- `frontend/public/manifest.webmanifest` — standalone display, black background
- `frontend/src/index.css`
    - `env(safe-area-inset-*)` padding on `.dashboard-container`
    - `100dvh` to dodge Safari's dynamic toolbar
    - `@media (max-width: 860px)` stacks sidebar → drawer, grid → single column
    - `@media (max-width: 420px)` tightens for iPhone SE / 12 mini
    - Inputs forced to `font-size: 16px` to block iOS zoom-on-focus
- `frontend/src/App.jsx`
    - Hamburger button (`.mobile-menu-btn`) in the header
    - `mobileNavOpen` state + backdrop that closes on tap
    - Drawer auto-closes when a module is selected

All 25+ modules are admin-operable from the phone: Scanner, WiFi-Strike,
Rogue-AP, Rogue-RADIUS, WiFi-Fingerprinter, Mesh-Injector, Sniffer, Proxy,
Spoofer, Post-Exploit, Fuzzer, HID-BLE-Strike, Cyber-Strike, AI-Orchestrator,
Secret-Hunter, Vuln-Scanner, Exploit-Mapper, Web-Scanner, Identity-Correlator,
Cred-Spray, Hash-Cracker, Cred-Genome, Baseline-Calibrator, OSINT-Enricher,
Report-Builder, Recon-Console.

---

## 4 · Files in this folder

| File | Purpose |
| --- | --- |
| `README.md` | This document |
| `manifest.webmanifest` | Copy of the PWA manifest (mirror of `frontend/public/`) |
| `env.template` | `.env.local` template for remote backend URLs |
| `install.sh` | On-device bootstrap helper (iSH / a-Shell safe) |
| `apple-touch-icon.svg` | Home-screen icon |

---

## 5 · Troubleshooting on iPhone

- **"Unable to connect"** → backend unreachable from phone network. Put
  both devices on the same LAN, or front the host with Tailscale.
- **Home-screen app opens in Safari tab, not full-screen** → reinstall:
  long-press icon → Remove → re-add from Safari.
- **Drawer won't slide** → force-refresh Safari (Settings → Safari →
  Clear History) to drop the cached CSS.
- **Text boxes zoom in** → fixed by the 16px input rule; clear cache.
- **Notch eats content** → the dashboard respects `safe-area-inset-*`;
  ensure your browser isn't forcing zoom.
