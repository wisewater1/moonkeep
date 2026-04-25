# Moonkeep on iPhone + Android — Admin Console

This folder turns Moonkeep into a **mobile-native admin console** for
both iOS and Android. You are the **operator / admin**, not the target.
Every module (Scanner, Wi-Fi Strike, Cyber Strike, Post-Exploit, Proxy,
AI-Orchestrator, etc.) is reachable from the phone UI.

Works on:

- iPhone (Safari, Chrome iOS, Brave iOS — all use WebKit)
- iPad (same behavior as iPhone in Safari)
- Android (Chrome, Edge, Samsung Internet, Brave, Firefox)

Two supported deployment shapes:

1. **PWA (recommended)** — install the React dashboard to the phone's
   home screen. Full-screen, no browser chrome, safe-area-aware, works
   on iOS and Android alike.
2. **On-device shell (iSH / Blink on iOS, Termux on Android)** — clone
   the repo straight to the phone and drive the remote backend via
   SSH / Tailscale.

---

## 1 · PWA install (fastest path)

Prereqs: Moonkeep backend (port 8001) and the Vite frontend (port 5173)
are reachable from your phone — either on the same LAN, or over
Tailscale / WireGuard / Cloudflare Tunnel.

1. On the host, run `./dev.sh` (backend on `:8001`, frontend on `:5173`).
2. From the phone, open a browser and navigate to `http://<host-ip>:5173`
   (or your tunnel URL — see §4 for mobile-carrier port constraints).
3. Log in as admin via the existing login screen.
4. **iPhone (Safari):** tap *Share → Add to Home Screen.*
   **Android (Chrome/Edge):** tap *⋮ menu → Install app* (an install
   banner also appears automatically thanks to the service worker).
5. Launch from the home screen. The app opens **full-screen, no URL
   bar**, with a hamburger drawer (☰) for all modules.

The app is responsive down to 320px (iPhone SE, Pixel 4a). On phones
the left sidebar becomes a slide-in drawer, the split-pane view stacks
vertically, and all buttons are bumped to ≥40px touch targets. Safe
areas (notch, Dynamic Island, Android gesture nav bar) are respected.

### Runtime server switcher

The sidebar footer shows the current backend origin as a small cyan
label (for example `192.168.1.5:5173` or `same origin`). **Tap it** to
paste in a new backend URL — useful on the phone when you switch
between LAN, Tailscale, and Cloudflare Tunnel without rebuilding the
app. It stores the choice in `localStorage` and reloads.

---

## 2 · Port / carrier restrictions — what actually matters on phones

Mobile browsers are **not** strict about ports 8001 / 5173. What breaks
apps on phones is usually one of:

| Problem | Why | Fix |
| --- | --- | --- |
| Phone on cellular, backend on home LAN | Carrier NAT blocks inbound | **Tailscale** or **Cloudflare Tunnel** — expose the backend on 443 |
| HTTPS frontend talking to HTTP backend | Mixed-content block | Put both behind the same HTTPS origin (tunnel / reverse proxy) |
| `localhost` fallback | Resolves to the phone itself | Handled: every call now defaults to same-origin, and the Settings tap re-points it |
| PWA installed, host moved to different IP | Hard-coded URL stale | Tap the server label in the sidebar footer to re-point at runtime |
| Android Chrome no install prompt | Missing SW | Handled: `frontend/public/sw.js` ships with the PWA |

iOS Safari's blocked-port list (ports 1–19, 21–25, 37, 42, 43, 53, 69,
77, 79, 87, 95, 101–115, 117, 119, 123, 135–143, 161, 179, 389, 427,
465, 512–515, 526, 530–532, 540, 548, 554, 556, 563, 587, 601, 636,
993, 995, 1719–1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566,
6665–6669, 6697, 10080) does **not** include 8001 or 5173. Android
Chromium has a similar list — same conclusion.

### Recommended production config

Put the whole stack behind a tunnel so the phone hits **port 443
HTTPS** (always reachable, always TLS):

```sh
# one-liner with Cloudflare Tunnel
cloudflared tunnel --url http://localhost:5173
# or Tailscale
tailscale serve https:443 / http://localhost:5173
```

Then on the phone, tap the server label → paste the tunnel URL → done.
The app stores it in localStorage; all fetch/WebSocket traffic
auto-switches (HTTPS → WSS).

---

## 3 · Copy-paste onto the phone

If you want the repo physically on the phone (iSH / a-Shell on iOS,
Termux on Android):

```sh
# iOS (iSH / a-Shell) or Android (Termux):
pkg install git nodejs  # Termux only; iSH uses apk
git clone https://github.com/wisewater1/moonkeep
cd moonkeep
cp -r iphone/* .            # drops the mobile manifest + helpers in place
sh iphone/install.sh        # prints next-step guidance for the phone
```

The on-device shell can't run Scapy / raw sockets, so treat it as a
**control plane only** — it SSHes into the remote Moonkeep host where
the real engine lives:

```sh
# on the phone, from iSH or Termux
ssh admin@moonkeep-host
cd moonkeep && ./dev.sh backend
```

Then open the browser to `http://moonkeep-host:5173` (or your tunnel
URL) and use the PWA as in §1.

---

## 4 · Changes in the main app for mobile support

- `frontend/index.html`
    - `viewport-fit=cover`, `user-scalable=no`
    - `apple-mobile-web-app-capable`, `apple-mobile-web-app-status-bar-style=black-translucent`
    - `theme-color=#000`, apple-touch-icon, manifest link
- `frontend/public/manifest.webmanifest` — standalone display, black background
- `frontend/public/sw.js` — minimal network-first service worker
    - Unlocks Android Chrome's "Install app" banner
    - Caches *only* the static shell — never API/WS
- `frontend/src/config.js`
    - `API_BASE` / `WS_BASE` resolve from localStorage → env → same-origin
    - `setApiBase()` / `setWsBase()` helpers for the runtime switcher
- `frontend/src/api.js` — delegates to `config.js` (same resolution order)
- `frontend/src/App.jsx`
    - ~20 hardcoded `http://localhost:8001` fallbacks removed in favor
      of `API_BASE` / `WS_BASE` — the PWA no longer points at the phone
      itself
    - Sidebar footer origin label became a tappable URL switcher
    - Hamburger button (`.mobile-menu-btn`) in the header
    - `mobileNavOpen` state + backdrop that closes on tap
    - `pickPlugin` auto-closes the drawer when a module is selected
- `frontend/src/index.css`
    - `env(safe-area-inset-*)` padding on `.dashboard-container`
    - `100dvh` to dodge Safari's dynamic toolbar + Chrome's URL bar
    - `@media (max-width: 860px)` stacks sidebar → drawer, grid → single column
    - `@media (max-width: 420px)` tightens for iPhone SE / 12 mini / Pixel 4a
    - `@media (max-width: 900px) and (orientation: landscape)` landscape polish
    - `@media (min-width: 861px) and (max-width: 1100px)` iPad / tablet layout
    - `@media (display-mode: standalone)` tweaks for installed PWA
    - `-webkit-overflow-scrolling: touch` + `overscroll-behavior: contain`
    - Inputs forced to `font-size: 16px` to block iOS zoom-on-focus

All 25+ modules are admin-operable from the phone: Scanner, WiFi-Strike,
Rogue-AP, Rogue-RADIUS, WiFi-Fingerprinter, Mesh-Injector, Sniffer,
Proxy, Spoofer, Post-Exploit, Fuzzer, HID-BLE-Strike, Cyber-Strike,
AI-Orchestrator, Secret-Hunter, Vuln-Scanner, Exploit-Mapper, Web-Scanner,
Identity-Correlator, Cred-Spray, Hash-Cracker, Cred-Genome,
Baseline-Calibrator, OSINT-Enricher, Report-Builder, Recon-Console.

---

## 5 · Files in this folder

| File | Purpose |
| --- | --- |
| `README.md` | This document |
| `manifest.webmanifest` | PWA manifest (mirror of `frontend/public/`) |
| `env.template` | `.env.local` template for remote backend URLs |
| `install.sh` | On-device bootstrap (iSH / a-Shell / Termux safe) |
| `apple-touch-icon.svg` | Home-screen icon (iOS + Android maskable) |

---

## 6 · Troubleshooting

- **"Unable to connect"** → backend unreachable from phone network.
  Use Tailscale or Cloudflare Tunnel (§4). Or tap the cyan origin
  label in the sidebar footer and paste a reachable URL.
- **Home-screen app opens in a browser tab, not full-screen** →
  reinstall: long-press icon → Remove → re-add via Share / Install.
- **Android: no "Install app" prompt** → ensure the site is served
  over HTTPS (required) and the service worker registered. Hard-
  refresh from Chrome's ⋮ menu.
- **Drawer won't slide** → force-refresh the browser (iOS: Settings →
  Safari → Clear History; Android: Chrome → History → Clear data)
  to drop the cached CSS.
- **Text boxes zoom in on iOS** → fixed by the 16px input rule; clear
  cache to pick up the CSS.
- **Notch / gesture bar eats content** → the dashboard respects
  `safe-area-inset-*`; ensure your browser isn't forcing zoom.
- **WebSocket won't connect over a tunnel** → confirm the tunnel
  supports WebSockets (Cloudflare does by default, some reverse proxies
  need `proxy_http_version 1.1` + `Upgrade` / `Connection` headers).
