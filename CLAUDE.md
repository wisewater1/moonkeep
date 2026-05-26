# Moonkeep Elite v2 - Development Guide

## Overview
Moonkeep is a full-stack cybersecurity reconnaissance and offensive security framework with a React dashboard and Python FastAPI backend. It integrates network scanning, WiFi analysis, MITM tools, AI-driven attack orchestration, and recon-ng OSINT capabilities.

## Architecture

```
moonkeep/
├── backend/                    # Python FastAPI server (port 8001)
│   ├── main.py                 # API entry point — all HTTP/WS routes (~1300 lines)
│   ├── core/
│   │   ├── auth.py             # JWT auth, bcrypt hashing, audit log
│   │   ├── plugin_manager.py   # BasePlugin ABC + dynamic plugin loader
│   │   ├── campaign_manager.py # SQLite persistence (campaigns, devices, creds)
│   │   ├── bettercap_adapter.py# Native bettercap CLI replacement (no binaries)
│   │   ├── recon_adapter.py    # Subprocess bridge to recon-ng with WS streaming
│   │   ├── pipeline_engine.py  # Event-driven plugin chaining
│   │   └── scapy_init.py       # IPv6-route patches (imported first in main.py)
│   ├── plugins/                # 26 security modules (all extend BasePlugin):
│   │                           #   scanner, sniffer, spoofer, proxy
│   │                           #   wifi_strike, wifi_fingerprint, rogue_ap, rogue_radius
│   │                           #   cyber_strike, post_exploit, fuzzer, mesh_injector
│   │                           #   hid_ble, wardriver
│   │                           #   cred_spray, cred_genome, hash_cracker
│   │                           #   vuln_scanner, exploit_mapper, web_scanner
│   │                           #   secret_hunter, osint_enricher, identity_correlator
│   │                           #   ai_orchestrator, baseline_calibrator, report_builder
│   ├── tests/                  # pytest suite (~92 tests across test_api/auth/bettercap/campaign_manager)
│   └── recon-ng/               # Integrated recon-ng framework
├── frontend/                   # React 19 + Vite 7 dashboard (port 5173)
│   └── src/
│       ├── App.jsx             # Main shell (~2000 lines)
│       ├── panels/             # Per-plugin UI panels
│       ├── components/         # Shared components (terminal, toasts, etc.)
│       ├── hooks/              # Custom React hooks
│       ├── api.js              # REST client wrapper
│       └── config.js           # Frontend config (backend URL, etc.)
├── .github/workflows/ci.yml    # Backend tests + frontend build + frontend lint
├── dev.sh                      # Start everything: ./dev.sh [backend|frontend|all]
├── install-pi.sh               # Raspberry Pi systemd installer
├── setup.sh                    # Local dev setup (venv + npm install)
├── docker-compose.yml          # Backend + frontend + redis container stack
└── CLAUDE.md                   # This file
```

## Quick Start

```bash
# Full stack (backend + frontend + redis):
./dev.sh

# Or individually:
./dev.sh backend    # FastAPI on :8001 with hot reload
./dev.sh frontend   # Vite on :5173 with HMR
```

First boot writes a random admin password to `/var/lib/moonkeep/initial-password.txt`
(mode 0600). Override with `MOONKEEP_ADMIN_PASSWORD=...` for scripted installs.

## Tech Stack
- **Backend**: Python 3.11, FastAPI, Scapy, SQLite, asyncio, WebSockets, slowapi (rate limits), PyJWT, bcrypt
- **Frontend**: React 19, Vite 7, xterm.js (terminal emulator)
- **Queue**: Redis + RQ (recon-ng async jobs)
- **Database**: SQLite (`moonkeep_campaigns.db`, `moonkeep_auth.db`)

## Backend API
- All routes in `backend/main.py`
- Auto-docs at `http://localhost:8001/docs` (Swagger UI)
- Auth: JWT Bearer tokens. Login `POST /auth/login` → `{token}`. All routes (HTTP + WS) require it except `/auth/login`, `/auth/register`, `/auth/status`, `/docs`, `/openapi.json`, `/redoc`.
- WebSocket endpoints (both require `?token=<jwt>` — no token = close 4401):
  - `/ws` — global event firehose
  - `/ws/recon` — interactive recon-ng terminal (xterm-compatible)
- Key REST endpoints: `/scan`, `/wifi_scan`, `/plugins`, `/campaigns`, `/metrics`, `/auth/*`, `/ai/*`, `/bettercap/*`, `/pipeline/*`

## Plugin System
Plugins live in `backend/plugins/`. Each must extend `BasePlugin` from `core.plugin_manager`:
- Required: `name`, `description` properties; `start()`, `stop()` async methods
- Auto-injected at startup: `event_queue`, `target_store`, `bettercap`
- Use `self.emit(type, data)` to push events to the WebSocket bus
- Use `self.log_event(msg)` for operational logging

All `.py` files in `backend/plugins/` are loaded dynamically by `PluginManager` at startup — no explicit registration needed.

## Database
SQLite with tables: `campaigns`, `devices`, `networks`, `findings`, `credentials`, `timeline`, `users`, `audit_log`
- Campaign schema in `backend/core/campaign_manager.py`
- Auth schema in `backend/core/auth.py`

## Environment
Key environment variables (see `backend/.env.example` for the full list):
- `MOONKEEP_SECRET_KEY` — JWT signing key. If unset, generated and persisted to `MOONKEEP_SECRET_KEY_FILE` (default `/var/lib/moonkeep/secret-key`, mode 0600).
- `MOONKEEP_ADMIN_PASSWORD` — Initial admin password. If unset, a random one is written to `MOONKEEP_INITIAL_PASSWORD_FILE` (default `/var/lib/moonkeep/initial-password.txt`, mode 0600).
- `MOONKEEP_CORS_ORIGINS` — Comma-separated allowed origins. Defaults to `http://localhost:5173,http://127.0.0.1:5173`. Setting `*` disables `allow_credentials`.
- `REDIS_URL` — for slowapi rate-limit storage + recon-ng job queue.
- Ramdisk cache at `/dev/shm/moonkeep-cache` and `/dev/shm/moonkeep-tmp`.

## Common Commands

```bash
# Install backend deps
cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# Install frontend deps
cd frontend && npm install

# Run backend only
cd backend && python3 -m uvicorn main:app --reload --port 8001

# Run frontend only
cd frontend && npx vite --host 0.0.0.0

# Lint frontend
cd frontend && npm run lint

# Build frontend for production
cd frontend && npm run build
```

## Testing
- Backend: `cd backend && python3 -m pytest -v --timeout=15` (requires `pytest-timeout`)
- Frontend: `cd frontend && npm run lint` (no test runner wired yet)
- API smoke test: `python3 verify_api.py`

## Deployment
- **Docker**: `docker-compose up` — backend + frontend + redis
- **Raspberry Pi**: `curl -fsSL .../install-pi.sh | sudo bash` — installs systemd service. Pass `--skip-frontend-build` if `frontend/dist/` is already built.
- **Vercel/serverless**: not supported — the backend needs Python + Redis + raw-socket privileges.

## Git Workflow
- Main branch: `main`
- Feature branches: `claude/<feature>-<id>`
- Always commit with descriptive messages
- Push to feature branch, create PR for review
