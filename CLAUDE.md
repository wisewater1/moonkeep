# Moonkeep Elite v2 - Development Guide

## Overview
Moonkeep is a full-stack cybersecurity reconnaissance and offensive security framework with a React dashboard and Python FastAPI backend. It integrates network scanning, WiFi analysis, MITM tools, AI-driven attack orchestration, and recon-ng OSINT capabilities.

## Architecture

```
moonkeep/
├── backend/                  # Python FastAPI server (port 8001)
│   ├── main.py               # API entry point — all HTTP/WS routes
│   ├── core/
│   │   ├── plugin_manager.py # BasePlugin ABC + dynamic plugin loader
│   │   ├── campaign_manager.py # SQLite persistence (campaigns, devices, creds)
│   │   ├── bettercap_adapter.py # Native bettercap CLI replacement (no binaries)
│   │   └── recon_adapter.py  # Subprocess bridge to recon-ng with WebSocket streaming
│   ├── plugins/              # 13 security modules (all extend BasePlugin)
│   └── recon-ng/             # Integrated recon-ng framework
├── frontend/                 # React 19 + Vite 7 dashboard (port 5173)
│   └── src/App.jsx           # Single-file dashboard (~800 lines)
├── dev.sh                    # Start everything: ./dev.sh [backend|frontend|all]
└── CLAUDE.md                 # This file
```

## Quick Start

```bash
# Full stack (backend + frontend + redis):
./dev.sh

# Or individually:
./dev.sh backend    # FastAPI on :8001 with hot reload
./dev.sh frontend   # Vite on :5173 with HMR
```

## Tech Stack
- **Backend**: Python 3.11, FastAPI, Scapy, SQLite, asyncio, WebSockets
- **Frontend**: React 19, Vite 7, xterm.js (terminal emulator)
- **Queue**: Redis + RQ (recon-ng async jobs)
- **Database**: SQLite (`moonkeep_campaigns.db`)

## Backend API
- All routes in `backend/main.py`
- Auto-docs at `http://localhost:8001/docs` (Swagger UI)
- WebSocket endpoints: `/ws` (events), `/ws/recon` (recon-ng terminal)
- Key REST endpoints: `/scan`, `/wifi_scan`, `/plugins`, `/campaigns`, `/ai/*`, `/bettercap/*`

## Plugin System
Plugins live in `backend/plugins/`. Each must extend `BasePlugin` from `core.plugin_manager`:
- Required: `name`, `description` properties; `start()`, `stop()` async methods
- Auto-injected at startup: `event_queue`, `target_store`, `bettercap`
- Use `self.emit(type, data)` to push events to the WebSocket bus
- Use `self.log_event(msg)` for operational logging

## Frontend
- Single-page app in `frontend/src/App.jsx`
- Vite proxies `/ws` to backend WebSocket and `/api` to backend REST
- xterm.js provides interactive recon-ng terminal

## Database
SQLite with tables: `campaigns`, `devices`, `networks`, `findings`, `credentials`
Schema in `backend/core/campaign_manager.py`

## Environment
- Copy `backend/.env.example` to `backend/.env` for configuration
- Redis must be running for recon-ng job queue (`redis-server` or `./dev.sh` handles it)
- Ramdisk cache at `/dev/shm/moonkeep-cache` and `/dev/shm/moonkeep-tmp`

## Common Commands

```bash
# Install backend deps
cd backend && source .venv/bin/activate && pip install -r requirements.txt

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
- Backend: `cd backend && python3 -m pytest` (add tests to `backend/tests/`)
- Frontend: `cd frontend && npm test` (add test runner as needed)
- API verification: `python3 verify_api.py`

## Git Workflow
- Main branch: `main`
- Feature branches: `claude/<feature>-<id>`
- Always commit with descriptive messages
- Push to feature branch, create PR for review
