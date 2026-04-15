#!/usr/bin/env bash
# Moonkeep Elite - Development Startup Script
# Usage: ./dev.sh [backend|frontend|all]
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[moonkeep]${NC} $1"; }
ok()  { echo -e "${GREEN}[moonkeep]${NC} $1"; }
err() { echo -e "${RED}[moonkeep]${NC} $1"; }

ensure_redis() {
    if ! redis-cli ping &>/dev/null; then
        log "Starting Redis..."
        redis-server --daemonize yes --maxmemory 512mb --maxmemory-policy allkeys-lru --port 6379
    fi
    ok "Redis: OK"
}

ensure_ramdisk() {
    mkdir -p /dev/shm/moonkeep-cache /dev/shm/moonkeep-tmp
    export TMPDIR=/dev/shm/moonkeep-tmp
    ok "Ramdisk: OK (/dev/shm/moonkeep-*)"
}

start_backend() {
    log "Starting backend (FastAPI on :8001)..."
    cd "$BACKEND_DIR"
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8001 --reload --log-level info
}

start_frontend() {
    log "Starting frontend (Vite on :5173)..."
    cd "$FRONTEND_DIR"
    exec npx vite --host 0.0.0.0
}

start_all() {
    ensure_redis
    ensure_ramdisk

    log "Starting backend..."
    cd "$BACKEND_DIR"
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    python3 -m uvicorn main:app --host 0.0.0.0 --port 8001 --reload --log-level info &
    BACKEND_PID=$!
    ok "Backend PID: $BACKEND_PID"

    log "Starting frontend..."
    cd "$FRONTEND_DIR"
    npx vite --host 0.0.0.0 &
    FRONTEND_PID=$!
    ok "Frontend PID: $FRONTEND_PID"

    ok "=== Moonkeep Elite Dev Environment ==="
    ok "  Backend:  http://localhost:8001"
    ok "  Frontend: http://localhost:5173"
    ok "  API docs: http://localhost:8001/docs"
    ok "  Redis:    localhost:6379"
    ok "======================================="

    trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
    wait
}

case "${1:-all}" in
    backend)  ensure_redis; ensure_ramdisk; start_backend ;;
    frontend) start_frontend ;;
    all)      start_all ;;
    *)        echo "Usage: $0 [backend|frontend|all]"; exit 1 ;;
esac
