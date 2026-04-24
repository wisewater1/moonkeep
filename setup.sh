#!/usr/bin/env bash
# Moonkeep Elite - Setup & Development Script
# Usage: ./setup.sh [dev|backend|frontend|test|docker]
#   (no args)  — Full setup: check deps, create venv, install everything
#   dev        — Start both backend + frontend dev servers
#   backend    — Start backend only
#   frontend   — Start frontend only
#   test       — Run backend pytest suite
#   docker     — Build and start via docker compose
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[moonkeep]${NC} $1"; }
ok()   { echo -e "${GREEN}[moonkeep]${NC} $1"; }
warn() { echo -e "${YELLOW}[moonkeep]${NC} $1"; }
err()  { echo -e "${RED}[moonkeep]${NC} $1"; }

# ─── Dependency checks ────────────────────────────────────────────────────

check_python() {
    if ! command -v python3 &>/dev/null; then
        err "Python 3 is not installed. Please install Python 3.11+."
        exit 1
    fi
    local py_version
    py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    local py_major py_minor
    py_major=$(echo "$py_version" | cut -d. -f1)
    py_minor=$(echo "$py_version" | cut -d. -f2)
    if [ "$py_major" -lt 3 ] || { [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 11 ]; }; then
        err "Python 3.11+ required (found $py_version)."
        exit 1
    fi
    ok "Python: $py_version"
}

check_node() {
    if ! command -v node &>/dev/null; then
        err "Node.js is not installed. Please install Node 18+."
        exit 1
    fi
    local node_version
    node_version=$(node -v | sed 's/^v//')
    local node_major
    node_major=$(echo "$node_version" | cut -d. -f1)
    if [ "$node_major" -lt 18 ]; then
        err "Node 18+ required (found $node_version)."
        exit 1
    fi
    ok "Node.js: $node_version"
}

check_redis() {
    if ! command -v redis-server &>/dev/null; then
        warn "Redis is not installed. Recon-ng job queue will not work."
        warn "Install with: apt install redis-server (Debian/Ubuntu) or brew install redis (macOS)"
        return 1
    fi
    ok "Redis: installed"
    return 0
}

# ─── Setup functions ──────────────────────────────────────────────────────

setup_env() {
    if [ ! -f "$BACKEND_DIR/.env" ]; then
        if [ -f "$BACKEND_DIR/.env.example" ]; then
            log "Creating .env from .env.example..."
            cp "$BACKEND_DIR/.env.example" "$BACKEND_DIR/.env"
            # Generate a random secret key
            local secret_key
            secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))")
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sed -i '' "s/change-me-to-a-random-64-char-hex-string/$secret_key/" "$BACKEND_DIR/.env"
            else
                sed -i "s/change-me-to-a-random-64-char-hex-string/$secret_key/" "$BACKEND_DIR/.env"
            fi
            ok ".env created with generated MOONKEEP_SECRET_KEY"
        else
            warn "No .env.example found — skipping .env creation."
        fi
    else
        ok ".env already exists"
    fi
}

setup_backend() {
    if [ ! -d "$VENV_DIR" ]; then
        log "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR"
        ok "Virtual environment created at $VENV_DIR"
    else
        ok "Virtual environment already exists"
    fi

    log "Installing backend dependencies..."
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip -q
    pip install -r "$BACKEND_DIR/requirements.txt" -q
    ok "Backend dependencies installed"
}

setup_frontend() {
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        log "Installing frontend dependencies..."
        cd "$FRONTEND_DIR"
        npm install
        ok "Frontend dependencies installed"
    else
        ok "Frontend node_modules already exists"
    fi
}

# ─── Runtime functions (preserved from dev.sh) ────────────────────────────

ensure_redis() {
    if ! redis-cli ping &>/dev/null; then
        log "Starting Redis..."
        redis-server --daemonize yes --maxmemory 512mb --maxmemory-policy allkeys-lru --port 6379
    fi
    ok "Redis: OK"
}

ensure_ramdisk() {
    mkdir -p /dev/shm/moonkeep-cache /dev/shm/moonkeep-tmp 2>/dev/null || true
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

run_tests() {
    log "Running backend tests..."
    cd "$BACKEND_DIR"
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    fi
    python3 -m pytest -v
}

run_docker() {
    log "Building and starting Docker containers..."
    cd "$ROOT_DIR"
    docker compose up --build -d
    ok "=== Moonkeep Elite (Docker) ==="
    ok "  Frontend: http://localhost:80"
    ok "  Backend:  http://localhost:8001"
    ok "  Redis:    localhost:6379"
    ok "================================"
}

# ─── Full setup (default, no args) ───────────────────────────────────────

full_setup() {
    log "=== Moonkeep Elite - Full Setup ==="
    echo ""
    log "Checking dependencies..."
    check_python
    check_node
    check_redis || true
    echo ""
    setup_env
    setup_backend
    setup_frontend
    echo ""
    ok "=== Setup complete! ==="
    ok "  Run './setup.sh dev' to start the development servers"
    ok "  Run './setup.sh docker' to start via Docker"
    ok "  Run './setup.sh test' to run the test suite"
}

# ─── Entrypoint ──────────────────────────────────────────────────────────

case "${1:-}" in
    "")        full_setup ;;
    dev)       ensure_redis; ensure_ramdisk; start_all ;;
    backend)   ensure_redis; ensure_ramdisk; start_backend ;;
    frontend)  start_frontend ;;
    test)      run_tests ;;
    docker)    run_docker ;;
    *)
        echo "Usage: $0 [dev|backend|frontend|test|docker]"
        echo ""
        echo "Commands:"
        echo "  (none)     Full setup — check deps, install everything"
        echo "  dev        Start backend + frontend dev servers"
        echo "  backend    Start backend only"
        echo "  frontend   Start frontend only"
        echo "  test       Run pytest test suite"
        echo "  docker     Build and start via docker compose"
        exit 1
        ;;
esac
