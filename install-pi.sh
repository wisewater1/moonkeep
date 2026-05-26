#!/usr/bin/env bash
# Moonkeep Elite — Raspberry Pi one-liner installer
# Usage: curl -fsSL https://raw.githubusercontent.com/wisewater1/moonkeep/main/install-pi.sh | sudo bash
#
# Flags:
#   --skip-frontend-build     Don't run `npm run build` (use existing frontend/dist).
#   --force-frontend-build    Run `npm run build` even if frontend/dist already exists.
set -e

INSTALL_DIR="${MOONKEEP_DIR:-/opt/moonkeep}"
PORT="${MOONKEEP_PORT:-8001}"
PIP_CACHE="${PIP_CACHE_DIR:-/var/cache/pip}"

SKIP_FRONTEND_BUILD=0
FORCE_FRONTEND_BUILD=0
for arg in "$@"; do
  case "$arg" in
    --skip-frontend-build)  SKIP_FRONTEND_BUILD=1 ;;
    --force-frontend-build) FORCE_FRONTEND_BUILD=1 ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[moonkeep]${NC} $1"; }
ok()   { echo -e "${GREEN}[moonkeep]${NC} $1"; }
warn() { echo -e "${YELLOW}[moonkeep]${NC} $1"; }
die()  { echo -e "${RED}[moonkeep] FATAL:${NC} $1"; exit 1; }

# ── Privilege check ─────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install-pi.sh"

# ── Arch detection ──────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  aarch64) ARCH_NAME="Pi 5 / Pi 4 / Zero 2W (64-bit)" ;;
  armv7l)  ARCH_NAME="Pi 3 / Pi 4 / Zero 2W (32-bit)" ;;
  armv6l)  die "ARMv6 (Pi Zero 1 / Pi 1) is not supported. Minimum: Pi Zero 2W or Pi 3." ;;
  x86_64)  ARCH_NAME="x86_64 (non-Pi)"; warn "Not a Pi — continuing anyway" ;;
  *)       ARCH_NAME="$ARCH"; warn "Unknown arch $ARCH — proceeding" ;;
esac
log "Detected: $ARCH_NAME"

# ── System packages ─────────────────────────────────────────────
log "Installing system dependencies (this may take a few minutes)..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-venv python3-dev \
  build-essential libffi-dev libssl-dev \
  libpcap-dev libxml2-dev libxslt1-dev pkg-config \
  openssl git curl wget ca-certificates \
  nodejs npm
ok "System packages installed"

# ── Source ──────────────────────────────────────────────────────
if [ -f "$INSTALL_DIR/backend/main.py" ]; then
  log "Source already present at $INSTALL_DIR — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only 2>/dev/null || warn "Could not pull; using existing source"
else
  log "Cloning Moonkeep to $INSTALL_DIR..."
  git clone --depth 1 https://github.com/wisewater1/moonkeep "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# ── piwheels (ARM only — prebuilt wheels for bcrypt, lxml, cryptography, etc.) ──
if [[ "$ARCH" == "aarch64" || "$ARCH" == "armv7l" ]]; then
  log "Configuring piwheels for faster ARM wheel installs..."
  pip3 config set global.extra-index-url https://www.piwheels.org/simple 2>/dev/null || true
fi

# ── Backend venv + deps ─────────────────────────────────────────
log "Creating Python venv and installing backend dependencies..."
mkdir -p "$PIP_CACHE"
export PIP_CACHE_DIR="$PIP_CACHE"
python3 -m venv backend/.venv
# shellcheck disable=SC1091
source backend/.venv/bin/activate
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
deactivate
ok "Backend dependencies installed (pip cache: $PIP_CACHE)"

# ── Frontend build (skipped if dist/ already present) ───────────
STATIC_DIR="$INSTALL_DIR/frontend/dist"
if [ "$SKIP_FRONTEND_BUILD" -eq 1 ]; then
  warn "Skipping frontend build (--skip-frontend-build)"
  [ -f "$STATIC_DIR/index.html" ] || warn "  $STATIC_DIR/index.html missing — dashboard will 404"
elif [ "$FORCE_FRONTEND_BUILD" -eq 0 ] && [ -f "$STATIC_DIR/index.html" ]; then
  ok "Frontend already built → $STATIC_DIR (pass --force-frontend-build to rebuild)"
else
  log "Building frontend dashboard (takes ~60s on Pi 4, ~3min on Pi 3)..."
  cd frontend
  npm install --prefer-offline --no-audit --silent
  npm run build --silent
  cd ..
  ok "Frontend built → $STATIC_DIR"
fi

# ── .env ────────────────────────────────────────────────────────
ENV_FILE="$INSTALL_DIR/backend/.env"
if [ ! -f "$ENV_FILE" ]; then
  cp "$INSTALL_DIR/backend/.env.example" "$ENV_FILE"
fi

SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

set_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
  fi
}

INITIAL_PW_FILE_DEFAULT="/var/lib/moonkeep/initial-password.txt"
SECRET_KEY_FILE_DEFAULT="/var/lib/moonkeep/secret-key"
mkdir -p "$(dirname "$INITIAL_PW_FILE_DEFAULT")"
chmod 700 "$(dirname "$INITIAL_PW_FILE_DEFAULT")"

set_env MOONKEEP_SECRET_KEY "$SECRET"
set_env MOONKEEP_SECRET_KEY_FILE "$SECRET_KEY_FILE_DEFAULT"
set_env MOONKEEP_STATIC_DIR "$STATIC_DIR"
set_env MOONKEEP_PORT "$PORT"
set_env MOONKEEP_INITIAL_PASSWORD_FILE "$INITIAL_PW_FILE_DEFAULT"
ok ".env configured"

# ── systemd service ─────────────────────────────────────────────
cat > /etc/systemd/system/moonkeep.service <<EOF
[Unit]
Description=Moonkeep Elite
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=${INSTALL_DIR}/backend/.env
ExecStart=${INSTALL_DIR}/backend/.venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port ${PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable moonkeep
systemctl restart moonkeep
ok "systemd service enabled and started (moonkeep.service)"

# ── Final banner ────────────────────────────────────────────────
PI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
INITIAL_PW_FILE="${MOONKEEP_INITIAL_PASSWORD_FILE:-$INITIAL_PW_FILE_DEFAULT}"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Moonkeep Elite — Pi Ready  ✓        ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
printf "${GREEN}║${NC}  Dashboard:  http://%-20s${GREEN}║${NC}\n" "${PI_IP}:${PORT}"
printf "${GREEN}║${NC}  API docs:   http://%-20s${GREEN}║${NC}\n" "${PI_IP}:${PORT}/docs"
echo -e "${GREEN}║${NC}  Admin user: admin                      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Password:   see file below              ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Logs:       journalctl -u moonkeep -f  ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
if [ -f "$INITIAL_PW_FILE" ]; then
  ok "Initial admin password written to: $INITIAL_PW_FILE (mode 0600)"
  log "Read it with:    sudo cat $INITIAL_PW_FILE"
else
  warn "Initial password file not found at $INITIAL_PW_FILE."
  warn "It will be created on first systemd-service startup; check journalctl -u moonkeep | grep AUTH"
fi
log "Change password: POST /auth/change_password (or via the dashboard UI)"
log "To stop:    systemctl stop moonkeep"
log "To restart: systemctl restart moonkeep"
log "To update:  git -C $INSTALL_DIR pull && systemctl restart moonkeep"
