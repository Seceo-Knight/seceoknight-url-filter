#!/usr/bin/env bash
# =============================================================================
# SecEoKnight Security Server — One-Shot Installer
# =============================================================================
# Replaces the 15 manual steps in README.md Part 1 (Steps 2-13) with a single
# script. Run this AFTER cloning the repo to /opt/seceoknight — it installs
# system packages, sets up the Python venv, trains the phishing model (if not
# already present), installs the systemd service + Nginx config, opens the
# firewall, and seeds the default blocklist.
#
# Usage (from inside the cloned repo, e.g. /opt/seceoknight):
#   sudo bash scripts/install.sh
#
# Safe to re-run: every step checks whether it's already done before doing it,
# so running this again after a `git pull` just picks up new changes without
# re-training the model or re-seeding the blocklist.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
err()  { echo -e "  ${RED}[ERROR]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
step() { echo -e "\n${CYAN}==> $1${NC}"; }

# ── Preconditions ────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    err "This script must be run as root: sudo bash scripts/install.sh"
    exit 1
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$INSTALL_DIR"

if [ ! -f "$INSTALL_DIR/server/unified_server.py" ]; then
    err "Couldn't find server/unified_server.py under $INSTALL_DIR"
    err "Run this script from inside the cloned repo, e.g.: cd /opt/seceoknight && sudo bash scripts/install.sh"
    exit 1
fi

if [ "$INSTALL_DIR" != "/opt/seceoknight" ]; then
    warn "Repo is at $INSTALL_DIR, not the default /opt/seceoknight."
    warn "systemd/seceoknight.service and nginx/seceoknight.conf are written for /opt/seceoknight —"
    warn "this script rewrites those paths to match $INSTALL_DIR automatically before installing"
    warn "them (Steps 4 and 5 below), so this is safe to continue with as-is."
fi

REAL_USER="${SUDO_USER:-$USER}"

echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}  SecEoKnight Security Server — Installer${NC}"
echo -e "${CYAN}  Install dir: $INSTALL_DIR${NC}"
echo -e "${CYAN}=================================================${NC}"

# ── Step 1 -- System packages ────────────────────────────────────────────────
step "Installing system packages (this can take a few minutes)"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev python3-pip nginx sqlite3 curl >/dev/null
ok "python3 $(python3 --version | awk '{print $2}'), nginx, sqlite3 installed"

# ── Step 2 -- Python virtual environment ────────────────────────────────────
step "Setting up Python virtual environment"
if [ -d "$INSTALL_DIR/venv" ]; then
    ok "venv already exists — skipping creation"
else
    python3 -m venv venv
    ok "Created venv"
fi
# shellcheck disable=SC1091
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip -q
echo "  Installing Python dependencies (TensorFlow install takes 5-10 min, this is normal)..."
pip install -r requirements.txt -q
ok "Python dependencies installed"

# ── Step 3 -- Train the phishing model (only if not already trained) ───────
step "Checking phishing detection model"
if [ -f "$INSTALL_DIR/server/models/phishing/bilstm_domain_model.h5" ] && \
   [ -f "$INSTALL_DIR/server/models/phishing/tokenizer.pkl" ]; then
    ok "Phishing model already trained — skipping (takes 5-15 min, so this saves real time on re-runs)"
else
    echo "  Training phishing model on 95,980 samples — this takes 5-15 minutes..."
    python3 scripts/train_phishing_model.py
    ok "Phishing model trained"
fi
deactivate

# ── Step 4 -- API key ────────────────────────────────────────────────────────
# Generated once and kept in server/.env, which the systemd service loads via
# EnvironmentFile. Idempotent like everything else here -- re-running this
# script (e.g. after a git pull) does NOT rotate the key or touch
# SECEOKNIGHT_REQUIRE_API_KEY if a .env already exists, so it won't silently
# flip enforcement on/off or invalidate a key you've already rolled out to
# every agent/extension/dashboard.
step "Checking API key"
ENV_FILE="$INSTALL_DIR/server/.env"
if [ -f "$ENV_FILE" ]; then
    ok ".env already exists — keeping existing API key and enforcement setting"
else
    GENERATED_KEY="$(openssl rand -hex 32)"
    cat > "$ENV_FILE" <<EOF
SECEOKNIGHT_API_KEY=$GENERATED_KEY
SECEOKNIGHT_REQUIRE_API_KEY=false
EOF
    chmod 600 "$ENV_FILE"
    ok "Generated a new API key and saved it to server/.env (grace period: not yet enforced)"
fi

# ── Step 5 -- systemd service ────────────────────────────────────────────────
# The repo's systemd/seceoknight.service and nginx/seceoknight.conf hardcode
# /opt/seceoknight as WorkingDirectory/ExecStart/proxy.pac paths. If this repo
# actually lives somewhere else (e.g. /opt/seceoknight/seceoknight-url-filter,
# a common result of `git clone <url>` without the trailing " ." that clones
# into a subfolder), copying those files unmodified would install a service
# that points at paths that don't exist and fails to start -- or worse,
# silently overwrite a DIFFERENT already-working service file that some
# previous manual setup had correctly pointed at the real path. So: always
# rewrite /opt/seceoknight -> $INSTALL_DIR in the copies we install, even
# when they're the same (harmless no-op in that case).
step "Installing systemd service"
if [ -f /etc/systemd/system/seceoknight.service ]; then
    cp /etc/systemd/system/seceoknight.service "/etc/systemd/system/seceoknight.service.bak.$(date +%s)"
    ok "Backed up existing service file before overwriting"
fi
sed "s|/opt/seceoknight|$INSTALL_DIR|g" "$INSTALL_DIR/systemd/seceoknight.service" > /etc/systemd/system/seceoknight.service
systemctl daemon-reload
systemctl enable seceoknight >/dev/null 2>&1
systemctl restart seceoknight

# Wait for the HTTP server to actually be ready, not just for the process to
# exist. `systemctl is-active` goes true as soon as the process launches --
# but loading the phishing model + 3 malware models into memory can take
# well over the few seconds it takes systemd to consider the unit "started",
# so anything that immediately curls the server (like blocklist seeding
# below) can hit "connection refused" even though the service is technically
# "running". Poll /health instead, up to 90 seconds.
READY=0
for i in $(seq 1 45); do
    if curl -sf http://127.0.0.1:5001/health >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done

if [ "$READY" -eq 1 ]; then
    ok "seceoknight service is running and responding on /health"
elif systemctl is-active --quiet seceoknight; then
    warn "Process is running but /health didn't respond within 90s — AI models may still be"
    warn "loading on slower hardware. Continuing, but the blocklist-seeding step below may fail;"
    warn "if it does, just re-run: source venv/bin/activate && python3 scripts/add_default_blocklist.py"
else
    err "seceoknight service failed to start — check: sudo journalctl -u seceoknight -n 50"
    LATEST_BACKUP="$(ls -t /etc/systemd/system/seceoknight.service.bak.* 2>/dev/null | head -1)"
    if [ -n "$LATEST_BACKUP" ]; then
        warn "Restoring the previous working service file from $LATEST_BACKUP so the server doesn't stay down..."
        cp "$LATEST_BACKUP" /etc/systemd/system/seceoknight.service
        systemctl daemon-reload
        systemctl restart seceoknight
        sleep 2
        if systemctl is-active --quiet seceoknight; then
            ok "Restored and running on the previous config. Fix the new one before re-running this script."
        else
            err "Restore also failed to start — this needs manual intervention. See journalctl output above."
        fi
    fi
    exit 1
fi

# ── Step 6 -- Nginx reverse proxy ───────────────────────────────────────────
step "Configuring Nginx"
if [ -f /etc/nginx/sites-available/seceoknight ]; then
    cp /etc/nginx/sites-available/seceoknight "/etc/nginx/sites-available/seceoknight.bak.$(date +%s)"
    ok "Backed up existing Nginx config before overwriting"
fi
sed "s|/opt/seceoknight|$INSTALL_DIR|g" "$INSTALL_DIR/nginx/seceoknight.conf" > /etc/nginx/sites-available/seceoknight
ln -sf /etc/nginx/sites-available/seceoknight /etc/nginx/sites-enabled/seceoknight
rm -f /etc/nginx/sites-enabled/default
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    ok "Nginx configured and reloaded"
else
    err "Nginx config test failed — run 'sudo nginx -t' for details"
    exit 1
fi

# ── Step 7 -- Firewall ────────────────────────────────────────────────────
step "Opening firewall ports"
if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp   >/dev/null
    ufw allow 80/tcp   >/dev/null
    ufw allow 5001/tcp >/dev/null
    if ufw status | grep -q "Status: active"; then
        ok "ufw already active — rules ensured"
    else
        warn "ufw is installed but not enabled. Enable it now? This keeps port 22 (SSH) open first,"
        warn "so you won't get locked out."
        read -p "  Enable ufw? [y/N] " -n 1 -r; echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ufw --force enable >/dev/null
            ok "ufw enabled"
        else
            warn "Skipped — remember to enable your firewall manually"
        fi
    fi
else
    warn "ufw not found — skipping firewall step (install ufw or configure iptables manually)"
fi

# ── Step 8 -- Seed default blocklist ────────────────────────────────────────
step "Seeding default blocklist rules"
source "$INSTALL_DIR/venv/bin/activate"
python3 scripts/add_default_blocklist.py
deactivate
ok "Blocklist seeded (safe to re-run — existing rules are skipped, not duplicated)"

# ── Done ─────────────────────────────────────────────────────────────────────
SERVER_IP="$(hostname -I | awk '{print $1}')"
echo ""
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}  Installation complete${NC}"
echo -e "${GREEN}=================================================${NC}"
echo "  Detected LAN IP: $SERVER_IP"
echo ""
CURRENT_API_KEY="$(grep -oP '(?<=^SECEOKNIGHT_API_KEY=).*' "$ENV_FILE" 2>/dev/null || true)"
if [ -n "$CURRENT_API_KEY" ]; then
    echo -e "  ${YELLOW}API key: $CURRENT_API_KEY${NC}"
    echo "  Not yet enforced (grace period) — the server accepts requests without it for now."
    echo "  Give this key to: agent.py, to-server.py, malware_watcher.py, the Chrome extension's"
    echo "  Settings panel, and the SIEM dashboard backend's URL_FILTER_API_KEY. Once every one"
    echo "  of those is sending it (no more '[AUTH] WARNING' lines in the logs), set"
    echo "  SECEOKNIGHT_REQUIRE_API_KEY=true in server/.env and restart the service to enforce it."
    echo ""
fi
echo "  Verify it's working:"
echo "    curl http://localhost/health"
echo "    curl -H \"X-API-Key: \$KEY\" http://localhost/blocklist"
echo "    curl -H \"X-API-Key: \$KEY\" http://localhost/api/stats"
echo ""
echo "  Full health check:"
echo "    bash scripts/health_check.sh"
echo ""
echo "  Next: point your Windows endpoints and the Chrome extension at this IP"
echo "  ($SERVER_IP) — see README.md Part 2 and Part 3."
echo ""
if [ "$REAL_USER" != "root" ]; then
    chown -R "$REAL_USER":"$REAL_USER" "$INSTALL_DIR" 2>/dev/null || true
fi
