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
    warn "Repo is at $INSTALL_DIR, not /opt/seceoknight."
    warn "The systemd service and Nginx config in this repo hardcode /opt/seceoknight —"
    warn "if you keep this location, you'll need to edit systemd/seceoknight.service and"
    warn "nginx/seceoknight.conf yourself after this script finishes. Recommended: move the"
    warn "clone to /opt/seceoknight and re-run this script from there instead."
    read -p "  Continue anyway? [y/N] " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
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

# ── Step 4 -- systemd service ────────────────────────────────────────────────
step "Installing systemd service"
cp "$INSTALL_DIR/systemd/seceoknight.service" /etc/systemd/system/seceoknight.service
systemctl daemon-reload
systemctl enable seceoknight >/dev/null 2>&1
systemctl restart seceoknight
sleep 2
if systemctl is-active --quiet seceoknight; then
    ok "seceoknight service is running"
else
    err "seceoknight service failed to start — check: sudo journalctl -u seceoknight -n 50"
    exit 1
fi

# ── Step 5 -- Nginx reverse proxy ───────────────────────────────────────────
step "Configuring Nginx"
cp "$INSTALL_DIR/nginx/seceoknight.conf" /etc/nginx/sites-available/seceoknight
ln -sf /etc/nginx/sites-available/seceoknight /etc/nginx/sites-enabled/seceoknight
rm -f /etc/nginx/sites-enabled/default
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    ok "Nginx configured and reloaded"
else
    err "Nginx config test failed — run 'sudo nginx -t' for details"
    exit 1
fi

# ── Step 6 -- Firewall ────────────────────────────────────────────────────
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

# ── Step 7 -- Seed default blocklist ────────────────────────────────────────
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
echo "  Verify it's working:"
echo "    curl http://localhost/health"
echo "    curl http://localhost/blocklist"
echo "    curl http://localhost/api/stats"
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
