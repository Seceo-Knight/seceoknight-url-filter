#!/usr/bin/env bash
# =============================================================================
# SecEoKnight Extension Packager
# =============================================================================
# Signs extension/ into a .crx3 file + update.xml for Group Policy's
# ExtensionInstallForcelist -- the enterprise way to push and auto-update the
# extension on every machine silently, no Developer Mode or manual
# "Load Unpacked" clicking required.
#
# Usage:
#   bash scripts/package_extension.sh http://YOUR_SERVER_IP/extension/seceoknight.crx
#
# Run this on the same server that will host the files (simplest — the
# extension-dist/ output is already exactly where Nginx's /extension/
# location expects it), but it'll work from any machine with Node.js.
#
# Safe to re-run: reuses the existing signing key so the extension ID never
# changes, and re-run any time you ship an extension update (bump the
# version in extension/manifest.json first).
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
err()  { echo -e "  ${RED}[ERROR]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
step() { echo -e "\n${CYAN}==> $1${NC}"; }

CODEBASE_URL="${1:-}"
if [ -z "$CODEBASE_URL" ]; then
    err "Usage: bash scripts/package_extension.sh http://YOUR_SERVER_IP/extension/seceoknight.crx"
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_DIR="$REPO_DIR/extension"
KEY_FILE="$EXT_DIR/key.pem"
DIST_DIR="$REPO_DIR/extension-dist"
TOOL_DIR="$REPO_DIR/scripts/crx_tool"

if ! command -v node >/dev/null 2>&1; then
    err "Node.js is required. Install it first: sudo apt-get install -y nodejs npm"
    exit 1
fi

# ── Step 1 -- Signing key ────────────────────────────────────────────────────
step "Checking signing key"
if [ -f "$KEY_FILE" ]; then
    ok "Using existing extension/key.pem -- extension ID stays the same as last build"
else
    warn "No signing key found -- generating one now. This is a ONE-TIME event."
    warn "Back up $KEY_FILE somewhere safe (outside git). If it's ever lost, the next"
    warn "package you build gets a NEW extension ID, and every machine's Group Policy"
    warn "would need to be reconfigured with that new ID."
    openssl genrsa -out "$KEY_FILE" 2048 2>/dev/null
    chmod 600 "$KEY_FILE"
    ok "Generated extension/key.pem"
fi

# ── Step 2 -- Packaging tool dependencies ───────────────────────────────────
step "Checking packaging tool dependencies"
if [ -d "$TOOL_DIR/node_modules" ]; then
    ok "Already installed — skipping"
else
    (cd "$TOOL_DIR" && npm install --no-audit --no-fund -q)
    ok "Installed"
fi

# ── Step 3 -- Pack and sign ──────────────────────────────────────────────────
step "Packaging and signing extension/"
node "$TOOL_DIR/pack.js" "$EXT_DIR" "$KEY_FILE" "$DIST_DIR" "$CODEBASE_URL"

# ── Done ─────────────────────────────────────────────────────────────────────
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}  Done${NC}"
echo -e "${GREEN}=================================================${NC}"
echo "  Output: $DIST_DIR/seceoknight.crx and $DIST_DIR/update.xml"
echo ""
echo "  If these files aren't already being served by Nginx (they are by default"
echo "  once install.sh has run — see nginx/seceoknight.conf's /extension/ block),"
echo "  copy $DIST_DIR to wherever your web server serves it from."
echo ""
echo "  Verify it's reachable:"
echo "    curl -sI ${CODEBASE_URL%/*}/update.xml"
echo ""
echo "  Then see README.md 'Deploying the Extension via Group Policy' for the"
echo "  exact GPO setting to push this to every machine."
