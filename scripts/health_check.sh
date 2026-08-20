#!/usr/bin/env bash
# =============================================================================
# health_check.sh — SecEoKnight Server Health Check
# Run after deployment to verify all subsystems are operational.
#
# Usage:
#   bash scripts/health_check.sh [SERVER_IP] [PORT]
#   bash scripts/health_check.sh                     # defaults to 127.0.0.1:5001
#   bash scripts/health_check.sh 192.168.1.63 5001
# =============================================================================

SERVER="${1:-127.0.0.1}"
PORT="${2:-5001}"
BASE="http://$SERVER:$PORT"
PASS=0
FAIL=0

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

ok()   { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }

echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}  SecEoKnight Health Check${NC}"
echo -e "${CYAN}  Server: $BASE${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

# ── 1. systemd service ────────────────────────────────────────────────────────
echo -e "${CYAN}[1] systemd service${NC}"
if systemctl is-active --quiet seceoknight 2>/dev/null; then
    ok "seceoknight.service is running"
else
    fail "seceoknight.service is NOT running — run: sudo systemctl start seceoknight"
fi

# ── 2. Port listening ─────────────────────────────────────────────────────────
echo -e "\n${CYAN}[2] Port availability${NC}"
if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
    ok "Port $PORT is open and listening"
else
    fail "Port $PORT is NOT listening"
fi

if command -v nginx &>/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
    ok "Nginx is running"
else
    info "Nginx not running (optional — only needed for port 80/443 reverse proxy)"
fi

# ── 3. /health endpoint ───────────────────────────────────────────────────────
echo -e "\n${CYAN}[3] API health endpoint${NC}"
HEALTH=$(curl -sf --max-time 5 "$BASE/health" 2>/dev/null)
if [ $? -eq 0 ]; then
    ok "/health responded"
    STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null)
    info "Server status: $STATUS"

    # AI models
    PHISHING=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ai',{}).get('phishing_model','?'))" 2>/dev/null)
    MALWARE=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); ml=d.get('ai',{}).get('malware_models',{}); print(','.join(f'{k}={v}' for k,v in ml.items()))" 2>/dev/null)

    if [ "$PHISHING" = "loaded" ]; then
        ok "Phishing model: loaded"
    else
        fail "Phishing model: $PHISHING (run: python3 scripts/train_phishing_model.py)"
    fi

    if echo "$MALWARE" | grep -q "loaded"; then
        ok "Malware models: $MALWARE"
    else
        fail "Malware models: $MALWARE (copy CNN.keras, ViT.keras, 1D-CNN-LSTM.keras to server/models/malware/)"
    fi
else
    fail "/health endpoint unreachable at $BASE/health"
fi

# ── 4. Blocklist endpoint ─────────────────────────────────────────────────────
echo -e "\n${CYAN}[4] Blocklist endpoint${NC}"
BL=$(curl -sf --max-time 5 "$BASE/blocklist" 2>/dev/null)
if [ $? -eq 0 ]; then
    RULES=$(echo "$BL" | grep -c "." || echo 0)
    ok "/blocklist responded ($RULES rules)"
else
    fail "/blocklist endpoint unreachable"
fi

# ── 5. Stats endpoint ─────────────────────────────────────────────────────────
echo -e "\n${CYAN}[5] Stats endpoint${NC}"
STATS=$(curl -sf --max-time 5 "$BASE/api/stats" 2>/dev/null)
if [ $? -eq 0 ]; then
    ok "/api/stats responded"
    TOTAL=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_requests',0))" 2>/dev/null)
    info "Total requests in DB: $TOTAL"
else
    fail "/api/stats endpoint unreachable"
fi

# ── 6. Endpoints list ─────────────────────────────────────────────────────────
echo -e "\n${CYAN}[6] Connected endpoints${NC}"
EP=$(curl -sf --max-time 5 "$BASE/api/endpoints" 2>/dev/null)
if [ $? -eq 0 ]; then
    COUNT=$(echo "$EP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
    ok "/api/endpoints responded ($COUNT endpoint(s) known)"
else
    fail "/api/endpoints endpoint unreachable"
fi

# ── 7. WebSocket ──────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[7] WebSocket${NC}"
if command -v python3 &>/dev/null; then
    WS_RESULT=$(python3 - <<EOF 2>&1
import asyncio, sys
try:
    import websockets
except ImportError:
    print("websockets_not_installed")
    sys.exit(0)

async def test():
    try:
        async with websockets.connect("ws://$SERVER:$PORT/ws/alerts", open_timeout=5) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=3)
            print("ok:" + msg[:80])
    except Exception as e:
        print("fail:" + str(e))

asyncio.run(test())
EOF
)
    if echo "$WS_RESULT" | grep -q "^ok:"; then
        ok "WebSocket /ws/alerts connected and sending messages"
    elif echo "$WS_RESULT" | grep -q "websockets_not_installed"; then
        info "WebSocket check skipped (pip install websockets to enable)"
    else
        fail "WebSocket /ws/alerts: $WS_RESULT"
    fi
else
    info "WebSocket check skipped (python3 not found)"
fi

# ── 8. Database ───────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[8] Database${NC}"
DB_PATH="/opt/seceoknight/server/seceoknight.db"
if [ -f "$DB_PATH" ]; then
    DB_SIZE=$(du -sh "$DB_PATH" 2>/dev/null | cut -f1)
    ok "Database exists at $DB_PATH ($DB_SIZE)"
    TABLES=$(sqlite3 "$DB_PATH" ".tables" 2>/dev/null)
    info "Tables: $TABLES"
else
    info "Database not at $DB_PATH (may be at a different path — starts on first request)"
fi

# ── 9. Firewall ───────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[9] Firewall${NC}"
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    info "UFW: $UFW_STATUS"
    if sudo ufw status 2>/dev/null | grep -q "$PORT"; then
        ok "Port $PORT is allowed in UFW"
    else
        fail "Port $PORT is NOT in UFW rules — run: sudo ufw allow $PORT/tcp"
    fi
else
    info "UFW not installed"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "  Results: ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Action required — see FAIL items above.${NC}"
    echo "Full troubleshooting: docs/TROUBLESHOOTING.md"
    exit 1
else
    echo -e "${GREEN}All checks passed. Server is healthy.${NC}"
    exit 0
fi
