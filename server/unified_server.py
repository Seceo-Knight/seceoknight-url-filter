"""
unified_server.py
SecEoKnight — Main FastAPI server.

Responsibilities:
  - Receive logs from 50 endpoints (via to-server.py)
  - Serve blocklist to all endpoint agent.py instances
  - Provide blocklist CRUD for dashboard
  - Run AI predictions (phishing + malware) for Chrome extensions
  - Store everything in SQLite
  - Push real-time alerts to dashboard via WebSocket

Start:
  uvicorn unified_server:app --host 0.0.0.0 --port 5001 --workers 4
"""

import json
import time
import sqlite3
import os
from contextlib import asynccontextmanager
from typing import Optional, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import database as db
import ai_engine as ai
from websocket_manager import ws_manager


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[SERVER] Starting SecEoKnight Unified Server...")
    db.init_db()
    ai.load_models()
    print("[SERVER] Ready ✓")
    yield
    print("[SERVER] Shutting down.")


app = FastAPI(
    title="SecEoKnight Unified API",
    description="Security server for URL filtering, AI threat detection, and SIEM data",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # restrict to dashboard IP in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════════
#  HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "healthy",
        "ai":     ai.get_status(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  BLOCKLIST  — consumed by agent.py on every endpoint
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/blocklist", response_class=PlainTextResponse, tags=["Blocklist"])
def get_blocklist_txt():
    """
    Returns the blocklist as plain text — same format as the original
    url_blocklist.txt so agent.py needs zero changes to its parser.

    Format:
      vid:VIDEOID        → block specific YouTube video
      hostname.com       → block entire domain
      hostname.com/path  → block URL prefix
      re:regex           → block by regex pattern
    """
    return db.get_blocklist_text()


# ── Blocklist CRUD (dashboard uses these) ─────────────────────────────────────

class BlocklistRule(BaseModel):
    rule_type:   str          # host | prefix | regex | vid
    rule_value:  str
    description: Optional[str] = ""
    added_by:    Optional[str] = "admin"


@app.get("/api/blocklist", tags=["Blocklist"])
def list_blocklist(active_only: bool = True):
    conn = db.get_connection()
    try:
        query = "SELECT * FROM blocklist"
        if active_only:
            query += " WHERE is_active=1"
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.post("/api/blocklist", tags=["Blocklist"], status_code=201)
def add_blocklist_rule(rule: BlocklistRule):
    valid_types = {"host", "prefix", "regex", "vid"}
    if rule.rule_type not in valid_types:
        raise HTTPException(400, f"rule_type must be one of {valid_types}")
    if not rule.rule_value.strip():
        raise HTTPException(400, "rule_value cannot be empty")

    conn = db.get_connection()
    try:
        # UPSERT: if rule was previously soft-deleted, reactivate it instead of erroring
        conn.execute("""
            INSERT INTO blocklist (rule_type, rule_value, description, added_by, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(rule_type, rule_value) DO UPDATE SET
                is_active   = 1,
                description = excluded.description,
                added_by    = excluded.added_by
        """, (rule.rule_type, rule.rule_value.strip(),
              rule.description, rule.added_by))
        conn.commit()
        return {"message": "Rule added", "rule": rule.model_dump()}
    finally:
        conn.close()


@app.delete("/api/blocklist/{rule_id}", tags=["Blocklist"])
def delete_blocklist_rule(rule_id: int):
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE blocklist SET is_active=0 WHERE id=?", (rule_id,)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        return {"message": f"Rule {rule_id} deactivated"}
    finally:
        conn.close()


@app.put("/api/blocklist/{rule_id}/restore", tags=["Blocklist"])
def restore_blocklist_rule(rule_id: int):
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE blocklist SET is_active=1 WHERE id=?", (rule_id,)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        return {"message": f"Rule {rule_id} restored"}
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  LOG RECEIVER  — called by to-server.py on every endpoint
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/logs", tags=["Logs"], status_code=202)
async def receive_log(payload: dict, request: Request):
    """
    Accepts a single log entry (JSON) from to-server.py or the Chrome
    extension. Saves to SQLite, updates endpoint record, and pushes
    high-severity events to the dashboard via WebSocket.
    """
    # Normalise event field
    event_type = payload.get("event", payload.get("event_type", "unknown"))
    blocked    = bool(payload.get("blocked", False))

    # Extract block_type from payload extras if present
    payload.setdefault("event_type", event_type)
    payload.setdefault("block_type", payload.get("block_type", ""))
    payload.setdefault("block_rule", payload.get("block_rule", ""))

    # Resolve the real endpoint IP. The Python agent self-reports a real
    # endpoint_ip (via a UDP-socket trick, see to-server.py), which we trust
    # as-is. The Chrome extension can't do that from JavaScript and sends the
    # placeholder "extension" instead -- for that case (and anything else
    # that didn't send a usable IP), fall back to request.client.host, the
    # real TCP-connection source IP as seen by uvicorn. Without this,
    # extension-originated events were permanently unattributable to any
    # specific machine, which is why per-endpoint AI-detection stats didn't
    # work.
    _skip = {"", "extension", "unknown"}
    reported_ip = payload.get("endpoint_ip", "") or payload.get("client_ip", "")
    if reported_ip in _skip or reported_ip.startswith("ext"):
        reported_ip = request.client.host if request.client else ""
        payload["endpoint_ip"] = reported_ip

    payload["raw_log"] = json.dumps(payload)

    # Save event
    db.insert_event(payload)

    # Update endpoint stats
    client_ip = reported_ip
    hostname  = payload.get("endpoint_hostname", "")
    if client_ip and client_ip not in _skip:
        db.upsert_endpoint(client_ip, hostname=hostname, blocked=blocked)

    # Push to dashboard if it's a threat
    HIGH_SEVERITY = {
        "blocked_watch", "blocked_api", "blocked_cdn_referer",
        "blocked_host", "blocked_prefix", "blocked_regex",
        "ai_phishing", "ai_malware",
    }
    if event_type in HIGH_SEVERITY:
        await ws_manager.broadcast({
            "type":       "alert",
            "event_type": event_type,
            "client_ip":  client_ip,
            "host":       payload.get("host", ""),
            "url":        payload.get("url", ""),
            "blocked":    blocked,
            "timestamp":  payload.get("timestamp_iso", ""),
            "threat_level": payload.get("threat_level", "High"),
        })

    return {"received": True}


class HeartbeatIn(BaseModel):
    ip: str
    hostname: str = ""
    agent_version: str = ""


@app.post("/api/heartbeat", tags=["Logs"], status_code=202)
def receive_heartbeat(hb: HeartbeatIn):
    """
    Lightweight periodic ping from to-server.py, sent independently of real
    browsing traffic. Keeps an idle-but-healthy endpoint's last_seen fresh
    so it doesn't get wrongly marked inactive, while an endpoint that's
    actually been uninstalled or crashed stops pinging and ages out to
    'inactive' on its own within a few minutes -- no manual DB edits needed.
    Also carries the endpoint script version so the dashboard can flag
    machines that need a redeploy after an agent-side fix.
    """
    db.heartbeat_endpoint(hb.ip, hb.hostname, hb.agent_version)
    return {"received": True}


# ═══════════════════════════════════════════════════════════════════════════════
#  EVENTS  — dashboard reads these
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/events", tags=["Dashboard"])
def get_events(
    limit:      int            = Query(100, ge=1, le=1000),
    offset:     int            = Query(0, ge=0),
    client_ip:  Optional[str]  = None,
    event_type: Optional[str]  = None,
    blocked:    Optional[bool] = None,
    host:       Optional[str]  = None,
    from_ts:    Optional[str]  = None,   # ISO datetime string
    to_ts:      Optional[str]  = None,
):
    conn = db.get_connection()
    try:
        where, params = [], []

        if client_ip:
            where.append("client_ip = ?");  params.append(client_ip)
        if event_type:
            where.append("event_type = ?"); params.append(event_type)
        if blocked is not None:
            where.append("blocked = ?");    params.append(1 if blocked else 0)
        if host:
            where.append("host LIKE ?");    params.append(f"%{host}%")
        if from_ts:
            where.append("timestamp_iso >= ?"); params.append(from_ts)
        if to_ts:
            where.append("timestamp_iso <= ?"); params.append(to_ts)

        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total  = conn.execute(
            f"SELECT COUNT(*) FROM events {clause}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM events {clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

        return {
            "total":  total,
            "limit":  limit,
            "offset": offset,
            "events": [dict(r) for r in rows],
        }
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  STATS  — dashboard analytics
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats", tags=["Dashboard"])
def get_stats(from_ts: Optional[str] = None):
    return db.get_stats(from_ts=from_ts)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS  — dashboard endpoint monitor tab
# ═══════════════════════════════════════════════════════════════════════════════

_ENDPOINT_STATUS_CASE = f"""
    CASE
        WHEN status = 'active'
             AND last_seen >= datetime('now', '-{db.STALE_THRESHOLD_MINUTES} minutes')
        THEN 'active'
        ELSE 'inactive'
    END AS status
"""


@app.get("/api/endpoints", tags=["Dashboard"])
def get_endpoints():
    conn = db.get_connection()
    try:
        rows = conn.execute(f"""
            SELECT id, ip, hostname, last_seen, total_requests, total_blocked,
                   agent_version, {_ENDPOINT_STATUS_CASE}
            FROM endpoints
            ORDER BY last_seen DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/endpoints/{ip}", tags=["Dashboard"])
def get_endpoint_detail(ip: str):
    conn = db.get_connection()
    try:
        ep = conn.execute(f"""
            SELECT id, ip, hostname, last_seen, total_requests, total_blocked,
                   agent_version, {_ENDPOINT_STATUS_CASE}
            FROM endpoints WHERE ip=?
        """, (ip,)).fetchone()
        if not ep:
            raise HTTPException(404, "Endpoint not found")

        # Match on endpoint_ip (the machine's real LAN IP, self-reported by
        # agent.py) rather than client_ip alone -- for locally-proxied
        # traffic client_ip is almost always 127.0.0.1 (the browser
        # connecting to mitmproxy on the same machine), so filtering on
        # client_ip alone would return nothing for a real endpoint.
        recent = conn.execute("""
            SELECT * FROM events WHERE endpoint_ip=? OR client_ip=?
            ORDER BY timestamp DESC LIMIT 50
        """, (ip, ip)).fetchall()

        return {
            "endpoint": dict(ep),
            "recent_events": [dict(r) for r in recent],
        }
    finally:
        conn.close()


@app.get("/api/my-stats", tags=["Dashboard"])
def get_my_stats(request: Request):
    """
    "This machine's own" stats, for the Chrome extension popup -- NOT the
    fleet-wide /api/stats. That endpoint aggregates across every deployed
    endpoint with no time or machine filter (its default is genuinely
    all-time, not "last 24h" -- see get_stats() in database.py), which made
    the extension popup show numbers indistinguishable from the whole
    company's activity rather than the one machine it's running on.

    Identifies "this machine" from request.client.host (the real TCP source
    IP as seen by uvicorn) rather than trusting a client-supplied IP, since
    a browser extension can't reliably self-report its own LAN address and
    a self-reported value could be spoofed anyway.
    """
    caller_ip = request.client.host if request.client else ""
    conn = db.get_connection()
    try:
        ep = conn.execute(f"""
            SELECT id, ip, hostname, last_seen, total_requests, total_blocked,
                   agent_version, {_ENDPOINT_STATUS_CASE}
            FROM endpoints WHERE ip=?
        """, (caller_ip,)).fetchone()

        ai_phish = conn.execute(
            "SELECT COUNT(*) FROM events WHERE (endpoint_ip=? OR client_ip=?) AND event_type='ai_phishing'",
            (caller_ip, caller_ip)
        ).fetchone()[0]
        ai_malware = conn.execute(
            "SELECT COUNT(*) FROM events WHERE (endpoint_ip=? OR client_ip=?) AND event_type='ai_malware'",
            (caller_ip, caller_ip)
        ).fetchone()[0]

        if not ep:
            # This machine hasn't sent any agent traffic yet (e.g. extension
            # installed before the Windows services, or first run) -- return
            # zeros instead of a 404 so the popup still renders cleanly.
            return {
                "ip": caller_ip, "hostname": "", "status": "unknown",
                "total_requests": 0, "total_blocked": 0,
                "ai_phishing": ai_phish, "ai_malware": ai_malware,
            }

        result = dict(ep)
        result["ai_phishing"] = ai_phish
        result["ai_malware"]  = ai_malware
        return result
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  AI PREDICTIONS  — Chrome extension calls these
# ═══════════════════════════════════════════════════════════════════════════════

class PhishingRequest(BaseModel):
    url: str


class MalwareRequest(BaseModel):
    image: str            # base64 encoded image
    model: Optional[str] = "CNN"


@app.post("/predict/phishing", tags=["AI"])
async def predict_phishing(req: PhishingRequest, request: Request):
    result = ai.predict_phishing(req.url)

    # If phishing detected, log it and alert dashboard
    if result.get("phishing"):
        # The Chrome extension can't reliably know its own LAN IP from
        # JavaScript, so it doesn't send one -- previously this left
        # client_ip as an empty string, meaning AI-detected phishing events
        # could never be attributed back to the machine that triggered them
        # (no per-endpoint breakdown, no way to answer "did MY machine see
        # anything?"). request.client.host is the real TCP-connection source
        # IP as seen by uvicorn -- since the extension and agent both talk
        # to port 5001 directly (not through Nginx), this correctly reflects
        # the calling endpoint's real LAN IP.
        caller_ip = request.client.host if request.client else ""
        event = {
            "event_type":   "ai_phishing",
            "event":        "ai_phishing",
            "timestamp":    time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "url":          req.url,
            "host":         req.url.split("/")[2] if "//" in req.url else req.url,
            "blocked":      True,
            "block_type":   "ai_phishing",
            "ai_score":     result.get("score"),
            "threat_level": "High",
            "client_ip":    caller_ip,
            "endpoint_ip":  caller_ip,
        }
        db.insert_event(event)
        await ws_manager.broadcast({
            "type":       "alert",
            "event_type": "ai_phishing",
            "url":        req.url,
            "score":      result.get("score"),
            "confidence": result.get("confidence"),
            "threat_level": "High",
        })

    return result


@app.get("/predict/phishing", tags=["AI"])
async def predict_phishing_get(request: Request, url: str = Query(...)):
    return await predict_phishing(PhishingRequest(url=url), request)


@app.post("/predict/malware", tags=["AI"])
async def predict_malware(req: MalwareRequest, request: Request):
    result = ai.predict_malware(req.image, req.model)

    # If malware detected, log it and alert dashboard
    if result.get("is_malware"):
        top = result.get("top_prediction", {})
        caller_ip = request.client.host if request.client else ""
        event = {
            "event_type":    "ai_malware",
            "event":         "ai_malware",
            "timestamp":     time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "blocked":       True,
            "block_type":    "ai_malware",
            "ai_model":      result.get("model_used", ""),
            "malware_family": top.get("malware_type", ""),
            "ai_score":      top.get("confidence"),
            "threat_level":  result.get("threat_level", "High"),
            "client_ip":     caller_ip,
            "endpoint_ip":   caller_ip,
        }
        db.insert_event(event)
        await ws_manager.broadcast({
            "type":          "alert",
            "event_type":    "ai_malware",
            "malware_family": top.get("malware_type", ""),
            "confidence":    top.get("confidence"),
            "threat_level":  result.get("threat_level"),
            "model_used":    result.get("model_used"),
        })

    return result


@app.get("/models/status", tags=["AI"])
def models_status():
    return ai.get_status()


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET  — real-time alerts to dashboard
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send welcome ping
        await ws_manager.send_to(websocket, {
            "type":    "connected",
            "message": "SecEoKnight alert stream connected",
        })
        # Keep connection alive — client sends pings
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await ws_manager.send_to(websocket, {"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ═══════════════════════════════════════════════════════════════════════════════
#  INCIDENT ALERTS  — dashboard incident tab
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/alerts", tags=["Dashboard"])
def get_alerts(
    limit:        int           = Query(50, ge=1, le=500),
    acknowledged: Optional[bool] = None,
):
    """Returns high-severity events for the Incident Alerts tab."""
    conn = db.get_connection()
    try:
        threat_types = (
            "blocked_watch", "blocked_api", "blocked_cdn_referer",
            "blocked_host", "blocked_prefix", "blocked_regex",
            "ai_phishing", "ai_malware",
        )
        placeholders = ",".join("?" * len(threat_types))
        rows = conn.execute(f"""
            SELECT * FROM events
            WHERE event_type IN ({placeholders})
            ORDER BY timestamp DESC LIMIT ?
        """, list(threat_types) + [limit]).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    # IMPORTANT: Must use workers=1 — the in-memory WebSocketManager
    # is not shared across processes. With multiple workers, only 1/N
    # dashboard clients receive alerts. Async uvicorn with 1 worker
    # handles 50+ concurrent endpoints with no performance issue.
    uvicorn.run(
        "unified_server:app",
        host="0.0.0.0",
        port=5001,
        workers=1,
        reload=False,
    )
