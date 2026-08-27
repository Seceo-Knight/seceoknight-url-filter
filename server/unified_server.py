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
import hashlib
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import database as db
import ai_engine as ai
from websocket_manager import ws_manager
from auth import verify_api_key, check_ws_api_key


# ── Background: agent-disconnect alerts ───────────────────────────────────────
# Runs independently of anyone having the dashboard open -- a machine going
# offline at 2am should have an alert waiting when someone checks in the
# morning, not just a "last seen" timestamp nobody happened to notice.
async def _disconnect_watcher():
    while True:
        try:
            for ep in db.get_stale_active_endpoints():
                name = ep.get("hostname") or ep.get("ip")
                alert_id = db.create_alert(
                    "agent_disconnect",
                    f"{name} hasn't checked in since {ep.get('last_seen')} (was active)",
                    severity="high",
                    hostname=ep.get("hostname"),
                )
                if alert_id:
                    await ws_manager.broadcast({"type": "alert", "alert_type": "agent_disconnect",
                                                 "hostname": ep.get("hostname"), "id": alert_id})
        except Exception as e:
            print(f"[SERVER] disconnect watcher error: {e}")
        await asyncio.sleep(60)


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[SERVER] Starting SecEoKnight Unified Server...")
    db.init_db()
    ai.load_models()
    watcher_task = asyncio.create_task(_disconnect_watcher())
    print("[SERVER] Ready ✓")
    yield
    watcher_task.cancel()
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
def get_blocklist_txt(_auth: bool = Depends(verify_api_key)):
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
def list_blocklist(active_only: bool = True, _auth: bool = Depends(verify_api_key)):
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


async def _alert_blocklist_edit(action: str, rule_type: str, rule_value: str, added_by: str = "admin"):
    """Every blocklist mutation gets a low-noise alert (dedup'd per type, not
    per rule, so a burst of edits doesn't flood the Alerts page) plus a
    live push so it shows up without a manual refresh."""
    msg = f"{added_by} {action} {rule_type} rule: {rule_value}"
    alert_id = db.create_alert("blocklist_edit", msg, severity="low", dedupe_minutes=2)
    if alert_id:
        await ws_manager.broadcast({"type": "alert", "alert_type": "blocklist_edit",
                                     "message": msg, "id": alert_id})


@app.post("/api/blocklist", tags=["Blocklist"], status_code=201)
async def add_blocklist_rule(rule: BlocklistRule, _auth: bool = Depends(verify_api_key)):
    valid_types = {"host", "prefix", "regex", "vid", "channel"}
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
        db.record_blocklist_history("add", rule.rule_type, rule.rule_value.strip(),
                                     rule.description, rule.added_by)
        await _alert_blocklist_edit("added", rule.rule_type, rule.rule_value.strip(), rule.added_by)
        return {"message": "Rule added", "rule": rule.model_dump()}
    finally:
        conn.close()


@app.delete("/api/blocklist/{rule_id}", tags=["Blocklist"])
async def delete_blocklist_rule(rule_id: int, _auth: bool = Depends(verify_api_key)):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT rule_type, rule_value FROM blocklist WHERE id=?", (rule_id,)).fetchone()
        cur = conn.execute(
            "UPDATE blocklist SET is_active=0 WHERE id=?", (rule_id,)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        if row:
            db.record_blocklist_history("remove", row["rule_type"], row["rule_value"])
            await _alert_blocklist_edit("removed", row["rule_type"], row["rule_value"])
        return {"message": f"Rule {rule_id} deactivated"}
    finally:
        conn.close()


@app.put("/api/blocklist/{rule_id}/restore", tags=["Blocklist"])
async def restore_blocklist_rule(rule_id: int, _auth: bool = Depends(verify_api_key)):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT rule_type, rule_value FROM blocklist WHERE id=?", (rule_id,)).fetchone()
        cur = conn.execute(
            "UPDATE blocklist SET is_active=1 WHERE id=?", (rule_id,)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Rule not found")
        if row:
            db.record_blocklist_history("restore", row["rule_type"], row["rule_value"])
            await _alert_blocklist_edit("restored", row["rule_type"], row["rule_value"])
        return {"message": f"Rule {rule_id} restored"}
    finally:
        conn.close()


# ── Blocklist history (versioning / diff / revert) ────────────────────────────
# One entry per add/remove/restore/revert, newest first. Every change to the
# blocklist -- via any of the endpoints above -- is captured automatically,
# so this needs no extra wiring beyond what's already in place.

class RevertRequest(BaseModel):
    added_by: Optional[str] = "admin"


@app.get("/api/blocklist-history", tags=["Blocklist"])
def get_blocklist_history(limit: int = 200, _auth: bool = Depends(verify_api_key)):
    return db.list_blocklist_history(limit=limit)


@app.get("/api/blocklist-history/{history_id}/snapshot", tags=["Blocklist"])
def get_blocklist_history_snapshot(history_id: int, _auth: bool = Depends(verify_api_key)):
    """Full rule text for one history entry -- used to render a line-by-line
    diff against another entry on the frontend."""
    snap = db.get_blocklist_history_snapshot(history_id)
    if not snap:
        raise HTTPException(404, "History entry not found")
    return snap


@app.post("/api/blocklist-history/{history_id}/revert", tags=["Blocklist"])
async def revert_blocklist_history(history_id: int, body: RevertRequest = RevertRequest(),
                                    _auth: bool = Depends(verify_api_key)):
    """Reconcile the live blocklist to exactly match a past snapshot. Nothing
    is deleted from history -- the revert itself is logged as a new entry."""
    result = db.revert_blocklist_to(history_id, added_by=body.added_by or "admin")
    if result is None:
        raise HTTPException(404, "History entry not found")
    await _alert_blocklist_edit("reverted to", "snapshot", f"#{history_id}", body.added_by or "admin")
    return {"message": f"Reverted to snapshot #{history_id}", **result}


# ── Alerts ──────────────────────────────────────────────────────────────────
# agent_disconnect (background watcher above) / blocklist_fetch_failure
# (reported by agent.py via the normal /logs pipeline) / blocklist_edit
# (above) / after_hours_browsing (see office-hours section).

@app.get("/api/alerts", tags=["Alerts"])
def get_alerts(resolved: Optional[bool] = None, limit: int = 200, _auth: bool = Depends(verify_api_key)):
    return db.list_alerts(resolved=resolved, limit=limit)


@app.put("/api/alerts/{alert_id}/resolve", tags=["Alerts"])
def put_resolve_alert(alert_id: int, resolved_by: str = "admin", _auth: bool = Depends(verify_api_key)):
    ok = db.resolve_alert(alert_id, resolved_by=resolved_by)
    if not ok:
        raise HTTPException(404, "Alert not found")
    return {"message": f"Alert {alert_id} resolved"}


# ── After-hours detection ──────────────────────────────────────────────────
# Office hours are opt-in (disabled by default -- see DEFAULT_OFFICE_HOURS in
# database.py) so turning on this feature never silently starts flagging
# traffic until an admin deliberately configures it.

class OfficeHoursConfig(BaseModel):
    enabled:  bool
    timezone: str = "Asia/Kolkata"
    days:     dict
    ranges:   List[dict]


@app.get("/api/settings/office-hours", tags=["Settings"])
def get_office_hours_setting(_auth: bool = Depends(verify_api_key)):
    return db.get_office_hours()


@app.put("/api/settings/office-hours", tags=["Settings"])
def put_office_hours_setting(config: OfficeHoursConfig, _auth: bool = Depends(verify_api_key)):
    db.set_office_hours(config.model_dump())
    return {"message": "Office hours saved"}


@app.get("/api/logs/after-hours", tags=["Logs"])
def get_after_hours_logs(days: int = 7, _auth: bool = Depends(verify_api_key)):
    return db.get_after_hours_stats(days=days)


# ═══════════════════════════════════════════════════════════════════════════════
#  LOG RECEIVER  — called by to-server.py on every endpoint
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/logs", tags=["Logs"], status_code=202)
async def receive_log(payload: dict, request: Request, _auth: bool = Depends(verify_api_key)):
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

    # agent.py emits this via the normal log pipeline (not a separate
    # channel) when it exhausts its retries fetching the blocklist -- an
    # agent that can't fetch fresh rules is quietly running stale ones,
    # which is worth an admin's attention.
    if event_type == "blocklist_fetch_failed":
        hostname = payload.get("endpoint_hostname", "")
        alert_id = db.create_alert(
            "blocklist_fetch_failure",
            f"{hostname or reported_ip} failed to fetch the blocklist: {payload.get('note', 'unknown error')}",
            severity="high", hostname=hostname, dedupe_minutes=30,
        )
        if alert_id:
            await ws_manager.broadcast({"type": "alert", "alert_type": "blocklist_fetch_failure",
                                         "hostname": hostname, "id": alert_id})

    # after-hours: insert_event() already computed & stored this per-event
    # (see database.py's is_after_hours) -- here we just turn it into a
    # (deduped, per-hostname) alert so it doesn't require anyone to go
    # looking at the After Hours page to notice.
    if payload.get("blocked") and db.is_after_hours(payload.get("timestamp_iso", "")):
        hostname = payload.get("endpoint_hostname", "")
        alert_id = db.create_alert(
            "after_hours_browsing",
            f"{hostname or reported_ip} was blocked browsing {payload.get('host', '')} outside office hours",
            severity="medium", hostname=hostname, dedupe_minutes=60,
        )
        if alert_id:
            await ws_manager.broadcast({"type": "alert", "alert_type": "after_hours_browsing",
                                         "hostname": hostname, "id": alert_id})

    return {"received": True}


class HeartbeatIn(BaseModel):
    ip: str
    hostname: str = ""
    agent_version: str = ""


@app.post("/api/heartbeat", tags=["Logs"], status_code=202)
def receive_heartbeat(hb: HeartbeatIn, _auth: bool = Depends(verify_api_key)):
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
    _auth:      bool           = Depends(verify_api_key),
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
def get_stats(from_ts: Optional[str] = None, _auth: bool = Depends(verify_api_key)):
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
def get_endpoints(_auth: bool = Depends(verify_api_key)):
    conn = db.get_connection()
    try:
        rows = conn.execute(f"""
            SELECT e.id, e.ip, e.hostname, e.last_seen, e.total_requests, e.total_blocked,
                   e.agent_version, {_ENDPOINT_STATUS_CASE},
                   COALESCE(ac.mode, 'enforce') AS mode
            FROM endpoints e
            LEFT JOIN agent_config ac ON ac.hostname = e.hostname
            ORDER BY e.last_seen DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/endpoints/{ip}", tags=["Dashboard"])
def get_endpoint_detail(ip: str, _auth: bool = Depends(verify_api_key)):
    conn = db.get_connection()
    try:
        ep = conn.execute(f"""
            SELECT e.id, e.ip, e.hostname, e.last_seen, e.total_requests, e.total_blocked,
                   e.agent_version, {_ENDPOINT_STATUS_CASE},
                   COALESCE(ac.mode, 'enforce') AS mode
            FROM endpoints e
            LEFT JOIN agent_config ac ON ac.hostname = e.hostname
            WHERE e.ip=?
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


# ── Per-agent blocking mode ────────────────────────────────────────────────
# enforce (default) / monitor (log-only) / disabled (pure passthrough).
# agent.py polls its own mode every RELOAD_INTERVAL alongside the blocklist
# (see agent.py's _load_blocklist) so a mode change takes effect within ~30s
# with no restart. Keyed by hostname, not IP -- see the schema comment in
# database.py for why.

class AgentConfigUpdate(BaseModel):
    hostname:   str
    mode:       str            # enforce | monitor | disabled
    updated_by: Optional[str] = "admin"


@app.get("/api/agents/config", tags=["Agents"])
def get_agent_config(hostname: str, _auth: bool = Depends(verify_api_key)):
    """Polled by agent.py itself -- returns just this one agent's mode."""
    return {"hostname": hostname, "mode": db.get_agent_mode(hostname)}


@app.get("/api/agents/config/all", tags=["Agents"])
def get_all_agent_configs(_auth: bool = Depends(verify_api_key)):
    """Used by the dashboard fleet view -- every hostname that has an
    explicit (non-default) mode set."""
    return db.list_agent_configs()


@app.put("/api/agents/config", tags=["Agents"])
def put_agent_config(body: AgentConfigUpdate, _auth: bool = Depends(verify_api_key)):
    if body.mode not in db.VALID_AGENT_MODES:
        raise HTTPException(400, f"mode must be one of {sorted(db.VALID_AGENT_MODES)}")
    db.set_agent_mode(body.hostname, body.mode, body.updated_by or "admin")
    return {"message": f"{body.hostname} set to {body.mode}"}


# ── Agent self-update ──────────────────────────────────────────────────────
# Solves the "manual machine-by-machine PowerShell rollout" problem: every
# deployed agent.py polls its own SHA-256 alongside the blocklist/config
# every RELOAD_INTERVAL. If it differs from what's on this server, it
# downloads the new copy, overwrites itself on disk, and exits -- NSSM
# (configured with AppRestartDelay in setup.ps1) restarts the mitmdump
# service automatically, which loads the new agent.py. No PowerShell or
# manual per-machine action needed to ship an agent update.
_AGENT_PY_PATH = os.path.join(os.path.dirname(__file__), "..", "endpoint", "agent.py")


@app.get("/agent-update/hash", tags=["Agents"])
def get_agent_update_hash(_auth: bool = Depends(verify_api_key)):
    try:
        with open(_AGENT_PY_PATH, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        raise HTTPException(500, "agent.py not found on server -- check deployment layout")
    return {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


@app.get("/agent-update/download", response_class=PlainTextResponse, tags=["Agents"])
def download_agent_update(_auth: bool = Depends(verify_api_key)):
    try:
        with open(_AGENT_PY_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(500, "agent.py not found on server -- check deployment layout")


@app.get("/api/my-stats", tags=["Dashboard"])
def get_my_stats(request: Request, _auth: bool = Depends(verify_api_key)):
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
async def predict_phishing(req: PhishingRequest, request: Request, _auth: bool = Depends(verify_api_key)):
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
            "threat_level": result.get("threat_level", "High"),
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
            "threat_level": result.get("threat_level", "High"),
        })

    return result


@app.get("/predict/phishing", tags=["AI"])
async def predict_phishing_get(request: Request, url: str = Query(...), _auth: bool = Depends(verify_api_key)):
    return await predict_phishing(PhishingRequest(url=url), request, _auth)


@app.post("/predict/malware", tags=["AI"])
async def predict_malware(req: MalwareRequest, request: Request, _auth: bool = Depends(verify_api_key)):
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
def models_status(_auth: bool = Depends(verify_api_key)):
    return ai.get_status()


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET  — real-time alerts to dashboard
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    # Header-based FastAPI dependencies don't apply cleanly to WebSocket
    # routes, so the key is passed as ?api_key=... on the connection URL
    # instead and checked manually before accepting the connection.
    supplied_key = websocket.query_params.get("api_key", "")
    ws_client_ip = websocket.client.host if websocket.client else "unknown"
    if not check_ws_api_key(supplied_key, ws_client_ip):
        await websocket.close(code=1008)
        return
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
    _auth:        bool           = Depends(verify_api_key),
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
