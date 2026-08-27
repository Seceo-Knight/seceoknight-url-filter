"""
database.py
SecEoKnight — SQLite database setup and helpers.
Tables: events, blocklist, endpoints
"""

import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "seceoknight.db")

# An endpoint is considered "active" only if it has sent a heartbeat or real
# traffic within this window. Heartbeats fire every 60s (see to-server.py),
# so 3 minutes tolerates a couple of missed beats without flapping.
STALE_THRESHOLD_MINUTES = 3


def get_connection():
    """Return a SQLite connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cur = conn.cursor()

    # ── Events ────────────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       REAL,
            timestamp_iso   TEXT,
            event_type      TEXT,        -- blocked_watch / blocked_host / allowed / ai_phishing / ai_malware …
            endpoint_ip     TEXT,        -- LAN IP of the Windows endpoint that generated this event
            endpoint_hostname TEXT,      -- hostname of the Windows endpoint
            client_ip       TEXT,
            client_port     INTEGER,
            host            TEXT,
            url             TEXT,
            method          TEXT,
            blocked         INTEGER DEFAULT 0,   -- 1 = blocked, 0 = allowed
            block_type      TEXT,        -- host / prefix / regex / vid / ai_phishing / ai_malware
            block_rule      TEXT,        -- the rule that matched
            ai_score        REAL,        -- phishing confidence 0-1
            ai_model        TEXT,        -- CNN / ViT / 1D-CNN-LSTM
            malware_family  TEXT,        -- Adialer.C, Allaple.A …
            threat_level    TEXT,        -- High / Medium / Low / Safe
            user_agent      TEXT,
            raw_log         TEXT,        -- full JSON string from agent
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_client_ip  ON events(client_ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_blocked    ON events(blocked)")

    # Migrate existing DBs — add columns that didn't exist in earlier versions
    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(events)").fetchall()}
    if "endpoint_ip" not in existing_cols:
        cur.execute("ALTER TABLE events ADD COLUMN endpoint_ip TEXT DEFAULT ''")
    if "endpoint_hostname" not in existing_cols:
        cur.execute("ALTER TABLE events ADD COLUMN endpoint_hostname TEXT DEFAULT ''")
    if "quarantine_path" not in existing_cols:
        cur.execute("ALTER TABLE events ADD COLUMN quarantine_path TEXT DEFAULT ''")

    # ── Blocklist ─────────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type   TEXT NOT NULL,   -- host / prefix / regex / vid
            rule_value  TEXT NOT NULL,
            description TEXT,
            added_by    TEXT DEFAULT 'admin',
            is_active   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_rule ON blocklist(rule_type, rule_value)")

    # ── Blocklist history ────────────────────────────────────────────────────
    # One row per mutation (add / remove / restore / revert). snapshot_text is
    # the FULL resulting blocklist (same format get_blocklist_text() returns)
    # captured right after the change -- that's what makes "revert to here"
    # possible without needing to replay every action from the beginning.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocklist_history (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            action         TEXT NOT NULL,   -- add / remove / restore / revert
            rule_type      TEXT,
            rule_value     TEXT,
            description    TEXT,
            added_by       TEXT DEFAULT 'admin',
            snapshot_text  TEXT NOT NULL,
            created_at     TEXT DEFAULT (datetime('now'))
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_history_created ON blocklist_history(created_at)")

    # ── Per-agent blocking mode ──────────────────────────────────────────────
    # Keyed by hostname (not IP) -- agent.py always knows its own hostname via
    # socket.gethostname(), whereas the IP the *server* sees an agent under
    # can shift with DHCP and isn't something agent.py can look up about
    # itself. 'enforce' (default, block+log) / 'monitor' (log-only, don't
    # actually block -- useful for staged rollouts) / 'disabled' (pure
    # passthrough, don't even log as blocked).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_config (
            hostname    TEXT PRIMARY KEY,
            mode        TEXT NOT NULL DEFAULT 'enforce',
            updated_at  TEXT DEFAULT (datetime('now')),
            updated_by  TEXT DEFAULT 'admin'
        )
    """)

    # ── Endpoints ─────────────────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT UNIQUE NOT NULL,
            hostname        TEXT,
            last_seen       TEXT,
            total_requests  INTEGER DEFAULT 0,
            total_blocked   INTEGER DEFAULT 0,
            agent_version   TEXT,
            status          TEXT DEFAULT 'active'   -- active / inactive
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialised at:", DB_PATH)


# ── Helper functions ──────────────────────────────────────────────────────────

def insert_event(data: dict):
    """Insert one event row from a parsed log dict."""
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO events
                (timestamp, timestamp_iso, event_type, endpoint_ip, endpoint_hostname,
                 client_ip, client_port,
                 host, url, method, blocked, block_type, block_rule,
                 ai_score, ai_model, malware_family, threat_level,
                 user_agent, quarantine_path, raw_log)
            VALUES
                (:timestamp, :timestamp_iso, :event_type, :endpoint_ip, :endpoint_hostname,
                 :client_ip, :client_port,
                 :host, :url, :method, :blocked, :block_type, :block_rule,
                 :ai_score, :ai_model, :malware_family, :threat_level,
                 :user_agent, :quarantine_path, :raw_log)
        """, {
            "timestamp":         data.get("timestamp", time.time()),
            "timestamp_iso":     data.get("timestamp_iso", ""),
            "event_type":        data.get("event", data.get("event_type", "unknown")),
            "endpoint_ip":       data.get("endpoint_ip", ""),
            "endpoint_hostname": data.get("endpoint_hostname", ""),
            "client_ip":         data.get("client_ip", ""),
            "client_port":       data.get("client_port"),
            "host":              data.get("host", ""),
            "url":               data.get("url", ""),
            "method":            data.get("method", ""),
            "blocked":           1 if data.get("blocked") else 0,
            "block_type":        data.get("block_type", ""),
            "block_rule":        data.get("block_rule", data.get("rule", "")),
            "ai_score":          data.get("ai_score"),
            "ai_model":          data.get("ai_model", ""),
            "malware_family":    data.get("malware_family", ""),
            "threat_level":      data.get("threat_level", ""),
            "user_agent":        data.get("user_agent", ""),
            "quarantine_path":   data.get("quarantine_path", ""),
            "raw_log":           data.get("raw_log", ""),
        })
        conn.commit()
    finally:
        conn.close()


def upsert_endpoint(ip: str, hostname: str = '', blocked: bool = False):
    """
    Update or insert endpoint record.

    Deduplication strategy:
      - If a hostname is known, use hostname as the stable identity key.
        The IP field is updated in-place so DHCP IP changes don't create
        duplicate endpoint rows.
      - If no hostname is available, fall back to IP-based deduplication.
    """
    conn = get_connection()
    try:
        inc_blocked = 1 if blocked else 0

        if hostname:
            # Check whether we already know this hostname (regardless of IP)
            existing = conn.execute(
                "SELECT id FROM endpoints WHERE hostname = ?", (hostname,)
            ).fetchone()
            if existing:
                # Hostname matched — update IP (handles DHCP changes) and stats
                conn.execute("""
                    UPDATE endpoints SET
                        ip             = ?,
                        last_seen      = datetime('now'),
                        total_requests = total_requests + 1,
                        total_blocked  = total_blocked + ?,
                        status         = 'active'
                    WHERE hostname = ?
                """, (ip, inc_blocked, hostname))
                conn.commit()
                return

        # No hostname, or hostname not yet seen — dedup on IP
        conn.execute("""
            INSERT INTO endpoints (ip, hostname, last_seen, total_requests, total_blocked)
            VALUES (?, ?, datetime('now'), 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen      = datetime('now'),
                total_requests = total_requests + 1,
                total_blocked  = total_blocked + ?,
                status         = 'active',
                hostname       = CASE WHEN ? != '' THEN ? ELSE hostname END
        """, (ip, hostname, inc_blocked, inc_blocked, hostname, hostname))
        conn.commit()
    finally:
        conn.close()


def heartbeat_endpoint(ip: str, hostname: str = '', agent_version: str = ''):
    """
    Lightweight periodic ping (independent of real browsing traffic).
    Refreshes last_seen/status/agent_version only -- does NOT touch
    total_requests or total_blocked, since a heartbeat isn't a browsing
    event. This is what lets an idle-but-running endpoint stay 'active'
    while one that's been uninstalled or crashed naturally ages out to
    'inactive' on its own.
    """
    conn = get_connection()
    try:
        if hostname:
            existing = conn.execute(
                "SELECT id FROM endpoints WHERE hostname = ?", (hostname,)
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE endpoints SET
                        ip            = ?,
                        last_seen     = datetime('now'),
                        status        = 'active',
                        agent_version = CASE WHEN ? != '' THEN ? ELSE agent_version END
                    WHERE hostname = ?
                """, (ip, agent_version, agent_version, hostname))
                conn.commit()
                return

        conn.execute("""
            INSERT INTO endpoints (ip, hostname, last_seen, total_requests, total_blocked, status, agent_version)
            VALUES (?, ?, datetime('now'), 0, 0, 'active', ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen     = datetime('now'),
                status        = 'active',
                hostname      = CASE WHEN ? != '' THEN ? ELSE hostname END,
                agent_version = CASE WHEN ? != '' THEN ? ELSE agent_version END
        """, (ip, hostname, agent_version, hostname, hostname, agent_version, agent_version))
        conn.commit()
    finally:
        conn.close()


def get_blocklist_text():
    """Return blocklist in the plain-text format agent.py expects."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT rule_type, rule_value FROM blocklist WHERE is_active=1"
        ).fetchall()
        lines = []
        for row in rows:
            rtype, rval = row["rule_type"], row["rule_value"]
            if rtype == "vid":
                lines.append(f"vid:{rval}")
            elif rtype == "channel":
                lines.append(f"channel:{rval}")
            elif rtype == "regex":
                lines.append(f"re:{rval}")
            elif rtype in ("host", "prefix"):
                lines.append(rval)
        return "\n".join(lines)
    finally:
        conn.close()


def _parse_blocklist_text(text):
    """Inverse of get_blocklist_text() -- turn plain-text blocklist lines back
    into (rule_type, rule_value) pairs, using the exact same rules agent.py's
    own parser uses (vid: / re: / contains "/" -> prefix / else -> host)."""
    pairs = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("vid:"):
            pairs.append(("vid", line.split(":", 1)[1].strip()))
        elif line.startswith("channel:"):
            pairs.append(("channel", line.split(":", 1)[1].strip()))
        elif line.startswith("re:"):
            pairs.append(("regex", line.split(":", 1)[1].strip()))
        elif "/" in line:
            pairs.append(("prefix", line))
        else:
            pairs.append(("host", line))
    return pairs


def record_blocklist_history(action, rule_type=None, rule_value=None,
                              description=None, added_by="admin"):
    """Snapshot the *current* (post-change) blocklist into history. Call this
    right after committing an add/remove/restore/revert so snapshot_text
    reflects the new state."""
    conn = get_connection()
    try:
        snapshot = get_blocklist_text()
        conn.execute("""
            INSERT INTO blocklist_history (action, rule_type, rule_value, description, added_by, snapshot_text)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (action, rule_type, rule_value, description, added_by, snapshot))
        conn.commit()
    finally:
        conn.close()


def list_blocklist_history(limit=200):
    """Return recent history entries, newest first, with a lightweight
    added/removed line-count vs. the immediately preceding snapshot so the
    UI can show a "+2 / -1" style summary without fetching every snapshot."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, action, rule_type, rule_value, description, added_by, snapshot_text, created_at
            FROM blocklist_history ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        rows = [dict(r) for r in rows]
        for i, row in enumerate(rows):
            # rows are newest-first, so the "previous" snapshot in time is the NEXT item in this list
            prev_snapshot = rows[i + 1]["snapshot_text"] if i + 1 < len(rows) else ""
            cur_lines  = set(l for l in row["snapshot_text"].splitlines() if l.strip())
            prev_lines = set(l for l in prev_snapshot.splitlines() if l.strip())
            row["added_count"]   = len(cur_lines - prev_lines)
            row["removed_count"] = len(prev_lines - cur_lines)
            row["rule_count"]    = len(cur_lines)
            del row["snapshot_text"]   # keep the list payload light; fetched separately for diff/revert
        return rows
    finally:
        conn.close()


def get_blocklist_history_snapshot(history_id):
    """Full snapshot_text for a single history row -- used for the diff view
    and as the source of truth for revert."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, snapshot_text, created_at FROM blocklist_history WHERE id=?",
            (history_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def revert_blocklist_to(history_id, added_by="admin"):
    """Reconcile the live `blocklist` table so its active rules exactly match
    a past snapshot, then log the revert itself as a new history entry (the
    audit trail is append-only -- nothing is ever deleted from history)."""
    conn = get_connection()
    try:
        target_row = conn.execute(
            "SELECT snapshot_text FROM blocklist_history WHERE id=?", (history_id,)
        ).fetchone()
        if not target_row:
            return None
        target_pairs = set(_parse_blocklist_text(target_row["snapshot_text"]))

        active_rows = conn.execute(
            "SELECT rule_type, rule_value FROM blocklist WHERE is_active=1"
        ).fetchall()
        active_pairs = set((r["rule_type"], r["rule_value"]) for r in active_rows)

        to_deactivate = active_pairs - target_pairs
        to_activate   = target_pairs - active_pairs

        for rtype, rval in to_deactivate:
            conn.execute(
                "UPDATE blocklist SET is_active=0 WHERE rule_type=? AND rule_value=?",
                (rtype, rval)
            )
        for rtype, rval in to_activate:
            conn.execute("""
                INSERT INTO blocklist (rule_type, rule_value, description, added_by, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(rule_type, rule_value) DO UPDATE SET
                    is_active = 1, added_by = excluded.added_by
            """, (rtype, rval, f"restored from history #{history_id}", added_by))
        conn.commit()
    finally:
        conn.close()

    record_blocklist_history(
        action="revert",
        description=f"Reverted to snapshot #{history_id}",
        added_by=added_by,
    )
    return {"deactivated": len(to_deactivate), "activated": len(to_activate)}


VALID_AGENT_MODES = {"enforce", "monitor", "disabled"}


def get_agent_mode(hostname: str) -> str:
    """A hostname with no row yet is implicitly 'enforce' -- the default and
    the only mode that existed before this feature, so upgrading the server
    never silently changes existing agents' behavior."""
    if not hostname:
        return "enforce"
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT mode FROM agent_config WHERE hostname=?", (hostname,)
        ).fetchone()
        return row["mode"] if row else "enforce"
    finally:
        conn.close()


def set_agent_mode(hostname: str, mode: str, updated_by: str = "admin"):
    if mode not in VALID_AGENT_MODES:
        raise ValueError(f"mode must be one of {VALID_AGENT_MODES}")
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO agent_config (hostname, mode, updated_by, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(hostname) DO UPDATE SET
                mode = excluded.mode, updated_by = excluded.updated_by, updated_at = datetime('now')
        """, (hostname, mode, updated_by))
        conn.commit()
    finally:
        conn.close()


def list_agent_configs():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT hostname, mode, updated_at, updated_by FROM agent_config").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats(from_ts: str = None):
    """
    Return aggregated stats dict for the dashboard.

    @param from_ts: optional ISO cutoff ("YYYY-MM-DDTHH:MM:SS", matching the
        format agent.py writes to timestamp_iso). When given, every volume
        metric below is scoped to events at or after this time -- this is
        what powers the dashboard's 12h/24h/3d/7d time-range picker.
        'today_blocked' is intentionally always "today" regardless of range.
    """
    conn = get_connection()
    try:
        time_clause = "timestamp_iso >= ?" if from_ts else "1=1"
        time_params = (from_ts,) if from_ts else ()

        total      = conn.execute(f"SELECT COUNT(*) FROM events WHERE {time_clause}", time_params).fetchone()[0]
        blocked    = conn.execute(f"SELECT COUNT(*) FROM events WHERE {time_clause} AND blocked=1", time_params).fetchone()[0]
        allowed    = conn.execute(f"SELECT COUNT(*) FROM events WHERE {time_clause} AND blocked=0", time_params).fetchone()[0]
        ai_phish   = conn.execute(f"SELECT COUNT(*) FROM events WHERE {time_clause} AND event_type='ai_phishing'", time_params).fetchone()[0]
        ai_malware = conn.execute(f"SELECT COUNT(*) FROM events WHERE {time_clause} AND event_type='ai_malware'", time_params).fetchone()[0]
        endpoints  = conn.execute(f"""
            SELECT COUNT(*) FROM endpoints
            WHERE status='active' AND last_seen >= datetime('now', '-{STALE_THRESHOLD_MINUTES} minutes')
        """).fetchone()[0]

        # Threats today (always "today", independent of the selected range)
        today_blocked = conn.execute("""
            SELECT COUNT(*) FROM events
            WHERE blocked=1 AND date(timestamp_iso) = date('now')
        """).fetchone()[0]

        # Top blocked domains (scoped to range)
        top_domains = conn.execute(f"""
            SELECT host, COUNT(*) as cnt FROM events
            WHERE {time_clause} AND blocked=1 AND host != ''
            GROUP BY host ORDER BY cnt DESC LIMIT 10
        """, time_params).fetchall()

        # Hourly activity -- scoped to range if given, else last 24h default
        if from_ts:
            hourly = conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp_iso) as hour,
                       COUNT(*) as total,
                       SUM(blocked) as blocked
                FROM events
                WHERE timestamp_iso >= ?
                GROUP BY hour ORDER BY hour
            """, (from_ts,)).fetchall()
        else:
            hourly = conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp_iso) as hour,
                       COUNT(*) as total,
                       SUM(blocked) as blocked
                FROM events
                WHERE timestamp >= strftime('%s', 'now', '-24 hours')
                GROUP BY hour ORDER BY hour
            """).fetchall()

        # Block type breakdown (scoped to range)
        breakdown = conn.execute(f"""
            SELECT block_type, COUNT(*) as cnt FROM events
            WHERE {time_clause} AND blocked=1 AND block_type != ''
            GROUP BY block_type ORDER BY cnt DESC
        """, time_params).fetchall()

        return {
            "total_requests":  total,
            "total_blocked":   blocked,
            "total_allowed":   allowed,
            "ai_phishing":     ai_phish,
            "ai_malware":      ai_malware,
            "active_endpoints": endpoints,
            "today_blocked":   today_blocked,
            "top_blocked_domains": [dict(r) for r in top_domains],
            "hourly_activity": [dict(r) for r in hourly],
            "block_type_breakdown": [dict(r) for r in breakdown],
        }
    finally:
        conn.close()
