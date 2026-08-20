"""
database.py
SecEoKnight — SQLite database setup and helpers.
Tables: events, blocklist, endpoints
"""

import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "seceoknight.db")


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
            elif rtype == "regex":
                lines.append(f"re:{rval}")
            elif rtype in ("host", "prefix"):
                lines.append(rval)
        return "\n".join(lines)
    finally:
        conn.close()


def get_stats():
    """Return aggregated stats dict for the dashboard."""
    conn = get_connection()
    try:
        total      = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked    = conn.execute("SELECT COUNT(*) FROM events WHERE blocked=1").fetchone()[0]
        allowed    = conn.execute("SELECT COUNT(*) FROM events WHERE blocked=0").fetchone()[0]
        ai_phish   = conn.execute("SELECT COUNT(*) FROM events WHERE event_type='ai_phishing'").fetchone()[0]
        ai_malware = conn.execute("SELECT COUNT(*) FROM events WHERE event_type='ai_malware'").fetchone()[0]
        endpoints  = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status='active'").fetchone()[0]

        # Threats today
        today_blocked = conn.execute("""
            SELECT COUNT(*) FROM events
            WHERE blocked=1 AND date(timestamp_iso) = date('now')
        """).fetchone()[0]

        # Top blocked domains
        top_domains = conn.execute("""
            SELECT host, COUNT(*) as cnt FROM events
            WHERE blocked=1 AND host != ''
            GROUP BY host ORDER BY cnt DESC LIMIT 10
        """).fetchall()

        # Hourly activity (last 24h)
        hourly = conn.execute("""
            SELECT strftime('%Y-%m-%dT%H:00:00', timestamp_iso) as hour,
                   COUNT(*) as total,
                   SUM(blocked) as blocked
            FROM events
            WHERE timestamp >= strftime('%s', 'now', '-24 hours')
            GROUP BY hour ORDER BY hour
        """).fetchall()

        # Block type breakdown
        breakdown = conn.execute("""
            SELECT block_type, COUNT(*) as cnt FROM events
            WHERE blocked=1 AND block_type != ''
            GROUP BY block_type ORDER BY cnt DESC
        """).fetchall()

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
