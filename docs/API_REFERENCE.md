# API Reference

All endpoints exposed by the SecEoKnight unified server.

Base URL: `http://YOUR_SERVER_IP:5001`  (or `http://YOUR_SERVER_IP` if Nginx is configured)

---

## Authentication

Every endpoint except `GET /health` expects an `X-API-Key` header. The key is
generated once by `install.sh` and saved to `server/.env` — it's printed at
the end of the install/reinstall output.

```
X-API-Key: <the key from server/.env>
```

**Grace period, by design.** A missing or wrong key is *not* rejected by
default — the request is still allowed through, and the server logs a
`[AUTH] WARNING` (throttled to once per 5 minutes) so you can tell it's
happening. This is deliberate: it lets you roll the key out to every
agent.py, to-server.py, malware_watcher.py, the Chrome extension, and the
SIEM dashboard's backend on your own schedule, instead of an instant
breaking change across every already-deployed machine.

Once you've updated every client and the `[AUTH] WARNING` lines have stopped
appearing in `journalctl -u seceoknight`, set in `server/.env`:

```
SECEOKNIGHT_REQUIRE_API_KEY=true
```

then `sudo systemctl restart seceoknight`. From that point, requests without
a valid key get a `401 Unauthorized`.

The WebSocket endpoint (`/ws/alerts`) can't use a header the same way — pass
the key as a query parameter instead: `ws://YOUR_SERVER_IP:5001/ws/alerts?api_key=...`.

---

## System

### GET /health
Returns server and AI model status.

**Response:**
```json
{
  "status": "healthy",
  "ai": {
    "phishing_model": "loaded",
    "malware_models": {"CNN": "loaded", "ViT": "loaded", "1D-CNN-LSTM": "loaded"},
    "available_malware_models": ["CNN", "ViT", "1D-CNN-LSTM"]
  }
}
```

---

## Blocklist

### GET /blocklist
Returns blocklist as plain text — consumed by `agent.py` on every endpoint.

**Response (plain text):**
```
youtube.com/watch
re:.*\.exe$
vid:dQw4w9WgXcQ
gambling-site.com
```

### GET /api/blocklist
Returns blocklist as JSON — for the dashboard Policy Management tab.

**Query params:**
- `active_only` (bool, default true)

**Response:**
```json
[
  {
    "id": 1,
    "rule_type": "host",
    "rule_value": "gambling-site.com",
    "description": "Gambling",
    "added_by": "admin",
    "is_active": 1,
    "created_at": "2024-01-01T10:00:00"
  }
]
```

### POST /api/blocklist
Add a new blocklist rule.

**Body:**
```json
{
  "rule_type": "host",
  "rule_value": "gambling-site.com",
  "description": "Block gambling",
  "added_by": "admin"
}
```

**rule_type values:**
- `host` — block entire domain (e.g. `gambling-site.com`)
- `prefix` — block URL prefix (e.g. `youtube.com/shorts`)
- `regex` — block by regex pattern (e.g. `.*torrent.*`)
- `vid` — block specific YouTube video ID (e.g. `dQw4w9WgXcQ`)

**Response (201):**
```json
{"message": "Rule added", "rule": {...}}
```

### DELETE /api/blocklist/{id}
Deactivate a blocklist rule (soft delete — keeps history).

**Response:**
```json
{"message": "Rule 5 deactivated"}
```

### PUT /api/blocklist/{id}/restore
Re-activate a previously deactivated rule.

---

## Log Receiver

### POST /logs
Receives a log entry from `to-server.py` running on each endpoint.

**Body:** JSON log entry from agent.py (any keys accepted)

**Required fields:**
```json
{
  "timestamp": 1700000000.0,
  "timestamp_iso": "2024-01-01T10:00:00",
  "event": "blocked_host",
  "client_ip": "192.168.1.101",
  "host": "gambling-site.com",
  "url": "https://gambling-site.com/page",
  "blocked": true,
  "block_type": "host"
}
```

**Response (202):**
```json
{"received": true}
```

---

## Events

### GET /api/events
Returns paginated list of security events. Used by Network Activity and Audit Logs tabs.

**Query params:**
- `limit` (int, default 100, max 1000)
- `offset` (int, default 0)
- `client_ip` (string) — filter by endpoint IP
- `event_type` (string) — e.g. `blocked_host`, `ai_phishing`
- `blocked` (bool) — true = blocked only, false = allowed only
- `host` (string) — partial match on domain
- `from_ts` (ISO datetime string)
- `to_ts` (ISO datetime string)

**Response:**
```json
{
  "total": 1500,
  "limit": 100,
  "offset": 0,
  "events": [
    {
      "id": 42,
      "timestamp": 1700000000.0,
      "timestamp_iso": "2024-01-01T10:00:00",
      "event_type": "blocked_host",
      "client_ip": "192.168.1.101",
      "host": "gambling-site.com",
      "url": "https://gambling-site.com/",
      "method": "GET",
      "blocked": 1,
      "block_type": "host",
      "block_rule": "gambling-site.com",
      "ai_score": null,
      "threat_level": null,
      "user_agent": "Mozilla/5.0..."
    }
  ]
}
```

**Event types:**
- `blocked_watch` — YouTube video ID blocked
- `blocked_api` — YouTube API call blocked
- `blocked_cdn_referer` — CDN request blocked via referer
- `blocked_host` — domain blocked
- `blocked_prefix` — URL prefix blocked
- `blocked_regex` — regex rule matched
- `allowed` — request allowed through
- `ai_phishing` — phishing detected by AI
- `ai_malware` — malware detected by AI

---

## Stats

### GET /api/stats
Returns aggregated statistics for dashboard charts and KPI cards.

**Query params:**
- `from_ts` (ISO datetime string, optional) — scopes all volume metrics (totals, top domains,
  hourly activity, block-type breakdown) to events at or after this time. Omit it and every
  field below is **all-time** (every event ever recorded), not a rolling window — the one
  exception is `hourly_activity`, which defaults to the last 24h specifically when `from_ts`
  is omitted. Used to power the 12h/24h/3d/7d/30d/60d/90d time-range toggle on the dashboard.

**Response:**
```json
{
  "total_requests": 15420,
  "total_blocked": 342,
  "total_allowed": 15078,
  "ai_phishing": 12,
  "ai_malware": 3,
  "active_endpoints": 47,
  "today_blocked": 28,
  "top_blocked_domains": [
    {"host": "gambling-site.com", "cnt": 89},
    {"host": "torrent-site.net", "cnt": 45}
  ],
  "hourly_activity": [
    {"hour": "2024-01-01T09:00:00", "total": 120, "blocked": 5}
  ],
  "block_type_breakdown": [
    {"block_type": "host", "cnt": 200},
    {"block_type": "ai_phishing", "cnt": 12}
  ]
}
```

---

## Endpoints

### GET /api/endpoints
Returns all known endpoints with status. Used by Endpoint Monitor tab.

`status` is computed live from `last_seen` — `active` if a heartbeat or event arrived within
the last 3 minutes (`STALE_THRESHOLD_MINUTES` in `database.py`), `inactive` otherwise. It is
not a stored flag, so it self-corrects if an endpoint goes offline without a clean shutdown.

**Response:**
```json
[
  {
    "id": 1,
    "ip": "192.168.1.101",
    "hostname": "DESKTOP-A1B2C3",
    "last_seen": "2024-01-01T10:05:00",
    "total_requests": 520,
    "total_blocked": 8,
    "agent_version": "1.1.0",
    "status": "active"
  }
]
```

### GET /api/endpoints/{ip}
Returns detail for a single endpoint plus its 50 most recent events.

**Response:**
```json
{
  "endpoint": {
    "id": 1,
    "ip": "192.168.1.101",
    "hostname": "DESKTOP-A1B2C3",
    "last_seen": "2024-01-01T10:05:00",
    "total_requests": 520,
    "total_blocked": 8,
    "agent_version": "1.1.0",
    "status": "active"
  },
  "recent_events": [
    {
      "id": 42,
      "timestamp_iso": "2024-01-01T10:04:12",
      "event_type": "blocked_host",
      "host": "gambling-site.com",
      "url": "https://gambling-site.com/",
      "blocked": 1,
      "block_type": "host"
    }
  ]
}
```
> `recent_events` matches on `endpoint_ip` (the machine's real LAN IP, self-reported by the
> agent) OR `client_ip`. For locally-proxied traffic (mitmproxy running on the same machine as
> the browser), `client_ip` is almost always `127.0.0.1` — `endpoint_ip` is what actually
> identifies the source machine.

### POST /api/heartbeat
Sent every 60 seconds by `to-server.py` on each endpoint, independent of any browsing traffic.
This is what keeps `active`/`inactive` status accurate even when a machine is idle — not
something the dashboard needs to call directly.

**Body:**
```json
{
  "ip": "192.168.1.101",
  "hostname": "DESKTOP-A1B2C3",
  "agent_version": "1.1.0"
}
```
`hostname` and `agent_version` are optional but recommended — omitting `hostname` falls back to
upserting by IP alone.

**Response (202):**
```json
{"received": true}
```

### GET /api/my-stats
Returns stats for **the calling machine only** — used by the Chrome extension popup. Unlike
`/api/stats` (fleet-wide, all-time by default), this identifies "which machine" from the
request's own source IP (`request.client.host`), not a client-supplied value — a browser
extension can't reliably know its own LAN IP from JavaScript, and a self-reported value could
be spoofed anyway.

**Response:**
```json
{
  "id": 1,
  "ip": "192.168.1.101",
  "hostname": "DESKTOP-A1B2C3",
  "last_seen": "2024-01-01T10:05:00",
  "total_requests": 520,
  "total_blocked": 8,
  "agent_version": "1.1.0",
  "status": "active",
  "ai_phishing": 3,
  "ai_malware": 0
}
```
If the calling machine hasn't sent any agent traffic yet, returns `total_requests`/`total_blocked`
as `0` and `status: "unknown"` instead of a 404, so the popup still renders cleanly on a
fresh install.

---

## Alerts

### GET /api/alerts
Returns high-severity events for the Incident Alerts tab.

**Query params:**
- `limit` (int, default 50)

**Response:** Array of event objects (same structure as /api/events) filtered to threat events only.

---

## AI Predictions

### POST /predict/phishing
Check if a URL is phishing. Called by Chrome extension.

**Body:**
```json
{"url": "http://paypa1-secure-login.xyz/verify"}
```

**Response:**
```json
{
  "phishing": true,
  "score": 0.9234,
  "confidence": "High",
  "threat_level": "High",
  "whitelisted": false,
  "source": "safe_browsing",
  "error": null
}
```

`source` explains what actually made the decision:
- `whitelist` — matched `LEGITIMATE_DOMAINS`, never reached any model
- `safe_browsing` — Google Safe Browsing confirmed this as a known threat (only present
  if `SECEOKNIGHT_SAFE_BROWSING_KEY` is configured — see README "Reducing AI Phishing
  False Positives")
- `local_model` — the local BiLSTM scored it ≥0.995 and Safe Browsing either isn't
  configured or hasn't indexed this URL either way
- `local_model_unconfirmed` — the local model scored it high, but Safe Browsing checked
  and came back clean, so `phishing` is forced to `false` — shown for admin visibility,
  not treated as a real detection

### GET /predict/phishing?url=...
Same as POST but via query param.

### POST /predict/malware
Analyse an image for malware patterns. Called by Chrome extension on downloads.

**Body:**
```json
{
  "image": "base64encodedimagedata...",
  "model": "CNN"
}
```

**model options:** `CNN`, `ViT`, `1D-CNN-LSTM`

**Response:**
```json
{
  "is_malware": true,
  "threat_level": "High",
  "model_used": "CNN",
  "predictions": [
    {"malware_type": "Allaple.A", "confidence": 0.97, "percentage": "97.00%"}
  ],
  "top_prediction": {"malware_type": "Allaple.A", "confidence": 0.97},
  "diagnostics": {
    "top_confidence": 0.97,
    "confidence_diff": 0.82,
    "normalized_entropy": 0.12
  },
  "error": null
}
```

### GET /models/status
Returns loaded AI model status.

---

## WebSocket

### WS /ws/alerts
Real-time alert stream for the dashboard.

**Connect:**
```javascript
const ws = new WebSocket("ws://YOUR_SERVER_IP:5001/ws/alerts?api_key=YOUR_KEY");
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(alert);
};
// Keep alive
setInterval(() => ws.send("ping"), 30000);
```

**Message types received:**

Connection confirmation:
```json
{"type": "connected", "message": "SecEoKnight alert stream connected"}
```

Threat alert:
```json
{
  "type": "alert",
  "event_type": "blocked_host",
  "client_ip": "192.168.1.101",
  "host": "gambling-site.com",
  "url": "https://gambling-site.com/",
  "blocked": true,
  "timestamp": "2024-01-01T10:00:00",
  "threat_level": "High"
}
```

AI phishing alert:
```json
{
  "type": "alert",
  "event_type": "ai_phishing",
  "url": "http://fake-bank.xyz/login",
  "score": 0.94,
  "confidence": "High",
  "threat_level": "High"
}
```

AI malware alert:
```json
{
  "type": "alert",
  "event_type": "ai_malware",
  "malware_family": "Allaple.A",
  "confidence": 0.97,
  "threat_level": "High",
  "model_used": "CNN"
}
```

Keepalive pong:
```json
{"type": "pong"}
```
