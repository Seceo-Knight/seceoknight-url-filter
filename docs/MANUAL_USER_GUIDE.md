# SecEoKnight — Manual User Guide

This guide is written for **IT administrators and security staff** who will use the SecEoKnight
system day-to-day. No programming knowledge required.

---

## What Is SecEoKnight?

SecEoKnight is a **network security system** that does three things:

1. **Blocks dangerous and unwanted websites** on every Windows computer in your office
2. **Detects phishing and malware** using AI — even if a site is new and not yet in any blocklist
3. **Shows you everything in your SIEM dashboard** — who visited what, what was blocked, and live threat alerts

Think of it as a security guard that watches all 50 computers at once, 24/7.

---

## System Overview

```
  50 Windows Endpoints          Security Server         Your SIEM Dashboard
  ─────────────────────         ──────────────          ────────────────────
  Chrome Extension ──AI check──▶
  mitmproxy ────────────────────▶ FastAPI + SQLite ───▶ Live alerts (WebSocket)
  to-server.py ─────log events──▶ REST API          ───▶ Events, stats, blocklist
                                      ▲
                    blocklist updated─┘  (every 30 seconds)
```

- Each endpoint runs **mitmproxy** (intercepts browser traffic) + **to-server.py** (sends logs)
- The **security server** (Ubuntu, IP 192.168.1.63) stores everything and serves the blocklist
- The **Chrome extension** adds AI detection directly in the browser

---

## Daily Operations

### How to Block a Website

**From the SIEM Dashboard** (Policy Management tab):
1. Click **"Add Rule"**
2. Choose rule type:
   - **Host** — block an entire website (e.g. `facebook.com`)
   - **Prefix** — block a specific section (e.g. `youtube.com/shorts`)
   - **Regex** — block by pattern (e.g. `.*torrent.*`)
   - **Video ID** — block a specific YouTube video
3. Enter the value and click **Save**

The rule is **live within 30 seconds** — no restart needed on any machine.

**Via command line on the server:**
```bash
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"host","rule_value":"facebook.com","description":"Social media block"}'
```

---

### How to Unblock a Website

**From the SIEM Dashboard** (Policy Management tab):
1. Find the rule in the list
2. Click the **Delete / Deactivate** button

The rule is deactivated (not permanently deleted — you can restore it later).

**Via command line:**
```bash
# First find the rule ID
curl http://localhost:5001/api/blocklist

# Then deactivate it (replace 5 with actual ID)
curl -X DELETE http://localhost:5001/api/blocklist/5
```

To restore a deactivated rule:
```bash
curl -X PUT http://localhost:5001/api/blocklist/5/restore
```

---

### How to View Security Events

**From the SIEM Dashboard** (Network Activity tab):

- Filter by **endpoint IP** to see one machine's traffic
- Filter by **Event Type** to see only blocks, or only AI detections
- Filter by **date range** to audit a specific period
- Export as needed

**Via command line on the server:**
```bash
# Last 20 events
curl "http://localhost:5001/api/events?limit=20"

# Only blocked events from one machine
curl "http://localhost:5001/api/events?blocked=true&client_ip=192.168.1.105"

# All phishing detections
curl "http://localhost:5001/api/events?event_type=ai_phishing"
```

---

### How to Check Server Health

```bash
# One command — checks everything
bash /opt/seceoknight/scripts/health_check.sh
```

Expected output: all `[PASS]` items. If something fails, the script tells you exactly what to fix.

---

### How to Check If an Endpoint Is Connected

**From the SIEM Dashboard** (Endpoint Monitor tab):
- Each endpoint appears in the list within 60 seconds of starting
- Status shows **active** / **inactive**
- Last seen timestamp tells you when it last sent data

**Via command line:**
```bash
curl http://localhost:5001/api/endpoints
```

---

### How to View Real-Time Alerts

**From the SIEM Dashboard** (Incident Alerts tab):
- New threats appear live via WebSocket — no page refresh needed
- Alerts include: what was blocked, which endpoint, what time

```bash
# Last 50 high-severity alerts
curl http://localhost:5001/api/alerts
```

---

### How to Check AI Model Status

```bash
curl http://localhost:5001/health
```

Response:
```json
{
  "status": "healthy",
  "ai": {
    "phishing_model": "loaded",
    "malware_models": {
      "CNN": "loaded",
      "ViT": "loaded",
      "1D-CNN-LSTM": "loaded"
    }
  }
}
```

If any model shows `"not_loaded"`, see the Troubleshooting section below.

---

## Understanding Event Types

| Event Type | What It Means |
|---|---|
| `blocked_host` | A domain in the blocklist was blocked |
| `blocked_prefix` | A URL prefix rule matched |
| `blocked_regex` | A pattern rule matched |
| `blocked_watch` | A specific YouTube video was blocked |
| `blocked_api` | YouTube internal API call for a blocked video was stopped |
| `blocked_cdn_referer` | CDN request for a blocked YouTube video was stopped |
| `allowed` | Request passed through (not blocked) |
| `ai_phishing` | Chrome extension detected phishing via AI |
| `ai_malware` | Chrome extension detected malware in a downloaded file |

---

## Understanding Threat Levels

| Level | Meaning |
|---|---|
| **High** | Confirmed block — rule matched or AI very confident (>95%) |
| **Medium** | AI flagged with moderate confidence |
| **Low** | Suspicious but uncertain |
| **Safe** | Passed all checks |

---

## Server Management

### Start / Stop / Restart the Server

```bash
sudo systemctl start seceoknight        # Start
sudo systemctl stop seceoknight         # Stop
sudo systemctl restart seceoknight      # Restart (after config changes)
sudo systemctl status seceoknight       # Check if it's running
```

### View Server Logs (Live)

```bash
sudo journalctl -u seceoknight -f
```

Press `Ctrl+C` to stop watching.

### View Last 100 Log Lines

```bash
sudo journalctl -u seceoknight -n 100
```

### Update the Server from GitHub

```bash
cd /opt/seceoknight
git pull
sudo systemctl restart seceoknight
```

---

## Database Queries (Advanced)

The database is at `/opt/seceoknight/server/seceoknight.db`.

```bash
# Open the database
sqlite3 /opt/seceoknight/server/seceoknight.db

# Count total events
SELECT COUNT(*) FROM events;

# How many blocks today?
SELECT COUNT(*) FROM events WHERE blocked=1 AND date(timestamp_iso)=date('now');

# Top 10 blocked domains
SELECT host, COUNT(*) as cnt FROM events WHERE blocked=1
GROUP BY host ORDER BY cnt DESC LIMIT 10;

# Events from a specific endpoint
SELECT timestamp_iso, event_type, url FROM events
WHERE client_ip='192.168.1.105' ORDER BY timestamp DESC LIMIT 20;

# Exit
.quit
```

---

## Adding an Endpoint (New Computer)

1. On the new Windows machine, **open PowerShell as Administrator**
2. Run:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Download and run the setup script:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/seceoknight-url-filter/main/endpoint/setup.ps1" -OutFile "$env:TEMP\setup.ps1"
   & "$env:TEMP\setup.ps1"
   ```
4. Follow the on-screen instructions — the script guides you step by step
5. When prompted, install the mitmproxy certificate (this is required)

The new endpoint appears in the dashboard within 60 seconds.

Full instructions: [ENDPOINT_SETUP.md](ENDPOINT_SETUP.md)

---

## Removing an Endpoint

On the Windows machine, open PowerShell as Administrator and run:
```powershell
# Stop and remove Windows Services
sc.exe stop  SecEoKnight-Proxy
sc.exe stop  SecEoKnight-Logger
C:\SecEoKnight\nssm.exe remove SecEoKnight-Proxy  confirm
C:\SecEoKnight\nssm.exe remove SecEoKnight-Logger confirm

# Remove machine-wide proxy
netsh winhttp reset proxy

# Disable browser proxy
$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0

# Remove files
Remove-Item -Recurse -Force C:\SecEoKnight
Remove-Item -Recurse -Force C:\url-block -ErrorAction SilentlyContinue
```

---

## Troubleshooting

### Server Is Not Responding

```bash
# Check if it's running
sudo systemctl status seceoknight

# If it's stopped, start it
sudo systemctl start seceoknight

# Check for errors
sudo journalctl -u seceoknight -n 50
```

### An Endpoint Is Not Showing in Dashboard

1. Check both services are running — open PowerShell as Administrator and run:
   ```powershell
   sc.exe query SecEoKnight-Proxy
   sc.exe query SecEoKnight-Logger
   ```
   Both should show `STATE: 4 RUNNING`. If stopped, run `sc.exe start SecEoKnight-Proxy` / `sc.exe start SecEoKnight-Logger`
2. Check the server IP in `C:\SecEoKnight\to-server.py` — should be `192.168.1.63`
3. Check the server is reachable: on the endpoint, open PowerShell and run:
   ```powershell
   Test-NetConnection -ComputerName 192.168.1.63 -Port 5001
   ```
   Should show `TcpTestSucceeded : True`

### Websites Are Not Being Blocked

1. Check the blocklist has the rule: `curl http://192.168.1.63/blocklist`
2. Wait 30 seconds — endpoints refresh every 30 seconds
3. Check the proxy is active on the endpoint: Settings → Network → Proxy

### AI Model Shows "not_loaded"

The phishing model needs to be trained. On the server:
```bash
cd /opt/seceoknight
source venv/bin/activate
python3 scripts/train_phishing_model.py
sudo systemctl restart seceoknight
```
This takes 5–15 minutes. Run it once.

### Nginx Is Not Working

```bash
sudo nginx -t                    # Test config — should say "test is successful"
sudo systemctl status nginx      # Check if nginx is running
sudo systemctl restart nginx     # Restart if needed
sudo tail -f /var/log/nginx/error.log   # Check for errors
```

---

## Quick Reference Card

| Task | Command / Location |
|---|---|
| Block a site | Dashboard → Policy Management → Add Rule |
| Unblock a site | Dashboard → Policy Management → Deactivate |
| View events | Dashboard → Network Activity |
| View live alerts | Dashboard → Incident Alerts |
| Check endpoint status | Dashboard → Endpoint Monitor |
| Health check | `bash /opt/seceoknight/scripts/health_check.sh` |
| Restart server | `sudo systemctl restart seceoknight` |
| View logs | `sudo journalctl -u seceoknight -f` |
| Update from GitHub | `cd /opt/seceoknight && git pull && sudo systemctl restart seceoknight` |
| Database location | `/opt/seceoknight/server/seceoknight.db` |
| Server API | `http://192.168.1.63:5001` or `http://192.168.1.63` (via Nginx) |

---

## Contacts and Support

- Server IP: **192.168.1.63**
- API port: **5001** (direct) / **80** (via Nginx)
- Log path on endpoints: `C:\url-block\logs.json`
- Agent path on endpoints: `C:\SecEoKnight\`
- Server install path: `/opt/seceoknight/`

Full technical docs:
- [SERVER_SETUP.md](SERVER_SETUP.md) — initial server deployment
- [ENDPOINT_SETUP.md](ENDPOINT_SETUP.md) — adding/managing endpoints
- [API_REFERENCE.md](API_REFERENCE.md) — all API endpoints for dashboard developers
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common errors and fixes
