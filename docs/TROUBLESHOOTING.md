# Troubleshooting Guide

---

## Server Issues

### Server won't start — "ModuleNotFoundError"

```bash
# Make sure you're in the virtual environment
source /opt/seceoknight/venv/bin/activate
pip install -r requirements.txt
```

### Server won't start — "Address already in use"

```bash
sudo lsof -i :5001
sudo kill -9 <PID>
sudo systemctl restart seceoknight
```

### TensorFlow import error

```bash
# Check Python version (TF 2.16 needs Python 3.9-3.11)
python3 --version

# Reinstall TensorFlow
pip uninstall tensorflow -y
pip install tensorflow==2.16.1
```

### AI models show "not_loaded"

- Check model files exist: `ls /opt/seceoknight/server/models/phishing/`
- You need: `bilstm_domain_model.h5` and `tokenizer.pkl`
- Check server logs: `sudo journalctl -u seceoknight -n 50`

### Database errors

```bash
# Check database exists
ls -la /opt/seceoknight/server/seceoknight.db

# Reset database (WARNING: deletes all data)
rm /opt/seceoknight/server/seceoknight.db
sudo systemctl restart seceoknight
```

---

## Endpoint Issues

### agent.py not blocking anything

1. Check the proxy service is running: `Get-Service SecEoKnight-Proxy` — must show `Running`
   (agent.py and mitmproxy run inside this one Windows Service now, no terminal window to look for)
2. Check proxy is set in Windows: Settings → Network → Proxy
3. Check blocklist: `curl http://YOUR_SERVER_IP:5001/blocklist`
4. Check the service's log file: `C:\SecEoKnight\Logs\proxy.log` (or `proxy-error.log`)

### Endpoint not appearing in dashboard

1. Check the logger service is running: `Get-Service SecEoKnight-Logger` — must show `Running`
   (to-server.py runs as this Windows Service; there's no terminal window to check anymore)
2. Endpoint status is heartbeat-driven — even with zero browsing traffic, the endpoint should
   still show `active` as long as `SecEoKnight-Logger` is running and can reach the server.
   If it shows `inactive`, the heartbeat POST to `/api/heartbeat` isn't getting through — check
   step 3 below.
3. Check server is reachable from endpoint:
   ```powershell
   Test-NetConnection -ComputerName 192.168.1.63 -Port 5001
   ```
4. Check the log file exists: `C:\url-block\logs.json`

### HTTPS sites showing SSL errors

Certificate not installed correctly, or the cert the browser trusts doesn't match the one the
running proxy service presents (a `confdir` mismatch — this used to be the most common cause
of "internet stopped working after setup" on this project).

1. Open PowerShell as Administrator and check:
   ```powershell
   Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*mitmproxy*" }
   ```
   If nothing prints, the cert isn't installed — re-run `setup.ps1` as Administrator.
2. If a cert IS listed but HTTPS still fails, confirm `SecEoKnight-Proxy`'s NSSM `AppParameters`
   include `--set confdir="C:\SecEoKnight\mitm-confdir"` (same path used to generate the cert
   above) — check with:
   ```powershell
   & "C:\SecEoKnight\nssm.exe" get SecEoKnight-Proxy AppParameters
   ```
   If `confdir` is missing or points somewhere else, the service is presenting a *different*
   CA than the one you trusted. Fix it with `nssm set SecEoKnight-Proxy AppParameters "..."`
   (see `endpoint/setup.ps1` for the exact string) and restart the service.
3. As a last resort, uninstall (see `docs/ENDPOINT_SETUP.md`'s removal steps) and re-run
   `setup.ps1` fresh — current versions of the script keep certificate generation and the
   service's `confdir` in sync automatically, so this class of bug shouldn't recur.

### Blocklist not updating on endpoint

agent.py refreshes the blocklist every 30 seconds. Wait 30 seconds after adding a rule.

To verify the blocklist is being fetched, look at the mitmproxy terminal — you should see a log line: `agent: blocklist loaded — vids=X prefixes=Y hosts=Z`

### Dashboard shows a blocked alert (e.g. "blocked_watch") but the site/video still loads in the browser

This is almost always **QUIC/HTTP3 bypassing the proxy**, not a bug in the blocklist logic. Chrome
and Edge use QUIC (HTTP/3, sent over UDP) for Google properties like `youtube.com` and
`googlevideo.com` by default. QUIC is its own transport — it does not go through the PAC-configured
proxy at all, so any request sent over QUIC never reaches `agent.py` and can't be blocked, even
though the initial page load (which did go through the proxy over normal TCP/TLS) shows up
correctly as a blocked event.

**Fix:** disable QUIC in the browser via the official enterprise policy. `setup.ps1` does this
automatically for new installs (Step 11B). For a machine that was set up before this fix existed,
run this once as Administrator, then fully close and reopen Chrome/Edge (check Task Manager —
lingering `chrome.exe`/`msedge.exe` processes keep old QUIC connections alive):

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "QuicAllowed" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "QuicAllowed" -Value 0 -Type DWord
```

This is a known, industry-wide limitation of any TLS-inspecting proxy (not specific to this tool) —
every enterprise proxy vendor (Zscaler, Netskope, Fortinet, etc.) requires the same QUIC-disable
step for the same reason.

### to-server.py shows "Cannot reach server"

- Server might be down: `sudo systemctl status seceoknight`
- Wrong IP: check `SERVER_IP` in `to-server.py`
- Firewall: `sudo ufw status` — port 5001 must be allowed

### Invoke-WebRequest to GitHub fails with "Blocked by SecEoKnight — Regex rule matched"

The default blocklist includes a regex rule blocking script/executable downloads
(`.ps1`, `.exe`, `.bat`, etc.) — once mitmproxy is active on a machine, that rule also
blocks the machine's own future updates (`setup.ps1`, `agent.py`, etc.), since those are
served from the same domains. Fixed at the source in `agent.py` — `raw.githubusercontent.com`,
`github.com`, `codeload.github.com`, and `objects.githubusercontent.com` are always allowed
regardless of blocklist rules. If you're on an older `agent.py` that predates this fix,
either update it (see "Useful Server Commands" → updating endpoints) or work around it
one time with:
```powershell
$wc = New-Object System.Net.WebClient
$wc.Proxy = $null
$wc.DownloadFile("https://raw.githubusercontent.com/YOUR_ORG/seceoknight-url-filter/main/endpoint/setup.ps1", "$env:TEMP\setup.ps1")
```

### Server API requests getting a 401 Unauthorized

The server's API key enforcement is on (`SECEOKNIGHT_REQUIRE_API_KEY=true` in `server/.env`)
and the caller isn't sending a valid `X-API-Key` header. Check: the Chrome extension's
Settings panel has the current key, `agent.py`/`to-server.py`/`malware_watcher.py` have
`API_KEY` set to the current key, and the SIEM dashboard backend's `.env` has
`URL_FILTER_API_KEY` set. The current key is in `server/.env` on the server (`SECEOKNIGHT_API_KEY=`).
See [docs/API_REFERENCE.md](API_REFERENCE.md#authentication) for the full rollout process.

---

## Dashboard Issues

### WebSocket keeps disconnecting

Add a keepalive ping every 30 seconds in your dashboard:
```javascript
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send("ping");
  }
}, 30000);
```

### /api/events returns empty

No events have been received yet. Confirm:
1. At least one endpoint is running and connected
2. Some traffic has flowed through the proxy
3. `sqlite3 /opt/seceoknight/server/seceoknight.db "SELECT COUNT(*) FROM events;"`

### CORS errors in browser

The server allows all origins by default. If you've restricted it, add your dashboard origin in `unified_server.py`:
```python
allow_origins=["http://192.168.1.200", "http://your-dashboard-ip"]
```

---

## Checking Logs

```bash
# Server logs (live)
sudo journalctl -u seceoknight -f

# Server logs (last 100 lines)
sudo journalctl -u seceoknight -n 100

# Nginx logs
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log

# SQLite — quick check
sqlite3 /opt/seceoknight/server/seceoknight.db "SELECT event_type, count(*) FROM events GROUP BY event_type;"
```
