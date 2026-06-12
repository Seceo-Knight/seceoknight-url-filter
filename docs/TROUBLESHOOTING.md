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

1. Check mitmproxy is running: look for the mitmproxy terminal window
2. Check proxy is set in Windows: Settings → Network → Proxy
3. Check blocklist: `curl http://YOUR_SERVER_IP:5001/blocklist`
4. Check mitmproxy logs in its terminal window

### Endpoint not appearing in dashboard

1. Check to-server.py is running (look for its terminal window)
2. Check server is reachable from endpoint:
   ```powershell
   Test-NetConnection -ComputerName 192.168.1.189 -Port 5001
   ```
3. Check the log file exists: `C:\url-block\logs.json`

### HTTPS sites showing SSL errors

Certificate not installed correctly.

1. Open `certmgr.msc` (Windows Certificate Manager)
2. Go to Trusted Root Certification Authorities → Certificates
3. Look for "mitmproxy" certificate
4. If missing: re-run the certificate installation step from `setup.ps1`

### mitm.it not loading during certificate setup

1. Make sure mitmproxy is running on port 8082
2. Make sure Windows proxy is set to `127.0.0.1:8082`
3. Close and reopen Chrome completely
4. Try: `chrome.exe --proxy-server="127.0.0.1:8082"`

### Blocklist not updating on endpoint

agent.py refreshes the blocklist every 30 seconds. Wait 30 seconds after adding a rule.

To verify the blocklist is being fetched, look at the mitmproxy terminal — you should see a log line: `agent: blocklist loaded — vids=X prefixes=Y hosts=Z`

### to-server.py shows "Cannot reach server"

- Server might be down: `sudo systemctl status seceoknight`
- Wrong IP: check `SERVER_IP` in `to-server.py`
- Firewall: `sudo ufw status` — port 5001 must be allowed

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
