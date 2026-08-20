# SecEoKnight — Security Backend

Enterprise-grade URL filtering and AI-powered threat detection for your SIEM.

---

## What This System Does

| Component | Where It Runs | What It Does |
|---|---|---|
| **Security Server** | Ubuntu 22.04 (192.168.1.63) | Stores all events, serves the blocklist, runs AI models, pushes alerts to your dashboard |
| **mitmproxy Agent** | Each Windows endpoint | Intercepts browser traffic, blocks URLs in real time |
| **Chrome Extension** | Each Windows endpoint | Detects phishing URLs using AI before the page loads |
| **Malware Scanner** | Each Windows endpoint | Watches Downloads folder, scans new files with AI CNN model, quarantines detected malware |
| **SIEM Dashboard** | Separate server *(built later)* | Shows alerts, events, stats, blocklist management |

---

## Network Architecture

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                    Your LAN (192.168.1.x)                       │
 │                                                                 │
 │  Windows Endpoint 1          ┌──────────────────────────┐       │
 │  ┌─────────────────┐         │   SECURITY SERVER        │       │
 │  │ mitmproxy       │─logs───▶│   Ubuntu 22.04           │       │
 │  │ Chrome Ext (AI) │─predict▶│   IP: 192.168.1.63      │       │
 │  └─────────────────┘◀─block─ │   Port 5001 (API)        │       │
 │                               │   Port 80  (Nginx)       │       │
 │  Windows Endpoint 2  ...×50  │                          │       │
 │  ┌─────────────────┐         │   SQLite Database        │       │
 │  │ mitmproxy       │─logs───▶│   AI Models (CNN/ViT/    │       │
 │  │ Chrome Ext (AI) │─predict▶│   BiLSTM/1D-CNN-LSTM)    │       │
 │  └─────────────────┘◀─block─ └──────────┬───────────────┘       │
 │                                         │ WebSocket / REST API  │
 │                               ┌─────────▼───────────────┐       │
 │                               │   SIEM Dashboard Server  │       │
 │                               │   (built separately)     │       │
 │                               └──────────────────────────┘       │
 └─────────────────────────────────────────────────────────────────┘
```

---

## Before You Start — What You Need

### Security Server
- Ubuntu 22.04 LTS (fresh install)
- Minimum: 8 GB RAM, 4 CPU cores, 100 GB SSD
- Static IP on your LAN — set to **192.168.1.63**
- Internet access (for first-time package install only)

### Each Windows Endpoint (×50)
- Windows 10 or Windows 11 (64-bit)
- Python 3.x installed — download from [python.org](https://www.python.org/downloads/)
  - ⚠️ During install: tick **"Add Python to PATH"**
- Google Chrome browser
- Administrator access on the machine

### GitHub Account
- Create a free account at [github.com](https://github.com) if you don't have one
- You will push this project to your own GitHub repository

---

# PART 1 — Security Server Setup

> **Do this first.** The server must be running before you touch any endpoint.

---

## Step 1 — Log Into Your Ubuntu Server

Open a terminal (or SSH into the server) and run all commands below.

---

## Step 2 — Update the System

```bash
sudo apt update && sudo apt upgrade -y
```

Wait for it to finish. This updates all system packages.

---

## Step 3 — Install Required System Packages

```bash
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip nginx git git-lfs sqlite3
```

Verify Python installed correctly:
```bash
python3.11 --version
```
You should see: `Python 3.11.x`

---

## Step 4 — Set Up Git LFS

Git LFS is required to download the large AI model files from GitHub.

```bash
git lfs install
```

You should see: `Git LFS initialized.`

---

## Step 5 — Push This Project to Your GitHub

**Do this from your Mac/PC (not the server).**

```bash
cd /path/to/SeceoKnight-backend

git init
git add .
git commit -m "SecEoKnight backend — initial release"

# Create a new repo on github.com called "seceoknight-url-filter"
# then run:
git remote add origin https://github.com/Seceo-Knight/seceoknight-url-filter.git
git push -u origin main
```

> Replace `Seceo-Knight` with your actual GitHub username.

---

## Step 6 — Clone the Repo on the Server

```bash
sudo mkdir -p /opt/seceoknight
sudo chown $USER:$USER /opt/seceoknight
cd /opt/seceoknight

git clone https://github.com/Seceo-Knight/seceoknight-url-filter.git .

# Download the large model files (Git LFS)
git lfs pull
```

After `git lfs pull` you should see the malware models are real files (not tiny pointer files):
```bash
ls -lh server/models/malware/
```
Expected: CNN.keras (~2 MB), ViT.keras (~7 MB), 1D-CNN-LSTM.keras (~6 MB)

---

## Step 7 — Create Python Virtual Environment

```bash
cd /opt/seceoknight
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

> ⏳ TensorFlow installation takes 5–10 minutes. This is normal.

---

## Step 8 — Train the Phishing Detection Model

The malware models are pre-trained and already downloaded. The phishing model must be
trained once from the included dataset:

```bash
cd /opt/seceoknight
source venv/bin/activate
python3 scripts/train_phishing_model.py
```

> ⏳ This takes 5–15 minutes depending on your hardware.
> It trains on 95,980 real phishing/safe domain samples.

When finished you will see:
```
✅  Training complete. Restart seceoknight service to load the new model.
```

Verify the model files were created:
```bash
ls -lh server/models/phishing/
```
Expected: `bilstm_domain_model.h5` and `tokenizer.pkl`

---

## Step 9 — Test the Server (Manual Start)

```bash
cd /opt/seceoknight/server
source /opt/seceoknight/venv/bin/activate
uvicorn unified_server:app --host 0.0.0.0 --port 5001
```

Open a browser on any computer on your LAN and go to:
```
http://192.168.1.63:5001/health
```

You should see:
```json
{
  "status": "healthy",
  "ai": {
    "phishing_model": "loaded",
    "malware_models": { "CNN": "loaded", "ViT": "loaded", "1D-CNN-LSTM": "loaded" }
  }
}
```

Press `Ctrl+C` to stop the test server.

---

## Step 10 — Install as Auto-Start Service

The server must start automatically every time Ubuntu boots.

```bash
# Copy the service file
sudo cp /opt/seceoknight/systemd/seceoknight.service /etc/systemd/system/

# If your Ubuntu username is NOT "ubuntu", edit the service file:
sudo nano /etc/systemd/system/seceoknight.service
# Find the line:  User=ubuntu
# Change it to:   User=YOUR_USERNAME
# Save: Ctrl+O  →  Enter  →  Ctrl+X

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable seceoknight
sudo systemctl start seceoknight

# Confirm it is running
sudo systemctl status seceoknight
```

You should see `Active: active (running)` in green.

---

## Step 11 — Configure Nginx (Port 80 Reverse Proxy)

Nginx sits in front of the server so endpoints connect on port 80 instead of 5001.

```bash
# Copy the ready-made nginx config from the repo
sudo cp /opt/seceoknight/nginx/seceoknight.conf /etc/nginx/sites-available/seceoknight

# Enable it
sudo ln -s /etc/nginx/sites-available/seceoknight /etc/nginx/sites-enabled/seceoknight

# Remove the default nginx page
sudo rm -f /etc/nginx/sites-enabled/default

# Test config and reload
sudo nginx -t
sudo systemctl reload nginx
```

You should see: `nginx: configuration file test is successful`

---

## Step 12 — Open the Firewall

```bash
sudo ufw allow 22/tcp       # SSH (keep this — otherwise you get locked out)
sudo ufw allow 80/tcp       # Nginx (endpoints + dashboard use this)
sudo ufw allow 5001/tcp     # Direct API access (for testing)
sudo ufw enable
```

Confirm:
```bash
sudo ufw status
```

---

## Step 13 — Seed the Default Blocklist

Populate the blocklist with enterprise-ready rules (social media, gambling, piracy, malware):

```bash
cd /opt/seceoknight
source venv/bin/activate
python3 scripts/add_default_blocklist.py
```

You should see 30+ rules added in green.

---

## Step 14 — Managing the Blocklist (Add / Remove / Update Rules)

Run all commands on the Ubuntu server. Endpoints pick up changes within 30 seconds automatically.

### View all active rules
```bash
curl http://localhost:5001/api/blocklist
```

### Block an entire domain (and all subdomains)
```bash
# Blocks facebook.com, www.facebook.com, m.facebook.com etc.
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "host", "rule_value": "facebook.com", "comment": "block facebook"}'
```

### Block a specific subdomain only
```bash
# Only blocks m.facebook.com — www.facebook.com still works
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "host", "rule_value": "m.facebook.com", "comment": "block mobile site only"}'
```

### Block a specific path on a domain (not the full site)
```bash
# Only blocks youtube.com/shorts — rest of YouTube still works
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "prefix", "rule_value": "youtube.com/shorts", "comment": "block shorts only"}'
```

### Block using regex (advanced — matches any URL containing the pattern)
```bash
# Blocks any URL containing "gambling" or "casino"
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "regex", "rule_value": "gambling|casino", "comment": "block gambling sites"}'
```

### Block a specific YouTube video by ID
```bash
# Get the video ID from the URL: youtube.com/watch?v=dQw4w9WgXcQ
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "vid", "rule_value": "dQw4w9WgXcQ", "comment": "block specific video"}'
```

### Remove a rule (get the ID from the list)
```bash
# First get IDs:
curl http://localhost:5001/api/blocklist

# Then delete by ID (rule is deactivated, not permanently deleted):
curl -X DELETE http://localhost:5001/api/blocklist/1
```

### Restore a previously removed rule
```bash
curl -X PUT http://localhost:5001/api/blocklist/1/restore
```

**Rule type summary:**

| Type | Blocks | Example value |
|------|--------|---------------|
| `host` | Entire domain + all subdomains | `facebook.com` |
| `prefix` | Specific path on a domain | `youtube.com/shorts` |
| `regex` | Any URL matching a pattern | `gambling\|casino` |
| `vid` | Specific YouTube video ID | `dQw4w9WgXcQ` |

> Endpoints refresh the blocklist every 30 seconds. No restart needed after adding or removing rules.

---

## Step 15 — Run Full Health Check

```bash
bash /opt/seceoknight/scripts/health_check.sh
```

Every item should show `[PASS]`. If anything shows `[FAIL]`, the script tells you exactly what to fix.

---

## ✅ Server Is Ready When

```bash
# Test from any machine on the LAN:
curl http://192.168.1.63/health        # Should return {"status":"healthy",...}
curl http://192.168.1.63/blocklist     # Should return list of blocked rules
curl http://192.168.1.63/api/stats     # Should return {"total_requests":0,...}
```

---

---

# PART 2 — Endpoint Setup (Windows Machines)

> **Do Part 1 first.** The server must be running before setting up any endpoint.

Each Windows machine needs: mitmproxy (intercepts traffic) + to-server.py (sends logs).

---

## Option A — Automatic Setup (Recommended)

Run this on each Windows machine. The script does everything automatically.

### Step 1 — Update setup.ps1 with Your GitHub Username

Before running the script on any machine, open `endpoint/setup.ps1` in the repo and find:
```powershell
$RepoBase = "https://raw.githubusercontent.com/Seceo-Knight/seceoknight-url-filter/main/endpoint"
```
Replace `Seceo-Knight` with your actual GitHub username, then push to GitHub:
```bash
git add endpoint/setup.ps1
git commit -m "Set GitHub username in setup.ps1"
git push
```

### Step 2 — On Each Windows Machine

1. **Open PowerShell as Administrator**
   Right-click the Start button → **Windows PowerShell (Admin)**

2. **Allow scripts to run** (one-time per machine)
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
   Type `Y` and press Enter.

3. **Download and run the setup script**
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Seceo-Knight/seceoknight-url-filter/main/endpoint/setup.ps1" -OutFile "$env:TEMP\setup.ps1"
   & "$env:TEMP\setup.ps1"
   ```

4. **The script will automatically:**
   - Create `C:\SecEoKnight\` and `C:\SecEoKnight\Quarantine\` folders
   - Download `agent.py`, `to-server.py`, and `malware_watcher.py`
   - Install Python packages (`requests`, `watchdog`, `pillow`)
   - Download and install mitmproxy
   - Download NSSM (Windows Service manager) to `C:\SecEoKnight\nssm.exe`
   - Open `http://mitm.it` so you can install the certificate
   - Install **SecEoKnight-Proxy** as a Windows Service (mitmproxy + agent.py)
   - Install **SecEoKnight-Logger** as a Windows Service (to-server.py)
   - Install **SecEoKnight-Scanner** as a Windows Service (malware_watcher.py)
   - Set machine-wide proxy to route all browser traffic through mitmproxy

5. **Install the certificate when prompted** *(critical — HTTPS blocking won't work without this)*

   The script opens `http://mitm.it` automatically and pauses. **Close all browser windows first**, then re-open the browser so it picks up the temporary proxy setting.

   **Method A — via mitm.it (preferred):**
   - Browser opens `http://mitm.it` automatically
   - Click **Windows**
   - Download `mitmproxy-ca-cert.cer`
   - Double-click the `.cer` file
   - Click **Install Certificate**
   - Select **Local Machine** → click Next
   - Select **Place all certificates in the following store**
   - Click Browse → select **Trusted Root Certification Authorities** → OK
   - Click Next → Finish
   - You should see: *"The import was successful"*
   - Go back to PowerShell and press **Enter**

   **Method B — if mitm.it shows "traffic is not going through mitmproxy":**

   Press **Enter** in PowerShell to let the script finish, then run this in PowerShell as Admin:
   ```powershell
   certutil -addstore root "C:\Windows\System32\config\systemprofile\.mitmproxy\mitmproxy-ca-cert.cer"
   ```
   You should see: *"CertUtil: -addstore command completed successfully."*

   This installs the certificate that the running Windows Service uses (stored in the LocalSystem profile).

6. **Setup completes — all three agents run as Windows Services:**
   - `SecEoKnight-Proxy` — mitmproxy traffic interceptor
   - `SecEoKnight-Logger` — log forwarder to security server
   - `SecEoKnight-Scanner` — AI malware file watcher (quarantines threats from Downloads)

   **No PowerShell windows to keep open.** All services:
   - Start automatically every time Windows boots
   - Run silently in the background — invisible to users
   - Restart automatically if they crash
   - Are managed via **Services** panel (`services.msc`) or PowerShell

### Step 3 — Verify the Endpoint Is Connected

From the server, run:
```bash
curl http://localhost:5001/api/endpoints
```
Within 60 seconds, the endpoint's IP address should appear in the list.

Or check from your SIEM dashboard → **Endpoint Monitor** tab.

---

## Option B — Manual Setup

Use this if the automatic script fails or if you prefer full control.

### Step 1 — Install mitmproxy

1. Download from [mitmproxy.org/downloads](https://mitmproxy.org/downloads/)
2. Choose: `mitmproxy-10.2.4-windows-x86_64-installer.exe`
3. Run the installer with default options
4. Verify in PowerShell: `mitmdump --version`

### Step 2 — Copy Agent Files

Create `C:\SecEoKnight\` and copy into it:
- `agent.py` (from `endpoint/agent.py` in the repo)
- `to-server.py` (from `endpoint/to-server.py` in the repo)

Both files already have `SERVER_IP = "192.168.1.63"` — leave as-is if that is your server IP.

### Step 3 — Configure Windows Proxy

Go to: **Settings → Network & Internet → Proxy**
- Automatically detect settings: **OFF**
- Use a proxy server: **ON**
- Address: `127.0.0.1`   Port: `8082`
- Click **Save**

### Step 4 — Install the Certificate

Open PowerShell and run:
```powershell
mitmdump --listen-port 8082
```

Open Chrome and go to `http://mitm.it` → click **Windows** → install the `.cer` file as described in Option A Step 5.

Stop mitmdump with `Ctrl+C`.

### Step 5 — Install as Windows Services

Download NSSM and install both agents as background services:
```powershell
# Download NSSM
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\nssm.zip"
Expand-Archive "$env:TEMP\nssm.zip" "$env:TEMP\nssm-extract" -Force
Copy-Item "$env:TEMP\nssm-extract\nssm-2.24\win64\nssm.exe" "C:\SecEoKnight\nssm.exe"

$nssm     = "C:\SecEoKnight\nssm.exe"
$mitmdump = (Get-Command mitmdump).Source
$python   = (Get-Command python).Source

# Proxy service
& $nssm install SecEoKnight-Proxy $mitmdump
& $nssm set SecEoKnight-Proxy AppParameters "--listen-host 0.0.0.0 --listen-port 8082 -s `"C:\SecEoKnight\agent.py`""
& $nssm set SecEoKnight-Proxy Start SERVICE_AUTO_START

# Logger service
& $nssm install SecEoKnight-Logger $python
& $nssm set SecEoKnight-Logger AppParameters "`"C:\SecEoKnight\to-server.py`""
& $nssm set SecEoKnight-Logger Start SERVICE_AUTO_START

# Scanner service
& $nssm install SecEoKnight-Scanner $python
& $nssm set SecEoKnight-Scanner AppParameters "`"C:\SecEoKnight\malware_watcher.py`""
& $nssm set SecEoKnight-Scanner AppDirectory "C:\SecEoKnight"
& $nssm set SecEoKnight-Scanner Start SERVICE_AUTO_START

# Start all three
Start-Service SecEoKnight-Proxy
Start-Service SecEoKnight-Logger
Start-Service SecEoKnight-Scanner
```

All three services now run silently in the background — no windows to keep open. They start automatically on every boot.

---

## Deploying to All 50 Endpoints with Group Policy

For large-scale deployment without visiting each machine individually:

### Step 1 — Create a Network Share

Put `setup.ps1`, `agent.py`, and `to-server.py` in a shared folder accessible from all machines (e.g. `\\fileserver\SecEoKnight\`).

### Step 2 — Deploy the mitmproxy Certificate via Group Policy

Open **Group Policy Management** on your domain controller:
- Computer Configuration → Windows Settings → Security Settings
- → Public Key Policies → Trusted Root Certification Authorities
- Right-click → Import → select the `mitmproxy-ca-cert.cer` file

This automatically installs the certificate on all domain computers.

### Step 3 — Create a Startup Script via Group Policy

- Computer Configuration → Windows Settings → Scripts → Startup
- Add a PowerShell script:
  ```powershell
  # Copy files from network share
  Copy-Item "\\fileserver\SecEoKnight\*" "C:\SecEoKnight\" -Force

  # Run setup (silent mode)
  & "C:\SecEoKnight\setup.ps1"
  ```

All 50 machines run the script on next boot.

---

---

# PART 3 — Chrome Extension Setup

The Chrome extension adds AI-powered phishing detection directly in the browser.
It checks every URL you visit against the SecEoKnight AI model in the background —
no delay on normal browsing. If a phishing site is detected, a warning banner
appears on the page and the alert is logged on the security server.

Install this on each endpoint after Part 2.

### Step 1 — Confirm Server Address (Usually No Change Needed)

Open `extension/background.js` and check this line near the top:
```javascript
const API_BASE = "http://192.168.1.63:5001";
```
If your server IP is `192.168.1.63` (the default), leave it as-is. If different, update it here.

### Step 2 — Install on Each Windows Machine

1. Copy the `extension/` folder from the repo to the Windows machine
   (or clone the repo there)

2. Open **Google Chrome**

3. Go to: `chrome://extensions/`

4. Turn on **Developer mode** — toggle in the top-right corner

5. Click **Load unpacked**

6. Select the `extension/` folder from the repo

7. The **SecEoKnight** shield icon appears in the Chrome toolbar ✓

### Step 3 — Verify It Works

Click the SecEoKnight icon in the Chrome toolbar. The popup shows:
- **Server Online** — green dot means it is connected to your security server
- **Total Blocks** — count of blocked URLs across all endpoints
- **AI Detections** — count of AI-detected phishing threats

Visit any website — the extension silently checks it in the background.
If phishing is detected, a red or orange banner appears at the top of the page
and the event is logged to the server automatically.

---

---

# PART 4 — Verify the Whole System Works

Run these checks after completing Parts 1, 2, and 3.

### Check 1 — Server Is Healthy

From any machine on the LAN:
```
http://192.168.1.63/health
```
Expected:
```json
{"status": "healthy", "ai": {"phishing_model": "loaded", "malware_models": {...}}}
```

### Check 2 — Endpoints Are Reporting

```
http://192.168.1.63/api/endpoints
```
Each connected endpoint shows as `"status": "active"`.

### Check 3 — Blocklist Is Being Served

```
http://192.168.1.63/blocklist
```
You should see a list of blocked rules (social media, gambling, etc.).

### Check 4 — Blocking Works on an Endpoint

On a Windows endpoint, open Chrome and try visiting `facebook.com`.
You should see: **"Blocked by SecEoKnight"**

### Check 5 — Events Are Being Recorded

```
http://192.168.1.63/api/events?limit=10
```
You should see recent events including the `facebook.com` block attempt.

### Check 6 — Stats Are Updating

```
http://192.168.1.63/api/stats
```
`total_requests` should be increasing as endpoints browse.

---

---

# Useful Server Commands

```bash
# Check server status
sudo systemctl status seceoknight

# Restart server (after config changes or updates)
sudo systemctl restart seceoknight

# View live server logs
sudo journalctl -u seceoknight -f

# Update from GitHub
cd /opt/seceoknight
git pull
sudo systemctl restart seceoknight

# Add a blocklist rule manually
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"host","rule_value":"example.com","description":"Test block"}'

# View database directly
sqlite3 /opt/seceoknight/server/seceoknight.db "SELECT COUNT(*) FROM events;"
```

---

# Troubleshooting

| Problem | Fix |
|---|---|
| Server won't start | `sudo journalctl -u seceoknight -n 50` — check error message |
| AI shows `not_loaded` | Run `python3 scripts/train_phishing_model.py` then restart server |
| Endpoint not appearing in list | Run `sc query SecEoKnight-Logger` — must show RUNNING; check server IP |
| Malware scanner not running | Run `Get-Service SecEoKnight-Scanner` — check `C:\SecEoKnight\Logs\scanner-error.log` |
| File not quarantined | Check file extension is in scan list and size is over 512 bytes |
| Websites not being blocked | Wait 30 seconds; check proxy is ON in Windows Settings |
| `http://mitm.it` won't open | Make sure mitmproxy is running first and proxy is configured |
| Certificate error in Chrome | Re-install mitmproxy certificate as Local Machine (not Current User) |

Full troubleshooting guide: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

---

# Project Files Reference

```
SeceoKnight-backend/
├── server/                        ← Runs on Ubuntu security server
│   ├── unified_server.py          ← Main API server (FastAPI)
│   ├── database.py                ← SQLite database logic
│   ├── ai_engine.py               ← Phishing + malware AI detection
│   ├── websocket_manager.py       ← Real-time alerts to dashboard
│   └── models/
│       ├── phishing/              ← bilstm_domain_model.h5 + tokenizer.pkl
│       └── malware/               ← CNN.keras, ViT.keras, 1D-CNN-LSTM.keras
│
├── endpoint/                      ← Runs on each Windows machine (×50)
│   ├── agent.py                   ← mitmproxy plugin — intercepts + blocks URLs
│   ├── to-server.py               ← Sends logs to security server
│   ├── malware_watcher.py         ← AI malware scanner — watches Downloads, quarantines threats
│   └── setup.ps1                  ← One-click Windows setup script (installs all 3 services)
│
├── scripts/                       ← Run on security server (one-time setup)
│   ├── train_phishing_model.py    ← Trains the BiLSTM phishing model
│   ├── add_default_blocklist.py   ← Seeds enterprise blocklist rules
│   ├── health_check.sh            ← Verifies everything is working
│   └── data/phishing.csv          ← 95,980 training samples (included)
│
├── nginx/
│   └── seceoknight.conf           ← Nginx reverse proxy config (ready to use)
│
├── systemd/
│   └── seceoknight.service        ← Auto-start service for Ubuntu
│
└── docs/
    ├── MANUAL_USER_GUIDE.md       ← Day-to-day operations (non-technical staff)
    ├── SERVER_SETUP.md            ← Detailed server setup reference
    ├── ENDPOINT_SETUP.md          ← Detailed endpoint setup reference
    ├── API_REFERENCE.md           ← All API endpoints for dashboard developers
    └── TROUBLESHOOTING.md         ← Common problems and fixes
```

---

# What's Next — SIEM Dashboard Server

The security backend is now fully operational. The next phase is building the **SIEM Dashboard** — a separate server that connects to the security server via REST API and WebSocket.

---

## Dashboard API Reference

All requests go to `http://192.168.1.63` (via Nginx on port 80).
Replace with `http://192.168.1.63:5001` for direct access during development.

---

### 🔒 Blocklist — Block & Unblock Websites

#### List all active rules
```bash
curl http://localhost:5001/api/blocklist
```

List ALL rules including inactive:
```bash
curl "http://localhost:5001/api/blocklist?active_only=false"
```

#### Block a website (add rule)
```bash
curl -X POST http://localhost:5001/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"rule_type": "host", "rule_value": "facebook.com", "comment": "Social media block"}'
```
`rule_type` options:
- `host` — block entire domain: `"facebook.com"`
- `prefix` — block URL path: `"youtube.com/shorts"`
- `regex` — block by pattern: `".*gambling.*"`
- `vid` — block specific YouTube video ID: `"dQw4w9WgXcQ"`

#### Unblock a website (deactivate rule)
```bash
# First get the rule ID:
curl http://localhost:5001/api/blocklist

# Then delete by ID:
curl -X DELETE http://localhost:5001/api/blocklist/1
```
> Rule is **deactivated, not deleted** — it can be restored. Endpoints stop blocking within 30 seconds.

#### Re-block a previously unblocked rule
```bash
curl -X PUT http://localhost:5001/api/blocklist/1/restore
```

---

### 📋 Events — Network Activity Log

#### Get events (with filters)
```http
GET /api/events
```
Query parameters — all optional, combine freely:

| Parameter    | Type    | Example                        | Description                        |
|---|---|---|---|
| `limit`      | int     | `?limit=50`                    | Max results (default 100, max 1000)|
| `offset`     | int     | `?offset=100`                  | Pagination offset                  |
| `client_ip`  | string  | `?client_ip=192.168.1.105`     | Filter by endpoint IP              |
| `event_type` | string  | `?event_type=blocked_host`     | Filter by event type               |
| `blocked`    | bool    | `?blocked=true`                | Only blocked / only allowed        |
| `host`       | string  | `?host=facebook`               | Search by hostname (partial match) |
| `from_ts`    | string  | `?from_ts=2024-01-01T00:00:00` | Start datetime (ISO)               |
| `to_ts`      | string  | `?to_ts=2024-01-31T23:59:59`   | End datetime (ISO)                 |

Response:
```json
{
  "total": 1523,
  "limit": 100,
  "offset": 0,
  "events": [
    {
      "id": 99,
      "timestamp_iso": "2024-01-15T14:23:01",
      "client_ip": "192.168.1.105",
      "event_type": "blocked_host",
      "host": "facebook.com",
      "url": "https://facebook.com/",
      "blocked": 1,
      "block_type": "host",
      "block_rule": "facebook.com",
      "threat_level": "High"
    }
  ]
}
```

Event type values:
- `blocked_host` — domain blocklist rule matched
- `blocked_prefix` — URL prefix rule matched
- `blocked_regex` — regex rule matched
- `blocked_watch` — YouTube video ID blocked
- `allowed` — request passed through
- `ai_phishing` — Chrome extension detected phishing URL
- `ai_malware` — malware_watcher.py detected and quarantined a malicious file

---

### 📊 Stats — Dashboard Analytics

```http
GET /api/stats
```
Response:
```json
{
  "total_requests": 48291,
  "blocked_requests": 1204,
  "allowed_requests": 47087,
  "ai_detections": 37,
  "active_endpoints": 12,
  "top_blocked_hosts": [
    {"host": "facebook.com", "count": 412},
    {"host": "instagram.com", "count": 289}
  ]
}
```

---

### 🖥️ Endpoints — Endpoint Monitor

#### List all endpoints
```http
GET /api/endpoints
```
Response:
```json
[
  {
    "ip": "192.168.1.105",
    "hostname": "",
    "status": "active",
    "last_seen": "2024-01-15T14:30:00",
    "total_requests": 2341,
    "blocked_count": 88
  }
]
```

#### Get one endpoint + its last 50 events
```http
GET /api/endpoints/{ip}
```
Example:
```http
GET /api/endpoints/192.168.1.105
```
Response:
```json
{
  "endpoint": {"ip": "192.168.1.105", "status": "active", ...},
  "recent_events": [...]
}
```

---

### 🚨 Alerts — Incident Alerts Tab

Returns only high-severity threat events (blocks + AI detections):
```http
GET /api/alerts?limit=50
```
Response: same structure as events, filtered to threat event types only.

---

### ⚡ WebSocket — Live Real-Time Alerts

Connect once from the dashboard — threats push instantly with no polling.

```
ws://192.168.1.63/ws/alerts
```

Keep-alive (send every 30s):
```json
"ping"
```
Server replies:
```json
{"type": "pong"}
```

Incoming alert message format:
```json
{
  "type": "alert",
  "event_type": "blocked_host",
  "client_ip": "192.168.1.105",
  "host": "facebook.com",
  "url": "https://facebook.com/login",
  "blocked": true,
  "timestamp": "2024-01-15T14:23:01",
  "threat_level": "High"
}
```
For AI detections:
```json
{
  "type": "alert",
  "event_type": "ai_phishing",
  "url": "https://paypa1-login.com",
  "confidence": 0.97,
  "threat_level": "High"
}
```

---

### 🤖 AI — Health & Model Status

```http
GET /health
```
```json
{
  "status": "healthy",
  "ai": {
    "phishing_model": "loaded",
    "malware_models": {"CNN": "loaded", "ViT": "loaded", "1D-CNN-LSTM": "loaded"}
  }
}
```

```http
GET /models/status
```
Returns just the AI section of `/health`.

---

Full API documentation with all edge cases: [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
