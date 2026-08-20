# Endpoint Setup Guide

How to deploy the SecEoKnight agent on each Windows 10/11 endpoint.

## What Gets Installed on Each Endpoint

- `mitmproxy` — intercepts all browser traffic
- `agent.py` — mitmproxy addon that checks/blocks URLs per the central blocklist
- `to-server.py` — streams log events to the security server
- **SecEoKnight-Proxy** Windows Service — runs mitmproxy + agent.py silently
- **SecEoKnight-Logger** Windows Service — runs to-server.py silently
- Chrome Extension — AI-powered phishing and malware detection in the browser

Both services start automatically on every boot, run with no visible windows, and restart themselves if they crash.

---

## Option A — Automatic Setup (Recommended)

### Prerequisites
- Windows 10 or 11 (64-bit)
- **Administrator access** on the machine
- Python 3.x installed — https://www.python.org/downloads/
  - ⚠️ During Python install: tick **"Add Python to PATH"**
- Internet access (to download mitmproxy and NSSM)
- Security server must already be running at `192.168.1.189`

### Steps

**1. Open PowerShell as Administrator**

Right-click the Start button → **Windows PowerShell (Admin)**

**2. Allow script execution (one time per machine)**

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Type `Y` and press Enter.

**3. Download and run setup.ps1**

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/seceoknight-url-filter/main/endpoint/setup.ps1" -OutFile "$env:TEMP\setup.ps1"
& "$env:TEMP\setup.ps1"
```

> Replace `YOUR_GITHUB_USERNAME` with your actual GitHub username.

**4. What the script does (fully automatic)**

- Creates `C:\SecEoKnight\` and `C:\SecEoKnight\Logs\`
- Downloads `agent.py` and `to-server.py` from your GitHub
- Downloads and installs mitmproxy
- Downloads NSSM to `C:\SecEoKnight\nssm.exe`
- Opens `http://mitm.it` — **you must install the certificate**
- Installs `SecEoKnight-Proxy` as a Windows Service
- Installs `SecEoKnight-Logger` as a Windows Service
- Configures machine-wide proxy (WinHTTP + browser)
- Starts both services

**5. Install the certificate (critical — HTTPS blocking won't work without this)**

When the script opens `http://mitm.it`:
1. Click **Windows**
2. Download `mitmproxy-ca-cert.cer`
3. Double-click the `.cer` file
4. Click **Install Certificate**
5. Select **Local Machine** → Next
6. Select **Place all certificates in the following store**
7. Click **Browse** → select **Trusted Root Certification Authorities** → OK
8. Click **Next** → **Finish**
9. You should see: *"The import was successful"*
10. Return to PowerShell and press **Enter**

**6. Setup complete**

```
+---------------------------------------------------+
|          SETUP COMPLETE                           |
+---------------------------------------------------+
| Services installed:                               |
|   SecEoKnight-Proxy   [running as Windows Service]|
|   SecEoKnight-Logger  [running as Windows Service]|
|                                                   |
| Both services:                                    |
|   Auto-start on every Windows boot               |
|   Run silently - no windows, no taskbar icon      |
|   Auto-restart if they crash                      |
+---------------------------------------------------+
```

**No PowerShell windows to keep open.** Setup is complete.

---

## Managing the Windows Services

### Check Status

Open PowerShell as Administrator:
```powershell
sc query SecEoKnight-Proxy
sc query SecEoKnight-Logger
```

Both should show: `STATE: 4 RUNNING`

Or open the Windows Services GUI:
```powershell
services.msc
```
Look for "SecEoKnight Proxy Agent" and "SecEoKnight Log Forwarder".

### Stop a Service

```powershell
sc stop SecEoKnight-Proxy
sc stop SecEoKnight-Logger
```

### Start a Service

```powershell
sc start SecEoKnight-Proxy
sc start SecEoKnight-Logger
```

### Restart a Service

```powershell
sc stop SecEoKnight-Proxy && sc start SecEoKnight-Proxy
```

### View Service Logs

Logs are written to `C:\SecEoKnight\Logs\`:
- `proxy.log` / `proxy-error.log` — mitmproxy + agent.py output
- `logger.log` / `logger-error.log` — to-server.py output

```powershell
Get-Content C:\SecEoKnight\Logs\proxy.log -Tail 50
Get-Content C:\SecEoKnight\Logs\logger-error.log -Tail 20
```

Logs rotate automatically at 10 MB — no manual cleanup needed.

---

## Option B — Manual Setup

Use this if the automatic script fails or you want step-by-step control.

### Step 1 — Install mitmproxy

1. Download from https://mitmproxy.org/downloads/
2. Choose: `mitmproxy-10.2.4-windows-x86_64-installer.exe`
3. Install with default options
4. Verify: open PowerShell and run `mitmdump --version`

### Step 2 — Copy agent files

Create folder `C:\SecEoKnight\` and `C:\SecEoKnight\Logs\`, then copy into `C:\SecEoKnight\`:
- `agent.py` (from `endpoint/agent.py` in the repo)
- `to-server.py` (from `endpoint/to-server.py` in the repo)

Both files already have `SERVER_IP = "192.168.1.189"` — leave as-is if that is your server.

Install the `requests` Python package:
```powershell
python -m pip install requests
```

### Step 3 — Configure Windows proxy

Settings → Network & Internet → Proxy:
- Automatically detect settings: **OFF**
- Use a proxy server: **ON**
- Address: your machine's LAN IP (e.g. `192.168.1.105`)  Port: `8082`
- Do not proxy: `192.168.*;10.*;172.16.*;localhost`
- Click **Save**

Also set WinHTTP proxy (for system-wide coverage):
```powershell
netsh winhttp set proxy "192.168.1.105:8082" "192.168.*;10.*;172.16.*;localhost"
```

### Step 4 — Install mitmproxy certificate

Start a temporary proxy:
```powershell
mitmdump --listen-port 8082
```

Open Chrome and go to `http://mitm.it` → click **Windows** → install the `.cer` file as described in Option A Step 5.

Press `Ctrl+C` to stop the temporary proxy.

> **Important:** the temporary proxy above generates its CA certificate under your current user profile (`%USERPROFILE%\.mitmproxy`). The permanent Windows service you install in Step 5 runs as `LocalSystem` — a different account with its own profile — so it will generate and present a *different* CA unless you explicitly point both at the same config directory. Use `--set confdir="C:\SecEoKnight\mitm-confdir"` on **both** the temporary proxy command above and the service's `AppParameters` in Step 5, or every HTTPS site will fail with a certificate-trust error once the permanent service takes over.

### Step 5 — Install as Windows Services (NSSM)

Download NSSM:
```powershell
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\nssm.zip"
Expand-Archive "$env:TEMP\nssm.zip" "$env:TEMP\nssm-extract" -Force
Copy-Item "$env:TEMP\nssm-extract\nssm-2.24\win64\nssm.exe" "C:\SecEoKnight\nssm.exe"
```

Install the proxy service:
```powershell
$nssm     = "C:\SecEoKnight\nssm.exe"
$mitmdump = (Get-Command mitmdump).Source
$python   = (Get-Command python).Source
$logdir   = "C:\SecEoKnight\Logs"

& $nssm install SecEoKnight-Proxy $mitmdump
& $nssm set SecEoKnight-Proxy AppParameters "--listen-host 0.0.0.0 --listen-port 8082 -s `"C:\SecEoKnight\agent.py`" --set confdir=`"C:\SecEoKnight\mitm-confdir`""
& $nssm set SecEoKnight-Proxy Start          SERVICE_AUTO_START
& $nssm set SecEoKnight-Proxy AppStdout      "$logdir\proxy.log"
& $nssm set SecEoKnight-Proxy AppStderr      "$logdir\proxy-error.log"
& $nssm set SecEoKnight-Proxy AppRotateFiles 1
& $nssm set SecEoKnight-Proxy AppRestartDelay 5000
```

Install the logger service:
```powershell
& $nssm install SecEoKnight-Logger $python
& $nssm set SecEoKnight-Logger AppParameters "`"C:\SecEoKnight\to-server.py`""
& $nssm set SecEoKnight-Logger Start          SERVICE_AUTO_START
& $nssm set SecEoKnight-Logger AppStdout      "$logdir\logger.log"
& $nssm set SecEoKnight-Logger AppStderr      "$logdir\logger-error.log"
& $nssm set SecEoKnight-Logger AppRotateFiles 1
& $nssm set SecEoKnight-Logger AppRestartDelay 5000
```

Start both services:
```powershell
Start-Service SecEoKnight-Proxy
Start-Service SecEoKnight-Logger
```

Both now run silently in the background — no windows to keep open.

---

## Chrome Extension Installation

1. Open Chrome → go to `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder from the repo root
5. The SecEoKnight extension icon appears in Chrome toolbar ✓

If your server IP differs from `192.168.1.189`, open `extension/background.js` and update line 1:
```javascript
const API_BASE = "http://YOUR_SERVER_IP:5001";
```
Then reload the extension in `chrome://extensions/` → click the refresh icon on the SecEoKnight card.

---

## Deploying to 50 Endpoints with Group Policy (Mass Deploy)

For large-scale deployment without visiting each machine individually:

### 1. Deploy the Certificate via Group Policy

This pushes the mitmproxy certificate to all domain computers automatically:
- Open **Group Policy Management** on your domain controller
- Computer Configuration → Windows Settings → Security Settings
- → Public Key Policies → Trusted Root Certification Authorities
- Right-click → **Import** → select `mitmproxy-ca-cert.cer`

### 2. Create a Network Share

Put `setup.ps1`, `agent.py`, and `to-server.py` in a shared folder accessible to all endpoints, e.g. `\\fileserver\SecEoKnight\`.

### 3. Create a Startup Script via Group Policy

- Computer Configuration → Windows Settings → Scripts → Startup
- Add a PowerShell startup script:

```powershell
# Copy files from network share
Copy-Item "\\fileserver\SecEoKnight\agent.py"     "C:\SecEoKnight\" -Force
Copy-Item "\\fileserver\SecEoKnight\to-server.py" "C:\SecEoKnight\" -Force

# Run setup if services not already installed
if (-not (Get-Service SecEoKnight-Proxy -ErrorAction SilentlyContinue)) {
    & "\\fileserver\SecEoKnight\setup.ps1"
}
```

All 50 machines install the services on their next boot.

---

## Verifying an Endpoint is Connected

From the security server:
```bash
curl http://localhost:5001/api/endpoints
```

Within 60 seconds of the services starting, the endpoint's IP appears in the list with `"status": "active"`.

Or from your SIEM dashboard → **Endpoint Monitor** tab.

---

## Temporarily Stopping Monitoring

To pause monitoring on a machine (services still installed):
```powershell
sc stop SecEoKnight-Proxy
sc stop SecEoKnight-Logger
```

To resume:
```powershell
sc start SecEoKnight-Proxy
sc start SecEoKnight-Logger
```

---

## Fully Uninstalling SecEoKnight from an Endpoint

Run as Administrator:
```powershell
# Stop and remove services
sc stop SecEoKnight-Proxy
sc stop SecEoKnight-Logger
C:\SecEoKnight\nssm.exe remove SecEoKnight-Proxy  confirm
C:\SecEoKnight\nssm.exe remove SecEoKnight-Logger confirm

# Remove machine-wide proxy (WinHTTP)
netsh winhttp reset proxy

# Remove browser proxy (WinINet)
$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0

# Remove all files
Remove-Item -Recurse -Force C:\SecEoKnight
Remove-Item -Recurse -Force C:\url-block -ErrorAction SilentlyContinue
```

---

## Troubleshooting

### Service Won't Start

```powershell
# Check why it failed
sc query SecEoKnight-Proxy
Get-Content C:\SecEoKnight\Logs\proxy-error.log -Tail 30
```

Common causes: mitmdump not found (check PATH), agent.py missing, port 8082 in use.

### Websites Not Being Blocked

1. Confirm service is running: `sc query SecEoKnight-Proxy` → must be RUNNING
2. Wait 30 seconds for blocklist refresh
3. Check proxy is set: `netsh winhttp show proxy`
4. Check browser proxy: Settings → Network → Proxy

### Endpoint Not Appearing in Dashboard

1. `sc query SecEoKnight-Logger` — must be RUNNING
2. `Get-Content C:\SecEoKnight\Logs\logger-error.log -Tail 20` — check for connection errors
3. Verify server reachable: `Test-NetConnection -ComputerName 192.168.1.189 -Port 5001`

### Certificate Error in Chrome

Re-run the certificate install and choose **Local Machine** (not Current User).
Check it installed: open `certmgr.msc` → Trusted Root Certification Authorities → Certificates → look for `mitmproxy`.
