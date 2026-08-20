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
- Security server must already be running at `192.168.1.63`

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
- Generates a mitmproxy CA certificate (in a shared `C:\SecEoKnight\mitm-confdir\`) and
  **automatically installs it** into the Windows Trusted Root store — no browser step
- Installs `SecEoKnight-Proxy` as a Windows Service
- Installs `SecEoKnight-Logger` as a Windows Service
- Configures machine-wide proxy (WinHTTP + browser)
- Starts both services

**5. Certificate is installed automatically (critical — HTTPS blocking won't work without this,
but there's nothing for you to do)**

`setup.ps1` briefly runs mitmproxy in the background with `--set confdir="C:\SecEoKnight\mitm-confdir"`
to generate a CA cert, then imports it with `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root`
and verifies the import by reading the cert back out of the store. You'll see:
```
Certificate installed and verified in Trusted Root (thumbprint: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)
```
The same `--set confdir=...` flag is baked into `SecEoKnight-Proxy`'s permanent `AppParameters`,
so the running service always presents the exact cert you just trusted — no mismatch, no
"internet stopped working after setup." If verification fails, re-run the script as
Administrator (cert import needs elevation).

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
sc.exe query SecEoKnight-Proxy
sc.exe query SecEoKnight-Logger
```

Both should show: `STATE: 4 RUNNING`

Or open the Windows Services GUI:
```powershell
services.msc
```
Look for "SecEoKnight Proxy Agent" and "SecEoKnight Log Forwarder".

### Stop a Service

```powershell
sc.exe stop SecEoKnight-Proxy
sc.exe stop SecEoKnight-Logger
```

### Start a Service

```powershell
sc.exe start SecEoKnight-Proxy
sc.exe start SecEoKnight-Logger
```

### Restart a Service

```powershell
sc.exe stop SecEoKnight-Proxy && sc.exe start SecEoKnight-Proxy
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

Both files already have `SERVER_IP = "192.168.1.63"` — leave as-is if that is your server.

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

Generate the CA into a shared confdir and import it directly — no browser or `mitm.it` step:
```powershell
New-Item -ItemType Directory -Force -Path "C:\SecEoKnight\mitm-confdir" | Out-Null
$proc = Start-Process -FilePath (Get-Command mitmdump).Source `
  -ArgumentList '--listen-host 127.0.0.1 --listen-port 8082 --set confdir="C:\SecEoKnight\mitm-confdir"' `
  -PassThru -WindowStyle Hidden

$cert = "C:\SecEoKnight\mitm-confdir\mitmproxy-ca-cert.cer"
$waited = 0
while (-not (Test-Path $cert) -and $waited -lt 30) { Start-Sleep -Seconds 1; $waited++ }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

Import-Certificate -FilePath $cert -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*mitmproxy*" }
```
The last line should print a certificate — that confirms it imported and is trusted.

> **Important:** this uses `--set confdir="C:\SecEoKnight\mitm-confdir"` for cert generation.
> The permanent Windows service you install in Step 5 must use the exact same `confdir` in its
> `AppParameters`, or it will generate and present a *different* CA than the one you just
> trusted — every HTTPS site will fail with a certificate-trust error once the permanent
> service takes over. This is the single most common cause of "internet stopped working after
> setup" on this project; keeping the confdir identical in both places is what fixes it.

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

If your server IP differs from `192.168.1.63`, no file editing needed — click the SecEoKnight
icon in the Chrome toolbar → **⚙ Change Server** → enter the correct IP and port →
**Save & Reconnect**. This is stored per-machine in the browser's own settings
(`chrome.storage.local`), read by `background.js`/`popup.js` at runtime.

---

## Deploying to 50 Endpoints with Group Policy (Mass Deploy)

For large-scale deployment without visiting each machine individually:

> **One shared CA, not 50 different ones.** `setup.ps1` generates a fresh, unique CA on each
> machine if `C:\SecEoKnight\mitm-confdir\` doesn't already exist there. Run it independently
> on 50 machines and you get 50 different CAs — the single certificate pushed in Step 1 below
> will only match the one machine it came from. To share one CA fleet-wide: run Option A once
> on a "template" machine, copy *that* machine's `mitm-confdir` folder (it holds the CA's
> private key, not just the `.cer`) into the network share in Step 2, and have the Step 3
> startup script copy it to `C:\SecEoKnight\mitm-confdir` **before** calling `setup.ps1` —
> since the cert file will already exist, the script reuses it instead of minting a new one.

### 1. Deploy the Certificate via Group Policy

This pushes the mitmproxy certificate to all domain computers automatically:
- Open **Group Policy Management** on your domain controller
- Computer Configuration → Windows Settings → Security Settings
- → Public Key Policies → Trusted Root Certification Authorities
- Right-click → **Import** → select `mitmproxy-ca-cert.cer` **from the shared `mitm-confdir`
  described above** — not a fresh one from an arbitrary machine

### 2. Create a Network Share

Put `setup.ps1`, `agent.py`, `to-server.py`, and the shared `mitm-confdir\` folder in a shared
folder accessible to all endpoints, e.g. `\\fileserver\SecEoKnight\`.

### 3. Create a Startup Script via Group Policy

- Computer Configuration → Windows Settings → Scripts → Startup
- Add a PowerShell startup script:

```powershell
# Copy files from network share, including the shared mitm-confdir so setup.ps1
# reuses the fleet-wide CA instead of generating a new one per machine
New-Item -ItemType Directory -Force -Path "C:\SecEoKnight" | Out-Null
Copy-Item "\\fileserver\SecEoKnight\agent.py"      "C:\SecEoKnight\" -Force
Copy-Item "\\fileserver\SecEoKnight\to-server.py"  "C:\SecEoKnight\" -Force
Copy-Item "\\fileserver\SecEoKnight\mitm-confdir"  "C:\SecEoKnight\" -Recurse -Force

# Run setup if services not already installed
if (-not (Get-Service SecEoKnight-Proxy -ErrorAction SilentlyContinue)) {
    & "\\fileserver\SecEoKnight\setup.ps1"
}
```

All 50 machines install the services on their next boot, reuse the same CA, and trust it
because the GPO in Step 1 already pushed that exact CA to their Trusted Root store.

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
sc.exe stop SecEoKnight-Proxy
sc.exe stop SecEoKnight-Logger
```

To resume:
```powershell
sc.exe start SecEoKnight-Proxy
sc.exe start SecEoKnight-Logger
```

---

## Fully Uninstalling SecEoKnight from an Endpoint

Run as Administrator:
```powershell
# Stop and remove services
sc.exe stop SecEoKnight-Proxy
sc.exe stop SecEoKnight-Logger
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
sc.exe query SecEoKnight-Proxy
Get-Content C:\SecEoKnight\Logs\proxy-error.log -Tail 30
```

Common causes: mitmdump not found (check PATH), agent.py missing, port 8082 in use.

### Websites Not Being Blocked

1. Confirm service is running: `sc.exe query SecEoKnight-Proxy` → must be RUNNING
2. Wait 30 seconds for blocklist refresh
3. Check proxy is set: `netsh winhttp show proxy`
4. Check browser proxy: Settings → Network → Proxy

### Endpoint Not Appearing in Dashboard

1. `sc.exe query SecEoKnight-Logger` — must be RUNNING
2. `Get-Content C:\SecEoKnight\Logs\logger-error.log -Tail 20` — check for connection errors
3. Verify server reachable: `Test-NetConnection -ComputerName 192.168.1.63 -Port 5001`

### Certificate Error in Chrome

1. Check whether the cert is actually installed:
   ```powershell
   Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*mitmproxy*" }
   ```
   Nothing printed → re-run `setup.ps1` as Administrator (cert import needs elevation).
2. If a cert IS listed but sites still fail, it may not match what `SecEoKnight-Proxy` is
   presenting. Confirm the service's `confdir` matches where the cert was generated:
   ```powershell
   & "C:\SecEoKnight\nssm.exe" get SecEoKnight-Proxy AppParameters
   ```
   Should include `--set confdir="C:\SecEoKnight\mitm-confdir"`. If it doesn't, or points
   elsewhere, fix it with `nssm set SecEoKnight-Proxy AppParameters "..."` and restart the
   service — see the "HTTPS sites showing SSL errors" section in `TROUBLESHOOTING.md` for details.
