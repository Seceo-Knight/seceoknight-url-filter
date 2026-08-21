# SecEoKnight — Security Backend

Enterprise-grade URL filtering and AI-powered threat detection for your SIEM.

---

## What This System Does

| Component | Where It Runs | What It Does |
|---|---|---|
| **Security Server** | Ubuntu 24.04 (192.168.1.63) | Stores all events, serves the blocklist, runs AI models, pushes alerts to your dashboard |
| **mitmproxy Agent** | Each Windows endpoint | Intercepts browser traffic, blocks URLs in real time |
| **Chrome Extension** | Each Windows endpoint | Detects phishing URLs using AI before the page loads |
| **Malware Scanner** | Each Windows endpoint | Watches Downloads folder, scans new files with AI CNN model, quarantines detected malware |
| **SIEM Dashboard** | Separate server *(built later)* | Shows alerts, events, stats, blocklist management |

> Setting this up somewhere you've already deployed it before, with a different server IP?
> Skip straight to [Deploying to a New Office / Different Server IP](#deploying-to-a-new-office--different-server-ip)
> — it's just 3 places to update, not a full redo of everything below.

---

## Network Architecture

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                    Your LAN (192.168.1.x)                       │
 │                                                                 │
 │  Windows Endpoint 1          ┌──────────────────────────┐       │
 │  ┌─────────────────┐         │   SECURITY SERVER        │       │
 │  │ mitmproxy       │─logs───▶│   Ubuntu 24.04           │       │
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
- Ubuntu 24.04 LTS (fresh install)
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

## Step 2 — Push This Project to Your GitHub

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

## Step 3 — Clone the Repo on the Server

```bash
sudo mkdir -p /opt/seceoknight
sudo chown $USER:$USER /opt/seceoknight
cd /opt/seceoknight

git clone https://github.com/Seceo-Knight/seceoknight-url-filter.git .
```

Confirm the malware models came down as real files (they're committed as regular Git objects,
not Git LFS pointers, so a plain clone downloads everything with no extra step):
```bash
ls -lh server/models/malware/
```
Expected: CNN.keras (~2 MB), ViT.keras (~7 MB), 1D-CNN-LSTM.keras (~6 MB)

---

## Step 4 — Run the Installer

Everything else — system packages, Python environment, training the phishing model,
the auto-start service, Nginx, the firewall, and the default blocklist — is one command:

```bash
sudo bash scripts/install.sh
```

This takes 10–20 minutes the first time (most of it is TensorFlow installing and the
phishing model training) — the script prints progress for each step as it goes, and tells
you exactly what to run if any step fails. It's also safe to re-run any time (after a
`git pull`, for example) — it checks what's already done and skips it rather than redoing
work or duplicating data.

If you'd rather understand or run each underlying step yourself instead of using the
script, they're documented individually in [docs/SERVER_SETUP.md](docs/SERVER_SETUP.md).

When it finishes, it prints your server's detected LAN IP and a few `curl` commands to
verify everything's running — run those now before moving on to Part 2.

It also generates an **API key** and saves it to `server/.env`, printing it once at the
end of the install. Every endpoint except `/health` expects this key in an `X-API-Key`
header — but it isn't enforced yet. The server starts in a "grace period": requests
without the key are still allowed through (just logged as a warning), so nothing breaks
on machines you haven't updated yet. Copy the printed key into:

- `endpoint/agent.py` and `endpoint/to-server.py` and `endpoint/malware_watcher.py` — set
  the `API_KEY` variable near the top of each
- The Chrome extension's popup → ⚙ Change Server → the API key field
- The SIEM dashboard backend's `.env` → `URL_FILTER_API_KEY`

Once every machine has been updated and you stop seeing `[AUTH] WARNING` lines in
`sudo journalctl -u seceoknight`, set `SECEOKNIGHT_REQUIRE_API_KEY=true` in
`server/.env` and `sudo systemctl restart seceoknight` to start actually rejecting
unauthenticated requests. Full details: [docs/API_REFERENCE.md](docs/API_REFERENCE.md#authentication).

---

## Step 5 — Managing the Blocklist (Add / Remove / Update Rules)

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

## Step 6 — Run Full Health Check

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

### Step 1 — Set Your GitHub Username and Server IP

Before running the script on any machine, open `endpoint/setup.ps1` in the repo and check
two lines near the top:
```powershell
$ServerIP = "192.168.1.63"      # <-- your security server's IP (Part 1's install.sh prints this)
```
```powershell
$RepoBase = "https://raw.githubusercontent.com/Seceo-Knight/seceoknight-url-filter/main/endpoint"
```
Set `$ServerIP` to whatever IP `install.sh` printed at the end of Part 1 (only needs
changing if you're not using the default `192.168.1.63`), and replace `Seceo-Knight` in
`$RepoBase` with your actual GitHub username. Then push:
```bash
git add endpoint/setup.ps1
git commit -m "Set server IP and GitHub username in setup.ps1"
git push
```
`setup.ps1` automatically writes this IP into `agent.py`, `to-server.py`, and
`malware_watcher.py` on every machine it runs on — you only ever set it in this one place.

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
   - Generate a mitmproxy CA certificate (shared `C:\SecEoKnight\mitm-confdir\`) and
     automatically install it into the Windows Trusted Root store — no browser step needed
   - Install **SecEoKnight-Proxy** as a Windows Service (mitmproxy + agent.py)
   - Install **SecEoKnight-Logger** as a Windows Service (to-server.py)
   - Install **SecEoKnight-Scanner** as a Windows Service (malware_watcher.py)
   - Set machine-wide proxy to route all browser traffic through mitmproxy

5. **Certificate installation is fully automatic** *(critical — HTTPS blocking won't work without this, but you don't need to do anything)*

   `setup.ps1` briefly runs mitmproxy in the background with `--set confdir="C:\SecEoKnight\mitm-confdir"`
   to generate a CA certificate, then imports it directly into `Cert:\LocalMachine\Root` with
   `Import-Certificate` and verifies the import by re-reading the cert store. You'll see:
   ```
   Certificate installed and verified in Trusted Root (thumbprint: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)
   ```
   No browser step, no `mitm.it`, nothing to click through. This CA is also what the permanent
   `SecEoKnight-Proxy` Windows Service uses (it's started with the same `--set confdir=...` flag),
   so there's no mismatch between the cert you installed and the cert the running service presents —
   that mismatch used to be the #1 cause of "internet stopped working after setup" on this project;
   it's fixed at the source now.

   If the script reports the certificate could not be verified, re-run it as Administrator —
   that's almost always a missing-elevation issue, not a mitmproxy problem.

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

Use a shared `confdir` for cert generation so it matches what the Windows Service will use later
in Step 5 — this is important, mixing confdirs is what causes "HTTPS stopped working after setup".

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
The last command should print a certificate — that confirms it's installed and trusted.

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

# Proxy service — must use the SAME confdir as Step 4, otherwise the service
# generates its own CA and the certificate you installed won't match it.
& $nssm install SecEoKnight-Proxy $mitmdump
& $nssm set SecEoKnight-Proxy AppParameters "--listen-host 0.0.0.0 --listen-port 8082 --set confdir=`"C:\SecEoKnight\mitm-confdir`" -s `"C:\SecEoKnight\agent.py`""
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

> **Important — one shared CA, not 50 different ones.** `setup.ps1` generates a fresh,
> unique CA certificate on each machine if none exists yet in its `C:\SecEoKnight\mitm-confdir\`.
> If you run it independently on 50 machines, you get 50 different CAs — and a GPO that pushes
> just *one* `mitmproxy-ca-cert.cer` will only match the one machine it came from. To use a
> single shared CA across the fleet (so the GPO import in Step 2 below actually works everywhere):
> 1. Run Option A on one "template" machine first, so it generates the CA.
> 2. Copy that machine's `C:\SecEoKnight\mitm-confdir\` folder (it contains the CA's private key,
>    not just the `.cer`) into the network share alongside `setup.ps1`.
> 3. Have the Step 3 startup script below copy `mitm-confdir` into `C:\SecEoKnight\` **before**
>    running `setup.ps1` — since the CA file will already exist, `setup.ps1` skips generation and
>    reuses the shared one instead of minting a new CA per machine.

### Step 2 — Deploy the mitmproxy Certificate via Group Policy

Open **Group Policy Management** on your domain controller:
- Computer Configuration → Windows Settings → Security Settings
- → Public Key Policies → Trusted Root Certification Authorities
- Right-click → Import → select the `mitmproxy-ca-cert.cer` file **from the shared `mitm-confdir`
  generated in the note above** (not a fresh/unrelated one)

This automatically installs the certificate on all domain computers.

### Step 3 — Create a Startup Script via Group Policy

- Computer Configuration → Windows Settings → Scripts → Startup
- Add a PowerShell script:
  ```powershell
  # Copy files from network share, including the shared mitm-confdir
  # (must exist BEFORE setup.ps1 runs so it reuses the CA instead of generating a new one)
  Copy-Item "\\fileserver\SecEoKnight\*" "C:\SecEoKnight\" -Recurse -Force

  # Run setup (silent mode)
  & "C:\SecEoKnight\setup.ps1"
  ```

All 50 machines run the script on next boot, reuse the same CA, and trust it because the GPO in
Step 2 already pushed that exact CA to their Trusted Root store.

---

---

# PART 3 — Chrome Extension Setup

The Chrome extension adds AI-powered phishing detection directly in the browser.
It checks every URL you visit against the SecEoKnight AI model in the background —
no delay on normal browsing. If a phishing site is detected, a warning banner
appears on the page and the alert is logged on the security server.

Install this on each endpoint after Part 2.

### Step 1 — Install on Each Windows Machine

No file editing needed — the server address is set from the extension's own popup after
install (Step 2), not by hand-editing JavaScript. On each Windows machine:

1. Get the extension files onto the machine (PowerShell, no admin needed):
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/Seceo-Knight/seceoknight-url-filter/archive/refs/heads/main.zip" -OutFile "$env:TEMP\seceoknight.zip"
   Expand-Archive "$env:TEMP\seceoknight.zip" "$env:TEMP\seceoknight-repo" -Force
   ```
   That gives you `%TEMP%\seceoknight-repo\seceoknight-url-filter-main\extension\`.

2. Open **Google Chrome**

3. Go to: `chrome://extensions/`

4. Turn on **Developer mode** — toggle in the top-right corner

5. Click **Load unpacked**

6. Select that `extension` folder

7. The **SecEoKnight** shield icon appears in the Chrome toolbar ✓

> This is fine for testing on one or a few machines. For rolling out to all 50 endpoints,
> package the extension as a signed `.crx` and push it via Group Policy's
> `ExtensionInstallForcelist` instead — no Developer Mode or per-machine clicking needed.

### Step 2 — Set the Server Address

Click the SecEoKnight icon in the Chrome toolbar → **⚙ Change Server** → enter your
server's IP (or hostname) and port → **Save & Reconnect**. This is stored per-machine in
the browser's own settings — it's the only place the server address lives for the
extension, and it's why deploying to a different office never requires editing
`background.js` or `popup.js` by hand.

On first install, it defaults to `192.168.1.63:5001` — if that's already your server's
address, you can skip this step entirely.

The same panel has an **API key** field. Paste in the key `install.sh` printed on the
server. It's optional while the server is still in its auth grace period, but once
`SECEOKNIGHT_REQUIRE_API_KEY=true` is set server-side, the popup and phishing detection
will stop working on this machine until the key is entered here.

### Step 3 — Verify It Works

Click the SecEoKnight icon in the Chrome toolbar. The popup shows:
- **Server Online** — green dot means it is connected to your security server
- **Total Blocks** — count of blocked URLs across all endpoints
- **AI Detections** — count of AI-detected phishing threats

Visit any website — the extension silently checks it in the background.
If phishing is detected, a red or orange banner appears at the top of the page
and the event is logged to the server automatically.

---

## Deploying the Extension via Group Policy (Recommended for 50 Machines)

Steps 1–3 above (Developer Mode, "Load Unpacked") are fine for testing on one machine, but
don't scale — Developer Mode has to stay on, and updating the extension means re-running
those PowerShell commands and reloading it by hand on every single machine. Group Policy's
`ExtensionInstallForcelist` installs and auto-updates the extension silently on every
managed machine instead, with no Developer Mode and no per-machine clicking.

### Step 1 — Package and Sign the Extension

Run this once, on the security server (it needs Node.js — `sudo apt-get install -y nodejs npm`
if not already present):

```bash
cd /opt/seceoknight/seceoknight-url-filter
bash scripts/package_extension.sh "http://192.168.1.63/extension/seceoknight.crx"
```

This generates a signing key (`extension/key.pem` — **back this up somewhere safe outside
git**; it's what keeps the extension's ID stable across future updates) and produces two
files in `extension-dist/`: `seceoknight.crx` (the signed extension) and `update.xml` (what
Chrome polls to check for updates). Nginx already serves both at `/extension/` once
`install.sh` has run — nothing else to configure.

The script prints an **Extension ID** and a ready-to-use Group Policy entry, e.g.:
```
Extension ID: eankdkjalbldacabieglehonpaiplffe
Group Policy ExtensionInstallForcelist entry:
eankdkjalbldacabieglehonpaiplffe;http://192.168.1.63/extension/update.xml
```
Save that line — you'll paste it into Group Policy in Step 2.

Verify the files are reachable before continuing:
```bash
curl -sI http://192.168.1.63/extension/update.xml
curl -sI http://192.168.1.63/extension/seceoknight.crx
```
Both should return `HTTP/1.1 200 OK`.

### Step 2 — Configure Group Policy

**If you manage machines with Active Directory / Group Policy Management Console:**

1. Open **Group Policy Management** → edit the GPO already used for this rollout (the one
   from "Deploying to All 50 Endpoints with Group Policy" above)
2. Navigate to: **Computer Configuration → Administrative Templates → Google → Google
   Chrome → Extensions → Configure the list of force-installed apps and extensions**
3. Set it to **Enabled**
4. Click **Show...** and add the exact line the script printed, e.g.:
   ```
   eankdkjalbldacabieglehonpaiplffe;http://192.168.1.63/extension/update.xml
   ```
5. **OK** → close the editor. Machines pick this up on their next policy refresh (or run
   `gpupdate /force` on a machine to apply immediately).

**If these machines aren't domain-joined** (standalone / workgroup), set the equivalent
registry value directly — this can go in the same startup script used for the mitmproxy
certificate deployment above:
```powershell
$path = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "1" -Value "eankdkjalbldacabieglehonpaiplffe;http://192.168.1.63/extension/update.xml"
```
(Replace the ID/URL with what your own `package_extension.sh` run printed — the ID above is
just an example and won't match your signing key.)

### Step 3 — Verify

On a test machine, either wait for policy refresh or force it:
```powershell
gpupdate /force
```
Open `chrome://extensions/` — the SecEoKnight extension should appear automatically,
**greyed out with no remove/disable option** (that's normal — it means policy is managing
it, not a bug) and **without** Developer Mode needing to be on.

### Shipping an Update Later

1. Make your code change, bump the version in `extension/manifest.json`
2. Re-run `bash scripts/package_extension.sh "http://192.168.1.63/extension/seceoknight.crx"`
   on the server (reuses the same signing key automatically — the extension ID doesn't change)
3. That's it — Chrome checks `update.xml` on its own schedule (typically within a few hours)
   and updates silently on every machine. No PowerShell, no manual reload, no GPO changes
   needed unless the extension ID itself changed (which only happens if the signing key is
   lost and regenerated).

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

# Deploying to a New Office / Different Server IP

Setting this up again somewhere else — a new office, a new network, a server that got a
different IP than last time? Everything in this system gets its server address from
exactly **three** places. Update these three and nothing else needs to change:

| # | Where | What to change | Applies to |
|---|---|---|---|
| 1 | `install.sh` | Nothing — the server doesn't need to know its own IP. It just binds to all network interfaces. | The server itself |
| 2 | `endpoint/setup.ps1`, top of the file | `$ServerIP = "..."` — one line, before running the script on any endpoint | All 50 Windows machines |
| 3 | Chrome extension popup, on each machine | Click the icon → **⚙ Change Server** → type the new IP → Save | The Chrome extension |

**Nothing else needs editing.** Specifically:
- `nginx/seceoknight.conf` doesn't reference an IP at all (`server_name _;` accepts any).
- `agent.py`, `to-server.py`, and `malware_watcher.py` don't need hand-editing — `setup.ps1`
  automatically writes the IP from step 2 into all three of them on every machine it runs on.
- The extension's `background.js`/`popup.js` don't need hand-editing or reloading — the
  address is stored in the browser's own settings (`chrome.storage.local`), set once per
  machine from the popup in step 3.

**Practical order of operations for a fresh office:**
1. Provision the new Ubuntu server, clone the repo, run `sudo bash scripts/install.sh` (Part 1).
   It prints the detected LAN IP at the end — that's your new server address.
2. Edit `$ServerIP` in `endpoint/setup.ps1` to that address, commit, push to GitHub (Part 2,
   Option A Step 1).
3. Run `setup.ps1` on each Windows machine as usual (Part 2) — the new IP is baked in
   automatically.
4. Install the Chrome extension as usual (Part 3) — if the new IP isn't `192.168.1.63`
   (the shipped default), open the popup once per machine and set it via **⚙ Change Server**.

**If you don't have a fixed IP at all** (e.g. the server gets a new DHCP-assigned address
on every reboot), the real fix is giving it a static IP or DNS hostname at the network
level — this system has no way to "auto-discover" a server that keeps moving without one
of those, the same as any other client-server application.

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

# Update from GitHub (code-only changes)
cd /opt/seceoknight
git pull
sudo systemctl restart seceoknight

# If the update touched requirements.txt, systemd/, or nginx/ instead of just
# application code, re-run the installer so those get picked up too:
#   sudo bash scripts/install.sh

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
| AI shows `not_loaded` | `cd /opt/seceoknight && source venv/bin/activate && python3 scripts/train_phishing_model.py`, then `sudo systemctl restart seceoknight` |
| Endpoint not appearing in list | Run `sc.exe query SecEoKnight-Logger` (not plain `sc` — PowerShell aliases that to `Set-Content`) — must show RUNNING; check server IP |
| Malware scanner not running | Run `Get-Service SecEoKnight-Scanner` — check `C:\SecEoKnight\Logs\scanner-error.log` |
| File not quarantined | Check file extension is in scan list and size is over 512 bytes |
| Websites not being blocked | Wait 30 seconds; check proxy is ON in Windows Settings |
| Certificate install failed during setup | Re-run `setup.ps1` as Administrator — cert import needs elevation |
| Certificate error in Chrome | Re-install mitmproxy certificate as Local Machine (not Current User) |

Full troubleshooting guide: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

---

# Project Files Reference

```
SeceoKnight-backend/
├── server/                        ← Runs on Ubuntu security server
│   ├── unified_server.py          ← Main API server (FastAPI)
│   ├── auth.py                    ← API key authentication (grace-period rollout)
│   ├── database.py                ← SQLite database logic
│   ├── ai_engine.py               ← Phishing + malware AI detection
│   ├── websocket_manager.py       ← Real-time alerts to dashboard
│   ├── .env                       ← Generated by install.sh — API key, NOT committed to git
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
├── extension/                     ← Chrome extension source
│   ├── key.pem                    ← Signing key, generated once, NOT committed to git
│   └── ...
├── extension-dist/                ← Built by package_extension.sh — .crx + update.xml, NOT committed
│
├── scripts/                       ← Run on security server
│   ├── install.sh                 ← One-shot server installer
│   ├── package_extension.sh       ← Signs the extension for Group Policy force-install
│   ├── crx_tool/                  ← Node helper package_extension.sh calls internally
│   ├── train_phishing_model.py    ← Trains the BiLSTM phishing model
│   ├── add_default_blocklist.py   ← Seeds enterprise blocklist rules
│   ├── health_check.sh            ← Verifies everything is working
│   └── data/phishing.csv          ← 95,980 training samples (included)
│
├── nginx/
│   └── seceoknight.conf           ← Nginx reverse proxy config (ready to use, includes /extension/)
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
Optional query param: `from_ts` (ISO datetime) — scopes all volume metrics to events at or
after this time, used for the dashboard's 12h/24h/3d/7d/30d/60d/90d range toggle. Omit it and
every field below is **all-time** (all events ever recorded), not a rolling window — the one
exception is `hourly_activity`, which defaults to the last 24h specifically when `from_ts` is
omitted (see `get_stats()` in `server/database.py`).

Response:
```json
{
  "total_requests": 48291,
  "total_blocked": 1204,
  "total_allowed": 47087,
  "ai_phishing": 22,
  "ai_malware": 15,
  "active_endpoints": 12,
  "today_blocked": 340,
  "top_blocked_domains": [
    {"host": "facebook.com", "cnt": 412},
    {"host": "instagram.com", "cnt": 289}
  ],
  "hourly_activity": [
    {"hour": "2024-01-15T09:00:00", "total": 120, "blocked": 5}
  ],
  "block_type_breakdown": [
    {"block_type": "host", "cnt": 200},
    {"block_type": "ai_phishing", "cnt": 12}
  ]
}
```
> Note: field names are `total_blocked` / `total_allowed` / `ai_phishing` / `ai_malware` /
> `top_blocked_domains` — not `blocked_requests` / `allowed_requests` / `ai_detections` /
> `top_blocked_hosts` as shown in some older references. Match your dashboard code to the
> field names above (see `server/database.py`'s `get_stats()` for the source of truth).

---

### 🖥️ Endpoints — Endpoint Monitor

#### List all endpoints
```http
GET /api/endpoints
```
`status` is computed live — `active` if a heartbeat or event arrived within the last
`STALE_THRESHOLD_MINUTES` (3 min), `inactive` otherwise. It's not a static stored flag.

Response:
```json
[
  {
    "id": 1,
    "ip": "192.168.1.105",
    "hostname": "DESKTOP-A1B2C3",
    "status": "active",
    "last_seen": "2024-01-15T14:30:00",
    "total_requests": 2341,
    "total_blocked": 88,
    "agent_version": "1.1.0"
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
  "endpoint": {"ip": "192.168.1.105", "hostname": "DESKTOP-A1B2C3", "status": "active", "agent_version": "1.1.0", ...},
  "recent_events": [...]
}
```
> `recent_events` matches on `endpoint_ip` (the machine's real LAN IP, self-reported by the
> agent) OR `client_ip`. For locally-proxied traffic `client_ip` is almost always `127.0.0.1`
> since mitmproxy runs on the same machine as the browser — `endpoint_ip` is the field that
> actually identifies which machine an event came from.

#### Heartbeat (internal — sent by `to-server.py`, not called by the dashboard)
```http
POST /api/heartbeat
```
```json
{"ip": "192.168.1.105", "hostname": "DESKTOP-A1B2C3", "agent_version": "1.1.0"}
```
Every endpoint pings this every 60 seconds regardless of browsing activity — this is what
makes `active`/`inactive` status reflect reality instead of going stale once traffic stops.

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
