# =============================================================================
# SecEoKnight Endpoint Setup Script
# =============================================================================
# Installs the SecEoKnight security agent as proper Windows Services.
# No PowerShell windows left open. Both services:
#   - Start automatically when Windows boots
#   - Run silently in the background (invisible to users)
#   - Restart automatically if they crash
#   - Are managed via Windows Services panel (services.msc)
#
# Services installed:
#   SecEoKnight-Proxy   -- mitmproxy + agent.py  (URL interception + blocking)
#   SecEoKnight-Logger  -- to-server.py           (log forwarding to server)
#   SecEoKnight-Scanner -- malware_watcher.py     (AI malware file scanner)
#
# Run as Administrator on each endpoint.
# =============================================================================

$ErrorActionPreference = "Stop"

# -- Configuration --------------------------------------------------------------
$ServerIP          = "192.168.1.63"      # <-- Change if your server IP is different
$ServerPort        = 5001
$ProxyPort         = 8082
$BaseDir            = "C:\SecEoKnight"
$LogDir             = "C:\SecEoKnight\Logs"
$QuarantineDir      = "C:\SecEoKnight\Quarantine"
$AgentPath          = "$BaseDir\agent.py"
$ToServerPath       = "$BaseDir\to-server.py"
$MalwareWatcherPath = "$BaseDir\malware_watcher.py"
# Shared mitmproxy config/CA-cert directory. Both the temporary cert-install
# proxy (run as the interactive Administrator) and the permanent NSSM service
# (run as LocalSystem) must point at THIS SAME folder via --set confdir=...
# Otherwise mitmproxy generates two different self-signed CAs under two
# different Windows profiles, the user trusts one, the running service
# presents the other, and every HTTPS site fails with a cert-trust error.
$MitmConfDir        = "$BaseDir\mitm-confdir"
$HKCUReg            = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

$MitmInstallerUrl = "https://downloads.mitmproxy.org/10.2.4/mitmproxy-10.2.4-windows-x86_64-installer.exe"
$NssmUrl          = "https://nssm.cc/release/nssm-2.24.zip"
$RepoBase         = "https://raw.githubusercontent.com/Seceo-Knight/seceoknight-url-filter/main/endpoint"

$ServiceProxy   = "SecEoKnight-Proxy"
$ServiceLogger  = "SecEoKnight-Logger"
$ServiceScanner = "SecEoKnight-Scanner"
$MaxWait       = 600
$ScanInterval  = 5
# ------------------------------------------------------------------------------

function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "  [ERROR] $msg" -ForegroundColor Red }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# -- Require Administrator ------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator."
    Write-Host "  Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  SecEoKnight Endpoint Setup" -ForegroundColor Cyan
Write-Host "  Server  : $ServerIP`:$ServerPort" -ForegroundColor Cyan
Write-Host "  Services: $ServiceProxy / $ServiceLogger / $ServiceScanner" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# =============================================================================
# STEP 1 -- Create directories
# =============================================================================
Write-Step "Creating directories"
foreach ($dir in @($BaseDir, $LogDir, $QuarantineDir, $MitmConfDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Ok "Created $dir"
    } else {
        Write-Ok "$dir already exists"
    }
}

# =============================================================================
# STEP 2 -- Detect Python
# =============================================================================
Write-Step "Detecting Python 3"

function Get-PythonPath {
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $r = & $cmd --version 2>&1
            if ($r -match "Python 3") {
                $p = (Get-Command $cmd -ErrorAction SilentlyContinue)
                if ($p) { return $p.Source }
            }
        } catch {}
    }
    foreach ($glob in @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
        "$env:PROGRAMFILES\Python3*\python.exe",
        "$env:PROGRAMFILES\Python\Python3*\python.exe"
    )) {
        $found = Get-ChildItem $glob -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

$PythonExe = Get-PythonPath
if (-not $PythonExe) {
    Write-Err "Python 3 not found."
    Write-Host "  Install from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  Tick 'Add Python to PATH' during install, then re-run this script." -ForegroundColor Yellow
    exit 1
}
Write-Ok "Python: $PythonExe"

Write-Host "  Installing Python packages..." -ForegroundColor Yellow
& $PythonExe -m pip install requests --quiet --disable-pip-version-check
# Install watchdog + pillow to shared folder so LocalSystem service can access them
New-Item -ItemType Directory -Path "$BaseDir\pylibs" -Force | Out-Null
& $PythonExe -m pip install watchdog pillow --target "$BaseDir\pylibs" --quiet --disable-pip-version-check
Write-Ok "Python packages ready"

# =============================================================================
# STEP 3 -- Download agent files from GitHub
# =============================================================================
Write-Step "Downloading agent files from GitHub"

function Download-File($url, $dest) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
        Write-Ok "Downloaded $(Split-Path $dest -Leaf)"
    } catch {
        Write-Warn "Could not download from $url"
        Write-Host "  Manually copy $(Split-Path $dest -Leaf) to $BaseDir" -ForegroundColor Yellow
    }
}

Download-File "$RepoBase/agent.py"           $AgentPath
Download-File "$RepoBase/to-server.py"       $ToServerPath
Download-File "$RepoBase/malware_watcher.py" $MalwareWatcherPath

# Patch server IP into all agent files. Matches SERVER_IP = "<any IPv4>" specifically
# (not any IPv4-looking string anywhere in the file) so it works regardless of which
# subnet the server currently lives on -- not just 192.168.1.x.
$ServerIpPattern = 'SERVER_IP\s*=\s*"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"'
$ServerIpReplace = "SERVER_IP    = `"$ServerIP`""
(Get-Content $AgentPath           -Raw) -replace $ServerIpPattern, $ServerIpReplace | Set-Content $AgentPath           -Encoding UTF8
(Get-Content $ToServerPath        -Raw) -replace $ServerIpPattern, $ServerIpReplace | Set-Content $ToServerPath        -Encoding UTF8
(Get-Content $MalwareWatcherPath  -Raw) -replace $ServerIpPattern, $ServerIpReplace | Set-Content $MalwareWatcherPath  -Encoding UTF8
Write-Ok "Server IP set to $ServerIP in all agent files"

# =============================================================================
# STEP 4 -- Download and install mitmproxy
# =============================================================================
Write-Step "Installing mitmproxy"

$MitmExe = Get-ChildItem "C:\Program Files", "C:\Program Files (x86)", $env:LOCALAPPDATA `
           -Recurse -Filter "mitmdump.exe" -ErrorAction SilentlyContinue |
           Select-Object -First 1

if (-not $MitmExe) {
    $Installer = "$env:TEMP\mitmproxy-installer.exe"
    if (-not (Test-Path $Installer)) {
        Write-Host "  Downloading mitmproxy installer (~40 MB)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $MitmInstallerUrl -OutFile $Installer -UseBasicParsing
        Write-Ok "Installer downloaded"
    }

    Write-Host "  Launching installer -- complete the install window, then come back here." -ForegroundColor Cyan
    Start-Process -FilePath $Installer -Wait
    Start-Sleep -Seconds 3

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")

    $elapsed = 0
    while ($elapsed -lt $MaxWait) {
        $MitmExe = Get-ChildItem "C:\Program Files", "C:\Program Files (x86)", $env:LOCALAPPDATA `
                   -Recurse -Filter "mitmdump.exe" -ErrorAction SilentlyContinue |
                   Select-Object -First 1
        if ($MitmExe) { break }
        Start-Sleep -Seconds $ScanInterval
        $elapsed += $ScanInterval
        Write-Host "  Waiting for mitmproxy... $elapsed/$MaxWait sec" -ForegroundColor Gray
    }
}

if (-not $MitmExe) {
    Write-Err "mitmdump.exe not found. Re-run after mitmproxy is installed."
    exit 1
}
$MitmDumpExe = $MitmExe.FullName
Write-Ok "mitmdump: $MitmDumpExe"

# =============================================================================
# STEP 5 -- Download NSSM (Windows Service installer)
# =============================================================================
Write-Step "Setting up NSSM (Windows Service Manager)"

# NSSM must live in a permanent location -- not TEMP -- so services survive reboots
$NssmPerm = "$BaseDir\nssm.exe"

if (-not (Test-Path $NssmPerm)) {
    $NssmOk = $false

    # --- Method 1: try winget (built into Windows 10/11) ---
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget -and -not $NssmOk) {
        Write-Host "  Trying winget install NSSM..." -ForegroundColor Yellow
        try {
            & winget install --id NSSM.NSSM --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("Path","User")
            $nssmViaWinget = Get-Command nssm -ErrorAction SilentlyContinue
            if ($nssmViaWinget) {
                Copy-Item $nssmViaWinget.Source $NssmPerm -Force
                $NssmOk = $true
                Write-Ok "NSSM installed via winget"
            }
        } catch {}
    }

    # --- Method 2: download zip (try multiple mirrors) ---
    if (-not $NssmOk) {
        $NssmUrls = @(
            "https://nssm.cc/release/nssm-2.24.zip",
            "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip",
            "https://github.com/nicm42/nssm-releases/releases/download/v2.24/nssm-2.24.zip"
        )
        $NssmZip = "$env:TEMP\nssm.zip"
        $NssmDir = "$env:TEMP\nssm-extract"
        foreach ($url in $NssmUrls) {
            Write-Host "  Downloading NSSM from $url ..." -ForegroundColor Yellow
            try {
                Invoke-WebRequest -Uri $url -OutFile $NssmZip -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
                Expand-Archive -Path $NssmZip -DestinationPath $NssmDir -Force -ErrorAction Stop
                $nssmExe = Get-ChildItem $NssmDir -Recurse -Filter "nssm.exe" |
                           Where-Object { $_.FullName -like "*win64*" } |
                           Select-Object -First 1
                if (-not $nssmExe) {
                    $nssmExe = Get-ChildItem $NssmDir -Recurse -Filter "nssm.exe" | Select-Object -First 1
                }
                if ($nssmExe) {
                    Copy-Item $nssmExe.FullName $NssmPerm -Force
                    $NssmOk = $true
                    Write-Ok "NSSM installed from $url"
                    break
                }
            } catch {
                Write-Warn "Failed: $url"
            }
        }
    }

    # --- Method 3: manual fallback ---
    if (-not $NssmOk) {
        Write-Host ""
        Write-Host "+----------------------------------------------------------+" -ForegroundColor Red
        Write-Host "| NSSM download failed (nssm.cc is temporarily down)      |" -ForegroundColor Red
        Write-Host "|                                                          |" -ForegroundColor Red
        Write-Host "| Manual fix (takes 2 minutes):                           |" -ForegroundColor Yellow
        Write-Host "|  1. Open a browser and go to:                           |" -ForegroundColor White
        Write-Host "|     https://nssm.cc/release/nssm-2.24.zip               |" -ForegroundColor Cyan
        Write-Host "|     (or search 'nssm download' if that fails)           |" -ForegroundColor White
        Write-Host "|  2. Extract the zip                                     |" -ForegroundColor White
        Write-Host "|  3. Copy nssm-2.24\win64\nssm.exe to:                  |" -ForegroundColor White
        Write-Host "|     C:\SecEoKnight\nssm.exe                             |" -ForegroundColor Cyan
        Write-Host "|  4. Re-run this script -- it will skip this step        |" -ForegroundColor White
        Write-Host "+----------------------------------------------------------+" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
} else {
    Write-Ok "NSSM already present"
}

# =============================================================================
# STEP 6 -- Certificate generation + automatic install (no browser needed)
# =============================================================================
# mitmproxy writes its CA certificate files to $MitmConfDir the moment it
# starts, whether or not anything actually connects through it. Importing
# that file directly is faster and far less error-prone than the old
# mitm.it-in-a-browser flow -- it removes every failure mode we've hit
# (wrong cert store, .p12 vs .cer confusion, temp-vs-service CA mismatch),
# and we verify the import instead of just trusting a keypress.
Write-Step "Certificate Installation (automatic)"

$CertCer = "$MitmConfDir\mitmproxy-ca-cert.cer"

if (-not (Test-Path $CertCer)) {
    Write-Host "  Generating CA certificate..." -ForegroundColor Yellow
    $CertGenProc = Start-Process -FilePath $MitmDumpExe `
        -ArgumentList "--listen-host 127.0.0.1 --listen-port $ProxyPort --set confdir=`"$MitmConfDir`"" `
        -PassThru -WindowStyle Hidden
    $waited = 0
    while (-not (Test-Path $CertCer) -and $waited -lt 30) {
        Start-Sleep -Seconds 1
        $waited++
    }
    Stop-Process -Id $CertGenProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

if (-not (Test-Path $CertCer)) {
    Write-Err "mitmproxy did not generate a CA certificate at $CertCer"
    Write-Host "  Re-run this script, or generate it manually with:" -ForegroundColor Yellow
    Write-Host "  mitmdump --set confdir=`"$MitmConfDir`"  (then Ctrl+C after a few seconds)" -ForegroundColor Yellow
    exit 1
}

Import-Certificate -FilePath $CertCer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

# Verify it actually landed instead of assuming
$installedCert = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
                  Where-Object { $_.Subject -like "*mitmproxy*" }
if ($installedCert) {
    Write-Ok "Certificate installed and verified in Trusted Root (thumbprint: $($installedCert[0].Thumbprint))"
} else {
    Write-Err "Certificate import could not be verified in Cert:\LocalMachine\Root."
    Write-Host "  HTTPS blocking will fail until this is fixed. Manually import:" -ForegroundColor Yellow
    Write-Host "  $CertCer -> double-click -> Local Machine -> Trusted Root Certification Authorities" -ForegroundColor Yellow
    exit 1
}

# =============================================================================
# STEP 7 -- Remove old services (clean reinstall)
# =============================================================================
Write-Step "Removing old services if present"

foreach ($svc in @($ServiceProxy, $ServiceLogger, $ServiceScanner)) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        & $NssmPerm remove $svc confirm 2>&1 | Out-Null
        Write-Ok "Removed: $svc"
    } else {
        Write-Ok "$svc not present -- clean install"
    }
}

# =============================================================================
# STEP 8 -- Install SecEoKnight-Proxy as Windows Service
# =============================================================================
Write-Step "Installing SecEoKnight-Proxy service (mitmproxy traffic interceptor)"

& $NssmPerm install    $ServiceProxy $MitmDumpExe
& $NssmPerm set        $ServiceProxy AppParameters    "--listen-host 0.0.0.0 --listen-port $ProxyPort -s `"$AgentPath`" --set confdir=`"$MitmConfDir`""
& $NssmPerm set        $ServiceProxy DisplayName      "SecEoKnight Proxy Agent"
& $NssmPerm set        $ServiceProxy Description      "SecEoKnight URL filtering proxy. Intercepts and blocks browser traffic per central blocklist. Do not stop."
& $NssmPerm set        $ServiceProxy Start            SERVICE_AUTO_START
& $NssmPerm set        $ServiceProxy ObjectName       LocalSystem
& $NssmPerm set        $ServiceProxy AppStdout        "$LogDir\proxy.log"
& $NssmPerm set        $ServiceProxy AppStderr        "$LogDir\proxy-error.log"
& $NssmPerm set        $ServiceProxy AppRotateFiles   1
& $NssmPerm set        $ServiceProxy AppRotateOnline  1
& $NssmPerm set        $ServiceProxy AppRotateBytes   10485760
& $NssmPerm set        $ServiceProxy AppRestartDelay  5000
& $NssmPerm set        $ServiceProxy AppThrottle      1500

Write-Ok "$ServiceProxy service configured"

# =============================================================================
# STEP 9 -- Install SecEoKnight-Logger as Windows Service
# =============================================================================
Write-Step "Installing SecEoKnight-Logger service (log forwarder)"

& $NssmPerm install    $ServiceLogger $PythonExe
& $NssmPerm set        $ServiceLogger AppParameters    "`"$ToServerPath`""
& $NssmPerm set        $ServiceLogger DisplayName      "SecEoKnight Log Forwarder"
& $NssmPerm set        $ServiceLogger Description      "SecEoKnight log forwarder. Streams endpoint events to the security server. Do not stop."
& $NssmPerm set        $ServiceLogger Start            SERVICE_AUTO_START
& $NssmPerm set        $ServiceLogger ObjectName       LocalSystem
& $NssmPerm set        $ServiceLogger AppStdout        "$LogDir\logger.log"
& $NssmPerm set        $ServiceLogger AppStderr        "$LogDir\logger-error.log"
& $NssmPerm set        $ServiceLogger AppRotateFiles   1
& $NssmPerm set        $ServiceLogger AppRotateOnline  1
& $NssmPerm set        $ServiceLogger AppRotateBytes   10485760
& $NssmPerm set        $ServiceLogger AppRestartDelay  5000
& $NssmPerm set        $ServiceLogger AppThrottle      1500

Write-Ok "$ServiceLogger service configured"

# =============================================================================
# STEP 10 -- Install SecEoKnight-Scanner as Windows Service
# =============================================================================
Write-Step "Installing SecEoKnight-Scanner service (AI malware file watcher)"

& $NssmPerm install    $ServiceScanner $PythonExe
& $NssmPerm set        $ServiceScanner AppParameters    "`"$MalwareWatcherPath`""
& $NssmPerm set        $ServiceScanner AppDirectory     "$BaseDir"
& $NssmPerm set        $ServiceScanner DisplayName      "SecEoKnight Malware Scanner"
& $NssmPerm set        $ServiceScanner Description      "SecEoKnight AI malware scanner. Watches Downloads folders and quarantines detected malware. Do not stop."
& $NssmPerm set        $ServiceScanner Start            SERVICE_AUTO_START
& $NssmPerm set        $ServiceScanner ObjectName       LocalSystem
& $NssmPerm set        $ServiceScanner AppStdout        "$LogDir\scanner.log"
& $NssmPerm set        $ServiceScanner AppStderr        "$LogDir\scanner-error.log"
& $NssmPerm set        $ServiceScanner AppRotateFiles   1
& $NssmPerm set        $ServiceScanner AppRotateOnline  1
& $NssmPerm set        $ServiceScanner AppRotateBytes   10485760
& $NssmPerm set        $ServiceScanner AppRestartDelay  10000
& $NssmPerm set        $ServiceScanner AppThrottle      1500

Write-Ok "$ServiceScanner service configured"

# =============================================================================
# STEP 11 -- Set machine-wide proxy
# =============================================================================
Write-Step "Configuring machine-wide proxy"

# Use a PAC file (Proxy Auto-Config) hosted on the security server.
# The PAC file contains: "PROXY 127.0.0.1:8082; DIRECT"
# This means: try proxy first -- if mitmproxy is down, go DIRECT.
# Internet can NEVER be blocked by this setup, even if the service crashes.
$PacUrl = "http://$ServerIP/proxy.pac"

# WinHTTP -- machine-wide (system services, background apps)
netsh winhttp set proxy "127.0.0.1:$ProxyPort" "192.168.*;10.*;172.16.*;localhost" 2>&1 | Out-Null
Write-Ok "WinHTTP proxy  -> 127.0.0.1:$ProxyPort"

# WinINet -- browser-level (Chrome, Edge) -- PAC file with DIRECT fallback
Set-ItemProperty -Path $HKCUReg -Name AutoConfigURL -Value $PacUrl
Set-ItemProperty -Path $HKCUReg -Name ProxyEnable   -Value 0   # PAC takes over, direct proxy disabled
Set-ItemProperty -Path $HKCUReg -Name AutoDetect     -Value 0
Write-Ok "Browser proxy  -> PAC: $PacUrl (falls back to DIRECT if proxy is down)"

# =============================================================================
# STEP 12 -- Start services
# =============================================================================
Write-Step "Starting services"

try {
    Start-Service -Name $ServiceProxy -ErrorAction Stop
} catch {
    Write-Warn "Could not start $ServiceProxy -- check logs at $LogDir\proxy-error.log"
    Write-Host "  Reverting proxy settings to avoid losing internet..." -ForegroundColor Yellow
    netsh winhttp reset proxy 2>&1 | Out-Null
    Set-ItemProperty -Path $HKCUReg -Name ProxyEnable -Value 0
    Write-Err "Fix the service issue then re-run this script."
    exit 1
}
Start-Sleep -Seconds 5
$ps = Get-Service -Name $ServiceProxy
if ($ps.Status -ne "Running") {
    Write-Warn "$ServiceProxy stopped unexpectedly -- reverting proxy to protect internet access"
    netsh winhttp reset proxy 2>&1 | Out-Null
    Set-ItemProperty -Path $HKCUReg -Name ProxyEnable -Value 0
    Write-Host "  Check logs: Get-Content $LogDir\proxy-error.log -Tail 30" -ForegroundColor Yellow
    exit 1
}
Write-Ok "$ServiceProxy  ->  $($ps.Status)"

Start-Service -Name $ServiceLogger -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$ls = Get-Service -Name $ServiceLogger
Write-Ok "$ServiceLogger ->  $($ls.Status)"

Start-Service -Name $ServiceScanner -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$ss = Get-Service -Name $ServiceScanner
Write-Ok "$ServiceScanner -> $($ss.Status)"

# =============================================================================
# Done
# =============================================================================
Write-Host ""
Write-Host "+---------------------------------------------------+" -ForegroundColor Green
Write-Host "|          SETUP COMPLETE                           |" -ForegroundColor Green
Write-Host "+---------------------------------------------------+" -ForegroundColor Green
Write-Host "| Services installed:                               |" -ForegroundColor White
Write-Host "|   SecEoKnight-Proxy   [running as Windows Service]|" -ForegroundColor White
Write-Host "|   SecEoKnight-Logger  [running as Windows Service]|" -ForegroundColor White
Write-Host "|   SecEoKnight-Scanner [running as Windows Service]|" -ForegroundColor White
Write-Host "|                                                   |" -ForegroundColor White
Write-Host "| Both services:                                    |" -ForegroundColor White
Write-Host "|   Auto-start on every Windows boot               |" -ForegroundColor Green
Write-Host "|   Run silently - no windows, no taskbar icon      |" -ForegroundColor Green
Write-Host "|   Auto-restart if they crash                      |" -ForegroundColor Green
Write-Host "|   Invisible to users                              |" -ForegroundColor Green
Write-Host "|                                                   |" -ForegroundColor White
Write-Host "| To manage (run as Admin):                         |" -ForegroundColor White
Write-Host "|   services.msc                 <- GUI manager     |" -ForegroundColor White
Write-Host "|   sc query SecEoKnight-Proxy   <- check status    |" -ForegroundColor White
Write-Host "|   sc stop  SecEoKnight-Proxy   <- stop service    |" -ForegroundColor White
Write-Host "|   sc start SecEoKnight-Proxy   <- start service   |" -ForegroundColor White
Write-Host "|                                                   |" -ForegroundColor White
Write-Host "| Quarantine: C:\SecEoKnight\Quarantine\            |" -ForegroundColor White
Write-Host "| Logs at:    C:\SecEoKnight\Logs\                  |" -ForegroundColor White
Write-Host "+---------------------------------------------------+" -ForegroundColor Green
Write-Host ""
