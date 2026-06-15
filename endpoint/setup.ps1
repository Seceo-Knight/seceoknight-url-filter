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
#
# Run as Administrator on each endpoint.
# =============================================================================

$ErrorActionPreference = "Stop"

# -- Configuration --------------------------------------------------------------
$ServerIP     = "192.168.1.189"      # <-- Change if your server IP is different
$ServerPort   = 5001
$ProxyPort    = 8082
$BaseDir      = "C:\SecEoKnight"
$LogDir       = "C:\SecEoKnight\Logs"
$AgentPath    = "$BaseDir\agent.py"
$ToServerPath = "$BaseDir\to-server.py"

$MitmInstallerUrl = "https://downloads.mitmproxy.org/10.2.4/mitmproxy-10.2.4-windows-x86_64-installer.exe"
$NssmUrl          = "https://nssm.cc/release/nssm-2.24.zip"
$RepoBase         = "https://raw.githubusercontent.com/Seceo-Knight/seceoknight-url-filter/main/endpoint"

$ServiceProxy  = "SecEoKnight-Proxy"
$ServiceLogger = "SecEoKnight-Logger"
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
Write-Host "  Services: $ServiceProxy / $ServiceLogger" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# =============================================================================
# STEP 1 -- Create directories
# =============================================================================
Write-Step "Creating directories"
foreach ($dir in @($BaseDir, $LogDir)) {
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

Write-Host "  Installing Python packages (requests)..." -ForegroundColor Yellow
& $PythonExe -m pip install requests --quiet --disable-pip-version-check
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

Download-File "$RepoBase/agent.py"     $AgentPath
Download-File "$RepoBase/to-server.py" $ToServerPath

# Patch server IP into both files
(Get-Content $AgentPath    -Raw) -replace '192\.168\.1\.189', $ServerIP | Set-Content $AgentPath    -Encoding UTF8
(Get-Content $ToServerPath -Raw) -replace '192\.168\.1\.189', $ServerIP | Set-Content $ToServerPath -Encoding UTF8
Write-Ok "Server IP set to $ServerIP in both files"

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
    $NssmZip = "$env:TEMP\nssm.zip"
    $NssmDir = "$env:TEMP\nssm-extract"

    Write-Host "  Downloading NSSM..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip -UseBasicParsing
    Expand-Archive -Path $NssmZip -DestinationPath $NssmDir -Force

    Copy-Item "$NssmDir\nssm-2.24\win64\nssm.exe" $NssmPerm -Force
    Write-Ok "NSSM installed at $NssmPerm"
} else {
    Write-Ok "NSSM already present"
}

# =============================================================================
# STEP 6 -- Certificate installation (one-time -- needed for HTTPS blocking)
# =============================================================================
Write-Step "Certificate Installation"

$HKCUReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Temporarily set proxy to localhost so the browser can reach http://mitm.it
Set-ItemProperty -Path $HKCUReg -Name ProxyEnable  -Value 1
Set-ItemProperty -Path $HKCUReg -Name ProxyServer   -Value "127.0.0.1:$ProxyPort"
Set-ItemProperty -Path $HKCUReg -Name ProxyOverride -Value "192.168.*;10.*;172.16.*;localhost;<local>"
Set-ItemProperty -Path $HKCUReg -Name AutoDetect    -Value 0
Write-Ok "Temporary proxy set to 127.0.0.1:$ProxyPort"

# Start temporary mitmproxy (hidden window -- not permanent)
$TempProxy = Start-Process -FilePath $MitmDumpExe `
    -ArgumentList "--listen-host 0.0.0.0 --listen-port $ProxyPort" `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

# Open the certificate page
Start-Process "http://mitm.it"

Write-Host ""
Write-Host "+--------------------------------------------------------------+" -ForegroundColor Yellow
Write-Host "| INSTALL THE CERTIFICATE (required for HTTPS blocking)        |" -ForegroundColor Yellow
Write-Host "+--------------------------------------------------------------+" -ForegroundColor Yellow
Write-Host "| A browser page opened at http://mitm.it                      |" -ForegroundColor White
Write-Host "|                                                              |" -ForegroundColor White
Write-Host "|  1. Click  [Windows]                                         |" -ForegroundColor White
Write-Host "|  2. Download  mitmproxy-ca-cert.cer                          |" -ForegroundColor White
Write-Host "|  3. Double-click the .cer file                               |" -ForegroundColor White
Write-Host "|  4. Click  [Install Certificate]                             |" -ForegroundColor White
Write-Host "|  5. Choose [Local Machine]  -> Next                          |" -ForegroundColor White
Write-Host "|  6. Choose [Place all certificates in the following store]   |" -ForegroundColor White
Write-Host "|  7. Click  [Browse] -> [Trusted Root Cert. Authorities] -> OK|" -ForegroundColor White
Write-Host "|  8. Next -> Finish                                           |" -ForegroundColor White
Write-Host "|                                                              |" -ForegroundColor White
Write-Host "|  Look for: 'The import was successful'                       |" -ForegroundColor Green
Write-Host "+--------------------------------------------------------------+" -ForegroundColor Yellow
Write-Host ""

Read-Host "  Press ENTER after certificate is installed"

Stop-Process -Id $TempProxy.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Ok "Certificate installed -- temporary proxy stopped"

# =============================================================================
# STEP 7 -- Remove old services (clean reinstall)
# =============================================================================
Write-Step "Removing old services if present"

foreach ($svc in @($ServiceProxy, $ServiceLogger)) {
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
& $NssmPerm set        $ServiceProxy AppParameters    "--listen-host 0.0.0.0 --listen-port $ProxyPort -s `"$AgentPath`""
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
# STEP 10 -- Set machine-wide proxy
# =============================================================================
Write-Step "Configuring machine-wide proxy"

# Get this machine's LAN IP
$LocalIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -ne "127.0.0.1" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -in @("Dhcp","Manual")
    } | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $LocalIP) { $LocalIP = "127.0.0.1" }

# WinHTTP -- machine-wide, affects system services and most Windows apps
netsh winhttp set proxy "$LocalIP`:$ProxyPort" "192.168.*;10.*;172.16.*;localhost" 2>&1 | Out-Null
Write-Ok "WinHTTP proxy -> $LocalIP`:$ProxyPort"

# WinINet -- browser-level (Chrome, Edge, IE)
$ProxyBypass = "192.168.*;10.*;172.16.*;localhost;<local>"
Set-ItemProperty -Path $HKCUReg -Name ProxyEnable  -Value 1
Set-ItemProperty -Path $HKCUReg -Name ProxyServer   -Value "$LocalIP`:$ProxyPort"
Set-ItemProperty -Path $HKCUReg -Name ProxyOverride -Value $ProxyBypass
Set-ItemProperty -Path $HKCUReg -Name AutoDetect    -Value 0
Write-Ok "Browser proxy  -> $LocalIP`:$ProxyPort"

# =============================================================================
# STEP 11 -- Start services
# =============================================================================
Write-Step "Starting services"

Start-Service -Name $ServiceProxy  -ErrorAction Stop
Start-Sleep -Seconds 3
$ps = Get-Service -Name $ServiceProxy
Write-Ok "$ServiceProxy  ->  $($ps.Status)"

Start-Service -Name $ServiceLogger -ErrorAction Stop
Start-Sleep -Seconds 2
$ls = Get-Service -Name $ServiceLogger
Write-Ok "$ServiceLogger ->  $($ls.Status)"

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
Write-Host "| Logs at: C:\SecEoKnight\Logs\                     |" -ForegroundColor White
Write-Host "+---------------------------------------------------+" -ForegroundColor Green
Write-Host ""
