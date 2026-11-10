<#
================================================================================
 install_agent.ps1 - register the Zero Trust context agent on a Windows client.

 What it does:
   1. validates the client certificate thumbprint exists in LocalMachine\My
   2. copies context_agent.ps1, the HE helpers and scoring.py into the install dir
   3. patches the five config variables in the installed copy
   4. registers a scheduled task that runs the agent at boot, as SYSTEM,
      and restarts it if it stops

 Run from the folder that contains context_agent.ps1, as Administrator:

   .\install_agent.ps1 -Mode hmac -CertThumb '<40-char thumbprint>' -Resources @('smb','s3') -TunnelIP '10.0.0.2'
================================================================================
#>
[CmdletBinding()]
param(
    [ValidateSet('baseline','hmac','he')]
    [string]   $Mode       = 'hmac',

    [Parameter(Mandatory = $true)]
    [string]   $CertThumb,

    [string[]] $Resources  = @('smb'),

    [Parameter(Mandatory = $true)]
    [string]   $TunnelIP,

    [string]   $PdpUrl     = 'https://192.168.10.1:8443/api/v1/telemetry',

    [string]   $InstallDir = 'C:\ProgramData\ZT-Agent',

    [string]   $TaskName   = 'ZeroTrust-ContextAgent',
    [string]   $TaskPath   = '\ZeroTrust\'
)

$ErrorActionPreference = 'Stop'

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){   Write-Host "[+] $m" -ForegroundColor Green }
function Die($m){  Write-Host "[!] $m" -ForegroundColor Red; exit 1 }

# --- 0. must be admin ------------------------------------------------------
$principalObj = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principalObj.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Die "Run this script as Administrator." }

# --- 1. normalise + validate the thumbprint --------------------------------
$CertThumb = ($CertThumb -replace '\s','').ToUpper()
Info "Looking for client certificate $CertThumb in LocalMachine\My ..."
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Thumbprint -eq $CertThumb } |
        Select-Object -First 1
if (-not $cert) {
    Die "Certificate $CertThumb not found in LocalMachine\My. Import the .pfx first (see setup guide step 4)."
}
Ok "Found certificate: $($cert.Subject)"

# --- 2. locate the source agent --------------------------------------------
$srcAgent = Join-Path $PSScriptRoot 'context_agent.ps1'
if (-not (Test-Path $srcAgent)) {
    Die "context_agent.ps1 not found next to this installer ($PSScriptRoot)."
}

# --- 3. create install dir and copy files ----------------------------------
Info "Installing to $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$dstAgent = Join-Path $InstallDir 'context_agent.ps1'
Copy-Item $srcAgent $dstAgent -Force

# copy ca.crt alongside if it's present in the source folder
$srcCa = Join-Path $PSScriptRoot 'ca.crt'
if (Test-Path $srcCa) {
    Copy-Item $srcCa (Join-Path $InstallDir 'ca.crt') -Force
    Ok "Copied ca.crt"
}

# --- 3b. HE helpers + shared scoring module (review fixes A / hygiene) ------
# scoring.py is the single source of truth for weights/threshold and MUST be
# byte-identical on client and PDP; he_encrypt.py / he_decrypt.py import it.
foreach ($f in @('he_encrypt.py', 'he_decrypt.py', 'scoring.py')) {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $InstallDir $f) -Force
        Ok "Copied $f"
    } elseif ($Mode -eq 'he') {
        Die "$f not found next to the installer - required for HE mode (the agent fails closed without it)."
    }
}

# lock down the install dir (it will hold he_key.json - the client's Paillier
# private key, which is what makes the HE privacy guarantee meaningful)
if ($Mode -eq 'he') {
    Info "Restricting $InstallDir ACL to SYSTEM + Administrators ..."
    icacls $InstallDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
    Ok "ACL set (he_key.json will be readable by SYSTEM/Administrators only)."
}

# --- 4. patch the five config variables in the installed copy --------------
Info "Patching agent configuration ..."
$resList = ($Resources | ForEach-Object { "'$_'" }) -join ','

# read as text, replace each config line, write back as UTF-8 WITHOUT BOM
$content = Get-Content $dstAgent -Raw

$content = $content -replace "(?m)^\s*\`$TELEMETRY_MODE\s*=.*$",      "`$TELEMETRY_MODE      = '$Mode'"
$content = $content -replace "(?m)^\s*\`$PDP_URL\s*=.*$",             "`$PDP_URL             = '$PdpUrl'"
$content = $content -replace "(?m)^\s*\`$CLIENT_CERT_THUMB\s*=.*$",   "`$CLIENT_CERT_THUMB   = '$CertThumb'"
$content = $content -replace "(?m)^\s*\`$REQUESTED_RESOURCES\s*=.*$", "`$REQUESTED_RESOURCES = @($resList)"
$content = $content -replace "(?m)^\s*\`$TUNNEL_IP\s*=.*$",           "`$TUNNEL_IP           = '$TunnelIP'"

# write WITHOUT a BOM (UTF-8 BOM breaks PowerShell parsing in some hosts)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($dstAgent, $content, $utf8NoBom)
Ok "Configuration written (mode=$Mode, tunnel=$TunnelIP, resources=$resList)"

# --- 5. register the scheduled task ----------------------------------------
Info "Registering scheduled task $TaskPath$TaskName ..."

# remove any previous version
$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Info "Removed existing task."
}

# splatting (no backtick line-continuations, which are fragile across editors)
$agentArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $dstAgent + '"'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $agentArgs

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

$settingsParams = @{
    AllowStartIfOnBatteries    = $true
    DontStopIfGoingOnBatteries = $true
    StartWhenAvailable         = $true
    RestartCount               = 999
    RestartInterval            = (New-TimeSpan -Minutes 1)
}
$settings = New-ScheduledTaskSettingsSet @settingsParams

$registerParams = @{
    TaskName  = $TaskName
    TaskPath  = $TaskPath
    Action    = $action
    Trigger   = $trigger
    Principal = $principal
    Settings  = $settings
}
Register-ScheduledTask @registerParams | Out-Null
Ok "Scheduled task registered."

# --- 6. start it now -------------------------------------------------------
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
Ok "Agent started."

Write-Host ""
Write-Host "Done. The agent is running as SYSTEM and will start on every boot." -ForegroundColor Green
Write-Host "Watch its log with:" -ForegroundColor Green
Write-Host "    Get-Content '$InstallDir\agent.log' -Tail 20 -Wait"
