
param([switch]$Once)

# Configuration
$Config = @{
    PDP_URL             = "https://192.168.10.1:8443"
    TELEMETRY_MODE      = "hmac"             
    POLL_INTERVAL_SECS  = 60
    WG_TUNNEL_NAME      = "ZeroTrust"
    WG_CONFIG_PATH      = "C:\ProgramData\WireGuard\ZeroTrust.conf"
    CLIENT_CERT_THUMB   = "AC382276EB589994E2E02563BCC502A26037DD28"
    LOG_PATH            = "C:\ProgramData\ZT-Agent\agent.log"
    SALT_CACHE_PATH     = "C:\ProgramData\ZT-Agent\salt.json"
    HE_PRIVKEY_PATH     = "C:\ProgramData\ZT-Agent\he_privkey.json"
    REQUESTED_RESOURCES = @("smb", "s3")
}

# Logging 
function Write-Log([string]$Level, [string]$Msg) {
    $ts   = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $line = "[$ts][$Level] $Msg"
    Write-Host $line
    New-Item -ItemType Directory -Force -Path (Split-Path $Config.LOG_PATH) | Out-Null
    Add-Content -Path $Config.LOG_PATH -Value $line -ErrorAction SilentlyContinue
}

# Context collection
function Get-NetworkZone {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.IPAddress -match "^192\.168\." } |
           Select-Object -First 1).IPAddress
    if     ($ip -match "^192\.168\.10\.")   { return "trusted"   }
    elseif ($ip -match "^192\.168\.20\.")   { return "public"    }
    elseif ($ip -match "^192\.168\.30\.")   { return "protected" }
    else                                    { return "unknown"   }
}

function Get-BitLockerOK {
    try { return (Get-BitLockerVolume "C:" -ErrorAction Stop).ProtectionStatus -eq "On" }
    catch { return $false }
}

function Get-FailedLogins([int]$Hours = 1) {
    try {
        return (Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625;
                StartTime=(Get-Date).AddHours(-$Hours)} -ErrorAction SilentlyContinue).Count
    } catch { return 0 }
}

function Get-PatchAgeDays {
    try {
        $latest = (Get-HotFix | Sort-Object InstalledOn -Desc | Select-Object -First 1).InstalledOn
        return [int]((Get-Date) - $latest).TotalDays
    } catch { return 999 }
}

function Get-WgPubKey {
    try {
        $conf = Get-Content $Config.WG_CONFIG_PATH -ErrorAction Stop
        $privLine = ($conf | Where-Object { $_ -match "^\s*PrivateKey\s*=" })
        if (-not $privLine) { return "" }
        $priv = ($privLine -split "=", 2)[1].Trim()
        return ($priv | & "C:\Program Files\WireGuard\wg.exe" pubkey 2>$null).Trim()
    } catch { return "" }
}

function Get-TunnelIP {
    try {
        $conf    = Get-Content $Config.WG_CONFIG_PATH -ErrorAction Stop
        $addrLine = ($conf | Where-Object { $_ -match "^\s*Address\s*=" })
        return ($addrLine -split "=", 2)[1].Trim() -replace "/\d+$", ""
    } catch { return "10.0.0.2" }
}

function Get-RawTelemetry {
    return @{
        hostname            = $env:COMPUTERNAME
        username            = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ip_address          = (Get-NetIPAddress -AddressFamily IPv4 |
                               Where-Object { $_.IPAddress -notmatch "^127\." } |
                               Select-Object -First 1).IPAddress
        mac_address         = (Get-NetAdapter -Physical |
                               Where-Object Status -eq "Up" |
                               Select-Object -First 1).MacAddress
        zone                = Get-NetworkZone
        disk_encrypted      = Get-BitLockerOK
        failed_logins       = Get-FailedLogins -Hours 1
        patch_age_days      = Get-PatchAgeDays
        domain_joined       = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        requested_resources = $Config.REQUESTED_RESOURCES
        tunnel_ip           = Get-TunnelIP
        wg_pubkey           = Get-WgPubKey
        timestamp           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

#HMAC privacy transform
function Get-DailySalt {
    if (Test-Path $Config.SALT_CACHE_PATH) {
        try {
            $c = Get-Content $Config.SALT_CACHE_PATH | ConvertFrom-Json
            if ((Get-Date) -lt [datetime]$c.expires) { return $c.salt_hash }
        } catch {}
    }
    try {
        $cert = Get-Item "Cert:\LocalMachine\My\$($Config.CLIENT_CERT_THUMB)"
        $resp = Invoke-RestMethod -Uri "$($Config.PDP_URL)/api/v1/salt" `
                    -Certificate $cert -Method GET -SkipCertificateCheck
        $resp | ConvertTo-Json | Set-Content $Config.SALT_CACHE_PATH
        return $resp.salt_hash
    } catch { Write-Log "WARN" "Salt fetch failed: $_"; return "" }
}

function Compute-HMAC([string]$Input, [string]$KeyHex) {
    $key   = [System.Text.Encoding]::UTF8.GetBytes($KeyHex)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Input)
    $hmac  = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $key
    return ([System.BitConverter]::ToString($hmac.ComputeHash($bytes)) `
            -replace "-").ToLower().Substring(0, 16)
}

function Convert-ZoneToRisk([string]$Zone) {
    switch ($Zone.ToLower()) {
        "trusted"   { return "low"    }
        "corporate" { return "low"    }
        "protected" { return "low"    }
        "public"    { return "medium" }
        "remote"    { return "medium" }
        default     { return "high"   }
    }
}

function Build-HMACPayload([hashtable]$Raw) {
    $salt = Get-DailySalt
    if (-not $salt) {
        Write-Log "WARN" "No salt — using baseline fallback"
        return $Raw
    }
    $id = Compute-HMAC -Input "$($Raw.hostname)|$($Raw.mac_address)" -KeyHex $salt
    return @{
        device_id           = $id
        zone_risk           = Convert-ZoneToRisk $Raw.zone
        posture_ok          = ($Raw.disk_encrypted -and $Raw.patch_age_days -lt 30)
        login_anomaly       = ($Raw.failed_logins -gt 3)
        requested_resources = $Raw.requested_resources
        tunnel_ip           = $Raw.tunnel_ip
        wg_pubkey           = $Raw.wg_pubkey
        timestamp           = $Raw.timestamp
    }
}

#HE mode
function Build-HEPayload([hashtable]$Raw) {
    # In real deployment: use python-paillier via a local Python helper script.
    # invoke a companion Python script that does the
    # Paillier encryption and returns the JSON ciphertext payload.
    $jsonIn = $Raw | ConvertTo-Json -Depth 3
    $jsonIn | Set-Content "C:\ProgramData\ZT-Agent\he_input.json"
    try {
        $result = & python "C:\ProgramData\ZT-Agent\he_encrypt.py" 2>$null
        return $result | ConvertFrom-Json
    } catch {
        Write-Log "WARN" "HE encrypt failed — using HMAC fallback"
        return Build-HMACPayload $Raw
    }
}

#PDP submission
function Submit-Telemetry([hashtable]$Payload) {
    try {
        $cert = Get-Item "Cert:\LocalMachine\My\$($Config.CLIENT_CERT_THUMB)" `
                         -ErrorAction Stop
        $body = $Payload | ConvertTo-Json -Depth 4
        return Invoke-RestMethod `
            -Uri        "$($Config.PDP_URL)/api/v1/telemetry" `
            -Method     POST `
            -Body       $body `
            -ContentType "application/json" `
            -Certificate $cert `
            -SkipCertificateCheck
    } catch {
        Write-Log "ERROR" "PDP submission failed: $_"
        return $null
    }
}

function Submit-HEFinalise([string]$Action, [hashtable]$Raw) {
    try {
        $cert = Get-Item "Cert:\LocalMachine\My\$($Config.CLIENT_CERT_THUMB)"
        $body = @{
            action              = $Action
            requested_resources = $Raw.requested_resources
            tunnel_ip           = $Raw.tunnel_ip
            wg_pubkey           = $Raw.wg_pubkey
        } | ConvertTo-Json
        return Invoke-RestMethod `
            -Uri        "$($Config.PDP_URL)/api/v1/he_finalise" `
            -Method     POST `
            -Body       $body `
            -ContentType "application/json" `
            -Certificate $cert `
            -SkipCertificateCheck
    } catch {
        Write-Log "ERROR" "HE finalise failed: $_"
        return $null
    }
}

# WireGuard management
function Start-ZTTunnel {
    $svc = Get-Service "WireGuardTunnel`$$($Config.WG_TUNNEL_NAME)" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Running") {
        Start-Service $svc.Name -ErrorAction SilentlyContinue
        Write-Log "INFO" "WireGuard tunnel started"
    }
}

function Stop-ZTTunnel {
    $svc = Get-Service "WireGuardTunnel`$$($Config.WG_TUNNEL_NAME)" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue
        Write-Log "INFO" "WireGuard tunnel stopped (access denied)"
    }
}

# Main loop 
function Invoke-ContextAgent {
    Write-Log "INFO" "Context agent starting (mode=$($Config.TELEMETRY_MODE), resources=$($Config.REQUESTED_RESOURCES -join ','))"

    do {
        $t0  = [System.Diagnostics.Stopwatch]::StartNew()
        $raw = Get-RawTelemetry

        # Build payload by mode
        $payload  = $null
        $decision = $null

        switch ($Config.TELEMETRY_MODE) {
            "hmac" {
                $payload  = Build-HMACPayload $raw
                $decision = Submit-Telemetry $payload
            }
            "he" {
                # Step 1: send ciphertext, receive Enc(total-threshold)
                $hePayload = Build-HEPayload $raw
                $heResp    = Submit-Telemetry $hePayload
                if ($heResp -and $heResp.enc_comparison) {
                    # Step 2: decrypt locally, return sign only
                    $sign   = Invoke-HEDecrypt $heResp   # returns "ALLOW" or "DENY"
                    $decision = Submit-HEFinalise $sign $raw
                }
            }
            default {
                $payload  = $raw
                $decision = Submit-Telemetry $payload
            }
        }

        $t0.Stop()
        $latMs = [math]::Round($t0.Elapsed.TotalMilliseconds, 1)

        if ($decision) {
            Write-Log "INFO" "action=$($decision.action) scope=$($decision.scope -join ',') score=$($decision.risk_score) latency=${latMs}ms"
            if ($decision.action -eq "ALLOW") { Start-ZTTunnel }
            else {
                Stop-ZTTunnel
                Write-Log "WARN" "Denied: $($decision.reasons -join ', ')"
            }
        } else {
            Write-Log "WARN" "PDP unreachable — fail-closed: stopping tunnel"
            Stop-ZTTunnel
        }

        if (-not $Once) { Start-Sleep -Seconds $Config.POLL_INTERVAL_SECS }

    } while (-not $Once)
}

function Invoke-HEDecrypt($heResp) {
    # Decrypt Enc(total-threshold) using local private key
    # Returns "ALLOW" (negative result) or "DENY" (non-negative result)
    try {
        $heResp | ConvertTo-Json | Set-Content "C:\ProgramData\ZT-Agent\he_response.json"
        $result = & python "C:\ProgramData\ZT-Agent\he_decrypt.py" 2>$null
        return $result.Trim()  # "ALLOW" or "DENY"
    } catch { return "DENY" }   # Fail closed
}

Invoke-ContextAgent
