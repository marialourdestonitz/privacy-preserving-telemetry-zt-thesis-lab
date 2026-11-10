<#
================================================================================
 context_agent.ps1 - Zero Trust client posture agent.

 Runs in a loop: every POLL_SECONDS it collects device posture, builds the
 telemetry payload for the configured mode (baseline / hmac / he), and POSTs it
 to the PDP over mTLS using the client certificate identified by thumbprint.
 In baseline/hmac the PDP replies ALLOW or DENY and enforces server-side. In HE
 the PDP returns Enc(score - threshold) only (it never sees the score); the
 agent decrypts the sign locally (he_decrypt.py) and reports the verdict to
 /api/v1/he_decision, which drives the PEP.

 REVISED per the implementation review 2026-07:
   Finding D: hmac mode now keys device_id_hmac with the PDP's real rotating
              salt, fetched over mTLS from /api/v1/salt/material (cached, and
              re-fetched when the fingerprint rotates). The old date-string
              salt was public knowledge, making the pseudonym brute-forceable.
              If the salt cannot be fetched, the cycle is SKIPPED (fail
              closed) - the agent never falls back to a weak key.
   Finding G: every request carries a random nonce; the PDP rejects replays
              inside the freshness window.
   Fail closed: (a) HE mode no longer silently downgrades to baseline when
              he_encrypt.py is missing - it logs and skips the cycle.
              (b) The machine-UUID fallback for the WireGuard key is gone -
              the UUID is a hardware identifier and would leak in hmac/he
              payloads. No wg key -> log and skip.
   Hygiene:   Python helper stderr is captured and logged instead of discarded.

 The five config values below are PATCHED by install_agent.ps1 - keep the
 variable names exactly as they are.
================================================================================
#>

# ---- config (patched by install_agent.ps1) --------------------------------
$TELEMETRY_MODE      = 'hmac'
$PDP_URL             = 'https://192.168.10.1:8443/api/v1/telemetry'
$CLIENT_CERT_THUMB   = 'REPLACE_WITH_THUMBPRINT'
$REQUESTED_RESOURCES = @('smb')
$TUNNEL_IP           = '10.0.0.2'

# ---- fixed settings --------------------------------------------------------
$POLL_SECONDS = 60
$LOG_PATH     = Join-Path $PSScriptRoot 'agent.log'
$CA_PATH      = Join-Path $PSScriptRoot 'ca.crt'   # used only for trust checks

# ---- salt cache (Finding D) -------------------------------------------------
$script:SaltHex  = $null
$script:SaltHash = $null

# ============================================================================
function Write-Log {
    param([string]$Message)
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LOG_PATH -Value $line
    Write-Host $line
}

# ---- persist the per-session S3 credentials the PEP issued on ALLOW ---------
# The PDP returns cloud_credentials in the ALLOW / he_decision response. Write
# them to a file so the employee (or an S3 tool / the MinIO console) can use
# them. Rewritten each ALLOW; the credential dies on the next DENY/expiry.
function Write-CloudCreds {
    param($resp)
    if ($resp -and $resp.cloud_credentials -and $resp.cloud_credentials.s3_access_key) {
        $c = $resp.cloud_credentials
        $path = Join-Path $PSScriptRoot 's3-credentials.txt'
        $lines = @(
            "# Issued by the PDP on ALLOW - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            "# Valid only while this device stays ALLOWed; revoked on DENY / expiry.",
            "S3 API endpoint : https://192.168.40.10:9000",
            "MinIO console   : https://192.168.40.10:9001",
            "Access Key      : $($c.s3_access_key)",
            "Secret Key      : $($c.s3_secret_key)"
        )
        Set-Content -Path $path -Value $lines -Encoding UTF8
        Write-Log "S3 credentials written to $path"
    }
}

# ---- run a python helper, capturing stderr properly -------------------------
function Invoke-PyHelper {
    param([string]$ScriptPath, [string]$StdinJson)
    $errFile = Join-Path $env:TEMP ("zt-agent-py-" + [guid]::NewGuid().ToString('N') + ".err")
    try {
        $out = $StdinJson | python $ScriptPath 2>$errFile
        if ($LASTEXITCODE -ne 0) {
            $err = (Get-Content $errFile -Raw -ErrorAction SilentlyContinue)
            Write-Log ("ERROR: {0} exited {1}: {2}" -f (Split-Path $ScriptPath -Leaf), $LASTEXITCODE, $err)
            return $null
        }
        return ($out | ConvertFrom-Json)
    } catch {
        Write-Log ("ERROR running {0}: {1}" -f (Split-Path $ScriptPath -Leaf), $_.Exception.Message)
        return $null
    } finally {
        Remove-Item $errFile -ErrorAction SilentlyContinue
    }
}

# ---- locate the WireGuard public key for this client -----------------------
function Get-WgPublicKey {
    # Read the active WireGuard tunnel's public key. REVIEW FIX: no fallback -
    # the old machine-UUID fallback injected a stable hardware identifier into
    # hmac/he payloads, defeating the privacy mode. No key -> the caller skips
    # this cycle (fail closed).
    try {
        $out = & wg show 2>$null
        foreach ($l in $out) {
            if ($l -match 'public key:\s*(\S+)') { return $matches[1] }
        }
    } catch { }
    return $null
}

# ---- fetch the pseudonymisation salt over mTLS (Finding D) ------------------
function Get-ServerSalt {
    param($Cert)
    $saltUrl = $PDP_URL -replace '/telemetry$', '/salt/material'
    try {
        $resp = Invoke-RestMethod -Uri $saltUrl -Method Get -Certificate $Cert -TimeoutSec 10
        if ($resp.salt) {
            if ($script:SaltHash -ne $resp.salt_hash) {
                Write-Log ("salt fetched/rotated (fingerprint {0}...)" -f $resp.salt_hash.Substring(0,12))
            }
            $script:SaltHex  = $resp.salt
            $script:SaltHash = $resp.salt_hash
            return $true
        }
    } catch {
        Write-Log ("ERROR fetching salt material: " + $_.Exception.Message)
    }
    return ($null -ne $script:SaltHex)   # keep last good salt if fetch fails
}

# ---- collect raw device posture --------------------------------------------
function Get-Posture {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem

    # disk encryption (BitLocker on C:)
    # REVIEW FIX: use manage-bde instead of Get-BitLockerVolume. The cmdlet can
    # report the wrong ProtectionStatus when the agent runs as SYSTEM (the
    # scheduled-task context), which spuriously added the disk penalty and
    # forced DENY on a fully-encrypted device. manage-bde reads the true
    # protection state reliably under SYSTEM.
    $diskEncrypted = $false
    try {
        $bde = & manage-bde -status C: 2>$null
        $diskEncrypted = [bool]($bde -match 'Protection Status:\s*Protection On')
    } catch {
        try {
            $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
            $diskEncrypted = ($bl.ProtectionStatus -eq 'On')
        } catch { $diskEncrypted = $false }
    }

    # patch age: days since last hotfix
    $patchAge = 999
    try {
        $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending |
              Select-Object -First 1
        if ($hf -and $hf.InstalledOn) {
            $patchAge = [int]((Get-Date) - $hf.InstalledOn).TotalDays
        }
    } catch { }

    # failed logins in the last 24h (event 4625)
    $failed = 0
    try {
        $failed = (Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4625;
            StartTime=(Get-Date).AddDays(-1)
        } -ErrorAction SilentlyContinue | Measure-Object).Count
    } catch { }

    # firewall + antivirus
    $fwOn = $false
    try { $fwOn = ((Get-NetFirewallProfile | Where-Object Enabled).Count -gt 0) } catch { }
    $avOn = $false
    try {
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        $avOn = ($av -ne $null)
    } catch { }

    # secure boot
    $secureBoot = $false
    try { $secureBoot = (Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }

    return [ordered]@{
        hostname       = $cs.Name
        username       = $env:USERNAME
        mac_address    = (Get-NetAdapter | Where-Object Status -eq 'Up' |
                          Select-Object -First 1 -ExpandProperty MacAddress)
        ip_address     = (Get-NetIPAddress -AddressFamily IPv4 |
                          Where-Object { $_.IPAddress -like '10.0.0.*' } |
                          Select-Object -First 1 -ExpandProperty IPAddress)
        zone           = if ($TUNNEL_IP -like '10.0.0.*') { 'remote' } else { 'public' }
        disk_encrypted = $diskEncrypted
        patch_age_days = $patchAge
        domain_joined  = $cs.PartOfDomain
        failed_logins  = $failed
        av_enabled     = $avOn
        fw_enabled     = $fwOn
        os_supported   = $true
        secure_boot    = $secureBoot
        login_anomaly  = ($failed -gt 3)
        uptime_hours   = [int]((Get-Date) - $os.LastBootUpTime).TotalHours
    }
}

# ---- HMAC pseudonymisation (mode = hmac) -----------------------------------
function Get-Hmac {
    param([string]$Value, [string]$SaltHex)
    # REVIEW FIX (Finding D): the key is the PDP's rotating 32-byte salt
    # (hex-decoded), fetched over mTLS - not a guessable date string.
    $saltBytes = [byte[]]::new($SaltHex.Length / 2)
    for ($i = 0; $i -lt $saltBytes.Length; $i++) {
        $saltBytes[$i] = [Convert]::ToByte($SaltHex.Substring($i * 2, 2), 16)
    }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($saltBytes)
    $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0,16)
}

function Build-HmacClaims {
    param($posture)
    # Minimised claims. REVIEW FIX (Finding A): the claim set now mirrors
    # scoring.py exactly - same factors, as bands/booleans. Keep this in
    # lock-step with scoring.claims_from_posture().
    $zoneRisk = switch ($posture.zone) {
        'trusted'   { 'low' }
        'corporate' { 'low' }
        'public'    { 'medium' }
        'remote'    { 'medium' }
        default     { 'high' }
    }
    $patchBand = if     ($posture.patch_age_days -gt 90) { 'very_stale' }
                 elseif ($posture.patch_age_days -gt 30) { 'stale' }
                 else                                    { 'recent' }
    $loginBand = if     ($posture.failed_logins -gt 10)  { 'many' }
                 elseif ($posture.failed_logins -gt 3)   { 'some' }
                 else                                    { 'none' }
    return [ordered]@{
        device_id_hmac = Get-Hmac -Value ($posture.hostname + $posture.mac_address) -SaltHex $script:SaltHex
        zone_risk      = $zoneRisk
        disk_ok        = [bool]$posture.disk_encrypted
        patch_band     = $patchBand
        domain_ok      = [bool]$posture.domain_joined
        login_band     = $loginBand
        av_ok          = [bool]$posture.av_enabled
        fw_ok          = [bool]$posture.fw_enabled
        os_ok          = [bool]$posture.os_supported
        secure_boot    = [bool]$posture.secure_boot
        login_anomaly  = [bool]$posture.login_anomaly
        uptime_ok      = ($posture.uptime_hours -le 720)
    }
}

# ---- build the full telemetry payload --------------------------------------
function Build-Payload {
    param($posture, $wgPub, $Cert)
    $payload = [ordered]@{
        mode                = $TELEMETRY_MODE
        timestamp           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        tunnel_ip           = $TUNNEL_IP
        wg_pubkey           = $wgPub
        requested_resources = $REQUESTED_RESOURCES
        nonce               = [guid]::NewGuid().ToString('N')   # Finding G
    }
    switch ($TELEMETRY_MODE) {
        'baseline' { $payload['telemetry'] = $posture }
        'hmac'     {
            # fail closed: no server salt -> no pseudonym -> no send
            if (-not (Get-ServerSalt -Cert $Cert)) {
                Write-Log "SKIP: hmac mode but no salt available (fail closed)."
                return $null
            }
            $payload['claims'] = (Build-HmacClaims $posture)
        }
        'he'       {
            $hePath = Join-Path $PSScriptRoot 'he_encrypt.py'
            if (-not (Test-Path $hePath)) {
                # REVIEW FIX: never silently downgrade a privacy mode to
                # baseline (full identifiers). Fail closed instead.
                Write-Log "SKIP: HE mode but he_encrypt.py not found (fail closed - no baseline downgrade)."
                return $null
            }
            $json = ($posture | ConvertTo-Json -Compress)
            $enc  = Invoke-PyHelper -ScriptPath $hePath -StdinJson $json
            if (-not $enc -or -not $enc.pub_key_n) {
                Write-Log "SKIP: he_encrypt.py produced no ciphertexts (fail closed)."
                return $null
            }
            $payload['enc_zone']    = $enc.enc_zone
            $payload['enc_posture'] = $enc.enc_posture
            $payload['enc_patch']   = $enc.enc_patch
            $payload['enc_login']   = $enc.enc_login
            $payload['pub_key_n']   = $enc.pub_key_n
        }
    }
    return $payload
}

# ---- send one telemetry cycle ----------------------------------------------
function Send-Telemetry {
    # find the client cert by thumbprint in the LocalMachine store
    $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Thumbprint -eq $CLIENT_CERT_THUMB } |
            Select-Object -First 1
    if (-not $cert) {
        Write-Log "ERROR: client cert thumbprint $CLIENT_CERT_THUMB not found in LocalMachine\My"
        return
    }

    $wgPub = Get-WgPublicKey
    if (-not $wgPub) {
        # REVIEW FIX: no UUID fallback - a hardware identifier in an hmac/he
        # payload would defeat the privacy mode. Fail closed.
        Write-Log "SKIP: WireGuard public key not readable (is the tunnel up? is wg.exe on PATH?)."
        return
    }

    $posture = Get-Posture
    $payload = Build-Payload -posture $posture -wgPub $wgPub -Cert $cert
    if (-not $payload) { return }   # a fail-closed branch already logged why
    $body = $payload | ConvertTo-Json -Depth 6 -Compress

    try {
        $resp = Invoke-RestMethod -Uri $PDP_URL -Method Post -Body $body `
                    -ContentType 'application/json' -Certificate $cert -TimeoutSec 10

        if ($payload['mode'] -eq 'he') {
            # HE: the PDP returned Enc(score - threshold) only - it never saw the
            # score. Decrypt locally to learn ALLOW/DENY, then report the verdict
            # so the PEP can enforce it.
            $heDecPath = Join-Path $PSScriptRoot 'he_decrypt.py'
            $decIn = @{ enc_comparison = $resp.enc_comparison
                        pub_key_n      = $resp.pub_key_n } | ConvertTo-Json -Compress
            $dec = Invoke-PyHelper -ScriptPath $heDecPath -StdinJson $decIn
            if (-not $dec -or -not $dec.action) {
                Write-Log "ERROR: local HE decrypt failed; no verdict reported this cycle."
                return
            }
            Write-Log ("PDP(he) -> Enc(score-thr) received; local decrypt action={0} score={1} session={2}" -f `
                        $dec.action, $dec.score, $resp.session_id)

            $decUrl  = $PDP_URL -replace '/telemetry$', '/he_decision'
            $decBody = @{ session_id = $resp.session_id
                          tunnel_ip  = $TUNNEL_IP
                          action     = $dec.action } | ConvertTo-Json -Compress
            try {
                $enf = Invoke-RestMethod -Uri $decUrl -Method Post -Body $decBody `
                            -ContentType 'application/json' -Certificate $cert -TimeoutSec 10
                Write-Log ("PDP(he) -> enforced={0} session={1}" -f $enf.enforced, $resp.session_id)
                Write-CloudCreds $enf
            } catch {
                Write-Log ("ERROR posting HE decision: " + $_.Exception.Message)
            }
        } else {
            Write-Log ("PDP -> action={0} score={1} session={2} mode={3}" -f `
                        $resp.action, $resp.score, $resp.session_id, $resp.mode)
            Write-CloudCreds $resp
        }
    } catch {
        Write-Log ("ERROR posting telemetry: " + $_.Exception.Message)
    }
}

# ============================================================================
Write-Log "context_agent starting (mode=$TELEMETRY_MODE, tunnel=$TUNNEL_IP, pdp=$PDP_URL)"
while ($true) {
    Send-Telemetry
    Start-Sleep -Seconds $POLL_SECONDS
}
