[CmdletBinding()]
param([switch]$Fix)

function Line($name, $ok, $detail) {
    $tag = if ($ok) { "PASS" } else { "FAIL" }
    "{0,-14} {1,-5} {2}" -f $name, $tag, $detail
}

Write-Host "`n=== Zero Trust client posture readiness ===`n"

# --- Secure Boot (firmware; report only) ---
try { $sb = Confirm-SecureBootUEFI } catch { $sb = $false }
$sbDetail = if ($sb) { "enabled" } else { "DISABLED - enable in VM UEFI firmware, then reboot" }
Line "secure_boot" $sb $sbDetail

# --- Disk encryption / BitLocker (drives posture_ok) ---
$bl = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
$blOn = $bl -and $bl.ProtectionStatus -eq 'On'
Line "disk_encrypt" $blOn ("C: $($bl.VolumeStatus)")
if ($Fix -and -not $blOn) {
    Write-Host "  -> enabling BitLocker on C: ..."
    Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
        -RecoveryPasswordProtector -ErrorAction SilentlyContinue | Out-Null
}

# --- Defender + firewall (av_fw_ok) ---
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
$avOn = $mp -and $mp.RealTimeProtectionEnabled
$fw = (Get-NetFirewallProfile | Where-Object Enabled -eq $true).Count -ge 1
Line "av_fw_ok" ($avOn -and $fw) ("AV=$avOn firewall=$fw")
if ($Fix) {
    if (-not $avOn) { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue }
    if (-not $fw)   { Set-NetFirewallProfile -All -Enabled True -ErrorAction SilentlyContinue }
}

# --- Patch recency (patch_recent) ---
$last = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$fresh = $last -and $last.InstalledOn -gt (Get-Date).AddDays(-30)
Line "patch_recent" $fresh ("last: $($last.HotFixID) $($last.InstalledOn)")

# --- Failed logons (login_anomaly) ---
$fails = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50 `
            -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) })
Line "login_anomaly" ($fails.Count -eq 0) ("$($fails.Count) failed logons in last hour")

Write-Host "`nNote: 'zone_risk' is network-derived (your subnet/segment) and is judged by the PDP.`n"
