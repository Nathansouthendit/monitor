<#
.SYNOPSIS
  Sends made-up monitoring data (servers, PCs, switches, Wi-Fi, M365) to the
  dashboard for testing, in the standard JSON format. Includes one server and
  one PC whose last report is 2 hours old, so you can see offline detection.

.EXAMPLE
  .\Send-TestData.ps1 -ApiKey "PASTE-KEY"
  .\Send-TestData.ps1 -ApiKey "PASTE-KEY" -Prefix "WL"
#>
param(
    [Parameter(Mandatory)] [string] $ApiKey,
    [string] $Url    = "http://127.0.0.1:8080/api/ingest",
    [string] $Prefix = "EW"
)

$now   = Get-Date
$stamp = $now.ToString("o")
$old   = $now.AddHours(-2).ToString("o")

function New-Item2($type, $hostName, $metrics, $collected = $stamp) {
    [ordered]@{ type = $type; host = $hostName; collected = $collected; metrics = $metrics }
}

function New-ServerMetrics {
    $total = Get-Random -InputObject 100,200,500,1000
    [ordered]@{
        OS              = Get-Random -InputObject "Windows Server 2019","Windows Server 2022"
        CPU_Pct         = Get-Random -Minimum 1 -Maximum 95
        RAM_UsedPct     = Get-Random -Minimum 20 -Maximum 97
        DiskC_TotalGB   = $total
        DiskC_FreeGB    = [math]::Round($total * (Get-Random -Minimum 3 -Maximum 70) / 100, 1)
        Uptime_Days     = Get-Random -Minimum 0 -Maximum 120
        PendingReboot   = Get-Random -InputObject "No","No","Yes"
        StoppedServices = Get-Random -InputObject 0,0,0,1
    }
}

$items = @()

# Servers (last one is "stale" to show offline)
foreach ($r in "DC01","DC02","FILE01","SQL01") {
    $items += New-Item2 "server" "$Prefix-SRV-$r" (New-ServerMetrics)
}
$items += New-Item2 "server" "$Prefix-SRV-OLD01" (New-ServerMetrics) $old

# PCs (last one "not seen" - grey, not red)
foreach ($n in 1..6) {
    $items += New-Item2 "pc" ("$Prefix-PC-{0:D3}" -f $n) ([ordered]@{
        OS          = "Windows 11 Education"
        CPU_Pct     = Get-Random -Minimum 1 -Maximum 60
        RAM_UsedPct = Get-Random -Minimum 30 -Maximum 90
        DiskC_FreeGB = Get-Random -Minimum 20 -Maximum 200
        LoggedOnUser = Get-Random -InputObject "","staff01","pupil123"
    })
}
$items += New-Item2 "pc" "$Prefix-PC-099" ([ordered]@{ OS = "Windows 11 Education" }) $old

# Switches
foreach ($s in "CORE01","EDGE01","EDGE02") {
    $items += New-Item2 "switch" "$Prefix-SW-$s" ([ordered]@{
        Model        = Get-Random -InputObject "Cisco C9200-48P","HPE Aruba 2930F"
        CPU_Pct      = Get-Random -Minimum 2 -Maximum 40
        Uptime_Days  = Get-Random -Minimum 1 -Maximum 400
        PortsUp      = Get-Random -Minimum 10 -Maximum 48
        PortErrors   = Get-Random -InputObject 0,0,0,3,12
        Temperature_C = Get-Random -Minimum 30 -Maximum 55
    })
}

# Wi-Fi controller
$items += New-Item2 "wifi" "$Prefix-ZoneDirector" ([ordered]@{
    APsOnline  = Get-Random -Minimum 18 -Maximum 22
    APsTotal   = 22
    Clients    = Get-Random -Minimum 50 -Maximum 400
    Alarms     = Get-Random -InputObject 0,0,1,2
})

# Microsoft 365 tenant
$items += New-Item2 "m365" "$Prefix-Tenant" ([ordered]@{
    ServiceHealth     = Get-Random -InputObject "Healthy","Healthy","Degraded (Exchange)"
    SecureScore_Pct   = Get-Random -Minimum 45 -Maximum 80
    ActiveAlerts      = Get-Random -InputObject 0,0,1,3
    LicencesAvailable = Get-Random -Minimum 0 -Maximum 25
})

# Intune summary
$items += New-Item2 "intune" "$Prefix-Intune" ([ordered]@{
    ManagedDevices = Get-Random -Minimum 150 -Maximum 300
    Compliant      = Get-Random -Minimum 140 -Maximum 150
    NonCompliant   = Get-Random -InputObject 0,2,5,9
    NotSyncedIn7d  = Get-Random -InputObject 0,1,4,12
    PendingApps    = Get-Random -InputObject 0,0,3
})

# Sophos Central summary
$items += New-Item2 "sophos" "$Prefix-Sophos" ([ordered]@{
    Endpoints       = Get-Random -Minimum 150 -Maximum 300
    HealthGood      = Get-Random -Minimum 140 -Maximum 150
    HealthBad       = Get-Random -InputObject 0,1,3
    ActiveAlerts    = Get-Random -InputObject 0,0,2,5
    TamperProtOff   = Get-Random -InputObject 0,0,1
})

$body = [ordered]@{ generated = $stamp; items = $items } | ConvertTo-Json -Depth 6

try {
    $r = Invoke-RestMethod -Uri $Url -Method Post -ContentType "application/json" `
            -Headers @{ "X-API-Key" = $ApiKey } -Body $body
    Write-Host "Posted OK: run $($r.run_id), $($r.items) item(s)" -ForegroundColor Green
} catch {
    Write-Host "Post failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
}
