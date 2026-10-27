<#
.SYNOPSIS
  Sends made-up server stats to the local dashboard for testing.

.EXAMPLE
  .\Send-TestData.ps1 -ApiKey "PASTE-KEY"
  .\Send-TestData.ps1 -ApiKey "PASTE-KEY" -Count 8 -Prefix "WL"
#>
param(
    [Parameter(Mandatory)] [string] $ApiKey,
    [string] $Url    = "http://127.0.0.1:8080/api/ingest",
    [int]    $Count  = 5,
    [string] $Prefix = "EW"
)

$roles = "DC01","DC02","FILE01","PRINT01","SQL01","APP01","WSUS01","BACKUP01","HV01","HV02"
$os    = "Windows Server 2019 Standard","Windows Server 2022 Standard","Windows Server 2016 Standard"

$servers = foreach ($i in 0..($Count - 1)) {
    $diskTotal = Get-Random -InputObject 100,200,500,1000
    $diskFree  = [math]::Round($diskTotal * (Get-Random -Minimum 3 -Maximum 70) / 100, 1)
    [ordered]@{
        ComputerName     = "$Prefix-SRV-$($roles[$i % $roles.Count])"
        OS               = Get-Random -InputObject $os
        CPU_Pct          = Get-Random -Minimum 1 -Maximum 95
        RAM_UsedPct      = Get-Random -Minimum 20 -Maximum 97
        DiskC_TotalGB    = $diskTotal
        DiskC_FreeGB     = $diskFree
        Uptime_Days      = Get-Random -Minimum 0 -Maximum 120
        PendingReboot    = Get-Random -InputObject "No","No","No","Yes"
        LastPatched      = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 60)).ToString("yyyy-MM-dd")
        StoppedServices  = Get-Random -InputObject 0,0,0,1,2
        LastCheck        = (Get-Date).ToString("yyyy-MM-dd HH:mm")
    }
}

$body = [ordered]@{ generated = (Get-Date).ToString("o"); servers = @($servers) } |
        ConvertTo-Json -Depth 5

try {
    $r = Invoke-RestMethod -Uri $Url -Method Post -ContentType "application/json" `
            -Headers @{ "X-API-Key" = $ApiKey } -Body $body
    Write-Host "Posted OK: run $($r.run_id), $($r.servers) server(s)" -ForegroundColor Green
} catch {
    Write-Host "Post failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
}