<#
.SYNOPSIS
  TEST ONLY - reads real Monitor-Agent CSVs from a share (read-only) and posts
  them to the local Flask dashboard. Does not change, move or delete anything.

.EXAMPLE
  # 1. Dry run: see what would be sent, nothing is posted
  .\Test-LivePush.ps1 -SharePath "\\SERVER\MonitorShare" -DryRun

  # 2. Post to the local dashboard
  .\Test-LivePush.ps1 -SharePath "\\SERVER\MonitorShare" -ApiKey "PASTE-KEY"
#>
param(
    [Parameter(Mandatory)] [string] $SharePath,
    [string] $ApiKey,
    [string] $Url = "http://127.0.0.1:8080/api/ingest",
    [string] $Filter = "*.csv",
    [int]    $MaxAgeHours = 24,     # ignore CSVs from servers that haven't reported recently
    [switch] $DryRun
)

$ErrorActionPreference = "Stop"
$hostKeys = "ComputerName","Hostname","HostName","Server","ServerName","Name"

if (-not (Test-Path $SharePath)) { throw "Can't reach $SharePath" }
if (-not $DryRun -and -not $ApiKey) { throw "Give -ApiKey, or use -DryRun" }

$cutoff = (Get-Date).AddHours(-$MaxAgeHours)
$files  = Get-ChildItem -Path $SharePath -Filter $Filter -File |
          Where-Object LastWriteTime -gt $cutoff

if (-not $files) { throw "No CSVs newer than $MaxAgeHours hours in $SharePath" }

$byHost = @{}
foreach ($f in $files) {
    try { $rows = @(Import-Csv -Path $f.FullName) } catch {
        Write-Warning "Skipping $($f.Name): $_"; continue
    }
    if ($rows.Count -eq 0) { continue }

    $row   = $rows[-1]                       # latest row in the file
    $entry = [ordered]@{}
    foreach ($p in $row.PSObject.Properties) { $entry[$p.Name] = $p.Value }

    $name = $hostKeys | Where-Object { $entry[$_] } | Select-Object -First 1
    $hostName = if ($name) { $entry[$name] } else { $f.BaseName }
    if (-not $name) { $entry.Insert(0, "ComputerName", $f.BaseName) }

    $entry["SourceFile"]   = $f.Name
    $entry["FileModified"] = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")

    # keep only the newest file per server
    if (-not $byHost.ContainsKey($hostName) -or
        $byHost[$hostName].FileModified -lt $entry["FileModified"]) {
        $byHost[$hostName] = $entry
    }
}

$payload = [ordered]@{
    generated = (Get-Date).ToString("o")
    servers   = @($byHost.Values)
}
$json = $payload | ConvertTo-Json -Depth 5

Write-Host "Found $($byHost.Count) server(s) from $($files.Count) file(s)" -ForegroundColor Cyan

if ($DryRun) {
    $out = Join-Path $PWD "test-payload.json"
    $json | Set-Content $out -Encoding UTF8
    Write-Host "Dry run - payload written to $out (nothing posted)" -ForegroundColor Yellow
    return
}

try {
    $resp = Invoke-RestMethod -Uri $Url -Method Post -ContentType "application/json" `
                -Headers @{ "X-API-Key" = $ApiKey } `
                -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
    Write-Host "Posted OK: run $($resp.run_id), $($resp.servers) server(s)" -ForegroundColor Green
} catch {
    Write-Host "Post failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
}
