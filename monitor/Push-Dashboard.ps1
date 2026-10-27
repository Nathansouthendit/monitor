# ============================================================
# Push-Dashboard.ps1  (the site "relay")
#
# Runs as a Scheduled Task on the site's host server (every 5-15 min).
# Sends every JSON file in the outbox to the web dashboard, oldest first,
# then moves it to \sent. Only THIS server needs outbound HTTPS.
#
#   - Dashboard down / no internet  -> files stay in the outbox, retried next run
#   - Bad API key (401) / blocked (429) -> stops, retried next run, logged
#   - File the dashboard rejects (400) -> moved to \failed (it won't fix itself)
#   - Sending the same file twice is harmless (the dashboard ignores repeats)
#
# ONE-TIME SETUP - store the site's API key, encrypted for the task account.
# Run this ONCE, interactively, AS THE ACCOUNT THE SCHEDULED TASK RUNS AS
# (the encryption only works for that account on this server):
#
#   Get-Credential -UserName "dashboard" -Message "Paste the site's API key as the password" |
#       Export-CliXml -Path "C:\Monitor\dashboard_key.xml"
#
# Test it by hand first:   .\Push-Dashboard.ps1 -Verbose
# ============================================================
[CmdletBinding()]
param(
    [string] $DashboardUrl = "https://dashboard.example.com/api/ingest",   # <-- your VPS
    [string] $Outbox       = "C:\Monitor\DashboardOutbox",
    [string] $KeyPath      = "C:\Monitor\dashboard_key.xml",
    [int]    $KeepSentDays = 7,
    [int]    $MaxFilesPerRun = 50
)

$ErrorActionPreference = 'Stop'
$SentDir   = Join-Path $Outbox "sent"
$FailedDir = Join-Path $Outbox "failed"
$LogFile   = Join-Path $Outbox "push.log"

function Write-Log([string]$msg, [string]$colour = "Gray") {
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line -ForegroundColor $colour
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Get-HttpStatus($err) {
    try { return [int]$err.Exception.Response.StatusCode } catch { return 0 }
}

function Get-ErrorBody($err) {
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) { return $err.ErrorDetails.Message }
    try {
        $r = $err.Exception.Response
        if ($r -and $r.GetResponseStream) { return (New-Object IO.StreamReader($r.GetResponseStream())).ReadToEnd() }
    } catch { }
    return ""
}

foreach ($dir in @($Outbox, $SentDir, $FailedDir)) {
    if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

# Keep the log small
if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) {
    Move-Item $LogFile "$LogFile.old" -Force
}

if ($DashboardUrl -notmatch '^https://' -and $DashboardUrl -notmatch '^http://(127\.0\.0\.1|localhost)[:/]') {
    Write-Log "Refusing to send: DashboardUrl must be https:// (got $DashboardUrl)" "Red"; exit 1
}
if (!(Test-Path $KeyPath)) {
    Write-Log "API key file not found at $KeyPath - see ONE-TIME SETUP at the top of this script" "Red"; exit 1
}
try {
    $apiKey = (Import-CliXml $KeyPath).GetNetworkCredential().Password
} catch {
    Write-Log "Could not decrypt $KeyPath - it must be created by the same account that runs this task, on this server" "Red"; exit 1
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$headers = @{ "X-API-Key" = $apiKey }

$files = @(Get-ChildItem -Path $Outbox -Filter "*.json" -File | Sort-Object LastWriteTime | Select-Object -First $MaxFilesPerRun)
if ($files.Count -eq 0) { Write-Verbose "Nothing to send"; }

$sent = 0
foreach ($f in $files) {
    try {
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $resp  = Invoke-RestMethod -Uri $DashboardUrl -Method Post -Headers $headers `
                    -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 60 -UseBasicParsing
        Move-Item -Path $f.FullName -Destination (Join-Path $SentDir $f.Name) -Force
        $sent++
        Write-Log "Sent $($f.Name): $($resp.items) item(s), $($resp.new_readings) new" "Green"
    }
    catch {
        $code = Get-HttpStatus $_
        $body = Get-ErrorBody $_
        if ($code -eq 400 -or $code -eq 413) {
            Move-Item -Path $f.FullName -Destination (Join-Path $FailedDir $f.Name) -Force
            Write-Log "REJECTED $($f.Name) (HTTP $code) - moved to failed: $body" "Red"
            continue
        }
        if ($code -eq 401) { Write-Log "HTTP 401 - the API key was refused. Check $KeyPath / rotate-key on the dashboard." "Red" }
        elseif ($code -eq 429) { Write-Log "HTTP 429 - this IP is temporarily blocked after bad API keys. Will retry next run." "Yellow" }
        elseif ($code -eq 403) { Write-Log "HTTP 403 - $body" "Red" }
        else { Write-Log "Could not reach the dashboard ($($_.Exception.Message)). Will retry next run." "Yellow" }
        break      # leave this and later files in the outbox, in order
    }
}

# Housekeeping
Get-ChildItem $SentDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepSentDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $Outbox -Filter "*.tmp" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

$left = @(Get-ChildItem -Path $Outbox -Filter "*.json" -File).Count
if ($sent -or $left) { Write-Log "Run complete: $sent sent, $left waiting" }
if ($left -gt 100) { Write-Log "WARNING: $left files waiting - the dashboard hasn't been reachable for a while" "Yellow" }
