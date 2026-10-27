# ============================================================
# Deploy-ToVps.ps1 - push the Monitor Dashboard code to the Fasthosts VPS.
#
# Sends ONLY: app.py, requirements.txt, templates\, static\, deploy\
# Never sends: .env, *.db, *.xml (credentials), *.json (client data), *.zip, *.ps1, Reports\ ...
# The VPS keeps its own database and secrets; they are never overwritten.
#
# Needs the built-in Windows OpenSSH client (ssh/scp) and tar (Windows 10 1803+).
# First-time server setup (user, folders, secrets, nginx) is in README.md - do that first.
#
#   .\Deploy-ToVps.ps1 -Server dashboard.example.com -User nat
#   .\Deploy-ToVps.ps1 -Server 203.0.113.5 -User nat -Port 2222 -KeyFile C:\Users\nat\.ssh\id_ed25519
# ============================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [Parameter(Mandatory)] [string] $User,
    [int]    $Port    = 22,
    [string] $KeyFile = "",
    [switch] $SkipAudit
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# Exactly what goes to the server - nothing else in this folder is ever uploaded.
$include = @("app.py", "requirements.txt", "templates", "static", "deploy")

foreach ($item in $include) {
    if (!(Test-Path (Join-Path $root $item))) { throw "Missing $item next to this script - aborting." }
}

# Sanity checks before anything leaves this PC
$base = Get-Content (Join-Path $root "templates\base.html") -Raw
if ($base -match 'cdn\.tailwindcss\.com') {
    throw "templates\base.html still loads the Tailwind CDN. Use static\app.css (see README 'Rebuilding the CSS')."
}
if (!(Test-Path (Join-Path $root "static\app.css"))) { throw "static\app.css missing - build it first (README)." }

$appText = Get-Content (Join-Path $root "app.py") -Raw
if ($appText -match 'debug\s*=\s*True') { throw "app.py contains debug=True - never deploy with debug on." }

if (-not $SkipAudit) {
    $audit = Get-Command pip-audit -ErrorAction SilentlyContinue
    if ($audit) {
        Write-Host "Checking requirements.txt for known vulnerabilities..." -ForegroundColor Cyan
        & pip-audit -r (Join-Path $root "requirements.txt")
        if ($LASTEXITCODE -ne 0) { throw "pip-audit found problems (or failed). Fix them, or rerun with -SkipAudit." }
    } else {
        Write-Host "pip-audit not installed - skipping vulnerability check (pip install pip-audit)." -ForegroundColor Yellow
    }
}

# Build a clean copy containing only the allowed items
$stage = Join-Path ([IO.Path]::GetTempPath()) ("monitor-deploy-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    foreach ($item in $include) { Copy-Item (Join-Path $root $item) -Destination $stage -Recurse }

    # Belt and braces: nothing secret-looking may be in the bundle
    $bad = Get-ChildItem $stage -Recurse -File -Force |
           Where-Object { $_.Name -match '^\.env' -or $_.Extension -in '.db', '.xml', '.json', '.zip', '.pfx', '.key' -or $_.FullName -match '__pycache__' }
    if ($bad) { throw "Refusing to deploy - unexpected files in bundle:`n$($bad.FullName -join "`n")" }

    $tgz = Join-Path ([IO.Path]::GetTempPath()) "monitor-deploy.tgz"
    if (Test-Path $tgz) { Remove-Item $tgz -Force }
    & tar -czf $tgz -C $stage @include
    if ($LASTEXITCODE -ne 0) { throw "tar failed" }

    Write-Host "`nBundle contents:" -ForegroundColor Cyan
    & tar -tzf $tgz | Where-Object { $_ -notmatch '/$' } | ForEach-Object { "  $_" }

    $sshArgs = @("-p", $Port)
    $scpArgs = @("-P", $Port)
    if ($KeyFile) { $sshArgs += @("-i", $KeyFile); $scpArgs += @("-i", $KeyFile) }
    $target = "$User@$Server"

    Write-Host "`nUploading to $target ..." -ForegroundColor Cyan
    & scp @scpArgs $tgz "${target}:/tmp/monitor-deploy.tgz"
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }

    # Unpack into a private temp folder on the VPS, run the installer with sudo, tidy up.
    # (No double quotes in here - Windows PowerShell 5.1 mangles them when calling ssh.
    #  The sed fixes Windows line endings in case a .sh file was edited in Notepad.)
    $remote = 'D=$(mktemp -d) && tar -xzf /tmp/monitor-deploy.tgz -C $D && rm -f /tmp/monitor-deploy.tgz && ' +
              'sed -i s/\\r$// $D/deploy/*.sh && sudo bash $D/deploy/remote-install.sh $D; rc=$?; rm -rf $D; exit $rc'
    Write-Host "Installing (you may be asked for your sudo password) ..." -ForegroundColor Cyan
    & ssh @sshArgs -t $target $remote
    if ($LASTEXITCODE -ne 0) { throw "Remote install failed - see output above." }

    Write-Host "`nDeployed. Check https://$Server and: ssh $target 'journalctl -u monitor-dashboard -n 50'" -ForegroundColor Green
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    if ($tgz -and (Test-Path $tgz)) { Remove-Item $tgz -Force -ErrorAction SilentlyContinue }
}
