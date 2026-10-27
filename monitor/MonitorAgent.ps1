# ============================================================
# Monitor-Agent.ps1
#
# Runs hourly (via Scheduled Task) on EVERY monitored device -
# server or PC. Collects local host stats and drops a CSV onto
# a shared folder for Monitor-Master.ps1 to pick up.
#
# This script does NOT build a dashboard and does NOT send
# alert emails - Monitor-Master.ps1 does both, once, across
# every device. Keeping that logic in one place avoids getting
# one alert email per device per issue.
# ============================================================

# ================== CONFIG ==================
$Server            = $env:COMPUTERNAME
$CsvFolder         = "C:\Monitor\Reports"           # local history for this device
$ShareRoot         = "\\ymca-host-02\MonitorShare"   # <-- UPDATE to your real share path
$DeviceShareFolder = Join-Path $ShareRoot $Server

foreach ($path in @($CsvFolder, $DeviceShareFolder)) {
    if (!(Test-Path $path)) {
        try {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        } catch {
            Write-Host "Could not create $path : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

$Timestamp  = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
$CurrentCsv = Join-Path $CsvFolder "stats_$Timestamp.csv"

# ================== DATA COLLECTION ==================
$CPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples.CookedValue
$OS  = Get-CimInstance Win32_OperatingSystem
$MemoryUsedGB  = [math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1MB, 2)
$TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)

$Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $percent = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace/$_.Size)*100,2) } else { 0 }
    $status  = if ($percent -lt 10) { "CRITICAL" } elseif ($percent -lt 20) { "WARNING" } else { "OK" }
    [PSCustomObject]@{
        DeviceID    = $_.DeviceID
        SizeGB      = [math]::Round($_.Size/1GB,2)
        FreeGB      = [math]::Round($_.FreeSpace/1GB,2)
        FreePercent = $percent
        Status      = $status
    }
}

# ================== EVENTS ==================
$Events = @()

# ✅ HOST SYSTEM EVENTS
try {
    $HostSystemEvents = Get-WinEvent -MaxEvents 10 -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            System = $Server
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Id = $_.Id
            Level = $_.LevelDisplayName
            Message = $_.Message.Substring(0,200)
        }
    }
} catch {
    $HostSystemEvents = @()
}

# ✅ HOST UPDATE EVENTS
try {
    $HostUpdateEvents = Get-WinEvent -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" -MaxEvents 10 |
    ForEach-Object {
        [PSCustomObject]@{
            System = $Server
            TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Id = $_.Id
            Level = $_.LevelDisplayName
            Message = $_.Message.Substring(0,200)
        }
    }
} catch {
    $HostUpdateEvents = @()
}

$Events += $HostSystemEvents
$Events += $HostUpdateEvents

# ================== BACKUP ==================
try {
    if (Get-Module -ListAvailable WindowsServerBackup) {

        $BackupSummary = Get-WBSummary
        $lastBackup = $BackupSummary.LastSuccessfulBackupTime

        if (!$lastBackup -or $lastBackup -eq [datetime]::MinValue) {
            $lastBackup = $null
        }

        $BackupStatus = [PSCustomObject]@{
            LastSuccessful = if ($lastBackup) {
                $lastBackup.ToString("yyyy-MM-ddTHH:mm:ss")
            } else {
                $null
            }
        }

    } else {
        throw "Windows Server Backup module not found"
    }
}
catch {
    $BackupStatus = [PSCustomObject]@{
        LastSuccessful = $null
    }
}

# ================== HOST UPDATE STATUS ==================
$HostUpdateReport = @()

try {

    $isRebootPending = $false

    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { $isRebootPending = $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { $isRebootPending = $true }

    $rebootText = if ($isRebootPending) { "YES" } else { "No" }

    $Searcher     = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $SearchResult = $Searcher.Search("IsInstalled=0 and IsHidden=0")

    if ($SearchResult.Updates.Count -gt 0){
        $HostUpdateReport = $SearchResult.Updates | ForEach-Object {
            [PSCustomObject]@{
                System = "HOST"
                Title  = $_.Title
                Status = if($_.IsDownloaded){"Ready"}else{"Needs Download"}
                SizeMB = [math]::Round($_.MaxDownloadSize/1MB, 2)
                Reboot = $rebootText
            }
        }
    }
    else {
        $HostUpdateReport = @([PSCustomObject]@{
            System="HOST"; Title="Up to date"; Status="Success"; SizeMB="0"; Reboot=$rebootText
        })
    }

}
catch {
    $HostUpdateReport = @([PSCustomObject]@{
        System="HOST"; Title="Error"; Status="Failed"; SizeMB="-"; Reboot="Error"
    })
}

# ================== SAVE ==================
$Stats = [PSCustomObject]@{
    Timestamp           = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Device              = $Server
    CPU_Load            = [math]::Round($CPU,2)
    Memory_UsedGB       = $MemoryUsedGB
    Total_MemoryGB      = $TotalMemoryGB
    Disk_Free           = ($Disks   | ConvertTo-Json -Compress)
    Events_JSON         = [System.Web.HttpUtility]::HtmlEncode(($Events | ConvertTo-Json -Compress))
    Backup_Status       = ($BackupStatus | ConvertTo-Json -Compress)
    Host_Update_Details = ($HostUpdateReport | ConvertTo-Json -Compress)
}

$Stats | Export-Csv -Path $CurrentCsv -NoTypeInformation

# ✅ Keep local history bounded to the last 50 runs
Get-ChildItem $CsvFolder -Filter "stats_*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 50 |
    Remove-Item -Force -ErrorAction SilentlyContinue

# ================== PUSH TO SHARE ==================
# This is what Monitor-Master.ps1 reads to build the combined
# dashboard and evaluate alerts across every device.
try {
    Copy-Item -Path $CurrentCsv -Destination $DeviceShareFolder -Force -ErrorAction Stop
} catch {
    Write-Host "Could not copy stats to $DeviceShareFolder : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "This run was still saved locally at $CurrentCsv, but the master won't see it until the share is reachable again." -ForegroundColor Yellow
}

# ✅ Keep the share copy bounded too
Get-ChildItem $DeviceShareFolder -Filter "stats_*.csv" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 50 |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "✅ Agent run complete for $Server"