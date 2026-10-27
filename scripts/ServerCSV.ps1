#---------------- CONFIG ----------------#

$Server      = $env:COMPUTERNAME
$MonitorRoot = "C:\Monitor"

if (!(Test-Path $MonitorRoot)) {
    New-Item -Path $MonitorRoot -ItemType Directory -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$CsvName   = "stats_$Timestamp.csv"
$CsvPath   = Join-Path $MonitorRoot $CsvName

#---------------- VM Credentials ----------------#

$CredPath = Join-Path $MonitorRoot "vm_creds.xml"

if (Test-Path $CredPath) {
    $VMCreds = Import-CliXml -Path $CredPath
} else {
    Write-Host "Credential file not found. Creating baseline..." -ForegroundColor Yellow
    $VMCreds = Get-Credential
    $VMCreds | Export-CliXml -Path $CredPath
    Write-Host "Credentials saved." -ForegroundColor Green
}

#---------------- COLLECT HOST & VM STATS ----------------#

# CPU & RAM
$CPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples.CookedValue
$OS  = Get-CimInstance Win32_OperatingSystem
$MemoryUsedGB = [math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1MB, 2)

# VM Stats
$VMStats = Get-VM | Select-Object Name, State, CPUUsage,
    @{n="AssignedMemGB";e={[math]::Round($_.MemoryAssigned/1GB, 2)}}

# Disk Stats
$Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID, @{n="FreeGB";e={[math]::Round($_.FreeSpace/1GB,2)}}

# Events (last hour)
$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Level     = 1, 2, 3
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, Message

$EventsJson = if ($Events) { $Events | ConvertTo-Json -Compress } else { "" }

# Backup Status
try {
    if (Get-Module -ListAvailable WindowsServerBackup) {
        $BackupSummary = Get-WBSummary
        $LastBackup = $BackupSummary.LastSuccessfulBackupTime
    } else {
        $LastBackup = "Not Installed"
    }
} catch {
    $LastBackup = "Unavailable"
}

#---------------- HOST WINDOWS UPDATE STATUS ----------------#

try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult   = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")

    $HostUpdates = foreach ($update in $SearchResult.Updates) {
        [PSCustomObject]@{
            Title        = $update.Title
            Status       = if ($update.IsDownloaded) { "Ready" } else { "Needs Download" }
            SizeMB       = [math]::Round($update.MaxDownloadSize/1MB, 2)
            Severity     = $update.MsrcSeverity
        }
    }
} catch {
    $HostUpdates = @()
}

$HostUpdatesJson = $HostUpdates | ConvertTo-Json -Compress

#---------------- VM WINDOWS UPDATE STATUS ----------------#

$SkipVMs = @("eh-pbx")  # Your skip list

$VMUpdateReport = Get-VM | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
    $vmName = $_.Name

    if ($vmName -in $SkipVMs) {
        [PSCustomObject]@{
            VM     = $vmName
            Title  = "Skipped"
            Status = "Skipped"
            SizeMB = "-"
        }
    } else {
        try {
            $updates = Invoke-Command -VMName $vmName -Credential $VMCreds -ErrorAction Stop -ScriptBlock {
                $Searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
                $SearchResult = $Searcher.Search("IsInstalled=0 and IsHidden=0")

                if ($SearchResult.Updates.Count -gt 0) {
                    return $SearchResult.Updates | Select-Object Title,
                        @{n='Status';e={if($_.IsDownloaded){"Ready"}else{"Needs Download"}}},
                        @{n='SizeMB';e={[math]::Round($_.MaxDownloadSize/1MB, 2)}}
                }
            }

            if ($null -eq $updates) {
                [PSCustomObject]@{
                    VM     = $vmName
                    Title  = "Up to date"
                    Status = "Success"
                    SizeMB = "0"
                }
            } else {
                $updates | ForEach-Object {
                    [PSCustomObject]@{
                        VM     = $vmName
                        Title  = $_.Title
                        Status = $_.Status
                        SizeMB = $_.SizeMB
                    }
                }
            }
        } catch {
            [PSCustomObject]@{
                VM     = $vmName
                Title  = "Error: $($_.Exception.Message)"
                Status = "Failed"
                SizeMB = "-"
            }
        }
    }
}

$VMUpdatesJson = $VMUpdateReport | ConvertTo-Json -Compress

#---------------- BUILD CSV OBJECT ----------------#

$Stats = [PSCustomObject]@{
    Timestamp        = Get-Date
    Server           = $Server
    CPU_Load         = [math]::Round($CPU,2)
    Memory_UsedGB    = $MemoryUsedGB
    VM_Count         = ($VMStats | Measure-Object).Count
    Disk_Free        = ($Disks | ConvertTo-Json -Compress)
    VM_Details       = ($VMStats | ConvertTo-Json -Compress)
    Events_JSON      = $EventsJson
    LastBackupDate   = $LastBackup
    HostUpdates_JSON = $HostUpdatesJson
    VMUpdates_JSON   = $VMUpdatesJson
}

#---------------- EXPORT CSV ----------------#

$Stats | Export-Csv -Path $CsvPath -NoTypeInformation

Write-Host "CSV exported: $CsvPath" -ForegroundColor Green

#---------------- UPDATE CSV LIST FOR DASHBOARD ----------------#

$Csvs = Get-ChildItem $MonitorRoot -Filter "stats_*.csv" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -ExpandProperty Name

$Csvs | ConvertTo-Json | Set-Content "$MonitorRoot\csv_list.json"
