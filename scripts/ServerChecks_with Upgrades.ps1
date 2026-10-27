#-- CONFIG SECTION             --#

$Server = $env:COMPUTERNAME

$PreviousCsv = "C:\Monitor\previous_stats.csv"

$CurrentCsv  = "C:\Monitor\current_stats.csv"

$Timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")

$DashboardPath = "c:\monitor\$($env:COMPUTERNAME)_$timestamp.html"

$SessionOpt = New-PSSessionOption -IdleTimeout 120000 -OperationTimeout 120000

Get-Service | ConvertTo-Html | Out-File -FilePath $DashboardPath

#-- CONFIG SECTION --#

$CredPath = "C:\Monitor\vm_creds.xml"

# Logic for Automation:
if (Test-Path $CredPath) {
    # If the file exists, import it silently (No popup)
    $VMCreds = Import-CliXml -Path $CredPath
} else {
    # If the file is missing, ask the user ONCE and save it
    Write-Host "Credential file not found. Creating baseline..." -ForegroundColor Yellow
    $VMCreds = Get-Credential
    $VMCreds | Export-CliXml -Path $CredPath
    Write-Host "Credentials saved to $CredPath. Only this user/machine can decrypt it." -ForegroundColor Green
}





#-----  NEW COMPARISON SECTION (SIDE-BY-SIDE ALL STATS) ----#
$ComparisonTable = @()
$EmailChangeText = ""

if (Test-Path $PreviousCsv) {
    $Old = Import-Csv $PreviousCsv
    $New = Import-Csv $CurrentCsv
    
    foreach ($Property in $New.PSObject.Properties.Name) {
        # Skip the Timestamp for comparison logic, but we can include it in the table
        if ($Property -eq "Timestamp") { continue }

        # Create an object for EVERY metric to show side-by-side
        $IsChanged = if ($New.$Property -ne $Old.$Property) { "YES" } else { "No" }
        
        $ComparisonTable += [PSCustomObject]@{
            Metric   = $Property
            Previous = $Old.$Property
            Current  = $New.$Property
            Changed  = $IsChanged
        }

        # Still build the email text ONLY for actual changes
        if ($IsChanged -eq "YES") {
            $EmailChangeText += "$Property changed:`n  OLD: $($Old.$Property)`n  NEW: $($New.$Property)`n`n"
        }
    }
} else {
    $EmailChangeText = "No previous baseline found - baseline created."
}


function Convert-ToHtmlTable {
    param($Data, [string]$Title = "")

    # Safety check: If Data is empty, just return the message
    if (-not $Data) { return "<h2>$Title</h2><p>No data available.</p>" }

    # Force Data to be an array so [0] always works
    $DataArray = @($Data)

    $html = "<h2>$Title</h2>"
    $html += "<table border='1' cellspacing='0' cellpadding='4'>"

    # 1. Header row
    $html += "<tr>"
    foreach ($col in $DataArray[0].psobject.Properties.Name) {
        $html += "<th>$col</th>"
    }
    $html += "</tr>" # <--- You had a } here originally that closed the function!

    # 2. Data rows (This part was likely being cut off)
    foreach ($row in $DataArray) {
        $html += "<tr>"
        foreach ($col in $row.psobject.Properties.Name) {
            $html += "<td>$($row.$col)</td>"
        }
        $html += "</tr>"
    }

    $html += "</table>"
    return $html
}

    
   

# Email settings

#$From = "nathanginn1970@gmail.com"
#
#$To = "nathan@southendit.com"
#
#$Subject = "System Change Alert for $Server"
#
#$SMTPServer = "smtp.google.com"
#
#$SMTPPort = 587
#
#$Username = "nathanginn1970@gmail.com"
#
#$Password = "hjfi ysgh jyvh cyjs" | ConvertTo-SecureString -AsPlainText -Force
#
#$Cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)



#---            COLLECT HARDWARE & VM STATS            --#



# 1. Host CPU & Memory

$CPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples.CookedValue

$OS = Get-CimInstance Win32_OperatingSystem

$MemoryUsedGB = [math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1MB, 2)



# 2. Hyper-V VM Status (NEW SECTION)

$VMStats = Get-VM | Select-Object Name, State, CPUUsage, @{n="AssignedMemGB";e={[math]::Round($_.MemoryAssigned/1GB, 2)}}



# 3. Per-disk free space

$Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |

    Select-Object DeviceID, @{n="FreeGB";e={[math]::Round($_.FreeSpace/1GB,2)}}



#--- 4. Service status & Events ---#

# Get Current Events
$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Level     = 1, 2, 3 
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message

# Parse Previous Events (Now $Old is defined!)
$PreviousEvents = if ($Old.Events_JSON) { $Old.Events_JSON | ConvertFrom-Json } else { @() }

# Create HTML for Current Events
if ($null -ne $Events) {
    $currentEvtHtml = Convert-ToHtmlTable -Data $Events -Title "Current System Events (Last Hour)"
    $EventsJson = $Events | ConvertTo-Json -Compress
} else {
    $currentEvtHtml = "<h3>Current System Events</h3><p style='color:green;'>No issues found in the last hour.</p>"
    $EventsJson = ""
}



#--- Retrieve and Decode Previous Events (Fixed for Single Objects) ---#
$PreviousEvents = @()
if ($Old -and $Old.Events_JSON -and ($Old.Events_JSON -ne "")) {
    try {
        $decoded = $Old.Events_JSON | ConvertFrom-Json
        
        # This is the "Magic" fix: 
        # If $decoded is a single object, wrap it in @() to make it an array.
        if ($null -ne $decoded) {
            $PreviousEvents = @($decoded) 
        }
    } catch {
        Write-Host "Note: Could not parse previous events JSON." -ForegroundColor Gray
    }
}

# Create HTML for Previous Events
if ($PreviousEvents -and $PreviousEvents.Count -gt 0) {
    $prevEvtHtml = Convert-ToHtmlTable -Data $PreviousEvents -Title "Previous Run Events"
} else {
    # If this shows up, it means $PreviousEvents.Count was 0 or null
    $prevEvtHtml = "<h3>Previous Run Events</h3><p style='color:orange;'>Baseline exists, but no events were found in the JSON string.</p>"
}


# Combine them into a side-by-side container for the dashboard
$combinedEvtHtml = @"
<h2>Event Comparison</h2>
<div style="display: flex; gap: 20px;">
    <div style="flex: 1;">$currentEvtHtml</div>
    <div style="flex: 1; opacity: 0.7;">$prevEvtHtml</div>
</div>
"@




#--- 6. Windows Backup Status ---#
try {
    # Import the backup module if not already loaded
    if (!(Get-Module -ListAvailable WindowsServerBackup)) {
        throw "Windows Server Backup feature not installed."
    }
    
    $BackupSummary = Get-WBSummary
    $BackupStats = [PSCustomObject]@{
        LastSuccessfulRun = $BackupSummary.LastSuccessfulBackupTime
        LastAttemptTime   = $BackupSummary.LastBackupTime
        LastResult        = $BackupSummary.LastBackupResultHR
    }
    $backupHtml = Convert-ToHtmlTable -Data $BackupStats -Title "Windows Backup Status"
} catch {
    $backupHtml = "<h2>Windows Backup Status</h2><p style='color:orange;'>Windows Server Backup is not configured or accessible: $($_.Exception.Message)</p>"
}

#--- 7. Check Available & Ready-to-Install Updates ---#
try {
    Write-Host "Checking for Windows Updates..." -ForegroundColor Cyan
    
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    
    # Query for updates not yet installed
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")
    
    $AllUpdates = foreach ($update in $SearchResult.Updates) {
        [PSCustomObject]@{
            Title        = $update.Title
            Status       = if ($update.IsDownloaded) { "Ready to Install" } else { "Needs Download" }
            SizeMB       = [math]::Round($update.MaxDownloadSize/1MB, 2)
            MsrcSeverity = $update.MsrcSeverity
        }
    }

    if ($AllUpdates.Count -gt 0) {
        $updateHtml = Convert-ToHtmlTable -Data $AllUpdates -Title "Windows Update Status ($($AllUpdates.Count) Total)"
    } else {
        $updateHtml = "<h2>Windows Updates</h2><p style='color:green;'>No pending updates found.</p>"
    }
} catch {
    $updateHtml = "<h2>Windows Updates</h2><p style='color:red;'>Update check failed: $($_.Exception.Message)</p>"
}
#--- 8.1 Check for Pending Reboot ---#
$RebootPending = $false
if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { $RebootPending = $true }
if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { $RebootPending = $true }

$rebootStyle = if ($RebootPending) { "background: #d9534f; color: white; padding: 10px; font-weight: bold;" } else { "color: green;" }
$rebootText = if ($RebootPending) { "⚠️ REBOOT REQUIRED to finish updates!" } else { "No reboot pending." }

$rebootHtml = "<h3>Reboot Status</h3><p style='$rebootStyle'>$rebootText</p>"

# 9 Gather VM Guest disks 
# VMs that currently have broken PowerShell Direct
$SkipVMs = @("eh-pbx") 

$VMGuestDiskStats = Get-VM | Where-Object {$_.State -eq 'Running'} | ForEach-Object {
    $vmName = $_.Name
    
    if ($vmName -in $SkipVMs) {
        [PSCustomObject]@{VM=$vmName; DeviceID="SKIPPED"; SizeGB="N/A"; FreeGB="N/A"; FreePercent="N/A"}
    } else {
        try {
            Invoke-Command -VMName $vmName -Credential $VMCreds -ErrorAction Stop -ScriptBlock {
                Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
                @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}},
                @{N="FreeGB";E={[math]::Round($_.FreeSpace/1GB,2)}},
                @{N="FreePercent";E={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
            } | Select-Object @{N="VM";E={$vmName}}, DeviceID, SizeGB, FreeGB, FreePercent
        } catch {
            [PSCustomObject]@{VM=$vmName; DeviceID="Error"; SizeGB="N/A"; FreeGB="Connection Broken"; FreePercent="N/A"}
        }
    }
}

$vmDiskHtml = Convert-ToHtmlTable -Data $VMGuestDiskStats -Title "Detailed VM Guest Disk Space"

# 10 DOWNLOAD & INSTALL UPDATES FOR RUNNING VMs
# CONFIG
$ThrottleLimit = 5          # Number of VMs to process simultaneously
$TaskTimeoutMinutes = 25     # Max wait per VM

$VMs = Get-VM | Where-Object { $_.State -eq 'Running' }

$VMUpdateReport = $VMs | ForEach-Object -Parallel {
    param($SkipVMs, $VMCreds, $TaskTimeoutMinutes)

    $vmName = $_.Name

    if ($vmName -in $SkipVMs) {
        return [PSCustomObject]@{
            VM     = $vmName
            Title  = "Skipped"
            Status = "Skipped"
            SizeMB = "-"
        }
    }

    try {
        Write-Output "Starting updates on $vmName"

        $UpdateScript = {
            $log = "C:\Windows\Temp\vm_update_log.txt"

            function Log($msg) {
                "$((Get-Date).ToString('s')) - $msg" | Out-File $log -Append
            }

            Log "Starting update scan"

            # Windows Update scan
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()

            $result = $searcher.Search("IsInstalled=0 and IsHidden=0")

            Log "Found $($result.Updates.Count) updates"

            if ($result.Updates.Count -eq 0) {
                "Up to date" | Out-File "C:\Windows\Temp\update_result.txt"
                return
            }

            $installList = New-Object -ComObject Microsoft.Update.UpdateColl

            foreach ($u in $result.Updates) {
                if ($u.InstallationBehavior.RebootBehavior -eq 0) {
                    $installList.Add($u) | Out-Null
                }
            }

            if ($installList.Count -gt 0) {
                Log "Downloading updates"

                $downloader = $session.CreateUpdateDownloader()
                $downloader.Updates = $installList
                $downloader.Download()

                Log "Installing updates"

                $installer = $session.CreateUpdateInstaller()
                $installer.Updates = $installList
                $resultInstall = $installer.Install()
            }

            $report = @()

            foreach ($u in $installList) {
                $report += [PSCustomObject]@{
                    Title  = $u.Title
                    Status = "Installed"
                    SizeMB = [math]::Round($u.MaxDownloadSize / 1MB, 2)
                }
            }

            $report | ConvertTo-Json | Out-File "C:\Windows\Temp\update_result.txt"
            Log "Completed updates"
        }

        # Run inside VM
        $job = Invoke-Command -VMName $vmName -Credential $VMCreds -ScriptBlock {
            param($script)

            Start-Job -ScriptBlock $script

        } -ArgumentList $UpdateScript -AsJob

        # Wait with timeout
        $completed = $false
        $start = Get-Date

        while (-not $completed) {
            Start-Sleep 5

            $state = (Get-Job -Id $job.Id).State

            if ($state -eq "Completed") {
                $completed = $true
            }

            if (((Get-Date) - $start).TotalMinutes -gt $TaskTimeoutMinutes) {
                Stop-Job -Id $job.Id -Force
                throw "Timeout after $TaskTimeoutMinutes minutes"
            }
        }

        # Retrieve result
        $RawResult = Invoke-Command -VMName $vmName -Credential $VMCreds -ScriptBlock {
            if (Test-Path "C:\Windows\Temp\update_result.txt") {
                Get-Content "C:\Windows\Temp\update_result.txt" -Raw
            }
        }

        if ($RawResult -eq "Up to date") {
            return [PSCustomObject]@{
                VM     = $vmName
                Title  = "All clear"
                Status = "Up to Date"
                SizeMB = "0"
            }
        }

        $Decoded = $RawResult | ConvertFrom-Json

        foreach ($r in $Decoded) {
            [PSCustomObject]@{
                VM     = $vmName
                Title  = $r.Title
                Status = $r.Status
                SizeMB = $r.SizeMB
            }
        }

    } catch {
        [PSCustomObject]@{
            VM     = $vmName
            Title  = $_.Exception.Message
            Status = "Failed"
            SizeMB = "-"
        }
    }

} -ThrottleLimit $ThrottleLimit -ArgumentList $SkipVMs, $VMCreds, $TaskTimeoutMinutes

# Output to HTML
$vmUpdateHtml = Convert-ToHtmlTable -Data $VMUpdateReport -Title "VM Guest Update Status"


# 11  Build unified object for Comparison

$Stats = [PSCustomObject]@{

    Timestamp     = Get-Date

    Server        = $Server

    CPU_Load      = [math]::Round($CPU,2)

    Memory_UsedGB = $MemoryUsedGB

    VM_Count      = ($VMStats | Measure-Object).Count

    Disk_Free     = ($Disks | ConvertTo-Json -Compress)

    VM_Details    = ($VMStats | ConvertTo-Json -Compress)

    Events_JSON   = $EventsJson  

    LastBackupDate = $BackupStats.LastSuccessfulRun # For change tracking

}



$Stats | Export-Csv -Path $CurrentCsv -NoTypeInformation









#----                Email Alert if Anything Changed              ---#

#if ($ChangeObjects.Count -gt 0) {

#    $Body = "Changes detected on $Server at $(Get-Date):`n`n$EmailChangeText"

#    

#    Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body `

#        -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl -Credential $Cred

#    

#   Write-Host "Changes detected! Email alert sent." -ForegroundColor Yellow

#}





#---             Generate HTML Dashboard Section                ---#





#--- Create HTML for Previous Events ---#
if ($PreviousEvents -and $PreviousEvents.Count -gt 0) {
    $prevEvtHtml = Convert-ToHtmlTable -Data $PreviousEvents -Title "Previous Run Events"
} else {
    $prevEvtHtml = "<h2>Previous Run Events</h2><p style='color:gray;'>No events were captured in the previous run.</p>"
}

# 2. Build the standard stat tables (These were in your original script)

$cpuMemHtml = @"

<h2>Host Overview</h2>

<table>
<tr><th>Performaance Stats</th><td style="background: #0078D4; color: white;">Current</td><td  style="background: #0078D4; color: white;">Previous</td>


<tr><th>CPU Load (%)</th><td>$($Stats.CPU_Load)</td><td>$($old.cpu_load)</td></tr>

<tr><th>Memory Used (GB)</th><td>$($Stats.Memory_UsedGB)</td><td>$($old.Memory_UsedGB)</td></tr>

<tr><th>Total VMs</th><td>$($Stats.VM_Count)</td><td>$($old.VM_Count)</td></tr>

</table>

"@



$vmHtml      = Convert-ToHtmlTable -Data $VMStats -Title "Virtual Machine Status"

$diskHtml    = Convert-ToHtmlTable -Data $Disks   
#$old_diskhtml = Convert-ToHtmlTable -Data $old.Disk_Free

$evtHtml     = Convert-ToHtmlTable -Data $Events  -Title "Recent System Errors"

$thermalText = if ($Thermal -is [string]) { $Thermal } else { (($Thermal | ForEach-Object { "$([math]::Round($_.TempC,1)) °C" }) -join ", ") }

# 2.1 Build the standard disk tables --#


#--- 2.1 Build the standard disk tables (Improved) ---#

# 1. Parse the JSON strings back into usable objects
$CurrentDisks = $Disks # This is already an object from Step 3 in your script
$PreviousDisks = if ($Old.Disk_Free) { $Old.Disk_Free | ConvertFrom-Json } else { $null }

# 2. Build the HTML manually to ensure a clean side-by-side view
$diskTableRows = ""

foreach ($disk in $CurrentDisks) {
    $driveId = $disk.DeviceID
    
    # Find the matching drive in the previous stats
    $oldDisk = $PreviousDisks | Where-Object { $_.DeviceID -eq $driveId }
    $oldFree = if ($oldDisk) { "$($oldDisk.FreeGB) GB" } else { "N/A" }
    
    # Check for changes to highlight (optional)
    $colorStyle = ""
    if ($oldDisk -and $disk.FreeGB -ne $oldDisk.FreeGB) {
        $colorStyle = "style='color: #d9534f; font-weight: bold;'" # Red text if changed
    }

    $diskTableRows += "<tr>
        <td>$driveId</td>
        <td $colorStyle>$($disk.FreeGB) GB</td>
        <td>$oldFree</td>
    </tr>"
}

$diskHtml = @"
<h2>Disk Overview</h2>
<table>
    <tr>
        <th>Drive</th>
        <th style="background: #0078D4; color: white;">Current Free</th>
        <th style="background: #555; color: white;">Previous Free</th>
    </tr>
    $diskTableRows
</table>
"@

# 3. Assemble the Master HTML Template

$Html = @"

<!DOCTYPE html>

<html>

<head>

    <meta charset="utf-8" />

    <title>Dashboard - $Server</title>

    <style>

        body { font-family: sans-serif; margin: 20px; background: #f5f5f5; }

        table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 20px; }

        th, td { border: 1px solid #ccc;padding:8px;  font-size: 13px; text-align: left; }

        th { background: #0078D4; color: white; }

        h2 { color: #333; border-bottom: 2px solid #0078D4; padding-bottom: 5px; }
        .event-container { display: flex; gap: 20px; align-items: flex-start; }
    .event-box { flex: 1; min-width: 0; } /* min-width: 0 prevents table overflow */

    </style>

</head>

<body>

    <h1>System Dashboard - $Server</h1>

    <p>Last updated: $(Get-Date)</p>

    

$cpuMemHtml

$diskHtml

    $backuphtml

    $updatehtml

    $combinedEvtHtml
     
     $vmHtml

     $vmDiskHtml

     $vmUpdateHtml

</body>

</html>

"@



# 4. Save the file and rotate the CSV baseline

$Html | Set-Content -Path $DashboardPath -Encoding UTF8



# Update the "previous" file so the next run has something to compare against

Copy-Item $CurrentCsv $PreviousCsv -Force



Write-Host "Dashboard generated successfully at: $DashboardPath" -ForegroundColor Green