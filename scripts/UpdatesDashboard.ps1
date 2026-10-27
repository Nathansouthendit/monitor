#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Import-Module Hyper-V

################################################################################
# CONFIG
################################################################################

$Global:Credential = $null

################################################################################
# LOAD VM CREDENTIALS
################################################################################

$CredFile = Join-Path $PSScriptRoot "vm_creds.xml"

if (-not (Test-Path $CredFile))
{
    [System.Windows.Forms.MessageBox]::Show(
        "Credential file not found:`n$CredFile`n`nCreate it with:`nGet-Credential | Export-Clixml vmcreds.xml",
        "Hyper-V Dashboard"
    )

    exit
}

try
{
    $Global:Credential = Import-Clixml $CredFile
}
catch
{
    [System.Windows.Forms.MessageBox]::Show(
        "Unable to load vmcreds.xml`n$($_.Exception.Message)",
        "Hyper-V Dashboard"
    )

    exit
}

################################################################################
# FUNCTIONS
################################################################################

function Get-PendingReboot {

    $RebootRequired = $false

    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    {
        $RebootRequired = $true
    }

    $SessionManager = Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -ErrorAction SilentlyContinue

    if($SessionManager.PendingFileRenameOperations)
    {
        $RebootRequired = $true
    }

    return $RebootRequired
}

function Get-AvailableUpdates {

    try {

        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()

        $Result = $Searcher.Search(
            "IsInstalled=0 and Type='Software'"
        )

        $Titles = @()
        $KBs = @()

        foreach($Update in $Result.Updates)
        {
            $Titles += $Update.Title

            if($Update.KBArticleIDs.Count -gt 0)
            {
                $KBs += ($Update.KBArticleIDs | ForEach-Object { "KB$_" })
            }
        }

        [PSCustomObject]@{
            Count  = $Result.Updates.Count
            KBs    = ($KBs -join ", ")
            Titles = ($Titles -join "; ")
        }

    }
    catch {

        [PSCustomObject]@{
            Count  = "Unknown"
            KBs    = ""
            Titles = "Unable to query updates"
        }
    }
}

function Get-HostData {

    try {

        $OS = Get-CimInstance Win32_OperatingSystem
        $WU = Get-AvailableUpdates

  [PSCustomObject]@{
    Name         = $env:COMPUTERNAME
    Type         = "Host"
    Updates      = $WU.Count
    KBs          = $WU.KBs
    UpdateTitles = $WU.Titles
    Reboot       = if(Get-PendingReboot){"Yes"}else{"No"}
    LastBoot     = $OS.LastBootUpTime
    Status       = "Online"
}

    }
    catch {

        [PSCustomObject]@{
            Name         = $env:COMPUTERNAME
            Type         = "Host"
            Updates      = "Error"
            UpdateTitles = ""
            Reboot       = "Unknown"
            LastBoot     = ""
            Status       = $_.Exception.Message
        }
    }
}

function Get-VMData {

    param($VM)

    try {

        $Result = Invoke-Command `
            -VMName $VM.Name `
            -Credential $Global:Credential `
            -ErrorAction Stop `
            -ScriptBlock {

            $Session = New-Object -ComObject Microsoft.Update.Session
            $Searcher = $Session.CreateUpdateSearcher()

            $Updates = $Searcher.Search(
                "IsInstalled=0 and Type='Software'"
            )

            $OS = Get-CimInstance Win32_OperatingSystem

            $Output = @()

            foreach($Update in $Updates.Updates)
            {
                $KB = ""

                if($Update.KBArticleIDs.Count -gt 0)
                {
                    $KB = "KB$($Update.KBArticleIDs[0])"
                }

                $UpdateReboot = $false

                try
                {
                    $UpdateReboot = (
                        $Update.InstallationBehavior.RebootBehavior -ne 0
                    )
                }
                catch
                {
                    $UpdateReboot = $false
                }

                $Output += [PSCustomObject]@{
                    KB          = $KB
                    UpdateTitle = $Update.Title
                    Reboot      = if($UpdateReboot){"Yes"}else{"No"}
                    LastBoot    = $OS.LastBootUpTime
                }
            }

            $Output
        }

        $Result | ForEach-Object {

            [PSCustomObject]@{
                Computer    = $VM.Name
                Type        = "VM"
                KB          = $_.KB
                UpdateTitle = $_.UpdateTitle
                Reboot      = $_.Reboot
                LastBoot    = $_.LastBoot
                Status      = "Online"
            }
        }
    }
    catch {

        [PSCustomObject]@{
            Computer    = $VM.Name
            Type        = "VM"
            KB          = "-"
            UpdateTitle = "Unavailable"
            Reboot      = "-"
            LastBoot    = "-"
            Status      = "Unavailable"
        }
    }
}

function Refresh-Grid {

    $table.Rows.Clear()

    $HostData = Get-HostData

  


[void]$table.Rows.Add(
    $HostData.Name,
    $HostData.Type,
    $HostData.Updates,
    $HostData.KBs,
    $HostData.UpdateTitles,
    $HostData.Reboot,
    $HostData.LastBoot,
    $HostData.Status
)


    Get-VM |
    Where-Object State -eq Running |
    Sort-Object Name |
    ForEach-Object {

        $Data = Get-VMData $_

      


$Updates = Get-VMData $_

foreach($Update in $Updates)
{
    [void]$table.Rows.Add(
        $Update.Computer,
        $Update.Type,
        $Update.KB,
        $Update.UpdateTitle,
        $Update.Reboot,
        $Update.LastBoot,
        $Update.Status
    )
}



    }

    foreach($row in $grid.Rows)
    {
        if($null -eq $row.Cells[5].Value)
        {
            continue
        }

        switch($row.Cells[5].Value)
        {
            "Yes" {
                $row.DefaultCellStyle.BackColor = "LightSalmon"
            }

            "No" {
                $row.DefaultCellStyle.BackColor = "LightGreen"
            }
        }
    }
}

function New-VMCheckpoint {

    param($VMName)

    try {

        Checkpoint-VM `
            -Name $VMName `
            -SnapshotName "PrePatch-$(Get-Date -Format yyyyMMdd-HHmm)"

    }
    catch {

        Write-Warning "Unable to create checkpoint for $VMName"

    }
}

function Install-UpdatesNow {

    foreach($row in $table.Rows)
    {
        if($row.Type -ne "VM")
        {
            continue
        }

        if($row.Reboot -eq "No")
        {
            Write-Host "Updating $($row.Name)"

            New-VMCheckpoint $row.Name

            try {

                Invoke-Command `
                    -VMName $row["Computer"]
                    -Credential $Global:Credential `
                    -ScriptBlock {

                    if(-not (Get-Module -ListAvailable PSWindowsUpdate))
                    {
                        Set-PSRepository PSGallery `
                            -InstallationPolicy Trusted `
                            -ErrorAction SilentlyContinue

                        Install-PackageProvider `
                            -Name NuGet `
                            -Force `
                            -ErrorAction SilentlyContinue

                        Install-Module `
                            PSWindowsUpdate `
                            -Force `
                            -Confirm:$false
                    }

                    Import-Module PSWindowsUpdate

                    Install-WindowsUpdate `
                        -MicrosoftUpdate `
                        -AcceptAll `
                        -IgnoreReboot

                }

            }
            catch
            {
                Write-Warning "Failed updating $($row.Name)"
            }
        }
    }

    [System.Windows.Forms.MessageBox]::Show(
        "Update installation started for eligible VMs."
    )
}
function Schedule-Updates {

    $RunTime = $dtSchedule.Value

    if($RunTime -lt (Get-Date))
    {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a date and time in the future.",
            "Invalid Schedule"
        )
        return
    }

    if($grid.SelectedRows.Count -eq 0)
    {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select one or more VMs first.",
            "No VMs Selected"
        )
        return
    }

    $ScheduledCount = 0

    foreach($SelectedRow in $grid.SelectedRows)
    {
        $VMName = $SelectedRow.Cells["Computer"].Value
        $VMType = $SelectedRow.Cells["Type"].Value
        $Updates = $SelectedRow.Cells["Updates"].Value

        if($VMType -ne "VM")
        {
            continue
        }

        if([int]$Updates -le 0)
        {
            continue
        }

        try {

            Invoke-Command `
                -VMName $VMName `
                -Credential $Global:Credential `
                -ArgumentList $RunTime `
                -ScriptBlock {

                param($ScheduleTime)

                $Script = @'
if(-not (Get-Module -ListAvailable PSWindowsUpdate))
{
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-PackageProvider NuGet -Force
    Install-Module PSWindowsUpdate -Force
}

Import-Module PSWindowsUpdate

Install-WindowsUpdate `
    -MicrosoftUpdate `
    -AcceptAll `
    -AutoReboot
'@

                $File = "C:\Windows\Temp\InstallUpdates.ps1"

                Set-Content `
                    -Path $File `
                    -Value $Script `
                    -Force

                Unregister-ScheduledTask `
                    -TaskName "HyperVScheduledUpdates" `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue

                $Action = New-ScheduledTaskAction `
                    -Execute "powershell.exe" `
                    -Argument "-ExecutionPolicy Bypass -File $File"

                $Trigger = New-ScheduledTaskTrigger `
                    -Once `
                    -At $ScheduleTime

                Register-ScheduledTask `
                    -TaskName "HyperVScheduledUpdates" `
                    -Action $Action `
                    -Trigger $Trigger `
                    -Force

            }

            $ScheduledCount++
        }
        catch
        {
            Write-Warning "Failed scheduling updates on $VMName"
            Write-Warning $_.Exception.Message
        }
    }

    [System.Windows.Forms.MessageBox]::Show(
        "$ScheduledCount VM(s) scheduled for updates at $($RunTime.ToString('dd/MM/yyyy HH:mm'))",
        "Updates Scheduled"
    )
}

################################################################################
# GUI
################################################################################

$form = New-Object System.Windows.Forms.Form
$form.Text = "Hyper-V Update Dashboard"
$form.Width = 1200
$form.Height = 700
$form.StartPosition = "CenterScreen"

$table = New-Object System.Data.DataTable




@(
    "Computer",
    "Type",
    "KB",
    "UpdateTitle",
    "Reboot",
    "LastBoot",
    "Status"
)| ForEach-Object {

    [void]$table.Columns.Add($_)
}


$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = "Top"
$grid.Height = 550
$grid.AutoSizeColumnsMode = "Fill"
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.DataSource = $table

$grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$grid.MultiSelect = $true
$grid.RowHeadersVisible = $false


$form.Controls.Add($grid)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh"
$btnRefresh.Width = 120
$btnRefresh.Top = 570
$btnRefresh.Left = 20
$form.Controls.Add($btnRefresh)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text = "Install Updates"
$btnInstall.Width = 160
$btnInstall.Top = 570
$btnInstall.Left = 160
$form.Controls.Add($btnInstall)


$dtSchedule = New-Object System.Windows.Forms.DateTimePicker
$dtSchedule.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
$dtSchedule.CustomFormat = "dd/MM/yyyy HH:mm"
$dtSchedule.Width = 180
$dtSchedule.Top = 570
$dtSchedule.Left = 340
$dtSchedule.Value = (Get-Date).AddHours(2)

$form.Controls.Add($dtSchedule)


$btnSchedule = New-Object System.Windows.Forms.Button
$btnSchedule.Text = "Schedule Updates"
$btnSchedule.Width = 160
$btnSchedule.Top = 570
$btnSchedule.Left = 540
$form.Controls.Add($btnSchedule)

$btnRefresh.Add_Click({ Refresh-Grid })
$btnInstall.Add_Click({ Install-UpdatesNow })
$btnSchedule.Add_Click({ Schedule-Updates })

Refresh-Grid

[void]$form.ShowDialog()