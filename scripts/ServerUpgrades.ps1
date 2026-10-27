Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
 
# --- CONFIGURATION & INITIAL SCAN ---
$CredPath = "C:\Monitor\vm_creds.xml"

# Logic for Automation:
if (Test-Path $CredPath) {
    # If the file exists, import it silently (No popup)
    $VMCred = Import-CliXml -Path $CredPath
} else {
    # If the file is missing, ask the user ONCE and save it
    Write-Host "Credential file not found. Creating baseline..." -ForegroundColor Yellow
    $VMCred = Get-Credential
    $VMCred | Export-CliXml -Path $CredPath
    Write-Host "Credentials saved to $CredPath. Only this user/machine can decrypt it." -ForegroundColor Green
}

$UpdateStageFile = "C:\Windows\Temp\UpdateStage_$($VM.Name).txt"

 
Write-Host "Scanning Hyper-V VMs for outstanding updates..." -ForegroundColor Cyan
$RunningVMs = Get-VM | Where-Object { $_.State -eq 'Running' }
$UpdateInventory = @()
 
foreach ($VM in $RunningVMs) {
    try {
        Invoke-Command -VMName $VM.Name -Credential $VMCred -ScriptBlock {
            param($StageFile)
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
                Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck -Confirm:$false
            }
            # Scan only (Do not download yet)
            Invoke-WUJob -ComputerName localhost -RunNow -Script {
                Import-Module PSWindowsUpdate
                $Updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction SilentlyContinue
                $RebootRequired = Get-WURebootStatus -Silent
                
                $DownloadList = @()
                foreach ($U in $Updates) {
                    $DownloadList += [PSCustomObject]@{ KB = $U.KB; Title = $U.Title; NeedsReboot = $U.RebootRequired }
                }
                if ($DownloadList.Count -eq 0 -and $RebootRequired) {
                    $DownloadList += [PSCustomObject]@{ KB = "PENDING REBOOT"; Title = "No new updates, but VM needs a restart"; NeedsReboot = $true }
                }
                $DownloadList | ConvertTo-Json | Out-File $StageFile -Force
            } -Confirm:$false
        } -ArgumentList $UpdateStageFile -ErrorAction Stop
 
        $ResultJson = $null
for ($i=0; $i -lt 10 -and -not $ResultJson; $i++) {
    Start-Sleep -Seconds 3
    $ResultJson = Invoke-Command -VMName $VM.Name -Credential $VMCred -ScriptBlock {
        param($StageFile)
        if (Test-Path $StageFile) { Get-Content $StageFile -Raw }
    } -ArgumentList $UpdateStageFile
}

        $ResultJson = Invoke-Command -VMName $VM.Name -Credential $VMCred -ScriptBlock {
            param($StageFile)
            if (Test-Path $StageFile) { Get-Content $StageFile -Raw }
        } -ArgumentList $UpdateStageFile
 
        if ($ResultJson) {
            $CleanJson = $ResultJson.Trim('"') -replace '\\',''
            $Results = @($CleanJson | ConvertFrom-Json)

            foreach ($R in $Results) {
                $UpdateInventory += [PSCustomObject]@{ VMName = $VM.Name; KB = $R.KB; NeedsReboot = $R.NeedsReboot; Title = $R.Title }
            }
        }
    } catch {
        Write-Warning "Failed to scan $($VM.Name)"
    }
}
 
# --- GUI CONSTRUCTION ---
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Hyper-V VM Update Control Center"
$Form.Size = New-Object System.Drawing.Size(850, 500)
$Form.StartPosition = "CenterScreen"
 
# Data Grid to show updates
$DataGridView = New-Object System.Windows.Forms.DataGridView
$DataGridView.Size = New-Object System.Drawing.Size(810, 300)
$DataGridView.Location = New-Object System.Drawing.Point(15, 15)
$DataGridView.AutoSizeColumnsMode = "AllCellsExceptHeader"
$DataGridView.SelectionMode = "FullRowSelect"
$DataGridView.MultiSelect = $false
 
# Convert Inventory to DataTable for GridView representation
$DataTable = New-Object System.Data.DataTable
$DataTable.Columns.Add("VMName")
$DataTable.Columns.Add("KB")
$DataTable.Columns.Add("NeedsReboot")
$DataTable.Columns.Add("Title")
foreach ($Item in $UpdateInventory) {
    [void]$DataTable.Rows.Add($Item.VMName, $Item.KB, $Item.NeedsReboot, $Item.Title)
}
$DataGridView.DataSource = $DataTable
# Fix column visibility and sizing
$DataGridView.AutoSizeColumnsMode = 'DisplayedCells'
$DataGridView.AutoResizeColumns()
$DataGridView.ColumnHeadersHeightSizeMode = 'AutoSize'
$DataGridView.ScrollBars = 'Both'
$DataGridView.Anchor = 'Top, Left, Right'

$Form.Controls.Add($DataGridView)
 
# --- BUTTON 1: DOWNLOAD ONLY ---
$BtnDownload = New-Object System.Windows.Forms.Button
$BtnDownload.Text = "1. Download Target Update"
$BtnDownload.Location = New-Object System.Drawing.Point(15, 340)
$BtnDownload.Size = New-Object System.Drawing.Size(180, 40)
$BtnDownload.Add_Click({
    $SelectedRow = $DataGridView.SelectedRows[0]
    if ($SelectedRow) {
        $VM = $SelectedRow.Cells["VMName"].Value
        $KB = $SelectedRow.Cells["KB"].Value
        [System.Windows.Forms.MessageBox]::Show("Downloading $KB inside $VM. Please wait...", "Status")
        
        Invoke-Command -VMName $VM -Credential $VMCred -ScriptBlock {
            param($KBNum)
            Invoke-WUJob -ComputerName localhost -RunNow -Script {
                param($K) Import-Module PSWindowsUpdate; Get-WindowsUpdate -KBArticleID $K -Download -AcceptAll
            } -ArgumentList $KBNum -Confirm:$false
        } -ArgumentList $KB
        [System.Windows.Forms.MessageBox]::Show("Download Complete for $KB!", "Success")
    }
})
$Form.Controls.Add($BtnDownload)
 
# --- BUTTON 2: INSTALL NOW ---
$BtnInstallNow = New-Object System.Windows.Forms.Button
$BtnInstallNow.Text = "2a. Install Now (No Reboot)"
$BtnInstallNow.Location = New-Object System.Drawing.Point(210, 340)
$BtnInstallNow.Size = New-Object System.Drawing.Size(180, 40)
$BtnInstallNow.BackColor = [System.Drawing.Color]::LightGreen
$BtnInstallNow.Add_Click({
    $SelectedRow = $DataGridView.SelectedRows[0]
    if ($SelectedRow) {
        $VM = $SelectedRow.Cells["VMName"].Value
        $KB = $SelectedRow.Cells["KB"].Value
        
        Invoke-Command -VMName $VM -Credential $VMCred -ScriptBlock {
            param($KBNum)
            Invoke-WUJob -ComputerName localhost -RunNow -Script {
                param($K) Import-Module PSWindowsUpdate; Get-WindowsUpdate -KBArticleID $K -Install -AcceptAll 
            } -ArgumentList $KBNum -Confirm:$false
        } -ArgumentList $KB
        [System.Windows.Forms.MessageBox]::Show("Installation deployment triggered immediately for $KB on $VM.", "Executed")
    }
})
$Form.Controls.Add($BtnInstallNow)
 
# --- BUTTON 3: SCHEDULE TIME ---
$BtnSchedule = New-Object System.Windows.Forms.Button
$BtnSchedule.Text = "2b. Schedule Execution Time"
$BtnSchedule.Location = New-Object System.Drawing.Point(405, 340)
$BtnSchedule.Size = New-Object System.Drawing.Size(180, 40)
$BtnSchedule.BackColor = [System.Drawing.Color]::LightYellow
$BtnSchedule.Add_Click({
    $SelectedRow = $DataGridView.SelectedRows[0]
    if ($SelectedRow) {
        $VM = $SelectedRow.Cells["VMName"].Value
        $KB = $SelectedRow.Cells["KB"].Value
        
        # Open an inner input prompt for the time mapping
        $TimeForm = New-Object System.Windows.Forms.Form
        $TimeForm.Text = "Set Schedule Time"
        $TimeForm.Size = New-Object System.Drawing.Size(300, 150)
        $TimeForm.StartPosition = "CenterParent"
        
        $Label = New-Object System.Windows.Forms.Label
        $Label.Text = "Enter Time (24hr HH:mm e.g. 23:00):"
        $Label.Location = New-Object System.Drawing.Point(15, 15)
        $Label.Size = New-Object System.Drawing.Size(250, 20)
        $TimeForm.Controls.Add($Label)
        
        $TextBox = New-Object System.Windows.Forms.TextBox
        $TextBox.Location = New-Object System.Drawing.Point(15, 40)
        $TextBox.Size = New-Object System.Drawing.Size(150, 20)
        $TimeForm.Controls.Add($TextBox)
        
        $BtnSubmit = New-Object System.Windows.Forms.Button
        $BtnSubmit.Text = "OK"
        $BtnSubmit.Location = New-Object System.Drawing.Point(180, 38)
        $BtnSubmit.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $TimeForm.Controls.Add($BtnSubmit)
        
        if ($TimeForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            if ([DateTime]::TryParse($TextBox.Text, [ref](Get-Date))) {
                $ScheduleDateTime = Get-Date $TextBox.Text
                if ($ScheduleDateTime -lt (Get-Date)) { $ScheduleDateTime = $ScheduleDateTime.AddDays(1) }
                
                Invoke-Command -VMName $VM -Credential $VMCred -ScriptBlock {
                    param($KBNum, $RunTime)
                    Import-Module PSWindowsUpdate
                    Invoke-WUJob -ComputerName localhost -Script {
                        param($K) Import-Module PSWindowsUpdate; Get-WindowsUpdate -KBArticleID $K -Install -AcceptAll
                    } -ArgumentList $KBNum -RunAt $RunTime -Confirm:$false
                } -ArgumentList $KB, $ScheduleDateTime
                
                [System.Windows.Forms.MessageBox]::Show("Successfully scheduled $KB on $VM for $($ScheduleDateTime.ToString('f'))", "Scheduled")
            } else {
                [System.Windows.Forms.MessageBox]::Show("Invalid time format entered.", "Error")
            }
        }
    }
})
$Form.Controls.Add($BtnSchedule)
 
# Display the main dashboard
$Form.ShowDialog()