# ============================================================
# Export-DashboardJson.ps1
#
# Called by Monitor-Master (ONE line, after Dashboard.html is written):
#
#   try { . (Join-Path $PSScriptRoot 'Export-DashboardJson.ps1') } catch { Write-Host "Dashboard JSON export failed: $($_.Exception.Message)" -ForegroundColor Yellow }
#
# It reads the data Monitor-Master has ALREADY collected
#   $AllDevices  $M365Data  $DefData  $IntuneData  $SwitchData
# and writes one JSON file in the web dashboard's format into an outbox
# folder. Push-Dashboard.ps1 sends it to the web dashboard.
#
# It makes NO network calls, changes none of Monitor-Master's variables,
# and any error here is caught, so Dashboard.html and the email carry on
# exactly as before.
#
# Works on Windows PowerShell 5.1 and PowerShell 7.
# ============================================================

& {
    $ErrorActionPreference = 'Stop'

    # ================== CONFIG ==================
    $DashSiteName      = "YMCA"                          # short label used for the cloud items (e.g. "YMCA Microsoft 365")
    $DashOutbox        = "C:\Monitor\DashboardOutbox"    # Push-Dashboard.ps1 reads from here
    $DashPcNameRegex   = ""                              # device names matching this are shown as PCs (e.g. '-PC-|^LAPTOP'); empty = all servers

    # How often each kind of data is refreshed, in minutes. The web dashboard
    # marks something offline when nothing new arrives for this long + 15 min.
    #   Agents: longest gap between agent runs (5am/10am/1pm -> 1pm to 5am = 16 h).
    #           Change to 15 or 60 once the agents run more often.
    #   Master: longest gap between Monitor-Master runs (applies to M365,
    #           Defender, Intune and switches).
    $DashAgentIntervalMinutes  = 16 * 60
    $DashMasterIntervalMinutes = 16 * 60

    # Thresholds for server status (the agent's own disk WARNING/CRITICAL is always used)
    $DashCpuWarnPct    = 90
    $DashRamWarnPct    = 95
    $DashBackupWarnDays = 2       # only checked on devices that have reported a backup at least once
    # ============================================

    $now = Get-Date

    function Get-DashTime($value) {
        # Agent timestamps are local time without an offset - attach this server's offset.
        if (-not $value) { return $null }
        try {
            $dt = [datetime]::ParseExact([string]$value, 'yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
            return ([DateTimeOffset]$dt).ToString('o')
        } catch { return $null }
    }

    function ConvertFrom-DashJson($text) {
        if (-not $text) { return $null }
        try { return (ConvertFrom-Json ([string]$text)) } catch { return $null }
    }

    function Test-Positive($v) { return (($v -is [int] -or $v -is [long] -or $v -is [double]) -and $v -gt 0) }

    # Row count for one section of $M365Data / $DefData / $IntuneData:
    #   $null  = not licensed (leave it off the dashboard)
    #   "n/a"  = the section errored
    #   number = matching rows
    function Get-SectionCount($data, [string]$name, [scriptblock]$where) {
        if (-not $data -or -not $data.Sections) { return $null }
        $s = $data.Sections[$name]
        if (-not $s -or $s.Unlicensed) { return $null }
        if ($s.Error) { return "n/a" }
        $rows = @($s.Rows)
        if ($where) { $rows = @($rows | Where-Object $where) }
        return [int]$rows.Count
    }

    function Get-SectionRows($data, [string]$name) {
        if (-not $data -or -not $data.Sections) { return @() }
        $s = $data.Sections[$name]
        if (-not $s -or $s.Unlicensed -or $s.Error) { return @() }
        return @($s.Rows)
    }

    function Set-Metric($metrics, [string]$key, $value) { if ($null -ne $value) { $metrics[$key] = $value } }

    # Not set up at all (no tenant ID / credentials) -> don't send an item for it
    function Test-NotConfigured($data) {
        return ($data -and $data.Error -and @($data.Sections.Keys).Count -eq 0 -and
                $data.Error -match 'not set|not found|CONFIG section')
    }

    function New-DashItem([string]$type, [string]$hostName, [string]$collected, [string]$status, [int]$interval, $metrics) {
        return [ordered]@{
            type             = $type
            host             = $hostName
            collected        = $collected
            status           = $status
            interval_minutes = $interval
            metrics          = $metrics
        }
    }

    $items   = New-Object System.Collections.Generic.List[object]
    $nowIso  = ([DateTimeOffset]$now).ToString('o')

    # ---------------- Servers / PCs (Monitor-Agent) ----------------
    if ($AllDevices) {
        foreach ($name in @($AllDevices.Keys)) {
            try {
                $latest = @($AllDevices[$name])[0]
                if (-not $latest) { continue }
                $d = $latest.Data
                $collected = Get-DashTime $d.Timestamp
                if (-not $collected) { continue }

                $m      = [ordered]@{}
                $issues = New-Object System.Collections.Generic.List[string]
                $level  = 0     # 0 ok, 1 warning, 2 critical

                $cpu = $null; try { $cpu = [math]::Round([double]$d.CPU_Load, 1) } catch { }
                $ramPct = $null
                try {
                    if ([double]$d.Total_MemoryGB -gt 0) {
                        $ramPct = [math]::Round(100 * [double]$d.Memory_UsedGB / [double]$d.Total_MemoryGB, 1)
                    }
                } catch { }
                Set-Metric $m "CPU_Pct" $cpu
                Set-Metric $m "RAM_UsedPct" $ramPct
                Set-Metric $m "RAM_TotalGB" $(if ($d.Total_MemoryGB) { [double]$d.Total_MemoryGB } else { $null })
                if ($null -ne $cpu -and $cpu -ge $DashCpuWarnPct) { $issues.Add("CPU at $cpu%"); $level = [math]::Max($level, 1) }
                if ($null -ne $ramPct -and $ramPct -ge $DashRamWarnPct) { $issues.Add("Memory at $ramPct%"); $level = [math]::Max($level, 1) }

                foreach ($disk in @(ConvertFrom-DashJson $d.Disk_Free)) {
                    if (-not $disk -or -not $disk.DeviceID) { continue }
                    $letter = ([string]$disk.DeviceID).TrimEnd(':')
                    $m["Disk_${letter}_FreePct"] = $disk.FreePercent
                    $m["Disk_${letter}_FreeGB"]  = $disk.FreeGB
                    if ($disk.Status -eq "CRITICAL") { $issues.Add("Disk ${letter}: $($disk.FreePercent)% free"); $level = 2 }
                    elseif ($disk.Status -eq "WARNING") { $issues.Add("Disk ${letter}: $($disk.FreePercent)% free"); $level = [math]::Max($level, 1) }
                }

                $backup = ConvertFrom-DashJson $d.Backup_Status
                if ($backup -and $backup.LastSuccessful) {
                    # PowerShell 7 turns the date into a [datetime]; 5.1 leaves it as text
                    $lb = $backup.LastSuccessful
                    if ($lb -isnot [datetime]) {
                        try { $lb = [datetime]::ParseExact([string]$lb, 'yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch { $lb = $null }
                    }
                    if ($lb) {
                        $m["LastBackup"] = $lb.ToString("yyyy-MM-dd HH:mm")
                        $age = ($now - $lb).TotalDays
                        if ($age -gt $DashBackupWarnDays) { $issues.Add("Last backup $([math]::Floor($age)) days ago"); $level = [math]::Max($level, 1) }
                    }
                }

                $updates = @(ConvertFrom-DashJson $d.Host_Update_Details)
                if ($updates.Count -gt 0 -and $updates[0]) {
                    $first = $updates[0]
                    if ($first.Title -eq "Error") { $m["PendingUpdates"] = "check failed" }
                    elseif ($first.Title -eq "Up to date") { $m["PendingUpdates"] = 0 }
                    else { $m["PendingUpdates"] = $updates.Count }
                    $reboot = [string]$first.Reboot
                    $m["RebootPending"] = $reboot
                    if ($reboot -eq "YES") { $issues.Add("Reboot pending"); $level = [math]::Max($level, 1) }
                }

                $m["Issues"] = ($issues -join " | ")
                $type   = if ($DashPcNameRegex -and $name -match $DashPcNameRegex) { "pc" } else { "server" }
                $status = @("ok", "warning", "critical")[$level]
                $items.Add((New-DashItem $type $name $collected $status $DashAgentIntervalMinutes $m))
            }
            catch {
                Write-Host "  Dashboard export: skipped device $name - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    # ---------------- Microsoft 365 ----------------
    if ($M365Data -and -not (Test-NotConfigured $M365Data)) {
        $m = [ordered]@{}
        if ($M365Data.Error) { $m["Error"] = [string]$M365Data.Error }
        Set-Metric $m "DegradedServices" (Get-SectionCount $M365Data "Health"  { $_.Status -ne "serviceOperational" })
        Set-Metric $m "OpenIncidents"    (Get-SectionCount $M365Data "Issues"  { $_.Type -eq "incident" })
        Set-Metric $m "Advisories"       (Get-SectionCount $M365Data "Issues"  { $_.Type -ne "incident" })
        Set-Metric $m "SecurityAlerts"   (Get-SectionCount $M365Data "Alerts"  $null)
        Set-Metric $m "HighAlerts"       (Get-SectionCount $M365Data "Alerts"  { $_.Severity -eq "high" })
        Set-Metric $m "RiskyUsers"       (Get-SectionCount $M365Data "Risky"   $null)
        Set-Metric $m "FailedSignIns"    $M365Data.FailedTotal
        Set-Metric $m "FailedFromOutside" $M365Data.FailedExternal
        Set-Metric $m "MessageCenter"    (Get-SectionCount $M365Data "Messages" $null)
        $score = @(Get-SectionRows $M365Data "Score") | Select-Object -First 1
        if ($score) { $m["SecureScore_Pct"] = $score.Percent }

        $issues = @()
        if (Test-Positive $m["HighAlerts"])       { $issues += "$($m['HighAlerts']) high-severity alert(s)" }
        if (Test-Positive $m["RiskyUsers"])       { $issues += "$($m['RiskyUsers']) risky user(s)" }
        if (Test-Positive $m["FailedFromOutside"]) { $issues += "$($m['FailedFromOutside']) user(s) failing sign-in from outside" }
        $warn = @()
        if (Test-Positive $m["OpenIncidents"])    { $warn += "$($m['OpenIncidents']) Microsoft incident(s)" }
        if (Test-Positive $m["DegradedServices"]) { $warn += "$($m['DegradedServices']) service(s) degraded" }
        if ((Test-Positive $m["SecurityAlerts"]) -and -not (Test-Positive $m["HighAlerts"])) { $warn += "$($m['SecurityAlerts']) security alert(s)" }
        $status = if ($M365Data.Error -or $issues) { "critical" } elseif ($warn) { "warning" } else { "ok" }
        $m["Issues"] = (@($M365Data.Error | Where-Object { $_ }) + $issues + $warn) -join " | "
        $items.Add((New-DashItem "m365" "$DashSiteName Microsoft 365" $nowIso $status $DashMasterIntervalMinutes $m))
    }

    # ---------------- Defender ----------------
    if ($DefData -and -not (Test-NotConfigured $DefData)) {
        $m = [ordered]@{}
        if ($DefData.Error) { $m["Error"] = [string]$DefData.Error }
        Set-Metric $m "Incidents"        (Get-SectionCount $DefData "Incidents" $null)
        Set-Metric $m "HighIncidents"    (Get-SectionCount $DefData "Incidents" { $_.Severity -eq "high" })
        Set-Metric $m "Alerts"           (Get-SectionCount $DefData "Alerts"    $null)
        Set-Metric $m "HighAlerts"       (Get-SectionCount $DefData "Alerts"    { $_.Severity -eq "high" })
        Set-Metric $m "Machines"         (Get-SectionCount $DefData "Machines"  $null)
        Set-Metric $m "HighRiskMachines" (Get-SectionCount $DefData "Machines"  { $_.Risk -eq "High" })
        Set-Metric $m "UnhealthySensors" (Get-SectionCount $DefData "Machines"  { $_.Health -and $_.Health -ne "Active" })
        Set-Metric $m "NotOnboarded"     $(if ($null -ne $DefData.NotInMde) { @($DefData.NotInMde).Count } else { $null })
        Set-Metric $m "Recommendations"  (Get-SectionCount $DefData "Recs"      $null)

        $issues = @(); $warn = @()
        if (Test-Positive $m["HighIncidents"])    { $issues += "$($m['HighIncidents']) high-severity incident(s)" }
        if (Test-Positive $m["HighAlerts"])       { $issues += "$($m['HighAlerts']) high-severity alert(s)" }
        if (Test-Positive $m["HighRiskMachines"]) { $issues += "$($m['HighRiskMachines']) high-risk device(s)" }
        if ((Test-Positive $m["Incidents"]) -and -not (Test-Positive $m["HighIncidents"])) { $warn += "$($m['Incidents']) open incident(s)" }
        if (Test-Positive $m["UnhealthySensors"]) { $warn += "$($m['UnhealthySensors']) device(s) with sensor problems" }
        if (Test-Positive $m["NotOnboarded"])     { $warn += "$($m['NotOnboarded']) monitored device(s) not in Defender" }
        $status = if ($DefData.Error -or $issues) { "critical" } elseif ($warn) { "warning" } else { "ok" }
        $m["Issues"] = (@($DefData.Error | Where-Object { $_ }) + $issues + $warn) -join " | "
        $items.Add((New-DashItem "defender" "$DashSiteName Defender" $nowIso $status $DashMasterIntervalMinutes $m))
    }

    # ---------------- Intune ----------------
    if ($IntuneData -and -not (Test-NotConfigured $IntuneData)) {
        $m = [ordered]@{}
        $stale = if ($IntuneData.StaleDays) { [double]$IntuneData.StaleDays } else { 7 }
        $certDays = if ($IntuneData.CertWarnDays) { [double]$IntuneData.CertWarnDays } else { 30 }
        if ($IntuneData.Error) { $m["Error"] = [string]$IntuneData.Error }
        Set-Metric $m "Devices"        (Get-SectionCount $IntuneData "Devices" $null)
        Set-Metric $m "NonCompliant"   (Get-SectionCount $IntuneData "Devices" { $_.Compliance -in @("noncompliant", "error", "conflict") })
        Set-Metric $m "NotCheckedIn"   (Get-SectionCount $IntuneData "Devices" { $null -ne $_.DaysSince -and [double]$_.DaysSince -gt $stale })
        Set-Metric $m "LowDisk"        (Get-SectionCount $IntuneData "Devices" { [string]$_.Issues -match 'Low disk' })
        Set-Metric $m "NotEncrypted"   (Get-SectionCount $IntuneData "Devices" { [string]$_.Issues -match 'Not encrypted' })
        Set-Metric $m "UnsupportedOS"  (Get-SectionCount $IntuneData "Devices" { [string]$_.Issues -match 'out of support' })
        Set-Metric $m "CertsExpiring"  (Get-SectionCount $IntuneData "Certs"   { $null -ne $_.DaysLeft -and "$($_.DaysLeft)" -ne "" -and [double]$_.DaysLeft -le $certDays })
        Set-Metric $m "AppFailures"    (Get-SectionCount $IntuneData "AppFail" $null)
        Set-Metric $m "PolicyFailures" (Get-SectionCount $IntuneData "Policies" $null)
        Set-Metric $m "NotInIntune"    $(if ($null -ne $IntuneData.NotInIntune) { @($IntuneData.NotInIntune).Count } else { $null })

        $expired = Get-SectionCount $IntuneData "Certs" { $null -ne $_.DaysLeft -and "$($_.DaysLeft)" -ne "" -and [double]$_.DaysLeft -le 7 }
        $issues = @(); $warn = @()
        if (Test-Positive $expired)             { $issues += "$expired Apple certificate/token(s) expiring within 7 days" }
        if ((Test-Positive $m["CertsExpiring"]) -and -not (Test-Positive $expired)) { $warn += "$($m['CertsExpiring']) Apple certificate/token(s) expiring soon" }
        if (Test-Positive $m["NonCompliant"])   { $warn += "$($m['NonCompliant']) non-compliant device(s)" }
        if (Test-Positive $m["NotEncrypted"])   { $warn += "$($m['NotEncrypted']) not encrypted" }
        if (Test-Positive $m["UnsupportedOS"])  { $warn += "$($m['UnsupportedOS']) on unsupported Windows" }
        if (Test-Positive $m["NotCheckedIn"])   { $warn += "$($m['NotCheckedIn']) not checked in for $stale+ days" }
        $status = if ($IntuneData.Error -or $issues) { "critical" } elseif ($warn) { "warning" } else { "ok" }
        $m["Issues"] = (@($IntuneData.Error | Where-Object { $_ }) + $issues + $warn) -join " | "
        $items.Add((New-DashItem "intune" "$DashSiteName Intune" $nowIso $status $DashMasterIntervalMinutes $m))
    }

    # ---------------- Network switches ----------------
    if ($SwitchData) {
        foreach ($s in @($SwitchData.Switches)) {
            if (-not $s) { continue }
            $hostName = if ($s.Name) { [string]$s.Name } else { [string]$s.IP }
            $m = [ordered]@{}
            $m["Issues"]    = [string]$s.Issues
            $m["IP"]        = [string]$s.IP
            $descr = [string]$s.Descr
            if ($descr.Length -gt 60) { $descr = $descr.Substring(0, 57) + "..." }
            Set-Metric $m "Model"     $(if ($descr) { $descr } else { $null })
            Set-Metric $m "Ping_ms"   $s.LatencyMs
            Set-Metric $m "Loss_Pct"  $s.LossPct
            Set-Metric $m "Uptime"    $(if ($s.Uptime) { [string]$s.Uptime } else { $null })
            if ($s.Snmp) {
                $m["PortsUp"]     = "$($s.PortsUp) / $($s.PortsTotal)"
                $m["ErrorPorts"]  = $s.ErrPorts
                $m["ChangedPorts"] = $s.ChangedPorts
            } else {
                $m["SNMP"] = "not answering"
            }
            if (@($s.Mgmt).Count) { $m["Management"] = (@($s.Mgmt) -join ", ") }
            if ($s.DownSince) { $m["DownSince"] = [string]$s.DownSince }
            $m["Source"] = [string]$s.Source

            $status = if (-not $s.Up) { "down" } elseif ($s.Issues) { "warning" } else { "ok" }
            $items.Add((New-DashItem "switch" $hostName $nowIso $status $DashMasterIntervalMinutes $m))
        }
    }

    if ($items.Count -eq 0) {
        Write-Host "  Dashboard export: nothing to export" -ForegroundColor Yellow
        return
    }

    # ---------------- Write to the outbox ----------------
    if (!(Test-Path $DashOutbox)) { New-Item -Path $DashOutbox -ItemType Directory -Force | Out-Null }
    $payload = [ordered]@{ generated = $nowIso; source = "monitor-master@$env:COMPUTERNAME"; items = $items.ToArray() }
    $json    = ConvertTo-Json -InputObject $payload -Depth 8 -Compress

    # Write to a temp name then rename, so Push-Dashboard never picks up a half-written file
    $name = "master_{0}.json" -f $now.ToString("yyyyMMdd_HHmmss")
    $tmp  = Join-Path $DashOutbox ($name + ".tmp")
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination (Join-Path $DashOutbox $name) -Force

    Write-Host "✅ Web dashboard export: $($items.Count) item(s) -> $DashOutbox\$name" -ForegroundColor Cyan
}
