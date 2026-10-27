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

    function New-DashItem([string]$type, [string]$hostName, [string]$collected, [string]$status, [int]$interval, $metrics, $details = $null) {
        $item = [ordered]@{
            type             = $type
            host             = $hostName
            collected        = $collected
            status           = $status
            interval_minutes = $interval
            metrics          = $metrics
        }
        if ($details) { $item["details"] = @($details) }
        return $item
    }

    # ---- Detail lists (the tables under each tab, same as Dashboard.html) ----
    $DashMaxRows = 2000

    function ConvertTo-DashValue($v) {
        if ($null -eq $v) { return "" }
        if ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { return $v }
        if ($v -is [datetime]) { return $v.ToString("yyyy-MM-dd HH:mm") }
        if ($v -is [string]) { return $v }
        if ($v -is [System.Collections.IEnumerable]) {
            return ((@($v) | ForEach-Object {
                if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { ConvertTo-Json -InputObject $_ -Compress -Depth 3 }
            }) -join "; ")
        }
        if ($v -is [psobject] -and $v.PSObject.Properties.Count) { return (ConvertTo-Json -InputObject $v -Compress -Depth 3) }
        return [string]$v
    }

    function ConvertTo-DashRow($obj) {
        $row = [ordered]@{}
        if ($obj -is [System.Collections.IDictionary]) {
            foreach ($k in $obj.Keys) { if ($k -ne "Id") { $row[[string]$k] = ConvertTo-DashValue $obj[$k] } }
        } else {
            foreach ($p in $obj.PSObject.Properties) { if ($p.Name -ne "Id") { $row[$p.Name] = ConvertTo-DashValue $p.Value } }
        }
        return $row
    }

    # One detail section from $M365Data / $DefData / $IntuneData.
    #   $where     - optional filter (e.g. only devices with issues)
    #   $addIssues - optional scriptblock param($r) returning an issues string for the row
    function New-DashSection($data, [string]$name, [string]$title, [scriptblock]$where = $null, [scriptblock]$addIssues = $null) {
        if (-not $data -or -not $data.Sections) { return $null }
        $s = $data.Sections[$name]
        if (-not $s -or $s.Unlicensed) { return $null }
        if ($s.Error) { return [ordered]@{ title = $title; error = [string]$s.Error; rows = @() } }
        $src = @($s.Rows | Where-Object { $null -ne $_ })
        if ($where) { $src = @($src | Where-Object $where) }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($r in ($src | Select-Object -First $DashMaxRows)) {
            $row = ConvertTo-DashRow $r
            if ($addIssues) {
                $iss = [string](& $addIssues $r)
                $new = [ordered]@{ Issues = $iss }
                foreach ($k in $row.Keys) { if ($k -ne "Issues") { $new[$k] = $row[$k] } }
                $row = $new
            }
            $rows.Add($row)
        }
        $sec = [ordered]@{ title = $title; rows = $rows.ToArray() }
        if ($src.Count -gt $DashMaxRows) { $sec["note"] = "Showing the first $DashMaxRows of $($src.Count)." }
        return $sec
    }

    function New-DashNameList([string]$title, $names) {
        if ($null -eq $names) { return $null }
        return [ordered]@{ title = $title; rows = @(@($names) | Where-Object { $_ } | ForEach-Object { [ordered]@{ Device = [string]$_; Issues = "Not enrolled" } }) }
    }

    function Join-DashSections { return @($args | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }

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
        $hrs = if ($M365Data.SignInHours) { $M365Data.SignInHours } else { 24 }
        $days = if ($M365Data.MessageDays) { $M365Data.MessageDays } else { 7 }
        $det = Join-DashSections `
            (New-DashSection $M365Data "Health"    "Service Health" $null { param($r) if ($r.Status -ne "serviceOperational") { [string]$r.Status } else { "" } }) `
            (New-DashSection $M365Data "Issues"    "Open Incidents & Advisories") `
            (New-DashSection $M365Data "Alerts"    "Security Alerts (Defender / Microsoft 365)") `
            (New-DashSection $M365Data "Risky"     "Risky Users") `
            (New-DashSection $M365Data "SignIns"   "Failed Sign-ins by User (last $hrs h)") `
            (New-DashSection $M365Data "SignInIPs" "Failed Sign-ins by Source IP") `
            (New-DashSection $M365Data "Messages"  "Message Center (changed in last $days days)") `
            (New-DashSection $M365Data "Score"     "Secure Score")
        if ($M365Data.SignInNote) {
            foreach ($d in $det) { if ($d.title -like "Failed Sign-ins by User*") { $d["note"] = [string]$M365Data.SignInNote } }
        }
        $items.Add((New-DashItem "m365" "$DashSiteName Microsoft 365" $nowIso $status $DashMasterIntervalMinutes $m $det))
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
        $defStale = if ($DefData.StaleDays) { [double]$DefData.StaleDays } else { 7 }
        $defIssues = {
            param($r)
            $x = @()
            if ($r.Risk -in @("High", "Medium")) { $x += "Risk: $($r.Risk)" }
            if ($r.Exposure -eq "High") { $x += "Exposure: High" }
            if ($r.Health -and $r.Health -ne "Active") { $x += "Health: $($r.Health)" }
            if ($r.AV -and ([string]$r.AV).ToLower() -notin @("updated", "unknown", "notsupported")) { $x += "Antivirus: $($r.AV)" }
            if ($null -ne $r.DaysSince -and "$($r.DaysSince)" -ne "" -and [double]$r.DaysSince -gt $defStale) { $x += "Not seen for $([math]::Round([double]$r.DaysSince)) days" }
            $x -join " | "
        }
        $det = Join-DashSections `
            (New-DashSection $DefData "Incidents" "Open Incidents") `
            (New-DashSection $DefData "Alerts"    "Unresolved Alerts") `
            (New-DashSection $DefData "Machines"  "Devices Needing Attention" { (& $defIssues $_) -ne "" -and $_.Onboarding -eq "Onboarded" } $defIssues) `
            (New-DashSection $DefData "Machines"  "Discovered But Not Onboarded" { $_.Onboarding -and $_.Onboarding -ne "Onboarded" }) `
            (New-DashNameList "Monitored Devices Not in Defender" $DefData.NotInMde) `
            (New-DashSection $DefData "Recs"      "Top Security Recommendations") `
            (New-DashSection $DefData "Controls"  "Secure Score - Biggest Improvements Available") `
            (New-DashSection $DefData "Exposure"  "Exposure Score") `
            (New-DashSection $DefData "Machines"  "All Onboarded Devices" { $_.Onboarding -eq "Onboarded" -or -not $_.Onboarding } $defIssues)
        $items.Add((New-DashItem "defender" "$DashSiteName Defender" $nowIso $status $DashMasterIntervalMinutes $m $det))
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
        $det = Join-DashSections `
            (New-DashSection $IntuneData "Certs"       "Apple Certificates & Tokens" $null { param($r) if ($null -ne $r.DaysLeft -and "$($r.DaysLeft)" -ne "" -and [double]$r.DaysLeft -le $certDays) { "Expires in $($r.DaysLeft) days" } else { "" } }) `
            (New-DashSection $IntuneData "Devices"     "Devices Needing Attention" { $_.Issues }) `
            (New-DashSection $IntuneData "Perf"        "Performance Issues (Endpoint analytics)") `
            (New-DashSection $IntuneData "Battery"     "Worn Batteries") `
            (New-DashSection $IntuneData "AppCrash"    "Apps Crashing / Hanging") `
            (New-DashSection $IntuneData "Scores"      "Lowest Scoring Devices") `
            (New-DashSection $IntuneData "Resource"    "CPU & Memory Strain") `
            (New-DashSection $IntuneData "Readiness"   "Windows 11 Hardware Readiness") `
            (New-DashSection $IntuneData "Models"      "Scores by Model") `
            (New-DashSection $IntuneData "StartupProc" "Programs Slowing Down Boot") `
            (New-DashSection $IntuneData "AppFail"     "Apps Failing to Install") `
            (New-DashSection $IntuneData "Policies"    "Policies With Errors or Conflicts") `
            (New-DashNameList "Monitored Devices Not in Intune" $IntuneData.NotInIntune) `
            (New-DashSection $IntuneData "Devices"     "All Managed Devices")
        $items.Add((New-DashItem "intune" "$DashSiteName Intune" $nowIso $status $DashMasterIntervalMinutes $m $det))
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
    $json    = ConvertTo-Json -InputObject $payload -Depth 12 -Compress

    # Write to a temp name then rename, so Push-Dashboard never picks up a half-written file
    $name = "master_{0}.json" -f $now.ToString("yyyyMMdd_HHmmss")
    $tmp  = Join-Path $DashOutbox ($name + ".tmp")
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination (Join-Path $DashOutbox $name) -Force

    Write-Host "✅ Web dashboard export: $($items.Count) item(s) -> $DashOutbox\$name" -ForegroundColor Cyan
}
