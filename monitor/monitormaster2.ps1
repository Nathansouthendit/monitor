# ============================================================
# Monitor-Master.ps1
#
# Runs on the management server (schedule it a few minutes after
# the top of the hour, so it runs after all the agents). Reads
# every device's folder under $ShareRoot - each populated hourly
# by Monitor-Agent.ps1 - and builds ONE Dashboard.html covering
# every server and PC. Also evaluates alert rules and sends
# email centrally, across all devices, in a single pass.
#
# Tabs:
#   Servers        - every device reporting via Monitor-Agent.ps1
#   Network Switches - every switch on the network: online/offline,
#                    ping time, uptime / restarts, port status and
#                    speed, new port errors, LLDP neighbours (what's
#                    plugged into the uplinks) and Telnet left on.
#                    Finds new switches on the subnet by itself.
#   Microsoft 365  - service health, open incidents/advisories,
#                    Defender alerts, risky users, failed sign-ins,
#                    Message Center and Secure Score (same as
#                    Eastwood / Westleigh)
#   Defender       - everything to investigate from the Defender
#                    portal: open incidents, unresolved alerts,
#                    device risk/health, devices not onboarded,
#                    vulnerability recommendations and Secure Score
#                    improvement actions
#   Intune         - proactive device checks: compliance (with the
#                    failing policies), check-in, disk space,
#                    encryption, unsupported Windows, Endpoint
#                    analytics performance (boot/sign-in time, blue
#                    screens, battery health, app crashes), app and
#                    policy failures, Apple certificate/token expiry,
#                    hardware & performance (device scores, CPU/memory
#                    strain, Windows 11 readiness, worst models,
#                    programs slowing boot)
# ============================================================

# ================== CONFIG ==================
$ShareRoot     = "\\ymca-host-02\MonitorShare"
$DashboardPath = "C:\Monitor\MonitorShare\Dashboard.html"

# ---------- Microsoft 365 (Microsoft Graph) ----------
# ONE-TIME SETUP (in Southend YMCA's tenant):
#
#   1. entra.microsoft.com (signed in as a YMCA admin) > App registrations
#      > New registration. Name "YMCA Monitoring (read-only)", single
#      tenant, no redirect URI.
#   2. API permissions > Add > Microsoft Graph > APPLICATION permissions:
#        ServiceHealth.Read.All      service health + incidents/advisories
#        ServiceMessage.Read.All     Message Center
#        SecurityEvents.Read.All     Secure Score
#        SecurityAlert.Read.All      Defender alerts  (needs a Defender licence)
#        IdentityRiskyUser.Read.All  risky users      (needs Entra ID P2)
#      AND API permissions > Add > "Office 365 Management APIs" > APPLICATION:
#        ActivityFeed.Read           failed sign-ins from the Unified Audit Log
#                                    (works on A1 - no Entra P1 needed)
#      then click "Grant admin consent". All read-only.
#   3. Certificates & secrets > New client secret (24 months). Copy the VALUE.
#      Put a reminder in your calendar - the tab shows a sign-in error when it expires.
#   4. Copy the Tenant ID from the app's Overview page into $M365TenantId below.
#   5. On YMCA's management server, run once, interactively, as the account
#      the Scheduled Task for THIS script runs as:
#
#      $cred = Get-Credential -Message "Username = Application (client) ID, Password = Client secret VALUE"
#      $cred | Export-CliXml -Path "C:\Monitor\m365_creds.xml"
#
# Sections the tenant isn't licensed for (Defender alerts, risky users) are
# hidden from the tab automatically. Other errors show in the tab.
#
# Failed sign-ins: the first run switches on the audit feed subscription.
# Microsoft can take up to 12 hours to start delivering after that.
$M365CredPath    = "C:\Monitor\graphmail_creds.xml"
$M365TenantId    = "4dae0b82-c3e4-41d6-906d-6c59d0508b58"   # <-- Southend YMCA's Directory (tenant) ID
$M365SignInHours = 24      # failed sign-ins look-back (max 168 = 7 days)
$M365MessageDays = 7       # Message Center look-back

# YMCA's public (WAN) IP address(es). Failed sign-ins from any other IP
# are flagged "External". Leave empty to skip. e.g. @("81.2.3.4")
$M365KnownIPs    = @()

# ---------- Microsoft Defender ----------
# The Defender tab uses the SAME app registration and m365_creds.xml as the
# Microsoft 365 tab above - it just needs these extra APPLICATION permissions
# adding to it (then "Grant admin consent" again):
#
#   Microsoft Graph:
#     SecurityIncident.Read.All       Defender XDR incidents
#     (SecurityAlert.Read.All and SecurityEvents.Read.All are already in the list above)
#   APIs my organization uses > "WindowsDefenderATP":
#     Machine.Read.All                device risk / health / onboarding
#     SecurityRecommendation.Read.All vulnerability & config recommendations
#     Score.Read.All                  exposure score / Secure Score for devices
#
# The device and recommendation sections need Defender for Endpoint or
# Defender for Business (e.g. Microsoft 365 Business Premium). If the tenant
# doesn't have it, those sections are hidden automatically.
$DefStaleDays    = 7      # onboarded devices not seen by Defender for longer than this are flagged
$DefMaxRecs      = 25     # how many vulnerability / config recommendations to show
$DefMaxControls  = 20     # how many Secure Score improvement actions to show

# ---------- Intune ----------
# The Intune tab uses the SAME app registration and credentials file as the
# Microsoft 365 tab. Add these Microsoft Graph APPLICATION permissions to it
# (then "Grant admin consent" again) - all read-only:
#
#   DeviceManagementManagedDevices.Read.All   devices, compliance, Endpoint analytics
#   DeviceManagementConfiguration.Read.All    configuration / compliance policy failures
#   DeviceManagementApps.Read.All             app install failures, Apple VPP tokens
#   DeviceManagementServiceConfig.Read.All    Apple push certificate, Apple enrolment (ADE) tokens
#
# Performance data comes from Endpoint analytics. If it has never been
# switched on: intune.microsoft.com > Reports > Endpoint analytics > Start.
# It takes a day or two to collect data after that.
$IntuneStaleDays      = 7     # devices that haven't checked in with Intune for longer than this are flagged
$IntuneLowDiskPct     = 10    # flag devices with less free disk than this percentage...
$IntuneLowDiskGB      = 10    # ...or less than this many GB free
$IntuneCertWarnDays   = 30    # warn when an Apple certificate / token expires within this many days
$IntuneBootWarnSec    = 60    # flag devices whose boot takes longer than this
$IntuneLoginWarnSec   = 60    # flag devices whose sign-in takes longer than this
$IntuneBatteryWarnPct = 60    # flag laptops whose battery has dropped below this % of its original capacity
$IntuneReasonLookups  = 50    # how many non-compliant devices to look up the failing policies for
$IntuneScoreWarn      = 50    # Endpoint analytics scores (0-100) below this are flagged
$IntuneSpikeWarnPct   = 20    # flag devices whose CPU or memory is maxed out for more than this % of the time
$IntuneMinRamGB       = 8     # flag Windows devices with less memory than this

# ---------- Network switches ----------
# The Network Switches tab pings each switch, checks which management ports
# (SSH / Telnet / HTTP / HTTPS) are open and, where SNMP is switched on, reads
# the model, uptime, every port's status and speed, port errors and LLDP
# neighbours.
#
# ONE-TIME SETUP on each managed switch: switch on SNMP v2c READ-ONLY with a
# community string of your own (not "public"), ideally restricted to this
# server's IP. Put the same string in $SwitchCommunity below. A switch without
# SNMP still shows on the tab, with ping and port checks only.
#
# Switches to always check, even when they're offline. Name is just a label.
$SwitchList = @(
    # @{ Name = "Core switch";   IP = "10.131.36.2" }
    # @{ Name = "Office switch"; IP = "10.131.36.3" }
)
# /24 networks (first three numbers) to search each run for switches you
# haven't listed above. Anything that answers SNMP and reports itself as a
# layer-2 device is added automatically and remembered, so it still shows (as
# offline) if it stops responding. Leave empty to only check $SwitchList.
$SwitchDiscoverSubnets = @("10.131.36")
$SwitchIgnore          = @("10.131.36.1")   # IPs never to treat as switches (e.g. the router) - add it to $SwitchList if you DO want it shown
$SwitchCommunity       = "public"           # SNMP read-only community - must match the switches
$SwitchSnmpTimeoutMs   = 1000
$SwitchStatePath       = "C:\Monitor\switch_state.json"   # last run's counters, so errors/restarts can be worked out hour to hour
$SwitchLatencyWarnMs   = 20     # flag switches slower than this to ping (on the LAN they're normally ~1 ms)
$SwitchRebootWarnHours = 24     # flag switches that restarted within this many hours
$SwitchChangeMinutes   = 65     # ports that went up/down within this many minutes count as "changed recently"
$SwitchForgetDays      = 30     # stop showing a discovered switch once it's been offline this long

if (!(Test-Path $ShareRoot)) {
    Write-Host "Cannot reach $ShareRoot - aborting this run" -ForegroundColor Red
    return
}

$ReportsFolder = Split-Path $DashboardPath -Parent
if (!(Test-Path $ReportsFolder)) {
    New-Item -Path $ReportsFolder -ItemType Directory -Force | Out-Null
}

# ================== LOAD ALL DEVICES ==================
$DeviceFolders = Get-ChildItem $ShareRoot -Directory -ErrorAction SilentlyContinue

$AllDevices = [ordered]@{}   # DeviceName -> array of {Data, FileName}, newest first

foreach ($folder in $DeviceFolders) {

    $csvFiles = Get-ChildItem $folder.FullName -Filter "stats_*.csv" |
        Where-Object { $_.Length -gt 0 } |
        Sort-Object LastWriteTime -Descending

    if ($csvFiles.Count -eq 0) { continue }

    $history = foreach ($f in $csvFiles) { Import-Csv $f.FullName }
    $history = $history | Select-Object -First 50

    $combined = for ($i = 0; $i -lt $history.Count; $i++) {
        [PSCustomObject]@{ Data = $history[$i]; FileName = $csvFiles[$i].Name }
    }

    $AllDevices[$folder.Name] = @($combined)
}

if ($AllDevices.Count -eq 0) {
    Write-Host "No device data found under $ShareRoot yet" -ForegroundColor Yellow
    return
}

$AllDevicesJson = $AllDevices | ConvertTo-Json -Depth 6 -Compress

# ================== MICROSOFT 365 ==================
$M365Data = [ordered]@{
    Error        = ""
    FetchedAt    = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    SignInHours  = $M365SignInHours
    MessageDays  = $M365MessageDays
    KnownIPsSet  = ($M365KnownIPs.Count -gt 0)
    FailedTotal  = $null
    FailedExternal = $null
    SignInNote   = ""
    Sections     = [ordered]@{}   # name -> @{ Error = ""; Unlicensed = $false; Rows = @() }
}

function Get-GraphPaged {
    param([string]$Url, [hashtable]$Headers, [int]$Max = 2000)
    $items = @()
    $next  = $Url
    while ($next -and $items.Count -lt $Max) {
        $r = Invoke-RestMethod -Uri $next -Headers $Headers -ErrorAction Stop
        if ($r.value) { $items += $r.value }
        $next = $r.'@odata.nextLink'
    }
    $items
}

function ConvertTo-M365Time($v) {
    if (-not $v) { return "" }
    try { return ([datetime]$v).ToString("yyyy-MM-dd HH:mm") } catch { return [string]$v }
}

function Get-GraphErrorText($err) {
    $msg  = $err.Exception.Message
    $body = $null
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) {
        $body = $err.ErrorDetails.Message
    }
    elseif ($err.Exception.Response) {
        try {
            $sr   = New-Object System.IO.StreamReader($err.Exception.Response.GetResponseStream())
            $body = $sr.ReadToEnd()
        } catch { }
    }
    if ($body) {
        try {
            $j = ConvertFrom-Json $body
            if ($j.error.message)      { $msg = "$($j.error.code): $($j.error.message)" }
            elseif ($j.error_description) { $msg = $j.error_description }
        } catch { }
    }
    return $msg
}

function Invoke-M365Section {
    param([string]$Name, [scriptblock]$Block)
    try {
        $rows = @(& $Block)
        $M365Data.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $false; Rows = $rows }
        Write-Host ("  M365 {0,-9} {1} row(s)" -f $Name, $rows.Count) -ForegroundColor DarkCyan
    }
    catch {
        $detail = Get-GraphErrorText $_
        if ($detail -match 'not provisioned|not licensed|NonPremium|doesn.t have premium licen') {
            $M365Data.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $true; Rows = @() }
            Write-Host "  M365 $Name : skipped - not included in your licence (hidden from the tab)" -ForegroundColor DarkGray
            return
        }
        $msg = $detail
        if ($_.Exception.Message -match '\(403\)|\(401\)|Forbidden' -or $detail -match 'Authorization_RequestDenied|AF10001') {
            $msg = "Not available - the app is missing the permission for this (or admin consent hasn't been granted). Error: $detail"
        }
        $M365Data.Sections[$Name] = [ordered]@{ Error = $msg; Unlicensed = $false; Rows = @() }
        Write-Host "  M365 $Name : $msg" -ForegroundColor Yellow
    }
}

$sevRank = @{ high = 0; medium = 1; low = 2; informational = 3 }

if ($M365TenantId -notmatch '^[0-9a-fA-F-]{36}$' -or $M365TenantId -eq "00000000-0000-0000-0000-000000000000") {
    $M365Data.Error = "Microsoft 365 tenant ID not set - fill in `$M365TenantId in the CONFIG section of this script (see the one-time setup notes there)."
}
elseif (!(Test-Path $M365CredPath)) {
    $M365Data.Error = "Microsoft 365 app credentials not found at $M365CredPath - see the one-time setup notes in the CONFIG section."
}
else {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # Make sure normal certificate checking is on
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $mc  = Import-CliXml $M365CredPath
        $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$M365TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                grant_type    = "client_credentials"
                client_id     = $mc.UserName
                client_secret = $mc.GetNetworkCredential().Password
                scope         = "https://graph.microsoft.com/.default"
            } -ErrorAction Stop
        $gh = @{ Authorization = "Bearer $($tok.access_token)" }

        # Show which Application permissions actually made it into the token
        try {
            $p = $tok.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
            switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
            $claims = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))
            $roles  = @($claims.roles)
            if ($roles.Count) { Write-Host "  M365 token permissions: $($roles -join ', ')" -ForegroundColor DarkCyan }
            else { Write-Host "  M365 token has NO application permissions - check they're 'Application' type and admin consent is granted" -ForegroundColor Yellow }
        } catch { }
        $G  = "https://graph.microsoft.com/v1.0"

        # 1) Service health
        Invoke-M365Section "Health" {
            Get-GraphPaged -Url "$G/admin/serviceAnnouncement/healthOverviews" -Headers $gh |
                ForEach-Object { [PSCustomObject]@{ Service = $_.service; Status = $_.status } } |
                Sort-Object @{ e = { if ($_.Status -eq "serviceOperational") { 1 } else { 0 } } }, Service
        }

        # 2) Open incidents & advisories
        Invoke-M365Section "Issues" {
            Get-GraphPaged -Url "$G/admin/serviceAnnouncement/issues" -Headers $gh |
                Where-Object { -not $_.isResolved } |
                Sort-Object @{ e = { if ($_.classification -eq "incident") { 0 } else { 1 } } }, @{ e = "lastModifiedDateTime"; d = $true } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Id      = $_.id
                        Type    = $_.classification
                        Service = $_.service
                        Status  = $_.status
                        Title   = $_.title
                        Impact  = $_.impactDescription
                        Started = ConvertTo-M365Time $_.startDateTime
                        Updated = ConvertTo-M365Time $_.lastModifiedDateTime
                        Link    = "https://admin.microsoft.com/Adminportal/Home#/servicehealth/:/alerts/$($_.id)"
                    }
                }
        }

        # 3) Defender / Microsoft 365 security alerts that aren't resolved
        Invoke-M365Section "Alerts" {
            $f = [uri]::EscapeDataString("status ne 'resolved'")
            Get-GraphPaged -Url "$G/security/alerts_v2?`$top=100&`$filter=$f" -Headers $gh -Max 500 |
                Sort-Object @{ e = { $r = $sevRank[[string]$_.severity]; if ($null -eq $r) { 9 } else { $r } } }, @{ e = "createdDateTime"; d = $true } |
                ForEach-Object {
                    $users = @($_.evidence | Where-Object { $_.userAccount.userPrincipalName } |
                        ForEach-Object { $_.userAccount.userPrincipalName } | Sort-Object -Unique)
                    $hosts = @($_.evidence | Where-Object { $_.deviceDnsName } |
                        ForEach-Object { $_.deviceDnsName } | Sort-Object -Unique)
                    [PSCustomObject]@{
                        Created  = ConvertTo-M365Time $_.createdDateTime
                        Severity = $_.severity
                        Status   = $_.status
                        Title    = $_.title
                        Source   = $_.serviceSource
                        Category = $_.category
                        Entities = (@($users) + @($hosts)) -join ", "
                        Link     = $_.alertWebUrl
                    }
                }
        }

        # 4) Risky users (Entra ID P2)
        Invoke-M365Section "Risky" {
            $f = [uri]::EscapeDataString("riskState eq 'atRisk'")
            Get-GraphPaged -Url "$G/identityProtection/riskyUsers?`$filter=$f" -Headers $gh |
                Sort-Object @{ e = { $r = $sevRank[[string]$_.riskLevel]; if ($null -eq $r) { 9 } else { $r } } } |
                ForEach-Object {
                    [PSCustomObject]@{
                        User    = $_.userPrincipalName
                        Risk    = $_.riskLevel
                        Detail  = $_.riskDetail
                        Updated = ConvertTo-M365Time $_.riskLastUpdatedDateTime
                    }
                }
        }

        # 5) Failed sign-ins from the Unified Audit Log (works on A1)
        $script:ualFails = $null
        $ualReason = @{
            InvalidUserNameOrPassword        = "Wrong password"
            InvalidPasswordExpiredPassword   = "Password expired"
            UserAccountNotFound              = "Account doesn't exist"
            UserDisabled                     = "Account disabled"
            IdsLocked                        = "Locked out (smart lockout)"
            BlockedByConditionalAccess       = "Blocked by Conditional Access"
            DeviceAuthenticationRequired     = "Device authentication required"
            UserStrongAuthEnrollmentRequired = "MFA registration required"
            UserStrongAuthClientAuthNRequired = "MFA required"
            InvalidReplyTo                   = "Bad app redirect"
        }

        Invoke-M365Section "SignIns" {
            $mtok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$M365TenantId/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{
                    grant_type    = "client_credentials"
                    client_id     = $mc.UserName
                    client_secret = $mc.GetNetworkCredential().Password
                    scope         = "https://manage.office.com/.default"
                } -ErrorAction Stop
            $mh   = @{ Authorization = "Bearer $($mtok.access_token)" }
            $feed = "https://manage.office.com/api/v1.0/$M365TenantId/activity/feed"
            $ct   = "Audit.AzureActiveDirectory"

            $subs = Invoke-RestMethod -Uri "$feed/subscriptions/list" -Headers $mh -ErrorAction Stop
            $sub  = $subs | Where-Object { $_.contentType -eq $ct } | Select-Object -First 1
            if (-not $sub -or $sub.status -ne "enabled") {
                Invoke-RestMethod -Method Post -Uri "$feed/subscriptions/start?contentType=$ct" -Headers $mh -ErrorAction Stop | Out-Null
                $M365Data.SignInNote = "The audit feed was switched on at $(Get-Date -Format 'dd/MM/yyyy HH:mm'). Microsoft can take up to 12 hours to start delivering sign-in events, so this section may be empty until then."
                Write-Host "  M365 SignIns : audit feed subscription switched on - data can take up to 12 hours to start" -ForegroundColor DarkCyan
            }

            $hours    = [math]::Min([math]::Max($M365SignInHours, 1), 168)
            $endUtc   = (Get-Date).ToUniversalTime()
            $startUtc = $endUtc.AddHours(-$hours)
            $blobs    = New-Object System.Collections.Generic.List[string]
            $winStart = $startUtc
            while ($winStart -lt $endUtc) {
                $winEnd = $winStart.AddHours(24)
                if ($winEnd -gt $endUtc) { $winEnd = $endUtc }
                $next = "$feed/subscriptions/content?contentType=$ct" +
                        "&startTime=" + $winStart.ToString("yyyy-MM-ddTHH:mm:ss") +
                        "&endTime="   + $winEnd.ToString("yyyy-MM-ddTHH:mm:ss")
                while ($next) {
                    $resp = Invoke-WebRequest -Uri $next -Headers $mh -UseBasicParsing -ErrorAction Stop
                    $page = ConvertFrom-Json $resp.Content
                    foreach ($b in $page) { if ($b.contentUri) { $blobs.Add([string]$b.contentUri) } }
                    $np   = $resp.Headers["NextPageUri"]
                    $next = if ($np) { [string](@($np)[0]) } else { $null }
                }
                $winStart = $winEnd
            }

            $fails = New-Object System.Collections.Generic.List[object]
            foreach ($u in ($blobs | Select-Object -Unique | Select-Object -First 1500)) {
                try { $evs = Invoke-RestMethod -Uri $u -Headers $mh -ErrorAction Stop }
                catch { Write-Host "  M365 SignIns : skipped one audit blob ($($_.Exception.Message))" -ForegroundColor DarkGray; continue }

                foreach ($ev in $evs) {
                    if ($ev.Operation -ne "UserLoginFailed") { continue }
                    if ([string]$ev.LogonError -match "Interrupt") { continue }

                    $t = [datetime]::SpecifyKind([datetime]$ev.CreationTime, [DateTimeKind]::Utc)
                    if ($t -lt $startUtc) { continue }

                    $err    = [string]$ev.LogonError
                    $reason = if ($ualReason.ContainsKey($err)) { $ualReason[$err] }
                              elseif ($err) { $err }
                              else { "Error $($ev.ErrorNumber)" }
                    $ip = if ($ev.ClientIP) { [string]$ev.ClientIP } else { [string]$ev.ActorIpAddress }

                    $fails.Add([PSCustomObject]@{
                        User   = [string]$ev.UserId
                        IP     = $ip
                        Time   = $t
                        Reason = $reason
                    })
                }
            }

            $script:ualFails = $fails
            $M365Data.FailedTotal = $fails.Count

            $perUser = @($fails | Group-Object User | ForEach-Object {
                $g    = $_.Group
                $last = $g | Sort-Object Time -Descending | Select-Object -First 1
                $ips  = @($g | ForEach-Object { $_.IP } | Where-Object { $_ } | Sort-Object -Unique)
                $ext  = @($ips | Where-Object { $M365KnownIPs.Count -gt 0 -and $M365KnownIPs -notcontains $_ })
                $top  = @($g | Group-Object Reason | Sort-Object Count -Descending)[0].Name
                [PSCustomObject]@{
                    User        = $_.Name
                    Failures    = $_.Count
                    TopReason   = $top
                    IPCount     = $ips.Count
                    ExternalIPs = $ext -join ", "
                    External    = ($ext.Count -gt 0)
                    LastIP      = $last.IP
                    Last        = $last.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                }
            })
            $M365Data.FailedExternal = if ($M365KnownIPs.Count) { @($perUser | Where-Object { $_.External }).Count } else { $null }

            $perUser | Sort-Object @{ e = { if ($_.External) { 0 } else { 1 } } }, @{ e = "Failures"; d = $true } |
                Select-Object -First 50
        }

        # 5b) Same failures grouped by source IP (password-spray check)
        if ($null -ne $script:ualFails) {
            Invoke-M365Section "SignInIPs" {
                $script:ualFails | Where-Object { $_.IP } | Group-Object IP | ForEach-Object {
                    $users = @($_.Group | ForEach-Object { $_.User } | Sort-Object -Unique)
                    $more  = if ($users.Count -gt 5) { " +" + ($users.Count - 5) + " more" } else { "" }
                    [PSCustomObject]@{
                        IP       = $_.Name
                        Failures = $_.Count
                        Users    = $users.Count
                        Accounts = (@($users | Select-Object -First 5) -join ", ") + $more
                        External = ($M365KnownIPs.Count -gt 0 -and $M365KnownIPs -notcontains $_.Name)
                        Last     = ($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    }
                } | Sort-Object @{ e = "Users"; d = $true }, @{ e = "Failures"; d = $true } | Select-Object -First 20
            }
        }

        # 6) Message Center
        Invoke-M365Section "Messages" {
            $cut = (Get-Date).AddDays(-$M365MessageDays)
            Get-GraphPaged -Url "$G/admin/serviceAnnouncement/messages" -Headers $gh |
                Where-Object { $_.lastModifiedDateTime -and [datetime]$_.lastModifiedDateTime -ge $cut } |
                Sort-Object @{ e = { if ($_.actionRequiredByDateTime) { 0 } elseif ($_.isMajorChange) { 1 } else { 2 } } }, @{ e = "lastModifiedDateTime"; d = $true } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Id       = $_.id
                        Title    = $_.title
                        Services = @($_.services) -join ", "
                        Category = $_.category
                        Major    = [bool]$_.isMajorChange
                        ActionBy = ConvertTo-M365Time $_.actionRequiredByDateTime
                        Updated  = ConvertTo-M365Time $_.lastModifiedDateTime
                        Link     = "https://admin.microsoft.com/Adminportal/Home#/MessageCenter/:/messages/$($_.id)"
                    }
                }
        }

        # 7) Secure Score
        Invoke-M365Section "Score" {
            Get-GraphPaged -Url "$G/security/secureScores?`$top=1" -Headers $gh -Max 1 | Select-Object -First 1 | ForEach-Object {
                [PSCustomObject]@{
                    Score   = [math]::Round([double]$_.currentScore, 1)
                    Max     = [math]::Round([double]$_.maxScore, 1)
                    Percent = if ($_.maxScore) { [math]::Round(100 * $_.currentScore / $_.maxScore) } else { 0 }
                    Date    = ConvertTo-M365Time $_.createdDateTime
                }
            }
        }

        Write-Host "Microsoft 365: data fetched" -ForegroundColor Cyan
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $msg = (ConvertFrom-Json $_.ErrorDetails.Message).error_description } catch { }
        }
        $M365Data.Error = "Could not sign in to Microsoft 365 (check the tenant ID, client ID and that the client secret hasn't expired): $msg"
        Write-Host $M365Data.Error -ForegroundColor Yellow
    }
}

$M365DataJson = (ConvertTo-Json -InputObject $M365Data -Depth 6 -Compress) -replace '<', ('\' + 'u003c')

# ================== MICROSOFT DEFENDER ==================
# Everything worth investigating from the Defender portal (security.microsoft.com):
# open incidents, unresolved alerts, device risk/health, devices not onboarded,
# vulnerability recommendations and Secure Score improvement actions. Each
# section is fetched independently - a missing permission or licence only
# affects that one section.
$DefData = [ordered]@{
    Error      = ""
    FetchedAt  = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    StaleDays  = $DefStaleDays
    NotInMde   = @()
    Sections   = [ordered]@{}   # name -> @{ Error = ""; Unlicensed = $false; Rows = @() }
}

function Invoke-DefSection {
    param([string]$Name, [scriptblock]$Block)
    try {
        $rows = @(& $Block)
        $DefData.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $false; Rows = $rows }
        Write-Host ("  Defender {0,-9} {1} row(s)" -f $Name, $rows.Count) -ForegroundColor DarkCyan
    }
    catch {
        $detail = Get-GraphErrorText $_
        if ($detail -match 'not provisioned|not licensed|NonPremium|doesn.t have premium licen|No license|license.*(not|required)|tenant.*not.*(onboarded|provisioned)|InvalidTenant') {
            $DefData.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $true; Rows = @() }
            Write-Host "  Defender $Name : skipped - not included in your licence (hidden from the tab)" -ForegroundColor DarkGray
            return
        }
        $msg = $detail
        if ($_.Exception.Message -match '\(403\)|\(401\)|Forbidden|Unauthorized' -or $detail -match 'Authorization_RequestDenied|AF10001|Forbidden|Unauthorized') {
            $msg = "Not available - the app is missing the permission for this (or admin consent hasn't been granted). Error: $detail"
        }
        $DefData.Sections[$Name] = [ordered]@{ Error = $msg; Unlicensed = $false; Rows = @() }
        Write-Host "  Defender $Name : $msg" -ForegroundColor Yellow
    }
}

if ($M365Data.Error) {
    # Same app/credentials as the Microsoft 365 tab - no point trying again
    $DefData.Error = $M365Data.Error
}
else {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $dc = Import-CliXml $M365CredPath
        $getToken = {
            param([string]$Scope)
            (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$M365TenantId/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{
                    grant_type    = "client_credentials"
                    client_id     = $dc.UserName
                    client_secret = $dc.GetNetworkCredential().Password
                    scope         = $Scope
                } -ErrorAction Stop).access_token
        }

        $dgh = @{ Authorization = "Bearer $(& $getToken 'https://graph.microsoft.com/.default')" }
        $G   = "https://graph.microsoft.com/v1.0"
        $defSev = @{ high = 0; medium = 1; low = 2; informational = 3 }

        # 1) Open incidents (Defender XDR)
        Invoke-DefSection "Incidents" {
            Get-GraphPaged -Url "$G/security/incidents?`$top=50" -Headers $dgh -Max 500 |
                Where-Object { $_.status -ne "resolved" } |
                Sort-Object @{ e = { $r = $defSev[[string]$_.severity]; if ($null -eq $r) { 9 } else { $r } } }, @{ e = "lastUpdateDateTime"; d = $true } |
                Select-Object -First 100 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Id       = $_.id
                        Name     = $_.displayName
                        Severity = $_.severity
                        Status   = $_.status
                        Assigned = $_.assignedTo
                        Created  = ConvertTo-M365Time $_.createdDateTime
                        Updated  = ConvertTo-M365Time $_.lastUpdateDateTime
                        Link     = $_.incidentWebUrl
                    }
                }
        }

        # 2) Unresolved alerts (all Defender products - Endpoint, Office 365, Identity, Cloud Apps, Entra)
        Invoke-DefSection "Alerts" {
            $f = [uri]::EscapeDataString("status ne 'resolved'")
            Get-GraphPaged -Url "$G/security/alerts_v2?`$top=100&`$filter=$f" -Headers $dgh -Max 500 |
                Sort-Object @{ e = { $r = $defSev[[string]$_.severity]; if ($null -eq $r) { 9 } else { $r } } }, @{ e = "createdDateTime"; d = $true } |
                ForEach-Object {
                    $users = @($_.evidence | Where-Object { $_.userAccount.userPrincipalName } |
                        ForEach-Object { $_.userAccount.userPrincipalName } | Sort-Object -Unique)
                    $hosts = @($_.evidence | Where-Object { $_.deviceDnsName } |
                        ForEach-Object { $_.deviceDnsName } | Sort-Object -Unique)
                    $mails = @($_.evidence | Where-Object { $_.'@odata.type' -match 'mailbox|analyzedMessage' -and $_.subject } |
                        ForEach-Object { "Email: " + $_.subject } | Select-Object -First 2)
                    $desc = [string]$_.description
                    if ($desc.Length -gt 300) { $desc = $desc.Substring(0, 300) + "..." }
                    [PSCustomObject]@{
                        Created   = ConvertTo-M365Time $_.createdDateTime
                        Severity  = $_.severity
                        Status    = $_.status
                        Title     = $_.title
                        Detail    = $desc
                        Source    = $_.serviceSource
                        Detection = $_.detectionSource
                        Category  = $_.category
                        Entities  = (@($users) + @($hosts) + @($mails)) -join ", "
                        Incident  = $_.incidentId
                        Link      = $_.alertWebUrl
                    }
                }
        }

        # 3) Secure Score improvement actions not yet fully done (biggest gain first)
        Invoke-DefSection "Controls" {
            $latest = @(Get-GraphPaged -Url "$G/security/secureScores?`$top=1" -Headers $dgh -Max 1)[0]
            $now = @{}
            if ($latest) { foreach ($c in $latest.controlScores) { $now[[string]$c.controlName] = $c } }

            Get-GraphPaged -Url "$G/security/secureScoreControlProfiles" -Headers $dgh -Max 1000 |
                Where-Object { -not $_.deprecated -and $_.maxScore -gt 0 } |
                ForEach-Object {
                    $cs  = $now[[string]$_.id]
                    $cur = if ($cs) { [double]$cs.score } else { 0 }
                    $gap = [double]$_.maxScore - $cur
                    if ($gap -gt 0.05) {
                        [PSCustomObject]@{
                            Action     = $_.title
                            Category   = $_.controlCategory
                            Service    = $_.service
                            Points     = "{0} / {1}" -f [math]::Round($cur, 1), [math]::Round([double]$_.maxScore, 1)
                            Gain       = [math]::Round($gap, 1)
                            UserImpact = $_.userImpact
                            Effort     = $_.implementationCost
                            Link       = $_.actionUrl
                        }
                    }
                } | Sort-Object @{ e = "Gain"; d = $true } | Select-Object -First $DefMaxControls
        }

        # 4) Defender for Endpoint / Business - separate API, separate token
        $mdeToken = $null
        try { $mdeToken = & $getToken 'https://api.securitycenter.microsoft.com/.default' }
        catch {
            $t = Get-GraphErrorText $_
            foreach ($n in @("Machines", "Recs", "Exposure")) {
                $DefData.Sections[$n] = [ordered]@{ Error = "Could not sign in to the Defender for Endpoint API: $t"; Unlicensed = $false; Rows = @() }
            }
        }

        if ($mdeToken) {
            $mh  = @{ Authorization = "Bearer $mdeToken" }
            $MDE = "https://api.security.microsoft.com/api"

            $script:mdeMachines = $null
            Invoke-DefSection "Machines" {
                $raw = @(Get-GraphPaged -Url "$MDE/machines" -Headers $mh -Max 5000)
                $script:mdeMachines = $raw
                $raw | ForEach-Object {
                    $seen = $null
                    if ($_.lastSeen) { try { $seen = [datetime]$_.lastSeen } catch { } }
                    [PSCustomObject]@{
                        Name       = if ($_.computerDnsName) { $_.computerDnsName } else { $_.id }
                        OS         = (@($_.osPlatform, $_.version) | Where-Object { $_ }) -join " "
                        Onboarding = $_.onboardingStatus
                        Health     = $_.healthStatus
                        Risk       = $_.riskScore
                        Exposure   = $_.exposureLevel
                        AV         = $_.defenderAvStatus
                        LastIP     = $_.lastIpAddress
                        LastSeen   = if ($seen) { $seen.ToString("yyyy-MM-dd HH:mm") } else { "" }
                        DaysSince  = if ($seen) { [math]::Round(((Get-Date) - $seen).TotalDays, 1) } else { $null }
                        Link       = "https://security.microsoft.com/machines/v2/$($_.id)/overview"
                    }
                } | Sort-Object Name
            }

            # Monitored devices (from this dashboard) that aren't onboarded to Defender
            if ($null -ne $script:mdeMachines) {
                $onb = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($m in $script:mdeMachines) {
                    if ($m.onboardingStatus -eq "Onboarded" -and $m.computerDnsName) {
                        [void]$onb.Add(([string]$m.computerDnsName -split '\.')[0])
                    }
                }
                $DefData.NotInMde = @($AllDevices.Keys | Where-Object { -not $onb.Contains(([string]$_ -split '\.')[0]) } | Sort-Object)
            }

            Invoke-DefSection "Recs" {
                Get-GraphPaged -Url "$MDE/recommendations" -Headers $mh -Max 5000 |
                    Where-Object { $_.status -eq "Active" -and [int]$_.exposedMachinesCount -gt 0 } |
                    Sort-Object @{ e = { [bool]$_.activeAlert }; d = $true }, @{ e = { [bool]$_.publicExploit }; d = $true }, @{ e = { [double]$_.exposureImpact }; d = $true }, @{ e = { [double]$_.severityScore }; d = $true } |
                    Select-Object -First $DefMaxRecs |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Recommendation = $_.recommendationName
                            Product        = (@($_.vendor, $_.productName) | Where-Object { $_ }) -join " "
                            Type           = $_.remediationType
                            Weaknesses     = $_.weaknesses
                            Exposed        = "{0} / {1}" -f $_.exposedMachinesCount, $_.totalMachineCount
                            Exploit        = [bool]$_.publicExploit
                            ActiveAlert    = [bool]$_.activeAlert
                            Severity       = [math]::Round([double]$_.severityScore, 1)
                        }
                    }
            }

            Invoke-DefSection "Exposure" {
                $e = Invoke-RestMethod -Uri "$MDE/exposureScore" -Headers $mh -ErrorAction Stop
                $c = $null
                try { $c = Invoke-RestMethod -Uri "$MDE/configurationScore" -Headers $mh -ErrorAction Stop } catch { }
                [PSCustomObject]@{
                    Exposure    = [math]::Round([double]$e.score, 1)
                    DeviceScore = if ($c) { [math]::Round([double]$c.score, 1) } else { $null }
                }
            }
        }

        Write-Host "Defender: data fetched" -ForegroundColor Cyan
    }
    catch {
        $DefData.Error = "Could not fetch Defender data: $(Get-GraphErrorText $_)"
        Write-Host $DefData.Error -ForegroundColor Yellow
    }
}

$DefDataJson = (ConvertTo-Json -InputObject $DefData -Depth 6 -Compress) -replace '<', ('\' + 'u003c')

# ================== INTUNE ==================
# Proactive checks across every Intune-managed device: compliance (with the
# failing policies), check-in, disk space, encryption, out-of-support Windows,
# Endpoint analytics performance (boot/sign-in time, blue screens, battery
# health, app crashes), app install and policy failures, and Apple
# certificate/token expiry, plus hardware & performance from Endpoint
# analytics (device scores, CPU/memory strain, Windows 11 hardware readiness,
# scores by model, boot-slowing programs). Each section is fetched independently.
$IntuneData = [ordered]@{
    Error        = ""
    FetchedAt    = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    StaleDays    = $IntuneStaleDays
    LowDiskPct   = $IntuneLowDiskPct
    LowDiskGB    = $IntuneLowDiskGB
    CertWarnDays = $IntuneCertWarnDays
    BootWarnSec  = $IntuneBootWarnSec
    LoginWarnSec = $IntuneLoginWarnSec
    BatteryWarnPct = $IntuneBatteryWarnPct
    ScoreWarn    = $IntuneScoreWarn
    SpikeWarnPct = $IntuneSpikeWarnPct
    MinRamGB     = $IntuneMinRamGB
    NotInIntune  = @()
    Sections     = [ordered]@{}   # name -> @{ Error = ""; Unlicensed = $false; Rows = @() }
}

function Invoke-IntuneSection {
    param([string]$Name, [scriptblock]$Block)
    try {
        $rows = @(& $Block)
        $IntuneData.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $false; Rows = $rows }
        Write-Host ("  Intune {0,-11} {1} row(s)" -f $Name, $rows.Count) -ForegroundColor DarkCyan
    }
    catch {
        $detail = Get-GraphErrorText $_
        if ($detail -match 'not provisioned|not licensed|No license|doesn.t have.*licen|Intune.*not.*(enabled|available)') {
            $IntuneData.Sections[$Name] = [ordered]@{ Error = ""; Unlicensed = $true; Rows = @() }
            Write-Host "  Intune $Name : skipped - not included in your licence (hidden from the tab)" -ForegroundColor DarkGray
            return
        }
        $msg = $detail
        if ($_.Exception.Message -match '\(403\)|\(401\)|Forbidden|Unauthorized' -or $detail -match 'Authorization_RequestDenied|Forbidden|Unauthorized|not have.*permission') {
            $msg = "Not available - the app is missing the permission for this (or admin consent hasn't been granted). Error: $detail"
        }
        $IntuneData.Sections[$Name] = [ordered]@{ Error = $msg; Unlicensed = $false; Rows = @() }
        Write-Host "  Intune $Name : $msg" -ForegroundColor Yellow
    }
}

# Intune "reports" endpoints return { Schema: [{Column}], Values: [[...]] } - turn that into objects
function Invoke-IntuneReport {
    param([string]$Url, [hashtable]$Headers, [hashtable]$Body)
    $resp = Invoke-WebRequest -Method Post -Uri $Url -Headers $Headers -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 5) -UseBasicParsing -ErrorAction Stop
    $text = if ($resp.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($resp.Content) } else { [string]$resp.Content }
    $j = ConvertFrom-Json $text
    $cols = @($j.Schema | ForEach-Object { $_.Column })
    foreach ($v in @($j.Values)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $v[$i] }
        [PSCustomObject]$o
    }
}

# Friendly Windows version from a build number like 10.0.22631.4317
function Get-WinRelease([string]$Ver) {
    if ($Ver -notmatch '^10\.0\.(\d+)') { return "" }
    $b = [int]$Matches[1]
    $map = [ordered]@{ 26200 = "Windows 11 25H2"; 26100 = "Windows 11 24H2"; 22631 = "Windows 11 23H2"; 22621 = "Windows 11 22H2"; 22000 = "Windows 11 21H2";
                       19045 = "Windows 10 22H2"; 19044 = "Windows 10 21H2"; 19043 = "Windows 10 21H1"; 19042 = "Windows 10 20H2" }
    foreach ($k in $map.Keys) { if ($b -ge $k) { return $map[$k] } }
    return "Windows 10 (old)"
}

if ($M365Data.Error) {
    $IntuneData.Error = $M365Data.Error
}
else {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $ic  = Import-CliXml $M365CredPath
        $itk = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$M365TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                grant_type    = "client_credentials"
                client_id     = $ic.UserName
                client_secret = $ic.GetNetworkCredential().Password
                scope         = "https://graph.microsoft.com/.default"
            } -ErrorAction Stop
        $ih = @{ Authorization = "Bearer $($itk.access_token)" }
        $IG = "https://graph.microsoft.com/v1.0/deviceManagement"
        $IB = "https://graph.microsoft.com/beta/deviceManagement"   # Endpoint analytics / reports are beta-only

        # 1) Every managed device, with its problems worked out here
        $script:intuneRaw = $null
        Invoke-IntuneSection "Devices" {
            $sel = "id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,complianceState,lastSyncDateTime," +
                   "enrolledDateTime,model,manufacturer,serialNumber,isEncrypted,freeStorageSpaceInBytes,totalStorageSpaceInBytes," +
                   "jailBroken,managedDeviceOwnerType,managementAgent"
            $raw = @(Get-GraphPaged -Url "$IG/managedDevices?`$select=$sel&`$top=999" -Headers $ih -Max 20000)
            $script:intuneRaw = $raw

            # Which compliance policies each non-compliant device is failing (one call per device, so capped)
            $reasons = @{}
            $nc = @($raw | Where-Object { $_.complianceState -in @("noncompliant", "error", "conflict") } | Select-Object -First $IntuneReasonLookups)
            foreach ($d in $nc) {
                try {
                    $st = Get-GraphPaged -Url "$IG/managedDevices/$($d.id)/deviceCompliancePolicyStates" -Headers $ih -Max 50
                    $reasons[$d.id] = (@($st | Where-Object { $_.state -notin @("compliant", "notApplicable", "unknown") } |
                        ForEach-Object { "$($_.displayName) ($($_.state))" }) -join "; ")
                } catch { }
            }

            $raw | ForEach-Object {
                $d = $_
                $sync = $null
                if ($d.lastSyncDateTime) { try { $sync = [datetime]$d.lastSyncDateTime } catch { } }
                $days = if ($sync) { [math]::Round(((Get-Date) - $sync).TotalDays, 1) } else { $null }

                $freeGB  = if ($d.freeStorageSpaceInBytes)  { [math]::Round([double]$d.freeStorageSpaceInBytes / 1GB, 1) } else { $null }
                $totalGB = if ($d.totalStorageSpaceInBytes) { [math]::Round([double]$d.totalStorageSpaceInBytes / 1GB, 1) } else { $null }
                $freePct = if ($totalGB -and $null -ne $freeGB) { [math]::Round(100 * $freeGB / $totalGB) } else { $null }

                $isWin   = $d.operatingSystem -match 'Windows'
                $release = if ($isWin) { Get-WinRelease $d.osVersion } else { "" }

                $issues = @()
                if ($d.complianceState -in @("noncompliant", "error", "conflict")) {
                    $r = $reasons[$d.id]
                    $issues += "Not compliant" + $(if ($r) { ": $r" } else { "" })
                }
                if ($null -ne $days -and $days -gt $IntuneStaleDays) { $issues += "No check-in for $([math]::Round($days)) days" }
                if ($totalGB -and $null -ne $freeGB -and ($freePct -lt $IntuneLowDiskPct -or $freeGB -lt $IntuneLowDiskGB)) {
                    $issues += "Low disk: $freeGB GB free ($freePct%)"
                }
                if (($isWin -or $d.operatingSystem -match 'mac') -and $d.isEncrypted -eq $false) { $issues += "Not encrypted" }
                if ($d.jailBroken -eq "True") { $issues += "Jailbroken / rooted" }
                if ($release -like "Windows 10*") { $issues += "$release - out of support (Windows 10 ended Oct 2025)" }
                elseif ($release -in @("Windows 11 21H2", "Windows 11 22H2", "Windows 11 23H2")) { $issues += "$release - old Windows 11 version, check it's still supported" }

                [PSCustomObject]@{
                    Name       = $d.deviceName
                    User       = if ($d.userPrincipalName) { $d.userPrincipalName } else { $d.userDisplayName }
                    OS         = $d.operatingSystem
                    Version    = if ($release) { "$release ($($d.osVersion))" } else { $d.osVersion }
                    Compliance = $d.complianceState
                    LastSync   = if ($sync) { $sync.ToString("yyyy-MM-dd HH:mm") } else { "" }
                    DaysSince  = $days
                    Model      = (@($d.manufacturer, $d.model) | Where-Object { $_ }) -join " "
                    Serial     = $d.serialNumber
                    FreeGB     = $freeGB
                    FreePct    = $freePct
                    Encrypted  = $d.isEncrypted
                    Owner      = $d.managedDeviceOwnerType
                    Issues     = $issues -join " | "
                    Link       = "https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/$($d.id)"
                }
            } | Sort-Object Name
        }

        # Monitored devices (from this dashboard) that Intune doesn't manage
        if ($null -ne $script:intuneRaw) {
            $inames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($d in $script:intuneRaw) { if ($d.deviceName) { [void]$inames.Add($d.deviceName) } }
            $IntuneData.NotInIntune = @($AllDevices.Keys | Where-Object { -not $inames.Contains(([string]$_ -split '\.')[0]) } | Sort-Object)
        }

        # 2) Apple push certificate, VPP and ADE (DEP) tokens - Apple devices stop managing when these lapse
        Invoke-IntuneSection "Certs" {
            $rows = @()
            $soon = {
                param($dt)
                if (-not $dt) { return $null }
                try { [math]::Floor(([datetime]$dt - (Get-Date)).TotalDays) } catch { $null }
            }
            try {
                $ap = Invoke-RestMethod -Uri "$IG/applePushNotificationCertificate" -Headers $ih -ErrorAction Stop
                if ($ap.expirationDateTime) {
                    $rows += [PSCustomObject]@{ Item = "Apple MDM push certificate"; Detail = $ap.appleIdentifier
                        Expires = ConvertTo-M365Time $ap.expirationDateTime; DaysLeft = & $soon $ap.expirationDateTime; State = "" }
                }
            } catch { if ((Get-GraphErrorText $_) -notmatch 'NotFound|ResourceNotFound|404') { throw } }

            foreach ($t in @(Get-GraphPaged -Url "https://graph.microsoft.com/v1.0/deviceAppManagement/vppTokens" -Headers $ih)) {
                $rows += [PSCustomObject]@{ Item = "Apple VPP token"; Detail = (@($t.displayName, $t.appleId, $t.organizationName) | Where-Object { $_ } | Select-Object -First 1)
                    Expires = ConvertTo-M365Time $t.expirationDateTime; DaysLeft = & $soon $t.expirationDateTime; State = $t.state }
            }
            try {
                foreach ($t in @(Get-GraphPaged -Url "$IB/depOnboardingSettings" -Headers $ih)) {
                    $rows += [PSCustomObject]@{ Item = "Apple ADE (DEP) token"; Detail = (@($t.tokenName, $t.appleIdentifier) | Where-Object { $_ } | Select-Object -First 1)
                        Expires = ConvertTo-M365Time $t.tokenExpirationDateTime; DaysLeft = & $soon $t.tokenExpirationDateTime
                        State = if ($t.lastSuccessfulSyncDateTime) { "Last sync " + (ConvertTo-M365Time $t.lastSuccessfulSyncDateTime) } else { "" } }
                }
            } catch { }
            $rows | Sort-Object { if ($null -eq $_.DaysLeft) { 99999 } else { $_.DaysLeft } }
        }

        # 3) Endpoint analytics - startup / sign-in performance, blue screens, restarts
        Invoke-IntuneSection "Perf" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsDevicePerformance" -Headers $ih -Max 20000 | ForEach-Object {
                $boot  = [math]::Round(([double]$_.coreBootTimeInMs + [double]$_.groupPolicyBootTimeInMs) / 1000)
                $login = [math]::Round(([double]$_.coreLoginTimeInMs + [double]$_.groupPolicyLoginTimeInMs) / 1000)
                $issues = @()
                if ([int]$_.blueScreenCount -gt 0)        { $issues += "$($_.blueScreenCount) blue screen(s)" }
                if ($boot -gt $IntuneBootWarnSec)          { $issues += "Slow boot ($boot s)" }
                if ($login -gt $IntuneLoginWarnSec)        { $issues += "Slow sign-in ($login s)" }
                if ($_.diskType -match 'hdd')              { $issues += "Spinning hard disk (HDD)" }
                if ([double]$_.averageRestarts -gt 2)      { $issues += "Restarting a lot ($([math]::Round([double]$_.averageRestarts, 1))/day avg)" }
                if ($_.healthStatus -eq "needsAttention" -and -not $issues.Count) { $issues += "Endpoint analytics: needs attention" }
                [PSCustomObject]@{
                    Name        = $_.deviceName
                    Model       = (@($_.manufacturer, $_.model) | Where-Object { $_ }) -join " "
                    Disk        = $_.diskType
                    BootSec     = $boot
                    LoginSec    = $login
                    StartScore  = [math]::Round([double]$_.startupPerformanceScore)
                    BlueScreens = [int]$_.blueScreenCount
                    Restarts    = [int]$_.restartCount
                    Health      = $_.healthStatus
                    Issues      = $issues -join " | "
                }
            } | Sort-Object @{ e = "BlueScreens"; d = $true }, @{ e = "BootSec"; d = $true }
        }

        # 4) Endpoint analytics - battery health
        Invoke-IntuneSection "Battery" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsBatteryHealthDevicePerformance" -Headers $ih -Max 20000 |
                Where-Object { ([double]$_.maxCapacityPercentage -gt 0 -and [double]$_.maxCapacityPercentage -lt $IntuneBatteryWarnPct) -or $_.healthStatus -eq "needsAttention" } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name       = $_.deviceName
                        Model      = (@($_.manufacturer, $_.model) | Where-Object { $_ }) -join " "
                        Capacity   = [math]::Round([double]$_.maxCapacityPercentage)
                        RuntimeMin = [math]::Round([double]$_.estimatedRuntimeInMinutes)
                        AgeDays    = [int]$_.batteryAgeInDays
                        Score      = [math]::Round([double]$_.deviceBatteryHealthScore)
                    }
                } | Sort-Object Capacity
        }

        # 5) Endpoint analytics - apps that crash or hang most
        Invoke-IntuneSection "AppCrash" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsAppHealthApplicationPerformance" -Headers $ih -Max 5000 |
                Where-Object { [int]$_.appCrashCount -gt 0 -or [int]$_.appHangCount -gt 0 } |
                Sort-Object @{ e = { [int]$_.appCrashCount + [int]$_.appHangCount }; d = $true } |
                Select-Object -First 15 |
                ForEach-Object {
                    [PSCustomObject]@{
                        App       = if ($_.appDisplayName) { $_.appDisplayName } else { $_.appName }
                        Publisher = $_.appPublisher
                        Crashes   = [int]$_.appCrashCount
                        Hangs     = [int]$_.appHangCount
                        Devices   = [int]$_.activeDeviceCount
                        MTTF      = [int]$_.meanTimeToFailureInMinutes
                    }
                }
        }

        # ---- HARDWARE & PERFORMANCE (Endpoint analytics, beta) ----

        # 5a) Overall device health scores - worst devices first
        Invoke-IntuneSection "Scores" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsDeviceScores" -Headers $ih -Max 20000 | ForEach-Object {
                [PSCustomObject]@{
                    Name      = $_.deviceName
                    Model     = (@($_.manufacturer, $_.model) | Where-Object { $_ }) -join " "
                    Overall   = [math]::Round([double]$_.endpointAnalyticsScore)
                    Startup   = [math]::Round([double]$_.startupPerformanceScore)
                    AppRel    = [math]::Round([double]$_.appReliabilityScore)
                    Battery   = [math]::Round([double]$_.batteryHealthScore)
                    Health    = $_.healthStatus
                }
            } | Sort-Object Overall
        }

        # 5b) Resource performance - CPU / memory maxed out (underpowered or overloaded devices)
        Invoke-IntuneSection "Resource" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsResourcePerformance" -Headers $ih -Max 20000 | ForEach-Object {
                $cpu = [math]::Round([double]$_.cpuSpikeTimePercentage, 1)
                $ram = [math]::Round([double]$_.ramSpikeTimePercentage, 1)
                $gb  = if ($_.totalRamInMB) { [math]::Round([double]$_.totalRamInMB / 1024) } else { $null }
                $issues = @()
                if ($cpu -gt $IntuneSpikeWarnPct) { $issues += "CPU maxed out $cpu% of the time" }
                if ($ram -gt $IntuneSpikeWarnPct) { $issues += "Memory maxed out $ram% of the time" }
                if ($gb -and $gb -lt $IntuneMinRamGB) { $issues += "Only $gb GB memory" }
                if ($_.diskType -match 'hdd') { $issues += "Spinning hard disk (HDD)" }
                [PSCustomObject]@{
                    Name     = $_.deviceName
                    Model    = (@($_.manufacturer, $_.model) | Where-Object { $_ }) -join " "
                    CPU      = (@($_.cpuDisplayName, $(if ($_.totalProcessorCoreCount) { "$($_.totalProcessorCoreCount) cores" })) | Where-Object { $_ }) -join ", "
                    RamGB    = $gb
                    CpuSpike = $cpu
                    RamSpike = $ram
                    Score    = [math]::Round([double]$_.deviceResourcePerformanceScore)
                    Issues   = $issues -join " | "
                }
            } | Sort-Object @{ e = { [math]::Max($_.CpuSpike, $_.RamSpike) }; d = $true }
        }

        # 5c) Windows 11 hardware readiness - which devices can't upgrade, and why
        Invoke-IntuneSection "Readiness" {
            $checks = [ordered]@{
                tpmCheckFailed                = "TPM 2.0"
                secureBootCheckFailed         = "Secure Boot"
                processorFamilyCheckFailed    = "CPU not supported"
                processor64BitCheckFailed     = "CPU not 64-bit"
                processorCoreCountCheckFailed = "Too few CPU cores"
                processorSpeedCheckFailed     = "CPU too slow"
                ramCheckFailed                = "Under 4 GB RAM"
                storageCheckFailed            = "Under 64 GB storage"
                osCheckFailed                 = "OS version"
            }
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices" -Headers $ih -Max 20000 |
                Where-Object { [string]$_.osVersion -notmatch '^10\.0\.2[2-9]\d{3}' } |   # already on Windows 11
                ForEach-Object {
                    $d = $_
                    $failed = @($checks.Keys | Where-Object { $d.$_ -eq $true } | ForEach-Object { $checks[$_] })
                    [PSCustomObject]@{
                        Name        = $d.deviceName
                        Model       = (@($d.manufacturer, $d.model) | Where-Object { $_ }) -join " "
                        OS          = (@($d.osDescription, $d.osVersion) | Where-Object { $_ }) -join " "
                        Eligibility = $d.upgradeEligibility
                        Failed      = $failed -join ", "
                        Serial      = $d.serialNumber
                    }
                } | Sort-Object @{ e = { if ($_.Eligibility -eq "notCapable") { 0 } elseif ($_.Eligibility -eq "capable") { 1 } else { 2 } } }, Name
        }

        # 5d) Scores by model - helps plan replacements
        Invoke-IntuneSection "Models" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsModelScores" -Headers $ih -Max 2000 | ForEach-Object {
                [PSCustomObject]@{
                    Model   = (@($_.manufacturer, $_.model) | Where-Object { $_ }) -join " "
                    Devices = [int]$_.modelDeviceCount
                    Overall = [math]::Round([double]$_.endpointAnalyticsScore)
                    Startup = [math]::Round([double]$_.startupPerformanceScore)
                    AppRel  = [math]::Round([double]$_.appReliabilityScore)
                    Battery = [math]::Round([double]$_.batteryHealthScore)
                    Health  = $_.healthStatus
                }
            } | Where-Object { $_.Devices -gt 0 } | Sort-Object Overall
        }

        # 5e) Programs that slow down boot the most
        Invoke-IntuneSection "StartupProc" {
            Get-GraphPaged -Url "$IB/userExperienceAnalyticsDeviceStartupProcessPerformance" -Headers $ih -Max 5000 |
                Sort-Object @{ e = { [double]$_.totalImpactInMs }; d = $true } |
                Select-Object -First 10 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Process   = $_.processName
                        Product   = $_.productName
                        Publisher = $_.publisher
                        Devices   = [int]$_.deviceCount
                        MedianSec = [math]::Round([double]$_.medianImpactInMs / 1000, 1)
                    }
                }
        }

        # 6) Apps failing to install
        Invoke-IntuneSection "AppFail" {
            Invoke-IntuneReport -Url "$IB/reports/getAppsInstallSummaryReport" -Headers $ih -Body @{ skip = 0; top = 500 } |
                ForEach-Object {
                    $failed = [int]$(if ($_.FailedDeviceCount) { $_.FailedDeviceCount } else { 0 })
                    if ($failed -gt 0) {
                        [PSCustomObject]@{
                            App       = $_.DisplayName
                            Publisher = $_.Publisher
                            Platform  = $_.Platform
                            Failed    = $failed
                            FailedPct = [math]::Round([double]$_.FailedDevicePercentage)
                            Installed = [int]$_.InstalledDeviceCount
                            Pending   = [int]$_.PendingInstallDeviceCount
                            Link      = if ($_.ApplicationId) { "https://intune.microsoft.com/#view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/$($_.ApplicationId)" } else { "" }
                        }
                    }
                } | Sort-Object @{ e = "Failed"; d = $true } | Select-Object -First 25
        }

        # 7) Configuration profiles and compliance policies with devices in error / conflict / not compliant
        Invoke-IntuneSection "Policies" {
            $out = @()
            foreach ($kind in @(@{ Path = "deviceConfigurations"; Type = "Configuration profile" },
                                @{ Path = "deviceCompliancePolicies"; Type = "Compliance policy" })) {
                foreach ($p in @(Get-GraphPaged -Url "$IG/$($kind.Path)?`$select=id,displayName" -Headers $ih -Max 300)) {
                    try {
                        $o = Invoke-RestMethod -Uri "$IG/$($kind.Path)/$($p.id)/deviceStatusOverview" -Headers $ih -ErrorAction Stop
                        $bad = [int]$o.errorCount + [int]$o.failedCount + [int]$o.conflictCount
                        if ($bad -gt 0) {
                            $out += [PSCustomObject]@{
                                Policy    = $p.displayName
                                Type      = $kind.Type
                                Errors    = [int]$o.errorCount + [int]$o.failedCount
                                Conflicts = [int]$o.conflictCount
                                Success   = [int]$o.successCount
                                Pending   = [int]$o.pendingCount
                            }
                        }
                    } catch { }
                }
            }
            $out | Sort-Object @{ e = { $_.Errors + $_.Conflicts }; d = $true }
        }

        Write-Host "Intune: data fetched" -ForegroundColor Cyan
    }
    catch {
        $IntuneData.Error = "Could not fetch Intune data: $(Get-GraphErrorText $_)"
        Write-Host $IntuneData.Error -ForegroundColor Yellow
    }
}

$IntuneDataJson = (ConvertTo-Json -InputObject $IntuneData -Depth 6 -Compress) -replace '<', ('\' + 'u003c')

# ================== NETWORK SWITCHES ==================
# Pings every switch and checks which management ports are open. Where SNMP
# is switched on it also reads the model, uptime, every port's status and
# speed, port errors and LLDP neighbours. New switches on
# $SwitchDiscoverSubnets are found automatically. The last run's counters are
# kept in $SwitchStatePath so new errors and restarts can be worked out
# hour to hour.
#
# SNMP uses the olePrn.OleSNMP component built into Windows, so there's
# nothing to install. If it's missing, the tab falls back to ping and port
# checks only.
$SwitchData = [ordered]@{
    Error           = ""
    FetchedAt       = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    SnmpAvailable   = $false
    UsingPublic     = ($SwitchCommunity -eq "public")
    Subnets         = @($SwitchDiscoverSubnets | ForEach-Object { "$_.0/24" })
    LatencyWarnMs   = $SwitchLatencyWarnMs
    RebootWarnHours = $SwitchRebootWarnHours
    ForgetDays      = $SwitchForgetDays
    Switches        = @()
}

# One SNMP value, or $null if the switch doesn't answer / doesn't have it
function Get-SwSnmp {
    param($Snmp, [string]$Oid)
    try { $v = $Snmp.Get($Oid); if ($null -ne $v) { return $v } } catch { }
    return $null
}

# A whole SNMP table column as index -> value. $IndexParts is how many numbers
# on the end of each OID make up the row index (1 for the interface table, 3 for LLDP).
function Get-SwSnmpColumn {
    param($Snmp, [string]$Oid, [int]$IndexParts = 1)
    $map = @{}
    $r = $null
    try { $r = $Snmp.GetTree($Oid) } catch { return $map }
    if ($null -eq $r -or $r.Rank -ne 2) { return $map }
    $byCol = ($r.GetLength(0) -eq 2)
    $n = if ($byCol) { $r.GetLength(1) } else { $r.GetLength(0) }
    for ($i = 0; $i -lt $n; $i++) {
        $name  = [string]$(if ($byCol) { $r[0, $i] } else { $r[$i, 0] })
        $value = $(if ($byCol) { $r[1, $i] } else { $r[$i, 1] })
        $parts = $name -split '\.'
        if ($parts.Count -lt $IndexParts) { continue }
        $key = ($parts[($parts.Count - $IndexParts)..($parts.Count - 1)]) -join '.'
        $map[$key] = $value
    }
    return $map
}

# Printable text only (SNMP strings can carry control characters)
function Get-SwText($v) {
    if ($null -eq $v) { return "" }
    return (([string]$v -replace '[\r\n\t]+', ' ') -replace '[^\x20-\x7E]', '').Trim()
}

function Test-SwTcp([string]$Ip, [int]$Port, [int]$TimeoutMs = 700) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Ip, $Port, $null, $null)
        return ($iar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected)
    }
    catch { return $false }
    finally { $c.Close() }
}

function Test-SwPing([string]$Ip, [int]$Count = 3) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $times = @()
    for ($i = 0; $i -lt $Count; $i++) {
        try { $r = $p.Send($Ip, 1000); if ($r.Status -eq 'Success') { $times += $r.RoundtripTime } } catch { }
    }
    [PSCustomObject]@{
        Up      = ($times.Count -gt 0)
        LossPct = [math]::Round(100 * ($Count - $times.Count) / $Count)
        AvgMs   = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
    }
}

function Format-SwUptime($Sec) {
    if ($null -eq $Sec) { return "" }
    $t = [TimeSpan]::FromSeconds([double]$Sec)
    if ($t.TotalDays -ge 1)  { return "{0}d {1}h" -f [math]::Floor($t.TotalDays), $t.Hours }
    if ($t.TotalHours -ge 1) { return "{0}h {1}m" -f $t.Hours, $t.Minutes }
    return "{0}m" -f [math]::Max(1, $t.Minutes)
}

function Get-SwIso($v) {
    if ($null -eq $v -or $v -eq "") { return $null }
    if ($v -is [datetime]) { return $v.ToString("s") }
    return [string]$v
}

try {
    $snmpOk = $false
    try { $null = New-Object -ComObject olePrn.OleSNMP -ErrorAction Stop; $snmpOk = $true }
    catch { Write-Host "  Switches: SNMP (olePrn.OleSNMP) isn't available on this server - ping and port checks only" -ForegroundColor Yellow }
    $SwitchData.SnmpAvailable = $snmpOk

    # Last run's state
    $swState = @{}
    if (Test-Path $SwitchStatePath) {
        try {
            $raw = Get-Content $SwitchStatePath -Raw | ConvertFrom-Json
            foreach ($p in $raw.PSObject.Properties) { $swState[$p.Name] = $p.Value }
        }
        catch { Write-Host "  Switches: couldn't read $SwitchStatePath - starting fresh" -ForegroundColor Yellow }
    }

    # Switches to check: the configured list, then ones found on earlier runs
    $swTargets = [ordered]@{}   # IP -> @{ Name; Source }
    foreach ($s in $SwitchList) {
        if ($s.IP) {
            $swTargets[[string]$s.IP] = @{ Name = $(if ($s.Name) { [string]$s.Name } else { [string]$s.IP }); Source = "Configured" }
        }
    }
    foreach ($ip in @($swState.Keys)) {
        $ps = $swState[$ip]
        if ($ps.Source -ne "Discovered" -or $swTargets.Contains($ip) -or $SwitchIgnore -contains $ip) { continue }
        $ds = Get-SwIso $ps.DownSince
        if ($ds) {
            try { if (((Get-Date) - [datetime]$ds).TotalDays -gt $SwitchForgetDays) { continue } } catch { }
        }
        $swTargets[$ip] = @{ Name = [string]$ps.Name; Source = "Discovered" }
    }

    # Look for new switches: sweep each /24, then ask every responder over SNMP
    # whether it's a layer-2 device (sysServices bit 2 - set on switches, not on
    # PCs, servers or printers)
    if ($snmpOk) {
        foreach ($net in $SwitchDiscoverSubnets) {
            $alive = New-Object 'System.Collections.Generic.HashSet[string]'
            $tasks = @(1..254 | ForEach-Object { (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$net.$_", 500) })
            try { [Threading.Tasks.Task]::WaitAll($tasks) } catch { }
            foreach ($t in $tasks) {
                if ($t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { [void]$alive.Add([string]$t.Result.Address) }
            }
            # Devices that ignore ping but answered ARP (only works on this server's own subnet)
            try {
                foreach ($n in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
                    if ($n.IPAddress -like "$net.*" -and $n.State -in @('Reachable', 'Stale', 'Delay', 'Probe')) { [void]$alive.Add($n.IPAddress) }
                }
            } catch { }

            foreach ($ip in $alive) {
                if ($swTargets.Contains($ip) -or $SwitchIgnore -contains $ip) { continue }
                $s = New-Object -ComObject olePrn.OleSNMP
                try {
                    $s.Open($ip, $SwitchCommunity, 0, 600)
                    $svc = (Get-SwSnmp $s ".1.3.6.1.2.1.1.7.0") -as [int]
                    if ($null -ne $svc -and ($svc -band 2)) {
                        $nm = Get-SwText (Get-SwSnmp $s ".1.3.6.1.2.1.1.5.0")
                        $swTargets[$ip] = @{ Name = $(if ($nm) { $nm } else { $ip }); Source = "Discovered" }
                        Write-Host "  Switches: found $ip ($nm)" -ForegroundColor DarkCyan
                    }
                }
                catch { }
                finally { try { $s.Close() } catch { } }
            }
        }
    }

    $operText  = @{ 1 = "Up"; 2 = "Down"; 3 = "Testing"; 4 = "Unknown"; 5 = "Dormant"; 6 = "Not present"; 7 = "Down" }
    $physTypes = @(6, 62, 69, 117, 161)   # Ethernet ports and LAGs - skips VLAN interfaces, loopbacks etc.
    $changeSec = $SwitchChangeMinutes * 60
    $nowIso    = (Get-Date).ToString("s")
    $newState  = @{}
    $swRows    = @()

    foreach ($ip in @($swTargets.Keys)) {
        $tg   = $swTargets[$ip]
        $prev = $swState[$ip]
        $ping = Test-SwPing $ip

        $row = [ordered]@{
            Name = $tg.Name; IP = $ip; Source = $tg.Source
            Up = $ping.Up; LossPct = $ping.LossPct; LatencyMs = $ping.AvgMs
            Snmp = $false; SysName = ""; Descr = ""; Location = ""; Contact = ""
            UptimeSec = $null; Uptime = ""; Rebooted = $false
            Mgmt = @(); PortsTotal = 0; PortsUp = 0; PortsDisabled = 0; ErrPorts = 0; ChangedPorts = 0
            DownSince = ""; Issues = ""; Interfaces = @(); Neighbours = @()
        }
        $issues  = @()
        $ifState = $null
        $ifs     = @()

        # ---- SNMP ----
        if ($snmpOk) {
            $s = New-Object -ComObject olePrn.OleSNMP
            try {
                $s.Open($ip, $SwitchCommunity, 1, $SwitchSnmpTimeoutMs)
                $descr = Get-SwSnmp $s ".1.3.6.1.2.1.1.1.0"
                if ($null -ne $descr) {
                    $row.Snmp = $true
                    $row.Up   = $true   # answering SNMP counts as up, even if ping is blocked
                    $d = Get-SwText $descr
                    if ($d.Length -gt 200) { $d = $d.Substring(0, 200) + "..." }
                    $row.Descr    = $d
                    $row.SysName  = Get-SwText (Get-SwSnmp $s ".1.3.6.1.2.1.1.5.0")
                    $row.Contact  = Get-SwText (Get-SwSnmp $s ".1.3.6.1.2.1.1.4.0")
                    $row.Location = Get-SwText (Get-SwSnmp $s ".1.3.6.1.2.1.1.6.0")
                    if ($tg.Source -eq "Discovered" -and $row.SysName) { $row.Name = $row.SysName }

                    $ticks = (Get-SwSnmp $s ".1.3.6.1.2.1.1.3.0") -as [double]
                    if ($null -ne $ticks) {
                        $row.UptimeSec = [math]::Round($ticks / 100)
                        $row.Uptime    = Format-SwUptime $row.UptimeSec
                        if ($prev -and $null -ne $prev.UptimeSec) {
                            $pu = [double]$prev.UptimeSec
                            # sysUpTime wraps after ~497 days, so a drop from near there isn't a restart
                            if ($row.UptimeSec -lt $pu -and $pu -lt 42000000) { $row.Rebooted = $true }
                        }
                    }

                    # Interfaces
                    $types   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.3"      # ifType
                    $descrs  = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.2"      # ifDescr
                    $names   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.31.1.1.1.1"   # ifName
                    $alias   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.31.1.1.1.18"  # ifAlias (port description)
                    $admin   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.7"      # ifAdminStatus
                    $oper    = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.8"      # ifOperStatus
                    $lastChg = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.9"      # ifLastChange
                    $hspeed  = Get-SwSnmpColumn $s ".1.3.6.1.2.1.31.1.1.1.15"  # ifHighSpeed (Mbps)
                    $speed   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.5"      # ifSpeed (bps)
                    $inErr   = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.14"     # ifInErrors
                    $outErr  = Get-SwSnmpColumn $s ".1.3.6.1.2.1.2.2.1.20"     # ifOutErrors

                    $ifState = @{}
                    foreach ($idx in @($oper.Keys | Sort-Object { $_ -as [int] })) {
                        $ty = $types[$idx] -as [int]
                        if ($types.Count -and $physTypes -notcontains $ty) { continue }
                        $op   = $oper[$idx] -as [int]
                        $ad   = $admin[$idx] -as [int]
                        $mbps = $hspeed[$idx] -as [double]
                        if (-not $mbps) { $sp = $speed[$idx] -as [double]; if ($sp) { $mbps = [math]::Round($sp / 1000000) } }
                        $ie = $inErr[$idx] -as [double]
                        $oe = $outErr[$idx] -as [double]

                        # New errors since the last run (not across a restart - counters reset)
                        $pi = $null
                        if ($prev -and $prev.Ifs) { $pi = $prev.Ifs.$idx }
                        $newErr = $null
                        if ($pi -and -not $row.Rebooted) {
                            $dIn  = if ($null -ne $ie -and $ie -ge [double]$pi.In)  { $ie - [double]$pi.In }  else { 0 }
                            $dOut = if ($null -ne $oe -and $oe -ge [double]$pi.Out) { $oe - [double]$pi.Out } else { 0 }
                            $newErr = $dIn + $dOut
                        }

                        # When the port last went up or down
                        $lc  = $lastChg[$idx] -as [double]
                        $ago = $null
                        if ($null -ne $ticks -and $lc -gt 0 -and $ticks -ge $lc) { $ago = [math]::Round(($ticks - $lc) / 100) }
                        $changed = ($null -ne $ago -and $ago -lt $changeSec -and $row.UptimeSec -gt $changeSec)
                        $lcText  = if ($null -ne $ago) { (Format-SwUptime $ago) + " ago" } elseif ($null -ne $ticks) { "Since restart" } else { "" }

                        $nm = Get-SwText $names[$idx]
                        if (-not $nm) { $nm = Get-SwText $descrs[$idx] }

                        $ifs += [PSCustomObject]@{
                            Index      = $idx -as [int]
                            Name       = $nm
                            Descr      = Get-SwText $descrs[$idx]
                            Alias      = Get-SwText $alias[$idx]
                            Admin      = if ($ad -eq 2) { "Disabled" } else { "Enabled" }
                            Oper       = if ($ad -eq 2) { "Disabled" } elseif ($null -ne $op -and $operText.ContainsKey($op)) { $operText[$op] } else { "Unknown" }
                            SpeedMbps  = $mbps
                            Slow       = ($op -eq 1 -and $mbps -gt 0 -and $mbps -lt 1000)
                            InErr      = $ie
                            OutErr     = $oe
                            NewErr     = $newErr
                            LastChange = $lcText
                            Changed    = [bool]$changed
                            IsLag      = ($ty -eq 161)
                            Uplink     = $false
                        }
                        $ifState[[string]$idx] = @{ In = $ie; Out = $oe; Uplink = $false }
                    }

                    # LLDP - what's plugged into each port (other switches, APs, phones, servers that advertise themselves)
                    $remName = Get-SwSnmpColumn $s ".1.0.8802.1.1.2.1.4.1.1.9" 3   # lldpRemSysName
                    if ($remName.Count) {
                        $remDesc = Get-SwSnmpColumn $s ".1.0.8802.1.1.2.1.4.1.1.8" 3   # lldpRemPortDesc
                        $remId   = Get-SwSnmpColumn $s ".1.0.8802.1.1.2.1.4.1.1.7" 3   # lldpRemPortId
                        $locDesc = Get-SwSnmpColumn $s ".1.0.8802.1.1.2.1.3.7.1.4"     # lldpLocPortDesc
                        $nbrs = @()
                        foreach ($k in $remName.Keys) {
                            $lp    = ($k -split '\.')[1]
                            $local = Get-SwText $locDesc[$lp]
                            $port  = $null
                            if ($local) { $port = $ifs | Where-Object { $_.Name -eq $local -or $_.Descr -eq $local } | Select-Object -First 1 }
                            if (-not $port) { $port = $ifs | Where-Object { $_.Index -eq ($lp -as [int]) } | Select-Object -First 1 }
                            if ($port) { $port.Uplink = $true }
                            $rp = Get-SwText $remDesc[$k]
                            if (-not $rp) { $rp = Get-SwText $remId[$k] }
                            $nbrs += [PSCustomObject]@{
                                LocalPort     = if ($port) { $port.Name } elseif ($local) { $local } else { "Port $lp" }
                                Neighbour     = Get-SwText $remName[$k]
                                NeighbourPort = $rp
                            }
                        }
                        $row.Neighbours = @($nbrs | Sort-Object LocalPort)
                    }

                    # Remember which ports led to another device, so a link that's gone
                    # down (and so lost its LLDP neighbour) is still known to be one
                    foreach ($i in $ifs) {
                        $pi = $null
                        if ($prev -and $prev.Ifs) { $pi = $prev.Ifs.([string]$i.Index) }
                        if (-not $i.Uplink -and $pi -and $pi.Uplink -and $i.Oper -ne "Up" -and $i.Admin -ne "Disabled") { $i.Uplink = $true }
                        $ifState[[string]$i.Index].Uplink = [bool]$i.Uplink
                    }

                    $phys = @($ifs | Where-Object { -not $_.IsLag })
                    $row.PortsTotal    = $phys.Count
                    $row.PortsUp       = @($phys | Where-Object { $_.Oper -eq "Up" }).Count
                    $row.PortsDisabled = @($phys | Where-Object { $_.Admin -eq "Disabled" }).Count
                    $row.ErrPorts      = @($ifs | Where-Object { $_.NewErr -gt 0 }).Count
                    $row.ChangedPorts  = @($ifs | Where-Object { $_.Changed }).Count
                    $row.Interfaces    = @($ifs)
                }
            }
            catch { Write-Host "  Switch $ip : SNMP error - $($_.Exception.Message)" -ForegroundColor DarkGray }
            finally { try { $s.Close() } catch { } }
        }

        # ---- Management ports ----
        if ($row.Up) {
            $mgmt = @()
            foreach ($p in @(@{ P = 22; N = "SSH" }, @{ P = 23; N = "Telnet" }, @{ P = 80; N = "HTTP" }, @{ P = 443; N = "HTTPS" })) {
                if (Test-SwTcp $ip $p.P) { $mgmt += $p.N }
            }
            $row.Mgmt = $mgmt
        }

        # ---- Problems ----
        $downSince = $null
        if (-not $row.Up) {
            $downSince = Get-SwIso $(if ($prev) { $prev.DownSince } else { $null })
            if (-not $downSince) { $downSince = $nowIso }
            $dsd = [datetime]$downSince
            $row.DownSince = $dsd.ToString("yyyy-MM-dd HH:mm")
            $gone = ((Get-Date) - $dsd).TotalSeconds
            $issues += if ($gone -lt 3600) { "Offline - not answering ping or SNMP" } else { "Offline for " + (Format-SwUptime $gone) + " (since " + $row.DownSince + ")" }
        }
        else {
            if ($null -ne $ping.AvgMs -and $ping.AvgMs -gt $SwitchLatencyWarnMs) { $issues += "Slow to respond ($($ping.AvgMs) ms)" }
            if ($ping.Up -and $ping.LossPct -gt 0) { $issues += "$($ping.LossPct)% packet loss" }
            if ($row.Rebooted) { $issues += "Restarted since the last check (up $($row.Uptime))" }
            elseif ($null -ne $row.UptimeSec -and $row.UptimeSec -lt $SwitchRebootWarnHours * 3600) { $issues += "Restarted $($row.Uptime) ago" }
            if ($row.ErrPorts) { $issues += "$($row.ErrPorts) port(s) with new errors" }
            $linkDown = @($ifs | Where-Object { $_.Uplink -and $_.Admin -ne "Disabled" -and $_.Oper -ne "Up" } | ForEach-Object { $_.Name })
            if ($linkDown.Count) { $issues += "Link to another network device is down: " + ($linkDown -join ", ") }
            $linkFlap = @($ifs | Where-Object { $_.Uplink -and $_.Changed -and $_.Oper -eq "Up" } | ForEach-Object { $_.Name })
            if ($linkFlap.Count) { $issues += "Link to another network device dropped recently: " + ($linkFlap -join ", ") }
            if ($row.Mgmt -contains "Telnet") { $issues += "Telnet is enabled (sends passwords unencrypted)" }
        }
        $row.Issues = $issues -join " | "

        $newState[$ip] = [ordered]@{
            Name      = $row.Name
            Source    = $row.Source
            UptimeSec = if ($null -ne $row.UptimeSec) { $row.UptimeSec } elseif ($prev) { $prev.UptimeSec } else { $null }
            DownSince = $downSince
            Ifs       = if ($null -ne $ifState) { $ifState } elseif ($prev) { $prev.Ifs } else { $null }
        }

        $swRows += [PSCustomObject]$row
        Write-Host ("  Switch {0,-15} {1}" -f $ip, $(if (-not $row.Up) { "OFFLINE" } elseif ($row.Issues) { $row.Issues } else { "OK" })) -ForegroundColor DarkCyan
    }

    try {
        $stateDir = Split-Path $SwitchStatePath -Parent
        if ($stateDir -and !(Test-Path $stateDir)) { New-Item -Path $stateDir -ItemType Directory -Force | Out-Null }
        ConvertTo-Json -InputObject $newState -Depth 6 | Set-Content -Path $SwitchStatePath -Encoding UTF8
    }
    catch { Write-Host "  Switches: couldn't save $SwitchStatePath : $($_.Exception.Message)" -ForegroundColor Yellow }

    $SwitchData.Switches = @($swRows)
    Write-Host "Network switches: $($swRows.Count) checked" -ForegroundColor Cyan
}
catch {
    $SwitchData.Error = "Could not check the network switches: $($_.Exception.Message)"
    Write-Host $SwitchData.Error -ForegroundColor Yellow
}

$SwitchDataJson = (ConvertTo-Json -InputObject $SwitchData -Depth 7 -Compress) -replace '<', ('\' + 'u003c')

# ================== HTML ==================
$FullHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>IT Monitoring Dashboard - All Devices ($env:COMPUTERNAME)</title>

<style>
body {
    background:#fafafa;
    color:#1a1a1a;
    font-family:Segoe UI;
    margin:20px;
}

.card {
    background:#ffffff;
    padding:15px;
    margin-top:20px;
    border-radius:12px;
    border:1px solid #e5e5e5;
    box-shadow:0 2px 6px rgba(0,0,0,0.05);
    overflow-x:auto;
}

.halfRow {
    display:flex;
    gap:20px;
    margin-top:20px;
}

.halfRow .card {
    flex:1;
    min-width:0;
    margin-top:0;
}

@media (max-width: 800px) {
    .halfRow {
        flex-direction:column;
    }
}

.statusBadge {
    display:inline-block;
    padding:10px 18px;
    border-radius:10px;
    font-weight:600;
    font-size:18px;
    background:#f0f0f0;
    color:#1a1a1a;
    margin-bottom:12px;
}

.green { background:#4CCB5F; color:white; }
.orange { background:#FFB347; color:white; }
.red { background:#FF6B6B; color:white; }

.deviceBtn {
    padding:10px 16px;
    background:#ffffff;
    border:1px solid #d0d0d0;
    border-radius:8px;
    cursor:pointer;
    white-space:nowrap;
    color:#1a1a1a;
    font-weight:600;
    transition:0.2s;
}

.deviceBtn:hover {
    background:#f0f0f0;
}

.deviceBtn.active {
    background:#1a1a1a;
    color:white;
    border-color:#1a1a1a;
}

.deviceBtn .lastSeen {
    display:block;
    font-size:11px;
    font-weight:400;
    margin-top:4px;
}

.freshness-ok { color:#1a7d2c; }
.deviceBtn.active .freshness-ok { color:#8fe3a3; }
.freshness-warn { color:#b06a00; }
.deviceBtn.active .freshness-warn { color:#ffcb80; }
.freshness-stale { color:#c92a2a; }
.deviceBtn.active .freshness-stale { color:#ff9d9d; }
.freshness-unknown { color:#6c6c6c; }
.deviceBtn.active .freshness-unknown { color:#c7c7c7; }

table {
    width:100%;
    border-collapse:collapse;
}

th {
    background:#f0f0f0;
    color:#1a1a1a;
    font-weight:600;
}

th, td {
    padding:8px;
    border-bottom:1px solid #e0e0e0;
}

th, td {
    text-align:left;
    white-space:nowrap;
}

/* Top-level tabs */
.tabBar {
    display:flex;
    gap:6px;
    margin:10px 0 20px;
    border-bottom:1px solid #e0e0e0;
    flex-wrap:wrap;
}

.tabBtn {
    padding:10px 18px;
    cursor:pointer;
    font-weight:600;
    font-size:15px;
    font-family:inherit;
    border:none;
    background:none;
    color:#6c6c6c;
    border-bottom:3px solid transparent;
    margin-bottom:-1px;
}

.tabBtn:hover { color:#1a1a1a; }
.tabBtn.active { color:#1a1a1a; border-bottom-color:#1a1a1a; }

.filterBox {
    padding:8px 10px;
    border:1px solid #d0d0d0;
    border-radius:8px;
    font-family:inherit;
    margin-bottom:10px;
    width:300px;
    max-width:100%;
}

</style>

</head>

<body>

<h1>IT Monitoring Dashboard - All Devices ($env:COMPUTERNAME)</h1>
<p>Updated: $(Get-Date)</p>

<div class="tabBar">
  <button class="tabBtn active" data-tab="tabDevices">Servers</button>
  <button class="tabBtn" data-tab="tabSwitches">Network Switches<span id="swTabCount"></span></button>
  <button class="tabBtn" data-tab="tabM365">Microsoft 365<span id="m365TabCount"></span></button>
  <button class="tabBtn" data-tab="tabDefender">Defender<span id="defTabCount"></span></button>
  <button class="tabBtn" data-tab="tabIntune">Intune<span id="itTabCount"></span></button>
</div>

<!-- ================= SERVERS TAB ================= -->
<div id="tabDevices">

<div id="deviceList" style="display:flex; gap:10px; overflow-x:auto; margin-bottom:15px;"></div>

<h1 id="hostHeading">Host Performance Stats</h1>
<p id="lastSeenInfo" style="margin-top:-8px; margin-bottom:15px; font-size:14px;"></p>

<div class="halfRow">
  <div class="card" id="cpuSection"></div>
  <div class="card" id="memSection"></div>
</div>
<div class="halfRow">
  <div class="card" id="backupSection"></div>
  <div class="card" id="diskSection"></div>
</div>

<div class="card" id="eventTable"></div>
<div class="card" id="updateTable"></div>

</div>

<!-- ================= NETWORK SWITCHES TAB ================= -->
<div id="tabSwitches" style="display:none"></div>

<!-- ================= MICROSOFT 365 TAB ================= -->
<div id="tabM365" style="display:none"></div>

<!-- ================= DEFENDER TAB ================= -->
<div id="tabDefender" style="display:none"></div>

<!-- ================= INTUNE TAB ================= -->
<div id="tabIntune" style="display:none"></div>

<script>

// ✅ Every device's history, keyed by device name
const allDevices = $AllDevicesJson;
const deviceNames = Object.keys(allDevices).sort();

// ✅ Network switch data, checked when this dashboard was built
const sw = $SwitchDataJson;
const swView = document.getElementById("tabSwitches");

// ✅ Microsoft 365 data, fetched from Microsoft Graph when this dashboard was built
const m365 = $M365DataJson;
const m365View = document.getElementById("tabM365");

// ✅ Defender data, fetched from Microsoft Graph / Defender for Endpoint when this dashboard was built
const def = $DefDataJson;
const defView = document.getElementById("tabDefender");

// ✅ Intune data, fetched from Microsoft Graph when this dashboard was built
const intune = $IntuneDataJson;
const itView = document.getElementById("tabIntune");

let currentDevice = deviceNames[0];
let currentHistory = [];

const deviceList = document.getElementById("deviceList");
const lastSeenInfo = document.getElementById("lastSeenInfo");

const cpuSection = document.getElementById("cpuSection");
const memSection = document.getElementById("memSection");
const backupSection = document.getElementById("backupSection");
const diskSection = document.getElementById("diskSection");

const eventTable = document.getElementById("eventTable");
const updateTable = document.getElementById("updateTable");

function parseJsonField(field){

    if (!field) return null;

    try {
        let cleaned = field;
        cleaned = cleaned.replace(/^"(.*)"$/, '$1');
        cleaned = cleaned.replace(/""/g, '"');
        cleaned = cleaned.replace(/\\"/g, '"');
        return JSON.parse(cleaned);
    } catch (e) {
        console.log("Parse error:", e, field);
        return null;
    }
}

function formatDate(ts){
    const d = new Date(ts);
    return isNaN(d) ? "Invalid" :
        d.toLocaleDateString('en-GB') + " " +
        d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
}

// ✅ How stale is a device's most recent report
function getFreshness(tsString){
    if (!tsString) return { text: "", css: "" };

    const ts = new Date(tsString);
    if (isNaN(ts)) return { text: "", css: "" };

    const hoursAgo = (Date.now() - ts.getTime()) / 3600000;

    // Only show a last-seen indicator for devices seen within the
    // last 365 days - older than that, show nothing.
    if (hoursAgo > 365 * 24) return { text: "", css: "" };

    let text;
    if (hoursAgo < 0) {
        text = "Just now";
    } else if (hoursAgo < 1) {
        text = Math.max(1, Math.round(hoursAgo * 60)) + "m ago";
    } else if (hoursAgo < 48) {
        text = Math.round(hoursAgo) + "h ago";
    } else {
        text = Math.round(hoursAgo / 24) + "d ago";
    }

    let css;
    if (hoursAgo <= 2) css = "freshness-ok";
    else if (hoursAgo <= 6) css = "freshness-warn";
    else css = "freshness-stale";

    return { text: "Last seen " + text, css: css };
}

function buildTable(data, customOrder){
    if(!data || !Array.isArray(data) || data.length === 0) return "<p>No data</p>";

    let columns;
    if(customOrder){
        columns = customOrder;
    } else {
        const columnSet = new Set();
        data.forEach(r => Object.keys(r).forEach(k => columnSet.add(k)));
        columns = Array.from(columnSet);
    }

    let html = "<table><thead><tr>";
    columns.forEach(col => html += "<th>"+col+"</th>");
    html += "</tr></thead><tbody>";

    data.forEach(row => {
        html += "<tr>";
        columns.forEach(col => html += "<td>"+(row[col] ?? "")+"</td>");
        html += "</tr>";
    });

    return html + "</tbody></table>";
}

// ✅ Device selector
function buildDeviceSelector(){
    deviceList.innerHTML = "";

    deviceNames.forEach(name => {
        const btn = document.createElement("div");
        btn.className = "deviceBtn";

        const deviceHistory = allDevices[name];
        const latestTs = (deviceHistory && deviceHistory.length > 0) ? deviceHistory[0].Data.Timestamp : null;
        const freshness = getFreshness(latestTs);

        btn.innerHTML = name +
            (freshness.text ? '<span class="lastSeen ' + freshness.css + '">' + freshness.text + '</span>' : '');

        btn.onclick = () => {
            document.querySelectorAll(".deviceBtn").forEach(b=>b.classList.remove("active"));
            btn.classList.add("active");
            currentDevice = name;
            loadDevice(name);
        };

        deviceList.appendChild(btn);
    });

    if (deviceNames.length > 0) {
        deviceList.firstChild.classList.add("active");
    }
}

// ✅ CPU section - latest reading as a badge, full history as a table
function renderCpuSection(){
    if (!currentHistory.length) {
        cpuSection.innerHTML = "<h2>CPU</h2><p>No data available</p>";
        return;
    }

    const latest = parseFloat(currentHistory[0].CPU_Load) || 0;

    const rows = currentHistory.map(d => ({
        Timestamp: formatDate(d.Timestamp),
        "CPU Load (%)": (parseFloat(d.CPU_Load) || 0).toFixed(1)
    }));

    cpuSection.innerHTML =
        "<h2>CPU</h2>" +
        '<div class="statusBadge">' + latest.toFixed(1) + '%</div>' +
        buildTable(rows, ["Timestamp","CPU Load (%)"]);
}

// ✅ Memory section - latest reading as a badge, full history as a table
function renderMemSection(){
    if (!currentHistory.length) {
        memSection.innerHTML = "<h2>Memory</h2><p>No data available</p>";
        return;
    }

    const latestUsed = parseFloat(currentHistory[0].Memory_UsedGB) || 0;

    const rows = currentHistory.map(d => {
        const used = parseFloat(d.Memory_UsedGB) || 0;
        const total = parseFloat(d.Total_MemoryGB) || 0;
        const pct = total > 0 ? ((used / total) * 100).toFixed(1) + "%" : "";
        return {
            Timestamp: formatDate(d.Timestamp),
            "Used (GB)": used.toFixed(1),
            "Total (GB)": total ? total.toFixed(1) : "",
            "Used %": pct
        };
    });

    memSection.innerHTML =
        "<h2>Memory</h2>" +
        '<div class="statusBadge">' + latestUsed.toFixed(1) + ' GB</div>' +
        buildTable(rows, ["Timestamp","Used (GB)","Total (GB)","Used %"]);
}

// ✅ Backup section - latest status as a badge, full history as a table.
// Hidden entirely when the device has no backup configured, rather than
// showing a card full of "No Backup Configured" rows.
function renderBackupSection(){
    if (!currentHistory.length) {
        backupSection.style.display = "none";
        return;
    }

    const latestB = parseJsonField(currentHistory[0].Backup_Status);
    const latestLast = latestB?.LastSuccessful;
    const latestOk = latestLast && latestLast !== "" && latestLast !== "0001-01-01T00:00:00";

    if (!latestOk) {
        backupSection.style.display = "none";
        return;
    }

    backupSection.style.display = "";

    const badgeClass = "green";
    const badgeText = formatDate(latestLast);

    const rows = currentHistory.map(d => {
        const b = parseJsonField(d.Backup_Status);
        const last = b?.LastSuccessful;
        const ok = last && last !== "" && last !== "0001-01-01T00:00:00";
        return {
            Timestamp: formatDate(d.Timestamp),
            "Last Successful Backup": ok ? formatDate(last) : "-",
            Status: ok ? "OK" : "No Backup Configured"
        };
    });

    backupSection.innerHTML =
        "<h2>Backup</h2>" +
        '<div class="statusBadge ' + badgeClass + '">' + badgeText + '</div>' +
        buildTable(rows, ["Timestamp","Last Successful Backup","Status"]);
}

// ✅ Disk section - worst disk right now as a badge, full history (one row
// per disk per snapshot, since a device can have more than one fixed disk)
function renderDiskSection(){
    if (!currentHistory.length) {
        diskSection.innerHTML = "<h2>Disk</h2><p>No data available</p>";
        return;
    }

    const latestRaw = parseJsonField(currentHistory[0].Disk_Free);
    const latestList = Array.isArray(latestRaw) ? latestRaw : (latestRaw ? [latestRaw] : []);

    let badgeClass = "red";
    let badgeText = "No Data";
    if (latestList.length > 0) {
        const worst = latestList.reduce((min, cur) =>
            (parseFloat(cur.FreeGB) < parseFloat(min.FreeGB) ? cur : min)
        );
        const freeGB = parseFloat(worst.FreeGB || 0);
        const label = latestList.length > 1 ? (worst.DeviceID + " Free: ") : "Free: ";
        badgeText = label + freeGB.toFixed(1) + " GB";
        badgeClass = freeGB < 50 ? "red" : (freeGB < 100 ? "orange" : "green");
    }

    const rows = [];
    currentHistory.forEach(d => {
        const raw = parseJsonField(d.Disk_Free);
        const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
        list.forEach(disk => {
            rows.push({
                Timestamp: formatDate(d.Timestamp),
                Drive: disk.DeviceID || "",
                "Free (GB)": (parseFloat(disk.FreeGB) || 0).toFixed(1),
                "Free (%)": disk.FreePercent !== undefined ? (parseFloat(disk.FreePercent) || 0).toFixed(1) + "%" : ""
            });
        });
    });

    diskSection.innerHTML =
        "<h2>Disk</h2>" +
        '<div class="statusBadge ' + badgeClass + '">' + badgeText + '</div>' +
        buildTable(rows, ["Timestamp","Drive","Free (GB)","Free (%)"]);
}

// ✅ Events + Updates - always the most recent snapshot
function renderEventsAndUpdates(){
    if (!currentHistory.length) {
        eventTable.innerHTML = "<h2>Events</h2><p>No data available</p>";
        updateTable.innerHTML = "<h2>Updates</h2><p>No data available</p>";
        return;
    }

    const d = currentHistory[0];

    let events = null;
    try {
        events = JSON.parse(
            new DOMParser().parseFromString(d.Events_JSON, "text/html").documentElement.textContent
        );
    } catch (e) { events = null; }

    eventTable.innerHTML =
        "<h2>Events</h2>" +
        (events ? buildTable(events, ["System","TimeCreated","Id","Level","Message"]) : "<p>No events available</p>");

    const hostUpdates = parseJsonField(d.Host_Update_Details);

    let updateRows = [];
    if (hostUpdates && Array.isArray(hostUpdates)){
        updateRows = hostUpdates.map(u => {
            const rebootIcon = u.Reboot === "YES" ? "🔴 YES" : "✅ No";
            const severity = (u.Status !== "Success" && u.Title !== "Up to date") ? "WARNING" : "OK";
            return { Title: u.Title, Status: u.Status, SizeMB: u.SizeMB, Reboot: rebootIcon, Severity: severity };
        });
    }

    updateTable.innerHTML =
        "<h2>Updates</h2>" +
        (updateRows.length ? buildTable(updateRows, ["Title","Status","SizeMB","Reboot","Severity"]) : "<p>No update data available</p>");
}

// ✅ Switch to a device: rebuild every section from its full history
function loadDevice(name){
    currentHistory = allDevices[name].map(h => h.Data);

    document.getElementById("hostHeading").innerText = name + " - Host Performance Stats";

    const latestTs = currentHistory.length > 0 ? currentHistory[0].Timestamp : null;
    const freshness = getFreshness(latestTs);
    lastSeenInfo.innerHTML = freshness.text
        ? '<span class="' + freshness.css + '">' + freshness.text + " (" + formatDate(latestTs) + ")</span>"
        : "";

    renderCpuSection();
    renderMemSection();
    renderBackupSection();
    renderDiskSection();
    renderEventsAndUpdates();
}

// ✅ Top-level tabs
function showTab(id){
    document.querySelectorAll(".tabBtn").forEach(b => b.classList.toggle("active", b.dataset.tab === id));
    ["tabDevices","tabSwitches","tabM365","tabDefender","tabIntune"].forEach(t => {
        document.getElementById(t).style.display = (t === id ? "" : "none");
    });
}
document.querySelectorAll(".tabBtn").forEach(b => { b.onclick = () => showTab(b.dataset.tab); });

// ================= MICROSOFT 365 TAB =================
// NB: this script sits inside a PowerShell here-string - no dollar signs in the JS.

// Shared helpers (same as Eastwood's dashboard)
function escHtml(s){
    return String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function pill(text, colour){
    return '<span style="font-weight:600;color:' + colour + '">' + escHtml(text) + '</span>';
}
function sophosBadge(text, cls){
    return '<div class="statusBadge ' + (cls || "") + '" style="margin-right:8px;">' + escHtml(text) + '</div>';
}

const m365Colours = {
    serviceOperational: "#1a7d2c", serviceRestored: "#1a7d2c", falsePositive: "#1a7d2c",
    postIncidentReviewPublished: "#1a7d2c", resolved: "#1a7d2c",
    serviceInterruption: "#c92a2a", extendedRecovery: "#c92a2a",
    high: "#c92a2a", medium: "#b06a00", low: "#1a1a1a", informational: "#6c6c6c", none: "#6c6c6c"
};
function m365Colour(v){ return m365Colours[v] || "#b06a00"; }

function m365Label(v){
    const s = String(v ?? "").replace(/([a-z])([A-Z])/g, (m, a, b) => a + " " + b.toLowerCase());
    return s.charAt(0).toUpperCase() + s.slice(1);
}

function m365Sec(name){ return (m365.Sections && m365.Sections[name]) || { Error: "", Rows: [] }; }
function m365Rows(name){ return m365Sec(name).Rows || []; }
function m365Na(name){ return !!m365Sec(name).Error; }
function m365Hidden(name){ return !!m365Sec(name).Unlicensed; }
function m365Note(name){
    return '<p style="color:#b06a00;white-space:normal;">' + escHtml(m365Sec(name).Error) + '</p>';
}
function m365Wrap(t, minW){
    return '<span style="white-space:normal;display:inline-block;min-width:' + (minW || 260) + 'px;max-width:520px;">' + escHtml(t) + '</span>';
}
function m365Link(url){
    return url ? '<a href="' + escHtml(url) + '" target="_blank" rel="noopener">Open &#8599;</a>' : "";
}

function m365AttentionCount(){
    if (m365.Error) return 0;
    return m365Rows("Health").filter(h => h.Status !== "serviceOperational").length +
           m365Rows("Issues").filter(i => i.Type === "incident").length +
           m365Rows("Alerts").filter(a => a.Severity === "high").length +
           m365Rows("Risky").length +
           m365Rows("SignIns").filter(s => s.External).length;
}

function renderM365Tab(){
    let html = "<h1>Microsoft 365</h1>";

    if (m365.Error) {
        m365View.innerHTML = html + '<div class="card"><p style="white-space:normal;">' + escHtml(m365.Error) + '</p></div>';
        return;
    }

    const health     = m365Rows("Health");
    const degraded   = health.filter(h => h.Status !== "serviceOperational");
    const issues     = m365Rows("Issues");
    const incidents  = issues.filter(i => i.Type === "incident");
    const advisories = issues.filter(i => i.Type !== "incident");
    const alerts     = m365Rows("Alerts");
    const highAlerts = alerts.filter(a => a.Severity === "high");
    const risky      = m365Rows("Risky");
    const signIns    = m365Rows("SignIns");
    const signInIPs  = m365Rows("SignInIPs");
    const msgs       = m365Rows("Messages");
    const actionMsgs = msgs.filter(m => m.ActionBy);
    const score      = m365Rows("Score")[0];

    html += '<p style="margin-top:-8px;font-size:14px;color:#555;">Data fetched from Microsoft 365 at ' + escHtml(m365.FetchedAt) +
        ' &nbsp;|&nbsp; Portals: ' +
        '<a href="https://admin.microsoft.com/Adminportal/Home#/servicehealth" target="_blank" rel="noopener">Service health</a> &middot; ' +
        '<a href="https://admin.microsoft.com/Adminportal/Home#/MessageCenter" target="_blank" rel="noopener">Message center</a> &middot; ' +
        '<a href="https://purview.microsoft.com/audit/auditsearch" target="_blank" rel="noopener">Audit log search</a> &middot; ' +
        '<a href="https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers" target="_blank" rel="noopener">Entra users</a> &middot; ' +
        '<a href="https://security.microsoft.com/securescore" target="_blank" rel="noopener">Secure Score</a></p>';

    // ---- Summary ----
    html += '<div class="card"><h2>Summary</h2>' +
        (m365Na("Health") ? sophosBadge("Service health n/a")
            : sophosBadge(degraded.length + " of " + health.length + " services with issues", degraded.length ? "orange" : "green")) +
        (m365Na("Issues") ? sophosBadge("Incidents n/a")
            : sophosBadge(incidents.length + " open incident(s)", incidents.length ? "red" : "green") +
              sophosBadge(advisories.length + " advisory(ies)", advisories.length ? "orange" : "")) +
        (m365Hidden("Alerts") ? "" : m365Na("Alerts") ? sophosBadge("Security alerts n/a")
            : sophosBadge(alerts.length + " security alert(s), " + highAlerts.length + " high", highAlerts.length ? "red" : (alerts.length ? "orange" : "green"))) +
        (m365Hidden("Risky") ? "" : m365Na("Risky") ? sophosBadge("Risky users n/a")
            : sophosBadge(risky.length + " risky user(s)", risky.length ? "red" : "green")) +
        (m365Hidden("SignIns") ? "" : m365Na("SignIns") ? sophosBadge("Failed sign-ins n/a")
            : sophosBadge((m365.FailedTotal || 0) + " failed sign-in(s) in " + m365.SignInHours + "h, " + signIns.length + " user(s)") +
              (m365.KnownIPsSet ? sophosBadge((m365.FailedExternal || 0) + " user(s) failing from outside school", m365.FailedExternal ? "red" : "green") : "")) +
        (m365Na("Messages") ? ""
            : sophosBadge(actionMsgs.length + " Message Center action(s)", actionMsgs.length ? "orange" : "green")) +
        (score ? sophosBadge("Secure Score " + score.Percent + "% (" + score.Score + " / " + score.Max + ")") : "") +
        '</div>';

    // ---- Service health ----
    html += '<div class="card"><h2>Service Health</h2>';
    if (m365Na("Health")) {
        html += m365Note("Health");
    } else {
        html += degraded.length
            ? buildTable(degraded.map(h => ({
                  Service: "<b>" + escHtml(h.Service) + "</b>",
                  Status:  pill(m365Label(h.Status), m365Colour(h.Status))
              })), ["Service","Status"])
            : '<div class="statusBadge green">All services healthy</div>';
        const ok = health.filter(h => h.Status === "serviceOperational").map(h => escHtml(h.Service));
        if (ok.length) html += '<p style="font-size:13px;color:#555;white-space:normal;"><b>Healthy:</b> ' + ok.join(", ") + '</p>';
    }
    html += '</div>';

    // ---- Open incidents & advisories ----
    html += '<div class="card"><h2>Open Incidents &amp; Advisories</h2>';
    if (m365Na("Issues"))   html += m365Note("Issues");
    else if (!issues.length) html += '<div class="statusBadge green">No open incidents or advisories</div>';
    else html += buildTable(issues.map(i => ({
            Id:      escHtml(i.Id),
            Type:    pill(m365Label(i.Type), i.Type === "incident" ? "#c92a2a" : "#b06a00"),
            Service: escHtml(i.Service),
            Status:  pill(m365Label(i.Status), m365Colour(i.Status)),
            Title:   m365Wrap(i.Title),
            Impact:  m365Wrap(i.Impact, 320),
            Started: escHtml(i.Started),
            Updated: escHtml(i.Updated),
            Link:    m365Link(i.Link)
        })), ["Id","Type","Service","Status","Title","Impact","Started","Updated","Link"]);
    html += '</div>';

    // ---- Security alerts ----
    if (!m365Hidden("Alerts")) {
    html += '<div class="card"><h2>Security Alerts (Defender / Microsoft 365)</h2>';
    if (m365Na("Alerts"))    html += m365Note("Alerts");
    else if (!alerts.length) html += '<div class="statusBadge green">No open security alerts</div>';
    else html += buildTable(alerts.map(a => ({
            Created:  escHtml(a.Created),
            Severity: pill(a.Severity, m365Colour(a.Severity)),
            Status:   escHtml(m365Label(a.Status)),
            Title:    m365Wrap(a.Title),
            Source:   escHtml(m365Label(a.Source)),
            Category: escHtml(a.Category),
            "Users / Devices": m365Wrap(a.Entities, 200),
            Link:     m365Link(a.Link)
        })), ["Created","Severity","Status","Title","Source","Category","Users / Devices","Link"]);
    html += '</div>';
    }

    // ---- Risky users ----
    if (!m365Hidden("Risky")) {
    html += '<div class="card"><h2>Risky Users <a href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskyUsers" target="_blank" rel="noopener" style="font-size:13px;font-weight:400;">Open in Entra &#8599;</a></h2>';
    if (m365Na("Risky"))    html += m365Note("Risky");
    else if (!risky.length) html += '<div class="statusBadge green">No users at risk</div>';
    else html += buildTable(risky.map(r => ({
            User:    "<b>" + escHtml(r.User) + "</b>",
            Risk:    pill(r.Risk, m365Colour(r.Risk)),
            Detail:  escHtml(m365Label(r.Detail)),
            Updated: escHtml(r.Updated)
        })), ["User","Risk","Detail","Updated"]);
    html += '</div>';
    }

    // ---- Failed sign-ins ----
    if (!m365Hidden("SignIns")) {
    html += '<div class="card"><h2>Failed Sign-ins by User (last ' + escHtml(m365.SignInHours) + 'h)</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">From the Microsoft 365 audit log. Events usually appear 30 minutes to a few hours after they happen. ' +
        'MFA and "stay signed in" prompts are not counted.' +
        (m365.KnownIPsSet ? ' Users failing from an IP outside school are listed first.' : '') + ' Top 50 shown.</p>';
    if (m365.SignInNote) html += '<p style="color:#b06a00;white-space:normal;">' + escHtml(m365.SignInNote) + '</p>';
    if (m365Na("SignIns"))    html += m365Note("SignIns");
    else if (!signIns.length) html += '<div class="statusBadge green">No failed sign-ins</div>';
    else {
        const cols = ["User","Failures","Top Reason","IPs","Last IP","Last Attempt"];
        if (m365.KnownIPsSet) cols.splice(4, 0, "External IPs");
        html += buildTable(signIns.map(s => ({
            User:           "<b>" + escHtml(s.User) + "</b>",
            Failures:       pill(s.Failures, s.Failures >= 10 ? "#c92a2a" : (s.Failures >= 3 ? "#b06a00" : "#1a1a1a")),
            "Top Reason":   escHtml(s.TopReason),
            IPs:            escHtml(s.IPCount),
            "External IPs": s.External ? pill(s.ExternalIPs, "#c92a2a") : "",
            "Last IP":      escHtml(s.LastIP),
            "Last Attempt": escHtml(s.Last)
        })), cols);
    }
    html += '</div>';

    if (signInIPs.length) {
        const cols = ["IP","Accounts Tried","Failures","Accounts","Last Attempt"];
        html += '<div class="card"><h2>Failed Sign-ins by Source IP</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">One IP failing against many different accounts is the typical sign of password guessing (a "spray"). ' +
            'Sorted by number of accounts tried. Top 20 shown.</p>' +
            buildTable(signInIPs.map(p => ({
                IP:               "<b>" + escHtml(p.IP) + "</b>" + (p.External ? " " + pill("External", "#c92a2a") : ""),
                "Accounts Tried": pill(p.Users, p.Users >= 5 ? "#c92a2a" : (p.Users >= 3 ? "#b06a00" : "#1a1a1a")),
                Failures:         escHtml(p.Failures),
                Accounts:         m365Wrap(p.Accounts, 320),
                "Last Attempt":   escHtml(p.Last)
            })), cols) +
            '</div>';
    }
    }

    // ---- Message Center ----
    html += '<div class="card"><h2>Message Center (changed in last ' + escHtml(m365.MessageDays) + ' days)</h2>';
    if (m365Na("Messages")) {
        html += m365Note("Messages") + '</div>';
    } else {
        html += '<select id="m365MsgShow" style="padding:8px;border:1px solid #d0d0d0;border-radius:8px;margin-bottom:10px;">' +
                '<option value="all">All messages</option>' +
                '<option value="action">Action required</option>' +
                '<option value="major">Major changes</option>' +
            '</select><div id="m365MsgTable"></div></div>';
    }

    m365View.innerHTML = html;

    const sel = document.getElementById("m365MsgShow");
    if (sel) { sel.onchange = renderM365Messages; renderM365Messages(); }
}

function renderM365Messages(){
    const all  = m365Rows("Messages");
    const show = document.getElementById("m365MsgShow").value;
    const list = all.filter(m => show === "action" ? !!m.ActionBy : (show === "major" ? !!m.Major : true));
    document.getElementById("m365MsgTable").innerHTML =
        '<p style="font-size:13px;color:#555;">Showing ' + list.length + ' of ' + all.length + ' message(s)</p>' +
        (list.length ? buildTable(list.map(m => ({
            Id:          escHtml(m.Id),
            Title:       m365Wrap(m.Title, 320),
            Services:    m365Wrap(m.Services, 160),
            Category:    escHtml(m365Label(m.Category)),
            Major:       m.Major ? pill("Major", "#b06a00") : "",
            "Action By": m.ActionBy ? pill(m.ActionBy, "#c92a2a") : "",
            Updated:     escHtml(m.Updated),
            Link:        m365Link(m.Link)
        })), ["Id","Title","Services","Category","Major","Action By","Updated","Link"]) : "");
}

// Count on the Microsoft 365 tab button
(function(){
    const n = m365AttentionCount();
    if (n > 0) {
        document.getElementById("m365TabCount").innerHTML =
            ' <span style="background:#FF6B6B;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">' + n + '</span>';
    }
})();

// ================= NETWORK SWITCHES TAB =================
// NB: this script sits inside a PowerShell here-string - no dollar signs in the JS.
function swList(){ return sw.Switches || []; }

function swSpeed(m){
    if (!m) return "";
    return m >= 1000 ? (Math.round(m / 100) / 10) + " Gbps" : m + " Mbps";
}

function swStatus(s){
    if (!s.Up)    return pill("Offline", "#c92a2a");
    if (s.Issues) return pill("Needs attention", "#b06a00");
    return pill("OK", "#1a7d2c");
}

function swPing(s){
    if (!s.Up) return pill("No reply", "#c92a2a");
    if (s.LatencyMs === null || s.LatencyMs === undefined) return pill("Ping blocked", "#6c6c6c");
    const bad = s.LatencyMs > sw.LatencyWarnMs || s.LossPct > 0;
    return pill(s.LatencyMs + " ms" + (s.LossPct ? ", " + s.LossPct + "% loss" : ""), bad ? "#b06a00" : "#1a1a1a");
}

function swMgmt(s){
    return (s.Mgmt || []).map(m => {
        if (m === "HTTPS")  return '<a href="https://' + escHtml(s.IP) + '" target="_blank" rel="noopener">HTTPS &#8599;</a>';
        if (m === "HTTP")   return '<a href="http://' + escHtml(s.IP) + '" target="_blank" rel="noopener">HTTP &#8599;</a>';
        if (m === "Telnet") return pill("Telnet", "#c92a2a");
        return escHtml(m);
    }).join(" &middot; ");
}

function swNbrFor(s, portName){
    return (s.Neighbours || []).filter(n => n.LocalPort === portName)
        .map(n => n.Neighbour + (n.NeighbourPort ? " (" + n.NeighbourPort + ")" : "")).join(", ");
}

function swAttentionCount(){ return swList().filter(s => s.Issues).length; }

function renderSwitchTab(){
    let html = "<h1>Network Switches</h1>";

    if (sw.Error) {
        swView.innerHTML = html + '<div class="card"><p style="white-space:normal;">' + escHtml(sw.Error) + '</p></div>';
        return;
    }

    // Offline first, then ones with problems, then by name
    const all = swList().slice().sort((a, b) =>
        ((a.Up ? 1 : 0) - (b.Up ? 1 : 0)) ||
        ((b.Issues ? 1 : 0) - (a.Issues ? 1 : 0)) ||
        String(a.Name).localeCompare(String(b.Name)));

    const offline   = all.filter(s => !s.Up);
    const attention = all.filter(s => s.Issues);
    const restarted = all.filter(s => s.Up && /Restarted/.test(s.Issues || ""));
    const errSw     = all.filter(s => s.ErrPorts > 0);
    const telnet    = all.filter(s => (s.Mgmt || []).indexOf("Telnet") >= 0);
    const noSnmp    = all.filter(s => s.Up && !s.Snmp);
    const subnets   = sw.Subnets || [];

    html += '<p style="margin-top:-8px;font-size:14px;color:#555;">Checked at ' + escHtml(sw.FetchedAt) +
        (subnets.length ? ' &nbsp;|&nbsp; Searching ' + escHtml(subnets.join(", ")) + ' for new switches' : '') + '</p>';

    if (all.length) {
        // ---- Summary ----
        html += '<div class="card"><h2>Summary</h2>' +
            sophosBadge(all.length + " switch(es)") +
            sophosBadge(offline.length + " offline", offline.length ? "red" : "green") +
            sophosBadge(attention.length + " needing attention", attention.length ? "orange" : "green") +
            sophosBadge(restarted.length + " restarted in the last " + sw.RebootWarnHours + "h", restarted.length ? "orange" : "green") +
            sophosBadge(errSw.length + " with new port errors", errSw.length ? "orange" : "green") +
            (telnet.length ? sophosBadge(telnet.length + " with Telnet enabled", "orange") : "") +
            (noSnmp.length ? sophosBadge(noSnmp.length + " without SNMP (ping only)") : "") +
            '</div>';

        // ---- Needing attention ----
        html += '<div class="card"><h2>Switches Needing Attention</h2>' +
            (attention.length ? buildTable(attention.map(s => ({
                Switch:     "<b>" + escHtml(s.Name) + "</b>",
                IP:         escHtml(s.IP),
                Issues:     m365Wrap(s.Issues, 360),
                Ping:       swPing(s),
                Uptime:     escHtml(s.Uptime),
                Management: swMgmt(s)
            })), ["Switch","IP","Issues","Ping","Uptime","Management"])
            : '<div class="statusBadge green">All switches look healthy</div>') +
            '</div>';

        // ---- All switches ----
        html += '<div class="card"><h2>All Switches</h2>' + buildTable(all.map(s => ({
            Switch:     "<b>" + escHtml(s.Name) + "</b>",
            IP:         escHtml(s.IP),
            Status:     swStatus(s),
            Ping:       swPing(s),
            Model:      s.Snmp ? m365Wrap(s.Descr, 260) : pill(s.Up ? "No SNMP" : "-", "#6c6c6c"),
            Uptime:     escHtml(s.Uptime),
            "Ports Up": s.Snmp ? escHtml(s.PortsUp + " / " + s.PortsTotal) : "",
            Location:   escHtml(s.Location),
            Management: swMgmt(s),
            Found:      escHtml(s.Source)
        })), ["Switch","IP","Status","Ping","Model","Uptime","Ports Up","Location","Management","Found"]) + '</div>';

        // ---- Per-switch ports and neighbours ----
        const withSnmp = all.filter(s => s.Snmp);
        if (withSnmp.length) {
            html += '<div class="card"><h2>Ports &amp; Neighbours</h2>' +
                '<select id="swPick" style="padding:8px;border:1px solid #d0d0d0;border-radius:8px;margin-bottom:10px;">' +
                withSnmp.map(s => '<option value="' + escHtml(s.IP) + '">' + escHtml(s.Name + " (" + s.IP + ")") + '</option>').join("") +
                '</select> ' +
                '<select id="swPortShow" style="padding:8px;border:1px solid #d0d0d0;border-radius:8px;margin-bottom:10px;">' +
                    '<option value="all">All ports</option>' +
                    '<option value="up">Connected</option>' +
                    '<option value="issues">Errors / recent changes / slow speed</option>' +
                    '<option value="links">Links to other network devices</option>' +
                    '<option value="down">Not connected</option>' +
                '</select><div id="swDetail"></div></div>';
        }
    }
    else {
        html += '<div class="card"><h2>No switches yet</h2><p style="white-space:normal;">No switches are listed and none were found on the network. ' +
            'Add them to the SwitchList setting at the top of Monitor-Master.ps1, or switch on SNMP on them so they are found automatically.</p></div>';
    }

    // ---- How it works ----
    html += '<div class="card"><h2>How Switches Are Checked</h2><ul style="white-space:normal;font-size:14px;line-height:1.6;margin:0;">' +
        '<li>Switches come from the SwitchList setting at the top of Monitor-Master.ps1, plus any found automatically on ' +
            (subnets.length ? escHtml(subnets.join(", ")) : "(no subnets set)") + '. Found switches are remembered, and dropped after ' + escHtml(sw.ForgetDays) + ' days offline.</li>' +
        '<li>Every switch is pinged and checked for SSH, Telnet and web management.</li>' +
        '<li>Model, uptime, ports, errors and neighbours need <b>SNMP v2c read-only</b> switched on on the switch, using the same community string as the SwitchCommunity setting.</li>' +
        '<li>"New errors" are errors since the last check. A connected port below 1 Gbps usually means a poor cable or an old device on the other end.</li>' +
        (sw.SnmpAvailable ? '' : '<li style="color:#c92a2a;">SNMP is not available on this server (the Windows olePrn.OleSNMP component is missing), so only ping and port checks are running.</li>') +
        (sw.UsingPublic ? '<li style="color:#b06a00;">The SNMP community is still the default "public". Set your own on the switches and in the SwitchCommunity setting.</li>' : '') +
        '</ul></div>';

    swView.innerHTML = html;

    const pick = document.getElementById("swPick");
    if (pick) {
        pick.onchange = renderSwDetail;
        document.getElementById("swPortShow").onchange = renderSwDetail;
        renderSwDetail();
    }
}

function renderSwDetail(){
    const ip   = document.getElementById("swPick").value;
    const show = document.getElementById("swPortShow").value;
    const s    = swList().find(x => x.IP === ip);
    if (!s) return;

    const ifs  = s.Interfaces || [];
    const list = ifs.filter(i =>
        show === "up"     ? i.Oper === "Up" :
        show === "down"   ? i.Oper !== "Up" :
        show === "issues" ? (i.NewErr > 0 || i.Changed || i.Slow) :
        show === "links"  ? i.Uplink : true);

    let html = '<p style="font-size:13px;color:#555;white-space:normal;">' + escHtml(s.Descr) +
        (s.Uptime ? ' &middot; <b>Up:</b> ' + escHtml(s.Uptime) : '') +
        (s.Location ? ' &middot; <b>Location:</b> ' + escHtml(s.Location) : '') +
        (s.Contact ? ' &middot; <b>Contact:</b> ' + escHtml(s.Contact) : '') + '</p>';

    html += '<p style="font-size:13px;color:#555;">Showing ' + list.length + ' of ' + ifs.length + ' port(s)</p>';
    html += list.length ? buildTable(list.map(i => ({
        Port:                   "<b>" + escHtml(i.Name) + "</b>" + (i.IsLag ? " " + pill("LAG", "#6c6c6c") : ""),
        Description:            m365Wrap(i.Alias, 160),
        Status:                 pill(i.Oper, i.Oper === "Up" ? "#1a7d2c" : ((i.Uplink && i.Oper !== "Disabled") ? "#c92a2a" : "#6c6c6c")),
        Speed:                  i.Oper === "Up" ? pill(swSpeed(i.SpeedMbps), i.Slow ? "#b06a00" : "#1a1a1a") : "",
        "Last Change":          i.Changed ? pill(i.LastChange, "#b06a00") : escHtml(i.LastChange),
        "New Errors":           (i.NewErr === null || i.NewErr === undefined) ? "" : (i.NewErr > 0 ? pill(i.NewErr, "#c92a2a") : "0"),
        "Errors Since Restart": escHtml((i.InErr ?? "-") + " in / " + (i.OutErr ?? "-") + " out"),
        "Connected To":         i.Uplink ? escHtml(swNbrFor(s, i.Name)) : ""
    })), ["Port","Description","Status","Speed","Last Change","New Errors","Errors Since Restart","Connected To"]) : "<p>No ports match</p>";

    const nb = s.Neighbours || [];
    html += '<h3 style="margin-top:20px;">LLDP Neighbours</h3>' +
        (nb.length ? buildTable(nb.map(n => ({
            "Local Port": "<b>" + escHtml(n.LocalPort) + "</b>",
            Device:       escHtml(n.Neighbour),
            "Their Port": escHtml(n.NeighbourPort)
        })), ["Local Port","Device","Their Port"])
        : '<p style="color:#555;white-space:normal;">None reported - LLDP may be switched off on this switch, or nothing connected advertises itself.</p>');

    document.getElementById("swDetail").innerHTML = html;
}

// Count on the Network Switches tab button
(function(){
    const el = document.getElementById("swTabCount");
    if (sw.Error) {
        el.innerHTML = ' <span style="background:#FFB347;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">!</span>';
        return;
    }
    const n = swAttentionCount();
    if (n > 0) el.innerHTML = ' <span style="background:#FF6B6B;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">' + n + '</span>';
})();

// ================= DEFENDER TAB =================
// NB: this script sits inside a PowerShell here-string - no dollar signs in the JS.
function defSec(name){ return (def.Sections && def.Sections[name]) || { Error: "", Rows: [] }; }
function defRows(name){ return defSec(name).Rows || []; }
function defNa(name){ return !!defSec(name).Error; }
function defHidden(name){ return !!defSec(name).Unlicensed; }
function defNote(name){ return '<p style="color:#b06a00;white-space:normal;">' + escHtml(defSec(name).Error) + '</p>'; }

const defLevelColour = { high: "#c92a2a", medium: "#b06a00", low: "#1a1a1a", informational: "#6c6c6c", none: "#6c6c6c", None: "#6c6c6c",
                         High: "#c92a2a", Medium: "#b06a00", Low: "#1a1a1a", Informational: "#6c6c6c" };
function defLevel(v){ return pill(v || "-", defLevelColour[v] || "#1a1a1a"); }

function defDeviceIssues(m){
    const issues = [];
    if (m.Risk === "High" || m.Risk === "Medium") issues.push("Risk: " + m.Risk);
    if (m.Exposure === "High") issues.push("Exposure: High");
    if (m.Health && m.Health !== "Active") issues.push("Health: " + m365Label(m.Health));
    if (m.AV && ["updated","unknown","notsupported"].indexOf(String(m.AV).toLowerCase()) < 0) issues.push("Antivirus: " + m365Label(m.AV));
    if (m.DaysSince !== null && m.DaysSince > def.StaleDays) issues.push("Not seen for " + Math.round(m.DaysSince) + " days");
    return issues;
}

function defAttentionCount(){
    if (def.Error) return 0;
    const onb = defRows("Machines").filter(m => m.Onboarding === "Onboarded");
    return defRows("Incidents").filter(i => i.Severity === "high" || i.Severity === "medium").length +
           defRows("Alerts").filter(a => a.Severity === "high").length +
           onb.filter(m => m.Risk === "High").length;
}

const defMachineCols = ["Device","OS","Health","Risk","Exposure","Antivirus","Last Seen","Last IP","Link"];
function defMachineRow(m){
    return {
        Device:      "<b>" + escHtml(m.Name) + "</b>",
        OS:          escHtml(m.OS),
        Health:      pill(m365Label(m.Health), m.Health === "Active" ? "#1a7d2c" : "#b06a00"),
        Risk:        defLevel(m.Risk),
        Exposure:    defLevel(m.Exposure),
        Antivirus:   m.AV ? pill(m365Label(m.AV), String(m.AV).toLowerCase() === "updated" ? "#1a7d2c" : "#b06a00") : "",
        "Last Seen": escHtml(m.LastSeen),
        "Last IP":   escHtml(m.LastIP),
        Link:        m365Link(m.Link)
    };
}

function renderDefMachineTable(){
    const all = defRows("Machines").filter(m => m.Onboarding === "Onboarded");
    const q = (document.getElementById("defFilter").value || "").toLowerCase();
    const list = all.filter(m => !q || [m.Name, m.OS, m.Health, m.Risk, m.Exposure, m.AV, m.LastIP]
        .some(v => String(v ?? "").toLowerCase().includes(q)));
    document.getElementById("defAllTable").innerHTML =
        '<p style="font-size:13px;color:#555;">Showing ' + list.length + ' of ' + all.length + ' onboarded device(s)</p>' +
        buildTable(list.map(defMachineRow), defMachineCols);
}

function renderDefenderTab(){
    let html = "<h1>Microsoft Defender</h1>";

    if (def.Error) {
        defView.innerHTML = html + '<div class="card"><p style="white-space:normal;">' + escHtml(def.Error) + '</p></div>';
        return;
    }

    const incidents  = defRows("Incidents");
    const incHigh    = incidents.filter(i => i.Severity === "high").length;
    const alerts     = defRows("Alerts");
    const alHigh     = alerts.filter(a => a.Severity === "high").length;
    const machines   = defRows("Machines");
    const onboarded  = machines.filter(m => m.Onboarding === "Onboarded");
    const notOnb     = machines.filter(m => m.Onboarding === "CanBeOnboarded");
    const attention  = onboarded.filter(m => defDeviceIssues(m).length > 0);
    const highRisk   = onboarded.filter(m => m.Risk === "High").length;
    const recs       = defRows("Recs");
    const exploitable = recs.filter(r => r.Exploit).length;
    const controls   = defRows("Controls");
    const exp        = defRows("Exposure")[0];
    const mdeOn      = !defHidden("Machines") && !defNa("Machines");
    const missing    = def.NotInMde || [];

    html += '<p style="margin-top:-8px;font-size:14px;color:#555;">Data fetched from Microsoft Defender at ' + escHtml(def.FetchedAt) +
        ' &nbsp;|&nbsp; Portal: ' +
        '<a href="https://security.microsoft.com/incidents" target="_blank" rel="noopener">Incidents</a> &middot; ' +
        '<a href="https://security.microsoft.com/alerts" target="_blank" rel="noopener">Alerts</a> &middot; ' +
        '<a href="https://security.microsoft.com/machines" target="_blank" rel="noopener">Device inventory</a> &middot; ' +
        '<a href="https://security.microsoft.com/security-recommendations" target="_blank" rel="noopener">Recommendations</a> &middot; ' +
        '<a href="https://security.microsoft.com/quarantine" target="_blank" rel="noopener">Email quarantine</a> &middot; ' +
        '<a href="https://security.microsoft.com/securescore" target="_blank" rel="noopener">Secure Score</a></p>';

    // ---- Summary ----
    html += '<div class="card"><h2>Summary</h2>' +
        (defNa("Incidents") ? sophosBadge("Incidents n/a") :
            sophosBadge(incidents.length + " open incident(s), " + incHigh + " high", incHigh ? "red" : (incidents.length ? "orange" : "green"))) +
        (defNa("Alerts") ? sophosBadge("Alerts n/a") :
            sophosBadge(alerts.length + " unresolved alert(s), " + alHigh + " high", alHigh ? "red" : (alerts.length ? "orange" : "green"))) +
        (mdeOn ? sophosBadge(onboarded.length + " onboarded device(s)") +
                 sophosBadge(highRisk + " high-risk device(s)", highRisk ? "red" : "green") +
                 sophosBadge(attention.length + " device(s) needing attention", attention.length ? "orange" : "green") +
                 sophosBadge(notOnb.length + " discovered device(s) not onboarded", notOnb.length ? "orange" : "green") +
                 sophosBadge(missing.length + " monitored device(s) not in Defender", missing.length ? "orange" : "green") : "") +
        (!defHidden("Recs") && !defNa("Recs") ? sophosBadge(exploitable + " recommendation(s) with a public exploit", exploitable ? "red" : "green") : "") +
        (exp ? sophosBadge("Exposure score " + exp.Exposure, exp.Exposure >= 70 ? "red" : (exp.Exposure >= 30 ? "orange" : "green")) +
               (exp.DeviceScore !== null ? sophosBadge("Secure Score for devices " + exp.DeviceScore) : "") : "") +
        '</div>';

    // ---- Incidents ----
    html += '<div class="card"><h2>Open Incidents</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Incidents group related alerts into one attack story - start here.</p>';
    if (defNa("Incidents"))      html += defNote("Incidents");
    else if (!incidents.length)  html += '<div class="statusBadge green">No open incidents</div>';
    else html += buildTable(incidents.map(i => ({
            Id:          escHtml(i.Id),
            Severity:    defLevel(i.Severity),
            Status:      escHtml(m365Label(i.Status)),
            Incident:    m365Wrap(i.Name, 320),
            Alerts:      alerts.filter(a => String(a.Incident) === String(i.Id)).length || "",
            "Assigned To": escHtml(i.Assigned),
            Created:     escHtml(i.Created),
            Updated:     escHtml(i.Updated),
            Link:        m365Link(i.Link)
        })), ["Id","Severity","Status","Incident","Alerts","Assigned To","Created","Updated","Link"]);
    html += '</div>';

    // ---- Alerts ----
    html += '<div class="card"><h2>Unresolved Alerts</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">From every Defender product (Endpoint, Office 365 email, Identity, Cloud Apps, Entra). Highest severity first.</p>';
    if (defNa("Alerts"))      html += defNote("Alerts");
    else if (!alerts.length)  html += '<div class="statusBadge green">No unresolved alerts</div>';
    else {
        html += '<select id="defAlertShow" style="padding:8px;border:1px solid #d0d0d0;border-radius:8px;margin-bottom:10px;">' +
                '<option value="all">All severities</option><option value="hm">High &amp; medium only</option><option value="high">High only</option>' +
                '</select><div id="defAlertTable"></div>';
    }
    html += '</div>';

    // ---- Devices needing attention ----
    if (!defHidden("Machines")) {
        html += '<div class="card"><h2>Devices Needing Attention</h2>';
        if (defNa("Machines"))       html += defNote("Machines");
        else if (!attention.length)  html += '<div class="statusBadge green">All onboarded devices look healthy</div>';
        else html += buildTable(attention
                .sort((a, b) => ({High:0,Medium:1}[a.Risk] ?? 2) - ({High:0,Medium:1}[b.Risk] ?? 2))
                .map(m => ({
                    Device:      "<b>" + escHtml(m.Name) + "</b>",
                    Issues:      m365Wrap(defDeviceIssues(m).join(" | "), 280),
                    Risk:        defLevel(m.Risk),
                    "Last Seen": escHtml(m.LastSeen),
                    OS:          escHtml(m.OS),
                    Link:        m365Link(m.Link)
                })), ["Device","Issues","Risk","Last Seen","OS","Link"]);
        html += '</div>';

        if (!defNa("Machines")) {
            html += '<div class="halfRow"><div class="card"><h2>Discovered But Not Onboarded</h2>' +
                '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Devices Defender has seen on the network that are not protected by it.</p>' +
                (notOnb.length
                    ? buildTable(notOnb.map(m => ({ Device: escHtml(m.Name), OS: escHtml(m.OS), "Last Seen": escHtml(m.LastSeen), "Last IP": escHtml(m.LastIP) })),
                                 ["Device","OS","Last Seen","Last IP"])
                    : '<div class="statusBadge green">None</div>') +
                '</div><div class="card"><h2>Monitored Devices Not in Defender</h2>' +
                '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Devices reporting to this dashboard that are not onboarded to Defender.</p>' +
                (missing.length ? '<p style="white-space:normal;">' + missing.map(n => escHtml(n)).join(", ") + '</p>'
                                : '<div class="statusBadge green">Every monitored device is onboarded</div>') +
                '</div></div>';
        }
    }

    // ---- Vulnerability / configuration recommendations ----
    if (!defHidden("Recs")) {
        html += '<div class="card"><h2>Top Security Recommendations</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Software updates and configuration fixes from Defender Vulnerability Management. ' +
            'Ones linked to an active alert or with a public exploit are listed first.</p>';
        if (defNa("Recs"))       html += defNote("Recs");
        else if (!recs.length)   html += '<div class="statusBadge green">No active recommendations</div>';
        else html += buildTable(recs.map(r => ({
                Recommendation:  m365Wrap(r.Recommendation, 320),
                Product:         escHtml(r.Product),
                Type:            escHtml(m365Label(r.Type)),
                "CVEs":          escHtml(r.Weaknesses),
                "Exposed Devices": escHtml(r.Exposed),
                "Public Exploit": r.Exploit ? pill("Yes", "#c92a2a") : "",
                "Active Alert":   r.ActiveAlert ? pill("Yes", "#c92a2a") : "",
                Severity:        pill(r.Severity, r.Severity >= 9 ? "#c92a2a" : (r.Severity >= 7 ? "#b06a00" : "#1a1a1a"))
            })), ["Recommendation","Product","Type","CVEs","Exposed Devices","Public Exploit","Active Alert","Severity"]);
        html += '</div>';
    }

    // ---- Secure Score improvement actions ----
    html += '<div class="card"><h2>Secure Score - Biggest Improvements Available</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Recommended settings that are not fully in place yet, biggest score gain first.</p>';
    if (defNa("Controls"))       html += defNote("Controls");
    else if (!controls.length)   html += '<div class="statusBadge green">Nothing outstanding</div>';
    else html += buildTable(controls.map(c => ({
            Action:        m365Wrap(c.Action, 360),
            Category:      escHtml(c.Category),
            Service:       escHtml(c.Service),
            Points:        escHtml(c.Points),
            "Gain":        pill("+" + c.Gain, c.Gain >= 5 ? "#c92a2a" : "#b06a00"),
            "User Impact": escHtml(c.UserImpact),
            Effort:        escHtml(c.Effort),
            Link:          m365Link(c.Link)
        })), ["Action","Category","Service","Points","Gain","User Impact","Effort","Link"]);
    html += '</div>';

    // ---- All onboarded devices ----
    if (mdeOn) {
        html += '<div class="card"><h2>All Onboarded Devices</h2>' +
            '<input id="defFilter" class="filterBox" type="text" placeholder="Filter by device, OS, health, risk, IP...">' +
            '<div id="defAllTable"></div></div>';
    }

    defView.innerHTML = html;

    const sel = document.getElementById("defAlertShow");
    if (sel) { sel.onchange = renderDefAlerts; renderDefAlerts(); }
    const flt = document.getElementById("defFilter");
    if (flt) { flt.oninput = renderDefMachineTable; renderDefMachineTable(); }
}

function renderDefAlerts(){
    const all  = defRows("Alerts");
    const show = document.getElementById("defAlertShow").value;
    const list = all.filter(a => show === "high" ? a.Severity === "high" : (show === "hm" ? (a.Severity === "high" || a.Severity === "medium") : true));
    document.getElementById("defAlertTable").innerHTML =
        '<p style="font-size:13px;color:#555;">Showing ' + list.length + ' of ' + all.length + ' alert(s)</p>' +
        (list.length ? buildTable(list.map(a => ({
            Created:   escHtml(a.Created),
            Severity:  defLevel(a.Severity),
            Status:    escHtml(m365Label(a.Status)),
            Alert:     m365Wrap(a.Title, 260),
            Detail:    m365Wrap(a.Detail, 340),
            Source:    escHtml(m365Label(a.Source)),
            Detection: escHtml(m365Label(a.Detection)),
            Category:  escHtml(a.Category),
            "Users / Devices / Email": m365Wrap(a.Entities, 220),
            Incident:  escHtml(a.Incident),
            Link:      m365Link(a.Link)
        })), ["Created","Severity","Status","Alert","Detail","Source","Detection","Category","Users / Devices / Email","Incident","Link"]) : "");
}

// Count on the Defender tab button
(function(){
    const el = document.getElementById("defTabCount");
    if (def.Error) {
        el.innerHTML = ' <span style="background:#FFB347;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">!</span>';
        return;
    }
    const n = defAttentionCount();
    if (n > 0) el.innerHTML = ' <span style="background:#FF6B6B;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">' + n + '</span>';
})();

// ================= INTUNE TAB =================
// NB: this script sits inside a PowerShell here-string - no dollar signs in the JS.
function itSec(name){ return (intune.Sections && intune.Sections[name]) || { Error: "", Rows: [] }; }
function itRows(name){ return itSec(name).Rows || []; }
function itNa(name){ return !!itSec(name).Error; }
function itHidden(name){ return !!itSec(name).Unlicensed; }
function itNote(name){ return '<p style="color:#b06a00;white-space:normal;">' + escHtml(itSec(name).Error) + '</p>'; }
function itEaNote(name){
    return '<p style="color:#555;white-space:normal;">No Endpoint analytics data. If it has never been switched on: ' +
        '<a href="https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsMenu/~/overview" target="_blank" rel="noopener">Intune &gt; Reports &gt; Endpoint analytics</a> &gt; Start. ' +
        'Data appears a day or two later.</p>';
}

const itCompColour = { compliant: "#1a7d2c", noncompliant: "#c92a2a", error: "#c92a2a", conflict: "#b06a00", inGracePeriod: "#b06a00" };
function itComp(v){ return pill(m365Label(v || "unknown"), itCompColour[v] || "#6c6c6c"); }

function itCertState(c){
    if (c.DaysLeft === null || c.DaysLeft === undefined) return { text: "Unknown", colour: "#6c6c6c" };
    if (c.DaysLeft < 0)                    return { text: "EXPIRED " + (-c.DaysLeft) + " day(s) ago", colour: "#c92a2a" };
    if (c.DaysLeft <= intune.CertWarnDays) return { text: c.DaysLeft + " day(s) left - renew now", colour: "#c92a2a" };
    if (c.DaysLeft <= 60)                  return { text: c.DaysLeft + " day(s) left", colour: "#b06a00" };
    return { text: c.DaysLeft + " day(s) left", colour: "#1a7d2c" };
}

function itAttentionCount(){
    if (intune.Error) return 0;
    return itRows("Devices").filter(d => d.Compliance === "noncompliant" || d.Compliance === "error").length +
           itRows("Certs").filter(c => c.DaysLeft !== null && c.DaysLeft <= intune.CertWarnDays).length +
           itRows("Perf").filter(p => p.BlueScreens > 0).length;
}

const itDeviceCols = ["Device","User","OS","Compliance","Last Check-in","Free Disk","Encrypted","Model","Serial","Link"];
function itDeviceRow(d){
    return {
        Device:          "<b>" + escHtml(d.Name) + "</b>",
        User:            escHtml(d.User),
        OS:              m365Wrap(d.OS + " " + d.Version, 200),
        Compliance:      itComp(d.Compliance),
        "Last Check-in": escHtml(d.LastSync),
        "Free Disk":     d.FreeGB !== null ? pill(d.FreeGB + " GB (" + d.FreePct + "%)",
                            (d.FreePct < intune.LowDiskPct || d.FreeGB < intune.LowDiskGB) ? "#c92a2a" : "#1a1a1a") : "",
        Encrypted:       d.Encrypted === true ? pill("Yes", "#1a7d2c") : (d.Encrypted === false ? pill("No", "#c92a2a") : ""),
        Model:           escHtml(d.Model),
        Serial:          escHtml(d.Serial),
        Link:            m365Link(d.Link)
    };
}

function renderItDeviceTable(){
    const all = itRows("Devices");
    const q = (document.getElementById("itFilter").value || "").toLowerCase();
    const os = document.getElementById("itOs").value;
    const list = all.filter(d =>
        (!os || String(d.OS).toLowerCase().indexOf(os) >= 0) &&
        (!q || [d.Name, d.User, d.OS, d.Version, d.Compliance, d.Model, d.Serial].some(v => String(v ?? "").toLowerCase().includes(q))));
    document.getElementById("itAllTable").innerHTML =
        '<p style="font-size:13px;color:#555;">Showing ' + list.length + ' of ' + all.length + ' device(s)</p>' +
        buildTable(list.map(itDeviceRow), itDeviceCols);
}

function renderIntuneTab(){
    let html = "<h1>Intune</h1>";

    if (intune.Error) {
        itView.innerHTML = html + '<div class="card"><p style="white-space:normal;">' + escHtml(intune.Error) + '</p></div>';
        return;
    }

    const devs     = itRows("Devices");
    const nonComp  = devs.filter(d => d.Compliance === "noncompliant" || d.Compliance === "error" || d.Compliance === "conflict");
    const stale    = devs.filter(d => d.DaysSince !== null && d.DaysSince > intune.StaleDays);
    const lowDisk  = devs.filter(d => d.FreeGB !== null && (d.FreePct < intune.LowDiskPct || d.FreeGB < intune.LowDiskGB));
    const unenc    = devs.filter(d => d.Encrypted === false && /windows|mac/i.test(d.OS));
    const oldWin   = devs.filter(d => /Windows 10|old Windows 11/.test(d.Issues || ""));
    const attention = devs.filter(d => d.Issues);
    const certs    = itRows("Certs");
    const certBad  = certs.filter(c => c.DaysLeft !== null && c.DaysLeft <= intune.CertWarnDays);
    const perf     = itRows("Perf");
    const perfBad  = perf.filter(p => p.Issues);
    const bsod     = perf.filter(p => p.BlueScreens > 0);
    const batt     = itRows("Battery");
    const crash    = itRows("AppCrash");
    const appFail  = itRows("AppFail");
    const pols     = itRows("Policies");
    const missing  = intune.NotInIntune || [];

    html += '<p style="margin-top:-8px;font-size:14px;color:#555;">Data fetched from Intune at ' + escHtml(intune.FetchedAt) +
        ' &nbsp;|&nbsp; Portal: ' +
        '<a href="https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/allDevices" target="_blank" rel="noopener">All devices</a> &middot; ' +
        '<a href="https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliance" target="_blank" rel="noopener">Compliance</a> &middot; ' +
        '<a href="https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UXAnalyticsMenu/~/overview" target="_blank" rel="noopener">Endpoint analytics</a> &middot; ' +
        '<a href="https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/AppsMenu/~/monitor" target="_blank" rel="noopener">App monitoring</a></p>';

    // ---- Summary ----
    html += '<div class="card"><h2>Summary</h2>' +
        (itNa("Devices") ? sophosBadge("Devices n/a") :
            sophosBadge(devs.length + " managed device(s)") +
            sophosBadge(nonComp.length + " not compliant", nonComp.length ? "red" : "green") +
            sophosBadge(stale.length + " not checked in for " + intune.StaleDays + "+ days", stale.length ? "orange" : "green") +
            sophosBadge(lowDisk.length + " low on disk space", lowDisk.length ? "orange" : "green") +
            sophosBadge(unenc.length + " not encrypted", unenc.length ? "red" : "green") +
            sophosBadge(oldWin.length + " on old / unsupported Windows", oldWin.length ? "orange" : "green")) +
        (certs.length ? sophosBadge(certBad.length ? certBad.length + " Apple cert/token expiring or expired" : "Apple certs & tokens OK", certBad.length ? "red" : "green") : "") +
        (perf.length ? sophosBadge(bsod.length + " device(s) with blue screens", bsod.length ? "red" : "green") +
                       sophosBadge(perfBad.length + " device(s) with performance issues", perfBad.length ? "orange" : "green") : "") +
        (batt.length ? sophosBadge(batt.length + " worn battery(ies)", "orange") : "") +
        (!itNa("AppFail") ? sophosBadge(appFail.length + " app(s) failing to install", appFail.length ? "orange" : "green") : "") +
        (!itNa("Policies") ? sophosBadge(pols.length + " policy(ies) with errors/conflicts", pols.length ? "orange" : "green") : "") +
        '</div>';

    // ---- Apple certificates / tokens ----
    if (certs.length || itNa("Certs")) {
        html += '<div class="card"><h2>Apple Certificates &amp; Tokens</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">If these lapse, iPads/Macs stop taking policies and apps. The push certificate must be renewed with the SAME Apple ID.</p>';
        if (itNa("Certs")) html += itNote("Certs");
        else html += buildTable(certs.map(c => {
                const s = itCertState(c);
                return { Item: "<b>" + escHtml(c.Item) + "</b>", Detail: escHtml(c.Detail), Expires: escHtml(c.Expires),
                         Status: pill(s.text, s.colour), State: escHtml(m365Label(c.State)) };
            }), ["Item","Detail","Expires","Status","State"]);
        html += '</div>';
    }

    // ---- Devices needing attention ----
    html += '<div class="card"><h2>Devices Needing Attention</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Not compliant (with the failing policies), not checked in, low disk, not encrypted, jailbroken, or on an old / unsupported Windows version.</p>';
    if (itNa("Devices"))          html += itNote("Devices");
    else if (!attention.length)   html += '<div class="statusBadge green">All managed devices look healthy</div>';
    else html += buildTable(attention
            .sort((a, b) => (b.Issues.indexOf("Not compliant") >= 0) - (a.Issues.indexOf("Not compliant") >= 0))
            .map(d => ({
                Device:          "<b>" + escHtml(d.Name) + "</b>",
                Issues:          m365Wrap(d.Issues, 360),
                User:            escHtml(d.User),
                OS:              escHtml(d.OS),
                "Last Check-in": escHtml(d.LastSync),
                Link:            m365Link(d.Link)
            })), ["Device","Issues","User","OS","Last Check-in","Link"]);
    html += '</div>';

    // ---- Performance (Endpoint analytics) ----
    html += '<div class="card"><h2>Performance Issues (Endpoint analytics)</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Blue screens, boot over ' + escHtml(intune.BootWarnSec) + 's, sign-in over ' +
        escHtml(intune.LoginWarnSec) + 's, spinning hard disks and frequent restarts. Windows devices only.</p>';
    if (itNa("Perf"))           html += itNote("Perf");
    else if (!perf.length)      html += itEaNote();
    else if (!perfBad.length)   html += '<div class="statusBadge green">No performance issues</div>';
    else html += buildTable(perfBad.map(p => ({
            Device:          "<b>" + escHtml(p.Name) + "</b>",
            Issues:          m365Wrap(p.Issues, 300),
            "Boot (s)":      pill(p.BootSec, p.BootSec > intune.BootWarnSec ? "#c92a2a" : "#1a1a1a"),
            "Sign-in (s)":   pill(p.LoginSec, p.LoginSec > intune.LoginWarnSec ? "#c92a2a" : "#1a1a1a"),
            "Blue Screens":  p.BlueScreens ? pill(p.BlueScreens, "#c92a2a") : "0",
            Restarts:        escHtml(p.Restarts),
            Disk:            escHtml(String(p.Disk || "").toUpperCase()),
            "Startup Score": escHtml(p.StartScore),
            Model:           escHtml(p.Model)
        })), ["Device","Issues","Boot (s)","Sign-in (s)","Blue Screens","Restarts","Disk","Startup Score","Model"]);
    html += '</div>';

    // ---- Battery + app crashes side by side ----
    html += '<div class="halfRow"><div class="card"><h2>Worn Batteries</h2>' +
        '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Laptops whose battery holds less than ' + escHtml(intune.BatteryWarnPct) + '% of its original charge.</p>';
    if (itNa("Battery"))       html += itNote("Battery");
    else if (!batt.length)     html += '<div class="statusBadge green">None</div>';
    else html += buildTable(batt.map(b => ({
            Device:     "<b>" + escHtml(b.Name) + "</b>",
            Capacity:   pill(b.Capacity + "%", b.Capacity < 40 ? "#c92a2a" : "#b06a00"),
            "Runtime":  b.RuntimeMin ? escHtml(Math.floor(b.RuntimeMin / 60) + "h " + (b.RuntimeMin % 60) + "m") : "",
            "Age (days)": escHtml(b.AgeDays),
            Model:      escHtml(b.Model)
        })), ["Device","Capacity","Runtime","Age (days)","Model"]);
    html += '</div><div class="card"><h2>Apps Crashing / Hanging</h2>';
    if (itNa("AppCrash"))      html += itNote("AppCrash");
    else if (!crash.length)    html += '<div class="statusBadge green">None reported</div>';
    else html += buildTable(crash.map(a => ({
            App:       "<b>" + escHtml(a.App) + "</b>",
            Publisher: escHtml(a.Publisher),
            Crashes:   pill(a.Crashes, a.Crashes >= 10 ? "#c92a2a" : "#b06a00"),
            Hangs:     escHtml(a.Hangs),
            Devices:   escHtml(a.Devices)
        })), ["App","Publisher","Crashes","Hangs","Devices"]);
    html += '</div></div>';

    // ================= HARDWARE & PERFORMANCE =================
    const scores    = itRows("Scores");
    const poorDevs  = scores.filter(s => s.Overall > 0 && s.Overall < intune.ScoreWarn);
    const res       = itRows("Resource");
    const resBad    = res.filter(r => r.Issues);
    const ready     = itRows("Readiness");
    const notCap    = ready.filter(r => r.Eligibility === "notCapable");
    const capable   = ready.filter(r => r.Eligibility === "capable");
    const models    = itRows("Models");
    const procs     = itRows("StartupProc");
    const scoreCol  = v => pill(v || "-", !v ? "#6c6c6c" : (v < intune.ScoreWarn ? "#c92a2a" : (v < 70 ? "#b06a00" : "#1a7d2c")));
    const avg       = arr => arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : null;
    const avgScore  = avg(scores.filter(s => s.Overall > 0).map(s => s.Overall));

    html += '<h2 style="margin-top:30px;">Hardware &amp; Performance</h2>';

    html += '<div class="card"><h2>Overview</h2>' +
        (avgScore !== null ? sophosBadge("Average device score " + avgScore + " / 100", avgScore < intune.ScoreWarn ? "red" : (avgScore < 70 ? "orange" : "green")) : "") +
        (scores.length ? sophosBadge(poorDevs.length + " device(s) scoring under " + intune.ScoreWarn, poorDevs.length ? "red" : "green") : "") +
        (res.length ? sophosBadge(resBad.length + " device(s) short of CPU / memory", resBad.length ? "orange" : "green") : "") +
        (ready.length ? sophosBadge(notCap.length + " device(s) can't run Windows 11", notCap.length ? "red" : "green") +
                        sophosBadge(capable.length + " ready for Windows 11 but not upgraded", capable.length ? "orange" : "green") : "") +
        (!scores.length && !res.length && !ready.length && !models.length ? itEaNote() :
            '<p style="font-size:13px;color:#555;white-space:normal;">Scores are out of 100 from Intune Endpoint analytics - under ' + escHtml(intune.ScoreWarn) + ' is poor, 70+ is good.</p>') +
        '</div>';

    // ---- Lowest scoring devices ----
    if (scores.length || itNa("Scores")) {
        html += '<div class="card"><h2>Lowest Scoring Devices</h2>';
        if (itNa("Scores")) html += itNote("Scores");
        else {
            const worst = scores.filter(s => s.Overall > 0).slice(0, 15);
            html += worst.length ? buildTable(worst.map(s => ({
                Device:            "<b>" + escHtml(s.Name) + "</b>",
                Overall:           scoreCol(s.Overall),
                Startup:           scoreCol(s.Startup),
                "App Reliability": scoreCol(s.AppRel),
                Battery:           scoreCol(s.Battery),
                Model:             escHtml(s.Model)
            })), ["Device","Overall","Startup","App Reliability","Battery","Model"]) : '<div class="statusBadge green">No scored devices yet</div>';
        }
        html += '</div>';
    }

    // ---- CPU / memory strain ----
    if (res.length || itNa("Resource")) {
        html += '<div class="card"><h2>CPU &amp; Memory Strain</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Devices whose processor or memory is maxed out more than ' + escHtml(intune.SpikeWarnPct) +
            '% of the time, or with under ' + escHtml(intune.MinRamGB) + ' GB memory - candidates for a memory upgrade or replacement.</p>';
        if (itNa("Resource"))     html += itNote("Resource");
        else if (!resBad.length)  html += '<div class="statusBadge green">No devices short of CPU or memory</div>';
        else html += buildTable(resBad.map(r => ({
                Device:        "<b>" + escHtml(r.Name) + "</b>",
                Issues:        m365Wrap(r.Issues, 280),
                "CPU Maxed %": pill(r.CpuSpike + "%", r.CpuSpike > intune.SpikeWarnPct ? "#c92a2a" : "#1a1a1a"),
                "RAM Maxed %": pill(r.RamSpike + "%", r.RamSpike > intune.SpikeWarnPct ? "#c92a2a" : "#1a1a1a"),
                Memory:        r.RamGB ? pill(r.RamGB + " GB", r.RamGB < intune.MinRamGB ? "#c92a2a" : "#1a1a1a") : "",
                Processor:     escHtml(r.CPU),
                Model:         escHtml(r.Model)
            })), ["Device","Issues","CPU Maxed %","RAM Maxed %","Memory","Processor","Model"]);
        html += '</div>';
    }

    // ---- Windows 11 readiness ----
    if (ready.length || itNa("Readiness")) {
        html += '<div class="card"><h2>Windows 11 Hardware Readiness</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Devices not yet on Windows 11. "Not capable" ones need a hardware fix (often just TPM / Secure Boot switched on in the BIOS) or replacing.</p>';
        if (itNa("Readiness")) html += itNote("Readiness");
        else html += buildTable(ready.map(r => ({
                Device:       "<b>" + escHtml(r.Name) + "</b>",
                "Windows 11": r.Eligibility === "notCapable" ? pill("Not capable", "#c92a2a")
                             : (r.Eligibility === "capable" ? pill("Capable - upgrade it", "#b06a00") : pill(m365Label(r.Eligibility || "unknown"), "#6c6c6c")),
                "Fails On":   m365Wrap(r.Failed, 220),
                "Current OS": escHtml(r.OS),
                Model:        escHtml(r.Model),
                Serial:       escHtml(r.Serial)
            })), ["Device","Windows 11","Fails On","Current OS","Model","Serial"]);
        html += '</div>';
    }

    // ---- Models + boot-slowing programs ----
    if (models.length || procs.length) {
        html += '<div class="halfRow"><div class="card"><h2>Scores by Model</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Worst first - useful for planning replacements.</p>' +
            (models.length ? buildTable(models.map(m => ({
                Model:   "<b>" + escHtml(m.Model) + "</b>",
                Devices: escHtml(m.Devices),
                Overall: scoreCol(m.Overall),
                Startup: scoreCol(m.Startup),
                Battery: scoreCol(m.Battery)
            })), ["Model","Devices","Overall","Startup","Battery"]) : (itNa("Models") ? itNote("Models") : "<p>No data</p>")) +
            '</div><div class="card"><h2>Programs Slowing Down Boot</h2>' +
            '<p style="font-size:13px;color:#555;margin-top:-6px;white-space:normal;">Startup programs adding the most time across all devices.</p>' +
            (procs.length ? buildTable(procs.map(p => ({
                Program:      "<b>" + escHtml(p.Process) + "</b>",
                Product:      escHtml(p.Product),
                Publisher:    escHtml(p.Publisher),
                Devices:      escHtml(p.Devices),
                "Adds (median)": pill(p.MedianSec + " s", p.MedianSec >= 10 ? "#c92a2a" : (p.MedianSec >= 3 ? "#b06a00" : "#1a1a1a"))
            })), ["Program","Product","Publisher","Devices","Adds (median)"]) : (itNa("StartupProc") ? itNote("StartupProc") : "<p>No data</p>")) +
            '</div></div>';
    }

    // ---- App install failures + policy failures ----
    html += '<h2 style="margin-top:30px;">Apps &amp; Policies</h2>';
    html += '<div class="card"><h2>Apps Failing to Install</h2>';
    if (itNa("AppFail"))       html += itNote("AppFail");
    else if (!appFail.length)  html += '<div class="statusBadge green">No app install failures</div>';
    else html += buildTable(appFail.map(a => ({
            App:       "<b>" + escHtml(a.App) + "</b>",
            Publisher: escHtml(a.Publisher),
            Platform:  escHtml(a.Platform),
            Failed:    pill(a.Failed + " (" + a.FailedPct + "%)", "#c92a2a"),
            Installed: escHtml(a.Installed),
            Pending:   escHtml(a.Pending),
            Link:      m365Link(a.Link)
        })), ["App","Publisher","Platform","Failed","Installed","Pending","Link"]);
    html += '</div>';

    html += '<div class="card"><h2>Policies With Errors or Conflicts</h2>';
    if (itNa("Policies"))      html += itNote("Policies");
    else if (!pols.length)     html += '<div class="statusBadge green">No policy errors or conflicts</div>';
    else html += buildTable(pols.map(p => ({
            Policy:    "<b>" + escHtml(p.Policy) + "</b>",
            Type:      escHtml(p.Type),
            "Errors / Not compliant": p.Errors ? pill(p.Errors, "#c92a2a") : "0",
            Conflicts: p.Conflicts ? pill(p.Conflicts, "#b06a00") : "0",
            Succeeded: escHtml(p.Success),
            Pending:   escHtml(p.Pending)
        })), ["Policy","Type","Errors / Not compliant","Conflicts","Succeeded","Pending"]);
    html += '</div>';

    // ---- Coverage gap ----
    if (!itNa("Devices")) {
        html += '<div class="card"><h2>Monitored Devices Not in Intune</h2>' +
            (missing.length ? '<p style="white-space:normal;">' + missing.map(n => escHtml(n)).join(", ") + '</p>'
                            : '<div class="statusBadge green">Every monitored device is managed by Intune</div>') +
            '</div>';
    }

    // ---- All devices ----
    if (!itNa("Devices")) {
        html += '<div class="card"><h2>All Managed Devices</h2>' +
            '<input id="itFilter" class="filterBox" type="text" placeholder="Filter by device, user, model, serial..."> ' +
            '<select id="itOs" style="padding:8px;border:1px solid #d0d0d0;border-radius:8px;margin-bottom:10px;">' +
                '<option value="">All platforms</option><option value="windows">Windows</option><option value="ios">iOS / iPadOS</option>' +
                '<option value="mac">macOS</option><option value="android">Android</option></select>' +
            '<div id="itAllTable"></div></div>';
    }

    itView.innerHTML = html;

    const f = document.getElementById("itFilter");
    if (f) {
        f.oninput = renderItDeviceTable;
        document.getElementById("itOs").onchange = renderItDeviceTable;
        renderItDeviceTable();
    }
}

// Count on the Intune tab button
(function(){
    const el = document.getElementById("itTabCount");
    if (intune.Error) {
        el.innerHTML = ' <span style="background:#FFB347;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">!</span>';
        return;
    }
    const n = itAttentionCount();
    if (n > 0) el.innerHTML = ' <span style="background:#FF6B6B;color:white;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px;">' + n + '</span>';
})();

// ✅ Build page
buildDeviceSelector();
loadDevice(currentDevice);
renderSwitchTab();
renderM365Tab();
renderDefenderTab();
renderIntuneTab();

// Open straight on a tab with Dashboard.html#switches, #m365, #defender or #intune
if (location.hash === "#switches") showTab("tabSwitches");
if (location.hash === "#m365") showTab("tabM365");
if (location.hash === "#defender") showTab("tabDefender");
if (location.hash === "#intune") showTab("tabIntune");

</script>

</body>
</html>
"@

$FullHtml | Out-File $DashboardPath -Encoding UTF8 -Force

Write-Host "✅ Master dashboard updated: $DashboardPath ($($AllDevices.Count) device(s))"

# ================================================================
# EMAIL THE DASHBOARD REPORT (Microsoft Graph)
#
# Sends Dashboard.html as an attachment through Microsoft Graph using a
# read/send-only app registration. No SMTP AUTH, no mailbox password,
# and nothing for MFA / Security Defaults to block - it carries on
# working after Microsoft switches off SMTP Basic auth.
#
# ONE-TIME SETUP (in Southend YMCA's tenant):
#
#   1. entra.microsoft.com > App registrations > New registration
#      Name "YMCA Monitoring Mail", single tenant, no redirect URI.
#   2. API permissions > Add > Microsoft Graph > APPLICATION permissions:
#        Mail.Send
#      then click "Grant admin consent".
#   3. Certificates & secrets > New client secret (24 months). Copy the VALUE.
#      Put a reminder in your calendar - emails stop when it expires (the
#      error shows in the Scheduled Task output).
#   4. Copy the Directory (tenant) ID from the app's Overview page into
#      TenantId below.
#   5. RECOMMENDED - lock the app down so it can only send as the one
#      mailbox (by default Mail.Send can send as ANY mailbox in the tenant).
#      In Exchange Online PowerShell:
#
#        New-DistributionGroup -Name "Monitoring Mail Senders" -Type Security `
#            -PrimarySmtpAddress monitoringsenders@southendymca.org.uk `
#            -Members administrator@southendymca.org.uk
#        New-ApplicationAccessPolicy -AppId <Application (client) ID> `
#            -PolicyScopeGroupId monitoringsenders@southendymca.org.uk `
#            -AccessRight RestrictAccess -Description "Monitoring mail - one mailbox only"
#
#      (Can take up to an hour to apply. Test with
#       Test-ApplicationAccessPolicy -AppId <id> -Identity administrator@southendymca.org.uk)
#   6. Run once, interactively, as the account the Scheduled Task for THIS
#      script runs as (the encryption is tied to that identity):
#
#        $cred = Get-Credential -Message "Username = Application (client) ID, Password = Client secret VALUE"
#        $cred | Export-CliXml -Path "C:\Monitor\graphmail_creds.xml"
#
# The old C:\Monitor\smtp_creds.xml is no longer used and can be deleted.
# ================================================================

$MailConfig = @{
    Enabled   = $true
    TenantId  = "4dae0b82-c3e4-41d6-906d-6c59d0508b58"   # <-- Southend YMCA's Directory (tenant) ID
    CredPath  = "C:\Monitor\graphmail_creds.xml"
    From      = "administrator@southendymca.org.uk"      # mailbox the email is sent from (must exist in the YMCA tenant)
    FromName  = "School Systems Monitoring Checks"
    To        = @("schoolsupport@southend.gov.uk")
    Subject   = "IT Monitoring Dashboard - $env:COMPUTERNAME ($($AllDevices.Count) device(s))"
    SaveToSentItems = $false
}

# Pull Graph's real error text out of a failed request (PowerShell 5.1
# doesn't always fill ErrorDetails, so read the response body too)
function Get-GraphMailError($err) {
    $msg  = $err.Exception.Message
    $body = $null
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) { $body = $err.ErrorDetails.Message }
    elseif ($err.Exception.Response) {
        try { $body = (New-Object System.IO.StreamReader($err.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
    }
    if ($body) {
        try {
            $j = ConvertFrom-Json $body
            if ($j.error.message)         { $msg = "$($j.error.code): $($j.error.message)" }
            elseif ($j.error_description) { $msg = $j.error_description }
        } catch { }
    }
    return $msg
}

function Send-DashboardEmail {
    param(
        [string]$Subject,
        [string]$Body,
        [string[]]$AttachmentPaths = @()
    )
    if (-not $MailConfig.Enabled) { return }

    if ($MailConfig.TenantId -notmatch '^[0-9a-fA-F-]{36}$' -or $MailConfig.TenantId -eq "00000000-0000-0000-0000-000000000000") {
        Write-Host "Email not sent - fill in TenantId in `$MailConfig (see the one-time setup notes above it)" -ForegroundColor Red
        return
    }
    if (!(Test-Path $MailConfig.CredPath)) {
        Write-Host "Email not sent - Graph mail credentials not found at $($MailConfig.CredPath) (see the one-time setup notes above `$MailConfig)" -ForegroundColor Red
        return
    }

    $prevProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $step = "signing in to Microsoft Graph"

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        # 1) App-only access token
        $gc  = Import-CliXml $MailConfig.CredPath
        $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($MailConfig.TenantId)/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                grant_type    = "client_credentials"
                client_id     = $gc.UserName
                client_secret = $gc.GetNetworkCredential().Password
                scope         = "https://graph.microsoft.com/.default"
            } -ErrorAction Stop
        $gh = @{ Authorization = "Bearer $($tok.access_token)" }

        $mailbox = [uri]::EscapeDataString($MailConfig.From)
        $base    = "https://graph.microsoft.com/v1.0/users/$mailbox"

        $message = [ordered]@{
            subject      = $Subject
            body         = @{ contentType = "Text"; content = $Body }
            from         = @{ emailAddress = @{ address = $MailConfig.From; name = $MailConfig.FromName } }
            toRecipients = @($MailConfig.To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
        }

        $files = @(foreach ($path in $AttachmentPaths) {
            if ($path -and (Test-Path $path)) { Get-Item $path }
            else { Write-Host "Attachment not found, skipping: $path" -ForegroundColor Yellow }
        })

        # Graph takes attachments inline only while the whole request stays under
        # ~4 MB (base64 adds a third), so anything over 3 MB goes up in chunks.
        $totalBytes = ($files | Measure-Object Length -Sum).Sum
        if (-not $totalBytes) { $totalBytes = 0 }

        if ($totalBytes -lt 3MB) {
            # 2a) Small: one call
            $step = "sending the email"
            $message.attachments = @($files | ForEach-Object {
                @{
                    "@odata.type" = "#microsoft.graph.fileAttachment"
                    name          = $_.Name
                    contentType   = "text/html"
                    contentBytes  = [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))
                }
            })
            $json = @{ message = $message; saveToSentItems = $MailConfig.SaveToSentItems } | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Method Post -Uri "$base/sendMail" -Headers $gh -ContentType "application/json; charset=utf-8" `
                -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop | Out-Null
        }
        else {
            # 2b) Large: draft -> upload each attachment in chunks -> send
            $step = "creating the draft email"
            $json  = $message | ConvertTo-Json -Depth 10
            $draft = Invoke-RestMethod -Method Post -Uri "$base/messages" -Headers $gh -ContentType "application/json; charset=utf-8" `
                -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop

            foreach ($f in $files) {
                $step = "uploading $($f.Name)"
                $sessBody = @{ AttachmentItem = @{ attachmentType = "file"; name = $f.Name; size = $f.Length; contentType = "text/html" } } | ConvertTo-Json -Depth 5
                $sess = Invoke-RestMethod -Method Post -Uri "$base/messages/$($draft.id)/attachments/createUploadSession" `
                    -Headers $gh -ContentType "application/json" -Body $sessBody -ErrorAction Stop

                $bytes = [IO.File]::ReadAllBytes($f.FullName)
                $chunk = 3276800   # 10 x 320 KiB (chunks must be multiples of 320 KiB)
                for ($pos = 0; $pos -lt $bytes.Length; $pos += $chunk) {
                    $len  = [math]::Min($chunk, $bytes.Length - $pos)
                    $part = New-Object byte[] $len
                    [Array]::Copy($bytes, $pos, $part, 0, $len)
                    # The upload URL is pre-authorised - sending the Bearer token here makes it fail
                    Invoke-WebRequest -Method Put -Uri $sess.uploadUrl -UseBasicParsing -ContentType "application/octet-stream" `
                        -Headers @{ "Content-Range" = "bytes $pos-$($pos + $len - 1)/$($bytes.Length)" } `
                        -Body $part -ErrorAction Stop | Out-Null
                }
            }

            $step = "sending the email"
            Invoke-RestMethod -Method Post -Uri "$base/messages/$($draft.id)/send" -Headers $gh -ErrorAction Stop | Out-Null
        }

        Write-Host "Dashboard report emailed via Microsoft Graph: $Subject" -ForegroundColor Green
    }
    catch {
        $detail = Get-GraphMailError $_
        $hint = ""
        if ($detail -match 'AADSTS7000215|invalid_client')                  { $hint = " - the client secret is wrong or has expired; create a new one and re-save $($MailConfig.CredPath)" }
        elseif ($detail -match 'AADSTS700016|AADSTS90002')                   { $hint = " - check TenantId and the Application (client) ID" }
        elseif ($detail -match 'ErrorAccessDenied|Access is denied|Authorization_RequestDenied|403') {
            $hint = " - check the app has the Mail.Send APPLICATION permission with admin consent, and that any Application Access Policy includes $($MailConfig.From)"
        }
        elseif ($detail -match 'MailboxNotEnabledForRESTAPI|ResourceNotFound|ErrorInvalidUser') {
            $hint = " - $($MailConfig.From) isn't a licensed Exchange Online mailbox in this tenant"
        }
        Write-Host "Failed to email dashboard report ($step): $detail$hint" -ForegroundColor Red
    }
    finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $prevProtocol
    }
}

Send-DashboardEmail -Subject $MailConfig.Subject `
                    -Body "Latest IT monitoring dashboard is attached. Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')." `
                    -AttachmentPaths @($DashboardPath)