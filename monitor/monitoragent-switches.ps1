<#
.SYNOPSIS
    Monitor-SwitchAgent.ps1 - polls network switches via SNMP and exports CSVs
    for Monitor-Master2 to collect.

.DESCRIPTION
    Runs centrally (e.g. hourly scheduled task on the management server).
    For each switch in the inventory (and optionally any discovered on a subnet
    sweep) it collects system info, CPU, port status, port utilisation and
    error/discard counts, then writes:

      <OutputPath>\Switch_<Name>.csv       one summary row per switch
      <OutputPath>\SwitchPorts_<Name>.csv  one row per physical port

    Files are written to a temp name then renamed, so Monitor-Master2 never
    reads a half-written CSV. Error/discard counts are deltas since the
    previous run (state kept in -StatePath).

.REQUIREMENTS
    SharpSnmpLib.dll (free, MIT). Download the "Lextm.SharpSnmpLib" package from
    nuget.org, rename .nupkg to .zip, extract lib\netstandard2.0\SharpSnmpLib.dll
    next to this script (or pass -SnmpDllPath). SNMP v2c must be enabled on the
    switches with a read-only community.

.EXAMPLE
    .\Monitor-SwitchAgent.ps1 -InventoryPath .\switches.csv -OutputPath \\SERVER\Monitor$\Switches

.EXAMPLE
    .\Monitor-SwitchAgent.ps1 -InventoryPath .\switches.csv -ScanSubnet 10.10.1 -Community "readonly"
#>
[CmdletBinding()]
param(
    # CSV with columns: Name,IP[,Community][,Site]
    [string]$InventoryPath,

    # Share Monitor-Master2 reads from
    [string]$OutputPath = "\\ymca-host-02\monitor\reports\monitorshare\Switches",

    # Default community if the inventory row has none
    [string]$Community = "public",

    # Optional: first three octets of subnets to sweep for extra switches, e.g. 10.10.1
    [string[]]$ScanSubnet = @(),

    [string]$SnmpDllPath,
    [string]$StatePath,
    [string]$LogPath,

    [int]$TimeoutMs     = 2000,
    [int]$SampleSeconds = 30,    # gap between the two counter samples for utilisation

    # Thresholds for Status/Alerts
    [int]$CpuWarnPct        = 80,
    [int]$PortUtilWarnPct   = 80,
    [int]$ErrorWarnCount    = 100,  # errors+discards on one port since last run
    [double]$RebootWarnDays = 1
)

$ErrorActionPreference = 'Stop'

# Resolve the script's own folder (PS 5.1 can leave $PSScriptRoot empty in param defaults)
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir -and $MyInvocation.MyCommand.Path) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
if (-not $InventoryPath) { $InventoryPath = Join-Path $ScriptDir 'switches.csv' }
if (-not $SnmpDllPath)   { $SnmpDllPath   = Join-Path $ScriptDir 'SharpSnmpLib.dll' }
if (-not $StatePath)     { $StatePath     = Join-Path $ScriptDir 'state' }
if (-not $LogPath)       { $LogPath       = Join-Path $ScriptDir 'logs' }

# ---------------------------------------------------------------- setup
foreach ($p in $StatePath, $LogPath) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null } }
$LogFile = Join-Path $LogPath ("SwitchAgent_{0:yyyyMMdd}.log" -f (Get-Date))

function Write-Log([string]$Msg, [string]$Level = 'INFO') {
    $line = "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}" -f (Get-Date), $Level, $Msg
    Add-Content -Path $LogFile -Value $line
    Write-Verbose $line
}

if (-not (Test-Path $SnmpDllPath)) { throw "SharpSnmpLib.dll not found at $SnmpDllPath - see .REQUIREMENTS in the script header." }
# Load the SNMP library from its bytes rather than its path. .NET blocks
# loading a DLL straight from a network share (\\server\share), which is
# what "Could not load file or assembly ... or one of its dependencies" means
# when the script is run from a UNC path.
if (-not ('Lextm.SharpSnmpLib.Messaging.Messenger' -as [type])) {
    try {
        [void][System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes($SnmpDllPath))
    } catch {
        throw "Could not load $SnmpDllPath : $($_.Exception.Message). Copy SharpSnmpLib.dll to a local folder (e.g. C:\monitor) and pass -SnmpDllPath."
    }
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# Tidy old logs (keep 1 month, matching the monitoring retention)
Get-ChildItem $LogPath -Filter *.log | Where-Object LastWriteTime -lt (Get-Date).AddDays(-31) | Remove-Item -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- OIDs
$OID = @{
    sysDescr     = '1.3.6.1.2.1.1.1.0'
    sysObjectID  = '1.3.6.1.2.1.1.2.0'
    sysUpTime    = '1.3.6.1.2.1.1.3.0'
    sysContact   = '1.3.6.1.2.1.1.4.0'
    sysName      = '1.3.6.1.2.1.1.5.0'
    sysLocation  = '1.3.6.1.2.1.1.6.0'
    sysServices  = '1.3.6.1.2.1.1.7.0'
    ifDescr      = '1.3.6.1.2.1.2.2.1.2'
    ifType       = '1.3.6.1.2.1.2.2.1.3'
    ifAdmin      = '1.3.6.1.2.1.2.2.1.7'
    ifOper       = '1.3.6.1.2.1.2.2.1.8'
    ifLastChange = '1.3.6.1.2.1.2.2.1.9'
    ifInDiscards = '1.3.6.1.2.1.2.2.1.13'
    ifInErrors   = '1.3.6.1.2.1.2.2.1.14'
    ifOutDiscards= '1.3.6.1.2.1.2.2.1.19'
    ifOutErrors  = '1.3.6.1.2.1.2.2.1.20'
    ifName       = '1.3.6.1.2.1.31.1.1.1.1'
    ifHCIn       = '1.3.6.1.2.1.31.1.1.1.6'
    ifHCOut      = '1.3.6.1.2.1.31.1.1.1.10'
    ifHighSpeed  = '1.3.6.1.2.1.31.1.1.1.15'
    ifAlias      = '1.3.6.1.2.1.31.1.1.1.18'
}

# CPU OIDs tried in order - first that answers wins (vendor-specific)
$CpuSources = @(
    @{ Vendor = 'Cisco';          Oid = '1.3.6.1.4.1.9.9.109.1.1.1.1.8';       Walk = $true  }  # cpmCPUTotal5minRev
    @{ Vendor = 'HPE/Aruba';      Oid = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0';  Walk = $false }  # hpSwitchCpuStat
    @{ Vendor = 'Netgear';        Oid = '1.3.6.1.4.1.4526.10.1.1.4.9.0';       Walk = $false }  # agentSwitchCpuProcessTotalUtilization (string)
    @{ Vendor = 'HOST-RESOURCES'; Oid = '1.3.6.1.2.1.25.3.3.1.2';              Walk = $true  }  # hrProcessorLoad
)

$PhysicalIfTypes = @(6, 117)   # ethernetCsmacd, gigabitEthernet

# ---------------------------------------------------------------- SNMP helpers
function ConvertFrom-SnmpData($Data) {
    switch ($Data.TypeCode) {
        ([Lextm.SharpSnmpLib.SnmpType]::NoSuchObject)   { return $null }
        ([Lextm.SharpSnmpLib.SnmpType]::NoSuchInstance) { return $null }
        ([Lextm.SharpSnmpLib.SnmpType]::EndOfMibView)   { return $null }
        ([Lextm.SharpSnmpLib.SnmpType]::TimeTicks)      { return ([Lextm.SharpSnmpLib.TimeTicks]$Data).ToUInt32() }
        default                                          { return $Data.ToString() }
    }
}

function New-SnmpTarget([string]$Ip, [string]$Comm) {
    [pscustomobject]@{
        EndPoint  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Ip), 161)
        Community = [Lextm.SharpSnmpLib.OctetString]::new($Comm)
    }
}

function Get-SnmpValues($Target, [string[]]$Oids, [int]$Timeout = $TimeoutMs) {
    $list = [System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()
    foreach ($o in $Oids) { $list.Add([Lextm.SharpSnmpLib.Variable]::new([Lextm.SharpSnmpLib.ObjectIdentifier]::new($o))) }
    $res = [Lextm.SharpSnmpLib.Messaging.Messenger]::Get(
        [Lextm.SharpSnmpLib.VersionCode]::V2, $Target.EndPoint, $Target.Community, $list, $Timeout)
    $out = @{}
    foreach ($v in $res) { $out[$v.Id.ToString()] = ConvertFrom-SnmpData $v.Data }
    return $out
}

# Walks a column; returns hashtable of ifIndex(last OID segment) -> value
function Get-SnmpColumn($Target, [string]$Oid) {
    $list = [System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()
    try {
        [void][Lextm.SharpSnmpLib.Messaging.Messenger]::Walk(
            [Lextm.SharpSnmpLib.VersionCode]::V2, $Target.EndPoint, $Target.Community,
            [Lextm.SharpSnmpLib.ObjectIdentifier]::new($Oid), $list, $TimeoutMs,
            [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree)
    } catch { Write-Log "Walk $Oid failed on $($Target.EndPoint): $($_.Exception.Message)" 'WARN' }
    $out = @{}
    foreach ($v in $list) {
        $idx = [int]($v.Id.ToString().Split('.')[-1])
        $out[$idx] = ConvertFrom-SnmpData $v.Data
    }
    return $out
}

function Get-SwitchCpu($Target) {
    foreach ($src in $CpuSources) {
        try {
            if ($src.Walk) {
                $vals = (Get-SnmpColumn $Target $src.Oid).Values | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
                if ($vals) { return [math]::Round(($vals | Measure-Object -Average).Average, 0) }
            } else {
                $v = (Get-SnmpValues $Target @($src.Oid)).Values | Select-Object -First 1
                # Netgear returns e.g. "5 Secs ( 12.5%) ..." - take the first percentage
                if ($v -match '(\d+(\.\d+)?)\s*%') { return [math]::Round([double]$Matches[1], 0) }
                if ($v -match '^\d+$')            { return [int]$v }
            }
        } catch { }
    }
    return $null
}

# ---------------------------------------------------------------- build switch list
$Switches = [System.Collections.Generic.List[object]]::new()
if (Test-Path $InventoryPath) {
    foreach ($row in Import-Csv $InventoryPath) {
        if (-not $row.IP) { continue }
        $Switches.Add([pscustomobject]@{
            Name      = if ($row.Name) { $row.Name } else { $row.IP }
            IP        = $row.IP.Trim()
            Community = if ($row.Community) { $row.Community } else { $Community }
            Site      = $row.Site
        })
    }
} else { Write-Log "Inventory $InventoryPath not found" 'WARN' }

foreach ($net in $ScanSubnet) {
    Write-Log "Scanning $net.1-254 for SNMP switches"
    foreach ($h in 1..254) {
        $ip = "$net.$h"
        if ($Switches.IP -contains $ip) { continue }
        try {
            $t = New-SnmpTarget $ip $Community
            $r = Get-SnmpValues $t @($OID.sysServices, $OID.sysName) 300
            $svc = [int]$r[$OID.sysServices]
            # sysServices bit 2 = layer 2 (bridging). Excludes PCs/printers that answer SNMP.
            if ($svc -band 2) {
                $Switches.Add([pscustomobject]@{ Name = $r[$OID.sysName]; IP = $ip; Community = $Community; Site = 'Discovered' })
                Write-Log "Discovered switch $ip ($($r[$OID.sysName]))"
            }
        } catch { }
    }
}

if ($Switches.Count -eq 0) { Write-Log "No switches to poll" 'ERROR'; exit 1 }
Write-Log "Polling $($Switches.Count) switch(es)"
Write-Host ""
Write-Host "Polling $($Switches.Count) switch(es) - output folder: $OutputPath" -ForegroundColor Cyan
$i = 0

# ---------------------------------------------------------------- output helper
$Exported = [System.Collections.Generic.List[object]]::new()

function Export-CsvAtomic($Data, [string]$Path, [string]$What) {
    $tmp  = "$Path.tmp"
    $rows = @($Data).Count
    $Data | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
    Move-Item -Path $tmp -Destination $Path -Force
    Write-Host ("    Exported {0,-13} {1,4} row(s) -> {2}" -f $What, $rows, $Path) -ForegroundColor Gray
    Write-Log  "Exported $What ($rows rows) to $Path"
    $Exported.Add([pscustomobject]@{ File = $Path; Rows = $rows })
}

function Get-SafeName([string]$s) { ($s -replace '[\\/:*?"<>|\s]', '_') }

# ---------------------------------------------------------------- poll
foreach ($sw in $Switches) {
    $i++
    Write-Host ""
    Write-Host ("[{0}/{1}] {2} ({3})" -f $i, $Switches.Count, $sw.Name, $sw.IP) -ForegroundColor White
    $now      = Get-Date
    $safe     = Get-SafeName $sw.Name
    $alerts   = [System.Collections.Generic.List[string]]::new()
    $pingMs   = $null
    $summary  = [ordered]@{
        Timestamp      = $now.ToString('yyyy-MM-dd HH:mm:ss')
        DeviceType     = 'Switch'
        Name           = $sw.Name
        IP             = $sw.IP
        Site           = $sw.Site
        Reachable      = $false
        PingMs         = $null
        SysName        = $null
        Description    = $null
        Location       = $null
        Contact        = $null
        UptimeDays     = $null
        CpuPct         = $null
        PortsTotal     = $null
        PortsUp        = $null
        PortsDown      = $null
        PortsAdminDown = $null
        PortsWithErrors= $null
        BusiestPort    = $null
        BusiestPortPct = $null
        Status         = 'Critical'
        Alerts         = $null
    }

    try {
        $p = Test-Connection -ComputerName $sw.IP -Count 2 -ErrorAction SilentlyContinue
        if ($p) { $pingMs = [math]::Round(($p | Measure-Object ResponseTime -Average).Average, 0) }
        $summary.PingMs = $pingMs

        $t   = New-SnmpTarget $sw.IP $sw.Community
        $sys = Get-SnmpValues $t @($OID.sysDescr, $OID.sysUpTime, $OID.sysContact, $OID.sysName, $OID.sysLocation)
        $summary.Reachable   = $true
        $summary.SysName     = $sys[$OID.sysName]
        $summary.Description = ($sys[$OID.sysDescr] -replace '\s+', ' ').Trim()
        $summary.Location    = $sys[$OID.sysLocation]
        $summary.Contact     = $sys[$OID.sysContact]
        $uptimeTicks         = [double]$sys[$OID.sysUpTime]
        $summary.UptimeDays  = [math]::Round($uptimeTicks / 100 / 86400, 2)

        $summary.CpuPct = Get-SwitchCpu $t

        # Interface tables
        $ifDescr  = Get-SnmpColumn $t $OID.ifDescr
        $ifName   = Get-SnmpColumn $t $OID.ifName
        $ifAlias  = Get-SnmpColumn $t $OID.ifAlias
        $ifType   = Get-SnmpColumn $t $OID.ifType
        $ifAdmin  = Get-SnmpColumn $t $OID.ifAdmin
        $ifOper   = Get-SnmpColumn $t $OID.ifOper
        $ifLast   = Get-SnmpColumn $t $OID.ifLastChange
        $ifSpeed  = Get-SnmpColumn $t $OID.ifHighSpeed
        $inErr    = Get-SnmpColumn $t $OID.ifInErrors
        $outErr   = Get-SnmpColumn $t $OID.ifOutErrors
        $inDisc   = Get-SnmpColumn $t $OID.ifInDiscards
        $outDisc  = Get-SnmpColumn $t $OID.ifOutDiscards

        # Two octet samples for live utilisation
        $in1  = Get-SnmpColumn $t $OID.ifHCIn;  $out1 = Get-SnmpColumn $t $OID.ifHCOut
        $sw1  = [Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Seconds $SampleSeconds
        $in2  = Get-SnmpColumn $t $OID.ifHCIn;  $out2 = Get-SnmpColumn $t $OID.ifHCOut
        $secs = $sw1.Elapsed.TotalSeconds

        # Previous-run counters for error deltas
        $stateFile = Join-Path $StatePath "$safe.json"
        $prev = @{}
        if (Test-Path $stateFile) {
            try {
                $j = Get-Content $stateFile -Raw | ConvertFrom-Json
                if ([double]$j.UptimeTicks -le $uptimeTicks) {     # ignore if switch rebooted (counters reset)
                    foreach ($prop in $j.Ports.PSObject.Properties) { $prev[[int]$prop.Name] = $prop.Value }
                }
            } catch { Write-Log "State file unreadable for $($sw.Name), resetting" 'WARN' }
        }
        $newState = @{}

        $ports = foreach ($idx in ($ifType.Keys | Sort-Object)) {
            if ($PhysicalIfTypes -notcontains [int]$ifType[$idx]) { continue }

            $speed = [double]$ifSpeed[$idx]                     # Mbps
            $inMbps = $outMbps = $util = $null
            if ($in1.ContainsKey($idx) -and $in2.ContainsKey($idx) -and $secs -gt 0) {
                $dIn  = [decimal]$in2[$idx]  - [decimal]$in1[$idx]
                $dOut = [decimal]$out2[$idx] - [decimal]$out1[$idx]
                if ($dIn -ge 0 -and $dOut -ge 0) {
                    $inMbps  = [math]::Round([double]$dIn  * 8 / $secs / 1e6, 2)
                    $outMbps = [math]::Round([double]$dOut * 8 / $secs / 1e6, 2)
                    if ($speed -gt 0) { $util = [math]::Round(([math]::Max($inMbps, $outMbps) / $speed) * 100, 1) }
                }
            }

            $cur = @{
                InErr = [decimal]$inErr[$idx]; OutErr = [decimal]$outErr[$idx]
                InDisc = [decimal]$inDisc[$idx]; OutDisc = [decimal]$outDisc[$idx]
            }
            $newState["$idx"] = $cur
            $d = @{ InErr = $null; OutErr = $null; InDisc = $null; OutDisc = $null }
            if ($prev.ContainsKey($idx)) {
                foreach ($k in 'InErr','OutErr','InDisc','OutDisc') {
                    $delta = $cur[$k] - [decimal]$prev[$idx].$k
                    $d[$k] = if ($delta -ge 0) { $delta } else { $null }   # counter wrapped/reset
                }
            }

            # ifLastChange is sysUpTime at last state change
            $lastChange = $null
            if ($ifLast[$idx] -ne $null -and [double]$ifLast[$idx] -gt 0) {
                $lastChange = $now.AddSeconds(-(($uptimeTicks - [double]$ifLast[$idx]) / 100)).ToString('yyyy-MM-dd HH:mm')
            }

            [pscustomobject][ordered]@{
                Timestamp      = $summary.Timestamp
                Switch         = $sw.Name
                IP             = $sw.IP
                IfIndex        = $idx
                Port           = if ($ifName[$idx]) { $ifName[$idx] } else { $ifDescr[$idx] }
                Description    = $ifAlias[$idx]
                Admin          = switch ([int]$ifAdmin[$idx]) { 1 {'Up'} 2 {'Down'} 3 {'Testing'} default {'Unknown'} }
                Oper           = switch ([int]$ifOper[$idx])  { 1 {'Up'} 2 {'Down'} 3 {'Testing'} 5 {'Dormant'} 7 {'LowerLayerDown'} default {'Unknown'} }
                SpeedMbps      = if ([int]$ifOper[$idx] -eq 1) { $speed } else { $null }
                InMbps         = $inMbps
                OutMbps        = $outMbps
                UtilPct        = $util
                InErrors       = $d.InErr
                OutErrors      = $d.OutErr
                InDiscards     = $d.InDisc
                OutDiscards    = $d.OutDisc
                LastChange     = $lastChange
            }
        }

        @{ UptimeTicks = $uptimeTicks; Saved = $summary.Timestamp; Ports = $newState } |
            ConvertTo-Json -Depth 4 | Set-Content -Path $stateFile -Encoding UTF8

        # Summary figures
        $ports = @($ports)
        $summary.PortsTotal     = $ports.Count
        $summary.PortsUp        = @($ports | Where-Object Oper -eq 'Up').Count
        $summary.PortsAdminDown = @($ports | Where-Object Admin -eq 'Down').Count
        $summary.PortsDown      = @($ports | Where-Object { $_.Admin -eq 'Up' -and $_.Oper -ne 'Up' }).Count

        $errPorts = @($ports | Where-Object {
            (($_.InErrors, $_.OutErrors, $_.InDiscards, $_.OutDiscards | Where-Object { $_ -ne $null } | Measure-Object -Sum).Sum) -ge $ErrorWarnCount })
        $summary.PortsWithErrors = $errPorts.Count

        $busiest = $ports | Where-Object UtilPct -ne $null | Sort-Object UtilPct -Descending | Select-Object -First 1
        if ($busiest) { $summary.BusiestPort = $busiest.Port; $summary.BusiestPortPct = $busiest.UtilPct }

        # Status
        if ($summary.UptimeDays -lt $RebootWarnDays)                 { $alerts.Add("Rebooted in last $RebootWarnDays day(s)") }
        if ($summary.CpuPct -ne $null -and $summary.CpuPct -ge $CpuWarnPct) { $alerts.Add("CPU $($summary.CpuPct)%") }
        if ($busiest -and $busiest.UtilPct -ge $PortUtilWarnPct)     { $alerts.Add("$($busiest.Port) at $($busiest.UtilPct)%") }
        if ($errPorts.Count)                                         { $alerts.Add("Errors on: " + (($errPorts.Port | Select-Object -First 5) -join ', ')) }
        if ($pingMs -eq $null)                                       { $alerts.Add("No ping reply (SNMP OK)") }

        $summary.Status = if ($alerts.Count) { 'Warning' } else { 'OK' }
        $summary.Alerts = $alerts -join '; '

        Export-CsvAtomic $ports (Join-Path $OutputPath "SwitchPorts_$safe.csv") 'port detail' 
        Write-Log "$($sw.Name) OK - $($summary.PortsUp)/$($summary.PortsTotal) ports up, status $($summary.Status)"
    }
    catch {
        $summary.Alerts = if ($pingMs -ne $null) { "SNMP not responding (ping OK - check community/ACL)" } else { "Unreachable" }
        Write-Host "    FAILED: $($summary.Alerts) - $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "$($sw.Name) ($($sw.IP)) failed: $($_.Exception.Message)" 'ERROR'
    }

    Export-CsvAtomic ([pscustomobject]$summary) (Join-Path $OutputPath "Switch_$safe.csv") 'summary'
    $colour = switch ($summary.Status) { 'OK' {'Green'} 'Warning' {'Yellow'} default {'Red'} }
    $detail = if ($summary.Reachable) { "$($summary.PortsUp)/$($summary.PortsTotal) ports up, CPU $($summary.CpuPct)%, uptime $($summary.UptimeDays) days" } else { $summary.Alerts }
    Write-Host "    Status: $($summary.Status) - $detail" -ForegroundColor $colour
    if ($summary.Reachable -and $summary.Alerts) { Write-Host "    Alerts: $($summary.Alerts)" -ForegroundColor Yellow }
}

Write-Log "Run complete"
Write-Host ""
Write-Host "Done. $($Exported.Count) file(s) exported to $OutputPath" -ForegroundColor Cyan
$Exported | Format-Table @{n='File';e={Split-Path $_.File -Leaf}}, Rows -AutoSize
Write-Host "Log: $LogFile" -ForegroundColor Gray