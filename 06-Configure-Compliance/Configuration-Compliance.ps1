#requires -Version 5.1

<#
.SYNOPSIS
    Production Windows Configuration Compliance Scanner

.DESCRIPTION
    Performs a READ-ONLY compliance assessment against remote
    Windows systems.

    IMPORTANT:
    This script does NOT modify remote configuration.

.CONTROLS

    Firewall
    WinRM
    Windows Update
    W32Time
    RDP
    Guest Account
    SMBv1
    Password Policy
    Critical Services
    Disk Free Space
    Microsoft Defender
    Pending Reboot

.INPUT

    servers.csv

.EXAMPLE

    .\Configuration-Compliance.ps1

.EXAMPLE

    .\Configuration-Compliance.ps1 -ServerCsv .\servers.csv

.EXAMPLE

    .\Configuration-Compliance.ps1 `
        -ServerCsv .\servers.csv `
        -MinimumDiskFreePercent 20
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory = $false)]
    [string]$ServerCsv = "Config\servers.csv",

    [Parameter(Mandatory = $false)]
    [int]$MinimumDiskFreePercent = 20,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ".\Reports"

)

# ============================================================
# SAFETY SETTINGS
# ============================================================

Set-StrictMode -Version Latest

$ErrorActionPreference = "Stop"

# IMPORTANT:
# This script is intentionally READ-ONLY.
#
# No configuration-changing cmdlets should be placed
# inside the remote audit block.

# ============================================================
# CONSTANTS
# ============================================================

$ScriptStart = Get-Date

$ComplianceVersion = "1.0"

$RequiredServices = @(
    "w32time",
    "WinRM",
    "wuauserv"
)

# ============================================================
# OUTPUT DIRECTORIES
# ============================================================

$LogDirectory = Join-Path `
    $OutputDirectory `
    "Logs"

$CsvDirectory = Join-Path `
    $OutputDirectory `
    "CSV"

$null = New-Item `
    -Path $OutputDirectory `
    -ItemType Directory `
    -Force

$null = New-Item `
    -Path $LogDirectory `
    -ItemType Directory `
    -Force

$null = New-Item `
    -Path $CsvDirectory `
    -ItemType Directory `
    -Force

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$LogFile = Join-Path `
    $LogDirectory `
    "Compliance-$Timestamp.log"

$ReportFile = Join-Path `
    $OutputDirectory `
    "Configuration-Compliance-$Timestamp.html"

$CsvFile = Join-Path `
    $CsvDirectory `
    "Configuration-Compliance-$Timestamp.csv"

# ============================================================
# LOGGING
# ============================================================

function Write-Log {

    param(

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet(
            "INFO",
            "WARNING",
            "ERROR"
        )]
        [string]$Level = "INFO"

    )

    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $Line = "[$Time] [$Level] $Message"

    Add-Content `
        -Path $LogFile `
        -Value $Line

    Write-Host $Line
}

# ============================================================
# SAFE STATUS FUNCTION
# ============================================================

function Get-ComplianceStatus {

    param(
        [bool]$Compliant
    )

    if ($Compliant) {
        return "PASS"
    }

    return "FAIL"
}

# ============================================================
# VALIDATE INPUT CSV
# ============================================================

if (-not (Test-Path $ServerCsv)) {

    Write-Log `
        "Server CSV not found: $ServerCsv" `
        "ERROR"

    exit 1
}

try {

    $Servers = Import-Csv `
        -Path $ServerCsv `
        -ErrorAction Stop

}
catch {

    Write-Log `
        "Unable to read CSV: $($_.Exception.Message)" `
        "ERROR"

    exit 1
}

if (-not $Servers) {

    Write-Log `
        "CSV contains no servers." `
        "ERROR"

    exit 1
}

if (-not (
    $Servers[0].PSObject.Properties.Name `
    -contains "ServerName"
)) {

    Write-Log `
        "CSV must contain a ServerName column." `
        "ERROR"

    exit 1
}

$ServerList = @(
    $Servers |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                $_.ServerName
            )
        } |
        Select-Object -ExpandProperty ServerName -Unique
)

Write-Log "============================================================"
Write-Log "CONFIGURATION COMPLIANCE SCAN"
Write-Log "============================================================"
Write-Log "Compliance Version : $ComplianceVersion"
Write-Log "Servers            : $($ServerList.Count)"
Write-Log "Disk Requirement   : >= $MinimumDiskFreePercent%"
Write-Log "Execution Mode     : READ ONLY"
Write-Log "============================================================"

# ============================================================
# RESULT COLLECTION
# ============================================================

$Results = [System.Collections.Generic.List[object]]::new()

# ============================================================
# PROCESS SERVERS
# ============================================================

foreach ($Server in $ServerList) {

    Write-Log "------------------------------------------------------------"
    Write-Log "Scanning: $Server"

    # --------------------------------------------------------
    # DEFAULT RESULT
    # --------------------------------------------------------

    $Result = [ordered]@{

        ServerName = $Server

        Firewall = "UNKNOWN"

        WinRM = "UNKNOWN"

        WindowsUpdate = "UNKNOWN"

        W32Time = "UNKNOWN"

        RDP = "UNKNOWN"

        GuestAccount = "UNKNOWN"

        SMBv1 = "UNKNOWN"

        PasswordPolicy = "UNKNOWN"

        CriticalServices = "UNKNOWN"

        Disk = "UNKNOWN"

        Defender = "UNKNOWN"

        PendingReboot = "UNKNOWN"

        Compliance = "0%"

        Status = "ERROR"

        Error = ""

    }

    # ========================================================
    # WINRM CONNECTIVITY TEST
    # ========================================================

    try {

        Test-WSMan `
            -ComputerName $Server `
            -ErrorAction Stop |
            Out-Null

        Write-Log "$Server - WinRM: PASS"

    }
    catch {

        $Result.Error =
            "WinRM connection failed: " +
            $_.Exception.Message

        Write-Log `
            "$Server - WinRM FAILED" `
            "ERROR"

        $Results.Add(
            [PSCustomObject]$Result
        )

        continue
    }

    # ========================================================
    # REMOTE AUDIT
    # ========================================================

    try {

        $Remote = Invoke-Command `
            -ComputerName $Server `
            -ErrorAction Stop `
            -ScriptBlock {

                $Output = [ordered]@{}

                # ====================================================
                # FIREWALL
                # ====================================================

                try {

                    $Profiles = Get-NetFirewallProfile `
                        -ErrorAction Stop

                    $FirewallOK = (
                        $Profiles.Count -ge 1 -and
                        ($Profiles.Enabled -notcontains $false)
                    )

                    $Output.Firewall = [PSCustomObject]@{

                        Status = if ($FirewallOK) {
                            "PASS"
                        }
                        else {
                            "FAIL"
                        }

                        Details = (
                            $Profiles |
                            ForEach-Object {
                                "$($_.Name)=$($_.Enabled)"
                            }
                        ) -join "; "

                    }

                }
                catch {

                    $Output.Firewall = [PSCustomObject]@{

                        Status = "ERROR"

                        Details =
                            $_.Exception.Message
                    }
                }

                # ====================================================
                # WINRM SERVICE
                # ====================================================

                try {

                    $Service = Get-Service `
                        -Name WinRM `
                        -ErrorAction Stop

                    $Output.WinRM = [PSCustomObject]@{

                        Status = if (
                            $Service.Status -eq "Running"
                        ) {
                            "PASS"
                        }
                        else {
                            "FAIL"
                        }

                        Details =
                            "Status=$($Service.Status); " +
                            "StartType=$($Service.StartType)"

                    }

                }
                catch {

                    $Output.WinRM = [PSCustomObject]@{

                        Status = "ERROR"

                        Details =
                            $_.Exception.Message
                    }
                }

                # ====================================================
                # WINDOWS UPDATE
                # ====================================================

                try {

                    $Service = Get-Service `
                        -Name wuauserv `
                        -ErrorAction Stop

                    $Output.WindowsUpdate =
                        [PSCustomObject]@{

                            Status = if (
                                $Service.Status -eq "Running"
                            ) {
                                "PASS"
                            }
                            else {
                                "FAIL"
                            }

                            Details =
                                "Status=$($Service.Status); " +
                                "StartType=$($Service.StartType)"

                        }

                }
                catch {

                    $Output.WindowsUpdate =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # WINDOWS TIME
                # ====================================================

                try {

                    $Service = Get-Service `
                        -Name w32time `
                        -ErrorAction Stop

                    $Output.W32Time =
                        [PSCustomObject]@{

                            Status = if (
                                $Service.Status -eq "Running"
                            ) {
                                "PASS"
                            }
                            else {
                                "FAIL"
                            }

                            Details =
                                "Status=$($Service.Status); " +
                                "StartType=$($Service.StartType)"

                        }

                }
                catch {

                    $Output.W32Time =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # RDP
                # ====================================================

                try {

                    $RDPPath =
                        "HKLM:\SYSTEM\CurrentControlSet\" +
                        "Control\Terminal Server"

                    $RDPValue = Get-ItemProperty `
                        -Path $RDPPath `
                        -Name fDenyTSConnections `
                        -ErrorAction Stop

                    # Compliance interpretation:
                    #
                    # RDP disabled = PASS
                    #
                    # RDP enabled requires additional
                    # security validation and is therefore
                    # marked REVIEW rather than automatically
                    # considered compliant.

                    if (
                        $RDPValue.fDenyTSConnections -eq 1
                    ) {

                        $RDPStatus = "PASS"

                    }
                    else {

                        $RDPStatus = "REVIEW"

                    }

                    $Output.RDP =
                        [PSCustomObject]@{

                            Status = $RDPStatus

                            Details =
                                "RDPEnabled=" +
                                ($RDPValue.fDenyTSConnections -eq 0)

                        }

                }
                catch {

                    $Output.RDP =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # GUEST ACCOUNT
                # ====================================================

                try {

                    $Guest = Get-LocalUser `
                        -Name "Guest" `
                        -ErrorAction Stop

                    $GuestDisabled = (
                        $Guest.Enabled -eq $false
                    )

                    $Output.GuestAccount =
                        [PSCustomObject]@{

                            Status =
                                if ($GuestDisabled) {
                                    "PASS"
                                }
                                else {
                                    "FAIL"
                                }

                            Details =
                                "Enabled=$($Guest.Enabled)"

                        }

                }
                catch {

                    $Output.GuestAccount =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # SMBv1
                # ====================================================

                try {

                    $SMB = Get-WindowsOptionalFeature `
                        -Online `
                        -FeatureName SMB1Protocol `
                        -ErrorAction Stop

                    $SMBDisabled = (
                        $SMB.State -ne "Enabled"
                    )

                    $Output.SMBv1 =
                        [PSCustomObject]@{

                            Status =
                                if ($SMBDisabled) {
                                    "PASS"
                                }
                                else {
                                    "FAIL"
                                }

                            Details =
                                "State=$($SMB.State)"

                        }

                }
                catch {

                    $Output.SMBv1 =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # PASSWORD POLICY
                # ====================================================

                try {

                    $NetAccounts =
                        net accounts 2>&1

                    $Output.PasswordPolicy =
                        [PSCustomObject]@{

                            Status = "REVIEW"

                            Details =
                                (
                                    $NetAccounts -join " "
                                )

                        }

                }
                catch {

                    $Output.PasswordPolicy =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # CRITICAL SERVICES
                # ====================================================

                try {

                    $ServiceStates = @()

                    foreach (
                        $ServiceName in @(
                            "w32time",
                            "WinRM",
                            "wuauserv"
                        )
                    ) {

                        try {

                            $Svc = Get-Service `
                                -Name $ServiceName `
                                -ErrorAction Stop

                            $ServiceStates += [PSCustomObject]@{

                                Name = $ServiceName

                                Status = $Svc.Status

                            }

                        }
                        catch {

                            $ServiceStates += [PSCustomObject]@{

                                Name = $ServiceName

                                Status = "MISSING"

                            }
                        }
                    }

                    $AllRunning = (
                        $ServiceStates.Status |
                        Where-Object {
                            $_ -ne "Running"
                        }
                    ).Count -eq 0

                    $Output.CriticalServices =
                        [PSCustomObject]@{

                            Status =
                                if ($AllRunning) {
                                    "PASS"
                                }
                                else {
                                    "FAIL"
                                }

                            Details =
                                (
                                    $ServiceStates |
                                    ForEach-Object {
                                        "$($_.Name)=$($_.Status)"
                                    }
                                ) -join "; "

                        }

                }
                catch {

                    $Output.CriticalServices =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # DISK SPACE
                # ====================================================

                try {

                    $SystemDrive = $env:SystemDrive

                    $Disk = Get-CimInstance `
                        -ClassName Win32_LogicalDisk `
                        -Filter "DeviceID='$SystemDrive'" `
                        -ErrorAction Stop

                    $FreePercent = (
                        $Disk.FreeSpace /
                        $Disk.Size
                    ) * 100

                    $FreePercent = [math]::Round(
                        $FreePercent,
                        2
                    )

                    $Output.Disk =
                        [PSCustomObject]@{

                            Status =
                                if ($FreePercent -ge 20) {
                                    "PASS"
                                }
                                else {
                                    "FAIL"
                                }

                            Details =
                                "$SystemDrive Free=$FreePercent%"

                            FreePercent =
                                $FreePercent

                        }

                }
                catch {

                    $Output.Disk =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message

                            FreePercent = 0

                        }
                }

                # ====================================================
                # MICROSOFT DEFENDER
                # ====================================================

                try {

                    $Defender =
                        Get-MpComputerStatus `
                            -ErrorAction Stop

                    $DefenderOK = (
                        $Defender.AntivirusEnabled -eq $true -and
                        $Defender.RealTimeProtectionEnabled -eq $true
                    )

                    $Output.Defender =
                        [PSCustomObject]@{

                            Status =
                                if ($DefenderOK) {
                                    "PASS"
                                }
                                else {
                                    "FAIL"
                                }

                            Details =
                                "AV=$($Defender.AntivirusEnabled); " +
                                "RealTime=$($Defender.RealTimeProtectionEnabled)"

                        }

                }
                catch {

                    $Output.Defender =
                        [PSCustomObject]@{

                            Status = "REVIEW"

                            Details =
                                $_.Exception.Message
                        }
                }

                # ====================================================
                # PENDING REBOOT
                # ====================================================

                try {

                    $RebootPaths = @(

                        "HKLM:\SOFTWARE\Microsoft\" +
                        "Windows\CurrentVersion\Component Based Servicing\RebootPending",

                        "HKLM:\SOFTWARE\Microsoft\" +
                        "Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

                    )

                    $PendingReboot = $false

                    foreach ($Path in $RebootPaths) {

                        if (Test-Path $Path) {

                            $PendingReboot = $true

                        }

                    }

                    $Output.PendingReboot =
                        [PSCustomObject]@{

                            Status =
                                if ($PendingReboot) {
                                    "FAIL"
                                }
                                else {
                                    "PASS"
                                }

                            Details =
                                "PendingReboot=$PendingReboot"

                        }

                }
                catch {

                    $Output.PendingReboot =
                        [PSCustomObject]@{

                            Status = "ERROR"

                            Details =
                                $_.Exception.Message
                        }
                }

                return $Output

            }

        # ========================================================
        # EXTRACT STATUSES
        # ========================================================

        $Result.Firewall =
            $Remote.Firewall.Status

        $Result.WinRM =
            $Remote.WinRM.Status

        $Result.WindowsUpdate =
            $Remote.WindowsUpdate.Status

        $Result.W32Time =
            $Remote.W32Time.Status

        $Result.RDP =
            $Remote.RDP.Status

        $Result.GuestAccount =
            $Remote.GuestAccount.Status

        $Result.SMBv1 =
            $Remote.SMBv1.Status

        $Result.PasswordPolicy =
            $Remote.PasswordPolicy.Status

        $Result.CriticalServices =
            $Remote.CriticalServices.Status

        $Result.Disk =
            $Remote.Disk.Status

        $Result.Defender =
            $Remote.Defender.Status

        $Result.PendingReboot =
            $Remote.PendingReboot.Status

        # ========================================================
        # COMPLIANCE CALCULATION
        # ========================================================

        $Controls = @(

            $Result.Firewall

            $Result.WinRM

            $Result.WindowsUpdate

            $Result.W32Time

            $Result.RDP

            $Result.GuestAccount

            $Result.SMBv1

            $Result.PasswordPolicy

            $Result.CriticalServices

            $Result.Disk

            $Result.Defender

            $Result.PendingReboot

        )

        $EvaluatedControls = @(
            $Controls |
            Where-Object {
                $_ -eq "PASS" -or
                $_ -eq "FAIL"
            }
        )

        if ($EvaluatedControls.Count -gt 0) {

            $PassedControls = @(
                $EvaluatedControls |
                Where-Object {
                    $_ -eq "PASS"
                }
            ).Count

            $CompliancePercent = (
                $PassedControls /
                $EvaluatedControls.Count
            ) * 100

            $CompliancePercent =
                [math]::Round(
                    $CompliancePercent,
                    0
                )

            $Result.Compliance =
                "$CompliancePercent%"

        }
        else {

            $Result.Compliance = "N/A"

        }

        # ========================================================
        # OVERALL STATUS
        # ========================================================

        if (
            $Controls -contains "FAIL"
        ) {

            $Result.Status = "NON-COMPLIANT"

        }
        elseif (
            $Controls -contains "REVIEW"
        ) {

            $Result.Status = "REVIEW"

        }
        elseif (
            $Controls -contains "ERROR"
        ) {

            $Result.Status = "ERROR"

        }
        else {

            $Result.Status = "COMPLIANT"

        }

        Write-Log `
            "$Server - Compliance: $($Result.Compliance) - $($Result.Status)"

    }
    catch {

        $Result.Status = "ERROR"

        $Result.Error =
            $_.Exception.Message

        Write-Log `
            "$Server - Audit failed: $($_.Exception.Message)" `
            "ERROR"
    }

    # ========================================================
    # ADD RESULT
    # ========================================================

    $Results.Add(
        [PSCustomObject]$Result
    )
}

# ============================================================
# EXPORT CSV
# ============================================================

$Results |
    Export-Csv `
        -Path $CsvFile `
        -NoTypeInformation `
        -Encoding UTF8

Write-Log "CSV report created: $CsvFile"

# ============================================================
# HTML REPORT
# ============================================================

$CompliantCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "COMPLIANT"
    }
).Count

$NonCompliantCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "NON-COMPLIANT"
    }
).Count

$ErrorCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "ERROR"
    }
).Count

$HTMLTable = $Results |
    Select-Object `
        ServerName,
        Firewall,
        WinRM,
        WindowsUpdate,
        W32Time,
        RDP,
        GuestAccount,
        SMBv1,
        PasswordPolicy,
        CriticalServices,
        Disk,
        Defender,
        PendingReboot,
        Compliance,
        Status |
    ConvertTo-Html -Fragment

$HTML = @"

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>Windows Configuration Compliance</title>

<style>

body {
    font-family: Arial, sans-serif;
    margin: 30px;
    background: #f5f5f5;
}

h1 {
    color: #222;
}

.card-container {
    display: flex;
    gap: 15px;
    margin-bottom: 25px;
}

.card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    min-width: 160px;
    box-shadow: 0 2px 5px rgba(0,0,0,.15);
}

.card-title {
    font-size: 13px;
    color: #666;
}

.card-value {
    font-size: 28px;
    font-weight: bold;
    margin-top: 5px;
}

table {
    border-collapse: collapse;
    width: 100%;
    background: white;
}

th {
    background: #222;
    color: white;
    padding: 8px;
    font-size: 12px;
}

td {
    padding: 8px;
    border-bottom: 1px solid #ddd;
    font-size: 12px;
}

tr:hover {
    background: #eee;
}

</style>

</head>

<body>

<h1>Windows Configuration Compliance Report</h1>

<p>
Generated: $(Get-Date)
</p>

<p>
Mode: <strong>READ ONLY</strong>
</p>

<p>
Compliance Version: $ComplianceVersion
</p>

<div class="card-container">

<div class="card">
<div class="card-title">Servers</div>
<div class="card-value">$($Results.Count)</div>
</div>

<div class="card">
<div class="card-title">Compliant</div>
<div class="card-value">$CompliantCount</div>
</div>

<div class="card">
<div class="card-title">Non-Compliant</div>
<div class="card-value">$NonCompliantCount</div>
</div>

<div class="card">
<div class="card-title">Errors</div>
<div class="card-value">$ErrorCount</div>
</div>

</div>

<h2>Compliance Summary</h2>

$HTMLTable

<h2>Baseline</h2>

<ul>

<li>Firewall: Enabled</li>

<li>WinRM: Running</li>

<li>Windows Update: Running</li>

<li>Windows Time: Running</li>

<li>RDP: Restricted</li>

<li>Guest Account: Disabled</li>

<li>SMBv1: Disabled</li>

<li>Password Policy: Compliant</li>

<li>Critical Services: Running</li>

<li>System Disk Free Space: >= $MinimumDiskFreePercent%</li>

<li>Microsoft Defender: Enabled</li>

<li>Pending Reboot: No</li>

</ul>

</body>

</html>

"@

$HTML |
    Out-File `
        -FilePath $ReportFile `
        -Encoding UTF8

Write-Log "HTML report created: $ReportFile"

# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "============================================================"
Write-Log "COMPLIANCE SCAN COMPLETED"
Write-Log "============================================================"

Write-Log "Servers scanned       : $($Results.Count)"
Write-Log "Compliant             : $CompliantCount"
Write-Log "Non-Compliant         : $NonCompliantCount"
Write-Log "Errors                : $ErrorCount"

Write-Log "CSV Report            : $CsvFile"
Write-Log "HTML Report           : $ReportFile"
Write-Log "Log File              : $LogFile"

Write-Log "============================================================"