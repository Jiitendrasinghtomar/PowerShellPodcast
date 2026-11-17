#requires -Version 5.1

<#
.SYNOPSIS
    Enterprise Windows Security Audit

.DESCRIPTION
    Performs:
        1. Local Administrators group audit
        2. Security Event Log investigation

    Target systems are read from a CSV file.

.EVENTS
    4624 - Successful logon
    4625 - Failed logon
    4672 - Special privileges assigned
    4720 - User created
    4726 - User deleted
    4728 - Member added to global security group
    4732 - Member added to local security group
    4740 - Account locked out

.NOTES
    Read-only security audit.
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory = $false)]
    [string]$ServerCsv = "C:\Users\Administrator.DC\Desktop\AD-Administration\05-Security-Automation\Config\servers.csv",

    [Parameter(Mandatory = $false)]
    [int]$Days = 7,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "C:\Users\Administrator.DC\Desktop\AD-Administration\05-Security-Automation\SecurityAudit"

)

# ============================================================
# CONFIGURATION
# ============================================================

$ErrorActionPreference = "Continue"

$EventIDs = @(
    4624,
    4625,
    4672,
    4720,
    4726,
    4728,
    4732,
    4740
)

$StartTime = (Get-Date).AddDays(-$Days)

# ============================================================
# CREATE OUTPUT DIRECTORIES
# ============================================================

$null = New-Item `
    -Path $OutputDirectory `
    -ItemType Directory `
    -Force

$LogDirectory = Join-Path $OutputDirectory "Logs"

$null = New-Item `
    -Path $LogDirectory `
    -ItemType Directory `
    -Force

$LocalAdminCsv = Join-Path `
    $OutputDirectory `
    "LocalAdminAudit.csv"

$SecurityEventCsv = Join-Path `
    $OutputDirectory `
    "SecurityEventAudit.csv"

$HtmlReport = Join-Path `
    $OutputDirectory `
    "SecurityAudit.html"

$LogFile = Join-Path `
    $LogDirectory `
    "SecurityAudit.log"

# ============================================================
# LOGGING FUNCTION
# ============================================================

function Write-Log {

    param(
        [string]$Message,

        [ValidateSet(
            "INFO",
            "WARNING",
            "ERROR"
        )]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $Line = "[$Timestamp] [$Level] $Message"

    Add-Content `
        -Path $LogFile `
        -Value $Line

    Write-Host $Line
}

# ============================================================
# EVENT ID DESCRIPTION
# ============================================================

function Get-EventDescription {

    param(
        [int]$EventID
    )

    switch ($EventID) {

        4624 {
            "Successful Logon"
        }

        4625 {
            "Failed Logon"
        }

        4672 {
            "Special Privileges Assigned"
        }

        4720 {
            "User Account Created"
        }

        4726 {
            "User Account Deleted"
        }

        4728 {
            "Member Added To Global Security Group"
        }

        4732 {
            "Member Added To Local Security Group"
        }

        4740 {
            "User Account Locked Out"
        }

        default {
            "Unknown Event"
        }
    }
}

# ============================================================
# VALIDATE CSV
# ============================================================

if (-not (Test-Path $ServerCsv)) {

    Write-Log `
        "Server CSV not found: $ServerCsv" `
        "ERROR"

    exit 1
}

try {

    $Servers = Import-Csv $ServerCsv

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

if (-not ($Servers[0].PSObject.Properties.Name -contains "ServerName")) {

    Write-Log `
        "CSV must contain a column named ServerName." `
        "ERROR"

    exit 1
}

$ServerList = $Servers |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ServerName)
    } |
    Select-Object -ExpandProperty ServerName -Unique

Write-Log "============================================================"
Write-Log "SECURITY AUDIT STARTED"
Write-Log "============================================================"
Write-Log "Servers discovered: $($ServerList.Count)"
Write-Log "Event investigation period: Last $Days day(s)"
Write-Log "Start time: $StartTime"

# ============================================================
# RESULT COLLECTION
# ============================================================

$LocalAdminResults = [System.Collections.Generic.List[object]]::new()

$SecurityEventResults = [System.Collections.Generic.List[object]]::new()

$SummaryResults = [System.Collections.Generic.List[object]]::new()

# ============================================================
# PROCESS EACH SERVER
# ============================================================

foreach ($Server in $ServerList) {

    Write-Log "------------------------------------------------------------"
    Write-Log "Processing server: $Server"

    # ========================================================
    # TEST WINRM
    # ========================================================

    try {

        Test-WSMan `
            -ComputerName $Server `
            -ErrorAction Stop | Out-Null

        Write-Log "$Server - WinRM connectivity: PASS"

    }
    catch {

        Write-Log `
            "$Server - WinRM connectivity: FAILED - $($_.Exception.Message)" `
            "ERROR"

        $SummaryResults.Add(
            [PSCustomObject]@{
                ServerName       = $Server
                Connectivity     = "FAILED"
                LocalAdminAudit  = "NOT RUN"
                SecurityAudit    = "NOT RUN"
                Status            = "ERROR"
                Error             = $_.Exception.Message
            }
        )

        continue
    }

    # ========================================================
    # REMOTE SECURITY AUDIT
    # ========================================================

    try {

        $RemoteResults = Invoke-Command `
            -ComputerName $Server `
            -ArgumentList (
                $EventIDs,
                $StartTime
            ) `
            -ScriptBlock {

                param(
                    $EventIDs,
                    $StartTime
                )

                # ====================================================
                # LOCAL ADMINISTRATOR AUDIT
                # ====================================================

                $LocalAdminResults = @()

                try {

                    $AdminGroup = Get-LocalGroupMember `
                        -Group "Administrators" `
                        -ErrorAction Stop

                    foreach ($Member in $AdminGroup) {

                        $AccountName = $Member.Name

                        $Domain = $null
                        $UserName = $AccountName

                        if ($AccountName -match "\\") {

                            $Parts = $AccountName.Split("\", 2)

                            $Domain = $Parts[0]
                            $UserName = $Parts[1]
                        }

                        $Enabled = $null

                        try {

                            if ($Member.ObjectClass -eq "User") {

                                $LocalUser = Get-LocalUser `
                                    -Name $UserName `
                                    -ErrorAction SilentlyContinue

                                if ($LocalUser) {
                                    $Enabled = $LocalUser.Enabled
                                }
                            }

                        }
                        catch {
                            $Enabled = $null
                        }

                        $LocalAdminResults += [PSCustomObject]@{

                            ResultType      = "LocalAdministrator"

                            ComputerName    = $env:COMPUTERNAME

                            AccountName     = $AccountName

                            Domain          = $Domain

                            UserName        = $UserName

                            ObjectClass     = $Member.ObjectClass

                            Enabled         = $Enabled

                            PrincipalSource = $Member.PrincipalSource

                            Status          = "Found"

                        }
                    }

                }
                catch {

                    $LocalAdminResults += [PSCustomObject]@{

                        ResultType      = "LocalAdministrator"

                        ComputerName    = $env:COMPUTERNAME

                        AccountName     = "ERROR"

                        Domain          = $null

                        UserName        = $null

                        ObjectClass     = $null

                        Enabled         = $null

                        PrincipalSource = $null

                        Status          = $_.Exception.Message

                    }
                }

                # ====================================================
                # SECURITY EVENT LOG
                # ====================================================

                $SecurityEvents = @()

                try {

                    $FilterHashTable = @{
                        LogName   = "Security"
                        Id        = $EventIDs
                        StartTime = $StartTime
                    }

                    $Events = Get-WinEvent `
                        -FilterHashtable $FilterHashTable `
                        -ErrorAction Stop

                    foreach ($Event in $Events) {

                        $Message = $Event.Message

                        $SecurityEvents += [PSCustomObject]@{

                            ResultType   = "SecurityEvent"

                            ComputerName = $env:COMPUTERNAME

                            EventID      = $Event.Id

                            Description  = switch ($Event.Id) {

                                4624 {
                                    "Successful Logon"
                                }

                                4625 {
                                    "Failed Logon"
                                }

                                4672 {
                                    "Special Privileges Assigned"
                                }

                                4720 {
                                    "User Account Created"
                                }

                                4726 {
                                    "User Account Deleted"
                                }

                                4728 {
                                    "Member Added To Global Security Group"
                                }

                                4732 {
                                    "Member Added To Local Security Group"
                                }

                                4740 {
                                    "User Account Locked Out"
                                }

                                default {
                                    "Unknown"
                                }
                            }

                            TimeCreated = $Event.TimeCreated

                            ProviderName = $Event.ProviderName

                            RecordID = $Event.RecordId

                            Level = $Event.LevelDisplayName

                            Message = $Message

                        }
                    }

                }
                catch {

                    $SecurityEvents += [PSCustomObject]@{

                        ResultType   = "SecurityEvent"

                        ComputerName = $env:COMPUTERNAME

                        EventID      = -1

                        Description  = "ERROR"

                        TimeCreated  = Get-Date

                        ProviderName = "Microsoft-Windows-Security-Auditing"

                        RecordID     = $null

                        Level        = "ERROR"

                        Message      = $_.Exception.Message

                    }
                }

                # ====================================================
                # RETURN RESULTS
                # ====================================================

                [PSCustomObject]@{

                    ComputerName = $env:COMPUTERNAME

                    LocalAdmins  = $LocalAdminResults

                    Events       = $SecurityEvents

                }

            }

        # ========================================================
        # PROCESS LOCAL ADMIN RESULTS
        # ========================================================

        foreach ($Admin in $RemoteResults.LocalAdmins) {

            $LocalAdminResults.Add(

                [PSCustomObject]@{

                    ServerName      = $Server

                    AccountName     = $Admin.AccountName

                    Domain          = $Admin.Domain

                    UserName        = $Admin.UserName

                    ObjectClass     = $Admin.ObjectClass

                    Enabled         = $Admin.Enabled

                    PrincipalSource = $Admin.PrincipalSource

                    Status          = $Admin.Status

                }

            )
        }

        # ========================================================
        # PROCESS SECURITY EVENTS
        # ========================================================

        foreach ($Event in $RemoteResults.Events) {

            $SecurityEventResults.Add(

                [PSCustomObject]@{

                    ServerName    = $Server

                    EventID       = $Event.EventID

                    Description   = $Event.Description

                    TimeCreated   = $Event.TimeCreated

                    ProviderName  = $Event.ProviderName

                    RecordID      = $Event.RecordID

                    Level         = $Event.Level

                    Message       = $Event.Message

                }

            )
        }

        # ========================================================
        # SUMMARY
        # ========================================================

        $AdminCount = @(
            $RemoteResults.LocalAdmins |
            Where-Object {
                $_.Status -eq "Found"
            }
        ).Count

        $EventCount = @(
            $RemoteResults.Events |
            Where-Object {
                $_.EventID -ne -1
            }
        ).Count

        Write-Log `
            "$Server - Local Administrators found: $AdminCount"

        Write-Log `
            "$Server - Security events found: $EventCount"

        $SummaryResults.Add(

            [PSCustomObject]@{

                ServerName      = $Server

                Connectivity    = "PASS"

                LocalAdminAudit = "COMPLETED"

                SecurityAudit   = "COMPLETED"

                LocalAdminCount = $AdminCount

                SecurityEvents  = $EventCount

                Status          = "SUCCESS"

                Error           = $null

            }

        )

    }
    catch {

        Write-Log `
            "$Server - Audit failed: $($_.Exception.Message)" `
            "ERROR"

        $SummaryResults.Add(

            [PSCustomObject]@{

                ServerName      = $Server

                Connectivity    = "PASS"

                LocalAdminAudit = "FAILED"

                SecurityAudit   = "FAILED"

                LocalAdminCount = 0

                SecurityEvents  = 0

                Status          = "ERROR"

                Error           = $_.Exception.Message

            }

        )
    }
}

# ============================================================
# EXPORT CSV FILES
# ============================================================

Write-Log "Exporting Local Administrator report..."

$LocalAdminResults |
    Export-Csv `
        -Path $LocalAdminCsv `
        -NoTypeInformation `
        -Encoding UTF8

Write-Log "Exporting Security Event report..."

$SecurityEventResults |
    Export-Csv `
        -Path $SecurityEventCsv `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# CREATE HTML REPORT
# ============================================================

$SuccessfulServers = @(
    $SummaryResults |
    Where-Object {
        $_.Status -eq "SUCCESS"
    }
).Count

$FailedServers = @(
    $SummaryResults |
    Where-Object {
        $_.Status -eq "ERROR"
    }
).Count

$TotalAdmins = $LocalAdminResults.Count

$TotalEvents = $SecurityEventResults.Count

$EventSummary = $SecurityEventResults |
    Where-Object {
        $_.EventID -ne -1
    } |
    Group-Object EventID |
    ForEach-Object {

        [PSCustomObject]@{

            EventID = $_.Name

            Description = Get-EventDescription `
                -EventID ([int]$_.Name)

            Count = $_.Count

        }
    }

$HTML = @"

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>Windows Security Audit</title>

<style>

body {
    font-family: Arial, Helvetica, sans-serif;
    margin: 30px;
    background-color: #f5f5f5;
}

h1 {
    color: #222;
}

h2 {
    margin-top: 30px;
}

.dashboard {
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
}

.card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    min-width: 180px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
}

.card-title {
    font-size: 13px;
    color: #666;
}

.card-value {
    font-size: 28px;
    font-weight: bold;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    margin-top: 10px;
}

th {
    background-color: #222;
    color: white;
    padding: 10px;
    text-align: left;
}

td {
    padding: 8px;
    border-bottom: 1px solid #ddd;
}

tr:hover {
    background-color: #f1f1f1;
}

</style>

</head>

<body>

<h1>Windows Security Audit Report</h1>

<p>
Generated: $(Get-Date)
</p>

<p>
Investigation period: Last $Days day(s)
</p>

<div class="dashboard">

<div class="card">
<div class="card-title">Servers Audited</div>
<div class="card-value">$($ServerList.Count)</div>
</div>

<div class="card">
<div class="card-title">Successful Audits</div>
<div class="card-value">$SuccessfulServers</div>
</div>

<div class="card">
<div class="card-title">Failed Audits</div>
<div class="card-value">$FailedServers</div>
</div>

<div class="card">
<div class="card-title">Local Admin Entries</div>
<div class="card-value">$TotalAdmins</div>
</div>

<div class="card">
<div class="card-title">Security Events</div>
<div class="card-value">$TotalEvents</div>
</div>

</div>

<h2>Server Audit Summary</h2>

$(
    $SummaryResults |
    ConvertTo-Html `
        -Fragment `
        -Property `
            ServerName,
            Connectivity,
            LocalAdminAudit,
            SecurityAudit,
            LocalAdminCount,
            SecurityEvents,
            Status,
            Error
)

<h2>Security Event Summary</h2>

$(
    $EventSummary |
    ConvertTo-Html `
        -Fragment `
        -Property EventID, Description, Count
)

<h2>Local Administrator Audit</h2>

$(
    $LocalAdminResults |
    ConvertTo-Html `
        -Fragment `
        -Property `
            ServerName,
            AccountName,
            Domain,
            UserName,
            ObjectClass,
            Enabled,
            PrincipalSource,
            Status
)

<h2>Security Events</h2>

$(
    $SecurityEventResults |
    Select-Object `
        ServerName,
        EventID,
        Description,
        TimeCreated,
        Level,
        RecordID,
        Message |
    ConvertTo-Html `
        -Fragment
)

</body>

</html>

"@

$HTML |
    Out-File `
        -FilePath $HtmlReport `
        -Encoding UTF8

# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "============================================================"
Write-Log "SECURITY AUDIT COMPLETED"
Write-Log "============================================================"

Write-Log "Servers scanned       : $($ServerList.Count)"
Write-Log "Successful servers    : $SuccessfulServers"
Write-Log "Failed servers        : $FailedServers"
Write-Log "Local admin entries   : $TotalAdmins"
Write-Log "Security events       : $TotalEvents"

Write-Log "Local Admin CSV       : $LocalAdminCsv"
Write-Log "Security Events CSV   : $SecurityEventCsv"
Write-Log "HTML Report           : $HtmlReport"
Write-Log "Log File              : $LogFile"

Write-Log "============================================================"