#requires -Version 5.1

<#
.SYNOPSIS
    Windows Server Patch Assessment and Multi-Server Patching

.DESCRIPTION
    Performs pre-patching health checks on multiple Windows Servers and,
    after administrator approval, installs available Windows Updates.

    Checks:
        - OS Version
        - Last Boot Time
        - Installed Updates
        - Latest Installed Update
        - Pending Updates
        - Reboot Required
        - Windows Update Service State

    After patching, the script performs post-patching validation.

.NOTES
    Author      : IT Infrastructure Team
    Purpose     : Production Windows Server Patching
#>

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

# $ServerList = (Import-Csv "C:\Users\Administrator.DC\Desktop\AD-Administration\02-Server Inventory\Input\servers.csv").servername

$ServerList = "SVR03"

# Set to $true if servers should reboot automatically
$AutoReboot = $true

# ------------------------------------------------------------
# FUNCTION: CHECK PSWINDOWSUPDATE MODULE
# ------------------------------------------------------------

function Test-PSWindowsUpdateModule {

    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {

        Write-Host ""
        Write-Host "PSWindowsUpdate module is not installed." -ForegroundColor Red
        Write-Host ""
        Write-Host "Install it using:" -ForegroundColor Yellow
        Write-Host "Install-Module PSWindowsUpdate -Force" -ForegroundColor Cyan
        Write-Host ""

        return $false
    }

    return $true
}

# ------------------------------------------------------------
# FUNCTION: GET SERVER PATCH STATUS
# ------------------------------------------------------------

function Get-ServerPatchStatus {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    Write-Host ""
    Write-Host "Checking $ComputerName ..." -ForegroundColor Cyan

    try {

        $Result = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {

            # ------------------------------------------------
            # OS INFORMATION
            # ------------------------------------------------

            $OS = Get-CimInstance Win32_OperatingSystem

            # ------------------------------------------------
            # LAST BOOT
            # ------------------------------------------------

            $LastBoot = $OS.LastBootUpTime

            # ------------------------------------------------
            # INSTALLED UPDATES
            # ------------------------------------------------

            $InstalledUpdates = Get-HotFix |
                Sort-Object InstalledOn -Descending

            $InstalledUpdateCount = $InstalledUpdates.Count

            $LatestUpdate = $InstalledUpdates |
                Select-Object -First 1

            # ------------------------------------------------
            # WINDOWS UPDATE SERVICE
            # ------------------------------------------------

            $WUService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

            if ($WUService) {
                $WUState = $WUService.Status
            }
            else {
                $WUState = "Not Found"
            }

            # ------------------------------------------------
            # REBOOT REQUIRED
            # ------------------------------------------------

            $RebootRequired = $false

            $RebootPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            )

            foreach ($Path in $RebootPaths) {

                if (Test-Path $Path) {
                    $RebootRequired = $true
                }
            }

            # ------------------------------------------------
            # PENDING WINDOWS UPDATES
            # ------------------------------------------------

            $PendingUpdates = @()

            try {

                $UpdateSession = New-Object -ComObject Microsoft.Update.Session
                $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

                $SearchResult = $UpdateSearcher.Search(
                    "IsInstalled=0 and IsHidden=0"
                )

                foreach ($Update in $SearchResult.Updates) {

                    $PendingUpdates += $Update.Title
                }

            }
            catch {

                $PendingUpdates = @(
                    "Unable to query Windows Update"
                )
            }

            # ------------------------------------------------
            # RETURN OBJECT
            # ------------------------------------------------

            [PSCustomObject]@{

                ServerName = $env:COMPUTERNAME

                OSVersion = $OS.Caption

                OSBuild = $OS.BuildNumber

                LastBoot = $LastBoot

                InstalledUpdates = $InstalledUpdateCount

                LatestUpdateKB = if ($LatestUpdate) {
                    $LatestUpdate.HotFixID
                }
                else {
                    "None"
                }

                LatestUpdateDate = if ($LatestUpdate) {
                    $LatestUpdate.InstalledOn
                }
                else {
                    "None"
                }

                PendingUpdateCount = $PendingUpdates.Count

                PendingUpdates = if ($PendingUpdates.Count -gt 0) {
                    $PendingUpdates -join " | "
                }
                else {
                    "None"
                }

                RebootRequired = $RebootRequired

                WindowsUpdateService = $WUState
            }

        }

        return $Result

    }
    catch {

        Write-Host "ERROR: Unable to connect to $ComputerName" -ForegroundColor Red

        return [PSCustomObject]@{

            ServerName = $ComputerName
            OSVersion = "ERROR"
            OSBuild = "ERROR"
            LastBoot = "ERROR"
            InstalledUpdates = "ERROR"
            LatestUpdateKB = "ERROR"
            LatestUpdateDate = "ERROR"
            PendingUpdateCount = "ERROR"
            PendingUpdates = $_.Exception.Message
            RebootRequired = "ERROR"
            WindowsUpdateService = "ERROR"
        }
    }
}

# ------------------------------------------------------------
# FUNCTION: PATCH SERVER
# ------------------------------------------------------------

function Install-ServerUpdates {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Patching Server: $ComputerName" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    try {

        Invoke-Command -ComputerName $ComputerName -ScriptBlock {

            Import-Module PSWindowsUpdate -ErrorAction Stop

            Write-Host "Starting Windows Update..." -ForegroundColor Cyan

            Install-WindowsUpdate `
                -MicrosoftUpdate `
                -AcceptAll `
                -IgnoreReboot:$false `
                -AutoReboot:$using:AutoReboot `
                -Verbose
        } -ErrorAction Stop

        Write-Host ""
        Write-Host "$ComputerName patching completed." -ForegroundColor Green
    }
    catch {

        Write-Host ""
        Write-Host "$ComputerName patching FAILED." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# ============================================================
# MAIN SCRIPT
# ============================================================

Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "        WINDOWS SERVER PATCH MANAGEMENT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Servers to be checked:" -ForegroundColor Yellow

$ServerList | ForEach-Object {
    Write-Host "  - $_"
}

# ------------------------------------------------------------
# CHECK MODULE
# ------------------------------------------------------------

if (-not (Test-PSWindowsUpdateModule)) {
    exit
}

# ------------------------------------------------------------
# PRE-PATCH ASSESSMENT
# ------------------------------------------------------------

Write-Host ""
Write-Host "Starting pre-patching assessment..." -ForegroundColor Cyan

$PatchResults = @()

foreach ($Server in $ServerList) {

    $Result = Get-ServerPatchStatus -ComputerName $Server

    if ($Result) {
        $PatchResults += $Result
    }
}

# ------------------------------------------------------------
# DISPLAY SUMMARY
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "                 PATCH ASSESSMENT" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

$PatchResults |
    Select-Object `
        ServerName,
        OSVersion,
        OSBuild,
        LastBoot,
        InstalledUpdates,
        LatestUpdateKB,
        LatestUpdateDate,
        PendingUpdateCount,
        RebootRequired,
        WindowsUpdateService |
    Format-Table -AutoSize

# ------------------------------------------------------------
# PENDING UPDATE DETAILS
# ------------------------------------------------------------

Write-Host ""
Write-Host "Pending Updates:" -ForegroundColor Yellow

foreach ($Result in $PatchResults) {

    Write-Host ""
    Write-Host "[$($Result.ServerName)]" -ForegroundColor Cyan

    if ($Result.PendingUpdateCount -gt 0) {

        $Result.PendingUpdates -split " \| " |
            ForEach-Object {
                Write-Host "  $_"
            }

    }
    else {

        Write-Host "  No pending updates." -ForegroundColor Green
    }
}

# ------------------------------------------------------------
# EXPORT PRE-PATCH REPORT
# ------------------------------------------------------------

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

$PrePatchReport = "Logs\PrePatchReport_$TimeStamp.csv"

$PatchResults |
    Export-Csv -Path $PrePatchReport -NoTypeInformation

Write-Host ""
Write-Host "Pre-patch report saved to:" -ForegroundColor Cyan
Write-Host $PrePatchReport

# ------------------------------------------------------------
# PATCH APPROVAL
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "                 PATCHING APPROVAL" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow

$ServersWithUpdates = $PatchResults |
    Where-Object {
        $_.PendingUpdateCount -gt 0
    }

if ($ServersWithUpdates.Count -eq 0) {

    Write-Host ""
    Write-Host "No pending updates found on any server." -ForegroundColor Green
    exit
}

Write-Host ""
Write-Host "Servers requiring patching:" -ForegroundColor Yellow

$ServersWithUpdates |
    ForEach-Object {

        Write-Host "  $($_.ServerName) - $($_.PendingUpdateCount) update(s)" `
            -ForegroundColor Yellow
    }

Write-Host ""

$Confirmation = Read-Host `
    "Do you want to patch these servers? [Y/N]"

if ($Confirmation -notmatch "^[Yy]$") {

    Write-Host ""
    Write-Host "Patching cancelled by administrator." -ForegroundColor Yellow
    exit
}

# ------------------------------------------------------------
# PATCH SERVERS
# ------------------------------------------------------------

Write-Host ""
Write-Host "Administrator approved patching." -ForegroundColor Green

foreach ($Server in $ServersWithUpdates) {

    Install-ServerUpdates `
        -ComputerName $Server.ServerName
}

# ------------------------------------------------------------
# POST-PATCH VALIDATION
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                 POST-PATCH VALIDATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Start-Sleep -Seconds 10

$PostPatchResults = @()

foreach ($Server in $ServersWithUpdates) {

    $Result = Get-ServerPatchStatus `
        -ComputerName $Server.ServerName

    if ($Result) {
        $PostPatchResults += $Result
    }
}

# ------------------------------------------------------------
# DISPLAY POST-PATCH RESULTS
# ------------------------------------------------------------

Write-Host ""
Write-Host "Post-Patching Status:" -ForegroundColor Green

$PostPatchResults |
    Select-Object `
        ServerName,
        LatestUpdateKB,
        LatestUpdateDate,
        PendingUpdateCount,
        RebootRequired,
        WindowsUpdateService |
    Format-Table -AutoSize

# ------------------------------------------------------------
# EXPORT POST-PATCH REPORT
# ------------------------------------------------------------

$PostPatchReport = "Logs\PostPatchReport_$TimeStamp.csv"

$PostPatchResults |
    Export-Csv `
        -Path $PostPatchReport `
        -NoTypeInformation

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "              PATCHING COMPLETED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

Write-Host ""
Write-Host "Pre-Patch Report :" -ForegroundColor Cyan
Write-Host $PrePatchReport

Write-Host ""
Write-Host "Post-Patch Report:" -ForegroundColor Cyan
Write-Host $PostPatchReport