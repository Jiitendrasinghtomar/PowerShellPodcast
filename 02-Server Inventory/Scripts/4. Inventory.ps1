# ==========================================================
# Server Inventory
# ==========================================================

cls

$servers = Import-Csv "C:\Users\Administrator.DC\Desktop\AD-Administration\02-Server Inventory\Input\servers.csv"

$results = foreach ($server in $servers) {

    $name = $server.ServerName

    # ------------------------------------------------------
    # Default values
    # ------------------------------------------------------

    $status = "Offline"
    $uptimeDisplay = "N/A"
    $cDriveSpace = "N/A"
    $memory = "N/A"
    $cpu = "N/A"


    # ------------------------------------------------------
    # 1. Check basic connectivity
    # ------------------------------------------------------

    if (-not (Test-Connection $name -Count 1 -Quiet)) {

        [PSCustomObject]@{
            ServerName  = $name
            Environment = $server.Environment
            Status      = "Offline"
            Uptime      = "N/A"
            CDriveSpace = "N/A"
            Memory      = "N/A"
            CPU         = "N/A"
        }

        continue
    }


    # ------------------------------------------------------
    # 2. Collect server information
    # ------------------------------------------------------

    try {

        $inventory = Invoke-Command -ComputerName $name -ScriptBlock {

            # --------------------------------------------------
            # OS / Uptime
            # --------------------------------------------------

            $os = Get-CimInstance Win32_OperatingSystem

            $lastBoot = $os.LastBootUpTime

            $uptime = (Get-Date) - $lastBoot

            $uptimeDisplay = "{0} Days {1} Hours {2} Minutes" -f `
                $uptime.Days,
                $uptime.Hours,
                $uptime.Minutes


            # --------------------------------------------------
            # C: Drive
            # --------------------------------------------------

            $disk = Get-CimInstance Win32_LogicalDisk `
                -Filter "DeviceID='C:'"

            if ($disk) {

                $freePercent = ($disk.FreeSpace / $disk.Size) * 100

                $cDriveSpace = "{0}%" -f `
                    [math]::Round($freePercent, 2)
            }
            else {

                $cDriveSpace = "C: Not Found"
            }


            # --------------------------------------------------
            # Memory
            # --------------------------------------------------

            $totalMemory = $os.TotalVisibleMemorySize
            $freeMemory = $os.FreePhysicalMemory

            $memoryUsedPercent =
                (($totalMemory - $freeMemory) / $totalMemory) * 100

            $memory = "{0}%" -f `
                [math]::Round($memoryUsedPercent, 2)


            # --------------------------------------------------
            # CPU
            # --------------------------------------------------

            $processor = Get-CimInstance Win32_Processor

            $cpuUsedPercent = (
                $processor |
                Measure-Object -Property LoadPercentage -Average
            ).Average

            $cpu = "{0}%" -f `
                [math]::Round($cpuUsedPercent, 2)


            # --------------------------------------------------
            # Return inventory data
            # --------------------------------------------------

            [PSCustomObject]@{
                Uptime      = $uptimeDisplay
                CDriveSpace = $cDriveSpace
                Memory      = $memory
                CPU         = $cpu
            }

        } -ErrorAction Stop


        # ------------------------------------------------------
        # 3. Assign collected information
        # ------------------------------------------------------

        $status = "Online"

        $uptimeDisplay = $inventory.Uptime
        $cDriveSpace = $inventory.CDriveSpace
        $memory = $inventory.Memory
        $cpu = $inventory.CPU

    }
    catch {

        $status = "Online"
        $uptimeDisplay = "Unable to retrieve"
        $cDriveSpace = "Unable to retrieve"
        $memory = "Unable to retrieve"
        $cpu = "Unable to retrieve"

        Write-Host "ERROR: $name - $($_.Exception.Message)" `
            -ForegroundColor Red
    }


    # ------------------------------------------------------
    # 4. Create ONE result object per server
    # ------------------------------------------------------

    [PSCustomObject]@{
        ServerName  = $name
        Environment = $server.Environment
        Status      = $status
        Uptime      = $uptimeDisplay
        CDriveSpace = $cDriveSpace
        Memory      = $memory
        CPU         = $cpu
    }
}


# ==========================================================
# Display results in PowerShell
# ==========================================================

$results | Format-Table -AutoSize


# ==========================================================
# Export CSV
# ==========================================================

$results |
    Export-Csv C:\Users\Administrator.DC\Desktop\AD-Administration\02-Server Inventory\Output\ServerInventory.csv -NoTypeInformation


# ==========================================================
# Generate HTML
# ==========================================================

$results |
    ConvertTo-Html `
        -Title "Server Inventory Report" `
        -CssUri "C:\Users\Administrator.DC\Desktop\AD-Administration\03-Web\styles.css" |
    Out-File "C:\Users\Administrator.DC\Desktop\AD-Administration\02-Server Inventory\Output\customOutput.html" -Encoding UTF8


Write-Host ""
Write-Host "Inventory completed successfully." -ForegroundColor Green
Write-Host "HTML Report : .\customOutput.html"
Write-Host "CSV Report  : .\ServerInventory.csv"

cd 'C:\Users\Administrator.DC\Desktop\AD-Administration\02-Server Inventory\output\'
.\customOutput.html
# .\ServerInventory.csv