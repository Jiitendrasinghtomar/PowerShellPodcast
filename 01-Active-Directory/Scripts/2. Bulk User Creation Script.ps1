################# Step 3 - Creating users in bulk.

Import-Module ActiveDirectory

# CSV file location
$CSVFile = "C:\Users\Administrator.DC\Desktop\AD-Administration\01-Active-Directory\Input\users.csv "

# Target OU


# Default password
$Password = ConvertTo-SecureString "Temp@12345" -AsPlainText -Force

# Import CSV
$Users = Import-Csv -Path $CSVFile

# Process every user dynamically
foreach ($User in $Users) {
$ou = $User.Department
$TargetOU = "OU=$ou,DC=apexaura,DC=local"

    # Build user information dynamically from CSV
    $FirstName = $User.FirstName.Trim()
    $LastName  = $User.LastName.Trim()

    $DisplayName = "$FirstName $LastName"

    # Generate username
    $SamAccountName = "$FirstName.$LastName".ToLower()

    $UserPrincipalName = "$SamAccountName@apexaura.local"

    Write-Host "Processing: $DisplayName" -ForegroundColor Cyan

    # Check whether user already exists
    $ExistingUser = Get-ADUser `
        -Filter "SamAccountName -eq '$SamAccountName'" `
        -ErrorAction SilentlyContinue

    if ($ExistingUser) {

        Write-Host "$DisplayName already exists. Skipping..." `
            -ForegroundColor Yellow

        continue
    }

    # Create user
    try {

        New-ADUser -Name $DisplayName `
            -GivenName $FirstName `
            -Surname $LastName `
            -DisplayName $DisplayName `
            -SamAccountName $SamAccountName `
            -UserPrincipalName $UserPrincipalName `
            -EmployeeID $User.EmployeeID `
            -Department $User.Department `
            -Title $User.JobTitle `
            -Path $TargetOU `
            -AccountPassword $Password `
            -Enabled $true `
            -ChangePasswordAtLogon $true

        Write-Host "$DisplayName created successfully." `
            -ForegroundColor Green

    }
    catch {

        Write-Host "Failed to create $DisplayName" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message `
            -ForegroundColor Red
    }
}