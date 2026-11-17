# listing current employees
cls

# first part
$ErrorActionPreference = "SilentlyContinue"
$DomainAdmins = Get-ADGroupMember "Domain Admins" |
Where-Object {$_.objectClass -eq "user"} |
Select-Object -ExpandProperty SamAccountName

Get-ADUser -Filter * |
Where-Object {($_.SamAccountName -notin $DomainAdmins) -and ($_.Enabled -eq "True")} |
Select-Object Name,SamAccountName

# ask SamAccountName to delete user.
# second part
$SamAccountName = Read-Host "Enter SamAccountName: "
$user = Get-ADUser -Identity $SamAccountName
if ($user) {
    Write-Host "Found user: $($user.Name)" -ForegroundColor Yellow
    Remove-ADUser -Identity $SamAccountName -Confirm:$true
    Write-Host "User deleted successfully." -ForegroundColor Green
}
else {
    Write-Host "User not found." -ForegroundColor Red
}