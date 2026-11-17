################# Step 1 - creating new OU manually
New-ADOrganizationalUnit ITAdmins -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit Finance -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit HR -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit Production -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit Management -ProtectedFromAccidentalDeletion $false

# Removing OUs
$ous = @("ITAdmins","Finance","HR","Production","Management")
foreach($o in $ous) {
    Remove-ADOrganizationalUnit  -Identity "OU=$o,DC=apexaura,DC=local" -Recursive -Confirm:$false
}

################# Step 2 - creating new groups using loops
notepad.exe groupList.txt
$group = Get-Content C:\Users\Administrator.DC\Desktop\AD-Administration\01-Active-Directory\Input\groupList.txt
$group | foreach{
    New-ADGroup -Name $_ -GroupScope Global
    Write-Host "$_ created sucessfully" -ForegroundColor Green
}

# removing groups using loops
foreach($g in $group){
    # New-ADGroup -Name $_ -GroupScope Global
    if((Get-ADGroup $g).name){
        Write-Host "Removing $g" -ForegroundColor Cyan
        Remove-ADGroup -Identity $g -Confirm:$false
    }else{
        Write-Host "$g NOT found" -ForegroundColor Red
    }
}
