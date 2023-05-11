Import-Module GroupPolicy
Import-Module ActiveDirectory

# Getting 'Domain Admins' SID to make script language independent
$DomainID = ((Get-ADDomain).DomainSID).Value 
$DomainAdminsSID = $DomainID + '-512'

$OwnerName = (Get-ADGroup -Identity $DomainAdminsSID).Name

$DomainNetBios = (Get-ADDomain).NetBIOSName
$Owner = $DomainNetBios + '\' + $OwnerName

$Domain = (Get-WmiObject Win32_ComputerSystem).Domain

$allGPOS = Get-GPO -all | Select-Object DisplayName,Owner,Path

$WrongOwnerGPOs = $allGPOS | Where-Object {$_.Owner -ne $Owner} | Select-Object DisplayName,Owner,Path

if(0 -eq ($WrongOwnerGPOs.Count)){
    Write-Host "All Policies have the GPO owner properly set" -ForegroundColor Green
    break
}

# Fixing GPOs with wrong owners
Foreach($WrongOwnerGPO in $WrongOwnerGPOs){
    $acl = $null
    $objUser = $null
    $GPOPath = $null

    $GPOtoChange = $WrongOwnerGPO.Path

    $GPOPath = "AD:$($GPOtoChange.ToString())"

    $acl = Get-Acl -Path $GPOPath
    $objUser = New-Object System.Security.Principal.NTAccount("$Domain", "$OwnerName")
    $acl.SetOwner($objUser)
    Set-Acl -Path $GPOPath -AclObject $acl
}
