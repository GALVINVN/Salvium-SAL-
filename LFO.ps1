attrib +h +s "C:\Users\Public\Downloads"

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoFolderOptions" -PropertyType DWORD -Value 1 -Force

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWORD -Value 2 -Force

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2

Stop-Process -Name explorer -Force
# KhÃ³a quyá»n chá»‰nh sá»­a key 'Explorer\Advanced'
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$acl = Get-Acl $regPath
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("$(whoami)", "SetValue", "Deny")
$acl.AddAccessRule($rule)
Set-Acl $regPath $acl

# KhÃ³a key 'Policies\Explorer'
$regPath2 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$acl2 = Get-Acl $regPath2
$rule2 = New-Object System.Security.AccessControl.RegistryAccessRule("$(whoami)", "SetValue", "Deny")
$acl2.AddAccessRule($rule2)
Set-Acl $regPath2 $acl2




