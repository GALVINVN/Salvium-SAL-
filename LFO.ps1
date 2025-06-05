attrib +h +s "C:\Users\Public\Downloads"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
-Name "NoFolderOptions" -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
-Name "Hidden" -PropertyType DWORD -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
-Name "Hidden" -Value 2
Stop-Process -Name explorer -Force

