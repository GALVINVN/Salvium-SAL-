$xmrigPath = "C:\Users\Public\Downloads\xmrig-6.22.2\COINRUN.cmd"
$xmrigProcessName = "xmrig"

function Start-XMRIG {
    Write-Host "Restart xmrig..."
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$xmrigPath`""
}

while ($true) {
    
    $xmrigRunning = Get-Process -Name $xmrigProcessName -ErrorAction SilentlyContinue

    if (-not $xmrigRunning) {
        Write-Warning "XMRig STOP. Wait running..."
        Start-XMRIG
    } else {
        Write-Host "XMRig running..."
    }

    Start-Sleep -Seconds 3
}
