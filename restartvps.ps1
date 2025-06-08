# Đường dẫn tới xmrig cần giám sát
$xmrigPath = "C:\Users\Public\Downloads\xmrig-6.22.2\xmrig.exe"

while ($true) {
    if (!(Test-Path $xmrigPath)) {
        Write-Warning "❌ xmrig.exe bị xóa hoặc không tồn tại!"
        Write-Host "🔁 Đang khởi động lại VPS..."

        # Chờ 3 giây trước khi khởi động lại (để in cảnh báo)
        Start-Sleep -Seconds 3

        # Khởi động lại máy ngay
        Restart-Computer -Force
    } else {
        Write-Host "✅ xmrig.exe đang hoạt động bình thường..."
    }

    # Kiểm tra lại sau mỗi 5 giây
    Start-Sleep -Seconds 5
}
