# WSUS / Windows Update 修復工具
#修改日期:
#20250626  新增測試連線功能
#20250725  美化顯示視窗
#20250806  更新選項彈窗
#20250908  新增自動更新按鈕
#20251205  修改文字顯示，新增自動強制提權
#20251229  修改UI，修改多項功能邏輯
#20260203  新增說明按鈕
# ==================================================================================

$version = "修改日期:2026.02.03 使用問題及建議請聯繫:fia-aws@ch-si.com.tw"

# --- 自動強制提權 ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# 字型定義
$uiFont = New-Object System.Drawing.Font("Microsoft JhengHei", 10)
$titleFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)

# === 讀取系統資訊 Function ===
function Update-Information {
    try {
        $script:wsusServer = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer
        if (-not $script:wsusServer) { $script:wsusServer = "未設定" }
    } catch { $script:wsusServer = "讀取失敗" }

    try {
        $script:clientID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue).SusClientId
        if (-not $script:clientID) { $script:clientID = "未設定" }
    } catch { $script:clientID = "讀取失敗" }

    try {
        $script:ntpServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue).NtpServer
        if (-not $script:ntpServer) { $script:ntpServer = "未設定" }
    } catch { $script:ntpServer = "讀取失敗" }

    try {
        $script:localIP = (ipconfig | Select-String "IPv4" | ForEach-Object { ($_ -split ":")[1].Trim() }) -join ", "
    } catch { $script:localIP = "讀取失敗" }
}
Update-Information

function Test-TcpPort {
    param (
        [string]$TargetHost,
        [int]$Port = 0,       # 預設改為 0
        [int]$Timeout = 3000  # 預設 3 秒
    )

    # --- 新增：如果 Port 為 0 或未輸入，則跑 Ping 測試 ---
    if ($Port -eq 0) {
        try {
            # -Count 1 只測一次，-Quiet 直接回傳 True/False
            return Test-Connection -ComputerName $TargetHost -Count 1 -Quiet -ErrorAction SilentlyContinue
        } catch {
            return $false
        }
    }

    # --- 原本你寫的 TCP 測試流程 ---
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout, $false)

        if ($wait -and $client.Connected) {
            $client.EndConnect($asyncResult)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}




# 獲取作業系統的主要版本號
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
# 將版本號轉換為可以比較的物件
$majorVersion = [version]$osVersion


# === 表單初始化 ===
$form = New-Object System.Windows.Forms.Form
$form.Text = "WSUS / Windows Update 修復工具"
$form.Size = New-Object System.Drawing.Size(730, 800)
$form.StartPosition = "CenterScreen"
$form.Font = $uiFont

# --- 資訊顯示 Label ---
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.AutoSize = $true
$infoLabel.Location = New-Object System.Drawing.Point(25, 15)
$infoLabel.Font = New-Object System.Drawing.Font("Consolas", 10)
$infoLabel.Text = "$version`n`n主機名稱: $env:computername`n本機 IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer"
$form.Controls.Add($infoLabel)

# --- 排版參數 ---
$btnW = 280; $btnH = 40
$L = 40; $R = 380; $startY = 180; $vGap = 55

# ======================================================================
# 左側功能 (命名規則: $btn1x)
# ======================================================================

# 11. 重新向 WSUS 報到
$btn11 = New-Object System.Windows.Forms.Button
$btn11.Text = "1. 重新向 WSUS 報到"
$btn11.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn11.Location = New-Object System.Drawing.Point($L, $startY)
$btn11.Add_Click({
    $statusLabel.Text = "正在執行報到指令..." ; [System.Windows.Forms.Application]::DoEvents()
    # 檢查是否存在 Sysnative (代表目前是在 32位元環境執行)
    $path = if (Test-Path "$env:windir\Sysnative") { "$env:windir\Sysnative\wuauclt.exe" } 
            else { "$env:windir\System32\wuauclt.exe" }

    # 使用 Start-Process 執行，並加入 -Wait 確保指令完成
    Start-Process -FilePath $path -ArgumentList "/resetauthorization /detectnow" -Wait
    Start-Process -FilePath $path -ArgumentList "/reportnow" -Wait
    (get-service wuauserv).Refresh()
    (New-Object -ComObject Microsoft.Update.Autoupdate).detectNow()
    [System.Windows.Forms.MessageBox]::Show($form, "已重新向 WSUS 報到。", "完成", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    $statusLabel.Text = "報到指令已發送。"
})

# 12. 清除更新快取
$btn12 = New-Object System.Windows.Forms.Button
$btn12.Text = "2. 清除更新快取"
$btn12.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn12.Location = New-Object System.Drawing.Point($L, ($startY + $vGap))
$btn12.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
此動作將會：

1. 停止 Windows Update 相關服務（wuauserv、BITS、cryptsvc、msiserver）
2. 刪除更新快取資料夾（SoftwareDistribution、catroot2）
3. 重新啟動相關服務

會清除Windows Update更新紀錄，建議執行前先備份或截圖記錄
僅在更新失敗或出現異常時建議使用。

確定要執行清除動作嗎？
", "清除更新快取", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping Windows Update related services..." ; [System.Windows.Forms.Application]::DoEvents()
        Stop-Service wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        
        $statusLabel.Text = "Removing SoftwareDistribution and Catroot2 folders..." ; [System.Windows.Forms.Application]::DoEvents()
        Remove-Item "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        
        $statusLabel.Text = "Starting services again..." ; [System.Windows.Forms.Application]::DoEvents()
        Start-Service wuauserv, bits, cryptsvc, msiserver
        $statusLabel.Text = "快取清理完成。"
        [System.Windows.Forms.MessageBox]::Show("更新快取已成功清除。")
    }
})

# 13. 完整重置 (整合 DLL 註冊)
$btn13 = New-Object System.Windows.Forms.Button
$btn13.Text = "3. 完整重置修復 (含DLL註冊)"
$btn13.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn13.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*2))
$btn13.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
此動作將會：

1. 停止 Windows Update 相關服務（wuauserv、BITS、cryptsvc、msiserver、appidsvc、ccmexec）
2. 刪除更新快取資料夾（SoftwareDistribution、catroot2）
3. 重新註冊相關dll
4. 重新啟動相關服務
5. 執行完成後檢查更新出錯需重新開機

會清除Windows Update更新紀錄，建議執行前先備份或截圖記錄
僅在更新失敗或出現異常和清除 Windows Update 快取也無效時建議使用。
執行完成後檢查更新出錯時需重新開機


確定要執行動作嗎？
", "完整重置修復 (含DLL註冊)", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "停止所有更新服務..."; [System.Windows.Forms.Application]::DoEvents()
        $services = @("w32time", "wuauserv", "bits", "msiserver", "appidsvc", "cryptsvc", "ccmexec")
        foreach ($s in $services) { Stop-Service $s -Force -ErrorAction SilentlyContinue }

        $statusLabel.Text = "正在清理檔案與快取..."; [System.Windows.Forms.Application]::DoEvents()
        Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\System32\catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue
        
        # 使用使用者提供的完整 DLL 清單
        $dlls = @(
            "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll", "vbscript.dll",
            "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll",
            "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll",
            "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll",
            "wups.dll", "wups2.dll", "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
        )
        
        foreach ($d in $dlls) {
            $statusLabel.Text = "正在重新註冊: $d"; [System.Windows.Forms.Application]::DoEvents()
            Start-Process "regsvr32.exe" "/s $env:WinDir\system32\$d" -Wait
        }

        $statusLabel.Text = "重啟服務中..."; [System.Windows.Forms.Application]::DoEvents()
        foreach ($s in $services) { Start-Service $s -ErrorAction SilentlyContinue }
        
        $statusLabel.Text = "完成深度修復。"
        [System.Windows.Forms.MessageBox]::Show("修復完成。")
    }
})
# 14. 設定自動更新參數
$btn14 = New-Object System.Windows.Forms.Button
$btn14.Text = "4. 設定自動更新參數 (AU)"
$btn14.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn14.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*3))
$btn14.Add_Click({
    # 建立輸入表單
    $inputForm = New-Object System.Windows.Forms.Form
    $inputForm.Text = "設定自動更新參數"
    $inputForm.Size = New-Object System.Drawing.Size(400, 450)
    $inputForm.StartPosition = "CenterParent"
    $inputForm.Font = $uiFont  # 套用你之前定義的正黑體

    # 使用 FlowLayoutPanel 自動排版
    $flowLayout = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowLayout.Dock = "Top"
    $flowLayout.Height = 300
    $flowLayout.Padding = New-Object System.Windows.Forms.Padding(20)
    $flowLayout.AutoScroll = $true
    $inputForm.Controls.Add($flowLayout)

    # 設定項目與預設值
    $settings = [ordered]@{
        "NoAUShutdownOption"           = "1"
        "NoAUAsDefaultShutdownOption"  = "1"
        "NoAutoUpdate"                 = "1"
        "AUOptions"                    = "2"
    }

    $textBoxes = @{}

    # 迴圈自動產生 UI 組件
    foreach ($key in $settings.Keys) {
        $p = New-Object System.Windows.Forms.Panel -Property @{ Size = "340, 35" }
        
        $lbl = New-Object System.Windows.Forms.Label -Property @{
            Text = "$key :"
            Location = "0, 5"
            Size = "180, 20"
        }
        
        $txt = New-Object System.Windows.Forms.TextBox -Property @{
            Text = $settings[$key]
            Location = "180, 2"
            Size = "140, 25"
        }
        
        $p.Controls.AddRange(@($lbl, $txt))
        $flowLayout.Controls.Add($p)
        $textBoxes[$key] = $txt
    }

    # 按鈕容器
    $btnPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = "Bottom"; Height = 80 }
    $inputForm.Controls.Add($btnPanel)

    # 參數說明按鈕
    $btnHelp = New-Object System.Windows.Forms.Button -Property @{
        Text = "參數說明"; Size = "100, 30"; Location = "80, 20"
    }
    $btnHelp.Add_Click({
        [System.Windows.Forms.MessageBox]::Show(@"
以下是自動更新參數說明：

- NoAUShutdownOption = 1  
  在關機時不顯示自動更新的選項，避免使用者在關機時無意中安裝更新。

- NoAUAsDefaultShutdownOption = 1  
  關機時的預設選項不是自動安裝更新後關機

- NoAutoUpdate = 1  
  關閉自動更新功能（但仍可手動更新）

- AUOptions  
1	通知下載與安裝
2	通知下載，手動安裝  ← 建議的設定
3	自動下載，通知安裝
4	自動下載與安裝
5	允許本機系統管理員選擇設定

建議設定為1112
微軟預設為0004

"@, "說明")
    })

    # 套用按鈕
    $okButton = New-Object System.Windows.Forms.Button -Property @{
        Text = "套用設定"; Size = "100, 30"; Location = "200, 20"; DialogResult = "OK"
    }
    $okButton.Add_Click({
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }
        
        foreach ($name in $textBoxes.Keys) {
            $val = $textBoxes[$name].Text
            if ($val -match '^\d+$') {
                Set-ItemProperty $regPath -Name $name -Value ([int]$val)
            }
        }
        $inputForm.Close()
        [System.Windows.Forms.MessageBox]::Show("已更新登錄檔並重啟服務檢查。")
        $btnRefresh.PerformClick()
    })

    $btnPanel.Controls.AddRange(@($btnHelp, $okButton))
    $inputForm.ShowDialog()
})


# 15. 清除 WSUS Client ID
$btn15 = New-Object System.Windows.Forms.Button
$btn15.Text = "5. 清除 WSUS Client ID"
$btn15.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn15.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*4))
$btn15.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
[確認] 是否執行清除 WSUS Client ID？

此功能專門解決「WSUS 後台找不到電腦」或「多台電腦 ID 重複導致報到互相蓋台」的問題。 執行後會重啟更新服務並生成新的識別碼。

", "清除 WSUS Client ID", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
    Stop-Service wuauserv -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId","SusClientIDValidation" -ErrorAction SilentlyContinue
    Start-Service wuauserv
    $btnRefresh.PerformClick()
    [System.Windows.Forms.MessageBox]::Show($form, "已清除 Client ID，將於下次報到重新產生。", "完成", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# ======================================================================
# 右側工具區 (命名規則: $btn2x)
# ======================================================================

# 21. 設定 WSUS server
$btn21 = New-Object System.Windows.Forms.Button
$btn21.Text = "設定 WSUS server"
$btn21.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn21.Location = New-Object System.Drawing.Point($R, $startY)
$btn21.Add_Click({
    $subForm = New-Object System.Windows.Forms.Form
    $subForm.Text = "WSUS 伺服器設定"
    $subForm.Size = New-Object System.Drawing.Size(420, 260) # 稍微拉高一點放新按鈕
    $subForm.StartPosition = "CenterParent"
    $subForm.Font = $uiFont
    $subForm.FormBorderStyle = "FixedDialog"
    $subForm.MaximizeBox = $false

    $lblIp = New-Object System.Windows.Forms.Label
    $lblIp.Text = "WSUS IP 位址:"
    $lblIp.Location = New-Object System.Drawing.Point(20, 30); $lblIp.AutoSize = $true
    
    $txtIp = New-Object System.Windows.Forms.TextBox
    $txtIp.Location = New-Object System.Drawing.Point(140, 27); $txtIp.Size = New-Object System.Drawing.Size(220, 25)
    try { $txtIp.Text = ([uri]$script:wsusServer).Host } catch { $txtIp.Text = "" }

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "通訊埠 (Port):"
    $lblPort.Location = New-Object System.Drawing.Point(20, 75); $lblPort.AutoSize = $true

    $txtPort = New-Object System.Windows.Forms.TextBox
    $txtPort.Location = New-Object System.Drawing.Point(140, 72); $txtPort.Size = New-Object System.Drawing.Size(80, 25)
    try { $txtPort.Text = ([uri]$script:wsusServer).Port } catch { $txtPort.Text = "8530" }

    # --- 套用按鈕 ---
    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "套用設定"
    $btnApply.Location = New-Object System.Drawing.Point(60, 140)
    $btnApply.Size = New-Object System.Drawing.Size(120, 35)
    $btnApply.Add_Click({
        $newIp = $txtIp.Text.Trim()
        $newPort = $txtPort.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($newIp) -or -not ($newPort -as [int])) {
            [System.Windows.Forms.MessageBox]::Show("請輸入有效的 IP 與 Port。", "錯誤", 0, 16)
            return
        }
        $url = "http://$newIp`:$newPort"
        if ([System.Windows.Forms.MessageBox]::Show("確定指向：$url ?", "套用確認", 4, 32) -eq "Yes") {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value $url
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value $url
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1
            Restart-Service wuauserv -Force
            $subForm.Close()
            $btnRefresh.PerformClick()
        }
    })

    # --- 清除設定按鈕 ---
    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = "清除 WSUS 設定"
    $btnClear.Location = New-Object System.Drawing.Point(220, 140)
    $btnClear.Size = New-Object System.Drawing.Size(120, 35)
    $btnClear.Add_Click({
        $warnMsg = "此動作將刪除登錄檔中的 WSUS 指向設定，使電腦恢復為預設的 Windows Update (雲端更新)。`n`n確定要清除嗎？"
        if ([System.Windows.Forms.MessageBox]::Show($warnMsg, "警告", 4, 48) -eq "Yes") {
            try {
                # 刪除關鍵機碼路徑
                $wuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
                if (Test-Path $wuPath) {
                    Remove-ItemProperty -Path $wuPath -Name "WUServer" -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $wuPath -Name "WUStatusServer" -ErrorAction SilentlyContinue
                }
                if (Test-Path "$wuPath\AU") {
                    Remove-ItemProperty -Path "$wuPath\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue
                }
                
                Restart-Service wuauserv -Force
                $statusLabel.Text = "WSUS 設定已清除，恢復預設更新。"
                $subForm.Close()
                $btnRefresh.PerformClick()
            } catch {
                [System.Windows.Forms.MessageBox]::Show("清除失敗：$($_.Exception.Message)")
            }
        }
    })

    $subForm.Controls.AddRange(@($lblIp, $txtIp, $lblPort, $txtPort, $btnApply, $btnClear))
    $subForm.ShowDialog()
})

# 22. 檢查更新介面
$btn22 = New-Object System.Windows.Forms.Button
$btn22.Text = "檢查更新"
$btn22.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn22.Location = New-Object System.Drawing.Point($R, ($startY + $vGap))
$btn22.Add_Click({
    # 顯示確認對話框
    $result = [System.Windows.Forms.MessageBox]::Show(
        "是否要開始檢查更新？",
        "檢查更新",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        # 先模擬按下「重新整理」按鈕
        $btnRefresh.PerformClick()

        # 執行 Windows Update 檢查
        if ($majorVersion.Build -ge 22000) {
        #win11以上
        Start-Process "ms-settings:windowsupdate"
        } else {
        #win10以下
        Start-Process "ms-settings:windowsupdate-action"
        }
    }
})

# 23. 更新紀錄
$btn23 = New-Object System.Windows.Forms.Button
$btn23.Text = "查看 Windows 更新紀錄"
$btn23.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn23.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*2))
$btn23.Add_Click({ Start-Process "ms-settings:windowsupdate-history" })

# 24. 同步時間 (NTP)
$btn24 = New-Object System.Windows.Forms.Button
$btn24.Text = "同步系統時間 (NTP)"
$btn24.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn24.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*3))
$btn24.Add_Click({
    $statusLabel.Text = "正在同步 NTP 時間..."
    $statusLabel.ForeColor = [System.Drawing.Color]::Blue
    [System.Windows.Forms.Application]::DoEvents()

    # 確保服務啟動，並將 w32tm 的輸出抓取到變數中
    Start-Service w32time -ErrorAction SilentlyContinue
    
    # 2>&1 是為了把「錯誤訊息」也一起抓回來顯示
    $result = $(w32tm /resync /force 2>&1) | Out-String
    
    # 將結果打印到狀態欄 (Trim 是為了去掉結尾換行，讓顯示更好看)
    $statusLabel.Text = "NTP 結果: " + $result.Trim()
    Update-Information
    $btnRefresh.PerformClick()
})

# ======================================================================
# 第三區域：連線診斷工具 (底部區)
# ======================================================================

# 分隔線 Label (視覺上區隔開來)
$lineLabel = New-Object System.Windows.Forms.Label
$lineLabel.Text = "--------------------------- 連線診斷工具 ---------------------------"
$lineLabel.Location = New-Object System.Drawing.Point($L, 500)
$lineLabel.Size = New-Object System.Drawing.Size(650, 25)
$lineLabel.ForeColor = [System.Drawing.Color]::Gray

# 測試連線 IP 標籤與輸入框
$lblTestIp = New-Object System.Windows.Forms.Label
$lblTestIp.Text = "目標 IP / Host:"
$lblTestIp.Location = New-Object System.Drawing.Point($L, 540)
$lblTestIp.AutoSize = $true

$txtTestIp = New-Object System.Windows.Forms.TextBox
$txtTestIp.Location = New-Object System.Drawing.Point(160, 537)
$txtTestIp.Size = New-Object System.Drawing.Size(160, 25)
# 預設抓取當前 WSUS 主機
try { $txtTestIp.Text = ([uri]$script:wsusServer).Host } catch { $txtTestIp.Text = "" }

# Port 標籤與輸入框
$lblTestPort = New-Object System.Windows.Forms.Label
$lblTestPort.Text = "Port:"
$lblTestPort.Location = New-Object System.Drawing.Point(340, 540)
$lblTestPort.AutoSize = $true

$txtTestPort = New-Object System.Windows.Forms.TextBox
$txtTestPort.Location = New-Object System.Drawing.Point(390, 537)
$txtTestPort.Size = New-Object System.Drawing.Size(60, 25)
try { $txtTestPort.Text = ([uri]$script:wsusServer).Port } catch { $txtTestPort.Text = "8530" }

# 測試連線按鈕
$btnRunTest = New-Object System.Windows.Forms.Button
$btnRunTest.Text = "執行連線測試"
$btnRunTest.Location = New-Object System.Drawing.Point(470, 535)
$btnRunTest.Size = New-Object System.Drawing.Size(120, 32)
$btnRunTest.BackColor = [System.Drawing.Color]::WhiteSmoke
$btnRunTest.Add_Click({
    $target = $txtTestIp.Text.Trim()
    $portText = $txtTestPort.Text.Trim()
    
    # 判斷 Port 是否為空，為空則設為 0 觸發 Ping 邏輯
    $port = if ([string]::IsNullOrWhiteSpace($portText)) { 0 } else { [int]$portText }
    
    # 介面顯示進度文字
    $statusLabel.Text = if ($port -eq 0) { "正在 Ping $target..." } else { "正在測試 TCP $target : $port..." }
    $statusLabel.ForeColor = [System.Drawing.Color]::Blue
    [System.Windows.Forms.Application]::DoEvents()

    # 執行測試
    if (Test-TcpPort -TargetHost $target -Port $port) {
        # --- 成功分支 ---
        if ($port -eq 0) {
            $statusLabel.Text = "Ping $target 成功！"
            [System.Windows.Forms.MessageBox]::Show("Ping $target 成功！", "測試結果", 0, 64)
        } else {
            $statusLabel.Text = "連線成功：$target : $port"
            [System.Windows.Forms.MessageBox]::Show("成功連線至 $target : $port", "測試結果", 0, 64)
        }
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
    } else {
        # --- 失敗分支 (多層判斷) ---
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
        
        if ($port -eq 0) {
            # 這是你要的 Ping 失敗分支
            $statusLabel.Text = "Ping 失敗：$target 無回應"
            [System.Windows.Forms.MessageBox]::Show("無法 Ping 通 $target`n`n請檢查：`n1. 目標主機是否在線上`n2. 防火牆是否阻擋 ICMP (Ping)", "Ping 失敗", 0, 16)
        } else {
            # 這是原本的 TCP 連線失敗分支
            $statusLabel.Text = "連線失敗：$target : $port"
            [System.Windows.Forms.MessageBox]::Show("無法連線至 $target : $port`n`n請檢查：`n1. 網路是否通訊`n2. 服務是否啟動`n3. 防火牆 Port $port 是否開啟", "TCP 連線失敗", 0, 16)
        }
    }
})
# 將新組件加入表單
$form.Controls.AddRange(@($lineLabel, $lblTestIp, $txtTestIp, $lblTestPort, $txtTestPort, $btnRunTest))


# --- 底部狀態欄與控制按鈕 ---
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "就緒"
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(40, 660)
$statusLabel.ForeColor = [System.Drawing.Color]::DarkBlue


# --- 功能說明按鈕 ---
$btnHelpMain = New-Object System.Windows.Forms.Button
$btnHelpMain.Text = "功能說明 (Help)"
$btnHelpMain.Size = New-Object System.Drawing.Size(130, 35)
$btnHelpMain.Location = New-Object System.Drawing.Point(40, 700) # 原本重新整理的位置
$btnHelpMain.Add_Click({
    $helpText = @"
=== WSUS / Windows Update 修復工具 功能說明 ===

【左側：修復與重置】
1. 重新向 WSUS 報到：強制觸發客戶端向伺服器傳送目前的更新狀態紀錄。
2. 清除更新快取：停止服務並刪除 SoftwareDistribution 資料夾，解決下載卡住的問題。
3. 完整重置修復：最深層的修復，包含重新註冊 36 個系統 DLL 組件。
4. 設定自動更新：調整登錄檔參數 (AUOptions)，控制系統是否自動下載或重啟。
5. 清除 Client ID：解決多台主機在 WSUS 後台「蓋台」消失的問題。

【右側：診斷與工具】
6. 設定 WSUS Server：手動指定內網更新伺服器 IP，或還原為微軟雲端更新。
7. 檢查更新：直接開啟系統介面進行即時更新掃描。
8. 更新紀錄：查看過去安裝成功的補丁清單。
9. 同步系統時間：修正因「時間不同步」導致的更新驗證失敗 (0x80072F8F)。

【底部：連線診斷】
- 連線測試：若 Port 留白則執行 Ping (ICMP)；輸入 Port 則執行 TCP 通訊埠掃描。
"@
    [System.Windows.Forms.MessageBox]::Show($helpText, "功能手冊", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})


# 重新整理
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "重新整理資訊"
$btnRefresh.Size = New-Object System.Drawing.Size(120, 35)
$btnRefresh.Location = New-Object System.Drawing.Point(180, 700)

# 離開
$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "離開程式"
$btnExit.Size = New-Object System.Drawing.Size(100, 35)
$btnExit.Location = New-Object System.Drawing.Point(580, 700)

# === 加載控制項 ===
$form.Controls.AddRange(@($btn11, $btn12, $btn13, $btn14, $btn15, $btn21, $btn22, $btn23, $btn24,$btn25,$lineLabel, $lblTestIp, $txtTestIp, $lblTestPort, $txtTestPort, $btnRunTest, $statusLabel, $btnHelpMain, $btnRefresh, $btnExit, $infoLabel))

$form.ShowDialog()