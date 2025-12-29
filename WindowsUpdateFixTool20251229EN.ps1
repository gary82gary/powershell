# WSUS / Windows Update Repair Tool
# Latest Update: 2025.12.29
# ==================================================================================

$version = "Modified: 2025.12.29  Contact: gary82gary@gmail.com"

# --- Elevation Check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating privileges..."
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Font Definitions
$uiFont = New-Object System.Drawing.Font("Segoe UI", 9)
$titleFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)

# === System Info Function ===
function Update-Information {
    try {
        $script:wsusServer = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer
        if (-not $script:wsusServer) { $script:wsusServer = "Not Configured" }
    } catch { $script:wsusServer = "Read Failed" }

    try {
        $script:clientID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue).SusClientId
        if (-not $script:clientID) { $script:clientID = "Not Configured" }
    } catch { $script:clientID = "Read Failed" }

    try {
        $script:ntpServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue).NtpServer
        if (-not $script:ntpServer) { $script:ntpServer = "Not Configured" }
    } catch { $script:ntpServer = "Read Failed" }

    try {
        $script:localIP = (ipconfig | Select-String "IPv4" | ForEach-Object { ($_ -split ":")[1].Trim() }) -join ", "
    } catch { $script:localIP = "Read Failed" }
}
Update-Information

function Test-TcpPort {
    param (
        [string]$TargetHost,
        [int]$Port = 0,
        [int]$Timeout = 3000
    )
    if ($Port -eq 0) {
        try {
            return Test-Connection -ComputerName $TargetHost -Count 1 -Quiet -ErrorAction SilentlyContinue
        } catch { return $false }
    }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($wait -and $client.Connected) {
            $client.EndConnect($asyncResult)
            return $true
        }
        return $false
    } catch { return $false }
    finally { $client.Dispose() }
}

$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$majorVersion = [version]$osVersion

# === Form Initialization ===
$form = New-Object System.Windows.Forms.Form
$form.Text = "WSUS / Windows Update Repair Tool v2.9"
$form.Size = New-Object System.Drawing.Size(750, 800)
$form.StartPosition = "CenterScreen"
$form.Font = $uiFont

$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.AutoSize = $true
$infoLabel.Location = New-Object System.Drawing.Point(25, 15)
$infoLabel.Font = $titleFont
$infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer"
$form.Controls.Add($infoLabel)

$btnW = 280; $btnH = 40
$L = 40; $R = 380; $startY = 180; $vGap = 55

# ======================================================================
# Left Column: Repair Functions
# ======================================================================

$btn11 = New-Object System.Windows.Forms.Button
$btn11.Text = "1. Reset WSUS Reporting"
$btn11.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn11.Location = New-Object System.Drawing.Point($L, $startY)
$btn11.Add_Click({
    $statusLabel.Text = "Executing reporting commands..." ; [System.Windows.Forms.Application]::DoEvents()
    Start-Process "wuauclt.exe" "/resetauthorization /detectnow"
    Start-Process "wuauclt.exe" "/reportnow"
    (get-service wuauserv).Refresh()
    (New-Object -ComObject Microsoft.Update.Autoupdate).detectNow()
    [System.Windows.Forms.MessageBox]::Show("WSUS reporting commands issued.", "Success", 0, 64)
    $statusLabel.Text = "Commands issued."
})

$btn12 = New-Object System.Windows.Forms.Button
$btn12.Text = "2. Clear Update Cache"
$btn12.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn12.Location = New-Object System.Drawing.Point($L, ($startY + $vGap))
$btn12.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("This will:`n1. Stop WU Services`n2. Delete SoftwareDistribution & Catroot2`n3. Restart Services`n`nContinue?", "Confirm Cache Reset", 3, 48)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping services..." ; [System.Windows.Forms.Application]::DoEvents()
        Stop-Service wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        $statusLabel.Text = "Cleaning directories..." ; [System.Windows.Forms.Application]::DoEvents()
        Remove-Item "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        $statusLabel.Text = "Restarting services..." ; [System.Windows.Forms.Application]::DoEvents()
        Start-Service wuauserv, bits, cryptsvc, msiserver
        $statusLabel.Text = "Cache cleared."
        [System.Windows.Forms.MessageBox]::Show("Windows Update cache cleared successfully.", "Success")
    }
})

$btn13 = New-Object System.Windows.Forms.Button
$btn13.Text = "3. Full Component Reset (DLL)"
$btn13.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn13.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*2))
$btn13.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Full reset including 36 DLL registrations. Restart recommended after completion. Proceed?", "Full Reset", 3, 48)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping all related services..." ; [System.Windows.Forms.Application]::DoEvents()
        $services = @("w32time", "wuauserv", "bits", "msiserver", "appidsvc", "cryptsvc", "ccmexec")
        foreach ($s in $services) { Stop-Service $s -Force -ErrorAction SilentlyContinue }
        $statusLabel.Text = "Registering components..." ; [System.Windows.Forms.Application]::DoEvents()
        $dlls = @("atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll", "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll")
        foreach ($d in $dlls) {
            $statusLabel.Text = "Registering: $d" ; [System.Windows.Forms.Application]::DoEvents()
            Start-Process "regsvr32.exe" "/s $env:WinDir\system32\$d" -Wait
        }
        $statusLabel.Text = "Restarting services..." ; [System.Windows.Forms.Application]::DoEvents()
        foreach ($s in $services) { Start-Service $s -ErrorAction SilentlyContinue }
        $statusLabel.Text = "Full reset complete."
        [System.Windows.Forms.MessageBox]::Show("Deep component repair finished.", "Complete")
    }
})

$btn14 = New-Object System.Windows.Forms.Button
$btn14.Text = "4. Configure Auto Update (AU)"
$btn14.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn14.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*3))
$btn14.Add_Click({
    $inputForm = New-Object System.Windows.Forms.Form
    $inputForm.Text = "AU Policy Settings"
    $inputForm.Size = New-Object System.Drawing.Size(400, 450)
    $inputForm.StartPosition = "CenterParent"
    $flowLayout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock="Top"; Height=300; Padding=20; AutoScroll=$true }
    $inputForm.Controls.Add($flowLayout)
    $settings = [ordered]@{"NoAUShutdownOption"="1"; "NoAUAsDefaultShutdownOption"="1"; "NoAutoUpdate"="1"; "AUOptions"="2"}
    $textBoxes = @{}
    foreach ($key in $settings.Keys) {
        $p = New-Object System.Windows.Forms.Panel -Property @{ Size="340, 35" }
        $lbl = New-Object System.Windows.Forms.Label -Property @{ Text="$key :"; Location="0, 5"; Size="180, 20" }
        $txt = New-Object System.Windows.Forms.TextBox -Property @{ Text=$settings[$key]; Location="180, 2"; Size="140, 25" }
        $p.Controls.AddRange(@($lbl, $txt)) ; $flowLayout.Controls.Add($p) ; $textBoxes[$key] = $txt
    }
    $btnPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock="Bottom"; Height=80 }
    $inputForm.Controls.Add($btnPanel)
    $btnHelp = New-Object System.Windows.Forms.Button -Property @{ Text="Help"; Size="100, 30"; Location="80, 20" }
    $btnHelp.Add_Click({ [System.Windows.Forms.MessageBox]::Show("AUOptions:`n1: Notify Download/Install`n2: Notify Download (Rec)`n3: Auto Download/Notify Install`n4: Auto Scheduled Install`n`nRecommended: 1112`nDefault: 0004", "Help") })
    $okButton = New-Object System.Windows.Forms.Button -Property @{ Text="Apply"; Size="100, 30"; Location="200, 20" }
    $okButton.Add_Click({
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }
        foreach ($name in $textBoxes.Keys) {
            $val = $textBoxes[$name].Text
            if ($val -match '^\d+$') { Set-ItemProperty $regPath -Name $name -Value ([int]$val) }
        }
        $inputForm.Close() ; $btnRefresh.PerformClick()
    })
    $btnPanel.Controls.AddRange(@($btnHelp, $okButton)) ; $inputForm.ShowDialog()
})

$btn15 = New-Object System.Windows.Forms.Button
$btn15.Text = "5. Reset WSUS Client ID"
$btn15.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn15.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*4))
$btn15.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("Reset SusClientId to fix duplicate IDs in WSUS console. Proceed?", "Reset Client ID", 3, 32) -eq "Yes") {
        Stop-Service wuauserv -Force
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId","SusClientIDValidation" -ErrorAction SilentlyContinue
        Start-Service wuauserv
        $btnRefresh.PerformClick()
        [System.Windows.Forms.MessageBox]::Show("Client ID reset. New ID will be generated upon next report.", "Done")
    }
})

# ======================================================================
# Right Column: Tools & Diagnostics
# ======================================================================

$btn21 = New-Object System.Windows.Forms.Button
$btn21.Text = "6. Config WSUS Server"
$btn21.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn21.Location = New-Object System.Drawing.Point($R, $startY)
$btn21.Add_Click({
    $subForm = New-Object System.Windows.Forms.Form -Property @{ Text="WSUS Server Config"; Size="420, 260"; StartPosition="CenterParent"; Font=$uiFont; FormBorderStyle="FixedDialog" }
    $lblIp = New-Object System.Windows.Forms.Label -Property @{ Text="WSUS IP/Host:"; Location="20, 30"; AutoSize=$true }
    $txtIp = New-Object System.Windows.Forms.TextBox -Property @{ Location="140, 27"; Size="220, 25" }
    try { $txtIp.Text = ([uri]$script:wsusServer).Host } catch { }
    $lblPort = New-Object System.Windows.Forms.Label -Property @{ Text="Port:"; Location="20, 75"; AutoSize=$true }
    $txtPort = New-Object System.Windows.Forms.TextBox -Property @{ Text="8530"; Location="140, 72"; Size="80, 25" }
    try { $txtPort.Text = ([uri]$script:wsusServer).Port } catch { }
    $btnApply = New-Object System.Windows.Forms.Button -Property @{ Text="Apply"; Location="60, 140"; Size="120, 35" }
    $btnApply.Add_Click({
        $url = "http://$($txtIp.Text.Trim()):$($txtPort.Text.Trim())"
        if ([System.Windows.Forms.MessageBox]::Show("Point to $url?", "Confirm", 4, 32) -eq "Yes") {
            $p = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
            New-Item "$p\AU" -Force | Out-Null
            Set-ItemProperty $p -Name "WUServer" -Value $url
            Set-ItemProperty $p -Name "WUStatusServer" -Value $url
            Set-ItemProperty "$p\AU" -Name "UseWUServer" -Value 1
            Restart-Service wuauserv -Force ; $subForm.Close() ; $btnRefresh.PerformClick()
        }
    })
    $btnClear = New-Object System.Windows.Forms.Button -Property @{ Text="Reset to Default"; Location="220, 140"; Size="120, 35" }
    $btnClear.Add_Click({
        if ([System.Windows.Forms.MessageBox]::Show("Revert to Microsoft Cloud Update?", "Warning", 4, 48) -eq "Yes") {
            $p = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
            Remove-ItemProperty $p -Name "WUServer","WUStatusServer" -EA SilentlyContinue
            Remove-ItemProperty "$p\AU" -Name "UseWUServer" -EA SilentlyContinue
            Restart-Service wuauserv -Force ; $subForm.Close() ; $btnRefresh.PerformClick()
        }
    })
    $subForm.Controls.AddRange(@($lblIp, $txtIp, $lblPort, $txtPort, $btnApply, $btnClear)) ; $subForm.ShowDialog()
})

$btn22 = New-Object System.Windows.Forms.Button
$btn22.Text = "7. Check for Updates Now"
$btn22.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn22.Location = New-Object System.Drawing.Point($R, ($startY + $vGap))
$btn22.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("Trigger update check?", "Update", 3, 32) -eq "Yes") {
        $btnRefresh.PerformClick()
        if ($majorVersion.Build -ge 22000) { Start-Process "ms-settings:windowsupdate" }
        else { Start-Process "ms-settings:windowsupdate-action" }
    }
})

$btn23 = New-Object System.Windows.Forms.Button
$btn23.Text = "8. View Update History"
$btn23.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn23.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*2))
$btn23.Add_Click({ Start-Process "ms-settings:windowsupdate-history" })

$btn24 = New-Object System.Windows.Forms.Button
$btn24.Text = "9. Sync System Time (NTP)"
$btn24.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn24.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*3))
$btn24.Add_Click({
    $statusLabel.Text = "Syncing NTP..." ; $statusLabel.ForeColor = "Blue" ; [System.Windows.Forms.Application]::DoEvents()
    Start-Service w32time -EA SilentlyContinue
    $result = $(w32tm /resync /force 2>&1) | Out-String
    $statusLabel.Text = "NTP: " + $result.Trim()
    Update-Information ; $btnRefresh.PerformClick()
})

# ======================================================================
# Connectivity Diagnostics (Bottom Area)
# ======================================================================

$lineLabel = New-Object System.Windows.Forms.Label -Property @{ Text="--------------------------- Connectivity Diagnostics ---------------------------"; Location="40, 500"; Size="650, 25"; ForeColor="Gray" }
$lblTestIp = New-Object System.Windows.Forms.Label -Property @{ Text="Target IP/Host:"; Location="40, 540"; AutoSize=$true }
$txtTestIp = New-Object System.Windows.Forms.TextBox -Property @{ Location="160, 537"; Size="160, 25" }
try { $txtTestIp.Text = ([uri]$script:wsusServer).Host } catch { }
$lblTestPort = New-Object System.Windows.Forms.Label -Property @{ Text="Port:"; Location="340, 540"; AutoSize=$true }
$txtTestPort = New-Object System.Windows.Forms.TextBox -Property @{ Location="390, 537"; Size="60, 25" }
try { $txtTestPort.Text = ([uri]$script:wsusServer).Port } catch { }
$btnRunTest = New-Object System.Windows.Forms.Button -Property @{ Text="Run Test"; Location="470, 535"; Size="120, 32"; BackColor="WhiteSmoke" }
$btnRunTest.Add_Click({
    $pTxt = $txtTestPort.Text.Trim() ; $port = if ([string]::IsNullOrWhiteSpace($pTxt)) { 0 } else { [int]$pTxt }
    $statusLabel.Text = if ($port -eq 0) { "Ping $target..." } else { "TCP $target : $port..." } ; $statusLabel.ForeColor = "Blue" ; [System.Windows.Forms.Application]::DoEvents()
    if (Test-TcpPort -TargetHost $txtTestIp.Text.Trim() -Port $port) {
        $msg = if ($port -eq 0) { "Ping Success!" } else { "TCP Connect Success!" }
        $statusLabel.Text = $msg ; $statusLabel.ForeColor = "Green" ; [System.Windows.Forms.MessageBox]::Show($msg, "Result", 0, 64)
    } else {
        $msg = if ($port -eq 0) { "Ping Failed" } else { "TCP Connect Failed" }
        $statusLabel.Text = $msg ; $statusLabel.ForeColor = "Red" ; [System.Windows.Forms.MessageBox]::Show($msg, "Result", 0, 16)
    }
})

# --- Bottom Bar ---
$statusLabel = New-Object System.Windows.Forms.Label -Property @{ Text="Ready"; AutoSize=$true; Location="40, 660"; ForeColor="DarkBlue" }
$btnRefresh = New-Object System.Windows.Forms.Button -Property @{ Text="Refresh Info"; Size="130, 35"; Location="40, 700" }
$btnRefresh.Add_Click({ Update-Information ; $infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer" })
$btnExit = New-Object System.Windows.Forms.Button -Property @{ Text="Exit"; Size="100, 35"; Location="200, 700" }
$btnExit.Add_Click({ $form.Close() })

$form.Controls.AddRange(@($btn11, $btn12, $btn13, $btn14, $btn15, $btn21, $btn22, $btn23, $btn24, $lineLabel, $lblTestIp, $txtTestIp, $lblTestPort, $txtTestPort, $btnRunTest, $statusLabel, $btnRefresh, $btnExit, $infoLabel))
$form.ShowDialog()