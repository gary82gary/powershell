# WSUS / Windows Update Repair Tool
# Latest Update: 2026.02.03
# ==================================================================================

$version = "Modified: 2026.02.03  Contact: publicegaryhuang@googlegroups.com"

# --- Elevation Check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
        if (-not $script:wsusServer) { $script:wsusServer = "Not Set" }
    } catch { $script:wsusServer = "Read Failed" }

    try {
        $script:clientID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue).SusClientId
        if (-not $script:clientID) { $script:clientID = "Not Set" }
    } catch { $script:clientID = "Read Failed" }

    try {
        $script:ntpServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue).NtpServer
        if (-not $script:ntpServer) { $script:ntpServer = "Not Set" }
    } catch { $script:ntpServer = "Read Failed" }

    try {
        $script:localIP = (ipconfig | Select-String "IPv4" | ForEach-Object { ($_ -split ":")[1].Trim() }) -join ", "
    } catch { $script:localIP = "Read Failed" }
}
Update-Information

# --- Precise Connectivity Test ---
function Test-TcpPort {
    param (
        [string]$TargetHost,
        [int]$Port = 0,       
        [int]$Timeout = 3000  
    )

    if ($Port -eq 0) {
        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            return ($p.Send($TargetHost, 1000).Status -eq "Success")
        } catch {
            return $false
        }
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

$majorVersion = [version](Get-CimInstance Win32_OperatingSystem).Version

# === Form Initialization ===
$form = New-Object System.Windows.Forms.Form
$form.Text = "WSUS / Windows Update Repair Tool"
$form.Size = New-Object System.Drawing.Size(730, 800)
$form.StartPosition = "CenterScreen"
$form.Font = $uiFont

# --- Info Label ---
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.AutoSize = $true
$infoLabel.Location = New-Object System.Drawing.Point(25, 15)
$infoLabel.Font = $titleFont
$infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer"
$form.Controls.Add($infoLabel)

$btnW = 280; $btnH = 40; $L = 40; $R = 380; $startY = 180; $vGap = 55

# ======================================================================
# Left Column: Repair Functions
# ======================================================================

$btn11 = New-Object System.Windows.Forms.Button
$btn11.Text = "1. Reset WSUS Reporting"
$btn11.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn11.Location = New-Object System.Drawing.Point($L, $startY)
$btn11.Add_Click({
    $statusLabel.Text = "Executing reporting commands..." ; [System.Windows.Forms.Application]::DoEvents()
    $path = if (Test-Path "$env:windir\Sysnative") { "$env:windir\Sysnative\wuauclt.exe" } else { "$env:windir\System32\wuauclt.exe" }
    Start-Process -FilePath $path -ArgumentList "/resetauthorization /detectnow" -Wait
    Start-Process -FilePath $path -ArgumentList "/reportnow" -Wait
    (get-service wuauserv).Refresh()
    (New-Object -ComObject Microsoft.Update.Autoupdate).detectNow()
    [System.Windows.Forms.MessageBox]::Show("Reporting commands issued.", "Success", 0, 64)
    $statusLabel.Text = "Done."
})

$btn12 = New-Object System.Windows.Forms.Button
$btn12.Text = "2. Clear Update Cache"
$btn12.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn12.Location = New-Object System.Drawing.Point($L, ($startY + $vGap))
$btn12.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("This will stop services and delete SoftwareDistribution folder. Proceed?", "Clear Cache", 3, 48)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping Services..." ; [System.Windows.Forms.Application]::DoEvents()
        Stop-Service wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service wuauserv, bits, cryptsvc, msiserver
        $statusLabel.Text = "Cache cleared."
        [System.Windows.Forms.MessageBox]::Show("Cache cleared successfully.")
    }
})

$btn13 = New-Object System.Windows.Forms.Button
$btn13.Text = "3. Full DLL Component Reset"
$btn13.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn13.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*2))
$btn13.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Deep repair: register 36 system DLLs. Restart may be required. Proceed?", "Full Reset", 3, 48)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping Services..." ; [System.Windows.Forms.Application]::DoEvents()
        $services = @("w32time", "wuauserv", "bits", "msiserver", "appidsvc", "cryptsvc", "ccmexec")
        foreach ($s in $services) { Stop-Service $s -Force -EA SilentlyContinue }
        $dlls = @("atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll", "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll")
        foreach ($d in $dlls) {
            $statusLabel.Text = "Registering: $d" ; [System.Windows.Forms.Application]::DoEvents()
            Start-Process "regsvr32.exe" "/s $env:WinDir\system32\$d" -Wait
        }
        foreach ($s in $services) { Start-Service $s -ErrorAction SilentlyContinue }
        $statusLabel.Text = "Deep repair completed."
        [System.Windows.Forms.MessageBox]::Show("Full repair completed.")
    }
})

$btn14 = New-Object System.Windows.Forms.Button
$btn14.Text = "4. Configure Auto-Update (AU)"
$btn14.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn14.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*3))
$btn14.Add_Click({
    $inputForm = New-Object System.Windows.Forms.Form
    $inputForm.Text = "AU Policy Configuration"
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
    $btnHelp.Add_Click({ [System.Windows.Forms.MessageBox]::Show("AUOptions:`n2: Notify Download (Recommended)`n4: Auto Install`n`nRecommended: 1112`nDefault: 0004", "Help") })
    $okButton = New-Object System.Windows.Forms.Button -Property @{ Text="Apply"; Size="100, 30"; Location="200, 20" }
    $okButton.Add_Click({
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }
        foreach ($name in $textBoxes.Keys) { Set-ItemProperty $regPath -Name $name -Value ([int]$textBoxes[$name].Text) }
        $inputForm.Close(); $btnRefresh.PerformClick()
    })
    $btnPanel.Controls.AddRange(@($btnHelp, $okButton)) ; $inputForm.ShowDialog()
})

$btn15 = New-Object System.Windows.Forms.Button
$btn15.Text = "5. Reset WSUS Client ID"
$btn15.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn15.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*4))
$btn15.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("Reset SusClientId to fix duplication issues? This will restart wuauserv.", "Confirm", 3, 32) -eq "Yes") {
        Stop-Service wuauserv -Force
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId","SusClientIDValidation" -EA SilentlyContinue
        Start-Service wuauserv
        $btnRefresh.PerformClick()
        [System.Windows.Forms.MessageBox]::Show("Client ID reset. New ID will generate on next report.")
    }
})

# ======================================================================
# Right Column: Tools
# ======================================================================

$btn21 = New-Object System.Windows.Forms.Button
$btn21.Text = "6. Config WSUS Server"
$btn21.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn21.Location = New-Object System.Drawing.Point($R, $startY)
$btn21.Add_Click({
    $subForm = New-Object System.Windows.Forms.Form -Property @{ Text="WSUS Server Settings"; Size="420, 260"; StartPosition="CenterParent"; Font=$uiFont; FormBorderStyle="FixedDialog" }
    $lblIp = New-Object System.Windows.Forms.Label -Property @{ Text="WSUS IP/Host:"; Location="20, 30"; AutoSize=$true }
    $txtIp = New-Object System.Windows.Forms.TextBox -Property @{ Location="140, 27"; Size="220, 25" }
    try { $txtIp.Text = ([uri]$script:wsusServer).Host } catch { }
    $lblPort = New-Object System.Windows.Forms.Label -Property @{ Text="Port:"; Location="20, 75"; AutoSize=$true }
    $txtPort = New-Object System.Windows.Forms.TextBox -Property @{ Text="8530"; Location="140, 72"; Size="80, 25" }
    try { $txtPort.Text = ([uri]$script:wsusServer).Port } catch { }
    $btnApply = New-Object System.Windows.Forms.Button -Property @{ Text="Apply"; Location="60, 140"; Size="120, 35" }
    $btnApply.Add_Click({
        $url = "http://$($txtIp.Text.Trim()):$($txtPort.Text.Trim())"
        if ([System.Windows.Forms.MessageBox]::Show("Point WSUS to $url?", "Confirm", 4, 32) -eq "Yes") {
            New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value $url
            Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value $url
            Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1
            Restart-Service wuauserv -Force; $subForm.Close(); $btnRefresh.PerformClick()
        }
    })
    $btnClear = New-Object System.Windows.Forms.Button -Property @{ Text="Restore Default"; Location="220, 140"; Size="120, 35" }
    $btnClear.Add_Click({
        if ([System.Windows.Forms.MessageBox]::Show("Restore to default Microsoft Update?", "Warning", 4, 48) -eq "Yes") {
            Remove-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer","WUStatusServer" -EA SilentlyContinue
            Remove-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -EA SilentlyContinue
            Restart-Service wuauserv -Force; $subForm.Close(); $btnRefresh.PerformClick()
        }
    })
    $subForm.Controls.AddRange(@($lblIp, $txtIp, $lblPort, $txtPort, $btnApply, $btnClear)) ; $subForm.ShowDialog()
})

$btn22 = New-Object System.Windows.Forms.Button
$btn22.Text = "7. System Check Update"
$btn22.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn22.Location = New-Object System.Drawing.Point($R, ($startY + $vGap))
$btn22.Add_Click({
    $btnRefresh.PerformClick()
    if ($majorVersion.Build -ge 22000) { Start-Process "ms-settings:windowsupdate" } else { Start-Process "ms-settings:windowsupdate-action" }
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
    $statusLabel.Text = "Syncing NTP..." ; [System.Windows.Forms.Application]::DoEvents()
    Start-Service w32time -EA SilentlyContinue
    & w32tm /resync /force
    $statusLabel.Text = "NTP Sync Sent." ; $btnRefresh.PerformClick()
})

# ======================================================================
# Connectivity Section
# ======================================================================

$lineLabel = New-Object System.Windows.Forms.Label; $lineLabel.Text = "--------------------------- Connectivity Diagnostics ---------------------------"
$lineLabel.Location = New-Object System.Drawing.Point($L, 500); $lineLabel.Size = New-Object System.Drawing.Size(650, 25); $lineLabel.ForeColor = [System.Drawing.Color]::Gray

$lblTestIp = New-Object System.Windows.Forms.Label; $lblTestIp.Text = "Target IP:"; $lblTestIp.Location = "40, 540"; $lblTestIp.AutoSize = $true
$txtTestIp = New-Object System.Windows.Forms.TextBox; $txtTestIp.Location = "120, 537"; $txtTestIp.Size = "160, 25"
try { $txtTestIp.Text = ([uri]$script:wsusServer).Host } catch { }

$lblTestPort = New-Object System.Windows.Forms.Label; $lblTestPort.Text = "Port (0=Ping):"; $lblTestPort.Location = "300, 540"; $lblTestPort.AutoSize = $true
$txtTestPort = New-Object System.Windows.Forms.TextBox; $txtTestPort.Location = "390, 537"; $txtTestPort.Size = "60, 25"; $txtTestPort.Text = "8530"

$btnRunTest = New-Object System.Windows.Forms.Button; $btnRunTest.Text = "Run Test"; $btnRunTest.Location = "470, 535"; $btnRunTest.Size = "120, 32"; $btnRunTest.BackColor = "WhiteSmoke"
$btnRunTest.Add_Click({
    $target = $txtTestIp.Text.Trim(); $pTxt = $txtTestPort.Text.Trim()
    $port = if ([string]::IsNullOrWhiteSpace($pTxt)) { 0 } else { [int]$pTxt }
    $statusLabel.Text = if ($port -eq 0) { "Pinging $target..." } else { "TCP Testing $target : $port..." }
    $statusLabel.ForeColor = "Blue" ; [System.Windows.Forms.Application]::DoEvents()

    if (Test-TcpPort -TargetHost $target -Port $port) {
        $statusLabel.Text = "Success"; $statusLabel.ForeColor = "Green"
        [System.Windows.Forms.MessageBox]::Show("Connection Success!", "Result", 0, 64)
    } else {
        $statusLabel.Text = "Failed"; $statusLabel.ForeColor = "Red"
        $msg = if ($port -eq 0) { "Ping Failed - Host unreachable." } else { "TCP Connect Failed - Port closed or blocked." }
        [System.Windows.Forms.MessageBox]::Show($msg, "Result", 0, 16)
    }
})

# --- Footer ---
$statusLabel = New-Object System.Windows.Forms.Label; $statusLabel.Text = "Ready"; $statusLabel.AutoSize = $true; $statusLabel.Location = "40, 660"; $statusLabel.ForeColor = "DarkBlue"
$btnHelpMain = New-Object System.Windows.Forms.Button; $btnHelpMain.Text = "Manual (Help)"; $btnHelpMain.Size = "130, 35"; $btnHelpMain.Location = "40, 700"
$btnHelpMain.Add_Click({
    $helpText = "Manual:`n1. Reset WSUS Reporting: Force client to sync status with server.`n2. Clear Cache: Delete SoftwareDistribution folder.`n3. Full Reset: Deep component repair (DLLs).`n4. AU Config: Adjust registry update parameters.`n5. Reset Client ID: Fix duplicate IDs in WSUS console.`n`nDiagnostics:`n- Ping: Set Port to 0 to test ICMP connection.`n- TCP: Input port (e.g., 8530) for port testing."
    [System.Windows.Forms.MessageBox]::Show($helpText, "Information")
})

$btnRefresh = New-Object System.Windows.Forms.Button; $btnRefresh.Text = "Refresh Info"; $btnRefresh.Size = "120, 35"; $btnRefresh.Location = "180, 700"
$btnRefresh.Add_Click({ Update-Information; $infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nClient ID: $clientID`nNTP Server: $ntpServer" })

$btnExit = New-Object System.Windows.Forms.Button; $btnExit.Text = "Exit Program"; $btnExit.Size = "100, 35"; $btnExit.Location = "580, 700"
$btnExit.Add_Click({ $form.Close() })

$form.Controls.AddRange(@($btn11, $btn12, $btn13, $btn14, $btn15, $btn21, $btn22, $btn23, $btn24, $lineLabel, $lblTestIp, $txtTestIp, $lblTestPort, $txtTestPort, $btnRunTest, $statusLabel, $btnHelpMain, $btnRefresh, $btnExit, $infoLabel))
$form.ShowDialog()