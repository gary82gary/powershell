# WSUS / Windows Update Repair Tool
# Revision History:
# 20250626  Added connection test feature
# 20250725  Improved UI display
# 20250806  Updated options popup
# 20250908  Added automatic update button
# 20251205  Modified text display, added automatic elevation
# 20251229  Modified UI and multiple functional logics
# 20260203  Added Help button
# ==================================================================================

$version = "Modified: 2026.02.03  Contact: publicegaryhuang@googlegroups.com"

# --- Automatic Elevation to Administrator ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Font Definitions
$uiFont = New-Object System.Drawing.Font("Segoe UI", 10)
$titleFont = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)

# === Function: Update System Information ===
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
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$majorVersion = [version]$osVersion

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
$infoLabel.Font = New-Object System.Drawing.Font("Consolas", 10)
$infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer"
$form.Controls.Add($infoLabel)

# --- Layout Parameters ---
$btnW = 280; $btnH = 40
$L = 40; $R = 380; $startY = 180; $vGap = 55

# ======================================================================
# Left Column: Repair Functions
# ======================================================================

# 1. Reset WSUS Reporting
$btn11 = New-Object System.Windows.Forms.Button
$btn11.Text = "1. Reset WSUS Reporting"
$btn11.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn11.Location = New-Object System.Drawing.Point($L, $startY)
$btn11.Add_Click({
    $statusLabel.Text = "Executing reporting commands..." ; [System.Windows.Forms.Application]::DoEvents()
    $path = if (Test-Path "$env:windir\Sysnative") { "$env:windir\Sysnative\wuauclt.exe" } 
            else { "$env:windir\System32\wuauclt.exe" }

    Start-Process -FilePath $path -ArgumentList "/resetauthorization /detectnow" -Wait
    Start-Process -FilePath $path -ArgumentList "/reportnow" -Wait
    (Get-Service wuauserv).Refresh()
    (New-Object -ComObject Microsoft.Update.Autoupdate).detectNow()
    [System.Windows.Forms.MessageBox]::Show($form, "Reporting commands sent to WSUS.", "Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    $statusLabel.Text = "Reporting commands dispatched."
})

# 2. Clear Update Cache
$btn12 = New-Object System.Windows.Forms.Button
$btn12.Text = "2. Clear Update Cache"
$btn12.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn12.Location = New-Object System.Drawing.Point($L, ($startY + $vGap))
$btn12.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
This action will:

1. Stop Windows Update services (wuauserv, BITS, cryptsvc, msiserver)
2. Delete update cache folders (SoftwareDistribution, catroot2)
3. Restart the services

This will clear the local update history. Recommended only if updates are failing or stuck.

Proceed with clearing the cache?
", "Clear Update Cache", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping Windows Update related services..." ; [System.Windows.Forms.Application]::DoEvents()
        Stop-Service wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        
        $statusLabel.Text = "Removing SoftwareDistribution and Catroot2 folders..." ; [System.Windows.Forms.Application]::DoEvents()
        Remove-Item "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        
        $statusLabel.Text = "Starting services..." ; [System.Windows.Forms.Application]::DoEvents()
        Start-Service wuauserv, bits, cryptsvc, msiserver
        $statusLabel.Text = "Cache cleared successfully."
        [System.Windows.Forms.MessageBox]::Show("Update cache has been cleared.")
    }
})

# 3. Full Reset (DLL Registration)
$btn13 = New-Object System.Windows.Forms.Button
$btn13.Text = "3. Full Reset (Inc. DLL Reg)"
$btn13.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn13.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*2))
$btn13.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
This action will:

1. Stop all related services (wuauserv, BITS, cryptsvc, msiserver, appidsvc, ccmexec)
2. Delete cache folders and downloader data
3. Re-register essential system DLLs
4. Restart services

A reboot may be required if errors persist after this process. Use this for deep repair.

Proceed with full reset?
", "Full System Reset", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
        $statusLabel.Text = "Stopping services..."; [System.Windows.Forms.Application]::DoEvents()
        $services = @("w32time", "wuauserv", "bits", "msiserver", "appidsvc", "cryptsvc", "ccmexec")
        foreach ($s in $services) { Stop-Service $s -Force -ErrorAction SilentlyContinue }

        $statusLabel.Text = "Cleaning files and cache..."; [System.Windows.Forms.Application]::DoEvents()
        Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\System32\catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue
        
        $dlls = @(
            "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll", "vbscript.dll",
            "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll",
            "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll",
            "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll",
            "wups.dll", "wups2.dll", "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
        )
        
        foreach ($d in $dlls) {
            $statusLabel.Text = "Registering: $d"; [System.Windows.Forms.Application]::DoEvents()
            Start-Process "regsvr32.exe" "/s $env:WinDir\system32\$d" -Wait
        }

        $statusLabel.Text = "Restarting services..."; [System.Windows.Forms.Application]::DoEvents()
        foreach ($s in $services) { Start-Service $s -ErrorAction SilentlyContinue }
        
        $statusLabel.Text = "Deep repair completed."
        [System.Windows.Forms.MessageBox]::Show("Repair finished.")
    }
})

# 4. Set Automatic Update (AU) Params
$btn14 = New-Object System.Windows.Forms.Button
$btn14.Text = "4. Configure AU Parameters"
$btn14.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn14.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*3))
$btn14.Add_Click({
    $inputForm = New-Object System.Windows.Forms.Form
    $inputForm.Text = "AU Parameter Settings"
    $inputForm.Size = New-Object System.Drawing.Size(400, 450)
    $inputForm.StartPosition = "CenterParent"
    $inputForm.Font = $uiFont

    $flowLayout = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowLayout.Dock = "Top"
    $flowLayout.Height = 300
    $flowLayout.Padding = New-Object System.Windows.Forms.Padding(20)
    $flowLayout.AutoScroll = $true
    $inputForm.Controls.Add($flowLayout)

    $settings = [ordered]@{
        "NoAUShutdownOption"           = "1"
        "NoAUAsDefaultShutdownOption"  = "1"
        "NoAutoUpdate"                 = "1"
        "AUOptions"                    = "2"
    }

    $textBoxes = @{}

    foreach ($key in $settings.Keys) {
        $p = New-Object System.Windows.Forms.Panel -Property @{ Size = "340, 35" }
        $lbl = New-Object System.Windows.Forms.Label -Property @{ Text = "$key :"; Location = "0, 5"; Size = "180, 20" }
        $txt = New-Object System.Windows.Forms.TextBox -Property @{ Text = $settings[$key]; Location = "180, 2"; Size = "140, 25" }
        $p.Controls.AddRange(@($lbl, $txt))
        $flowLayout.Controls.Add($p)
        $textBoxes[$key] = $txt
    }

    $btnPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = "Bottom"; Height = 80 }
    $inputForm.Controls.Add($btnPanel)

    $btnHelp = New-Object System.Windows.Forms.Button -Property @{ Text = "Help"; Size = "100, 30"; Location = "80, 20" }
    $btnHelp.Add_Click({
        [System.Windows.Forms.MessageBox]::Show(@"
AU Parameter Descriptions:

- NoAUShutdownOption = 1  
  Do not show 'Install Updates and Shutdown' in the Start menu.

- NoAUAsDefaultShutdownOption = 1  
  Default shutdown option is not 'Update and Shutdown'.

- NoAutoUpdate = 1  
  Disable automatic updates (manual update still available).

- AUOptions  
1: Notify for download and install
2: Notify for download, manual install (Recommended)
3: Auto download, notify for install
4: Auto download and install
5: Allow local admin to choose setting

Suggested Config: 1112
Microsoft Default: 0004
"@, "Parameter Help")
    })

    $okButton = New-Object System.Windows.Forms.Button -Property @{ Text = "Apply"; Size = "100, 30"; Location = "200, 20"; DialogResult = "OK" }
    $okButton.Add_Click({
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }
        foreach ($name in $textBoxes.Keys) {
            $val = $textBoxes[$name].Text
            if ($val -match '^\d+$') { Set-ItemProperty $regPath -Name $name -Value ([int]$val) }
        }
        $inputForm.Close()
        [System.Windows.Forms.MessageBox]::Show("Registry updated. Restarting services to apply.")
        $btnRefresh.PerformClick()
    })

    $btnPanel.Controls.AddRange(@($btnHelp, $okButton))
    $inputForm.ShowDialog()
})

# 5. Reset WSUS Client ID
$btn15 = New-Object System.Windows.Forms.Button
$btn15.Text = "5. Reset WSUS Client ID"
$btn15.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn15.Location = New-Object System.Drawing.Point($L, ($startY + $vGap*4))
$btn15.Add_Click({
$confirm = [System.Windows.Forms.MessageBox]::Show("
Confirm Reset WSUS Client ID?

Use this if computers are 'disappearing' or 'overwriting' each other in the WSUS console due to duplicate IDs (common in cloned VMs). 
A new ID will be generated upon next check-in.
", "Reset Client ID", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq "Yes") {
        Stop-Service wuauserv -Force
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId","SusClientIDValidation" -ErrorAction SilentlyContinue
        Start-Service wuauserv
        $btnRefresh.PerformClick()
        [System.Windows.Forms.MessageBox]::Show($form, "Client ID cleared. New ID will be generated at next reporting cycle.", "Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# ======================================================================
# Right Column: Tools & Diagnostics
# ======================================================================

# 6. Set WSUS Server
$btn21 = New-Object System.Windows.Forms.Button
$btn21.Text = "Configure WSUS Server"
$btn21.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn21.Location = New-Object System.Drawing.Point($R, $startY)
$btn21.Add_Click({
    $subForm = New-Object System.Windows.Forms.Form
    $subForm.Text = "WSUS Server Settings"
    $subForm.Size = New-Object System.Drawing.Size(420, 260)
    $subForm.StartPosition = "CenterParent"
    $subForm.Font = $uiFont
    $subForm.FormBorderStyle = "FixedDialog"
    $subForm.MaximizeBox = $false

    $lblIp = New-Object System.Windows.Forms.Label
    $lblIp.Text = "WSUS Host/IP:"
    $lblIp.Location = New-Object System.Drawing.Point(20, 30); $lblIp.AutoSize = $true
    
    $txtIp = New-Object System.Windows.Forms.TextBox
    $txtIp.Location = New-Object System.Drawing.Point(140, 27); $txtIp.Size = New-Object System.Drawing.Size(220, 25)
    try { $txtIp.Text = ([uri]$script:wsusServer).Host } catch { $txtIp.Text = "" }

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "Port:"
    $lblPort.Location = New-Object System.Drawing.Point(20, 75); $lblPort.AutoSize = $true

    $txtPort = New-Object System.Windows.Forms.TextBox
    $txtPort.Location = New-Object System.Drawing.Point(140, 72); $txtPort.Size = New-Object System.Drawing.Size(80, 25)
    try { $txtPort.Text = ([uri]$script:wsusServer).Port } catch { $txtPort.Text = "8530" }

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply Settings"
    $btnApply.Location = New-Object System.Drawing.Point(60, 140); $btnApply.Size = New-Object System.Drawing.Size(120, 35)
    $btnApply.Add_Click({
        $newIp = $txtIp.Text.Trim()
        $newPort = $txtPort.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($newIp) -or -not ($newPort -as [int])) {
            [System.Windows.Forms.MessageBox]::Show("Enter a valid IP/Host and Port.", "Error", 0, 16); return
        }
        $url = "http://$newIp`:$newPort"
        if ([System.Windows.Forms.MessageBox]::Show("Point to: $url ?", "Confirm", 4, 32) -eq "Yes") {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value $url
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value $url
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1
            Restart-Service wuauserv -Force
            $subForm.Close(); $btnRefresh.PerformClick()
        }
    })

    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = "Remove WSUS"
    $btnClear.Location = New-Object System.Drawing.Point(220, 140); $btnClear.Size = New-Object System.Drawing.Size(120, 35)
    $btnClear.Add_Click({
        if ([System.Windows.Forms.MessageBox]::Show("This will revert settings to default Windows Update (Cloud). Proceed?", "Warning", 4, 48) -eq "Yes") {
            try {
                $wuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
                if (Test-Path $wuPath) {
                    Remove-ItemProperty -Path $wuPath -Name "WUServer" -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $wuPath -Name "WUStatusServer" -ErrorAction SilentlyContinue
                }
                if (Test-Path "$wuPath\AU") { Remove-ItemProperty -Path "$wuPath\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue }
                Restart-Service wuauserv -Force
                $statusLabel.Text = "WSUS removed. Reverted to default."
                $subForm.Close(); $btnRefresh.PerformClick()
            } catch { [System.Windows.Forms.MessageBox]::Show("Failed: $($_.Exception.Message)") }
        }
    })

    $subForm.Controls.AddRange(@($lblIp, $txtIp, $lblPort, $txtPort, $btnApply, $btnClear))
    $subForm.ShowDialog()
})

# 7. Check for Updates
$btn22 = New-Object System.Windows.Forms.Button
$btn22.Text = "Check for Updates"
$btn22.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn22.Location = New-Object System.Drawing.Point($R, ($startY + $vGap))
$btn22.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("Start update scan now?", "Update Check", 3, 32) -eq "Yes") {
        $btnRefresh.PerformClick()
        if ($majorVersion.Build -ge 22000) { Start-Process "ms-settings:windowsupdate" }
        else { Start-Process "ms-settings:windowsupdate-action" }
    }
})

# 8. Update History
$btn23 = New-Object System.Windows.Forms.Button
$btn23.Text = "View Update History"
$btn23.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn23.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*2))
$btn23.Add_Click({ Start-Process "ms-settings:windowsupdate-history" })

# 9. Sync Time (NTP)
$btn24 = New-Object System.Windows.Forms.Button
$btn24.Text = "Sync System Time (NTP)"
$btn24.Size = New-Object System.Drawing.Size($btnW, $btnH)
$btn24.Location = New-Object System.Drawing.Point($R, ($startY + $vGap*3))
$btn24.Add_Click({
    $statusLabel.Text = "Syncing NTP time..."
    $statusLabel.ForeColor = [System.Drawing.Color]::Blue
    [System.Windows.Forms.Application]::DoEvents()
    Start-Service w32time -ErrorAction SilentlyContinue
    $result = $(w32tm /resync /force 2>&1) | Out-String
    $statusLabel.Text = "NTP Result: " + $result.Trim()
    Update-Information; $btnRefresh.PerformClick()
})

# ======================================================================
# Connection Diagnostics (Bottom Area)
# ======================================================================

$lineLabel = New-Object System.Windows.Forms.Label
$lineLabel.Text = "--------------------------- Connection Diagnostics ---------------------------"
$lineLabel.Location = New-Object System.Drawing.Point($L, 500)
$lineLabel.Size = New-Object System.Drawing.Size(650, 25)
$lineLabel.ForeColor = [System.Drawing.Color]::Gray

$lblTestIp = New-Object System.Windows.Forms.Label
$lblTestIp.Text = "Target IP/Host:"
$lblTestIp.Location = New-Object System.Drawing.Point($L, 540); $lblTestIp.AutoSize = $true

$txtTestIp = New-Object System.Windows.Forms.TextBox
$txtTestIp.Location = New-Object System.Drawing.Point(160, 537); $txtTestIp.Size = New-Object System.Drawing.Size(160, 25)
try { $txtTestIp.Text = ([uri]$script:wsusServer).Host } catch { $txtTestIp.Text = "" }

$lblTestPort = New-Object System.Windows.Forms.Label
$lblTestPort.Text = "Port:"
$lblTestPort.Location = New-Object System.Drawing.Point(340, 540); $lblTestPort.AutoSize = $true

$txtTestPort = New-Object System.Windows.Forms.TextBox
$txtTestPort.Location = New-Object System.Drawing.Point(390, 537); $txtTestPort.Size = New-Object System.Drawing.Size(60, 25)
try { $txtTestPort.Text = ([uri]$script:wsusServer).Port } catch { $txtTestPort.Text = "8530" }

$btnRunTest = New-Object System.Windows.Forms.Button
$btnRunTest.Text = "Run Test"
$btnRunTest.Location = New-Object System.Drawing.Point(470, 535); $btnRunTest.Size = New-Object System.Drawing.Size(120, 32)
$btnRunTest.BackColor = [System.Drawing.Color]::WhiteSmoke
$btnRunTest.Add_Click({
    $target = $txtTestIp.Text.Trim()
    $portText = $txtTestPort.Text.Trim()
    $port = if ([string]::IsNullOrWhiteSpace($portText)) { 0 } else { [int]$portText }
    
    $statusLabel.Text = if ($port -eq 0) { "Pinging $target..." } else { "Testing TCP $target : $port..." }
    $statusLabel.ForeColor = [System.Drawing.Color]::Blue
    [System.Windows.Forms.Application]::DoEvents()

    if (Test-TcpPort -TargetHost $target -Port $port) {
        if ($port -eq 0) {
            $statusLabel.Text = "Ping $target Successful!"
            [System.Windows.Forms.MessageBox]::Show("Ping $target successful!", "Result", 0, 64)
        } else {
            $statusLabel.Text = "Connected: $target : $port"
            [System.Windows.Forms.MessageBox]::Show("Successfully connected to $target : $port", "Result", 0, 64)
        }
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
    } else {
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
        if ($port -eq 0) {
            $statusLabel.Text = "Ping Failed: $target unreachable"
            [System.Windows.Forms.MessageBox]::Show("Could not Ping $target`n`nCheck:`n1. Host is online`n2. ICMP (Ping) is allowed by firewall", "Ping Failed", 0, 16)
        } else {
            $statusLabel.Text = "Connection Failed: $target : $port"
            [System.Windows.Forms.MessageBox]::Show("Could not connect to $target : $port`n`nCheck:`n1. Network connectivity`n2. Service is running`n3. Firewall port $port is open", "TCP Failed", 0, 16)
        }
    }
})

# Bottom Status and Control
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(40, 660)
$statusLabel.ForeColor = [System.Drawing.Color]::DarkBlue

# Main Help Button
$btnHelpMain = New-Object System.Windows.Forms.Button
$btnHelpMain.Text = "Help Guide"
$btnHelpMain.Size = New-Object System.Drawing.Size(130, 35)
$btnHelpMain.Location = New-Object System.Drawing.Point(40, 700)
$btnHelpMain.Add_Click({
    $helpText = @"
=== WSUS / Windows Update Repair Tool Manual ===

[Left: Repair & Reset]
1. Reset WSUS Reporting: Force client to report status to the server.
2. Clear Update Cache: Deletes SoftwareDistribution folder to fix stuck downloads.
3. Full Reset: Deep repair including re-registration of 36 system DLLs.
4. Configure AU: Control automatic download/reboot behaviors.
5. Reset Client ID: Fixes duplicate ID issues in WSUS consoles.

[Right: Tools & Diagnosis]
6. Configure WSUS: Point to local server IP or revert to Cloud Update.
7. Check for Updates: Open Windows Update UI for manual scan.
8. Update History: Review installed KB patches.
9. Sync Time: Fixes update verification errors (0x80072F8F) caused by clock drift.

[Bottom: Diagnostics]
- Connection Test: Tests Ping (leave port blank) or TCP Port connectivity.
"@
    [System.Windows.Forms.MessageBox]::Show($helpText, "User Guide", 0, 64)
})

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh Info"
$btnRefresh.Size = New-Object System.Drawing.Size(120, 35)
$btnRefresh.Location = New-Object System.Drawing.Point(180, 700)
$btnRefresh.Add_Click({ Update-Information; $infoLabel.Text = "$version`n`nHostname: $env:computername`nLocal IP: $localIP`nWSUS Server: $wsusServer`nWSUS Client ID: $clientID`nNTP Server: $ntpServer" })

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Exit"
$btnExit.Size = New-Object System.Drawing.Size(100, 35)
$btnExit.Location = New-Object System.Drawing.Point(580, 700)
$btnExit.Add_Click({ $form.Close() })

# === Add Controls ===
$form.Controls.AddRange(@($btn11, $btn12, $btn13, $btn14, $btn15, $btn21, $btn22, $btn23, $btn24, $lineLabel, $lblTestIp, $txtTestIp, $lblTestPort, $txtTestPort, $btnRunTest, $statusLabel, $btnHelpMain, $btnRefresh, $btnExit, $infoLabel))

$form.ShowDialog()