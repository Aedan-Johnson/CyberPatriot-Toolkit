<#
.SYNOPSIS
    CyberPatriot All-in-One Script — Menu for Windows Hardening, Program Installs, Antivirus Check

.DESCRIPTION
    By: Aedan Johnson (11th grade, CyberPatriot Team)
    This menu-driven script lets you:
      - Run the most important CyberPatriot fixes (CIS, Windows security stuff)
      - Install legit security tools/utilities through an easy menu
      - Check if any antivirus is running (good for scoring!)

    Just run as admin, pick what you want. It asks before deleting users or making big changes.
    If you want to install or use this, put your installer files in the same folder as this script.

.NOTES
    Made for school CyberPatriot rounds, but anyone can use!
    If you have a suggestion for another tool or menu, tell me at practice!
#>

function Show-MainMenu {
    Clear-Host
    Write-Host "CyberPatriot Ultimate Script - Main Menu" -ForegroundColor Cyan
    Write-Host "-----------------------------------------"
    Write-Host "1. Secure/Check System (CyberPatriot Tasks)"
    Write-Host "2. Install Security & Utility Programs"
    Write-Host "3. Antivirus Software Detector"
    Write-Host "0. Exit"
    Write-Host "-----------------------------------------"
}

function Show-HardeningMenu {
    Write-Host ""
    Write-Host "CyberPatriot Tasks"
    Write-Host "a. Password & Lockout Policy"
    Write-Host "b. Disable Guest Account"
    Write-Host "c. Review/Delete Unauthorized Users"
    Write-Host "d. Search for Music & Game Files"
    Write-Host "e. List Listening Network Ports"
    Write-Host "f. Disable Unneeded Services"
    Write-Host "g. Disable SMBv1"
    Write-Host "h. Configure Firewall & Logging"
    Write-Host "z. Run ALL CyberPatriot Fixes"
    Write-Host "0. Return to Main Menu"
}

function Show-InstallMenu {
    Write-Host ""
    Write-Host "Program Installer Menu"
    Write-Host "--------------------------"
    Write-Host "1. Malwarebytes"
    Write-Host "2. Nessus"
    Write-Host "3. Rapid7 Insight"
    Write-Host "4. Sysinternals Suite"
    Write-Host "5. Firefox"
    Write-Host "6. KeePass"
    Write-Host "7. WinDirStat"
    Write-Host "8. Wireshark"
    Write-Host "9. PuTTY"
    Write-Host "10. Notepad++"
    Write-Host "11. 7-Zip"
    Write-Host "12. Admin Templates (.admx)"
    Write-Host "A. Install ALL of the above"
    Write-Host "0. Return to Main Menu"
    Write-Host "--------------------------"
}

function Show-AVMenu {
    Write-Host ""
    Write-Host "Antivirus Detector"
    Write-Host "--------------------------"
    Write-Host "1. Quick Antivirus Process Scan"
    Write-Host "2. List All Detected Antivirus Processes"
    Write-Host "3. Show Microsoft Defender Status"
    Write-Host "0. Return to Main Menu"
    Write-Host "--------------------------"
}

# Admin check (DO NOT RUN without admin!)
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You must run as Administrator! (Right-click PowerShell, select 'Run as Administrator')"
    exit 1
}

function Pause { Read-Host "`nPress Enter to continue..." }
function Safe-Run { param($ScriptBlock, $Description) try { & $ScriptBlock; Write-Output "OK: $Description" } catch { Write-Warning "FAILED: $Description - $($_.Exception.Message)" } }
function Just-Check { param($ScriptBlock, $Description) try { & $ScriptBlock } catch { Write-Warning "Check failed: $Description - $($_.Exception.Message)" } }

# Program installer mapping -- match the file names to what you have!
$installerMap = @{
    "1"  = @{ Name="Malwarebytes";     File="mbsetup-50010.50010.exe";   Args="/silent" }
    "2"  = @{ Name="Nessus";           File="Nessus-10.8.3-x64.msi";     Args="/quiet" }
    "3"  = @{ Name="Rapid7 Insight";   File="Rapid7Setup-Windows64.exe"; Args="/quiet" }
    "4"  = @{ Name="Sysinternals Suite"; File="SysinternalsSuite.zip";   Args=$null }
    "5"  = @{ Name="Firefox";          File="Firefox Setup.exe";         Args="/S" }
    "6"  = @{ Name="KeePass";          File="KeePass-2.xx-setup.exe";    Args="/SILENT" }
    "7"  = @{ Name="WinDirStat";       File="WinDirStat.exe";            Args="/SILENT" }
    "8"  = @{ Name="Wireshark";        File="Wireshark.exe";             Args="/S" }
    "9"  = @{ Name="PuTTY";            File="putty.exe";                 Args=$null }
    "10" = @{ Name="Notepad++";        File="npp.8.6.0.Installer.exe";   Args="/S" }
    "11" = @{ Name="7-Zip";            File="7zSetup.exe";               Args="/S" }
    "12" = @{ Name="Admin Templates";  File="Administrative Templates (.admx) for Windows 11 October 2021 Update.msi"; Args="/quiet" }
}
function Install-One ($option) {
    $item = $installerMap[$option]
    if (-not $item) { Write-Warning "No program for this choice."; return }
    $path = Join-Path $PSScriptRoot $item.File
    if (-not (Test-Path $path)) { Write-Warning "File $($item.File) not found."; return }
    Write-Host "Installing $($item.Name)..."
    if ($path -like "*.zip") {
        $target = "C:\Sysinternals"
        Expand-Archive -Path $path -DestinationPath $target -Force
        Write-Host "Sysinternals Suite extracted to $target"
    } else {
        try {
            $args = $item.Args
            $customArgs = Read-Host "Extra install arguments for $($item.Name) (Enter for none, or Enter for default: '$args')"
            if ($customArgs) { $args = $customArgs }
            if ($args) {
                Start-Process -FilePath $path -ArgumentList $args -Wait -Verb RunAs
            } else {
                Start-Process -FilePath $path -Wait -Verb RunAs
            }
            Write-Host "Installer for $($item.Name) started."
        } catch {
            Write-Warning "Failed to launch $($item.Name): $($_.Exception.Message)"
        }
    }
}
function Install-All {
    foreach ($key in $installerMap.Keys) {
        Install-One $key
    }
}

# --- Antivirus Detection ---
$avKeywords = @(
    "MsMpEng.exe","avast","kaspersky","norton","mcafee","bitdefender","avg","mbam","clamav","sophos","eset","f-secure","trend","defender"
)
function QuickAVScan {
    $avFound = $false
    $procList = Get-Process | Select-Object -ExpandProperty ProcessName
    foreach ($keyword in $avKeywords) {
        $matched = $procList | Where-Object { $_ -like "*$keyword*" }
        if ($matched) { Write-Host "Antivirus software detected: $matched" -ForegroundColor Green; $avFound = $true }
    }
    if (-not $avFound) { Write-Host "No common antivirus processes detected." -ForegroundColor Yellow }
}
function AllAVProcesses {
    Write-Host "Full process list with possible AV matches highlighted:"
    $procList = Get-Process
    foreach ($proc in $procList) {
        $isAV = $false
        foreach ($k in $avKeywords) {
            if ($proc.ProcessName -like "*$k*") { $isAV = $true }
        }
        if ($isAV) {
            Write-Host "$($proc.ProcessName).exe" -ForegroundColor Green
        } else {
            Write-Host "$($proc.ProcessName).exe"
        }
    }
}
function DefenderStatus {
    try {
        Get-MpComputerStatus | Format-Table AMServiceEnabled,AMServiceRunning,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,DefenderSignaturesOutOfDate -AutoSize
    } catch {
        Write-Warning "Can't check Windows Defender status (maybe you're not on Windows 10/11 or it's disabled)."
    }
}

# --- Hardening Step Functions ---
function Hardening-PasswordLockout {
    $mode = Read-Host "Check or Remediate? Type 'check' or 'remediate'"
    If ($mode.ToLower() -eq "remediate") {
        Safe-Run { net accounts /minpwlen:14 } "Set minimum password length to 14"
        Safe-Run { net accounts /maxpwage:365 } "Set max password age to 365 days"
        Safe-Run { net accounts /minpwage:1 } "Set min password age to 1 day"
        Safe-Run { net accounts /uniquepw:24 } "Set password history to 24"
        Safe-Run { net accounts /lockoutthreshold:5 } "Set lockout to 5 attempts"
        Safe-Run { net accounts /lockoutduration:15 } "Set lockout duration to 15m"
        Safe-Run { net accounts /lockoutwindow:15 } "Set lockout window to 15m"
    } else {
        Just-Check { net accounts } "Current password policy"
    }
    Pause
}
function Hardening-GuestDisable {
    $mode = Read-Host "Check or Remediate? Type 'check' or 'remediate'"
    If ($mode.ToLower() -eq "remediate") {
        Safe-Run { net user Guest /active:no } "Disable Guest account"
    } else {
        Just-Check { net user Guest | Select-String -Pattern "Active" } "Check Guest account status"
    }
    Pause
}
function Hardening-UnauthorizedUsers {
    $authorized = @("Administrator","Guest","DefaultAccount","WDAGUtilityAccount")
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $users) {
        if ($authorized -notcontains $user.Name) {
            Write-Warning "-- Unauthorized user found: $($user.Name)"
            $answer = Read-Host "Delete user '$($user.Name)'? (y/n)"
            if ($answer -eq "y") { Safe-Run { Remove-LocalUser -Name $user.Name } "Delete user $($user.Name)" }
        }
    }
    Pause
}
function Hardening-FunFiles {
    $music = Get-ChildItem -Path 'C:\Users' -Recurse -Include *.mp3,*.wav,*.aac,*.flac,*.m4a,*.ogg -ErrorAction SilentlyContinue | Select-Object -First 10
    $games = Get-ChildItem -Path 'C:\Users' -Recurse -Include *.exe,*.iso,*.zip -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "Games|game|steam" } | Select-Object -First 10
    if ($music) { Write-Host "Music Files:"; $music | ForEach-Object { Write-Host $_.FullName } } else { Write-Host "No music files found." }
    if ($games) { Write-Host "Game/Installer Files:"; $games | ForEach-Object { Write-Host $_.FullName } } else { Write-Host "No game/installer files found." }
    Pause
}
function Hardening-Ports {
    Just-Check { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess } "Listening TCP ports"
    Pause
}
function Hardening-DisableServices {
    $servicesToDisable = @(
        "XblAuthManager","WMPNetworkSvc","Spooler","UmRdpService","RpcLocator",
        "WerSvc","RemoteRegistry","WMSvc","XblGameSave","XboxGipSvc",
        "PushToInstall","WpnService"
    )
    $mode = Read-Host "Check or Remediate? Type 'check' or 'remediate'"
    foreach ($svc in $servicesToDisable) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($null -ne $s) {
            If ($mode.ToLower() -eq "remediate") {
                Safe-Run { Stop-Service -Name $svc -Force -ErrorAction Stop } "Stop service $svc"
                Safe-Run { Set-Service -Name $svc -StartupType Disabled } "Disable $svc"
            } else {
                Just-Check { Write-Host "$svc - Status: $($s.Status); Startup: $($s.StartType)" } "$svc status"
            }
        } else {
            Write-Host "Note: Service $svc not present."
        }
    }
    Pause
}
function Hardening-SMBv1 {
    $mode = Read-Host "Check or Remediate? Type 'check' or 'remediate'"
    If ($mode.ToLower() -eq "remediate") {
        Safe-Run { if (Get-Command -Name Set-SmbServerConfiguration -ErrorAction SilentlyContinue) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false } } "Disable SMB1 (Server)"
        Safe-Run { 
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
            if (-Not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "Start" -Value 4 -Type DWord -Force
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        } "Disable SMBv1 client & remove feature"
        Safe-Run {
            $lmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
            if (-Not (Test-Path $lmPath)) { New-Item -Path $lmPath -Force | Out-Null }
            New-ItemProperty -Path $lmPath -Name "MinSmb2Dialect" -PropertyType DWord -Value 785 -Force | Out-Null
        } "Set SMB minimum dialect"
    } else {
        Just-Check { 
            Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10").Start
            (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation").MinSmb2Dialect
        } "SMB config"
    }
    Pause
}
function Hardening-Firewall {
    $mode = Read-Host "Check or Remediate? Type 'check' or 'remediate'"
    if ($mode.ToLower() -eq "remediate") {
        Safe-Run { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false } "Enable firewall, block inbound"
        Try {
            $privateLog = Join-Path $env:SystemRoot "System32\LogFiles\Firewall\PrivateFW.log"
            $publicLog  = Join-Path $env:SystemRoot "System32\LogFiles\Firewall\PublicFW.log"
            New-Item -ItemType Directory -Path (Split-Path $privateLog) -Force | Out-Null
            Safe-Run { Set-NetFirewallProfile -Profile Private -LogAllowed $true -LogBlocked $true -LogFileName $privateLog -LogMaxSizeKilobytes 16384 } "Private firewall logging"
            Safe-Run { Set-NetFirewallProfile -Profile Public -LogAllowed $true -LogBlocked $true -LogFileName $publicLog -LogMaxSizeKilobytes 16384 } "Public firewall logging"
        } catch {
            Write-Warning "Firewall log settings error: $($_.Exception.Message)"
        }
    } else {
        Just-Check { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,LogFileName,LogMaxSizeKilobytes } "Firewall status/logs"
    }
    Pause
}
function Hardening-All {
    Hardening-PasswordLockout
    Hardening-GuestDisable
    Hardening-UnauthorizedUsers
    Hardening-FunFiles
    Hardening-Ports
    Hardening-DisableServices
    Hardening-SMBv1
    Hardening-Firewall
}

# --- Main MENU LOOP ---
Do {
    Show-MainMenu
    $mainChoice = Read-Host "Enter your choice (number)"
    Switch ($mainChoice) {
        "1" {
            Do {
                Show-HardeningMenu
                $hChoice = Read-Host "Pick a CyberPatriot task (a-h, z for all, 0 back)"
                Switch ($hChoice.ToLower()) {
                    "a" { Hardening-PasswordLockout }
                    "b" { Hardening-GuestDisable }
                    "c" { Hardening-UnauthorizedUsers }
                    "d" { Hardening-FunFiles }
                    "e" { Hardening-Ports }
                    "f" { Hardening-DisableServices }
                    "g" { Hardening-SMBv1 }
                    "h" { Hardening-Firewall }
                    "z" { Hardening-All }
                    "0" { break }
                    Default { Write-Host "Invalid option."; Pause }
                }
            } while ($true)
        }
        "2" {
            Do {
                Show-InstallMenu
                $installChoice = Read-Host "Which program? (number, A for all, 0 back)"
                if ($installChoice -eq "0") { break }
                elseif ($installChoice.ToUpper() -eq "A") { Install-All; Pause }
                elseif ($installerMap.ContainsKey($installChoice)) { Install-One $installChoice; Pause }
                else { Write-Warning "Invalid selection."; Pause }
            } while ($true)
        }
        "3" {
            Do {
                Show-AVMenu
                $avChoice = Read-Host "Pick AV action (number, 0 back)"
                Switch ($avChoice) {
                    "1" { Write-Host "`n--- Quick Antivirus Process Scan ---" -ForegroundColor Yellow; QuickAVScan; Pause }
                    "2" { Write-Host "`n--- Possible AV Processes ---" -ForegroundColor Yellow; AllAVProcesses; Pause }
                    "3" { Write-Host "`n--- Microsoft Defender Status ---" -ForegroundColor Yellow; DefenderStatus; Pause }
                    "0" { break }
                    Default { Write-Host "Invalid option."; Pause }
                }
            } while ($true)
        }
        "0" { Write-Host "Goodbye! Script finished."; }
        Default { Write-Host "Invalid menu choice."; Pause }
    }
} while ($mainChoice -ne "0")