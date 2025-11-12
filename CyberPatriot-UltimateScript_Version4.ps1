<#
.SYNOPSIS
    CyberPatriot Universal Script — Automated Windows Hardening & Compliance Toolkit

.DESCRIPTION
    By: Aedan Johnson (CyberPatriot Windows Pro)
    This script provides universal features for any CyberPatriot round, covering:
      - Automated user, group, and privilege audits
      - Enforcement of password/account policies
      - System/service hardening (firewall, SMB, updates)
      - Program install/removal (whitelist/blacklist support)
      - Listening port/network policy checks
      - Scorecard dashboard to track compliance
      - Forensics/log export features for easy scoring

    Run as an administrator! All destructive changes ask before proceeding.

.NOTES
    Generalized for ANY CyberPatriot round. Student-built, ready for customization.
#>

### -- UNIVERSAL MODULES/HELPERS -- ###
function Pause { Read-Host "`nPress Enter to continue..." }
function Safe-Run { param($ScriptBlock, $Description) try { & $ScriptBlock; Write-Host "OK: $Description" } catch { Write-Warning "FAILED: $Description - $($_.Exception.Message)" } }
function Just-Check { param($ScriptBlock, $Description) try { & $ScriptBlock } catch { Write-Warning "Check failed: $Description - $($_.Exception.Message)" } }

If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run as Administrator! (Right-click PowerShell, Run as Admin)"
    exit 1
}

### -- FEATURE 1: Automated User Audit & Management -- ###
function Audit-Users {
    $allowedUsers = @("Administrator","Guest","DefaultAccount","WDAGUtilityAccount")
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $unauthorized = @()
    foreach ($user in $users) {
        if ($allowedUsers -notcontains $user.Name) {
            Write-Warning "-- Unauthorized user found: $($user.Name)"
            $unauthorized += $user.Name
        }
    }
    # Bulk removal
    if ($unauthorized) {
        $ans = Read-Host "Remove ALL unauthorized users? (y/n)"
        if ($ans -eq "y") {
            foreach ($u in $unauthorized) { Safe-Run { Remove-LocalUser -Name $u } "Deleted user $u" }
        }
    }
    Pause
}

### -- FEATURE 2: Group & Admin Privilege Audit -- ###
function Audit-Groups {
    $adminGroup = "Administrators"
    $remoteDesktop = "Remote Desktop Users"
    Write-Host "`nAdministrators Group:"
    $admins = Get-LocalGroupMember -Group $adminGroup
    $allowed = @("Administrator")
    foreach ($user in $admins) {
        if ($allowed -notcontains $user.Name) {
            Write-Warning "$($user.Name) is in $adminGroup (flagged)"
            $rem = Read-Host "Remove $($user.Name) from $adminGroup? (y/n)"
            if ($rem -eq "y") { Safe-Run { Remove-LocalGroupMember $adminGroup $user.Name } "Removed $user.Name from $adminGroup" }
        }
    }
    Write-Host "`nRemote Desktop Users:"
    $rdUsers = Get-LocalGroupMember -Group $remoteDesktop
    foreach ($user in $rdUsers) {
        Write-Host $user.Name
    }
    Pause
}

### -- FEATURE 3: Password and Account Policy Enforcement -- ###
function Enforce-AccountPolicy {
    Safe-Run { net accounts /minpwlen:14 } "Set minimum password length to 14"
    Safe-Run { net accounts /maxpwage:365 } "Set max password age to 365 days"
    Safe-Run { net accounts /minpwage:1 } "Set min password age to 1 day"
    Safe-Run { net accounts /uniquepw:24 } "Password history to 24 values"
    Safe-Run { net accounts /lockoutthreshold:5 } "Lockout after 5 attempts"
    Safe-Run { net accounts /lockoutduration:15 } "Lockout duration to 15m"
    Safe-Run { net accounts /lockoutwindow:15 } "Lockout window to 15m"
    # Blank passwords prompt
    $blank = net user | Select-String "No password"
    if ($blank) { Write-Warning "Accounts found with blank passwords!" }
    Pause
}

### -- FEATURE 4: Guest & Default Accounts Disabled -- ###
function Enforce-DisableGuestDefaults {
    Safe-Run { net user Guest /active:no } "Guest account disabled"
    Safe-Run { net user DefaultAccount /active:no } "DefaultAccount disabled"
    Pause
}

### -- FEATURE 5: OS Updates Check -- ###
function Audit-WindowsUpdate {
    Write-Host "`nChecking for Windows Updates... (this may take time)"
    Try {
        Get-WindowsUpdate
        Write-Host "Updates listed. Run 'Install-WindowsUpdate' if remediation needed."
    } catch {
        Write-Warning "Windows Update module not found. Please install PSWindowsUpdate."
    }
    Pause
}

### -- FEATURE 6: Service Hardening -- ###
function Harden-Services {
    $svcList = @(
        "XblAuthManager","WMPNetworkSvc","Spooler","UmRdpService","RpcLocator",
        "WerSvc","RemoteRegistry","WMSvc","XblGameSave","XboxGipSvc","PushToInstall","WpnService",
        "FTP","Telnet"
    )
    foreach ($svc in $svcList) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($null -ne $s) {
            Safe-Run { Stop-Service $svc -Force -ErrorAction Stop } "Service $svc stopped"
            Safe-Run { Set-Service $svc -StartupType Disabled } "Service $svc disabled"
        }
    }
    Pause
}

### -- FEATURE 7: Firewall and Logging -- ###
function Enforce-Firewall {
    Safe-Run { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false } "Firewall enabled, inbound blocked"
    Pause
}

### -- FEATURE 8: Whitelist/Blacklist Program Audit -- ###
function Audit-Programs {
    # Blacklist scanning (can add 'games', 'keyloggers', etc)
    $blacklist = @("wireshark","ccleaner","nmap","putty","hackingtool") # demo entries
    Write-Host "`nScanning for blacklisted programs..."
    $apps = Get-WmiObject -Query "SELECT Name FROM Win32_Product"
    foreach ($item in $apps) {
        foreach ($bad in $blacklist) {
            if ($item.Name -like "*$bad*") {
                Write-Warning "Blacklisted: $($item.Name)"
                $rem = Read-Host "Uninstall $($item.Name)? (y/n)"
                if ($rem -eq "y") { msiexec.exe /x $item.Name /quiet }
            }
        }
    }
    Pause
}

### -- FEATURE 9: Port Audit -- ###
function Audit-Ports {
    $listening = Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
    Write-Host "`nListening Ports:"
    $listening | Format-Table
    Pause
}

### -- FEATURE 10: Network Sharing Policy Enforcement -- ###
function Enforce-NetworkPolicy {
    # Disable anonymous SAM enumeration
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
    # Enforce RDP network-level authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    Pause
}

### -- FEATURE 11: Forensics & Log Export -- ###
function Export-Forensics {
    $logPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\CyberPatriot_Forensics_$(Get-Date -Format 'yyyyMMdd').txt"
    Get-EventLog -LogName Security -Newest 100 | Out-File $logPath
    Write-Host "Exported Event Logs to $logPath"
    Pause
}

### -- FEATURE 12: Universal Scorecard Dashboard -- ###
function Show-Scorecard {
    Write-Host "`n--- Universal Compliance Scorecard ---" -ForegroundColor Cyan
    Write-Host "User Audit:"
    Audit-Users
    Write-Host "Group/Admin Audit:"
    Audit-Groups
    Write-Host "Account Policies:"
    Enforce-AccountPolicy
    Write-Host "Guest/Defaults Disabled:"
    Enforce-DisableGuestDefaults
    Write-Host "Windows Update Status:"
    Audit-WindowsUpdate
    Write-Host "Service Hardening:"
    Harden-Services
    Write-Host "Firewall:"
    Enforce-Firewall
    Write-Host "Software Blacklist:"
    Audit-Programs
    Write-Host "Listening Ports:"
    Audit-Ports
    Write-Host "Network Sharing Policy:"
    Enforce-NetworkPolicy
    Write-Host "Log/Forensics Export:"
    Export-Forensics
    Pause
}

### -- UNIVERSAL MAIN MENU -- ###
function Show-UniversalMenu {
    Clear-Host
    Write-Host "CyberPatriot Universal Toolkit - Main Menu" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------------"
    Write-Host "1. Audit Users"
    Write-Host "2. Audit Group/Admin Membership"
    Write-Host "3. Enforce Password/Account Policies"
    Write-Host "4. Disable Guest/Default Accounts"
    Write-Host "5. Check for Windows Updates"
    Write-Host "6. Harden Risky Services"
    Write-Host "7. Harden Firewall"
    Write-Host "8. Audit Programs (Blacklist)"
    Write-Host "9. Audit Listening Network Ports"
    Write-Host "10. Enforce Network Sharing/RDP Policy"
    Write-Host "11. Export Forensics/Logs"
    Write-Host "12. Scorecard Dashboard (Do All)"
    Write-Host "0. Exit"
    Write-Host "-----------------------------------------------------------"
}

Do {
    Show-UniversalMenu
    $uChoice = Read-Host "Choose Universal Task (1-12, 0 exit)"
    Switch ($uChoice) {
        "1" { Audit-Users }
        "2" { Audit-Groups }
        "3" { Enforce-AccountPolicy }
        "4" { Enforce-DisableGuestDefaults }
        "5" { Audit-WindowsUpdate }
        "6" { Harden-Services }
        "7" { Enforce-Firewall }
        "8" { Audit-Programs }
        "9" { Audit-Ports }
        "10" { Enforce-NetworkPolicy }
        "11" { Export-Forensics }
        "12" { Show-Scorecard }
        "0" { Write-Host "Goodbye! Script finished."; }
        Default { Write-Host "Invalid option."; Pause }
    }
} while ($uChoice -ne "0")

#################################################################################
#########                  YOUR ORIGINAL SCRIPT BELOW                   #########
#################################################################################
# Refer to file: CyberPatriot-UltimateScript_Version3.ps1 for original features #
#################################################################################

<# ========== ORIGINAL SCRIPT ========== #>
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
    Write-Host "2. Sysinternals Suite"
    Write-Host "3. Firefox"
    Write-Host "4. KeePass"
    Write-Host "5. WinDirStat"
    Write-Host "6. Wireshark"
    Write-Host "7. PuTTY"
    Write-Host "8. Notepad++"
    Write-Host "9. 7-Zip"
    Write-Host "10. Admin Templates (.admx)"
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
    "2"  = @{ Name="Sysinternals Suite"; File="SysinternalsSuite.zip";   Args=$null }
    "3"  = @{ Name="Firefox";          File="Firefox Setup.exe";         Args="/S" }
    "4"  = @{ Name="KeePass";          File="KeePass-2.xx-setup.exe";    Args="/SILENT" }
    "5"  = @{ Name="WinDirStat";       File="WinDirStat.exe";            Args="/SILENT" }
    "6"  = @{ Name="Wireshark";        File="Wireshark.exe";             Args="/S" }
    "7"  = @{ Name="PuTTY";            File="putty.exe";                 Args=$null }
    "8" = @{ Name="Notepad++";        File="npp.8.6.0.Installer.exe";   Args="/S" }
    "9" = @{ Name="7-Zip";            File="7zSetup.exe";               Args="/S" }
    "10" = @{ Name="Admin Templates";  File="Administrative Templates (.admx) for Windows 11 October 2021 Update.msi"; Args="/quiet" }
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
