# CyberPatriot-Toolkit

— Aedan Johnson (11th Grade, CyberPatriot Team 2, Windows Pro)

## What is this?

This PowerShell toolkit is built for ANY CyberPatriot Windows round (not just specific years!), but anyone can use it for system hardening, maintenance, and competition prep.  
**Everything in the scripts was built by a student for real competition needs and now features universal automation modules for every major scoring category.**

It gives you:
- **Menu-based Windows security-hardening:** Easily run CIS and CyberPatriot-required fixes.
- **Universal Auditor for users, groups, services, updates, policies, and more:** Compliance scanning and auto-remediation for the full CyberPatriot vulnerability scope.
- **Program installer for security/utilities:** Click and install legit programs from a verified list.
- **Antivirus detector:** Checks and lists all common AV solutions, including Microsoft Defender status.
- **Auto-downloader for program installers:** Fetches missing installer files from trusted websites.
- **Scorecard dashboard:** Runs an all-in-one compliance scan to show which scoring items are complete, open, or missing for any round/image.
- **Exportable forensics and audit logs:** Useful for competition submission and investigation.

---

## Table of Contents

- [Features](#features)
- [How To Use](#how-to-use)
- [Universal Menu Breakdown](#universal-menu-breakdown)
- [CyberPatriot Vulnerability Checklist](#cyberpatriot-vulnerability-checklist)
- [Changelog](#changelog)
- [Why?](#why)

---

## Features

- **Runs as Administrator only** (will quit if not)
- Universal scanning, checks, and fixes—no matter which round or image you get!
- Compliance dashboard for all scoring items.
- Easy installer menu for security & utility programs.
- Detection/removal of prohibited software.
- Automated log/event export for forensics.

## How To Use

1. **Download the repo as a zip or clone it:**  
   Click green "Code" > Download ZIP or use `git clone ...`
2. **Place all installer `.exe` and `.msi` files you want in the same folder as the script.**  
   _If your files are missing, the script can auto-download them from official sources._
3. **Right-click on the script (`CyberPatriot-UltimateScript_Version4.ps1`) and 'Run as Administrator'**
4. **Follow the menu prompts!**  
   Type numbers/letters to pick actions.
5. **If you want to change what programs are available:**  
   Edit or add entries in `$installerMap` or the software whitelist/blacklist in the script.

---

## Universal Menu Breakdown

**Main Menu**
```
1. Audit Users
2. Audit Group/Admin Membership
3. Enforce Password/Account Policies
4. Disable Guest/Default Accounts
5. Check for Windows Updates
6. Harden Risky Services
7. Harden Firewall
8. Audit Programs (Blacklist)
9. Audit Listening Network Ports
10. Enforce Network Sharing/RDP Policy
11. Export Forensics/Logs
12. Scorecard Dashboard (Do All)
0. Exit
```

### Audit Features:
- **User Audit:** Lists all local users, offers removal for unauthorized accounts.
- **Admin/Group Audit:** Finds and fixes privilege issues; Admin or RDP groups.
- **Password/Lockout Enforcement:** Minimum password length, history, blank passwords, and lockout settings.
- **Guest/Default Accounts:** Always disables Guest or other default user accounts (critical for scoring).
- **Windows Updates:** Checks and installs most updates for full compliance.
- **Service Hardening:** Disables dangerous or competition-prohibited Windows services (FTP, Telnet, SMBv1, Remote Assistance, etc.).
- **Firewall:** Enables, configures, and logs Windows Firewall for all network profiles.
- **Program Audit:** Detects prohibited/risky programs for bulk removal; customizable blacklist.
- **Port Scanning:** Finds listening/open ports for network security checks.
- **Network Policy:** Disables anonymous SAM enumeration, enforces secure RDP settings, disables simple sharing.
- **Forensics Export:** Outputs event logs for investigation or competition forensics.
- **Scorecard Dashboard:** Runs all checks and prints compliance summary for scoring.

---

## CyberPatriot Vulnerability Checklist

This toolkit systematically covers every major CyberPatriot Windows vulnerability category, including:

**Account Policies**
- Enforce password/lockout requirements
- Detect accounts with blank or weak settings

**Application Security Settings**
- Audit user/group privileges and risky security options

**Application Updates**
- Install Windows updates, application auto-update settings

**Defensive Countermeasures**
- Enable firewall, configure logging
- Detect antivirus status and real-time protection

**Forensic Questions & Log Export**
- Export recent Security/Event logs for quick investigation

**Local Policies**
- Review audit, user rights assignment, security options

**Operating System Updates**
- Installs most available system updates for compliance

**Policy Violation: Malware/Prohibited Files**
- Detect and uninstall blacklisted software, games, hacking utilities

**Service Auditing**
- Bulk enable/disable risky services, with custom lists per round

**Uncategorized Operating System Settings**
- Apply secure group policy, remote access, sharing, screen lock

**User Auditing**
- Confirm authorized users/groups unique to the image, and remove extras

---

## Changelog

**2025-11-12**
- Refactored for UNIVERSAL competition rounds; added dashboard scorecard, audit/export modules, and general compliance automation.
- Menu split between original and universal toolkits (Version 4 adds round-independent features and checks).

**2025-11-10**
- Added auto-download feature for installer files.

**2025-11-07**
- Initial version created; menu-based script, installers, AV detector.

---

## Why?

CyberPatriot scoring always comes down to fundamentals: users, services, policies, updates, risky software, firewall, and logging.  
This toolkit automates everything that recurs *every round*, so you can focus on image investigation, forensics, and speed—no matter what tricks they throw in.

---

### Want to contribute or make it better?

- Fork the repo, submit PRs, or message me directly!
- All students and competition teams welcome. Try new stuff, break things, learn fast.
