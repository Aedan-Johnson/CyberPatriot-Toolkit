# CyberPatriot-UltimateScript

— Aedan Johnson (11th Grade, CyberPatriot Team 2, Windows Pro)

## What is this?

This PowerShell script is my all-in-one toolkit for CyberPatriot Windows rounds, but anyone can use it for system hardening, maintenance, or quick setups. **Everything in the script was built by a student competitor, for other students or beginners.**

It gives you:
- **Menu-based Windows security-hardening:** Easily run (or just check) CIS and CyberPatriot-required fixes.
- **Installer menu for security/utilities:** Click and install legit programs (no hassle hunting for downloads).
- **Antivirus detector:** Quickly checks if any AV is running—including Microsoft Defender status.

---

## Table of Contents

- [Features](#features)
- [How To Use](#how-to-use)
- [Menu Breakdown (Full Features)](#menu-breakdown-full-features)
- [Changelog (What Changed, When)](#changelog-what-changed-when)
- [Why? (Student Perspective)](#why-student-perspective)

---

## Features

- **Runs as Administrator only** (will quit if not)
- One script—no dependencies (just place program installers in the same folder)
- **Main Menu:**
    - 1. CyberPatriot Security Hardening (CIS recommendations)
    - 2. Program Installer (pick one or all from a categorized menu)
    - 3. Antivirus Detector (detects almost any AV and checks Defender)
    - 0. Exit

- **Everything is interactive and beginner-friendly:**
    - Each step asks you before making major changes (like deleting users)
    - Check or Remediate modes for system tweaks
    - Clear, logical subscreens for each task

---

## How To Use

1. **Download the repo as a zip or clone it:**  
   Click green "Code" > Download ZIP or `git clone ...`
2. **Place all installer `.exe` and `.msi` files you want in the same folder as the script.**  
   (Match the filenames to those in the script or adjust `$installerMap`.)
3. **Right-click on `CyberPatriot-UltimateScript.ps1` and 'Run as Administrator'**
4. **Follow the menu prompts!**  
   Type numbers/letters to pick actions.
5. **If you want to change what programs are available:**  
   Just add file references in `$installerMap` (see script or this README).

---

## Menu Breakdown (Full Features)

**Main Menu**
```
1. Secure/Check System (CyberPatriot Tasks)
2. Install Security & Utility Programs
3. Antivirus Software Detector
0. Exit
```

### 1. Secure/Check System (CyberPatriot Tasks)
- a. Password & Lockout Policy (Enforce or check strong passwords, lockouts)
- b. Disable Guest Account (no open guest doors)
- c. Review/Delete Unauthorized Users (shows local accounts, offers delete)
- d. Search for Music & Game Files (looks for "fun" files to clean)
- e. List Listening Network Ports (find open ports that shouldn't be open)
- f. Disable Unneeded Services (turn off risky or CIS-unsanctioned Windows services)
- g. Disable SMBv1 (close the big old Windows file sharing vuln)
- h. Configure Firewall & Logging (block inbound, enable logs as needed)
- z. Run ALL CyberPatriot Fixes (does it all in one go)
- 0. Back

### 2. Install Security & Utility Programs

_Principle: No more hunting for the right sites! Just click and install real tools. Change the list to what your team/coach wants._

(Default programs & their expected file names are in `$installerMap` in the script.)

- Malwarebytes
- Nessus
- Rapid7 Insight Agent
- Sysinternals Suite (unzipped to C:\Sysinternals)
- Firefox
- KeePass
- WinDirStat
- Wireshark
- PuTTY
- Notepad++
- 7-Zip
- Admin Templates (.admx)
- "A" = Install all (runs everything available)
- 0 = Back

### 3. Antivirus Detector

- 1. Quick Antivirus Process Scan (checks for running AV processes)
- 2. List All Detected Antivirus Processes (shows all process names, highlights AV)
- 3. Show Microsoft Defender Status (uses Windows cmdlets)
- 0. Back

---

## Changelog (What Changed, When)

**2025-11-07**
- Initial version created:
    - Menu-driven script, everything in one file.
    - Main menu: CyberPatriot tasks, installer, antivirus detector.
    - Installer sub-menu for Malwarebytes, Nessus, Rapid7, Sysinternals, Firefox, KeePass, WinDirStat, Wireshark, PuTTY, Notepad++, 7-Zip, Admin Templates.
    - Antivirus detection sub-menu (quick scan, full process list with color highlights, Defender check).
    - All CIS/CyberPatriot hardening steps gathered and integrated into submenus.
    - Every menu/option asks and double-checks before any destructive action.

- All features proposed through [this AI-assisted GitHub Copilot session].

**Features roadmap/candidate ideas for the future:**
- Add logging to .txt file for scoring reports
- Tutor/explanation system ("What is this option/step?")
- Auto-download latest program installers (less manual download before rounds)
- Allow custom scripts/fixes to be dropped into a special folder for menu integration

---

## Why? (Student Perspective)

I made this because at competitions, it wastes tons of time either typing commands or hunting for tools, and sometimes it's easy to forget what CIS wants. This script fixes that.  
If you want to change something, just do it—send feedback to your team's next member or make a pull request!

---

### Want to contribute or make it better?

- Fork it, open a PR, or message me (Aedan Johnson) or our coach.
- Beginners and other 11th graders: seriously, try stuff! That's how you learn.