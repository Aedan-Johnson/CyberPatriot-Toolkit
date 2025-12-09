# CyberPatriot Windows Hardening Script

## What is this?

This is an easy, menu-driven PowerShell tool for locking down and checking Windows computers in CyberPatriot competitions.  
It helps you follow the official CyberPatriot Vulnerability Categories (see your event handout) and CIS Windows 11 security rules.

You don’t need to memorize the checklist—a lot of the hard stuff is automated!

---

## Why do I need it?

- It makes sure you don’t forget about things that can cost you points in CyberPatriot (like user accounts, updates, bad programs, passwords, firewall settings, etc).
- Every menu choice matches what Graders/Scoring look for.  
  You just pick a number to check or fix that area!
- It will tell you if something looks good or needs manual fixing.
- You can run all the checks at once, or just work category-by-category with your team.

---

## How do I use it?

1. **Open PowerShell as Administrator** (right-click and "Run as Admin").
2. Go to the folder where this script is saved.
3. Type:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   .\CyberPatriot-Hardening.ps1
   ```
4. The menu will show up. It looks like this (each number is a competition category):

   - 1. Account Policies (Passwords, Lockout)
   - 2. Application Security (Antivirus, Defender, UAC)
   - 3. Application Updates (Windows and Program Updates)
   - 4. Defensive Countermeasures (Firewall, Anti-virus)
   - 5. Forensic Questions (Manual checks/README stuff)
   - 6. Local Policies (Audit, User Rights, Security Options)
   - 7. Operating System Updates (Windows Updates/Service Packs)
   - 8. Policy Violation: Malware (Check/remove hacking/tools/malware)
   - 9. Policy Violation: Prohibited Files (Delete forbidden stuff)
   - 10. Policy Violation: Unwanted Software (Delete games/adware/hacking stuff)
   - 11. Service Auditing (Turn risky services on/off)
   - 12. Uncategorized OS Settings (Sharing, permissions, screen locking)
   - 13. User Auditing (Authorized users/groups only)
   - 14. Run ALL Tasks (auto-run everything)
   - 0. Exit

5. After each check, it tells you what passed and what needs fixing.  
6. Some stuff you must fix manually (like answering forensic questions or checking the README).

---

## What does it actually fix or check?

- Makes password and lockout settings strong
- Makes sure Windows Defender & Firewall are on
- Removes guest/admin accounts you don’t want
- Lists risky programs, games, malware, hacking tools
- Turns off dangerous Windows features/services
- Checks user/group permissions and file shares
- Makes sure Windows and apps are up to date
- Checks for problems in group policy, sharing, unauthorized files...
- Reminds you to check for stuff judges ask in README or Forensics

---

## IMPORTANT! ⚠️

- **Never change or delete stuff in the `C:\CyberPatriot` folder if you’re competing!**
- ALWAYS check the Score Report icon on your desktop for official scoring.
- This script is for practice, training, or self-check/scoring—**not official competition** unless your coach says it’s okay.
- If the script says “manual check required”, get your team to fix it and double-check with the README and your Score Report!

---

## Questions?
Ask your coach, mentor, teacher, or CyberPatriot captain for help.
Or look at the [CyberPatriot Training Docs](https://www.uscyberpatriot.org/competition/training-materials).

---

Good luck, and don’t forget to read the README on your competition image before you run anything!
