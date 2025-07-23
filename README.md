# 🧰 Silent Software Installer (Archived)

This PowerShell script automates the silent installation of a set of common desktop applications and applies system configuration tweaks. It was originally built for post-deployment use in a German language environment and includes unattended installation for Adobe Reader DC, Firefox, WinRAR, VLC, Java, and Adblock Plus.

The script also sets folder view defaults, adjusts registry settings, disables UAC, optionally runs Windows Updates, and creates a scheduled task to open the post-install log.

---

## 🧩 Features

- Silent install logic for:
  - Adobe Reader DC
  - Firefox
  - WinRAR
  - VLC Player
  - Java Runtime
- Adblock Plus extension deployment
- Firefox defaults customization (homepage, default browser, welcome screen)
- System configuration tasks:
  - UAC disablement
  - File Explorer behavior
  - Disk defrag task disablement
  - Windows activation status check
  - Windows Update toggle (optional)
- Scheduled task to display log file on reboot and remove installer

---

## ⚙️ Configurable Variables

| Variable                          | Description |
|----------------------------------|-------------|
| `$DownloadFolder`                | Where installers are saved to be run |
| `$CreateLogFile`                 | Path to install log |
| `$RestartComputer`               | If `true`, restarts machine when finished |
| `$InstallUpdates`                | If `true`, installs available Windows Updates |
| `$Cleanup`                       | If `true`, deletes installer files and temp |
| `$WindowsUpdate_Notification_level` | Sets update behavior (2 = notify, 3 = download, 4 = install) |

---

## 🧪 Requirements

- PowerShell 5.1 or later  
- Local administrator rights  

---

## 🚀 Usage

PS C:\Scripts> .\Silent-Software-Installer.ps1
- Ensure you're running as admin
- Check and set variables as needed
- Optional restart and cleanup will depend on those toggles
- Review the log file after reboot for install outcomes

---

## ⚠️ Disclaimer

This script is shared for educational and archival purposes only. It installs outdated software, uses German language installers, and makes system-level changes that may not be suitable for modern deployments. Always test in a controlled environment before applying to any live machines.