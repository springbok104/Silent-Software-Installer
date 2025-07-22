# 💻 Silent Software Installer (Archived)

This PowerShell script automates the silent installation and configuration of multiple desktop applications alongside key system settings. It was originally designed for post-deployment use in German-language environments and serves as a workstation provisioning tool.

---

## 📦 Key Capabilities

- Silent installation of apps: Adobe Reader DC, Firefox, WinRAR, VLC, Java, and Adblock Plus
- System configuration: registry edits, folder view customization, UAC and update behavior
- Firefox default settings and extension install automation
- Windows license checks, defrag task disablement, and cleanup routines
- Scheduled task to launch post-deploy logs and remove installer script

---

## 🧪 Requirements

- PowerShell 5.1
- Internet access for downloading installer files
- Local admin rights
- Tested on Windows 10 and Server 2016 (German builds)

---

## ⚠️ Notes

- Installer URLs are based on version scraping logic and may no longer be reliable
- Firefox extensions are configured via custom scripting
- Includes system changes such as disabling UAC and altering Windows Update
- German-language installers are used for all apps

---

## ⚠️ Disclaimer

This script is shared for archival and educational purposes. It reflects provisioning tasks from past environments and includes outdated software versions and configuration routines. Please review and adapt the logic before applying it to any live or modern systems. Use at your own discretion and always test in a controlled setting.