<#
.DISCLAIMER
    ⚠️ This script is provided for educational and archival purposes only.

    - It installs outdated software versions that may no longer be secure or supported.
    - It uses German installers and configurations.
    - It makes system-level changes including disabling UAC, modifying registry settings, and altering Windows Update behavior.
    - It is not intended for use in production environments without thorough review and adaptation.

    Use at your own risk. Always test in a controlled environment before applying to any live systems.
    
.SYNOPSIS
    Automates the silent installation and configuration of common applications and system settings on a Windows machine.

.DESCRIPTION
    This script performs the following operations:
        1. Downloads and installs the latest available (at time of writing) German-language versions of Adobe Reader DC, Firefox, WinRAR, VLC, Java, and Adblock Plus.
        2. Sets execution policy and disables UAC.
        3. Configures File Explorer, folder view settings, and Firefox defaults.
        4. Checks Windows activation status and disables scheduled defrag.
        5. Optionally installs Windows Updates and restarts the system.
        6. Creates a scheduled task to open the log file on reboot and deletes the script.
        7. Cleans up downloaded installer files and temporary Firefox extension scripts.

.REQUIREMENTS
    - PowerShell 5.1
    - Internet access to download installers
    - Local administrator privileges
    - WinRM not required (runs locally)

.NOTES
    Tested on: Windows 10 / Windows Server 2016  
    Useful for post-deployment automation or workstation provisioning in German-language environments.

    Variables:
    - $DownloadFolder: Path where installers are saved.
    - $CreateLogFile: Path to the log file.
    - $RestartComputer: If $true, restarts the machine after completion.
    - $InstallUpdates: If $true, installs available Windows Updates.
    - $Cleanup: If $true, deletes downloaded installers and temp files.
    - $WindowsUpdate_Notification_level: Sets Windows Update behavior (2 = notify, 3 = auto-download, 4 = auto-install)
#>


#Script Variables:
$DownloadFolder = "C:\Windows\Temp"                                           #Path to folder where downloads will be stored
$CreateLogFile = "C:\windows\Temp.txt"                                        #Log file path (Log file created here)
$RestartComputer = $false                                                     #Restart the computer after everything is done ($true or $false)
$WindowsUpdate_Notification_level = "3"                                       #Windows Update Notification == 2 = notify before download, 3 = Download automatically and notify for install, 4 = auto download and install
$InstallUpdates = $false                                                      #Install outstanding windows updates (Use caution, may take considerable time) ($true or $false) ##CAUTION##
$Cleanup = $true                                                              #Remove all the downloaded files ($true or $false)

#Command Lines:
$Adobe_CommandLine = "/qn /sALL /rs /msi EULA_ACCEPT=YES"
$Firefox_CommandLine = "/s"
$Winrar_CommandLine = "/s"
$VLC_CommandLine = "/L=1031 /S"
$Java_CommandLine = "/s WEB_JAVA=1"

#Installer Files:
$Adobe_Installer = "adobereader_dc_de.exe"
$Firefox_Installer = "Firefox50_de.exe"
$Winrar_Installer = "winrar_de.exe"
$Adblock_Installer = "adblockplus.xpi"
$VLC_Installer = "vlc_de.exe"
$Java_Installer = "java.exe"

#Download URL's:
$Adobe_Download = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/[version]/AcroRdrDC[version]_de_DE.exe"
$Firefox_Download = "https://download.mozilla.org/?product=firefox-[version]-SSL&os=win&lang=de"
$Winrar_Download = "http://www.rarlab.com[version]"
$Adblock_Download = "https://update.adblockplus.org/latest/adblockplusfirefox.xpi"
$VLC_Download = "http://mirror.netcologne.de/videolan.org/vlc/[version]/win32/vlc-[version]-win32.exe"

#Version reference URL's:
$Adobe_ref = "https://get.adobe.com/reader/"
$Firefox_ref = "https://www.mozilla.org/en-US/firefox/new/"
$Winrar_ref = "www.rarlab.com/download.htm"
$VLC_ref = "http://www.videolan.org/vlc/index.de.html"
$Java_ref = "https://java.com/de/download/manual.jsp"

#Initialise variables
$global:ErrorLog = @()

#Functions:
function Download-Installer($url, $path, $appname){
    
    if (!(Test-Path $path)){
        $uri = New-Object "System.Uri" "$url"
        $WebRequest = [System.Net.HttpWebRequest]::Create($uri)
        $WebRequest.set_Timeout(15000)
        $Response = $WebRequest.GetResponse()
        $Total = [System.Math]::Floor($Response.get_ContentLength()/1024)
        $ResponseStream = $Response.GetResponseStream()
        $TargetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $path, Create
        $buffer = new-object byte[] 10KB
        $count = $ResponseStream.Read($buffer,0,$buffer.length)
        $downloadedBytes = $count

        while ($count -gt 0){

            $TargetStream.Write($buffer, 0, $count)
            $count = $ResponseStream.Read($buffer, 0, $buffer.length)
            $downloadedBytes = $downloadedBytes + $count
            Write-Progress -activity "Downloading application $appname " -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($Total)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $Total)  * 100)
            }

        Write-Progress -activity "Application finished downloading $appname"
        $TargetStream.Flush()
        $TargetStream.Close()
        $TargetStream.Dispose()
        $ResponseStream.Dispose()
    }
} 

Function Log{                                                 #Writes information to console, and outputs to log file
    Param ([string]$logstring, $logtype, $errorcode, $task) 
    if (! (test-path $CreateLogFile)){
        Add-Content $CreateLogFile -Value "DATE:       Time:    TYPE:          MESSAGE:                                           ERRORCODE:                     TASK:"
    }
    if ($CreateLogFile){
        Add-Content $CreateLogFile -Value ((Get-Date -Format 'dd-MM-yyyy HH:mm:ss') + ' ' + '::' + $logtype + '::' + ' ' + $logstring)
    }
    $global:ErrorLog += ((Get-Date -Format 'dd-MM-yyyy HH:mm:ss') + ' ' + '::' + $logtype + '::' + ' ' + $logstring + '' + $errorcode + '' + $task)
    if ($logtype -match "ERROR|WARN"){
        Write-Host -Object "[$logtype] " -f Red -NoNewline
        }
    else{
    Write-Host -Object "[$logtype] " -f Yellow -NoNewline
        }
    write-host -Object " $logstring"

    if ($errorcode -ne $null -or $task -ne $null){
        write-host -Object "Error Code :    " -f Cyan -NoNewline
        write-host -Object $errorcode -f Yellow
        Write-Host -Object "Task :          " -f Cyan -NoNewline
        write-host -Object $task -f Yellow 
        }
}

function Get-InstalledApp{                                   #Checks whether a program is installed and gets the full name and install path       
    Param($appname)
    if ([IntPtr]::Size -eq 4) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    }
    Get-ItemProperty $regpath | where {$_.displayname -ne $null-and $_.DisplayName -match $appname} | select DisplayName, InstallLocation
}

#Start script

###########################################################################################################################################

#Set execution policy to unrestricted

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

#Check for internet connectivity before continuing:

    log -logstring "Testing for internet connectivity" -logtype "INFO"
    $NetTest = Test-NetConnection "google.com"

    if ($NetTest.PingSucceeded -eq "True"){
        log -logstring "Internet connectivity detected. Continuing" -logtype "INFO"
        }
    else{
        log -logstring "Internet connectivity failed. Stopping script." -logtype "ERROR" -errorcode "FailedPing" -task "Test internet connectivity"
        exit
        }

#Adobe Reader DC - Install

    try{

    $AdobeFullPath = $DownloadFolder + "\" + $Adobe_Installer

    $web = Invoke-WebRequest $Adobe_ref
    $elements = $web.AllElements | where {$_.tagname -match "strong" -and $_.OuterText -match "version"}
    $elements = $elements | select -ExpandProperty InnerHTML
    $version = $elements -replace "Version ", ""
    $version = $version -replace '\.', ''

    $DownloadURL = $Adobe_Download -replace "\[version\]", ($version).Substring(2)

    Download-Installer -url $DownloadURL -path $AdobeFullPath -appname "Adobe Reader DC"

        if (test-path $AdobeFullPath){
            
            cmd /c "$AdobeFullPath $Adobe_CommandLine"
            write-host "Adobe reader DC is installing" -f Green
        }
    }
    catch [exception]{

    log -logstring "Error during installation of Adobe Reader DC" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }
    finally{
        sleep 3
        $check = Get-InstalledApp -appname "Acrobat Reader"
            if ($check.DisplayName.count -ge 1){
                log -logstring "Adobe Reader DC has been installed" -logtype "INFO"
            }
            else{
                log -logstring "Adobe Reader DC failed installation" -logtype "ERROR"
            }
        }

#Firefox - Install

    try{
    $FirefoxFullpath = $DownloadFolder + "\" + $Firefox_Installer

    $web = Invoke-WebRequest $Firefox_ref
    $elements = $web.AllElements | where {$_.tagname -match "HTML"}
    $version = $elements | select -ExpandProperty data-latest-firefox

    $DownloadURL = $Firefox_Download -replace "\[version\]", $version

    Download-Installer -url $DownloadURL -path $FirefoxFullpath -appname "Firefox"

        if (test-path $FirefoxFullpath){
            
            cmd /c "$FirefoxFullpath $Firefox_CommandLine"
            write-host "Firefox is installing" -f Green
        }
    }
    catch [exception]{

    log -logstring "Error during installation of Firefox" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }
    finally{
        sleep 3
        $check = Get-InstalledApp -appname "Firefox"
            if ($check.DisplayName.count -ge 1){
                log -logstring "Firefox has been installed" -logtype "INFO"
            }
            else{
                log -logstring "Firefox failed installation" -logtype "ERROR"
            }
        }

#Winrar - Install

    try{
    $WinrarFullPath = $DownloadFolder + "\" + $Winrar_Installer

    $web = Invoke-WebRequest $Winrar_ref
    $elements = $web.Links | where {$_.innertext -match "German \(64 bit\)"}
    $version = $elements | select -ExpandProperty href

    $DownloadURL = $Winrar_Download -replace "\[version\]", $version

    Download-Installer -url $DownloadURL -path $WinrarFullPath -appname "WinRar"

        if (test-path $WinrarFullPath){
            
            cmd /c "$WinrarFullPath $Winrar_CommandLine"
            write-host "Winrar is installing" -f Green
        }
    }
    catch [exception]{

    log -logstring "Error during installation of Winrar" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }
    finally{
        sleep 3
        $check = Get-InstalledApp -appname "Winrar"
            if ($check.DisplayName.count -ge 1){
                log -logstring "Winrar has been installed" -logtype "INFO"
            }
            else{
                log -logstring "Winrar failed installation" -logtype "ERROR"
            }
        }

#Adblock Plus - Install and configure

    try{
    $AdblockFullPath = $DownloadFolder + "\" + $Adblock_Installer
    Download-Installer -url $Adblock_Download -path $AdblockFullPath -appname "Adlock Plus"

        if (test-path $AdblockFullPath){
            write-host "Adblock is installing" -f Green

                $Winrar_Path = Get-InstalledApp -appname "winrar" | select -ExpandProperty InstallLocation
                if (test-path $Winrar_Path){
                    $Winrar_exe = "$Winrar_Path" + "Winrar.exe"
                    }
                if (!(test-path $Winrar_Path)){
                    Log -logstring "Cannot locate WinRar to unzip Adblock" -logtype "ERROR" -errorcode "FileNotFound" -task "Unzip Adblock"
                    }

                if (test-path $Winrar_exe){
                & $Winrar_exe  x -ibck $AdblockFullPath *.rdf $DownloadFolder
                }

                sleep 3
                [xml]$xml = Get-Content $DownloadFolder\install.rdf
                $ID = $xml.DocumentElement.Description | select -ExpandProperty ID
                
                $newname = $DownloadFolder + "\" + "$id" + ".xpi"

                if (test-path $newname){
                Remove-Item -Path $newname -ErrorAction SilentlyContinue
                }
                Rename-Item -Path $AdblockFullPath -NewName $newname -Force
                Remove-Item -Path $DownloadFolder\install.rdf -ErrorAction SilentlyContinue

                $Firefox_Path = (Get-InstalledApp -appname "firefox") | select -ExpandProperty InstallLocation
                $Firefox_Extension_Path = $Firefox_Path + "\" + "browser\extensions"
                $Firefox_Browser_Path = $Firefox_Path + "\" + "browser"
                $JavaScript_data = 'pref("extensions.autoDisableScopes", 0);'

                if ($Firefox_Extension_Path){
                
                Copy-Item -Path $newname -Destination $Firefox_Extension_Path -Force
                New-Item -Path "$Firefox_Browser_Path\defaults" -ItemType Directory | Out-Null
                New-Item -Path "$Firefox_Browser_Path\defaults\preferences" -ItemType Directory | Out-Null
                
                if (test-path "$Firefox_Browser_Path\defaults\preferences"){
                    New-Item -Path "$Firefox_Browser_Path\defaults\preferences\silent-install.js" -ItemType File -Value $JavaScript_data | Out-Null
                }
            }
        }
    }
    catch [exception]{

    log -logstring "Error during installation of Adblock" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }

#VLC -Install

    try{
    $VLCFullPath = $DownloadFolder + "\" + $VLC_Installer

    $web = Invoke-WebRequest $VLC_ref
    $elements = $web.AllElements | where {$_.tagname -match "div" -and $_.ID -match "downloadDetails"} | select -ExpandProperty InnerText
    $version = $elements.split(" ") | where {$_ -match "[0-9]\.[0-9]"}

    $DownloadURL = $VLC_Download -replace "\[version\]", $version

    Download-Installer -url $DownloadURL -path $VLCFullPath -appname "VLC"

        if (test-path $VLCFullPath){
            
            cmd /c "$VLCFullPath $VLC_CommandLine"
            write-host "VLC is installing" -f Green
        }
    }
    catch [exception]{

    log -logstring "Error during installation of VLC" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }
    finally{
        sleep 3
        $check = Get-InstalledApp -appname "VLC"
            if ($check.DisplayName.count -ge 1){
                log -logstring "VLC has been installed" -logtype "INFO"
            }
            else{
                log -logstring "VLC failed installation" -logtype "ERROR"
            }
        }

#Java - Install

    try{
    $JavaFullPath = $DownloadFolder + "\" + $Java_Installer

    $web = Invoke-WebRequest $Java_ref
    $DownloadURL = $web.Links | where {$_.outertext -contains "Windows Offline (64-Bit)"} | select -ExpandProperty href

    Download-Installer -url $DownloadURL -path $JavaFullPath -appname "Java"

        if (test-path $JavaFullPath){
            
            cmd /c "$JavaFullPath $Java_CommandLine"
            write-host "Java is installing" -f Green
        }
    }
    catch [exception]{

    log -logstring "Error during installation of Java" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task $error[0].CategoryInfo.Activity
    }
    finally{
        sleep 3
        $check = Get-InstalledApp -appname "Java"
            if ($check.DisplayName.count -ge 1){
                log -logstring "Java has been installed" -logtype "INFO"
            }
            else{
                log -logstring "Java failed installation" -logtype "ERROR"
            }
        }

#END OF APPLICATION INSTALLS
#Disable UAC:

    try{
        log -logstring "Setting registry key to disable UAC" -logtype "INFO"
        New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    }
    catch [exception]{
        log -logstring "Failed to set registry key for UAC disable" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task "Disable UAC"
    }

#Windows Activation Check

    try{
        log -logstring "Getting Windows license information" -logtype "INFO"
        $DNSHostName = $Env:COMPUTERNAME
        $wpa = Get-WmiObject SoftwareLicensingProduct `
                -ComputerName $DNSHostName `
                -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
                -Property LicenseStatus -ErrorAction Stop

    }
    catch [exception]{
        log -logstring "Failed to retrieve WMI object for Windows Activation" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task "Retrieve WMI software licensing key"
    }
    finally{
        if ($wpa){
        foreach($i in $wpa){
                switch ($i.LicenseStatus){
                    0 {$LicenseStatus = "Unlicensed"}
                    1 {$LicenseStatus = "Licensed"; break}
                    2 {$LicenseStatus = "Grace Period"; break}
                    3 {$LicenseStatus = "Out-Of-Tolerance"; break}
                    4 {$LicenseStatus = "Non-Genuine Grace"; break}
                    5 {$LicenseStatus = "Notification"; break}
                    6 {$LicenseStatus = "Extended Grace"; break}
                    default {$LicenseStatus = "Unknown value"}
                }
            }
        }
        if ($LicenseStatus -match "Unlicensed|Out-Of-Tolerance|Grace"){
            log -logstring "Windows needs to be activated" -logtype "WARN"
        }
        log -logstring "Windows licensing is: $LicenseStatus" -logtype "INFO"
    }

#Set File Explorer Open to 'ThisPC'

    try{
        log -logstring "Setting registry key for 'File Explorer open to This PC'" -logtype "INFO"
        $Explorer_Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $LaunchTo_Key = Get-ItemProperty -Path $Explorer_Key -Name "LaunchTo"

        Set-ItemProperty -Path $Explorer_Key -Name "LaunchTo" -Value "1" -ErrorAction Stop
    }
    catch [Exception]{
        Log -logstring "Failed to set registry key for 'File Explorer open to This PC'" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task "Set registry for File Explorer open to This PC"
    }

#Set folder properties (HideDrivesWithNoMedia, HideFileExt, ShowSuperHidden, HideMergeConflicts, Hidden)

    log -logstring "Setting registry keys for folder properties" -logtype "INFO"
    $Explorer_Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $RegistryKeys = @{ 
                    "hidedriveswithnomedia" = 1 ; 
                    "HideFileExt" = 0 ; 
                    "showsuperhidden" = 0 ; 
                    "hidemergeconflicts" = 1 ; 
                    "hidden" = 2 
                    } 

    ForEach ($i in $RegistryKeys.Keys){ 
        Set-ItemProperty -path $Explorer_Key -name $i -value $RegistryKeys[$i] 
        log -logstring "Setting registry key for $i" -logtype "INFO"
      }  
 
#Set Firefox defaults - Creates 3 files in Firefox to disable welcome screen, default browser check and set homepage

$override_ini = @' 
[XRE]
EnableProfileMigrator=false
'@

$localsettings_js = @'
pref("general.config.obscure_value", 0);
pref("general.config.filename", "mozilla.cfg");
pref("browser.shell.checkDefaultBrowser", false);
'@

$mozilla_cfg = @'
pref("browser.shell.checkDefaultBrowser", false);
pref("browser.startup.homepage_override.mstone", "ignore");
pref("browser.rights.3.shown", true);
pref("toolkit.telemetry.prompted", 2);
pref("toolkit.telemetry.rejected", true);
pref("browser.startup.homepage", "http://www.google.com");
'@
    log -logstring "Retrieving Firefox install path" -logtype "INFO"
    $Firefox_Path = Get-InstalledApp -appname "Firefox" | select -ExpandProperty InstallLocation

    log -logstring "Creating Override.ini , local-settings.js and mozilla.cfg for Firefox" -logtype "INFO"
    New-Item -Path "$Firefox_Path\browser\override.ini" -ItemType File -Value $override_ini -Force | Out-Null
    New-Item -Path "$Firefox_Path\defaults\pref\local-settings.js" -ItemType File -Value $localsettings_js -Force | Out-Null
    New-Item -Path "$Firefox_Path\mozilla.cfg" -ItemType File -Value $mozilla_cfg -Force | Out-Null

    log -logstring "Setting Firefox as default browser - May require user interaction" -logtype "WARN"
    Start-Process -FilePath "$Firefox_Path\firefox.exe" -ArgumentList "-silent -nosplash -setDefaultBrowser"
    Start-Process -FilePath "$Firefox_Path\uninstall\helper.exe" -ArgumentList "/SetAsDefaultAppGlobal"

#Disable disk defrag task
    
    log -logstring "Checking if scheduled task named 'ScheduledDefrag' exists" -logtype "INFO"
    If ((Get-ScheduledTask -TaskName "ScheduledDefrag").State -eq 'Ready'){
        Disable-ScheduledTask -TaskName 'ScheduledDefrag' -TaskPath '\Microsoft\Windows\Defrag'
        Log -logstring "Disabling the task 'ScheduledDefrag'" -logtype "INFO"
    }
    else{
        log -logstring "No ScheduledDefrag task found. Perhaps it's been disabled?" -logtype "WARN"
    }

#Scheduled task for opening log file

    try{
    
        if ($CreateLogFile){
            log -logstring "Creating scheduled task to open this log file after reboot" -logtype "INFO"
            $ScriptPath = $myinvocation.mycommand.path
            $TaskName = "OpenLogFile-PostDeploy"
            $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -command . $CreateLogFile ; remove-item $ScriptPath"
            $Trigger = New-ScheduledTaskTrigger -AtStartup
            $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings (New-ScheduledTaskSettingsSet)
            $Task | Register-ScheduledTask -TaskName "$TaskName"
        }
    }
    catch [exception]{
        log -logstring "Couldn't create scheduled task: $TaskName" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task "Create scheduled task for log file"
    }

#Windows Update - Sets updates, checks and installs outstanding updates

    log -logstring "Enabling Windows updates" -logtype "INFO"
    $UpdateSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
    $UpdateSettings.NotificationLevel = $WindowsUpdate_Notification_level
    $UpdateSettings.save()

    if ($InstallUpdates -eq $true){

    $Criteria = "IsInstalled=0 and Type='Software'"
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
	    try {
            log -logstring "Starting Windows Updates" -logtype "INFO"
		    $SearchResult = $Searcher.Search($Criteria).Updates

		    if ($SearchResult.Count -gt 0){
                log -logstring "Found $SearchResult.count updates to install" -logtype "INFO"
                log -logstring "This process can take a while" -logtype "WARN"

			    $Session = New-Object -ComObject Microsoft.Update.Session
			    $Downloader = $Session.CreateUpdateDownloader()
			    $Downloader.Updates = $SearchResult
			    $Downloader.Download()
			    $Installer = New-Object -ComObject Microsoft.Update.Installer
			    $Installer.Updates = $SearchResult
			    $Result = $Installer.Install()
		    } 
		    else {
			    log -logstring "No Windows Updates to be installed" -logtype "INFO"
		    }
	    }
	    catch [exception]{
		    log -logstring "Failure during installation of Windows Updates" -logtype "ERROR" -errorcode $error[0].FullyQualifiedErrorId -task "Install Windows Updates"
	    }
    }

#Cleanup all download installers and the firefox extension script

    if ($Cleanup -eq $true){

        $AllVars = get-variable | where {$_.name -match "_installer"} | select -ExpandProperty Value
        log -logstring "Removing all installer files" -logtype "WARN"

        foreach ($i in $AllVars){
            $rempath = $DownloadFolder + "\" + $i
            Remove-Item -Path $rempath -Force -ErrorAction SilentlyContinue -force
        }
        Remove-Item -Path "$Firefox_Browser_Path\defaults\preferences" -Force
    }

#Restart the computer (Countdown to 10)

if ($RestartComputer -eq $true){
    log -logstring "Restarting computer in 10 seconds" -logtype "WARN"

    $c = 1
    While ($c -le 10) {sleep 1 ; $c; $c += 1}
    
    if ($c -ge 10){
        log -logstring "Restarting now" -logtype "INFO" 
        Restart-Computer
        }
    }

log -logstring "Script finished" -logtype "INFO"
#End of Script
