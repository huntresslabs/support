# Copyright (c) 2025 Huntress Labs, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the Huntress Labs nor the names of its contributors may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL HUNTRESS LABS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Written by Alan Bishop
#
# This script attempts to reset a machine's Defender settings to the Huntress / Microsoft Defender defaults. It also logs several Defender related environmental 
# variables, Defender service status, and gpresult. All stored in a couple log files in \Windows\temp
#
# * Must be run as admin
# * This will wipe out any existing Defender exclusions, use with caution!
# * Skip to line 106 to see line by line which commands match Huntress policies
#
# Usage: 
#       powershell -executionpolicy bypass -f .\Huntress.reset.Defender.ps1


# Using \Windows\temp\ to store logs as the Huntress folder won't be accessible with TP turned on
$DebugLog  = 'C:\Windows\temp\HuntressMAV.log'
$PolicyLog = 'C:\Windows\temp\PolicyResult.html'

# adds time stamp to a message and then writes that to the log file
function LogMessage ($msg) {
    $timeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
    Add-Content $DebugLog "$($timeStamp) $msg"
    Write-Host "$($timeStamp) $msg"
}

# Used by the Huntress support team when troubleshooting.
LogMessage "MAV repair script: 2025 Nov 19"
LogMessage "Beginning status and preferences:"
$MPCS = Out-String -inputobject $(Get-MPComputerStatus)
$MPP  = Out-String -inputobject $(Get-MPPreference)
LogMessage $MPCS
LogMessage $MPP

# Find script issues faster with the most stringent setting.
Set-StrictMode -Version Latest

# Check for Tamper Protection, if it's on then this script may have difficulty reseting MAV to defaults. Tamper Protection can ONLY be changed in the GUI or your Microsoft portal!
# TP only exists with Windows Security Center, which is only on workstations. i.e. servers don't have TP. 1 = workstation, 2 = DC, 3 = server
if ((Get-CimInstance -ClassName win32_operatingsystem).producttype -eq 1)
{
    if ((Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows Defender\Features" -Name "TamperProtection") -ne 0) {
        LogMessage "Tamper Protection is ON, you'll need to turn it off within the GUI for this script to work correctly! TP can be turned back on after running this script successfully." 
        LogMessage "Last change to Tamper Protection was done by:"
        switch (Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows Defender\Features" -Name "TamperProtectionSource")
        {
             1 {LogMessage "Init (default, unchanged)"}
             2 {LogMessage "User Interface (GUI)"}
             3 {LogMessage "E3"}
             4 {LogMessage "E5"}
             5 {LogMessage "Signatures"}
             6 {LogMessage "MpCmdRun (Powershell)"}
            40 {LogMessage "Intune or ConfigMgr"}
            41 {LogMessage "ATP (aka Defender for Business aka Microsoft Defender for Endpoints)"}
        }
        pause
    }
}

# Check for AD joined machines that cannot currently talk to any DC
if ($env:UserDNSDomain -ne $null) {
    if (!(Test-ComputerSecureChannel)) {
        LogMessage "WARNING: End point is AD joined but unable to contact a DC. This script will only work on end points that can currently talk to a DC or for end points not joined to a domain." 
        pause
    } else { LogMessage "Domain joined, DC connectivity is working - no problems"}
}

# Check system uptime. 95% of the time Defender appears broken, Windows is silently waiting on a reboot in order to fix or update something
$uptime = (New-TimeSpan -start $((Get-CimInstance -ClassName win32_operatingsystem ).lastbootuptime) -end $(Get-Date)).Days
if ($uptime -gt 6) {
    LogMessage "High uptime detected, $($uptime) days, STRONGLY suggest a reboot before proceeding!" 
    pause
}
cls

# make sure the 8 base engines are on - best effort
# Antimalware / Antispyware / Antivirus -> cannot be manually turned on or off, instead just make sure the service is running
Start-Service windefend
# Network Inspection -> same as above, cannot be turned on/off, but sometimes restarting the service helps
Start-Service wdnissvc    
# Real-time Protection
Set-MpPreference -DisableRealtimeMonitoring $false
# on access protection - for Win10/11 only, command to turn on/off was deprecated
# IE/Outlook antivirus
Set-MpPreference -DisableIOAVProtection $false
# Behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $false


##################################################################################################################################
#                                    Begin Huntress policy matching                                                              #
##################################################################################################################################
# In this section match the commented-titles below with the policy tabs in the Huntress portal. See the General commented title below for more details.

############ General ############                         # match this title with your AV policy under the "General" tab in Huntress MAV policy
# Hide Defender UI                                        # this is the setting as it's described in the Huntress portal
Set-MpPreference -UILockdown $false                       # this is the command to set the policy to the recommended Huntress default of "Visible" for the Defender UI

# Suppress All Notifications (0=do not suppress notifications, 1=suppress notifications)
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration' /v 'Notification_Suppress' /t 'REG_DWORD' /d '0' /f

############ Protection ############
# Enabled/Disabled Status (0=disabled, 1=enabled, 2=advanced reporting)
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Spynet' /v 'SpyNetReporting' /t 'REG_DWORD' /d '1' /f

# Automatic Sample Submission (0=always prompt, 1=send safe samples automatically, 2=never send, 3=send all samples automatically)
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Spynet' /v 'SubmitSamplesConsent' /t 'REG_DWORD' /d '1' /f

############ Exclusions ############
# Path exclusions
$pathExclusions = (Get-MpPreference).ExclusionPath 
foreach ($exclusion in $pathExclusions) {
    if ($exclusion -ne "%PROGRAMFILES%\Huntress\Rio\Rio.exe") {
        Remove-MpPreference -ExclusionPath $exclusion
    }
}

# Extension exclusions
$extensionExclusion = (Get-MpPreference).ExclusionExtension 
foreach ($exclusion in $extensionExclusion) {
    if ($null -ne $exclusion) {
        Remove-MpPreference -ExclusionExtension $exclusion
    }
}

# Process exclusions
$processExclusions = (Get-MpPreference).ExclusionProcess
foreach ($exclusion in $processExclusions) {
    if ($exclusion -ne "%PROGRAMFILES%\Huntress\HuntressAgent.exe" -and $exclusion -ne "%PROGRAMFILES%\Huntress\Rio\Rio.exe") {
        Remove-MpPreference -ExclusionProcess $exclusion
    }
}

############ Reputation ############
# SmartScreen 
# ShellSmartScreenLevel is required for EnableSmartScreen to function, however SmartScreen is recommended to keep off so the below statement is commented out
# reg add 'HKLM\Software\Policies\Microsoft\Windows\System' /v 'ShellSmartScreenLevel' /t 'REG_SZ' /d 'Enabled' /f
# Policy Setting for Apps and Files (1=enabled, 0=disabled)
reg add 'HKLM\Software\Policies\Microsoft\Windows\System' /v 'EnableSmartScreen' /t 'REG_DWORD' /d '0' /f
# ConfigureAppInstallControlEnabled is required for ConfigureAppInstallControl to function.
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen' /v 'ConfigureAppInstallControlEnabled' /t 'REG_DWORD' /d '0' /f
# Policy Setting for Microsoft Store ()
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen' /v 'ConfigureAppInstallControl' /t 'REG_SZ' /d 'Anywhere' /f

# PUA Blocking (0=disabled, 1=enabled, 2=audit)
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'PUAProtection' /t 'REG_DWORD' /d '2' /f

############ Scans ############
# Scan Time
Set-MpPreference -ScanScheduleQuickScanTime "02:00:00"

# Catch-up Scans
Set-MpPreference -DisableCatchupFullScan $true
Set-MpPreference -DisableCatchupQuickScan $false

# Removable Drive Scanning
Set-MpPreference -DisableRemovableDriveScanning $false

# Archive File Scanning
Set-MpPreference -DisableArchiveScanning $false

# Packed Executable Scanning (1=packed exe are scanned, 0=packed exe are not scanned)
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender' /v 'DisablePackedExeScanning' /t 'REG_DWORD' /d '1' /f

# Network File Scanning
Set-MpPreference -DisableScanningNetworkFiles $true

############ Signatures ############
# Signature Update Interval
Set-MpPreference -SignatureUpdateInterval 6

# Signature Update Catch-up Interval
Set-MpPreference -SignatureUpdateCatchupInterval 1

# Update Signatures on Startup
# making sure these settings aren't a blocker
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'ForceUpdateFromMU' /t 'REG_DWORD' /d '0' /f
# 1=enabled, 0=disabled
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates' /v 'UpdateOnStartup' /t 'REG_DWORD' /d '1' /f

# Update Signatures from Microsoft Update
Set-MpPreference -SignatureFallbackOrder "MicrosoftUpdateServer|MMPC"

############ Advanced ############
# Purge Quarantine After Delay
Set-MpPreference -QuarantinePurgeItemsAfterDelay 0

# NIS Definition Retirement
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS' /v 'DisableSignatureRetirement' /t 'REG_DWORD' /d '0' /f

# NIS Protocol Recognition
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\NIS' /v 'DisableProtocolRecognition' /t 'REG_DWORD' /d '0' /f



# Log the final state of the machine - Defender status, Defender services, and gpresult
LogMessage "Script successfully finished running, results:"
$MPCS     = Out-String -inputobject $(Get-MPComputerStatus)
$MPP      = Out-String -inputobject $(Get-MPPreference)
$Services = Out-String -inputobject (Get-Service | Where{$_.displayname -like "*defender*"} | Select Name, Status, StartType)
LogMessage $MPCS
LogMessage $MPP
LogMessage $Services

# Save the current applied policy in a separate file
gpresult /h $PolicyLog /f

Write-Host "Log saved to $($DebugLog)"
Write-Host "RSoP - results of current policy set saved to $($PolicyLog)"
