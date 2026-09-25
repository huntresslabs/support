# Helper script that is primarily for detecting active Huntress Host Isolation.
# Also attempts to identify 3rd party WFP network isolations or Microsoft Defender for Endpoint (MDE) isolation events.
# There is substantial complication and depth to detecting these, so this is a "best effort" for 3rd party software. There 
# are other ways a program could isolate a machine from its network that aren't detectable! 
#
# Huntress Isolation Detection - very accurate!
# 3rd party WFP Isolation Detection - may miss some WFP events. Best effort.
# MDE Isolation Detection - somewhere in between the other two tests. Relies on MDE writing to Windows Event Logs.
#
# Suggested Usage:
#         powershell -executionpolicy bypass -f .\Test-IsolationHuntress.ps1

Write-Output "---------------------------------------------------------------------"
Write-Output "Huntress Network Isolation Tester, last updated Sept 25, 2026"
Write-Output "---------------------------------------------------------------------`n"

# This script is compatible with all versions of Windows that Huntress Host Isolation supports.
if ( [System.Environment]::OSVersion.Version.Major -lt 6) {
    Write-Output "Machine is not supported. Windows Filtering Platform only exists on kernel 6 and higher. Exiting..."
    exit 1
}

$user    = [Security.Principal.WindowsIdentity]::GetCurrent();
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (! $isAdmin) {
    Write-Output "This script must be run as Administrator! Exiting..."
    exit 1
}

function prettyPrintMDE {
    param ( [array]$eventsFromMDE )

    Write-Output ""
    foreach ($MDEEvent in $eventsFromMDE) {
        Write-Output "Message            : $($MDEEvent.Message)"
        if ($MDEEvent.Id -eq 60) {
            Write-Output "Event Code/Id      : $($MDEEvent.Id)  Id 60 indicates the task failed!"
        } else {
            Write-Output "Event Code/Id      : $($MDEEvent.Id)"
        }
        Write-Output "Machine Name       : $($MDEEvent.MachineName)"
        Write-Output "Provider Name      : $($MDEEvent.ProviderName)"
        Write-Output "Time Created       : $($MDEEvent.TimeCreated)"
        Write-Output "Record ID (unique) : $($MDEEvent.RecordId)`n"
    }
}

function cleanupTempFile {
    param ( [string]$out )

    if (Test-Path $tempDIR) {
        Remove-Item -Path $tempDIR -Force -Recurse
    }
}


# Store current WFP rules in a temp file
$tempDIR = "$env:TEMP\Huntress.$((Get-Date).Second.ToString())"
New-Item -Path $tempDIR -ItemType "directory" | Out-Null
if (! (Test-Path $tempDIR)) {
    Write-Output "Unable to create temporary directory in $env:TEMP  Exiting"
    exit 1
}

$out = "$tempDIR\wfp_filters.xml"
netsh wfp show filters file=$out | Out-Null
[xml]$wfp = Get-Content $out
$allFilters = $wfp.wfpdiag.filters.item
# If the filters variable is null or the wfp_filters file wasn't created, exit
if ($null -eq $allFilters -or ! (Test-Path $out) ) {
    Write-Output "Unable to retrieve data from netsh! Exiting..."
    exit 1
}

# Look for Huntress WFP rules
$HuntressFilters = New-Object System.Collections.ArrayList 
Write-Output "Looking for Huntress rules in WFP..."
foreach ($filter in $allFilters) {
    # WFP rules are left in place but in an inactive state, so it's necessary to filter out disabled rules
    if ($filter.displayData.name -match 'Huntress' -and $filter.flags.item -notcontains 'FWPM_FILTER_FLAG_DISABLED' -and $filter.flags.item -notcontains 'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT'){
        $filterToAdd = New-Object PSObject -Property @{
            Name = $filter.displayData.name
            Action = $filter.action.type
            Flags = $($filter.flags.item -join ', ')
            Weight = $($filter.effectiveWeight.uint64)
        }
        [void]$HuntressFilters.Add($filterToAdd)
    }
}
$numHuntressFilters = @($HuntressFilters).Count

# Also try to find other WFP-based blocking rules
# This is a best effort attempt, there are other ways to block network traffic besides WFP!
Write-Output "Looking for 3rd party WFP blocking rules (best effort)..."
$blockedFilters = New-Object System.Collections.ArrayList 
foreach ($filter in $allFilters) {
    # if it's a blocking rule, not named Huntress, and it's not a disabled rule -> add to array
    if ($filter.action.type -eq "BLOCK" -and $filter.action.type -eq "FWP_ACTION_BLOCK" -and $filter.displayData.name -notmatch 'Huntress' -and $filter.flags.item -notcontains 'FWPM_FILTER_FLAG_DISABLED') {
        echo "'$($filter.displayData.name)' -> filter"
        $filterToAdd = New-Object PSObject -Property @{
            Name = $filter.displayData.name
            Action = $filter.action.type
            Flags = $($filter.flags.item -join ', ')
            Weight = $($filter.effectiveWeight.uint64)
        }
        [void]$blockedFilters.Add($filterToAdd)
    }
}

# Look for MDE isolation, which is easiest found by looking in event logs
Write-Output "Looking for Microsoft Defender for Endpoint (MDE) isolation events..."
$cutoff        = (Get-Date).AddDays(-30)
$newestEvent   = $null
$eventsFromMDE = @()
try {
    $loggedMDEEvents = @(Get-WinEvent -LogName "Microsoft-Windows-SENSE/Operational" -ErrorAction Stop)
    # for passing a EVTX instead of using local Windows Event Logs (comment line above, uncomment line below)
    #$loggedMDEEvents = @(Get-WinEvent -Path ".\sense logs.evtx")

    foreach ($loggedEvent in $loggedMDEEvents) {
        if ($loggedEvent.TimeCreated -ge $cutoff -and $loggedEvent.Message -match 'isolate|unisolate|isolation|unisolation') {
            $eventsFromMDE += $loggedEvent
            $total3rdPartyBlocks++
            # Event ID 60 indicates "failed to run command" so we ignore those. ID 59 indicates starting command, while 71 indicates the command succeeded
            if ($null -eq $newestEvent -or $newestEvent.TimeCreated -gt $loggedEvent.TimeCreated -or $newestEvent.EventId -eq 60) {
                $newestEvent = $loggedEvent
            }
            # WEL uses seconds to log events, since that's not nearly granular enough use RecordId to resolve time conflicts
            if ($newestEvent.TimeCreated -eq $loggedEvent.TimeCreated -and $newestEvent.RecordId -gt $loggedEvent.RecordId) {
                $newestEvent = $loggedEvent
            }
        }
    }
} catch {
    $scOutput = $(sc.exe query sense)
    if ($scOutput -like "*STOPPED*") {
        Write-Output "Error retrieving Windows Event Logs! This is expected if Microsoft Defender for Endpoint is not installed on the endpoint"
        Write-Output "(AKA Defender for Business AKA Defender ATP)"
    } else {
        Write-Output $scOutput
        Write-Output "Unknown error retrieving Windows Event Logs! You can ignore this if Microsoft Defender for Endpoint is not installed."
    }
}
if ($newestEvent.Message -like "*unisolationcommand*" -or $newestEvent.Message -like "*unisolate*") {
    $unisolationNewest = $true
} 


Write-Output "`n------------------------------ Results ------------------------------"
if ($numHuntressFilters -gt 0) {
    $HuntressFilters | Format-List
    Write-Output "Huntress      : Host Isolation active, active Huntress WFP filters found: $numHuntressFilters!"
} else {
    Write-Output "Huntress      : not isolating this machine!"
}

if ($blockedFilters.Count -gt 0) {
    $blockedFilters | Format-List
    Write-Output "3rd party WFP : $($blockedFilters.Count) potential WFP blocking rules found from 3rd party!"
} else {
    Write-Output "3rd party WFP : no WFP blocking rules found on this machine. This isn't conclusive, simply a best effort."
}

if ($eventsFromMDE.Count -gt 0) {
    prettyPrintMDE $eventsFromMDE
    if ($unisolationNewest -ne $true) {
        Write-Output "MDE           : isolation event found in the last 30 days! Check your Microsoft portal for alerts!"
    } else {
        Write-Output "MDE           : an isolation event was detected, however an unisolation event was detected as the most recent event."
        Write-Output "Examine the Event Logs above or check your Microsoft portal to confirm the endpoint isn't isolated by MDE"
    }
} else {
    Write-Output "MDE           : no isolation events found in the event logs"
}
cleanupTempFile
