# Helper script that is primarily for detecting active Huntress Host Isolation, all other functions are "best effort". 
# Also attempts to identify Defender Firewall-based isolations or Microsoft Defender for Endpoint (MDE) isolation events.
# There is substantial complication and depth to detecting these, so this is a "best effort" for 3rd party software. There 
# are other ways a program could isolate a machine from its network that aren't easily detectable! 
#
# This script can't detect: 3rd party WFP isolation, group policy based firewall rules, hardware based isolation, or Quality of Service (QoS) policies.
#
# Suggested Usage:
#         powershell -executionpolicy bypass -f .\Test-IsolationHuntress.ps1

Write-Output "---------------------------------------------------------------------"
Write-Output "Huntress Network Isolation Tester, last updated Sept 30, 2026"
Write-Output "---------------------------------------------------------------------`n"

# This script is compatible with all versions of Windows that Huntress Host Isolation supports.
$kernelVersion = [float]"$([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor)"
if ( $kernelVersion -lt 6) {
    Write-Output "Machine is not supported. Windows Filtering Platform (WFP) only exists on kernel 6 and higher. Exiting..."
    exit 1
}

$cutoff          = (Get-Date).AddDays(-30)
$HuntressFilters = New-Object System.Collections.ArrayList 
$user            = [Security.Principal.WindowsIdentity]::GetCurrent();
$isAdmin         = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
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

# Using a unique-random path inside the users temp folder, script uses a temporary WFP filter cache file
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tempDir | Out-Null
if (! (Test-Path $tempDIR)) {
    Write-Output "Unable to create temporary directory in $env:TEMP  Exiting"
    exit 1
}
try {
    $out = Join-Path $tempDIR "wfp_filters.xml"
    netsh wfp show filters file=$out | Out-Null
    [xml]$wfp = Get-Content $out
    $allFilters = $wfp.wfpdiag.filters.item
    # If the filters variable is null or the wfp_filters file wasn't created, exit
    if ($null -eq $allFilters) {
        Write-Output "Unable to retrieve data from netsh! Exiting..."
        exit 1
    }
    if ( ! (Test-Path $out) ) {
        Write-Output "Unable to retrieve cache file in $out"
        exit 1
    }

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
    if ($numHuntressFilters -gt 0) {
        $HuntressFilters | Format-List
    }


    if ( $kernelVersion -ge 6.2 ) {
        $skipDFTest=$false
        Write-Output "Looking for Defender Firewall blocking rules (best effort)..."
        $firewallRules = New-Object System.Collections.ArrayList
        Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {
            $portFilter   = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $addressFilter = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

            $firewallRules += New-Object PSObject -Property@{
                Name          = $_.Name
                DisplayName   = $_.DisplayName
                Direction     = $_.Direction
                Profile       = $_.Profile
                Protocol      = $portFilter.Protocol
                LocalPort     = $portFilter.LocalPort
                RemotePort    = $portFilter.RemotePort
                LocalAddress  = $addressFilter.LocalAddress
                RemoteAddress = $addressFilter.RemoteAddress
            }
        }
        if ($firewallRules.Count -gt 0) {
            $firewallRules | Format-List
        }
    } else {
        Write-Output "This version of Windows doesn't support the commands needed to view Defender Firewall rules with sufficient detail. Skipping Defender Firewall test..."
        $skipDFTest = $true
    }

    Write-Output "Looking for Microsoft Defender for Endpoint (MDE/DfE/ATP) isolation events..."
    $newestEvent      = $null
    $MDETryCatch      = $false
    $eventsFromMDE    = @()
    try {
        $loggedMDEEvents = @(Get-WinEvent -FilterHashTable @{
            LogName   = 'Microsoft-Windows-SENSE/Operational'
            StartTime = $cutoff
        } -ErrorAction Stop)
        #$loggedMDEEvents = @(Get-WinEvent -Path ".\sense logs.evtx" -ErrorAction Stop)

        foreach ($loggedEvent in $loggedMDEEvents) {
            if ($loggedEvent.TimeCreated -ge $cutoff -and $loggedEvent.Message -match 'isolate|unisolate|isolation|unisolation') {
                $eventsFromMDE += $loggedEvent
                $total3rdPartyBlocks++
                # Grabbing the most recent successful event (i.e. Id 71)
                # Event ID 60 indicates "failed to run command". ID 59 indicates "starting command", while 71 indicates the command succeeded
                if ($null -eq $newestEvent -and $loggedEvent.Id -eq 71) {
                    $newestEvent = $loggedEvent
                } elseif ($newestEvent.RecordId -lt $loggedEvent.RecordId -and $loggedEvent.Id -eq 71) {
                    $newestEvent = $loggedEvent
                }
            }
        }
    } catch {
        $MDETryCatch = $true
        $scOutput    = $(sc.exe query sense)
        if ($scOutput -like "*STOPPED*") {
            Write-Output "MDE service is not running, unable to retrieve MDE logs. Likely MDE/DfE/DfB/ATP isn't installed."
        } else {
            Write-Output $scOutput
            Write-Output "Unknown error retrieving Windows Event Logs! You can ignore this if Microsoft Defender for Endpoint is not installed."
        }
    }
    # If the most recent command is an unisolation that succeeded (RecordId 71), mark the scan as most likely not isolated by MDE
    if ( ($newestEvent.Message -like "*unisolationcommand*" -or $newestEvent.Message -like "*unisolate*") -and $newestEvent.Id -eq 71) {
        $unisolationNewest = $true
    }
    if ($eventsFromMDE.Count -gt 0) {
        prettyPrintMDE $eventsFromMDE
    }


    Write-Output "`n------------------------------ Results ------------------------------"
    if ($numHuntressFilters -gt 0) {
        Write-Output "Huntress          : Host Isolation active, active Huntress WFP filters found: $numHuntressFilters!"
    } else {
        Write-Output "Huntress          : not isolating this machine!"
    }

    if ($skipDFTest) {
        Write-Output "Defender Firewall : Skipped test, unsupported OS."
    } else {
        if ($firewallRules.Count -gt 0) {
            Write-Output "Defender Firewall : $($firewallRules.Count) potential blocking rules found!"
        } else {
            Write-Output "Defender Firewall : no blocking rules found on this machine. This isn't conclusive, simply a best effort."
        }
    }

    if ($eventsFromMDE.Count -gt 0 -and ! $MDETryCatch) {
        if ($unisolationNewest -ne $true) {
            Write-Output "Microsoft DfE     : isolation event found in the last 30 days! Check your Microsoft portal for alerts!"
        } else {
            Write-Output "Microsoft DfE     : a recent isolation event was detected, however an unisolation event was detected as a more recent event."
            Write-Output "Examine the Event Logs above or check your Microsoft portal to confirm the endpoint isn't isolated by MDE"
        }
    } elseif ($eventsFromMDE.Count -gt 0 -and $MDETryCatch) {
        Write-Output "Microsoft DfE     : Error retrieving data from Event Logs, however some data was retrieved which should be visible above."
    } elseif ($MDETryCatch) {
        Write-Output "Microsoft DfE     : Likely not installed, no data found. This isn't conclusive, simply a best effort."
    } else {
        Write-Output "Microsoft DfE     : no isolation events found in the event logs. This isn't conclusive, simply a best effort."
    }
} finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}
