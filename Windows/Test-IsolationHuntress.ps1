# Helper script that is primarily for detecting active Huntress Host Isolation, all other functions are "best effort". 
# Also attempts to identify Defender Firewall-based isolations, Microsoft Defender for Endpoint (MDE) isolation events, and 3rd party WFP isolations.
# There is substantial complication and depth to detecting these, so this is a "best effort" for 3rd party software. There 
# are other ways a program could isolate a machine from its network that aren't easily detectable! 
#
# This script can't detect: group policy based firewall rules, hardware based isolation, DNS-based isolation, or Quality of Service (QoS) policies.
#
# Suggested Usage:
#         powershell -executionpolicy bypass -f .\Test-IsolationHuntress.ps1

Write-Host ""
Write-Host "     ##   ## ##    ## ###    ##  ######  ######  ####### ####### #######" -ForegroundColor Cyan
Write-Host "     ##   ## ##    ## ####   ##    ##    ##   ## ##      ##      ##     " -ForegroundColor Cyan
Write-Host "     ####### ##    ## ## ##  ##    ##    ######  #####   ####### #######" -ForegroundColor Cyan
Write-Host "     ##   ## ##    ## ##  ## ##    ##    ##   ## ##           ##      ##" -ForegroundColor Cyan
Write-Host "     ##   ##  ######  ##   ####    ##    ##   ## ####### ####### #######" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------------------"
Write-Host "    Huntress Network Isolation Tester, last updated October 12, 2026"
Write-Host "-------------------------------------------------------------------------`n"

# This script is compatible with all versions of Windows that Huntress Host Isolation supports, i.e. Kernel 6+.
$kernelVersion = [float]"$([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor)"
if ( $kernelVersion -lt 6) {
    Write-Output "Machine is not supported. Windows Filtering Platform (WFP) only exists on kernel 6+ (Vista/2008 and higher). Exiting..."
    exit 1
}

$unisolationNewest = $false
$cutoff            = (Get-Date).AddDays(-30)
$HuntressFilters   = New-Object System.Collections.ArrayList
$otherWFPFilters   = New-Object System.Collections.ArrayList
$user              = [Security.Principal.WindowsIdentity]::GetCurrent();
$isAdmin           = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
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
try {
    if (! (Test-Path $tempDIR)) {
        Write-Output "Unable to create temporary directory in $env:TEMP Skipping test for Huntress isolation."
        $numHuntressFilters = 0
        $numOtherFilters    = 0
    } else { 
        $out = Join-Path $tempDIR "wfp_filters.xml"
        netsh wfp show filters file=$out | Out-Null
        # exit if netsh wasn't able to create the file
        if ( ! (Test-Path $out) ) {
            Write-Output "Unable to retrieve cache file in $out"
            exit 1
        }
        [xml]$wfp = Get-Content $out
        $allFilters = $wfp.wfpdiag.filters.item
        # exit if the WFP rules can't be read
        if ($null -eq $allFilters) {
            Write-Output "Unable to retrieve data from netsh! Exiting..."
            exit 1
        }

        Write-Output "Looking for WFP blocking rules..."
        foreach ($filter in $allFilters) {
            # Huntress rules
            if ($filter.displayData.name -match 'Huntress' -and $filter.action.type -contains "FWP_ACTION_BLOCK" -and $filter.flags.item -notcontains 'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT') {
                $filterToAdd = New-Object PSObject -Property @{
                    Name = $filter.displayData.name
                    Action = $filter.action.type
                    Flags = $($filter.flags.item -join ', ')
                    Weight = $($filter.effectiveWeight.uint64)
                }
                [void]$HuntressFilters.Add($filterToAdd)
            }
            # 3rd party rules (best effort based on best practices for preventing isolation bypass using weight)
            if ($filter.displayData.name -notmatch 'Huntress' -and $filter.action.type -contains 'FWP_ACTION_BLOCK' -and $filter.flags.item -notcontains 'FWPM_FILTER_FLAG_DISABLED' -and $filter.weight.uint64 -ge 2305843009213696559) {
                # weight is a metric used to prevent other WFP filters from interferring, logged for troubleshooting
                $filterToAdd = New-Object PSObject -Property @{
                    Name = $filter.displayData.name
                    Action = $filter.action.type
                    Flags = $($filter.flags.item -join ', ')
                    Weight = $($filter.weight.uint64)
                }
                [void]$otherWFPFilters.Add($filterToAdd)
            }
        }
        $numHuntressFilters = @($HuntressFilters).Count
        if ($numHuntressFilters -gt 0) {
            $HuntressFilters | Format-List
        }
        $numOtherFilters = @($otherWFPFilters).Count
        if ($numOtherFilters -gt 0) {
            $otherWFPFilters | Format-List
        }
    }


    # Kernel must be 6.2+ for a Defender Firewall check (Win 8/Server 2012 or higher)
    if ( $kernelVersion -ge 6.2 ) {
        $skipDFTest    = $false
        $firewallRules = New-Object System.Collections.ArrayList
        $tempRules     = New-Object System.Collections.ArrayList

        $tempRules = Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue
        if ($null -eq $tempRules) {
            if ($null -eq $(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
                $firewallFail = "Warning: Unable to retrieve Defender Firewall rules"
            }
        } else {
            Write-Output "Looking for Defender Firewall blocking rules (best effort)..."
            foreach ($rule in $tempRules){
                $portFilter    = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                if ($null -ne $portFilter -and $null -ne $addressFilter){
                    $firewallRules += New-Object PSObject -Property@{
                        Name          = $rule.Name
                        DisplayName   = $rule.DisplayName
                        Direction     = $rule.Direction
                        Profile       = $rule.Profile
                        Protocol      = $portFilter.Protocol
                        LocalPort     = $portFilter.LocalPort
                        RemotePort    = $portFilter.RemotePort
                        LocalAddress  = $addressFilter.LocalAddress
                        RemoteAddress = $addressFilter.RemoteAddress
                    }
                }
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
            # storing all isolate and unisolate events in the last $cutoff days to display for troubleshooting
            if ($loggedEvent.TimeCreated -ge $cutoff -and $loggedEvent.Message -match 'isolate|unisolate|isolation|unisolation') {
                $eventsFromMDE += $loggedEvent
                $total3rdPartyBlocks++
                # Id 60 indicates "failed to run command". Id 59 indicates "starting command", while 71 indicates the command succeeded
                # grabbing the most recent successful event if $newestEvent hasn't been set yet. 
                if ($null -eq $newestEvent -and $loggedEvent.Id -eq 71) {
                    $newestEvent = $loggedEvent
                # if a newer successful event is found, use it instead.
                } elseif ($newestEvent.RecordId -lt $loggedEvent.RecordId -and $loggedEvent.Id -eq 71) {
                    $newestEvent = $loggedEvent
                }
            }
        }
    } catch {
        $MDETryCatch = $true
        $scOutput    = $(sc.exe query sense 2>$null | Select-String "STATE")
        if ($scOutput -like "*STOPPED*") {
            Write-Output "MDE service is not running, unable to retrieve MDE logs. Likely MDE/DfE/DfB/ATP isn't installed."
        } else {
            Write-Output "MDE unknown service state, unable to retrieve Windows Logs! Ignore this if MDE/DfE/DfB/ATP isn't installed."
        }
    }
    if ( ! $MDETryCatch ) {
        # If the most recent command is an unisolation event, mark this scan as most likely not isolated by MDE
        if ($newestEvent.Message -like "*unisolationcommand*" -or $newestEvent.Message -like "*unisolate*") {
            $unisolationNewest = $true
        }
        if ($eventsFromMDE.Count -gt 0) {
            prettyPrintMDE $eventsFromMDE
        } else {
            Write-Output "No MDE events found in the last $cutoff days."
        }
    }

    Write-Output "`n------------------------------ Results ------------------------------"
    if ($numHuntressFilters -gt 0) {
        Write-Host "Huntress          : Host Isolation active, active Huntress WFP filters found: $numHuntressFilters!" -ForegroundColor Black -BackgroundColor Red
    } else {
        Write-Host "Huntress          : Not isolating this machine!" -ForegroundColor Green -BackgroundColor Black
    }

    if ($numOtherFilters -gt 0) {
        Write-Host "Other WFP Filters : Active 3rd party WFP filters found: $numOtherFilters! Look above at the 'Name' field to see the source of isolation." -ForegroundColor Black -BackgroundColor Red
    } else {
        Write-Host "Other WFP Filters : No active 3rd party WFP blocking filters found. This isn't conclusive, simply a best effort." -ForegroundColor Green -BackgroundColor Black
    }

    if ($skipDFTest) {
        Write-Host "Defender Firewall : Skipped test, unsupported OS." -ForegroundColor Green -BackgroundColor Black
    } elseif ($null -ne $firewallFail) {
        Write-Host "$firewallFail"
    } else {
        if ($firewallRules.Count -gt 0) {
            Write-Host "Defender Firewall : $($firewallRules.Count) potential blocking rules found!" -ForegroundColor Black -BackgroundColor Red
        } else {
            Write-Host "Defender Firewall : No blocking rules found on this machine. This isn't conclusive, simply a best effort." -ForegroundColor Green -BackgroundColor Black
        }
    }

    # if we collected events and the 'catch' path wasn't used
    if ($eventsFromMDE.Count -gt 0 -and ! $MDETryCatch) {
        # if the most recent event was not an unisolation
        if ($unisolationNewest -eq $false) {
            Write-Host "Microsoft DfE     : Isolation event found in the last 30 days! Check your Microsoft portal for alerts!" -ForegroundColor Black -BackgroundColor Red
        # if the most recent event was an unisolation
        } else {
            Write-Host "Microsoft DfE     : A recent isolation event was detected, however an unisolation event was detected as a more recent event." -ForegroundColor White -BackgroundColor Black
            Write-Host "Examine the Event Logs above or check your Microsoft portal to confirm the endpoint isn't isolated by MDE" -ForegroundColor White -BackgroundColor Black
        }
    # if we collected events but the 'catch' path was used (printing whatever we can find, best effort)
    } elseif ($eventsFromMDE.Count -gt 0 -and $MDETryCatch) {
        Write-Host "Microsoft DfE     : Error retrieving data from Event Logs, however some data was retrieved which should be visible above." -ForegroundColor Black -BackgroundColor Red
    # no events, but 'catch' path was used (likely DfE is not installed)
    } elseif ($MDETryCatch) {
        Write-Host "Microsoft DfE     : Likely not installed, no data found. This isn't conclusive, simply a best effort." -ForegroundColor Green -BackgroundColor Black
    # catch-all for edge cases
    } else {
        Write-Host "Microsoft DfE     : No isolation events found in the event logs. This isn't conclusive, simply a best effort." -ForegroundColor Green -BackgroundColor Black
    }
} finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}
