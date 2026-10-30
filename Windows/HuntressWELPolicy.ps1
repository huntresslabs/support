# What does this do?
# This script is designed to be a quick _estimation_ of which system is interfering with Huntress WEL Audit Policy. There are several 
# different systems which can interfere and not all of them expose this data in a programmatic fashion, thus this script is a "best effort" 
# intended to quickly spot check an endpoint. Additional work may be required to identify the source of interference. This script does not
# attempt to change policy, it's read only but the output explains how to remediate!
#
# Why is this needed?
# The Huntress agent will automatically attempt to change these policies, however the agent can be blocked by higher priority systems. This 
# script does a cursory check for audit policies set by Entra, AD, and local group policy. If a system is found to be setting policy,
# that is the system that needs to have it's policy adjusted or removed from that system so that Huntress can set audit logging policy.
#
# Important Note:
# This script uses the auditpol command to pull AD and local policy, however auditpol does not clearly differentiate between AD and local
# policy. auditpol is the only way to see what is currently enforced, as other methods like gpedit.msc only show desired policy which can be 
# affected by domain connectivity issues. Some differentiation is created by comparing the two audit.csv files to auditpol results and testing
# for AD connectivity.
#
# Bottom line: 
# The policies being detected are accurate, but may be inaccurately classified as AD or local policy. The script will help guide you either way.
#
# Requirements:
# * Script must be run as administrator on an endpoint with WEL Audit Policy mismatches!
# * This endpoint must be able to reach raw.githubusercontent.com for the script to download a CSV file containing the recommended policies
#
# These KB articles go into considerable more depth in ways a script cannot:
$urlFind    = "https://support.huntress.io/hc/en-us/articles/51811065416851-Finding-the-Source-of-Windows-Logging-Audit-Policy-Configuration"
$urlADLocal = "https://support.huntress.io/hc/en-us/articles/49363914702867-Enforcing-Windows-Logging-Audit-Policies-AD-and-local-GPO"
$urlEntra   = "https://support.huntress.io/hc/en-us/articles/49828550456979-Enforcing-Windows-Logging-Audit-Policies-Microsoft-Intune"

$latestUpdate = "Huntress WEL Audit Policy Check, last updated: Oct 30, 2026"


# Setup variables for later use and set working directory
$LocalPolicyFile1 = "c:\Windows\security\audit\audit.csv"
$LocalPolicyFile2 = "c:\Windows\System32\GroupPolicy\Machine\Microsoft\WindowsNT\Audit\audit.csv"
$tempPath         = "c:\Windows\temp"
$debugLog         = "c:\Windows\temp\HuntressWELPolicy.log"
$DeviceStatus     = New-Object System.Collections.ArrayList
$hPolicy          = @()              # recommended policy name, retrieved from github
$hSet             = @()              # recommended policy value, retrieved from github
$localPolicy      = @()              # local policy name (all 3 systems share this temp array)
$localSet         = @()              # local policy value (all 3 systems share this temp array)
$GUIDArrayAD      = @()              # stores all AD GUID for tracing back to source
$GUIDArrayLocal   = @()              # stores all local policy GUID for tracing back to source
$GUIDArrayEntra   = @()              # stores all Entra GUID for tracing back to source
$ADPolicyArray    = @()              # all AD policies that don't match recommended
$localPolicyArray = @()              # all local group policies that don't match recommended
$EntraPolicyArray = @()              # all Entra policies that don't match recommended

Set-Location -Path $tempPath


# download Huntress recommended policies from github
function getHuntressPolicy {
    param ( [String]$hPolicyFile )

    $hPolicy = @()
    $hSet    = @()

    # Attempt to download the CSV from github
    $URL = 'https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/WELpolicy.csv'
    try { 
        Invoke-WebRequest -Uri $URL -OutFile $hPolicyFile -UseBasicParsing -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        alertLogger $msg "Red"
        logger "Attempting to use WebClient fallback...."
        $wc = New-Object System.Net.WebClient
        $wc.Headers['User-Agent'] = 'HuntressSupportScript'
        try {
            (New-Object System.Net.WebClient).DownloadFile($URL, $hPolicyFile)
        } catch {
            $msg = $_Exception.Message
            alertLogger $msg "Red"
            if ( ! (Test-Path -Path $hPolicyFile) ) {
                logger "[ERROR: Unable to connect to github, unable to find local copy of JSON file!]"
                logger "Save the file $URL in the same directory as this script to run without needing to open a port to github"
                throw "Unable to connect to github"
            }
        }
    }

    # Split the file into two arrays
    foreach ($line in $(Get-Content -Path $hPolicyFile)) {
        $temp     = $line -split ','
        $hPolicy += $($temp[0].ToLower().Substring(6).Trim() -replace '[ /-]','')
        $hSet    += $temp[1].ToLower().Trim()
    }

    return [PSCustomObject]@{
                hPolicy = $hPolicy
                hSet    = $hSet
            }
}

# adds time stamp to a message and then writes that to the log file
function logger ($msg) {
    $TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
    Add-Content $debugLog "$TimeStamp $msg"
    Write-Host "$msg"
}

# same as logger, but uses Write-Host with colors to call attention to it (since the output must be wordy)
function alertLogger {
    param ( [Parameter(Mandatory = $true)]
            [string]$msg,
            [string]$textColor )

    $TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
    Add-Content $debugLog "$TimeStamp $msg"
    Write-Host "$msg" -BackgroundColor Black -ForegroundColor $textColor
}

# Prints the array in a clean format, auto adjusting size
function prettyPrint {
    param ( [Parameter(Mandatory = $true)]
            [array]$array )

    alertLogger "Policy                               Suggested Value            Current Value           GUID                                " "Red"
    alertLogger "----------------------------------------------------------------------------------------------------------------------------" "Red"
    foreach ($element in $array) {
        $len1=" " * (35-$($element.Policy.Length))  #35-
        $len2=" " * (25-$($element.ExpectedValue.Length))  #25-
        $len3=" " * (22-$($element.LocalValue.Length))  #35-
        $output="$($element.Policy) $len1 $($element.ExpectedValue) $len2 $($element.LocalValue) $len3 $($element.GUID)"  #87 
        alertLogger $output "Red"
    }
}

# Compares policy names in $hPolicy to $localPolicy, if a match is found compare the corresponding $hSet to $localSet and
# if those differ write the $localSet and $GUID values to a custom object $results to be returned.
function comparePol {
    [CmdletBinding()]
    param ( [Parameter(Mandatory = $true)]
            [array]$hPolicy,
            [array]$hSet,
            [array]$localPolicy,
            [array]$localSet,
            [array]$GUID
           )

    # Validate that each pair of arrays lines up
    if ($hPolicy.Count -ne $hSet.Count) {
        throw "`$hPolicy ($($hPolicy.Count)) and `$hSet ($($hSet.Count)) have different element counts. Error retrieving data!"
    }
    if ($localPolicy.Count -ne $localSet.Count -or $localPolicy.Count -ne $GUID.Count) {
        throw "`$localPolicy ($($localPolicy.Count)), `$localSet ($($localSet.Count)), or `$GUID ($($GUID.Count)) have different element counts. Error retrieving data!"
    }

    # Build lookup: policy text -> list of index positions in $localPolicy
    $localIndex = @{}
    for ($i = 0; $i -lt $localPolicy.Count; $i++) {
        $key = ([string]$localPolicy[$i]).Trim()
        if (-not $localIndex.ContainsKey($key)) {
            $localIndex[$key] = New-Object System.Collections.ArrayList
        }
        [void]$localIndex[$key].Add($i)
    }

    # Increment through $hPolicy, find matching text in $localPolicy, only storing if the corresponding $hValue and $localValue don't match
    $results = for ($h = 0; $h -lt $hPolicy.Count; $h++) {
        $key      = ([string]$hPolicy[$h]).Trim()
        $hValue   = ([string]$hSet[$h]).Trim()
        $tempGUID = ([string]$GUID[$h]).Trim()

        if ($localIndex.ContainsKey($key)) {
            foreach ($l in $localIndex[$key]) {
                $localValue = ([string]$localSet[$l]).Trim()
                if ($hValue -ne $localValue -and $null -ne $tempGUID -and "" -ne $tempGUID) {
                    [PSCustomObject][ordered]@{
                        Policy        = $key
                        ExpectedValue = $hValue
                        LocalValue    = $localValue
                        GUID          = $tempGUID
                    }
                }
            }
        }
    }
    return $results
}

# Helper function to split the contents of $policyFileLocation (audit.csv) into 3 arrays
function getlocalPolicy {
    param ( [Parameter(Mandatory = $true)]
            [string]$policyFileLocation ) 

    $localPolicy      = @()
    $localSet         = @()
    $GUID             = @()
    $localPolicyArray = @(Get-Content -Path $policyFileLocation | Select-Object -Skip 1 )

    foreach ($line in $localPolicyArray) {
        $array=$line -split ','
        $GUID        +=$($array[3].ToLower() -Replace '[{}]', "")
        $localPolicy +=$array[2].ToLower().Substring(6).Trim() -Replace " ",""
        $localSet    +=$array[4].ToLower().Trim()
    }

    return [PSCustomObject]@{
                localPolicy = $localPolicy
                localSet    = $localSet
                GUID        = $GUID
            }
}

# used when script detects Entra or AD joined domains and finds some potential conflicts
function policyConflictJoined {
    param ( [Parameter(Mandatory = $true)]
            [string]$systemName )

    alertLogger "A potential conflicting audit policy was found in $systemName!" "Red"
}

# used when local potentially conflicting policies are found
function localPolicyConflict {
    param ( [Parameter(Mandatory = $true)]
            [string]$localPolicyResults )

    alertLogger "==> A potential conflict with local group policy is detected in:" "Red"
    alertLogger $localPolicyResults "Red"
    alertLogger "Deleting the above file and rebooting should resolve this section." "Green"
}

# used when potential conflicts are found, but no Entra or AD link is detected
function policyConflictNotJoined {
    param ( [Parameter(Mandatory = $true)]
            [string]$systemName )

    if ($systemName -eq "AD") {
        alertLogger "A potential conflict with Active Directory/local policy is detected, however this endpoint is not AD joined!" "Red"
        alertLogger "This is likely local group policy or a 'tattooed' (rare) setting from a previous join." "Red"
        alertLogger "Adjust Local Group Policy Editor to match the competing policies above, navigate to these 2 areas and adjust settings:" "Green"
        alertLogger "1.  Computer Config > Windows Setting > Security Setting > Local Policies > Audit Policy" "Green"
        alertLogger "2.  Computer Config > Windows Setting > Security Setting > Local Policies > Advanced Audit Policy Config > System Audit Policies" "Green"
        alertLogger "Removing tattooed policy is beyond what can be listed here, however there are many great resources on the internet." "Green"
    } else {
        alertLogger "A potential conflict with Entra/Intune is detected, however this endpoint is not Entra joined." "Red"
        alertLogger "This is likely a 'tattooed' setting from a previous join!" "Red"
    }
}

# Adds GUID value to GUID array if not found
function addGUID {
    param ( [Parameter(Mandatory = $true)]
        [array]$localPolicy,
        [array]$GUIDArray,
        [string]$policyName,
        [string]$GUID )

    # find the policy name, and add GUID if it hasn't been found
    for ($i = 0; $i -lt $localPolicy.Count; $i++) {
        if ($policyName -eq $localPolicy[$i]) {
            if ($null -eq $GUIDArray[$i] -or $GUIDArray[$i] -eq ".") {
                $GUIDArray[$i]=$GUID.ToLower()
            }
        }
    }
    return New-Object PSObject -Property @{ localPolicy = $localPolicy
                                            GUIDArray   = $GUIDArray }
}

# Return the index value of the string if found, otherwise return -2
function getIndexOfStringInArray {
    param ( [Parameter(Mandatory = $true)]
        [array]$array,
        [string]$string )

    for ($i = 0; $i -lt $array.Count; $i++) {
        if ($array[$i] -eq $string) {
            return $i
        }
    }
    return -2
}

# Helper to convert number value to string value (for Entra)
function getConversionValue {
    param ( [Parameter(Mandatory = $true)]
        [int]$intValue )

    switch ($intValue) {
        0 {return "no auditing"}
        1 {return "success"}
        2 {return "failure"}
        3 {return "success and failure"}
        default {return "error retrieving"}
    }
}

# returns custom object that indicates whether the machine is AD and/or Entra joined
function getJoinedStatus {
    # find the correct path for dsregcmd and execute it
    $Path = if (Test-Path "$env:SystemRoot\sysnative\dsregcmd.exe") {
        "$env:SystemRoot\sysnative\dsregcmd.exe"
    } else {
        "$env:SystemRoot\System32\dsregcmd.exe"
    }
    $Output = & $Path /status

    # Parse the text lines into a custom PowerShell object
    $StatusObj = [ordered]@{}
    $Output | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z]+)\s*:\s*(.+)$') {
            $Key = $Matches[1].Trim()
            $Value = $Matches[2].Trim()
            if (-not $StatusObj.Contains($Key)) {
                $StatusObj[$Key] = $Value
            }
        }
    }

    $EntraJoined = $true
    $ADJoined = $true
    if ($StatusObj.AzureAdJoined -like "*NO*") {
        $EntraJoined = $false
    }
    if ($StatusObj.DomainJoined -like "*NO*") {
        $ADJoined = $false
    }

    return New-Object PSObject -Property @{ EntraJoined = $EntraJoined
                                            ADJoined    = $ADJoined }
}


############################################## Script Pre-Flight Check ##############################################################
# Exit if script isn't run as admin
$user = [Security.Principal.WindowsIdentity]::GetCurrent();
if ((New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host ""
    Write-Host "     ##   ## ##    ## ###    ##  ######  ######  ####### ####### #######" -ForegroundColor Cyan
    Write-Host "     ##   ## ##    ## ####   ##    ##    ##   ## ##      ##      ##     " -ForegroundColor Cyan
    Write-Host "     ####### ##    ## ## ##  ##    ##    ######  #####   ####### #######" -ForegroundColor Cyan
    Write-Host "     ##   ## ##    ## ##  ## ##    ##    ##   ## ##           ##      ##" -ForegroundColor Cyan
    Write-Host "     ##   ##  ######  ##   ####    ##    ##   ## ####### ####### #######" -ForegroundColor Cyan
    logger "------------------------------------------------------------------------------------------------------------------------------"
    logger "                                    $latestUpdate"
    logger "------------------------------------------------------------------------------------------------------------------------------"
} else {
    logger "Warning: this script must be run as admin. Exiting."
    exit 1
}

$hPolicyFile   = Join-Path $(Split-Path -Parent -Path $MyInvocation.MyCommand.Definition) "WELpolicy.csv"
$hPolicyObject = getHuntressPolicy $hPolicyFile   # retrieve the recommended file from github
$hPolicy       = $($hPolicyObject.hPolicy)        # set array based on downloaded content
$hSet          = $($hPolicyObject.hSet)           # set array based on downloaded content
$DeviceStatus  = getJoinedStatus                  # get Entra and AD joined status


############################################################## Entra ################################################################
# Grab Entra policy from registry
$regData = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device -ErrorAction SilentlyContinue | Where {$_.Name -like "*\current\device\Audit"}
$audPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Audit"

# copy names to be inspected into local array, then set other two arrays to same length
# based on the name in $localPolicy, the other 2 arrays will be filled in later
$localPolicy    = $hPolicy
$localSet       = New-Object -TypeName 'object[]' -ArgumentList $localPolicy.Length
$GUIDArrayEntra = New-Object -TypeName 'object[]' -ArgumentList $localPolicy.Length

Write-Host "Entra/Azure AD entries: " -NoNewLine

if ($regData.Length -gt 0) {
    Write-Host "Entries found, searching..."
    foreach ($property in $regData.Property) {
        # since all 3 tests use the same recommended policy file, the data needs to be altered to fit Entra registry entries
        $tempPolData = $( $property.ToLower() -replace "_lastwrite", "" )
        $tempPolName = @($tempPolData -split "_")[1] -replace "audit", ""
        
        # tempPropValue is the 'Set' value if _ProviderSet, otherwise it is the 'GUID' (i.e. _WinningProvider)
        $tempPropValue = $(Get-ItemPropertyValue -Path $audPath -Name $property)

        # get the index location of where the policy name is in the array, if found write to $localSet array
        if ($tempPolData -like "*_ProviderSet") {
            $index = getIndexOfStringInArray $localPolicy $tempPolName
            if ($index -le -1) {
                throw "unknown error $index, can't find $tempPolName in array: $localPolicy"
            } else {
                $localSet[$index] = getConversionValue $tempPropValue
            }
        # add the GUID value to $GUIDArray
        } elseif ($tempPolData -like "*_WinningProvider") {
            if ($null -ne $tempPropValue) {
                $polGUIDObj     = addGUID $localPolicy $GUIDArrayEntra $tempPolName $tempPropValue # $tempSet
                $localPolicy    = $($polGUIDObj.localPolicy)
                $GUIDArrayEntra = $($polGUIDObj.GUIDArray)
            }
        }
    }
} else {
    Write-Host "No Entra registry entries found." -BackgroundColor "Black" -ForegroundColor "Green"
}

$EntraPolicyArray = comparePol $hPolicy $hSet $localPolicy $localSet $GUIDArrayEntra


############################################################## Local Policy ################################################################
Write-Host "Local GPO entries: " -NoNewLine
# reset the local arrays before re-use, setup 2 temp variables
$localPolicy = @()
$localSet    = @()
$pol1Results = $false
$pol2Results = $false

if (! (Test-Path $LocalPolicyFile1) -and ! (Test-Path $LocalPolicyFile2)) {
    Write-Host "No local policy files found." -BackgroundColor "Black" -ForegroundColor "Green"
} else {
    Write-Host "Entries found, searching..."
    # pull data from $LocalPolicyFile1 into arrays, then compare with recommended policy
    if (Test-Path $LocalPolicyFile1) {
        $tempPolicyObject = getlocalPolicy $LocalPolicyFile1
        $localPolicy      = @($tempPolicyObject.localPolicy).ToLower()
        $localSet         = @($tempPolicyObject.localSet)
        $GUIDArrayLocal   = @($tempPolicyObject.GUID)
        $localPolicyArray = comparePol $hPolicy $hSet $localPolicy $localSet $GUIDArrayLocal
        if ($null -ne $localPolicyArray) {
            $pol1Results = $true
        }
    }
    # pull data from $LocalPolicyFile2 into arrays, then compare with recommended policy
    if (Test-Path $LocalPolicyFile2) {
        $tempPolicyObject = getlocalPolicy $LocalPolicyFile2
        $localPolicy      = @($tempPolicyObject.localPolicy)
        $localSet         = @($tempPolicyObject.localSet)
        $GUIDArrayLocal   = @($tempPolicyObject.GUID)
        $localTemp        = comparePol $hPolicy $hSet $localPolicy $localSet $GUIDArrayLocal
        # if 2nd audit.csv is found, combine both into $localPolicyArray
        if ($null -ne $localTemp) {
            $pol2Results = $true
            $localPolicyArray += $localTemp
        }
    }
}


############################################################## Active Directory ################################################################
Write-Host "Active Directory entries: " -NoNewLine

# Reset these for re-use, ensure arrays are same length
$localPolicy = $hPolicy 
$localSet    = New-Object -TypeName 'object[]' -ArgumentList $hSet.Length
$GUIDArrayAD = New-Object -TypeName 'object[]' -ArgumentList $hSet.Length

# Filter out blank lines from auditpol, and skip the header line
$raw = (auditpol /get /category:* /r).ToLower() | Where-Object { $_.Trim() -ne '' }
[array]$allPolicies = $raw | Select-Object -Skip 1

# Look through all local policies for policies Huntress suggests
if ($allPolicies.Length -gt 0) {
    Write-Host "Entries found, searching..."

    # split each policy data set into the appropriate arrays
    foreach ($policy in $allPolicies) {
        $array=@($policy -split ',')
        $tempPolName = $array[2].ToLower() -replace '[ /-]', ''
        
        # if policy name is found in array, add Set and GUID value to the same array indices in their respective arrays
        $index = getIndexOfStringInArray $localPolicy $tempPolName
        if ($index -ge 0) {
            $localSet[$index] = $array[4].ToLower()
            $tempGUID    = $($array[3].ToLower()) -replace '[{}]', ''
            $polGUIDObj  = addGUID $localPolicy $GUIDArrayAD $tempPolName $tempGUID
            $localPolicy = $($polGUIDObj.localPolicy)
            $GUIDArrayAD = $($polGUIDObj.GUIDArray) 
        }
    }

    $ADPolicyArray = comparePol $hPolicy $hSet $localPolicy $localSet $GUIDArrayAD
} else {
    Write-Host "No auditpol entries found." -BackgroundColor "Black" -ForegroundColor "Green"
}


# Compile all the results and display/log the info
# Note: this is where the results are, so we use logger() or alertLogger() to display and log at the same time
$conflictsFound = 0     # compiling results for final summary
logger ""

if ($null -ne $EntraPolicyArray) {
    $conflictsFound++
    if ($($DeviceStatus.EntraJoined) -eq $true) {
        alertLogger "################################## Potential Entra policy conflicts found (Entra-join detected) ############################" "Red"
    } else {
        alertLogger "############################### Potential Entra policy conflicts found (machine not Entra-joined!) #########################" "Red"
    }
    prettyPrint $EntraPolicyArray
    alertLogger "----------------------------------------------------------------------------------------------------------------------------" "Red"
    if ( $($DeviceStatus.EntraJoined) ) {
        policyConflictJoined "Entra"
    } else {
        policyConflictNotJoined "Entra"
    }
    if ( $($DeviceStatus.EntraJoined) ) {
        alertLogger "This KB has instructions on how to address Entra / Intune conflicts:" "Green"
        alertLogger $urlEntra "Green"
    } else {
        alertLogger "It's highly recommended you verify Settings > Accounts > 'Access Work..' does not list any Entra tenants first." "Green"
        alertLogger "Then expand the GUID key(s) listed below to ensure you aren't removing other policy!" "Green"
        alertLogger "Deleting all the keys in the registry sections below should remove tatooed policies" "Green"
        alertLogger "For the first entry you'll want to remove the GUID keys in the 'Entra Policy Conflicts' table above" "Green"
        alertLogger "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\providers" "Green"
        alertLogger "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Audit" "Green"
    }
    logger ""
} 

if ($ADPolicyArray.Count -gt 1) {
    $conflictsFound++
    if ($($DeviceStatus.ADJoined) -eq $true) {
        alertLogger "############################## Potential AD policy conflicts found (AD-join detected) ######################################" "Red"
    } else {
        alertLogger "########################## Potential AD/local policy conflicts found (machine not AD-joined!) ##############################" "Red"
    }
    prettyPrint $ADPolicyArray
    alertLogger "----------------------------------------------------------------------------------------------------------------------------" "Red"
    if ($DeviceStatus.ADJoined) {
        policyConflictJoined "AD"
    } else {
        policyConflictNotJoined "AD"
    }
    alertLogger "This KB has instructions on how to address AD and local group policy conflicts:" "Green"
    alertLogger $urlADLocal "Green"
    logger ""
} 

if ($null -ne $localPolicyArray) {
    $conflictsFound++
    alertLogger "################################### Potential Local Policy conflicts found #################################################" "Red"
    prettyPrint $localPolicyArray
    alertLogger "----------------------------------------------------------------------------------------------------------------------------" "Red"
    if (Test-Path $LocalPolicyFile1) {
        localPolicyConflict $LocalPolicyFile1
    } 
    if (Test-Path $LocalPolicyFile2) {
        localPolicyConflict $LocalPolicyFile2
    }
    alertLogger "This KB has instructions on how to address local group policy conflicts:" "Green"
    alertLogger $urlADLocal "Green"
}

if ($conflictsFound -eq 0) {
    logger "No potential conflicts found. It is likely this particular endpoint will need a deep dive to find the source of conflict. This KB will help:"
    logger $urlFind
}
