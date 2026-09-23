# Tests a number of ways Huntress agents communicate with the Huntress portal, essentially a TCP port 443 connection outbound.
# This effectively tests connectivity as well as checks for certificate interception/inspection services which will prevent the
# Huntress agent from communicating with the Huntress portal.
#
# This script is designed for use in PowerShell versions 3 through 7. 
# PoSh 2.x is missing ConvertFrom-Json, out of the box native TLS 1.2 support, and would require .NET that isn't always installed.
#
# If the file URLdata.json is found and not more than 2 weeks old, use that file, otherwise the script downloads from github.
# So if your network blocks access to githubusercontent.com you'll need to keep the below file in the same directory as the script.
#    https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json


# If you'd like to use a local JSON file in a specified location, uncomment the below line and change the location if needed
# $alternateLocalJSONFile = "$env:temp\URLdata.json"

$latestUpdate = "Huntress Network Tester, Windows PowerShell, last updated: September 23, 2026"
$DebugLog     = "c:\Windows\temp\huntress_network_test.log"

# adds time stamp to a message and then writes that to the log file
function logger ($msg) {
    $TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
    Add-Content $DebugLog "$TimeStamp $msg"
    Write-Output "$msg"
}

logger "-----------------------------------------------------------------------------"
logger $latestUpdate
logger "-----------------------------------------------------------------------------"

# Simple test to establish working DNS, basic internet connectivity, and ability to connect to huntress.io
function simpleTest {
    param ( [PSObject]$netDataObject )

    logger "-- Testing DNS resolution and port 443 connectivity --"
    try {
        $pageOutput = $(Invoke-WebRequest "https://huntress.io" -UseBasicParsing)
        if ($pageOutput.StatusCode -eq 200) {
            $pageOutput = $($pageOutput.Content) | Select-Object -First 20 
            $startIndex = $pageOutput.IndexOf("<title>")
            if ($startIndex -ne -1) {
                $contentStart = $startIndex + 7
                $result = $pageOutput.Substring($contentStart, 27)
                logger "[DNS Resolution / port 443 connection successful]"
            } else {
                logger "The tag '<title>' was not found."
                $netDataObject.countFails++
            }
        } else {
            logger "[FAILED: DNS and port 443 checks]"
            $netDataObject.countFails++
        }
    } catch {
        logger "Error interacting with Invoke-WebRequest: $_"
        $netDataObject.countFails++
    }
    logger ""
}
# <--

# Setup custom object for network testing
$localJSONLocation = Join-Path $(Split-Path -Parent -Path $MyInvocation.MyCommand.Definition) "URLdata.json"
if ($null -ne $alternateLocalJSONFile) {
    $localJSONLocation = $alternateLocalJSONFile
}
$testURLs      = @()
$certData      = @()
$netDataObject = New-Object -TypeName PSObject -Property @{
    altJSON    = "$env:temp\URLdata.json"
    localJSON  = $localJSONLocation
    countFails = 0
    testURLs   = $testURLs
    certData   = $certData
}


# Select a secure TLS protocol for the current PowerShell process. This must occur before any communication.
function setNetworking {
    # Keep "First Run Customize" popup window from blocking the testing (by disabling it)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

    try {
        $ProtocolsSupported = [System.Enum]::GetValues([System.Net.SecurityProtocolType])
        # Only TLS 1.3 or 1.2 are supported for secure communication with the Huntress portal
        if ( ($ProtocolsSupported -contains 'Tls13') -and ($ProtocolsSupported -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = (
                [System.Enum]::ToObject([System.Net.SecurityProtocolType], 12288) -bOR [System.Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
            )
        } else {
            # In certain .NET 4.0 patch levels, SecurityProtocolType does not have a TLS 1.2 entry.
            # Rather than check for 'Tls12', we force-set TLS 1.2 and catch the error if it's truly unsupported.
            # Note that these legacy systems will also need some manual configuration work before using protocol 3072 (TLS 1.2)
            # See: https://support.microsoft.com/en-us/topic/support-for-tls-system-default-versions-included-in-the-net-framework-2-0-sp2-on-windows-vista-sp2-and-server-2008-sp2-1001add1-103f-0a22-e807-00ee2fc7c75d
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
        }
    } catch {
        $msg = $_.Exception.Message
        logger "Failed to enable TLS 1.2, Huntress requires TLS 1.2 or higher for security reasons."
        logger "$msg"
        throw $msg
    }
}

# Helper function to print lengthy error/instructional message
function certFail {
    param ( [Parameter(Mandatory = $true)]
            [string]$cleanURL )
    logger "------------------------------------------------------------------------------------------------------------------------------"
    logger "The Subject/Issuer text above usually identifies if this is a DPI/cert interception issue, or a cert chain issue."
    logger "* If the returned SUBJECT does not contain 'Huntress' or 'Microsoft' in the text this is likely a DPI/cert interception issue."
    logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
    logger "* If the returned ISSUER does not contain 'DigiCert', 'Google', or 'Microsoft', this is likely a  DPI/cert interception issue."
    logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
    logger "* Otherwise this is likely a missing certificate chain. Check for pending OS updates, reboot, and try again."
    logger "------------------------------------------------------------------------------------------------------------------------------"
    
}

# If the local JSON file exists and was modified less than 14 days ago, skip downloading from github
function getLocalJSON {
    param ( [PSObject]$netDataObject )

    # try to use local JSON first
    if (Test-Path -Path $netDataObject.localJSON) {
        $lastWrite = (Get-Item $netDataObject.localJSON).LastWriteTime
        if ($lastWrite -gt ((Get-Date).AddDays(-14))) {
            logger "Using local URLdata.json from $lastWrite for network testing.`n"
            getJSON $netDataObject
        } else {
            logger "$netDataObject.localJSON is stale, downloading new version from github for network testing"
            getJSON $netDataObject -downloadFromGithub
        }
    # try to use alternate JSON location next
    } elseif (Test-Path -Path $netDataObject.altJSON) {
        $netDataObject.localJSON = $netDataObject.altJSON
        $lastWrite = (Get-Item $netDataObject.localJSON).LastWriteTime
        if ($lastWrite -gt ((Get-Date).AddDays(-14))) {
            logger "Using alternate local URLdata.json ($($netDataObject.altJSON)) from $lastWrite `n"
            getJSON $netDataObject
        } else {
            logger "$localJSON (alternate location) is stale, downloading new version from github"
            getJSON $netDataObject -downloadFromGithub
        }
    # Otherwise download github to localJSON if writable, alternate otherwise
    } else {
        try {
            New-Item -Path $netDataObject.localJSON -ItemType File
            Remove-Item $netDataObject.localJSON -Force
            logger "$($netDataObject.localJSON) not found, attempting to retrieve from github."
        } catch {
            logger "$($netDataObject.localJSON) is not writeable, attempting to use alternate"
            $netDataObject.localJSON = $netDataObject.altJSON
        }
        getJSON $netDataObject -downloadFromGithub
    }
}

# Pass [bool]true to download a fresh copy of the JSON data, or [bool]false to use a local copy. Must pass PSObject as well.
# This function populates $data array with the resulting file contents
function getJSON {
    param ( [PSObject]$netDataObject,
            [switch]$downloadFromGithub )

    # Attempt to download the JSON from github if prompted by $downloadFromGithub
    if ($downloadFromGithub) {
        try { 
            $URL = 'https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json'
            Invoke-WebRequest -Uri $URL -OutFile $netDataObject.localJSON -UseBasicParsing -ErrorAction Stop
        } catch {
            logger "Fallback using WebClient (still uses TLS 1.2)"
            $wc = New-Object System.Net.WebClient
            $wc.Headers['User-Agent'] = 'HuntressSupportScript'
            try {
                (New-Object System.Net.WebClient).DownloadFile($URL, $netDataObject.localJSON)
            } catch {
                if (Test-Path -Path $netDataObject.localJSON) {
                    logger "[Warning: Unable to connect to github, using a stale version of the JSON. Test may be inaccurate without fresh data!]"
                } else {
                    logger "[ERROR: Unable to connect to github, unable to find local copy of JSON file!]"
                    logger "Save the file $URL in the same directory as this script to run without needing to open a port to github"
                    throw "Unable to connect to github"
                }
            }
        }
    }

    # Read text lines from file and convert them into a JSON array. Not using ConvertFrom-Json as PowerShell 2.0 doesn't support it.
    [array]$data = @(Get-Content -Path $netDataObject.localJSON -Raw | ConvertFrom-Json)
    #  Note if you really need PoSh 2.0 compatibility you can comment the line above, and uncomment the 4 lines below
    #  You will need TLS 1.2 setup, .NET 3.5, and may need some registry patches to accomplish those. More info here:
    #  https://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
    #  https://knowledge.digicert.com/quovadis/ssl-certificates/ssl-general-topics/how-to-enable-tls-1-2-on-windows-server-2008-r2
    #Add-Type -AssemblyName System.Web.Extensions
    #$jsonString = Get-Content -Path $localJSON -Raw
    #$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    #[array]$data = $serializer.DeserializeObject($jsonString)

    # process the data from the $data array
    $netDataObject.testURLs = @($data.array1)
    $certURL                = @($data.array2)
    $certArrayTemp          = @($data.array4)
    $expIssuerName          = @($data.array5)

    # array4 contains two different sets of info, even indices are subject, odd indices are issuer
    # The rest of the arrays are single sets of data, enjoy.
    for ($i = 0; $i -lt $certArrayTemp.Count-1; $i = $i + 2) {
        $tempCert = $(($certURL[$i/2] -replace '^https://', '') -replace '/.*', '')

        $netDataObject.certData += New-Object -TypeName PSObject -Property @{
            certURL       = $tempCert
            expIssuerName = $expIssuerName[$($i/2)]
            expSubject    = $certArrayTemp[$i]
            expIssuer     = $certArrayTemp[$i+1]
        }
    }

    # The data on github is purposely over-verbose for future use, so we strip extra characters.
    for ($i = 0; $i -lt $netDataObject.testURLs.Count; $i++) {
        $netDataObject.testURLs[$i] = $(($netDataObject.testURLs[$i] -replace '^https://', '') -replace '/.*', '')
    }
}

# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
function certTest {
    param ( [PSObject]$netDataObject )

    logger "-- Testing Certificate Validation --"
    $failCounter = 0
    $failURLs    = @()
    # for each URL, establish secure TCP connection and grab the certificate and subject lines to compare with known-good values.
    foreach ($singleCert in $($netDataObject.certData)) {
        $cleanURL = $singleCert.certURL
        $uri = ([uri]($cleanURL))
        $tcp = $null
        $ssl = $null
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $tcp.Connect("$uri", 443)
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(),$false,{$true})
            $ssl.AuthenticateAsClient($uri)
            $cert       = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
            $recSubject = $cert.Subject
            $recIssuer  = $cert.Issuer
            # retrieve a hashed/encrypted version of the certificate to log in case troubleshooting is required
            # Note: the 5 lines below must remain at their current indentation!
            $PEM = @"
-----BEGIN CERTIFICATE-----
$([System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), [System.Base64FormattingOptions]::InsertLineBreaks))
-----END CERTIFICATE-----
"@

            # Check for Subject match. No need for wildcards as these should all be static Huntress certs.
            if ($recSubject -eq $($singleCert.expSubject)) {
                logger "[Certificate subject validation successful for $cleanURL]"
            } else {
                logger "[FAILED: Subject validation. Certificate does not match for [$cleanURL] !]"
                logger "Subject that was returned: [$recSubject]"
                logger "Subject that was expected: [$($singleCert.expSubject)]"
                $failCounter++
                $netDataObject.countFails++
                $failURLs += $cleanURL
            }

            # Issuer can vary based on the specific server the script reaches. To compensate, we check for exact match then a wildcard match.
            if ($recIssuer -eq $($singleCert.expIssuer)) {
                logger "[Certificate issuer validation successful for $cleanURL]"
            } else {
                # Wildcard match compensates for big infrastructure where the leaf cert's might vary slightly
                if ($recIssuer -like "*$($singleCert.expIssuer)*") {
                    logger "Please note this was not an exact match, which is expected with big infrastructure."
                    logger "Issuer that was returned: [$recIssuer]"
                    logger "Issuer that was expected: [$($singleCert.expIssuer)]"
                } else { 
                    logger "[FAILED: Issuer validation. Certificate does not match for [$cleanURL] !]"
                    logger "Issuer that was returned: [$recIssuer]"
                    logger "Issuer that was expected: [$($singleCert.expIssuer)]"
                    logger "PEM that was received: $PEM"
                    $failCounter++
                    $netDataObject.countFails++
                    $failURLs += $cleanURL
                }
            }
        } catch {
            logger "Error: $($_.Exception.Message)"
            logger "[Error during certificate validation for '$cleanURL'!]"
            $failCounter++
            $netDataObject.countFails++
            $failURLs += $cleanURL
        } finally {
            if ($null -ne $ssl) {
                $ssl.Dispose()
            }
            $tcp.Close()
        }
    }
    # If we see any fails, print more info about those failures.
    if ($failCounter -gt 0) {
        foreach ($failURL in $failURLs) {
            echo "failURL - $failURL"
            certFail $failURL
        }
    }
    logger ""
}

# test outgoing port 443 connectivity to Huntress URLs
function tcpTest {
    param ( [PSObject]$netDataObject )

    logger "-- Verifying Huntress services can be reached --"
    foreach ($testURL in $netDataObject.testURLs) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.connect($testURL, 443)
            logger "[Connection to $testURL successful]"
        } catch {
            logger "WARNING, connectivity to Huntress URL's is being interrupted. You MUST open port 443 for $testURL in order for the Huntress agent to function."
            logger "Error: $($_.Exception.Message)"
            $netDataObject.countFails++
        } finally {
            $tcp.Close()
        }
    }
    logger ""
}


setNetworking
getLocalJSON $netDataObject
simpleTest $netDataObject
tcpTest $netDataObject
certTest $netDataObject

# --> this section marker is for internal use
if ($netDataObject.countFails -gt 0) {
    logger "[FAILED to connect to all Huntress services]"
    logger "------------------------ FAILED network test ----------------------------------"
} else {
    logger "[Successfully connected to Huntress services]"
    logger "---------------------- Network testing complete --------------------------------"
}
# <--
