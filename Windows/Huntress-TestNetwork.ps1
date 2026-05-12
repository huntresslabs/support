# Tests a number of ways Huntress agents communicate with the Huntress portal
# Output is to standard out as well as the file represented by $DebugLog
# 
# <<< PowerShell version >>>

$latestUpdate = "Huntress Network Tester, Windows PowerShell, last updated: May 11, 2026 (release B)"


# adds time stamp to a message and then writes that to the log file
$DebugLog = "c:\Windows\temp\huntress_network_test.log"
function logger ($msg) {
	$TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
	Add-Content $DebugLog "$TimeStamp $msg"
    Write-Output "$msg"
}
logger "-----------------------------------------------------------------------------"
logger $latestUpdate
logger "-----------------------------------------------------------------------------"

# for the summary, keeps track of failures for a conclusive singular pass/fail at the end
$countFails=0

# Avoid "First Run Customize" blocking the testing by disabling it
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
# Force TLS 1.2 to avoid compatibility issues and ensure accurate testing (Huntress uses TLS 1.2+ only)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    logger "Failed to enable TLS 1.2, Huntress requires TLS 1.2 or higher for security reasons."
    exit 1
}

# retrieve URLs, cert Issuer, and cert Subject from Huntress github
$URL = 'https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json'
try {
    $data = Invoke-RestMethod -Uri $URL -UseBasicParsing -ErrorAction Stop
} catch {
    logger "Fallback using WebClient (still uses TLS 1.2)"
    $wc = New-Object System.Net.WebClient
    $wc.Headers['User-Agent'] = 'HuntressSupportScript'
    $jsonString = $wc.DownloadString($URL)
    $data = $jsonString | ConvertFrom-Json
}
# process the data from github
$data = (Invoke-WebRequest -Uri $URL -UseBasicParsing -ErrorAction Stop).Content | ConvertFrom-Json
$testURLs      = @($data.array1)
$certURLs      = @($data.array2)
$certTemp      = @($data.array4)
$expIssuerName = @($data.array5)
$expSubject    = @()
$expIssuer     = @()
# array4 contains two different sets of info, even indices are subject, odd indices are issuer
for ($i = 0; $i -lt $certTemp.Count; $i++) {
    if ($i % 2 -eq 0) {
        $expSubject += $certTemp[$i]
    } else {
        $expIssuer += $certTemp[$i]
    }
}


# Simple test just to establish working DNS and basic internet connectivity
logger "-- Testing DNS resolution and port 80 connectivity --"
try {
    $pageOutput = $(Invoke-WebRequest "https://huntress.io" -UseBasicParsing)
    if ($pageOutput.StatusCode -eq 200) {
        $pageOutput = $($pageOutput.Content) | Select-Object -First 14 | Select-Object -Last 1
        $startIndex = $pageOutput.IndexOf("<title>")
        if ($startIndex -ne -1) {
            $contentStart = $startIndex + 7
            $result = $pageOutput.Substring($contentStart, 27)
            logger "[DNS Resolution / port 80 connection successful]"
        } else {
            logger "The tag '<title>' was not found."
            $countFails++
        }
    } else {
        logger "[FAILED: DNS and port 80 checks]"
        logger "Output: $pageOutput"
        $countFails++
    }
} catch {
    logger "Error interacting with Invoke-WebRequest: $_"
    $countFails++
}
logger ""



# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
logger "-- Testing Certificate Validation --"
$failCounter = 0
for ($i = 0; $i -lt $certURLs.Count; $i++) {
    $cleanURL = ($certURLs[$i] -replace '^https://', '') -replace '/.*',''
    $uri = ([uri]$cleanURL)
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect("$uri", 443)
    $ssl = New-Object Net.Security.SslStream($tcp.GetStream(),$false,{$true})
    $ssl.AuthenticateAsClient($uri)
    $cert       = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
    $recSubject = $cert.Subject
    $recIssuer  = $cert.Issuer
    # retrieve a hashed/encrypted version of the certificate to log in case troubleshooting is required
    $PEM = @"
-----BEGIN CERTIFICATE-----
$([System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), [System.Base64FormattingOptions]::InsertLineBreaks))
-----END CERTIFICATE-----
"@

    if ($recSubject -eq $expSubject[$i]) {
        logger "[Certificate subject validation successful for $cleanURL]"
    } else {
        logger "[FAILED: Subject validation. Certificate does not match for [$cleanURL] !]"
        logger "Subject that was returned: [$recSubject]"
        logger "Subject that was expected: [$($expSubject[$i])]"
        $failCounter++
        $countFails++
    }

    # Issuer can vary based on the specific server the script reaches. To compensate, we check for exact match then a wildcard match.
    if ($recIssuer -eq $expIssuer[$i]) {
        logger "[Certificate issuer validation successful for $cleanURL]"
    } else {
		if ($recIssuer -like "*$($expIssuerName[$i])*") {
            logger "Please note this was not an exact match, which is expected with big infrastructure."
            logger "Subject that was returned: [$recIssuer]"
            logger "Subject that was expected: [$($expIssuer[$i])]"
        } else { 
            logger "[FAILED: Issuer validation. Certificate does not match for [$cleanURL] !]"
            logger "Subject that was returned: [$recIssuer]"
            logger "Subject that was expected: [$($expIssuer[$i])]"
            logger "PEM that was received: $PEM"
            $failCounter++
            $countFails++
        }
    }
    $ssl.Dispose()
    $tcp.Close()
}
if ($failCounter -gt 0) {
     logger ""
     logger "------------------------------------------------------------------------------------------------------------------------------"
     logger "The Subject/Issuer text above usually identifies if this is a DPI/cert interception issue, or a cert chain issue."
     logger "* If the returned SUBJECT does not contain 'Huntress' or 'Microsoft' in the text this is likely a DPI/cert interception issue."
     logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
     logger "* If the returned ISSUER does not contain 'DigiCert', 'Google', or 'Microsoft', this is likely a  DPI/cert interception issue."
     logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
     logger "* Otherwise this is likely a missing certificate chain. Check for pending OS updates, reboot, and try again."
     logger "------------------------------------------------------------------------------------------------------------------------------"
}
logger ""

 
# test outgoing port 443 connectivity to Huntress URLs
logger "-- Verifying Huntress services can be reached --"
foreach ($testURL in $testURLs) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $cleanURL = $($testURL -replace '^https://', '') -replace '/.*',''
        $tcp.connect($cleanURL, 443)
        logger "[Connection to $cleanURL successful]"
    } catch {
        logger = "WARNING, connectivity to Huntress URL's is being interrupted. You MUST open port 443 for $cleanURL in order for the Huntress agent to function."
        logger "Error: $($_.Exception.Message)"
        $countFails++
    } finally {
        $tcp.Close()
    }
}
logger ""

if ($countFails -gt 0) {
    logger "[FAILED to connect to all Huntress services]"
    logger "------------------------ FAILED network test ----------------------------------"
} else {
    logger "[Successfully connected to Huntress services]"
    logger "---------------------- Network testing complete --------------------------------"
}
