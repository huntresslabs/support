# This script tests that HTTPS connectivity can be established to the Huntress cloud and that communication is not intercepted (certificate mismatch)
# Output will be printed to console as well as saved in \Windows\temp\HuntressNetworkTest.txt

$latestUpdate = "Huntress Network Tester, Windows PowerShell, last updated: Mar 31, 2026"


$DebugLog = "c:\Windows\temp\huntress_network_test.log"
# adds time stamp to a message and then writes that to the log file
function LogMessage ($msg) {
	$TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
	Add-Content $DebugLog "$TimeStamp $msg"
    Write-Output "$TimeStamp $msg"
}
LogMessage $latestUpdate+"`n"

# Testing for blocked port 443
# Avoid "First Run Customize" blocking the testing by disabling it
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

# Force TLS 1.2 to avoid compatibility issues and ensure accurate testing (Huntress uses TLS 1.2+ only)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$file_name  = "96bca0cef10f45a8f7cf68c4485f23a4.txt"
$file_name2 = "96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:03:27Z&se=3026-03-06T09:18:27Z&spr=https&sv=2024-11-04&sr=b&sig=9gZx9aselhUP0SjeYvYSXD14S5QMpxkD1F0LMv0UBS0%3D"
$file_name3 = "96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:08:31Z&se=3026-03-06T09:23:31Z&spr=https&sv=2024-11-04&sr=b&sig=TgKJlXd7Q0ggdX5DN7DHfpXHUMLVZdujzZS5%2FcCWgIs%3D"
$file_name4 = "96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:04:57Z&se=3026-03-06T09:19:57Z&spr=https&sv=2024-11-04&sr=b&sig=TczBN0PJ8F375iD3xzgB0j%2BZLgJ6Q8LsS2IR0kuGPFQ%3D"
$file_name5 = "96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:05:16Z&se=3026-03-06T09:20:16Z&spr=https&sv=2024-11-04&sr=b&sig=wop9nqdC255Fbe84mlgz98cHUZ8Q1qFr%2BEOcyZsFEsM%3D"
$URLs = @(("https://update.huntress.io/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress.io/agent/connectivity/{0}" -f $file_name),
		  ("https://eetee.huntress.io/{0}"-f $file_name),
		  ("https://huntresscdn.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-installers.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-updates.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-uploads.s3.us-west-2.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-user-uploads.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-rio.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-survey-results.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://huntress-log-uploads.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
		  ("https://agent.huntress.io/agent/connectivity/{0}" -f $file_name),
		  ("https://update.huntress.io/agent/connectivity/{0}" -f $file_name),
		  ("https://huntressedrue2.blob.core.windows.net/huntress-installers/agent/connectivity/{0}" -f $file_name2),
		  ("https://huntresssiemue2.blob.core.windows.net/huntress-log-uploads/agent/connectivity/{0}" -f $file_name3),
		  ("https://huntresssharedue2.blob.core.windows.net/huntress-uploads/agent/connectivity/{0}" -f $file_name4))

LogMessage "Checking for HTTPS connectivity with Huntress cloud servers:"
foreach ($URL in $URLs) {
    $StatusCode = 0
    try {
        $Response = Invoke-WebRequest -Uri $URL -TimeoutSec 5 -ErrorAction Stop -ContentType "text/plain" -UseBasicParsing
        $StatusCode = $Response.StatusCode

        # Convert from bytes, if necessary
        if ($Response.Content.GetType() -eq [System.Byte[]]) {
            $StrContent = [System.Text.Encoding]::UTF8.GetString($Response.Content)
        } else {
            $StrContent = $Response.Content.ToString().Trim()
        }
        $StrContent = [string]::join("",($StrContent.Split("`n")))
    } catch {
        LogMessage "Error: $($_.Exception.Message)"
    }

    $shortURL = (($URL.Split('/'))[0..2] -join '/')
    if ($StatusCode -ne 200) {
        LogMessage = "WARNING, connectivity to Huntress URL's is being interrupted. You MUST open port 443 for $shortURL in order for the Huntress agent to function. Status code: $StatusCode"
    } elseif ( ! ($StrContent -eq "96bca0cef10f45a8f7cf68c4485f23a4")) {
        LogMessage = "WARNING, successful connection to Huntress URL, however, content did not match expected. Ensure no proxy or content filtering is preventing access!"
    } else {
        LogMessage "Connection succeeded to $shortURL"
    }
}
Write-Output "-----------------------------------------------------------------------------"

LogMessage "Testing for certificate interception/inspection/deep packet inspection"
$URLs = @("https://www.huntress.io", 
		  "https://huntresscdn.com", 
		  "https://huntressedrue2.blob.core.windows.net/huntress-installers/agent/connectivity/96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:03:27Z&se=3026-03-06T09:18:27Z&spr=https&sv=2024-11-04&sr=b&sig=9gZx9aselhUP0SjeYvYSXD14S5QMpxkD1F0LMv0UBS0%3D", 
		  "https://huntresssharedue2.blob.core.windows.net/huntress-uploads/agent/connectivity/96bca0cef10f45a8f7cf68c4485f23a4.txt?sp=r&st=2026-03-06T01:04:57Z&se=3026-03-06T09:19:57Z&spr=https&sv=2024-11-04&sr=b&sig=TczBN0PJ8F375iD3xzgB0j%2BZLgJ6Q8LsS2IR0kuGPFQ%3D")
foreach ($URL in $URLs) {
	if ($URL -eq "https://www.huntress.io") {
		$subject = "CN=*.huntress.io, O=Huntress Labs Inc., L=Ellicott City, S=Maryland, C=US"
		$issuer = "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US"
		$Connection = [System.Net.HttpWebRequest]::Create("$URL/agent/connectivity/96bca0cef10f45a8f7cf68c4485f23a4.txt")
	} elseif ($URL -eq "https://huntresscdn.com") {
		$subject = "CN=huntresscdn.com"
		$issuer  = "CN=WE1, O=Google Trust Services, C=US"
		$Connection = [System.Net.HttpWebRequest]::Create("$URL/agent/connectivity/96bca0cef10f45a8f7cf68c4485f23a4.txt")
	} else {
		$subject = "CN=*.blob.core.windows.net, O=Microsoft Corporation, L=Redmond, S=WA, C=US"
		$issuer  = "CN=Microsoft Azure RSA TLS Issuing CA 07, O=Microsoft Corporation, C=US"
		$Connection = [System.Net.HttpWebRequest]::Create($URL)
	}
	$Response = $Connection.GetResponse()
	$cert = $Connection.ServicePoint.Certificate
	$Response.Dispose()

	$shortURL = (($url.Split('/'))[0..2] -join '/')
	LogMessage "Checking cert for $shortURL"
	LogMessage "Subject value:  $($cert.Subject)"
	if ( $cert.Subject -eq $subject) {
		LogMessage "Certificate is correct!"
	} else {
		LogMessage "Expected value: $subject"
		LogMessage "Certificate does not match expected value. Possible DPI, certificate interception, or pinning of Huntress certificates."
	}

	LogMessage "Issuer: $($cert.Issuer)"
	if ( $cert.Issuer -eq $issuer) {
		LogMessage "Certificate is correct!"
	} else {
		LogMessage "Expected value: $issuer"
		LogMessage "Certificate does not match expected value. Possible DPI, certificate interception, or pinning of Huntress certificates. Issuer name is the likely source of certificate interception"
	}
	Write-Output ""
}
LogMessage "---------------------- Network testing complete --------------------------------"
