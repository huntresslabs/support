# This script tests that HTTPS connectivity can be established to the Huntress cloud and that communication is not intercepted (certificate mismatch)
# Output will be printed to console as well as saved in \Windows\temp\HuntressNetworkTest.txt
#
# Last Updated: Nov 12, 2025

$DebugLog = "c:\Windows\temp\huntress_network_test.log"

# adds time stamp to a message and then writes that to the log file
function LogMessage ($msg) {
	$TimeStamp = "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
	Add-Content $DebugLog "$TimeStamp $msg"
    Write-Output "$TimeStamp $msg"
}


# Testing for blocked port 443
# Avoid "First Run Customize" blocking the testing by disabling it
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

$file_name = "96bca0cef10f45a8f7cf68c4485f23a4.txt"
$URLs = @(("https://eetee.huntress.io/{0}"-f $file_name),
("https://huntress-installers.s3.us-east-1.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress-rio.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress-survey-results.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress-updates.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress-uploads.s3.us-west-2.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress-user-uploads.s3.amazonaws.com/agent/connectivity/{0}" -f $file_name),
("https://huntress.io/agent/connectivity/{0}" -f $file_name),
("https://huntresscdn.com/agent/connectivity/{0}" -f $file_name),
("https://update.huntress.io/agent/connectivity/{0}" -f $file_name))
LogMessage "Checking for HTTPS connectivity with Huntress cloud"

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

    if ($StatusCode -ne 200) {
        LogMessage = "WARNING, connectivity to Huntress URL's is being interrupted. You MUST open port 443 for $($URL) in order for the Huntress agent to function. Status code: $StatusCode"
    } elseif ( ! ($StrContent -eq "96bca0cef10f45a8f7cf68c4485f23a4")) {
        LogMessage = "WARNING, successful connection to Huntress URL, however, content did not match expected. Ensure no proxy or content filtering is preventing access!"
    } else {
        LogMessage "Connection succeeded to $($URL)"
    }
}


# Testing for certificate issues
$URLs = @("https://www.huntress.io", "https://huntresscdn.com")
foreach ($URL in $URLs) {
	if ($URL -eq "https://www.huntress.io") {
		$subject = "CN=*.huntress.io, O=Huntress Labs Inc., L=Ellicott City, S=Maryland, C=US"
		$issuer = "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US"
	} else {
		$subject = "CN=huntresscdn.com"
		$issuer  = "CN=WE1, O=Google Trust Services, C=US"
	}
	$Connection = [System.Net.HttpWebRequest]::Create("$URL/agent/connectivity/96bca0cef10f45a8f7cf68c4485f23a4.txt")
	$Response = $Connection.GetResponse()
	$cert = $Connection.ServicePoint.Certificate
	$Response.Dispose()
	Write-Output "`n"
	LogMessage "Checking cert for $URL"
	LogMessage "Subject value:  $($cert.Subject)"
	if ( $cert.Subject -eq $subject) {
		LogMessage "Certificate is correct!"
	} else {
		LogMessage "Expected value: $subject"
		LogMessage "Certificate does not match expected value. Possible DPI, certificate interception or pinning of Huntress certificates."
	}

	LogMessage "Issuer: $($cert.Issuer)"
	if ( $cert.Issuer -eq $issuer) {
		LogMessage "Certificate is correct!"
	} else {
		LogMessage "Expected value: $issuer"
		LogMessage "Certificate does not match expected value. Possible DPI, certificate interception or pinning of Huntress certificates. Issuer name is the likely source of certificate interception"
	}
}
