# Diagnostic script to help view certificates, which can help identify cert interception services and other cert issues. Run this script
# with the URL you want to test and the script will display the certificate owner and issuer. The owner is typically the company who
# owns the website, while the issuer is the certificate authority that approved the certificate. You may see slight variations in these
# entries, but if the company name(s) in the CN= and O= values varies then the variance is usually the source of cert interception. 
#
# In other words, if you're testing google.com and the Issuer or Owner comes back as "FortiNet", then "FortiNet" is the thing 
# intercepting certificates. 
#
# Note that you may need to test on different networks to establish a baseline or contact the website vendor, since the Owner will 
# usually vary wildly from the Issuer (unless it's a big tech company).

param (  [string]$URL  )

$testTimeout = 20  # number of seconds to wait for TCP connection to establish
$latestUpdate = "Huntress Certificate Helper, Windows PowerShell, last updated: October 28, 2026"
$Usage = "Usage examples:`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"microsoft.com`"`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"api.google.com`"`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"https://www.huntress.com`""


# Select a secure TLS protocol for the current PowerShell process.
function setNetworking {

    try {
        $ProtocolsSupported = [System.Enum]::GetValues([System.Net.SecurityProtocolType])
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
        Write-Host "Failed to enable TLS 1.2, proper testing requires TLS 1.2 or higher for accurate results. Exiting..."
        throw $msg
    }
}

# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
function certTest {
    param ( [string]$URL,
            [string]$testTimeout )

    $uri = ([uri]($URL))
    $tcp = $null
    $ssl = $null
    try {
        # establish a TCP connection
        $job = Start-Job -ScriptBlock {
            param ($uri)
            $tcp = New-Object Net.Sockets.TcpClient
            $tcp.Connect("$uri", 443)
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(),$false,{$true})
            $SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
            $ssl.AuthenticateAsClient($uri, $null, $SslProtocols, $false)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
            return $cert
        } -ArgumentList "$uri"

        $isJobComplete = Wait-Job $job -Timeout $testTimeout

        if ($isJobComplete) {
            $cert = Receive-Job $job
        } else {
            Write-Host "TCP SSL connection couldn't be established in $testTimeout seconds. Stopping test."
            Stop-Job $job
            Remove-Job $job -Force
            throw "Unable to establish TCP connection to $uri in $testTimeout seconds."
        }
        Remove-Job $job -Force

        if ($($cert.Subject.Length) -gt $($cert.Issuer.Length)) {
            $spaceLength = $($cert.Subject.Length) + 10
        } else {
            $spaceLength = $($cert.Issuer.Length) + 10
        }
        if ($spaceLength -lt 100) {
            $spaceLength = 100
        }
        $space = " " * ($spaceLength - 13)
        Write-Host "Certificate Owner:$space" -BackgroundColor "Black" -ForegroundColor "Green"
        $space = " " * ($spaceLength - $($cert.Subject.Length))
        Write-Host "     $($cert.Subject)$space" -BackgroundColor "Black" -ForegroundColor "Green"

        $space = " " * ($spaceLength - 14)
        Write-Host "Certificate Issuer:$space" -BackgroundColor "Black" -ForegroundColor "Green"
        $space = " " * ($spaceLength - $($cert.Issuer.Length))
        Write-Host "     $($cert.Issuer)$space" -BackgroundColor "Black" -ForegroundColor "Green"

    } catch {
        # Fully inspect the last error
        $Error[0].Exception | Format-List * -Force
        Write-Host "[Error during certificate validation for '$uri'!]" -BackgroundColor "Black" -ForegroundColor "Red"
    } finally {
        if ($null -ne $ssl) {
            $ssl.Dispose()
        }
        if ($null -ne $tcp) {
            $tcp.Close()
        }
    }
}


$user = [Security.Principal.WindowsIdentity]::GetCurrent();
if ((New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host ""
    Write-Host "                ##   ## ##    ## ###    ##  ######  ######  ####### ####### #######" -ForegroundColor Cyan
    Write-Host "                ##   ## ##    ## ####   ##    ##    ##   ## ##      ##      ##     " -ForegroundColor Cyan
    Write-Host "                ####### ##    ## ## ##  ##    ##    ######  #####   ####### #######" -ForegroundColor Cyan
    Write-Host "                ##   ## ##    ## ##  ## ##    ##    ##   ## ##           ##      ##" -ForegroundColor Cyan
    Write-Host "                ##   ##  ######  ##   ####    ##    ##   ## ####### ####### #######" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------------------------------------------------"
    Write-Host "           $latestUpdate"
    Write-Host "---------------------------------------------------------------------------------------------------------"
} else {
    throw "Warning: this script must be run as admin. Exiting."
}

if ($null -like $URL) {
    Write-Host $Usage -BackgroundColor "Black" -ForegroundColor "Magenta"
    Write-Host "No URL passed to the script, defaulting to testing Huntress.com" -BackgroundColor "Black" -ForegroundColor "Red"
    $URL = "huntress.com"
}
# remove https:// or http://
if ($URL -like "*//*") {
    $URL = @($URL -split "//")[1]
}
# remove any trailing forward slash /
if ($($URL[-1]) -eq "/") {
    $URL = $URL.Substring(0, $URL.length-1)
}

setNetworking
certTest $URL $testTimeout
