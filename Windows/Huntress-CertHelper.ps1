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

$latestUpdate = "Huntress Certificate Helper, Windows PowerShell, last updated: October 27, 2026"
$Usage = "Usage examples:`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"microsoft.com`"`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"api.google.com`"`n" +
    "    powershell -executionpolicy bypass -f .\Huntress-CertHelper.ps1 `"https://www.huntress.com`""


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
        Write-Host "Failed to enable TLS 1.2, proper testing requires TLS 1.2 or higher for accurate results. Exiting..."
        Write-Host "$msg"
        throw $msg
    }
}


# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
function certTest {
    param ( [string]$URL )

    $uri = ([uri]($URL))
    $tcp = $null
    $ssl = $null
    try {
        # establish a TCP connection
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.Connect("$uri", 443)

        # get the stream of SSL data from the TCP connection
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(),$false,{$true})
        # Explicitly target TLS 1.2 or TLS 1.3, allowing the client to ignore cert collection issues
        $SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
        $ssl.AuthenticateAsClient($uri, $null, $SslProtocols, $false)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
        
        $spaceLength = 100
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
        $tcp.Close()
    }
}

if ($null -like $URL) {
    Write-Host $Usage -BackgroundColor "Black" -ForegroundColor "Magenta"
    Write-Host "No URL passed to the script, defaulting to testing Huntress.com" -BackgroundColor "Black" -ForegroundColor "Red"
    $URL = "huntress.com"
}
if ($URL -like "*//*") {
    $URL = @($URL -split "//")[1]
}

setNetworking
certTest $URL
