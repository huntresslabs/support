# Suggested Usage:
#    .\Huntress.SIEM.Meraki.ps1 "$IPaddress"
# Simply replace $IPAddress with the IP address of the machine ingesting syslogs

# If user doesn't pass an IP default to loopback
if($args[0] -eq $null) {
    $agentIP = "127.0.0.1"
    Write-Host -BackgroundColor "red" -ForegroundColor "black"  "Warning: Sending to loopback, this won't test Windows firewall. Suggest sending from another machine to syslog collecting machine"
} else {
    $agentIP = $args[0]
    Write-Host "Sending SIEM data to $agentIP"
}

# Setting up the sample data to use today's date to make it easier to find in the portal
$unixTime = [int](Get-Date -UFormat %s -Millisecond 0)
$sampleData = "<134>1 $unixTime Stamford_FW01 security_event ids_alerted signature=1:300786:1 priority=1 timestamp=1726768963.282067 dhost=64:16:7F:D3:67:89 direction=ingress protocol=tcp/ip src=10.10.10.1:57478 dst=10.10.10.11:80 decision=blocked action=reset message: Huntress Meraki SIEM test"

# Create a UDP Client Object
$UDPCLient = New-Object System.Net.Sockets.UdpClient
$UDPCLient.Connect($agentIP, 514)
$Encoding = [System.Text.Encoding]::ASCII

# Convert into byte array representation
$ByteSyslogMessage = $Encoding.GetBytes($sampleData)

# Send the Message
$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null
