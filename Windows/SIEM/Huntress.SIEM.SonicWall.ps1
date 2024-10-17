# Suggested Usage:
#    .\Huntress.SIEM.SonicWall.ps1 "$IPaddress"
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
$year  = (Get-Date).year
$month = (Get-Date).month
$day   = (Get-Date).day
$sampleData = "<134>  id=firewall sn=00B00000000A time=""$year-$month-$day 01:23:45"" fw=1.2.3.72 pri=6 c=1024 m=537 msg=""Huntress SonicWall SIEM test"" app=2 n=117201470 src=10.10.10.4:53:X7 dst=1.2.3.4:12295:X7 proto=udp/dns sent=525 spkt=1"

# Create a UDP Client Object
$UDPCLient = New-Object System.Net.Sockets.UdpClient
$UDPCLient.Connect($agentIP, 514)
$Encoding = [System.Text.Encoding]::ASCII

# Convert into byte array representation
$ByteSyslogMessage = $Encoding.GetBytes($sampleData)

# Send the Message
$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null
