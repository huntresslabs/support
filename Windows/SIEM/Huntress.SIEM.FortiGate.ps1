# Suggested running this from a machine on the same network as the syslog ingesting machine:
#    .\Huntress.SIEM.FortiGate.ps1 "$IPaddress"
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
$month = Get-Date -UFormat %b
$day   = (Get-Date).day
$sampleData = "<190>$month $day 01:23:45 dmi-fw101 CEF:0|Fortinet|Fortigate|v7.2.8|26001|event:system|2|deviceExternalId=FGT60FTK1234C123 FTNTFGTeventtime=1726768963263686912 FTNTFGTtz=-0400 FTNTFGTlogid=0100026001 cat=event:system FTNTFGTsubtype=system FTNTFGTlevel=information FTNTFGTvd=root FTNTFGTlogdesc=DHCP Ack log deviceInboundInterface=PNI_Guest FTNTFGTdhcp_msg=Ack FTNTFGTmac=4A:CC:9D:36:D6:93 FTNTFGTip=192.168.1.1 FTNTFGTlease=604800 dhost=N/A msg=Huntress FortiGate SIEM test"

# Create a UDP Client Object
$UDPCLient = New-Object System.Net.Sockets.UdpClient
$UDPCLient.Connect($agentIP, 514)
$Encoding = [System.Text.Encoding]::ASCII

# Convert into byte array representation
$ByteSyslogMessage = $Encoding.GetBytes($sampleData)

# Send the Message
$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null
