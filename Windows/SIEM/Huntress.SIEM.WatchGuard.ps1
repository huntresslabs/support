# Suggested Usage:
#    .\Huntress.SIEM.WatchGuard.ps1 "$IPaddress"
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
$sampleData = "<142>$month $day 01:23:45 EDGE-FW LEEF:1.0|WatchGuard|XTM|12.10.3.B694994|1AFF0024|serial=A01B999CCC111   policy=HTTP-proxy-00    disp=Allow  in_if=Private LAN   out_if=External    geo_dst=USA  src=192.168.100.106 srcPort=59938   dst=1.2.3.4    dstPort=80   icmpType=0 proto=tcp   proxy_act=Default-HTTP-Client   op=GET  dstname=1.2.3.4 arg=/test/test.txt    sent_bytes=93 rcvd_bytes=229   elapsed_time=0.202470 sec(s)    msg=Huntress WatchGuard SIEM test"

# Create a UDP Client Object
$UDPCLient = New-Object System.Net.Sockets.UdpClient
$UDPCLient.Connect($agentIP, 514)
$Encoding = [System.Text.Encoding]::ASCII

# Convert into byte array representation
$ByteSyslogMessage = $Encoding.GetBytes($sampleData)

# Send the Message
$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null
