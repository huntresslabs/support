#!/bin/bash

# Tests a number of ways Huntress agents communicate with the Huntress portal
# Output is to standard out as well as the file represented by $DebugLog
# 
# <<< macOS version >>>

DebugLog="huntress_network_test.log"

dd=$(date "+%Y-%m-%d  %H:%M:%S")
logger() {
    echo "$*";
    echo "$dd -- $*" >> $DebugLog;
}

logger "Huntress Network Tester, macOS Bash, last updated April 21, 2026"
logger ""
countFails=0

# #test connectivity to Huntress.io on port 80 - output should be <title>Huntress Management Console</title>
logger "-- Testing DNS resolution and port 80 connectivity"
curlOutput=$(sudo curl https://huntress.io -s | head -n 14 | tail -n 1)
if [ "$curlOutput" == "<title>Huntress Management Console</title>" ]; then
     logger "[DNS Resolution / port 80 connection successful]"
else
     logger "[FAILED: DNS and port 80 checks]"
     countFails++
fi
logger ""


#tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
#output should indicate the cert is for Huntress or Microsoft 
logger "-- Testing Certificate Validation --"
hash=("87:5B:E4:BB:1B:08:7F:57:3E:EB:4D:F0:C6:CB:81:1F:07:78:B0:E0:EF:9E:2F:31:84:EA:9F:2A:25:88:47:5C" "75:A9:87:63:3E:2C:C0:B8:98:4B:0B:02:45:AB:2C:E9:53:8F:CE:F6:63:D9:9A:93:21:DC:53:22:8A:EE:69:DE" "E8:56:CB:80:E1:A3:18:70:01:7C:B0:0B:58:65:1A:FB:70:6B:B9:30:7C:38:5B:FE:66:CA:9F:5E:06:E5:33:CE")
subj=("subject= /C=US/ST=Maryland/L=Ellicott City/O=Huntress Labs Inc./CN=*.huntress.io" "subject= /CN=huntresscdn.com" "subject= /C=US/ST=WA/L=Redmond/O=Microsoft Corporation/CN=*.blob.core.windows.net")
urls=("huntress.io" "huntresscdn.com" "huntressedrue2.blob.core.windows.net")

for i in "${!urls[@]}"; do
     sha256=$( openssl s_client -connect "${urls[i]}:443" -servername "${urls[i]}" 2> /dev/null < /dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d'=' -f2 )
     subject=$( openssl s_client -connect "${urls[i]}:443" -servername "${urls[i]}" 2> /dev/null < /dev/null | openssl x509 -noout -subject )
     if [[ "${hash[i]}" == "$sha256" ]]; then
          logger "[Certificate validation successful for ${urls[i]}]"
     else
          logger "[FAILED: Certificate validation. Hash value does not match!]"
          logger "Hash that was returned: $sha256"
          logger "Hash that was expected: ${hash[i]}"
          logger "Subject that was returned: $subject"
          logger "Subject that was expected: ${subj[i]}"
          countFails++
     fi
done
logger ""


#test outgoing port 443 connectivity to Huntress URLs
#output should indicate every URL connection succeeded
logger "-- Verifying Huntress services can be reached --"
for hostn in "update.huntress.io" "huntress.io" "eetee.huntress.io" "huntresscdn.com" "huntress-installers.s3.amazonaws.com" "huntress-updates.s3.amazonaws.com" "huntress-uploads.s3.us-west-2.amazonaws.com" "huntress-user-uploads.s3.amazonaws.com" "huntress-rio.s3.amazonaws.com" "huntress-survey-results.s3.amazonaws.com" "huntress-log-uploads.s3.amazonaws.com" "agent.huntress.io" "update.huntress.io" "huntressedrue2.blob.core.windows.net" "huntresssiemue2.blob.core.windows.net" "huntresssharedue2.blob.core.windows.net"; do
     nc=$(nc -z -v $hostn 443 2>&1 | grep "succeeded")
     if [ -n "$nc" ]; then
          logger "[Connection to $hostn successful]"
     else
          logger "[FAILED: Connection to $hostn]"
          countFails++
     fi
done
logger ""

if [ "$countFails" -gt 0 ]; then
     logger "[FAILED to connect to all Huntress services]"
else
     logger "[Successfully connected to Huntress services]"
fi
