#!/bin/bash

# Tests a number of ways Huntress agents communicate with the Huntress portal
# Output is to standard out as well as the file represented by $DebugLog
#
# <<< Linux version >>>

DebugLog="huntress_network_test.log"

dd=$(date "+%Y-%m-%d  %H:%M:%S")
logger() {
    echo "$*";
    echo "$dd -- $*" >> $DebugLog;
}

logger "Huntress Network Tester, Linux Bash, last updated Nov 17, 2025"
logger ""

#test connectivity to Huntress.io on port 80 - output should be <title>Huntress Management Console</title>
logger "-- Testing DNS resolution and port 80 connectivity"
curlOutput=$(sudo curl https://huntress.io -s)
if [[ "$curlOutput" == *"<title>Huntress Management Console</title>"* ]]; then
     logger "[DNS Resolution / port 80 connection successful]"
else
     logger "[FAILED: DNS and port 80 checks]"
fi
logger ""

#tests that the Huntress certificate is not intercepted. If the Huntress cert is not returned the agent will not function.
#output should indicate the cert is for Huntress (should be the first entry, begins with 0)
logger "-- Testing Certificate Validation --"
cert=$( openssl s_client -connect huntress.io:443 -servername huntress.io 2> /dev/null < /dev/null | head | grep "Huntress" )
issuer=$( openssl s_client -connect huntress.io:443 -servername huntress.io 2> /dev/null < /dev/null | head | grep "1 s:/C=US" )
if [[ "$cert" == " 0 s:/C=US/ST=Maryland/L=Ellicott City/O=Huntress Labs Inc./CN=*.huntress.io" && "$issuer" == " 1 s:/C=US/O=DigiCert Inc/CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1" ]]; then
     logger "[Certificate validation successful]"
else
     logger "[FAILED: Certificate validation]"
     logger "Certificate that was returned: $cert $issuer"

fi
logger ""

#test outgoing port 443 connectivity to Huntress
#output should indicate every URL connection succeeded
countFails=0
logger "-- Verifying Huntress services can be reached --"
for hostn in "update.huntress.io" "huntress.io" "eetee.huntress.io" "eetee.huntresscdn.com" "huntresscdn.com" "huntress-installers.s3.amazonaws.com" "huntress-updates.s3.amazonaws.com" "huntress-uploads.s3.us-west-2.amazonaws.com" "huntress-user-uploads.s3.amazonaws.com" "huntress-rio.s3.amazonaws.com" "huntress-survey-results.s3.amazonaws.com" "huntress-log-uploads.s3.amazonaws.com"; do
     nc=$(nc -z -v $hostn 443 2>&1 | grep "succeeded")
     if [ -n "$nc" ]; then
          logger "[Connection to $hostn successful]"
     else
          logger "[FAILED: Connection to $hostn]"
          countFails++
     fi
done
if [ "$countFails" -gt 0 ]; then
     logger "[FAILED to connect to all Huntress services]"
else
     logger "[Successfully connected to Huntress services]"
fi
