#!/bin/bash

# Tests a number of ways Huntress agents communicate with the Huntress portal
# Output is to standard out as well as the file huntress_network_test.log
# 
# <<< macOS version >>> 

#test connectivity to Huntress.io on port 80 - output should be <title>Huntress Management Console</title>
echo "-- Testing DNS resolution and port 80 connectivity" | tee -a huntress_network_test.log 
curlOutput=$(sudo curl https://huntress.io -s | head -n 14 | tail -n 1)
if [ "$curlOutput" == "<title>Huntress Management Console</title>" ]; then
     echo "[DNS Resolution / port 80 connection successful]" | tee -a huntress_network_test.log 
else
     echo "[FAILED: DNS and port 80 checks]" | tee -a huntress_network_test.log 
fi
echo "" | tee -a huntress_network_test.log 

#tests that the Huntress certificate is not intercepted. If the Huntress cert is not returned the agent will not function.
#output should indicate the cert is for Huntress (should be the first entry, begins with 0)
echo "-- Testing Certificate Validation --" | tee -a huntress_network_test.log 
cert=$( openssl s_client -connect huntress.io:443 -servername huntress.io 2> /dev/null < /dev/null | head | grep "Huntress" ) 
if [ "$cert" == " 0 s:/C=US/ST=Maryland/L=Ellicott City/O=Huntress Labs Inc./CN=*.huntress.io" ]; then
     echo "[Certificate validation successful]" | tee -a huntress_network_test.log 
else
     echo "[FAILED: Certificate validation]" | tee -a huntress_network_test.log 
     echo "$cert"

fi
echo ""  | tee -a huntress_network_test.log 

#test outgoing port 443 connectivity to Huntress
#output should indicate every URL connection succeeded
countFails=0
echo "-- Verifying Huntress services can be reached --" | tee -a huntress_network_test.log 
for hostn in "update.huntress.io" "huntress.io" "eetee.huntress.io" "huntress-installers.s3.amazonaws.com" "huntress-updates.s3.amazonaws.com" "huntress-uploads.s3.us-west-2.amazonaws.com" "huntress-user-uploads.s3.amazonaws.com" "huntress-rio.s3.amazonaws.com" "huntress-survey-results.s3.amazonaws.com"; do
     nc=$(nc -z -v $hostn 443 2>&1 | grep "succeeded")
     if [ -n "$nc" ]; then
          echo "[Connection to $hostn successful]" | tee -a huntress_network_test.log 
     else
          echo "[FAILED: Connection to $hostn]" | tee -a huntress_network_test.log 
          countFails++
     fi 
done
if [ "$countFails" -gt 0 ]; then
     echo "[FAILED to connect to all Huntress services]" | tee -a huntress_network_test.log 
else
     echo "[Successfully connected to Huntress services]" | tee -a huntress_network_test.log 
fi
