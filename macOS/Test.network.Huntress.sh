#!/bin/bash

# Tests a number of ways Huntress agents communicate with the Huntress portal
# Output is to standard out as well as the file represented by $DebugLog
# 
# <<< Bash version >>>

latestUpdate="Huntress Network Tester, macOS and Linux Bash, last updated May 4, 2026"


# adds time stamp to a message and then writes that to the log file
DebugLog="huntress_network_test.log"
dd=$(date "+%Y-%m-%d  %H:%M:%S")
logger() {
    echo "$*";
    echo "$dd -- $*" >> $DebugLog;
}
logger "-----------------------------------------------------------------------------"
logger $latestUpdate
logger "-----------------------------------------------------------------------------"

# for the summary, keeps track of failures for a conclusive singular pass/fail at the end
countFails=0

# retrieve a list of URLs to test from Huntress github
URL='https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json'
json="$(curl -fsSL --tlsv1.2 "$URL")"
testURLs=()
certURLs=()
expSubject=()
expIssuer=()
while IFS= read -r item; do
     [ -z "$item" ] && continue
     testURLs+=("$item")
done < <(echo "$json" | jq -r '.array1[] | select(length > 0)')
while IFS= read -r item; do
     [ -z "$item" ] && continue
     certURLs+=("$item")
done < <(echo "$json" | jq -r '.array2[] | select(length > 0)')
# even array indices are Subjects, odd are Issuer
count=0    
while IFS= read -r item; do
     [ -z "$item" ] && continue
     if (( $count % 2 == 0 )); then
          expSubject+=("$(echo "$item" | xargs)")
     else
          expIssuer+=("$(echo "$item" | xargs)")
     fi
     ((count++))
done < <(echo "$json" | jq -r '.array3[] | select(length > 0)')


# Simple test just to establish working DNS and basic internet connectivity
logger "-- Testing DNS resolution and port 80 connectivity --"
curlOutput="$(sudo curl -fsS --connect-timeout 5 --max-time 10 "https://huntress.io" 2>&1 | head -n 14 | tail -n 1)"
status=$?
if [ "$curlOutput" == "<title>Huntress Management Console</title>" ]; then
     logger "[DNS Resolution / port 80 connection successful]"
else
     logger "[FAILED: DNS and port 80 checks] $curlOutput"
     ((countFails++))
fi
logger ""


# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
logger "-- Testing Certificate Validation --"
certFailCounter=0
numEntries=${#certURLs[@]}
for (( i=0; i<numEntries; i++ )); do
     cleanURL=$(echo "${certURLs[i]}" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
     s_client==$(printf '\n' | openssl s_client -connect "${cleanURL}:443" -servername "${cleanURL}" 2> /dev/null < /dev/null )
     recIssuer=$(printf '%s\n' "$s_client" | openssl x509 -noout -issuer -nameopt compat | cut -d'/' -f2- | xargs)
     recSubject=$(printf '%s\n' "$s_client" | openssl x509 -noout -subject -nameopt compat | cut -d'/' -f2- | xargs)

     if [[ "$recSubject" == "${expSubject[i]}" ]]; then
          logger "[Certificate subject validation successful for $cleanURL]"
     else
          ((certFailCounter++))
          ((countFails++))
          logger "[FAILED: Subject validation. Certificate does not match for [$cleanURL] !]"
          logger "Subject that was returned: [$recSubject]"
          logger "Subject that was expected: [${expSubject[i]}]"
     fi

     if [[ "$recIssuer" == "${expIssuer[i]}" ]]; then
          logger "[Certificate issuer validation successful for $cleanURL]"
     else
          ((certFailCounter++))
          ((countFails++))
          logger "[FAILED: Issuer validation. Certificate does not match for [$cleanURL] !]"
          logger "Subject that was returned: [$recIssuer]"
          logger "Subject that was expected: [${expIssuer[i]}]"
     fi

done
if [[ "$certFailCounter" > 0 ]]; then
     logger ""
     logger "------------------------------------------------------------------------------------------------------------------------------"
     logger "The Subject/Issuer text above usually identifies if this is a DPI/cert interception issue, or a cert chain issue."
     logger "* If the returned SUBJECT does not contain 'Huntress' or 'Microsoft' in the text this is likely a DPI/cert interception issue."
     logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
     logger "* If the returned ISSUER does not contain 'DigiCert', 'Google', or 'Microsoft', this is likely a  DPI/cert interception issue."
     logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
     logger "* Otherwise this is likely a missing certificate chain. Check for pending OS updates, reboot, and try again."
     logger "------------------------------------------------------------------------------------------------------------------------------"
fi
logger ""


# test outgoing port 443 connectivity to Huntress URLs
logger "-- Verifying Huntress services can be reached --"
for i in "${!testURLs[@]}"; do
     cleanURL=$(echo "${testURLs[i]}" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
     nc=$(nc -zvw 5 "$cleanURL" 443 2>&1 | grep "succeeded")
     if [ -n "$nc" ]; then
          logger "[Connection to $cleanURL successful]"
     else
          logger "[FAILED: Connection to $cleanURL"
          ((countFails++))
     fi
done
logger ""

if [ "$countFails" -gt 0 ]; then
     logger "[FAILED to connect to all Huntress services]"
     logger "------------------------ FAILED network test ----------------------------------"
else
     logger "[Successfully connected to Huntress services]"
     logger "---------------------- Network testing complete --------------------------------"
fi
