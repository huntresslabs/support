#!/bin/bash

# Tests a number of ways Huntress agents communicate with the Huntress portal, essentially a TCP port 443 connection outbound and checks 
# for certificate interception/inspection services which will prevent the Huntress agent from communicating with the Huntress portal.
#
# This script is designed for use in all macOS and Linux distros/versions that Huntress supports, however some distros may be missing
# dependencies that Huntress uses in this script, primarily curl, jq, openssl, and nc.
# https://support.huntress.io/hc/en-us/articles/4410699983891-Supported-Operating-Systems-System-Requirements-Compatibility
#
# If the file URLdata.json is found and not more than 2 weeks old, use that file, otherwise the script downloads from github.
# So if your network blocks access to githubusercontent.com you'll need to keep the below file in the same directory as the script.
#    https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json

# If you want to change the JSON file location, uncomment and change one localJSONOverride variable below to your desired directory. 
# The location must be writable for the user who is running the script!
#     Suggested locations:
# localJSONOverride="/var/root/"
# localJSONOverride="/root/"

# --> this section marker is for internal use 
latestUpdate="Huntress Network Tester: macOS and Linux Bash, last updated Sept 24, 2026"
DebugLog="huntress_network_test.log"

# adds time stamp to a message and then writes that to the log file
dd=$(date "+%Y-%m-%d  %H:%M:%S")
logger() {
    echo "$*";
    echo "$dd -- $*" >> $DebugLog;
}

# captures script exit and removes temp folder if it was created
function trapFunction {
     if [[ "$tempDIRCreated" ]]; then
          rm -rf "$localJSONOverrideDIR"
          logger "Cleaning up $localJSONOverrideDIR..."
     fi
}
trap trapFunction EXIT

logger "-----------------------------------------------------------------------------"
logger $latestUpdate
logger "-----------------------------------------------------------------------------"

# Simple test just to establish working DNS and basic internet connectivity
function simpleTest {
     logger "-- Testing DNS resolution and port 443 connectivity --"
     curlOutput="$(sudo curl -fsS --connect-timeout 5 --max-time 10 "https://huntress.io" 2>&1 | head -n 20 )"
     if [[ "$curlOutput" == *"<title>Huntress Management Console</title>"* ]]; then
          logger "[DNS Resolution / port 443 connection successful]"
     else
          logger "[FAILED: DNS and port 443 checks] $curlOutput"
          ((countFails++))
     fi
     logger ""
}

# Exit the script with error if a required dependency is missing
function checkDependency {
     tools=("curl" "jq" "openssl" "nc")
     for tool in "${tools[@]}"; do
          if [ -z "$tool" ]; then
               logger "Error retrieving install status of curl, jq, openssl, or nc! $tool"
          else
               if ! command -v $tool &> /dev/null; then
                    logger "Error: $tool is not installed and is required to run this script! You may need to"
                    logger "install this using your package manager. Here are some suggestions:"
                    logger "macOS:               brew install $tool"
                    logger "Debian/Ubuntu:       sudo apt install $tool"
                    logger "CentOS/Fedora/RHEL:  sudo dnf install $tool"
                    if [ "$tool" == "jq" ]; then
                         logger "** Please note the jq tool in CentOS/RHEL may require EPEL first! **"
                    fi
                    logger "SUSE:                sudo zypper install $tool"
                    logger "If the above commands don't work for your distro, please refer to your distro's support team or their documentation."
                    exit 1
               fi
          fi
     done
}
# <--------------------------------------------------------------------------------------

# How old (in days) the local JSON can be before it's ignored. 14 days is suggested.

# Setup some variables
gitURL='https://raw.githubusercontent.com/huntresslabs/support/refs/heads/main/URLdata.json'
scriptDIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
localJSON="$scriptDIR/URLdata.json"  # from the same working directory as the script
altJSON="/tmp/URLdata.json"          # alternate location if current working directory is inaccessible or is missing the JSON file
countFails=0                         # total number of network tests that failed (including cert fails)
certFailCounter=0                    # total number of certificate tests that failed
gracePeriodForJSON=14                # number of days old the local JSON can be before it's ignored
declare -a testURLs=()               # the URLs to test TCP connectivity
declare -a certURLs=()               # the URLs to test certificate interception
declare -a expIssuer=()              # the expected issuer (owner of the server certificate)
declare -a expSubject=()             # the expected subject (leaf certificate)
declare -a expIssuerName=()          # used for wildcard matching


# If the local JSON file exists and was modified less than 14 days ago, skip downloading from github
function getLocalJSON {
     # alternate file location override
     if ! [[ -z "$localJSONOverride" ]]; then
          localJSON="${localJSONOverride}URLdata.json"
     fi

     # Symbolic links could potentially give a user limited access to a directory they normally can't access.
     # The script will exit if it can't find a non-symlink file.
     if [ -L "$localJSON" ]; then
          if [ -L "$altJSON" ]; then
               logger "WARNING: Both JSON files are symbolic links. This is not recommended for security reasons. Exiting!"
               exit 1
          else
               localJSON=$altJSON
               logger "Local JSON is a symbolic link, using alternate location $altJSON."
          fi
     fi

     # look for local JSON file
     if [[ -f "$localJSON" ]]; then
          if [[ $(find "$localJSON" -type f -mtime -"$gracePeriodForJSON" -print) ]]; then
               lastWrite="$(date -r "$localJSON" '+%Y-%m-%d %H:%M:%S %Z')"
               logger "Using $localJSON from $lastWrite"
               getJSON false
          else
               logger "Local JSON file is stale, downloading new version from github"
               getJSON true
          fi
     # if local JSON isn't found, use alternate
     elif [[ -f "$altJSON" ]]; then
          localJSON=$altJSON
          if [[ $(find "$localJSON" -type f -mtime -"$gracePeriodForJSON" -print) ]]; then
               lastWrite="$(date -r "$localJSON" '+%Y-%m-%d %H:%M:%S %Z')"
               logger "Using alternate JSON file ($localJSON) from $lastWrite"
               getJSON false
          else
               logger "Alternate JSON file ($localJSON) too old to safely use, attempting to retrieve from github"
               getJSON true
          fi
     # no existing files found, look for a writable directory
     else 
          # script directory is writable, download fresh copy from github 
          if [[ -w "$scriptDIR" ]]; then
               logger "JSON file not found, using $scriptDIR"
               getJSON true
          # alternate directory is writable, download fresh copy from github to alternate location
          elif [[ -w "/tmp/" ]]; then
               logger "JSON file not found, script directory not writable, using $altJSON"
               localJSON=$altJSON
               getJSON true
          # else exit the script with error
          else
               logger "Unable to write to either local or alternate JSON files:"
               logger "$localJSON"
               logger "$altJSON"
               exit 1
          fi
     fi
}

# Download a JSON from github to a local file (represented by $localJSON), then process that file into arrays.
function getJSON {
     local downloadFromGithub="${1:?Error: downloadFromGithub variable is required.}"

     # retrieve URLs, cert Issuer, and cert Subject from Huntress github
     if $downloadFromGithub; then
          curl -fsSL --tlsv1.2 -o "$localJSON" "$gitURL"
          if [ $? -ne 0 ]; then
               logger "Unable to connect to github, if you can't allow connections to githubusercontent.com then download this file and save it in same DIR as this script."
               logger "$gitURL"
               exit 1
          else 
               logger "Download successful from github!"
               logger
          fi
     fi
     if ! [ -f "$localJSON" ]; then
          logger "Unable to find $localJSON"
          exit 1
     fi

     # Splitting the JSON file into several arrays
     while IFS= read -r item; do
          [ -z "$item" ] && continue
          testURLs+=($(printf "%s\n" "$item" | sed -e 's|^[^/]*//||' -e 's|/.*$||'))
     done < <(cat "$localJSON" | jq -r '.array1[] | select(length > 0)')
     while IFS= read -r item; do
          [ -z "$item" ] && continue
          certURLs+=($(printf "%s\n" "$item" | sed -e 's|^[^/]*//||' -e 's|/.*$||'))
     done < <(cat "$localJSON" | jq -r '.array2[] | select(length > 0)')
     # even array indices are Subjects, odd are Issuer. 
     count=0    
     while IFS= read -r item; do
          [ -z "$item" ] && continue
          if (( $count % 2 == 0 )); then
               expSubject+=("$(echo "$item" | xargs)")
          else
               expIssuer+=("$(echo "$item" | xargs)")
          fi
          ((count++))
     done < <(cat "$localJSON" | jq -r '.array3[] | select(length > 0)')
     while IFS= read -r item; do
          [ -z "$item" ] && continue
          expIssuerName+=("$item")
     done < <(cat "$localJSON" | jq -r '.array5[] | select(length > 0)')

     # If the data wasn't ingested into the arrays, exit with error (likely a corrupted JSON download)
     if [[ ${#testURLs[@]} -eq 0 || ${#certURLs[@]} -eq 0 || ${#expSubject[@]} -eq 0 || ${#expIssuer[@]} -eq 0 || ${#expIssuerName[@]} -eq 0 ]]; then
          logger "Error reading data from JSON file. Delete the local JSON file and try again."
          exit 1
     fi
}

# tests that the expected certificates are not intercepted. If the expected cert is not returned the agent will not function.
function certTest {
     logger "-- Testing Certificate Validation --"
     declare -a failURLs=()
     for i in "${!certURLs[@]}"; do
          cleanURL=${certURLs[i]}
          # there is no cross-platform timeout command, so attempt to use timeout, perl, or gtimeout before defaulting to no timeout (with warning)
          if command -v timeout >/dev/null 2>&1; then
               s_client=$(timeout 5 openssl s_client -connect "${cleanURL}:443" -servername "${cleanURL}" </dev/null 2>/dev/null)
          elif command -v perl >/dev/null 2>&1; then
               s_client=$(perl -e 'alarm 5; exec @ARGV' openssl s_client -connect "${cleanURL}:443" -servername "${cleanURL}" </dev/null 2>/dev/null)
          elif command -v gtimeout >/dev/null 2>&1; then
               s_client=$(gtimeout 5 openssl s_client -connect "${cleanURL}:443" -servername "${cleanURL}" </dev/null 2>/dev/null)
          else
               logger "Warning: Unable to find an appropriate 'timeout' library. Using openssl without a timer, it's rare but possible for this to hang!"
               s_client=$(printf '\n' | openssl s_client -connect "${cleanURL}:443" -servername "${cleanURL}" 2> /dev/null < /dev/null )
          fi

          PEM=$(printf '%s\n' "$s_client" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')
          recIssuer=$(printf '%s\n' "$s_client" | openssl x509 -noout -issuer -nameopt compat | cut -d'/' -f2- | xargs)
          recSubject=$(printf '%s\n' "$s_client" | openssl x509 -noout -subject -nameopt compat | cut -d'/' -f2- | xargs)

          # abort install if certificates can't be retrieved
          if [[ -z $recSubject || -z $recIssuer ]]; then
               logger "WARNING: Unable to retrieve certificate data! Exiting."
               exit 1
          fi

          if [[ "$recSubject" == "${expSubject[i]}" ]]; then
               logger "[Certificate subject validation successful for $cleanURL]"
          else
               ((certFailCounter++))
               ((countFails++))
               failURLs+=($cleanURL)
               logger "[FAILED: Subject validation. Certificate does not match for [$cleanURL] !]"
               logger "Subject that was returned: [$recSubject]"
               logger "Subject that was expected: [${expSubject[i]}]"
               logger "PEM that was received: $PEM"
          fi

          # Issuer can vary based on the specific server the script reaches. To compensate, we check for exact match then a wildcard match.
          if [[ "$recIssuer" == "${expIssuer[i]}" ]]; then 
               logger "[Certificate issuer validation successful for $cleanURL]"
          else
               if [[ "$recIssuer" == *"${expIssuerName[i]}"* ]]; then
                    logger "Please note this was not an exact match, which is expected with big infrastructure."
                    logger "Issuer that was returned: [$recIssuer]"
                    logger "Issuer that was expected: [${expIssuer[i]}]"
               else
                    ((certFailCounter++))
                    ((countFails++))
                    failURLs+=($cleanURL)
                    logger "[FAILED: Issuer validation. Certificate does not match for [$cleanURL] !]"
                    logger "Issuer that was returned: [$recIssuer]"
                    logger "Issuer that was expected: [${expIssuer[i]}]"
                    logger "PEM that was received: $PEM"
               fi
          fi
     done
     # list every cert failure so the appropriate DPI system can be adjusted
     if [[ "$certFailCounter" > 0 ]]; then
          for i in "${!failURLs[@]}"; do
               certFail "${failURLs[i]}"
          done
     fi
     logger ""
}

# test outgoing port 443 connectivity to Huntress URLs
function tcpTest {
     logger "-- Verifying Huntress services can be reached --"
     for i in "${!testURLs[@]}"; do
          cleanURL=${testURLs[i]}
          if nc -zvw 5 "$cleanURL" 443 > /dev/null 2>&1; then
              logger "[Connection to $cleanURL successful]"
          else
              logger "[FAILED: Connection to $cleanURL"
               ((countFails++))
          fi
     done
     logger ""
}

# Helper function to print lengthy error/instructional message
function certFail {
    # If $1 parameter is missing, prints the message and exits the script
    local cleanURL="${1:?Error: cleanURL variable is required.}"
    logger "------------------------------------------------------------------------------------------------------------------------------"
    logger "The Subject/Issuer text above usually identifies if this is a DPI/cert interception issue, or a cert chain issue."
    logger "* If the returned SUBJECT does not contain 'Huntress' or 'Microsoft' in the text this is likely a DPI/cert interception issue."
    logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
    logger "* If the returned ISSUER does not contain 'DigiCert', 'Google', or 'Microsoft', this is likely a  DPI/cert interception issue."
    logger "      You'll need to add an exclusion for the certificate for this URL in your DPI/cert interception service: $cleanURL"
    logger "* Otherwise this is likely a missing certificate chain. Check for pending OS updates, reboot, and try again."
    logger "------------------------------------------------------------------------------------------------------------------------------"
}

# Creates a temp directory if the file storage location is unsafe 
function useTempDIR {
     logger "Caution: Running from root directory is not recommended, using temporary directory"
     localJSONOverrideDIR=$(mktemp -d "${TMPDIR:-/var/tmp}/huntress.XXXXXX") || {
          logger "WARNING: Unable to create a private temporary directory in /var/tmp/!"
          logger "WARNING: No safe place to store JSON file found, exiting!"
          exit 1
     }
     tempDIRCreated=true
     logger "Successfully created $localJSONOverrideDIR directory!"
     # ensure temp directory is only writable by admins
     chmod 700 "$localJSONOverrideDIR"
     localJSONOverride="$localJSONOverrideDIR/"
}

# if the script is ran from the root directory and there isn't a local override, use a temp directory
if [[ "$scriptDIR" == "/" && -z "$localJSONOverride" ]]; then 
     useTempDIR
# if the override is the root directory, use a temp directory
elif [[ "$localJSONOverride" == "/" ]]; then
     useTempDIR
fi

checkDependency
getLocalJSON
simpleTest
tcpTest
certTest

# --> this section marker is for internal use
if [ "$countFails" -gt 0 ]; then
     logger "[FAILED to connect to all Huntress services]"
     logger "------------------------ FAILED network test ----------------------------------"
else
     logger "[Successfully connected to Huntress services]"
     logger "---------------------- Network testing complete --------------------------------"
fi
# <--------------------------------------------------------------------------------------
