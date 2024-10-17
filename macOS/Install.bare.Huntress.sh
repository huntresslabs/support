#!/bin/sh

# This is a bare Huntress installer and should only be used if directed to by Huntress. This contains no logging or 
# error checking and isn't suitable for most cases.
#
# The preferred Bash installer for most cases can be found here:
# https://raw.githubusercontent.com/huntresslabs/deployment-scripts/refs/heads/main/Bash/InstallHuntress-macOS-bash.sh

actKey="PASTE YOUR ACCT KEY HERE!"
orgKey="CHANGE THIS TOO PLEASE"

if [ "$actKey" == "PASTE YOUR ACCT KEY HERE!" ]; then
  echo "You must hardcode your actKey and orgKey variables to use this script."
  echo "Please edit lines 9 and 10."
  exit 1
fi

echo "Version 11+ required, you have ${$(sw_vers -productVersion):0:2}"
url="https://huntress.io/script/darwin/"$actKey
sudo curl -w "%{http_code}" -L $url -o "/tmp/HuntressMacInstall.sh"
sudo /bin/bash "/tmp/HuntressMacInstall.sh" -a $actKey -o $orgKey -v
