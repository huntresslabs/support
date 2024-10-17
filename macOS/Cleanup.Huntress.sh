#!/bin/sh

help() {
    cat<<EOF
Usage: sudo sh ./Cleanup.Huntress.sh

This script will clean up an existing macOS agent installation without uninstalling it in the portal. The purpose 
is to clean a system for installation of a new macOS agent as part of a manual upgrade. This may be necessary 
when breaking changes are made or when directed to use this by Huntress.

This is not an uninstaller! If you want to uninstall you should use:
sudo sh ./Applications/Huntress.app/Contents/Scripts/Uninstall.sh

EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            help && exit 1
            ;;
        *)
            shift
            ;;
    esac
done

if [ "$(id -u)" != 0 ];
then
    echo This script must be run with sudo
    echo Usage: sudo sh ./HuntressCleanup.sh
    exit 1
fi

echo Stopping and removing any Huntress services
for service in HuntressAgent HuntressUpdater
do
    if [ -f "/Library/LaunchDaemons/com.huntress.${service}.plist" ]; then
        launchctl unload "/Library/LaunchDaemons/com.huntress.${service}.plist"
        killall "${service}"
        rm -f "/Library/LaunchDaemons/com.huntress.${service}.plist"
    fi
done

echo Removing Huntress data and configurations
rm -rf /Library/Application\ Support/Huntress

echo Removing Huntress
rm -rf /Applications/HuntressAgent.app
rm -rf /Applications/Huntress.app

pkgutil --forget com.huntresslabs.pkg.agent
