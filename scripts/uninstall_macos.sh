#!/usr/bin/env bash
set -euo pipefail

# Cerberus Network Sentinel — Complete macOS Clean Uninstaller
# Wipes all databases, scan history, privileged helper tools, and system privileges.

echo "==> Cerberus Sentinel macOS Clean Uninstaller"

# 1. Terminate running application instances
echo "--> Stopping Cerberus processes..."
killall cerberus 2>/dev/null || true
killall cerberus-desktop 2>/dev/null || true

# 2. Remove application bundle
if [ -d "/Applications/Cerberus.app" ]; then
  echo "--> Removing /Applications/Cerberus.app..."
  rm -rf "/Applications/Cerberus.app"
elif [ -d "/Applications/cerberus.app" ]; then
  echo "--> Removing /Applications/cerberus.app..."
  rm -rf "/Applications/cerberus.app"
fi

# 3. Unload and remove privileged helper daemon
HELPER_PLIST="/Library/LaunchDaemons/com.cerberus.helper.plist"
HELPER_BIN="/Library/PrivilegedHelperTools/com.cerberus.helper"
HELPER_SOCK="/var/run/com.cerberus.helper.sock"

if [ -f "${HELPER_PLIST}" ] || [ -f "${HELPER_BIN}" ] || [ -S "${HELPER_SOCK}" ]; then
  echo "--> Removing privileged helper daemon (requires sudo)..."
  sudo launchctl unload "${HELPER_PLIST}" 2>/dev/null || true
  sudo rm -f "${HELPER_PLIST}"
  sudo rm -f "${HELPER_BIN}"
  sudo rm -f "${HELPER_SOCK}"
fi

# 4. Revoke /dev/bpf permissions
if [ -e "/dev/bpf0" ]; then
  echo "--> Resetting /dev/bpf* device permissions..."
  sudo chmod o-rw /dev/bpf* 2>/dev/null || true
fi

# 5. Purge user database, scan history, and preferences
USER_SUPPORT="${HOME}/Library/Application Support/cerberus"
if [ -d "${USER_SUPPORT}" ]; then
  echo "--> Purging database and scan history in ${USER_SUPPORT}..."
  rm -rf "${USER_SUPPORT}"
fi

rm -rf "${HOME}/Library/Caches/cerberus"
rm -rf "${HOME}/Library/Saved Application State/com.cerberus.desktop.savedState"
rm -rf "${HOME}/Library/Saved Application State/cerberus.savedState"
rm -f "${HOME}/Library/Preferences/com.cerberus.*" 2>/dev/null || true

echo "==> Cerberus Sentinel has been completely uninstalled and all data reset."
