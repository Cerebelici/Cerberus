#!/usr/bin/env bash
set -euo pipefail

# Cerberus Network Sentinel — Development Mode Privileged Helper Installer
# This script compiles and registers com.cerberus.helper into launchd for local development.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HELPER_BIN="/Library/PrivilegedHelperTools/com.cerberus.helper"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.cerberus.helper.plist"
PLIST_SRC="${PROJECT_ROOT}/build/darwin/com.cerberus.helper.plist"

echo "[Cerberus] Building privileged helper daemon..."
mkdir -p "${PROJECT_ROOT}/build/bin"
go build -o "${PROJECT_ROOT}/build/bin/com.cerberus.helper" "${PROJECT_ROOT}/cmd/helper"

echo "[Cerberus] Installing to /Library/PrivilegedHelperTools/ (requires sudo)..."
sudo mkdir -p /Library/PrivilegedHelperTools
sudo cp "${PROJECT_ROOT}/build/bin/com.cerberus.helper" "${HELPER_BIN}"
sudo chown root:wheel "${HELPER_BIN}"
sudo chmod 755 "${HELPER_BIN}"

echo "[Cerberus] Installing launchd daemon configuration..."
sudo cp "${PLIST_SRC}" "${LAUNCHD_PLIST}"
sudo chown root:wheel "${LAUNCHD_PLIST}"
sudo chmod 644 "${LAUNCHD_PLIST}"

echo "[Cerberus] Loading service into macOS launchd..."
sudo launchctl unload "${LAUNCHD_PLIST}" 2>/dev/null || true
sudo launchctl load -w "${LAUNCHD_PLIST}"

echo "[Cerberus] Privileged helper successfully installed and running!"
