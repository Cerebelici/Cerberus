#!/usr/bin/env bash
set -euo pipefail

# Cerberus Network Sentinel — Development-only root helper installer
#
# This bypasses SMJobBless and installs the helper directly with sudo. Use it only
# when you want to exercise the privileged scanning path locally without a Developer
# ID, or when the SMJobBless prompt is unavailable. It does NOT test the signed
# install flow; use scripts/install_helper_dev.sh for that.
#
# The helper binary and launchd plist are installed under /Library and removed by
# scripts/uninstall_macos.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the privileged helper can only be installed on macOS" >&2
  exit 1
fi

# Build and ad-hoc sign as the invoking user so later rebuilds can overwrite the file.
if [[ "${EUID}" -ne 0 ]]; then
  "${SCRIPT_DIR}/build_helper_macos.sh" "${PROJECT_ROOT}/build/bin/com.cerberus.helper"
  exec sudo -- "$0" --install
fi

HELPER_BIN="/Library/PrivilegedHelperTools/com.cerberus.helper"
HELPER_PLIST="/Library/LaunchDaemons/com.cerberus.helper.plist"
HELPER_SOCK="/var/run/com.cerberus.helper.sock"
SRC_BIN="${PROJECT_ROOT}/build/bin/com.cerberus.helper"
SRC_PLIST="${PROJECT_ROOT}/build/darwin/com.cerberus.helper.plist"

if [[ ! -x "${SRC_BIN}" ]]; then
  echo "error: ${SRC_BIN} not found; run scripts/build_helper_macos.sh first" >&2
  exit 1
fi

echo "==> Installing ${HELPER_BIN}"
install -d -m 0755 -o root -g wheel /Library/PrivilegedHelperTools
install -m 0755 -o root -g wheel "${SRC_BIN}" "${HELPER_BIN}"

echo "==> Installing ${HELPER_PLIST}"
install -m 0644 -o root -g wheel "${SRC_PLIST}" "${HELPER_PLIST}"

echo "==> Restarting launchd job"
launchctl bootout system/com.cerberus.helper 2>/dev/null || true
launchctl bootstrap system "${HELPER_PLIST}"

for _ in {1..20}; do
  if [[ -S "${HELPER_SOCK}" ]]; then
    break
  fi
  sleep 0.25
done

echo "==> Status"
launchctl print system/com.cerberus.helper | head -12
if [[ -S "${HELPER_SOCK}" ]]; then
  ls -l "${HELPER_SOCK}"
  echo "Development helper is ready. Start Cerberus.app normally."
else
  echo "error: ${HELPER_SOCK} was not created; check /var/log/com.cerberus.helper.err.log" >&2
  exit 1
fi
