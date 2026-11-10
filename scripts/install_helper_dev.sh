#!/usr/bin/env bash
set -euo pipefail

# Cerberus Network Sentinel — Development SMJobBless Helper Installer
#
# This script does not copy files into /Library or call sudo. It builds the helper,
# embeds the Info.plist and launchd plist sections SMJobBless requires, places the helper
# where SMJobBless expects it, signs both the app and helper, and launches the app. The
# app then calls SMJobBless, which raises the native macOS authorization prompt
# (Touch ID / Apple Watch / administrator password).
#
# Requirements:
#   - Build the app first, e.g. `cd desktop && wails build`.
#   - Set CERBERUS_APP if the bundle is not at desktop/build/bin/Cerberus.app.
#   - Set CERBERUS_CODESIGN_IDENTITY to a Developer ID for a release-like signature.
#     The ad-hoc default works only because the development requirements use the bare
#     `identifier` form (see build/darwin/helper-Info.plist).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IDENTITY="${CERBERUS_CODESIGN_IDENTITY:--}"

APP="${CERBERUS_APP:-}"
if [[ -z "${APP}" ]]; then
  for candidate in \
    "${PROJECT_ROOT}/desktop/build/bin/Cerberus.app" \
    "${PROJECT_ROOT}/desktop/build/bin/cerberus.app"; do
    if [[ -d "${candidate}" ]]; then
      APP="${candidate}"
      break
    fi
  done
fi

if [[ -z "${APP}" || ! -d "${APP}" ]]; then
  echo "error: Cerberus.app not found." >&2
  echo "       Build it first (cd desktop && wails build) or set CERBERUS_APP=/path/to/Cerberus.app" >&2
  exit 1
fi

APP_PLIST="${APP}/Contents/Info.plist"
APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${APP_PLIST}" 2>/dev/null || true)
if [[ "${APP_ID}" != "io.github.gr0gu.cerberus" ]]; then
  echo "error: ${APP} has CFBundleIdentifier '${APP_ID}', expected io.github.gr0gu.cerberus." >&2
  echo "       Rebuild the app so desktop/build/darwin/Info.plist is applied." >&2
  exit 1
fi
if ! /usr/libexec/PlistBuddy -c 'Print :SMPrivilegedExecutables:com.cerberus.helper' "${APP_PLIST}" >/dev/null 2>&1; then
  echo "error: ${APP} has no SMPrivilegedExecutables entry for com.cerberus.helper." >&2
  echo "       Rebuild the app so desktop/build/darwin/Info.plist is applied." >&2
  exit 1
fi

echo "==> Building helper"
"${SCRIPT_DIR}/build_helper_macos.sh" "${PROJECT_ROOT}/build/bin/com.cerberus.helper"

HELPER_DIR="${APP}/Contents/Library/LaunchServices"
echo "==> Installing helper into ${HELPER_DIR}"
mkdir -p "${HELPER_DIR}"
cp "${PROJECT_ROOT}/build/bin/com.cerberus.helper" "${HELPER_DIR}/com.cerberus.helper"
chmod 0755 "${HELPER_DIR}/com.cerberus.helper"

echo "==> Signing helper and app (identity: ${IDENTITY})"
codesign --force --sign "${IDENTITY}" --timestamp=none "${HELPER_DIR}/com.cerberus.helper"
codesign --force --deep --sign "${IDENTITY}" --timestamp=none "${APP}"
codesign --verify --deep --strict "${APP}"

echo "==> Launching ${APP}"
echo "    Approve the Touch ID / administrator prompt to register com.cerberus.helper."
open "${APP}"

echo "Done. Check the helper with:"
echo "  launchctl print system/com.cerberus.helper"
echo "  ls -l /var/run/com.cerberus.helper.sock"
echo
echo "If SMJobBless cannot be used locally (for example without a signing identity),"
echo "install the same helper directly with sudo instead:"
echo "  scripts/install_helper_root_dev.sh"
