#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DMG="${1:-../Cerberus-macOS-universal.dmg}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APP_SRC="build/bin/cerberus.app"
if [ ! -d "${APP_SRC}" ] && [ -d "build/bin/Cerberus.app" ]; then
  APP_SRC="build/bin/Cerberus.app"
fi

if [ ! -d "${APP_SRC}" ]; then
  echo "Error: ${APP_SRC} not found"
  exit 1
fi

# 1. Validate Info.plist XML syntax and the helper contract. SMJobBless checks that
#    the app satisfies SMAuthorizedClients and that the helper satisfies
#    SMPrivilegedExecutables, so a stale bundle identifier fails installation.
plutil -lint "${APP_SRC}/Contents/Info.plist"
APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${APP_SRC}/Contents/Info.plist")
if [ "${APP_ID}" != "io.github.gr0gu.cerberus" ]; then
  echo "Error: ${APP_SRC} has CFBundleIdentifier '${APP_ID}', expected io.github.gr0gu.cerberus" >&2
  exit 1
fi
if ! /usr/libexec/PlistBuddy -c 'Print :SMPrivilegedExecutables:com.cerberus.helper' "${APP_SRC}/Contents/Info.plist" >/dev/null 2>&1; then
  echo "Error: ${APP_SRC} has no SMPrivilegedExecutables entry for com.cerberus.helper" >&2
  exit 1
fi

# 2. Inject bundled tools into App Bundle Resources if present
if [ -d "tools" ]; then
  echo "==> Injecting bundled engines from tools/ into ${APP_SRC}/Contents/Resources/bin"
  mkdir -p "${APP_SRC}/Contents/Resources/bin"
  cp -R tools/* "${APP_SRC}/Contents/Resources/bin/"
elif [ -d "build/bin/tools" ]; then
  echo "==> Injecting bundled engines from build/bin/tools into ${APP_SRC}/Contents/Resources/bin"
  mkdir -p "${APP_SRC}/Contents/Resources/bin"
  cp -R build/bin/tools/* "${APP_SRC}/Contents/Resources/bin/"
fi

# 3. Build and inject the SMJobBless privileged helper. SMJobBless looks for it at
#    Contents/Library/LaunchServices/<label> and requires embedded Info.plist and
#    launchd plist sections, so the helper must be built by the dedicated script.
IDENTITY="${CERBERUS_CODESIGN_IDENTITY:--}"
if [ "${IDENTITY}" = "-" ]; then
  echo "warning: building an ad-hoc signed app. macOS will not bless an ad-hoc signed" >&2
  echo "         privileged helper, so scanning stays unavailable in this build." >&2
  echo "         Set CERBERUS_CODESIGN_IDENTITY to a Developer ID for a distributable app." >&2
fi
"${REPO_ROOT}/scripts/build_helper_macos.sh" "${REPO_ROOT}/build/bin/com.cerberus.helper"
mkdir -p "${APP_SRC}/Contents/Library/LaunchServices"
cp "${REPO_ROOT}/build/bin/com.cerberus.helper" "${APP_SRC}/Contents/Library/LaunchServices/com.cerberus.helper"
chmod 0755 "${APP_SRC}/Contents/Library/LaunchServices/com.cerberus.helper"
codesign --force --sign "${IDENTITY}" --timestamp=none "${APP_SRC}/Contents/Library/LaunchServices/com.cerberus.helper"

# 4. Prepare DMG staging directory using ditto (preserves bundle structure & attributes)
DMG_ROOT="dmg_root"
rm -rf "${DMG_ROOT}"
mkdir -p "${DMG_ROOT}"
ditto "${APP_SRC}" "${DMG_ROOT}/cerberus.app"

# 5. Strip any extended attributes and sign the bundle (including the helper)
xattr -cr "${DMG_ROOT}/cerberus.app"
if [ -d "${DMG_ROOT}/cerberus.app/Contents/Resources/bin" ]; then
  find "${DMG_ROOT}/cerberus.app/Contents/Resources/bin" -type f -perm +111 -exec codesign --force --sign "${IDENTITY}" --timestamp=none {} + 2>/dev/null || true
fi
codesign --force --deep --sign "${IDENTITY}" --timestamp=none "${DMG_ROOT}/cerberus.app"
codesign --verify --deep --strict --verbose=2 "${DMG_ROOT}/cerberus.app"

# 6. Add an Applications shortcut so the app can be installed by drag and drop
ln -s /Applications "${DMG_ROOT}/Applications"

# 7. Create compressed DMG
rm -f "${OUTPUT_DMG}"
hdiutil create -volname "Cerberus Sentinel" -srcfolder "${DMG_ROOT}" -ov -format UDZO "${OUTPUT_DMG}"
rm -rf "${DMG_ROOT}"
echo "macOS DMG created: ${OUTPUT_DMG}"

