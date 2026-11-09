#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DMG="${1:-../Cerberus-macOS-universal.dmg}"
APP_SRC="build/bin/cerberus.app"

if [ ! -d "${APP_SRC}" ]; then
  echo "Error: ${APP_SRC} not found"
  exit 1
fi

# 1. Validate Info.plist XML syntax
plutil -lint "${APP_SRC}/Contents/Info.plist"

# 2. Inject bundled tools into App Bundle Resources if present
if [ -d "build/bin/tools" ]; then
  echo "==> Injecting bundled engines into ${APP_SRC}/Contents/Resources/bin"
  mkdir -p "${APP_SRC}/Contents/Resources/bin"
  cp -R build/bin/tools/* "${APP_SRC}/Contents/Resources/bin/"
fi

# 3. Prepare DMG staging directory using ditto (preserves bundle structure & attributes)
DMG_ROOT="dmg_root"
rm -rf "${DMG_ROOT}"
mkdir -p "${DMG_ROOT}"
ditto "${APP_SRC}" "${DMG_ROOT}/cerberus.app"

# 4. Strip any extended attributes and perform clean deep ad-hoc code signing
xattr -cr "${DMG_ROOT}/cerberus.app"
if [ -d "${DMG_ROOT}/cerberus.app/Contents/Resources/bin" ]; then
  find "${DMG_ROOT}/cerberus.app/Contents/Resources/bin" -type f -perm +111 -exec codesign --force --sign - {} + 2>/dev/null || true
fi
codesign --force --deep --sign - "${DMG_ROOT}/cerberus.app"
codesign --verify --deep --strict --verbose=2 "${DMG_ROOT}/cerberus.app"

# 5. Add an Applications shortcut so the app can be installed by drag and drop
ln -s /Applications "${DMG_ROOT}/Applications"

# 6. Create compressed DMG
rm -f "${OUTPUT_DMG}"
hdiutil create -volname "Cerberus Sentinel" -srcfolder "${DMG_ROOT}" -ov -format UDZO "${OUTPUT_DMG}"
rm -rf "${DMG_ROOT}"
echo "macOS DMG created: ${OUTPUT_DMG}"

