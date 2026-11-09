#!/usr/bin/env bash
set -euo pipefail

PLAIN_VERSION="${1:-1.0.0}"
OUTPUT_DEB="${2:-cerberus-sentinel-linux-amd64.deb}"

PKG_DIR="pkg_debian"
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/opt/cerberus/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps"

cp build/bin/cerberus-desktop "${PKG_DIR}/opt/cerberus/bin/cerberus-desktop"
chmod 0755 "${PKG_DIR}/opt/cerberus/bin/cerberus-desktop"
ln -sf "/opt/cerberus/bin/cerberus-desktop" "${PKG_DIR}/usr/bin/cerberus-desktop"
ln -sf "/opt/cerberus/bin/cerberus-desktop" "${PKG_DIR}/usr/bin/cerberus"

if [ -d "tools" ]; then
  echo "==> Bundling portable engines from tools/ into /opt/cerberus/bin/"
  cp -R tools/* "${PKG_DIR}/opt/cerberus/bin/"
  chmod -R 0755 "${PKG_DIR}/opt/cerberus/bin"
elif [ -d "build/bin/tools" ]; then
  echo "==> Bundling portable engines from build/bin/tools into /opt/cerberus/bin/"
  cp -R build/bin/tools/* "${PKG_DIR}/opt/cerberus/bin/"
  chmod -R 0755 "${PKG_DIR}/opt/cerberus/bin"
fi

if [ -f "packaging/linux/cerberus.desktop" ]; then
  cp packaging/linux/cerberus.desktop "${PKG_DIR}/usr/share/applications/cerberus.desktop"
  chmod 0644 "${PKG_DIR}/usr/share/applications/cerberus.desktop"
fi

if [ -f "build/appicon.png" ]; then
  cp build/appicon.png "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps/cerberus.png"
  chmod 0644 "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps/cerberus.png"
fi

INSTALLED_SIZE="$(du -sk "${PKG_DIR}" | cut -f1)"

DEB_ARCH="${3:-}"
if [ -z "${DEB_ARCH}" ]; then
  DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
fi
if [ -z "${DEB_ARCH}" ]; then
  case "$(uname -m)" in
    aarch64|arm64) DEB_ARCH="arm64" ;;
    *) DEB_ARCH="amd64" ;;
  esac
fi

cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: cerberus-sentinel
Version: ${PLAIN_VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Installed-Size: ${INSTALLED_SIZE}
Depends: nmap, pkexec | policykit-1, libgtk-3-0t64 | libgtk-3-0, libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-37
Maintainer: Cerberus Team <security@cerberus.local>
Homepage: https://github.com/Cerebelici/SIEM_Home
Description: Cerberus Automated Network Sentinel and Vulnerability Assessment Desktop
 Automated local network discovery, device identification, and vulnerability
 auditing desktop application built with Wails.
EOF

cat <<'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1; then
    for nb in /opt/cerberus/bin/nmap /opt/cerberus/bin/nmap/nmap /usr/bin/nmap; do
        if [ -f "$nb" ]; then
            setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$nb" 2>/dev/null || true
        fi
    done
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF

chmod 0644 "${PKG_DIR}/DEBIAN/control"
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"
find "${PKG_DIR}" -type d -exec chmod 0755 {} +

dpkg-deb -Zxz --root-owner-group --build "${PKG_DIR}" "${OUTPUT_DEB}"
echo "Debian package created: ${OUTPUT_DEB}"
