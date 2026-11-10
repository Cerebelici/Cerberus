#!/usr/bin/env bash
set -euo pipefail

# Build com.cerberus.helper with the Mach-O sections SMJobBless requires:
#   __TEXT,__info_plist      -> CFBundleIdentifier + SMAuthorizedClients
#   __TEXT,__launchd_plist   -> launchd job description
#
# The optional first argument is the output path. CERBERUS_CODESIGN_IDENTITY selects the
# signing identity; the default is ad-hoc ("-"). A Developer ID identity is required for
# the tightened `anchor apple generic` requirements used in production.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT="${1:-${PROJECT_ROOT}/build/bin/com.cerberus.helper}"
IDENTITY="${CERBERUS_CODESIGN_IDENTITY:--}"

INFO_PLIST="${PROJECT_ROOT}/build/darwin/helper-Info.plist"
LAUNCHD_PLIST="${PROJECT_ROOT}/build/darwin/com.cerberus.helper.plist"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the privileged helper can only be built on macOS" >&2
  exit 1
fi

plutil -lint "${INFO_PLIST}" >/dev/null
plutil -lint "${LAUNCHD_PLIST}" >/dev/null

mkdir -p "$(dirname "${OUTPUT}")"

echo "==> Building privileged helper (${OUTPUT})"
CGO_ENABLED=1 go build \
  -o "${OUTPUT}" \
  -ldflags "-linkmode=external -extldflags \"-sectcreate __TEXT __info_plist ${INFO_PLIST} -sectcreate __TEXT __launchd_plist ${LAUNCHD_PLIST}\"" \
  "${PROJECT_ROOT}/cmd/helper"

echo "==> Signing helper with identity: ${IDENTITY}"
codesign --force --sign "${IDENTITY}" --timestamp=none "${OUTPUT}"

echo "==> Verifying embedded sections and signature"
otool -l "${OUTPUT}" | grep -q "__info_plist"
otool -l "${OUTPUT}" | grep -q "__launchd_plist"
codesign --verify --strict "${OUTPUT}"

echo "Helper ready: ${OUTPUT}"
