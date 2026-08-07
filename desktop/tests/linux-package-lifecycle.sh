#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BASELINE.deb CURRENT.deb CURRENT.AppImage" >&2
  exit 2
fi

BASELINE_DEB="$(realpath "$1")"
CURRENT_DEB="$(realpath "$2")"
CURRENT_APPIMAGE="$(realpath "$3")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_NAME="$(dpkg-deb -f "$CURRENT_DEB" Package)"

cleanup() {
  if dpkg-query -W -f='${db:Status-Status}' "$PACKAGE_NAME" 2>/dev/null | grep -qx installed; then
    sudo dpkg -r "$PACKAGE_NAME"
  fi
}
trap cleanup EXIT

sudo apt-get install -y "$BASELINE_DEB"
BASELINE_VERSION="$(dpkg-query -W -f='${Version}' "$PACKAGE_NAME")"
APP_EXECUTABLE="$(command -v basilisk)"
xvfb-run --auto-servernum node "$ROOT/desktop/tests/packaged-smoke.js" "$APP_EXECUTABLE"

sudo apt-get install -y "$CURRENT_DEB"
CURRENT_VERSION="$(dpkg-query -W -f='${Version}' "$PACKAGE_NAME")"
if [ "$BASELINE_VERSION" = "$CURRENT_VERSION" ]; then
  echo "upgrade did not change package version ($CURRENT_VERSION)" >&2
  exit 1
fi
xvfb-run --auto-servernum node "$ROOT/desktop/tests/packaged-smoke.js" "$APP_EXECUTABLE"

sudo dpkg -r "$PACKAGE_NAME"
if dpkg-query -W -f='${db:Status-Status}' "$PACKAGE_NAME" 2>/dev/null | grep -qx installed; then
  echo "package remained installed after uninstall" >&2
  exit 1
fi

chmod +x "$CURRENT_APPIMAGE"
APPIMAGE_EXTRACT_AND_RUN=1 xvfb-run --auto-servernum node \
  "$ROOT/desktop/tests/packaged-smoke.js" "$CURRENT_APPIMAGE"
echo "Linux install/launch/upgrade/uninstall passed: $BASELINE_VERSION -> $CURRENT_VERSION"
