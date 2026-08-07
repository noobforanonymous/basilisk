#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 BASELINE.dmg CURRENT.dmg" >&2
  exit 2
fi

BASELINE_DMG="$(realpath "$1")"
CURRENT_DMG="$(realpath "$2")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIFECYCLE_ROOT="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/basilisk-lifecycle.XXXXXX")"
INSTALL_ROOT="$LIFECYCLE_ROOT/Applications"
INSTALLED_APP="$INSTALL_ROOT/Basilisk.app"
MOUNT_POINT=""

detach_image() {
  if [ -n "$MOUNT_POINT" ] && mount | grep -Fq "on $MOUNT_POINT "; then
    hdiutil detach "$MOUNT_POINT" -quiet
  fi
  MOUNT_POINT=""
}

cleanup() {
  detach_image
  case "$LIFECYCLE_ROOT" in
    "${RUNNER_TEMP:-${TMPDIR:-/tmp}}"/basilisk-lifecycle.*) rm -rf -- "$LIFECYCLE_ROOT" ;;
    *) echo "refusing to remove unexpected lifecycle path: $LIFECYCLE_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT

install_from_dmg() {
  local dmg="$1"
  MOUNT_POINT="$LIFECYCLE_ROOT/mount"
  mkdir -p "$MOUNT_POINT" "$INSTALL_ROOT"
  hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$MOUNT_POINT" -quiet
  local source_app
  source_app="$(find "$MOUNT_POINT" -maxdepth 2 -type d -name 'Basilisk.app' -print -quit)"
  test -n "$source_app"
  rm -rf -- "$INSTALLED_APP"
  ditto "$source_app" "$INSTALLED_APP"
  detach_image
}

install_from_dmg "$BASELINE_DMG"
BASELINE_VERSION="$(defaults read "$INSTALLED_APP/Contents/Info" CFBundleShortVersionString)"
node "$ROOT/desktop/tests/packaged-smoke.js" "$INSTALLED_APP/Contents/MacOS/Basilisk"

install_from_dmg "$CURRENT_DMG"
CURRENT_VERSION="$(defaults read "$INSTALLED_APP/Contents/Info" CFBundleShortVersionString)"
if [ "$BASELINE_VERSION" = "$CURRENT_VERSION" ]; then
  echo "upgrade did not change application version ($CURRENT_VERSION)" >&2
  exit 1
fi
node "$ROOT/desktop/tests/packaged-smoke.js" "$INSTALLED_APP/Contents/MacOS/Basilisk"

rm -rf -- "$INSTALLED_APP"
if [ -e "$INSTALLED_APP" ]; then
  echo "application remained after uninstall" >&2
  exit 1
fi
echo "macOS install/launch/upgrade/uninstall passed: $BASELINE_VERSION -> $CURRENT_VERSION"
