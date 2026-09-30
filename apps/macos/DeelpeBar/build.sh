#!/bin/bash
# Builds DLPrevent.app (the menu bar app) into apps/macos/DeelpeBar/build/ and
# bundles the service (deelpe) together with the LaunchDaemon/LaunchAgent plist,
# so that the app can install the service itself.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"

# A public program should not name the machine it was built on: without this
# the bundled service carried ~470 paths under the builder's home directory.
# The last prefix that matches wins, so the project root comes last.
REMAP="--remap-path-prefix=$HOME=/build --remap-path-prefix=$ROOT=/src"
(cd "$ROOT" && RUSTFLAGS="${RUSTFLAGS:-} $REMAP" cargo build --release 2>&1 | grep -E "error|warning: unused|Finished" || true)
test -x "$ROOT/target/release/deelpe"

swift build -c release 2>&1 | grep -E "error:|warning:|Build complete" || true
test -x .build/release/DeelpeBar

APP=build/DLPrevent.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp Info.plist "$APP/Contents/"
# macOS replaces an activated system extension only when its version changed,
# so every build gets its own.
BUILD=$(date -u +%Y%m%d%H%M)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" "$APP/Contents/Info.plist"
cp .build/release/DeelpeBar "$APP/Contents/MacOS/DeelpeBar"
cp .build/release/DeelpeCageRelay "$APP/Contents/MacOS/DeelpeCageRelay"
swift icon/make-icon.swift "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/target/release/deelpe" "$APP/Contents/Resources/deelpe"
cp "$ROOT/packaging/ch.deelpe.daemon.plist" "$APP/Contents/Resources/"
cp "$ROOT/packaging/ch.deelpe.bar.plist" "$APP/Contents/Resources/"

# The network cage's content filter is a system extension: macOS loads it only
# from an app signed with a Developer ID, with provisioning profiles that
# grant the Network Extension capability, and notarized. Without those the
# app is built as before — it reports, and the settings say the filter is
# missing. The portal steps are in docs/INSTALL.md.
#
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID \
#   APP_PROFILE=DLPrevent.provisionprofile FILTER_PROFILE=DLPreventFilter.provisionprofile \
#   NOTARY_PROFILE=deelpe-notary ./build.sh
if [ -n "${DEVELOPER_ID:-}" ]; then
  : "${TEAM_ID:?TEAM_ID missing}" "${APP_PROFILE:?APP_PROFILE missing}" "${FILTER_PROFILE:?FILTER_PROFILE missing}"
  SYSX="$APP/Contents/Library/SystemExtensions/ch.deelpe.bar.filter.systemextension"
  mkdir -p "$SYSX/Contents/MacOS"
  sed "s/TEAM_ID/$TEAM_ID/g" Signing/Filter-Info.plist > "$SYSX/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" "$SYSX/Contents/Info.plist"
  cp .build/release/DeelpeFilter "$SYSX/Contents/MacOS/ch.deelpe.bar.filter"
  cp "$FILTER_PROFILE" "$SYSX/Contents/embedded.provisionprofile"
  cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
  sed "s/TEAM_ID/$TEAM_ID/g" Signing/Filter.entitlements > build/filter.entitlements
  sed "s/TEAM_ID/$TEAM_ID/g" Signing/App.entitlements > build/app.entitlements
  SIGN=(codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID")
  # Inside out: nested code first, the bundle around it last.
  "${SIGN[@]}" --entitlements build/filter.entitlements "$SYSX"
  "${SIGN[@]}" "$APP/Contents/MacOS/DeelpeCageRelay" "$APP/Contents/Resources/deelpe"
  "${SIGN[@]}" --entitlements build/app.entitlements "$APP"
  codesign --verify --deep --strict "$APP"
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    rm -f build/notarize.zip
    ditto -c -k --keepParent "$APP" build/notarize.zip
    xcrun notarytool submit build/notarize.zip --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f build/notarize.zip
  fi
else
  codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
  echo "  (unsigned: no network filter in this build; set DEVELOPER_ID, see docs/INSTALL.md)"
fi
echo "→ $APP"

# The dashboard takes the zip around the bundle, not the bundle itself
# (`binaries.rs`: "mac" → DLPrevent.zip), and the enrollment command unpacks
# it straight into /Applications — so DLPrevent.app has to be the top level.
# `zip -y` keeps the symlinks. Not `ditto -c -k`: its AppleDouble entries
# land inside the bundle on unzip and the signature is then broken.
rm -f build/DLPrevent.zip
(cd build && zip -qry DLPrevent.zip DLPrevent.app)
echo "→ build/DLPrevent.zip  $(shasum -a 256 build/DLPrevent.zip | cut -d' ' -f1)"
