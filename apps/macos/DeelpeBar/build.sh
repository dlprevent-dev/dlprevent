#!/bin/bash
# Builds DLPrevent.app (the menu bar app) into apps/macos/DeelpeBar/build/ and
# bundles the service (deelpe) together with the LaunchDaemon/LaunchAgent plist,
# so that the app can install the service itself.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"

(cd "$ROOT" && cargo build --release 2>&1 | grep -E "error|warning: unused|Finished" || true)
test -x "$ROOT/target/release/deelpe"

swift build -c release 2>&1 | grep -E "error:|warning:|Build complete" || true
test -x .build/release/DeelpeBar

APP=build/DLPrevent.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp Info.plist "$APP/Contents/"
cp .build/release/DeelpeBar "$APP/Contents/MacOS/DeelpeBar"
swift icon/make-icon.swift "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/target/release/deelpe" "$APP/Contents/Resources/deelpe"
cp "$ROOT/packaging/ch.deelpe.daemon.plist" "$APP/Contents/Resources/"
cp "$ROOT/packaging/ch.deelpe.bar.plist" "$APP/Contents/Resources/"
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
echo "→ $APP"

# The dashboard takes the zip around the bundle, not the bundle itself
# (`binaries.rs`: "mac" → DLPrevent.zip), and the enrollment command unpacks
# it straight into /Applications — so DLPrevent.app has to be the top level.
# `zip -y` keeps the symlinks. Not `ditto -c -k`: its AppleDouble entries
# land inside the bundle on unzip and the signature is then broken.
rm -f build/DLPrevent.zip
(cd build && zip -qry DLPrevent.zip DLPrevent.app)
echo "→ build/DLPrevent.zip  $(shasum -a 256 build/DLPrevent.zip | cut -d' ' -f1)"
