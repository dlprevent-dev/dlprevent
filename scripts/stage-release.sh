#!/usr/bin/env bash
# Build every agent into one folder, ready to drag into a GitHub release by
# hand. Nothing is uploaded — that stays a click in the browser.
#
#   scripts/stage-release.sh        # -> dist/v<version>/
#
# The names are not free to choose: the dashboard's *Fetch* looks for exactly
# `deelpe-winagent.exe`, `DLPrevent.zip`, `deelpe-linux-amd64` and
# `deelpe-linux-arm64`, each with a `.sig` beside it (`binaries::KNOWN`,
# `release::assets_for`). The .debs are not fetched by the central server —
# they are the first install; SHA256SUMS covers them for whoever downloads
# them.
#
# The Mac app is signed and notarized, never staged without: an unsigned
# DLPrevent.zip carries no network filter, and nobody would notice until a
# strict folder failed to block. So the signing variables of
# apps/macos/DeelpeBar/build.sh are required here (docs/INSTALL.md, "Network
# blocking"):
#
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID \
#   APP_PROFILE=… FILTER_PROFILE=… NOTARY_PROFILE=… scripts/stage-release.sh
#
# Prerequisites, once:
#   deelpe-sign keygen ~/.deelpe/release.key    # public key into the dashboard
#   rustup target add x86_64-pc-windows-gnu; brew install mingw-w64
#   Docker running (the .debs), Xcode (the Mac app)
set -euo pipefail

KEY="${DEELPE_RELEASE_KEY:-$HOME/.deelpe/release.key}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "error: $*" >&2; exit 1; }

[ -f "$KEY" ] || die "no signing key at $KEY — once: deelpe-sign keygen $KEY"
for v in DEVELOPER_ID TEAM_ID APP_PROFILE FILTER_PROFILE NOTARY_PROFILE; do
  [ -n "${!v:-}" ] || die "$v is not set — the Mac app is only released signed and notarized (see the header)"
done
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] \
  || die "uncommitted changes — a release is built from a commit, or nobody can rebuild it"

VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version = /{gsub(/[";]/,"",$3); print $3; exit}' "$ROOT/Cargo.toml")"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
OUT="$ROOT/dist/v$VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== windows"
( cd "$ROOT" && cargo build --release --target x86_64-pc-windows-gnu -p deelpe-winagent >/dev/null )
cp "$ROOT/target/x86_64-pc-windows-gnu/release/deelpe-winagent.exe" "$OUT/"

echo "== mac"
"$ROOT/apps/macos/DeelpeBar/build.sh" >/dev/null
[ -d "$ROOT/apps/macos/DeelpeBar/build/DLPrevent.app/Contents/Library/SystemExtensions/ch.deelpe.bar.filter.systemextension" ] \
  || die "the Mac app came out without its network filter"
xcrun stapler validate "$ROOT/apps/macos/DeelpeBar/build/DLPrevent.app" >/dev/null \
  || die "the Mac app is not notarized"
cp "$ROOT/apps/macos/DeelpeBar/build/DLPrevent.zip" "$OUT/"

for arch in amd64 arm64; do
  echo "== linux $arch"
  "$ROOT/scripts/build-agent-deb.sh" "$arch" >/dev/null
  mv "$ROOT/dist/deelpe_${VERSION}-1_${arch}.deb" "$OUT/"
  mv "$ROOT/dist/deelpe-linux-${arch}" "$OUT/"
done

echo "== signing"
( cd "$ROOT" && cargo build --release -p deelpe-server --bin deelpe-sign >/dev/null )
for f in deelpe-winagent.exe DLPrevent.zip deelpe-linux-amd64 deelpe-linux-arm64; do
  "$ROOT/target/release/deelpe-sign" sign "$KEY" "$OUT/$f" "$VERSION" >/dev/null
done
( cd "$OUT" && shasum -a 256 deelpe-winagent.exe DLPrevent.zip deelpe-linux-amd64 deelpe-linux-arm64 ./*.deb | sed 's| \./| |' > SHA256SUMS )

echo
echo "dist/v$VERSION  (commit $(git -C "$ROOT" rev-parse --short HEAD))"
ls -1 "$OUT" | sed 's/^/   /'
echo
echo "Upload all of them to a release tagged v$VERSION on that commit. Not a draft,"
echo "not a pre-release: the dashboard only sees the latest regular release."
