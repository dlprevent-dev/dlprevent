#!/usr/bin/env bash
# Build the Linux agent as a .deb, from a Mac or from Linux. One command.
#
#   scripts/build-agent-deb.sh              # amd64, what almost every server is
#   scripts/build-agent-deb.sh arm64        # Raspberry Pi, Graviton, Ampere
#
# The package lands in dist/ with its SHA-256 printed, for the first install
# (your apt repository, Ansible, a share). Next to it lies
# dist/deelpe-linux-<arch>: the bare program **taken out of that package**,
# for the dashboard (Agents → Agent programs), from which agents replace
# themselves. Out of the package and not out of target/: cargo-deb strips the
# binary, so the one in target/ has a different fingerprint than the one on
# the machines — and the dashboard would call every agent outdated forever.
#
# **Why Docker and not `cargo deb` straight away.** A .deb contains a Linux
# binary, and the architecture of that binary is decided by where it was
# built, not by a flag on the package. Run `cargo deb -p deelpe` on a Mac and
# you package a macOS binary; run it in Docker on an Apple Silicon Mac
# without saying otherwise and you get an arm64 package that no amd64 server
# will install — and `dpkg` says "wrong architecture" only at the far end,
# after the rollout. Hence `--platform`, spelled out, every time.
#
# Emulation costs about two minutes of build time on an M-series Mac, and
# nothing at all on a Linux box of the same architecture. The cargo cache
# lives in a named Docker volume, so the second build is far quicker; reclaim
# it with `docker volume rm deelpe-deb-<arch>`.
set -euo pipefail

ARCH="${1:-amd64}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DEELPE_BUILD_IMAGE:-rust:1.90-slim-bookworm}"
VOLUME="deelpe-deb-$ARCH"

die() { echo "error: $*" >&2; exit 1; }

case "$ARCH" in
  amd64|arm64) ;;
  *) die "architecture '$ARCH': amd64 or arm64" ;;
esac
command -v docker >/dev/null || die "docker is missing"

VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version = /{gsub(/[";]/,"",$3); print $3; exit}' "$ROOT/Cargo.toml")"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
DEB="deelpe_${VERSION}-1_${ARCH}.deb"

echo "== building $DEB (linux/$ARCH)"
docker volume create "$VOLUME" >/dev/null
mkdir -p "$ROOT/dist"
# `/src` read-write: one test in deelpe-core writes below the source tree's
# own `target/`, and a read-only mount fails it. Nothing else is written
# there — the build itself goes into the volume.
docker run --rm --platform "linux/$ARCH" \
  -v "$ROOT":/src -v "$VOLUME":/target -v "$ROOT/dist":/out \
  -w /src -e CARGO_TARGET_DIR=/target \
  -e CARGO_INSTALL_ROOT=/target/tools \
  -e PATH=/target/tools/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "$IMAGE" bash -euo pipefail -c "
    apt-get update -qq >/dev/null
    apt-get install -y -qq dpkg-dev >/dev/null
    # Into the volume, not the container: otherwise every run reinstalls
    # cargo-deb, which takes longer than the build it is there for.
    command -v cargo-deb >/dev/null || cargo install cargo-deb --quiet
    cargo deb -p deelpe >/dev/null
    cp /target/debian/$DEB /out/
    rm -rf /tmp/pkg && dpkg-deb -x /target/debian/$DEB /tmp/pkg
    cp /tmp/pkg/usr/bin/deelpe /out/deelpe-linux-$ARCH
  "

[ -f "$ROOT/dist/$DEB" ] || die "dist/$DEB was not produced"
SHA="$(shasum -a 256 "$ROOT/dist/$DEB" 2>/dev/null || sha256sum "$ROOT/dist/$DEB")"
echo
echo "   dist/$DEB"
echo "   ${SHA%% *}"
echo
BIN_SHA="$(shasum -a 256 "$ROOT/dist/deelpe-linux-$ARCH" 2>/dev/null || sha256sum "$ROOT/dist/deelpe-linux-$ARCH")"
echo "   dist/deelpe-linux-$ARCH   (upload in the dashboard)"
echo "   ${BIN_SHA%% *}"
echo
echo "   sudo apt install ./$DEB        # enables and starts the service"
echo "   then enroll: dashboard -> Agents -> Enroll agent -> Linux"
