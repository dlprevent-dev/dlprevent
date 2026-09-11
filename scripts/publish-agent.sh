#!/usr/bin/env bash
# Build the agent and put it into your own central server. One command.
#
#   git pull && scripts/publish-agent.sh
#
# Afterwards the new build sits in the dashboard under Agents, and the agents
# fetch it on their next report — provided "Update agents from here" is
# switched on. Otherwise it waits there for the button.
#
# **No network, no token, no password.** The file goes straight into the
# central server's staging slot. That is not a hole: whoever can run this
# runs the central server anyway — they could just sign in. A password in a
# file on the development machine would be the worse solution for the same
# thing.
#
# The price: there is no entry in the audit log, as there would be for an
# upload through the dashboard. Whoever needs one keeps uploading in the
# browser.
set -euo pipefail

CONTAINER="${DEELPE_CONTAINER:-dlp-server-1}"
DATA_DIR="${DEELPE_DATA_DIR:-}"          # only for a central server without Docker
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="$ROOT/target/x86_64-pc-windows-gnu/release/deelpe-winagent.exe"
NAME="deelpe-winagent.exe"

die() { echo "error: $*" >&2; exit 1; }

echo "== building"
( cd "$ROOT" && cargo build --release --target x86_64-pc-windows-gnu -p deelpe-winagent >/dev/null ) \
  || die "cross build failed — is mingw-w64 missing? see docs/INSTALL.md"
[ -f "$EXE" ] || die "$EXE is missing"

# The same check the server does on upload: it does not catch the malicious
# program, it catches the file you mixed up.
[ "$(head -c2 "$EXE")" = "MZ" ] || die "$EXE does not start with MZ — that is not a Windows program"

VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version = /{gsub(/[";]/,"",$3); print $3; exit}' "$ROOT/Cargo.toml")"
SHA="$(shasum -a 256 "$EXE" | cut -d' ' -f1)"

echo "== storing"
if [ -n "$DATA_DIR" ]; then
  # Central server without Docker (package, systemd).
  [ -d "$DATA_DIR" ] || die "$DATA_DIR does not exist"
  mkdir -p "$DATA_DIR/agents"
  # Beside it first, then rename — exactly like the server: half a file must
  # never sit in the place things are distributed from.
  cp "$EXE" "$DATA_DIR/agents/$NAME.part"
  mv "$DATA_DIR/agents/$NAME.part" "$DATA_DIR/agents/$NAME"
  echo "   $DATA_DIR/agents/$NAME"
else
  docker inspect "$CONTAINER" >/dev/null 2>&1 \
    || die "container '$CONTAINER' is not running. Different setup? Set DEELPE_CONTAINER=... or DEELPE_DATA_DIR=..."
  docker exec "$CONTAINER" mkdir -p /var/lib/deelpe-server/agents
  docker cp "$EXE" "$CONTAINER:/var/lib/deelpe-server/agents/$NAME.part"
  docker exec "$CONTAINER" mv "/var/lib/deelpe-server/agents/$NAME.part" "/var/lib/deelpe-server/agents/$NAME"
  echo "   $CONTAINER:/var/lib/deelpe-server/agents/$NAME"
fi

echo
echo "deelpe-winagent $VERSION is ready."
echo "  ${SHA:0:12}   <- these twelve characters show in the dashboard and in the Version column"
echo
echo "Agents fetch it on their next report if 'Update agents from here' is on;"
echo "otherwise use the 'Update' button in the device's row."
