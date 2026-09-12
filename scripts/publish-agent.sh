#!/usr/bin/env bash
# Build the agent and put it into your own central server. One command.
#
#   git pull && scripts/publish-agent.sh                    # server on this machine
#   DEELPE_SSH=root@dashboard.example scripts/publish-agent.sh   # server somewhere else
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
#
# **Why over SSH and not over the dashboard's own upload.** `POST
# /api/binaries/windows` wants an administrator *session*; an API key is
# read-only on four monitoring paths and cannot upload (`auth::API_KEY_PATHS`).
# So an HTTP upload from here would mean the dashboard's administrator
# password in a file on a development machine — and if the installation
# demands a second factor, it would not even work unattended. SSH is the
# access you already have, with the key you already have, and it is the same
# `docker cp` this script does locally.
set -euo pipefail

CONTAINER="${DEELPE_CONTAINER:-dlp-server-1}"
DATA_DIR="${DEELPE_DATA_DIR:-}"          # only for a central server without Docker
SSH_TARGET="${DEELPE_SSH:-}"             # user@host of the central server; empty = this machine
DOCKER="${DEELPE_DOCKER:-docker}"        # e.g. "sudo docker" when the account is not in the docker group
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="$ROOT/target/x86_64-pc-windows-gnu/release/deelpe-winagent.exe"
NAME="deelpe-winagent.exe"

die() { echo "error: $*" >&2; exit 1; }

# The Windows program is cross-compiled, and this is where the three
# prerequisites for that are checked — one at a time, because "cross build
# failed" used to cover all three and the most common case of all: running
# this script on the central server, which has no compiler on purpose and
# never will. That one belongs on the machine that builds, with DEELPE_SSH
# pointing over here.
TARGET="x86_64-pc-windows-gnu"
LINKER="x86_64-w64-mingw32-gcc"
command -v cargo >/dev/null \
  || die "no Rust toolchain on this machine. Build where the compiler is and let it reach the
       central server: DEELPE_SSH=$(id -un)@$(hostname -f 2>/dev/null || hostname) scripts/publish-agent.sh"
if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx "$TARGET"; then
  die "the target $TARGET is not installed: rustup target add $TARGET"
fi
command -v "$LINKER" >/dev/null \
  || die "the mingw-w64 linker ($LINKER) is missing: brew install mingw-w64, or apt install gcc-mingw-w64-x86-64"

echo "== building"
# Only the progress goes to /dev/null; whatever cargo has to say about a
# failure belongs on the screen, not behind a guess of ours.
( cd "$ROOT" && cargo build --release --target "$TARGET" -p deelpe-winagent >/dev/null ) \
  || die "cross build failed — cargo's reason is above this line"
[ -f "$EXE" ] || die "$EXE is missing"

# The same check the server does on upload: it does not catch the malicious
# program, it catches the file you mixed up.
[ "$(head -c2 "$EXE")" = "MZ" ] || die "$EXE does not start with MZ — that is not a Windows program"

VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version = /{gsub(/[";]/,"",$3); print $3; exit}' "$ROOT/Cargo.toml")"
SHA="$(shasum -a 256 "$EXE" | cut -d' ' -f1)"

# Put the file where the central server distributes from. Runs here or, with
# DEELPE_SSH, over there — the commands are the same, only `run` and the
# place the file comes from differ.
#
# Beside it first, then rename, in both cases: the server picks up a new
# modification time by itself (`binaries::cached`), and half a file must
# never sit in the place things are distributed from.
store_local() {
  local src="$1"
  if [ -n "$DATA_DIR" ]; then
    # Central server without Docker (package, systemd).
    [ -d "$DATA_DIR" ] || die "$DATA_DIR does not exist"
    mkdir -p "$DATA_DIR/agents"
    cp "$src" "$DATA_DIR/agents/$NAME.part"
    mv "$DATA_DIR/agents/$NAME.part" "$DATA_DIR/agents/$NAME"
    echo "   $DATA_DIR/agents/$NAME"
  else
    $DOCKER inspect "$CONTAINER" >/dev/null 2>&1 \
      || die "container '$CONTAINER' is not running. Different setup? Set DEELPE_CONTAINER=... or DEELPE_DATA_DIR=..."
    $DOCKER exec "$CONTAINER" mkdir -p /var/lib/deelpe-server/agents
    $DOCKER cp "$src" "$CONTAINER:/var/lib/deelpe-server/agents/$NAME.part"
    $DOCKER exec "$CONTAINER" mv "/var/lib/deelpe-server/agents/$NAME.part" "/var/lib/deelpe-server/agents/$NAME"
    echo "   $CONTAINER:/var/lib/deelpe-server/agents/$NAME"
  fi
}

echo "== storing"
if [ -z "$SSH_TARGET" ]; then
  store_local "$EXE"
else
  # The staging path carries the process ID: two publishes at once must not
  # write over each other's half-transferred file.
  REMOTE_TMP="/tmp/$NAME.$$"
  scp -q "$EXE" "$SSH_TARGET:$REMOTE_TMP" || die "scp to $SSH_TARGET failed"
  # The remote side runs this same script's storing step, passed in as text.
  # One round trip, one place where the commands stand — and `set -e` over
  # there too, otherwise a failed `docker cp` would end in a cheerful
  # success message here.
  ssh "$SSH_TARGET" "NAME='$NAME' CONTAINER='$CONTAINER' DATA_DIR='$DATA_DIR' DOCKER='$DOCKER' SRC='$REMOTE_TMP' bash -s" <<'REMOTE' \
    || die "storing on $SSH_TARGET failed — is DEELPE_CONTAINER right, and may the account use docker? (DEELPE_DOCKER=\"sudo docker\")"
set -euo pipefail
trap 'rm -f "$SRC"' EXIT
if [ -n "$DATA_DIR" ]; then
  [ -d "$DATA_DIR" ] || { echo "error: $DATA_DIR does not exist" >&2; exit 1; }
  mkdir -p "$DATA_DIR/agents"
  cp "$SRC" "$DATA_DIR/agents/$NAME.part"
  mv "$DATA_DIR/agents/$NAME.part" "$DATA_DIR/agents/$NAME"
  echo "   $DATA_DIR/agents/$NAME"
else
  $DOCKER inspect "$CONTAINER" >/dev/null 2>&1 \
    || { echo "error: container '$CONTAINER' is not running" >&2; exit 1; }
  $DOCKER exec "$CONTAINER" mkdir -p /var/lib/deelpe-server/agents
  $DOCKER cp "$SRC" "$CONTAINER:/var/lib/deelpe-server/agents/$NAME.part"
  $DOCKER exec "$CONTAINER" mv "/var/lib/deelpe-server/agents/$NAME.part" "/var/lib/deelpe-server/agents/$NAME"
  echo "   $CONTAINER:/var/lib/deelpe-server/agents/$NAME"
fi
REMOTE
  echo "   on $SSH_TARGET"
fi

echo
echo "deelpe-winagent $VERSION is ready."
echo "  ${SHA:0:12}   <- these twelve characters show in the dashboard and in the Version column"
echo
echo "Agents fetch it on their next report if 'Update agents from here' is on;"
echo "otherwise use the 'Update' button in the device's row."
