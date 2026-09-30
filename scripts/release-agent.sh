#!/usr/bin/env bash
# Publish a new agent build: build it, sign it, attach it to the release.
# Afterwards it shows up in every dashboard that points at this repo — two
# clicks over there (Check now, Fetch), and the agents fetch it.
#
# The detour via the release is deliberate. This script could only upload
# straight into the dashboard with an administrator account of the central
# server, and then a password for the monitoring installation would sit in a
# file on a development machine. The token here only opens the repo, and the
# signature makes the central server independent of who it trusts.
#
#   scripts/release-agent.sh                 # GitHub, signed in via `gh`
#   GITEA_TOKEN=...  scripts/release-agent.sh   # your own Gitea
#
# Prerequisites, once:
#   deelpe-sign keygen ~/.deelpe/release.key    # public key into the dashboard
#   GitHub: gh auth login  (scope `repo`)
#   Gitea:  Settings -> Applications -> token with write access to the repo
set -euo pipefail

KEY="${DEELPE_RELEASE_KEY:-$HOME/.deelpe/release.key}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXE="$ROOT/target/x86_64-pc-windows-gnu/release/deelpe-winagent.exe"

die() { echo "error: $*" >&2; exit 1; }

[ -f "$KEY" ] || die "no signing key at $KEY — once: deelpe-sign keygen $KEY"

VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version = /{gsub(/[";]/,"",$3); print $3; exit}' "$ROOT/Cargo.toml")"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
TAG="v$VERSION"

echo "== building ($TAG)"
# The agent checks the release statement itself before it swaps; it needs
# the public key compiled in, the same one the server image carries.
( cd "$ROOT" && cargo build --release -p deelpe-server --bin deelpe-sign >/dev/null )
DEELPE_UPDATE_PUBKEY="$("$ROOT/target/release/deelpe-sign" pubkey "$KEY")"
export DEELPE_UPDATE_PUBKEY
( cd "$ROOT" && cargo build --release --target x86_64-pc-windows-gnu -p deelpe-winagent >/dev/null )
[ -f "$EXE" ] || die "$EXE is missing"

echo "== signing"
rm -f "$EXE.sig"
"$ROOT/target/release/deelpe-sign" sign "$KEY" "$EXE" "$VERSION" >/dev/null
SHA="$(shasum -a 256 "$EXE" | cut -d' ' -f1)"
echo "   $SHA"

NOTES="deelpe-winagent $VERSION

SHA-256: $SHA"

echo "== release $TAG"
if [ -z "${GITEA_TOKEN:-}" ]; then
  # GitHub. `gh` already brings sign-in, creation and replacement along;
  # --clobber is exactly what needs a loop for Gitea below.
  command -v gh >/dev/null || die "gh is missing (brew install gh; gh auth login) — or set GITEA_TOKEN for a Gitea"
  if gh release view "$TAG" >/dev/null 2>&1; then
    echo "   exists, replacing its files"
  else
    gh release create "$TAG" --title "$TAG" --notes "$NOTES" >/dev/null
    echo "   created"
  fi
  echo "== attaching"
  gh release upload "$TAG" "$EXE" "$EXE.sig" --clobber >/dev/null
else
  REPO_API="${DEELPE_RELEASE_REPO:-https://git.example.com/api/v1/repos/owner/dlprevent}"
  api() { curl -fsSL -H "Authorization: token $GITEA_TOKEN" "$@"; }
  # Reuse what is there: a second run of the same build should replace the
  # files, not create a second release.
  if ID="$(api "$REPO_API/releases/tags/$TAG" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)"; then
    echo "   exists (id $ID), replacing its files"
  else
    ID="$(api -X POST -H 'Content-Type: application/json' \
          -d "{\"tag_name\":\"$TAG\",\"name\":\"$TAG\",\"body\":\"deelpe-winagent $VERSION\\n\\nSHA-256: $SHA\"}" \
          "$REPO_API/releases" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
    echo "   created (id $ID)"
  fi

  # Attachments of the same name go first — otherwise Gitea hangs a second
  # file with the same name beside it, and the central server takes whichever
  # comes first.
  for name in deelpe-winagent.exe deelpe-winagent.exe.sig; do
    api "$REPO_API/releases/$ID/assets" \
      | python3 -c "import json,sys; [print(a['id']) for a in json.load(sys.stdin) if a['name']=='$name']" \
      | while read -r aid; do api -X DELETE "$REPO_API/releases/$ID/assets/$aid" >/dev/null; done
  done

  echo "== attaching"
  api -X POST -F "attachment=@$EXE"     "$REPO_API/releases/$ID/assets?name=deelpe-winagent.exe"     >/dev/null
  api -X POST -F "attachment=@$EXE.sig" "$REPO_API/releases/$ID/assets?name=deelpe-winagent.exe.sig" >/dev/null
fi

echo
echo "$TAG published."
echo "In the dashboard: Agents -> Check now -> Fetch. Then it rolls out as configured."
