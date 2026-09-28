#!/bin/sh
# A Keycloak to test DLPrevent single sign-on against, in one command:
#
#   ./setup.sh <dashboard-url> <keycloak-host>
#   ./setup.sh https://192.0.2.20:8443 192.0.2.20
#
# <dashboard-url> is how browsers open the DLPrevent dashboard (the redirect
# URI is registered for it). <keycloak-host> is a name or address under
# which both the browser and the DLPrevent server reach this machine — not
# localhost when DLPrevent runs in a container.
#
# Creates its own CA and server certificate, random passwords, and a realm
# "dlprevent" with the groups dlp-admins and dlp-users, the users anna
# (admin), bob (read only) and carl (in no group), and a client with PKCE
# and a groups claim. Then starts Keycloak and prints what to enter in
# DLPrevent. Lab only: dev mode, passwords in credentials.txt.
set -eu
[ $# -eq 2 ] || { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
cd "$(dirname "$0")"
DLP_URL=${1%/}
KC_HOST=$2
KC_PORT=${KC_PORT:-8543}
case "$KC_HOST" in localhost|127.*) echo "note: $KC_HOST only works when the DLPrevent server does not run in a container" >&2 ;; esac

rand() { openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-20; }

mkdir -p certs import
if [ ! -f certs/ca.pem ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -subj "/CN=DLPrevent lab CA" \
    -keyout certs/ca.key -out certs/ca.pem 2>/dev/null
fi
case "$KC_HOST" in *[!0-9.]*) SAN="DNS:$KC_HOST" ;; *) SAN="IP:$KC_HOST" ;; esac
openssl req -newkey rsa:2048 -sha256 -nodes -subj "/CN=$KC_HOST" -keyout certs/keycloak.key -out certs/keycloak.csr 2>/dev/null
printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SAN" > certs/ext.cnf
openssl x509 -req -in certs/keycloak.csr -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial -days 825 -sha256 \
  -extfile certs/ext.cnf -out certs/keycloak.pem 2>/dev/null
rm -f certs/keycloak.csr certs/ext.cnf
# Keycloak runs as uid 1000 in its container and must read the key. Lab only.
chmod 644 certs/keycloak.key certs/keycloak.pem certs/ca.pem
chmod 600 certs/ca.key

ADMIN=$(rand); ANNA=$(rand); BOB=$(rand); CARL=$(rand); SECRET=$(rand)$(rand)
umask 077
printf 'KC_HOST=%s\nKC_PORT=%s\nKC_ADMIN_PASSWORD=%s\n' "$KC_HOST" "$KC_PORT" "$ADMIN" > .env
sed -e "s|@ANNA@|$ANNA|" -e "s|@BOB@|$BOB|" -e "s|@CARL@|$CARL|" -e "s|@SECRET@|$SECRET|" \
    -e "s|@REDIRECT@|$DLP_URL/api/sso/callback|" realm.template.json > import/dlprevent-realm.json
chmod 644 import/dlprevent-realm.json

docker compose down -v >/dev/null 2>&1 || true
docker compose up -d
ISSUER="https://$KC_HOST:$KC_PORT/realms/dlprevent"
printf 'Waiting for Keycloak'
i=0
until curl -fsS --cacert certs/ca.pem "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 90 ] || { echo; echo "Keycloak did not come up: docker compose logs keycloak" >&2; exit 1; }
  printf '.'; sleep 2
done
echo " up."

cat > credentials.txt <<OUT
DLPrevent -> System -> Single sign-on
  Issuer:                $ISSUER
  Client ID:             dlprevent
  Client secret:         $SECRET
  Client authentication: post
  User name claim:       preferred_username
  Groups claim:          groups
  Administrator group:   dlp-admins
  Allowed group:         dlp-users
  Provider's CA:         paste the content of $(pwd)/certs/ca.pem

Test users (sign in with "Sign in with single sign-on"):
  anna  $ANNA   -> administrator
  bob   $BOB   -> read only
  carl  $CARL   -> refused (in no group)

Keycloak admin console: https://$KC_HOST:$KC_PORT/admin  (admin / $ADMIN)
Browsers warn about the lab CA; import certs/ca.pem or accept the warning.
OUT
cat credentials.txt
echo
cat certs/ca.pem
