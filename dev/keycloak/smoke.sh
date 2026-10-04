#!/usr/bin/env bash
# Smoke test of the opt-in Keycloak dev service (`make dev-keycloak` first; run with
# `make dev-keycloak-smoke`). Checks, from the host:
# - the OIDC discovery document of the `databastion` realm (exact issuer, endpoints, PKCE S256,
#   RFC 9207 `iss` parameter) and its JWKS (an RSA signing key for RS256);
# - through the admin API (master realm administrator from dev/.env): the seeded client, the groups
#   claim mapper, the groups, the users and their memberships, and that users can edit their
#   username, e-mail and name (ADR-0038 decision 17).
# It does not log in as a realm user: the client has no password grant, and the login itself is
# tested by the console (P8-A integration tests, P8-D end-to-end scenario). Nothing secret is
# printed; the admin password goes to curl on stdin, never on its command line.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
if [ -f ./.env ]; then set -a; . ./.env; set +a; fi

PORT=${KEYCLOAK_PORT:-8180}
BASE="http://127.0.0.1:$PORT"
ISSUER="$BASE/realms/databastion"
ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-dev-only-keycloak-admin}
CURL=(curl -sS --fail --max-time 10 --max-filesize 1048576 --proto "=http")

fail=0
ok() { echo "ok   - $*"; }
ko() { echo "FAIL - $*"; fail=1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# check <name> <json file> <python expression on `d`>: the expression must be true.
check() {
  local name=$1 file=$2 expr=$3
  if python3 - "$file" "$expr" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
sys.exit(0 if eval(sys.argv[2], {"d": d}) else 1)
PY
  then ok "$name"; else ko "$name"; fi
}

echo "# OIDC discovery and JWKS ($ISSUER)"
if "${CURL[@]}" -o "$tmp/discovery.json" "$ISSUER/.well-known/openid-configuration"; then
  ok "discovery document reachable"
  check "issuer is exactly $ISSUER" "$tmp/discovery.json" "d['issuer'] == '$ISSUER'"
  check "endpoints are under the issuer" "$tmp/discovery.json" \
    "all(d[k].startswith('$ISSUER/') for k in ('authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint'))"
  check "authorization code flow with PKCE S256 advertised" "$tmp/discovery.json" \
    "'code' in d['response_types_supported'] and 'S256' in d['code_challenge_methods_supported']"
  check "RS256 among the id_token signing algorithms" "$tmp/discovery.json" \
    "'RS256' in d['id_token_signing_alg_values_supported']"
  check "authorization response iss parameter advertised (RFC 9207)" "$tmp/discovery.json" \
    "d.get('authorization_response_iss_parameter_supported') is True"
  jwks_uri=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["jwks_uri"])' "$tmp/discovery.json")
  if "${CURL[@]}" -o "$tmp/jwks.json" "$jwks_uri"; then
    ok "JWKS reachable"
    check "JWKS has an RSA RS256 signing key with a kid" "$tmp/jwks.json" \
      "any(k.get('kty') == 'RSA' and k.get('alg') == 'RS256' and k.get('use', 'sig') == 'sig' and k.get('kid') for k in d['keys'])"
  else
    ko "JWKS reachable"
  fi
else
  ko "discovery document reachable (is the service up? make dev-keycloak)"
fi

echo "# Seeded realm (admin API)"
if printf '%s' "$ADMIN_PASSWORD" | "${CURL[@]}" -o "$tmp/token.json" \
    --data-urlencode grant_type=password --data-urlencode client_id=admin-cli \
    --data-urlencode username=admin --data-urlencode password@- \
    "$BASE/realms/master/protocol/openid-connect/token"; then
  ok "admin API token"
  # The bearer token goes to curl through a header file, not its command line.
  python3 -c 'import json,sys; print("Authorization: Bearer " + json.load(open(sys.argv[1]))["access_token"])' \
    "$tmp/token.json" >"$tmp/auth-header"
  # api <output name> [path under the realm]
  api() { "${CURL[@]}" -H "@$tmp/auth-header" -o "$tmp/$1.json" "$BASE/admin/realms/databastion${2:+/$2}"; }

  if api realm; then
    check "users may edit their username, duplicate e-mails allowed" "$tmp/realm.json" \
      "d['editUsernameAllowed'] is True and d['duplicateEmailsAllowed'] is True and d['registrationAllowed'] is False"
  else ko "realm readable"; fi

  if api profile "users/profile"; then
    check "username, email, firstName, lastName editable by the user (user profile)" "$tmp/profile.json" \
      "all('user' in a.get('permissions', {}).get('edit', []) for a in d['attributes'] if a['name'] in ('username', 'email', 'firstName', 'lastName')) and {'username', 'email', 'firstName', 'lastName'} <= {a['name'] for a in d['attributes']}"
  else ko "user profile readable"; fi

  if api clients "clients?clientId=databastion-console"; then
    check "client databastion-console: confidential, code flow only" "$tmp/clients.json" \
      "len(d) == 1 and d[0]['publicClient'] is False and d[0]['clientAuthenticatorType'] == 'client-secret' and d[0]['standardFlowEnabled'] is True and not d[0]['implicitFlowEnabled'] and not d[0]['directAccessGrantsEnabled'] and not d[0]['serviceAccountsEnabled']"
    check "client: PKCE S256 required, exact redirect and post-logout URIs" "$tmp/clients.json" \
      "d[0]['attributes'].get('pkce.code.challenge.method') == 'S256' and d[0]['redirectUris'] == ['http://localhost:3000/api/auth/oidc/callback'] and d[0]['attributes'].get('post.logout.redirect.uris') == 'http://localhost:3000/login' and not d[0]['attributes'].get('backchannel.logout.url')"
    check "client: groups claim in the id_token, full path off" "$tmp/clients.json" \
      "any(m['protocolMapper'] == 'oidc-group-membership-mapper' and m['config'].get('claim.name') == 'groups' and m['config'].get('full.path') == 'false' and m['config'].get('id.token.claim') == 'true' for m in d[0].get('protocolMappers', []))"
  else ko "client readable"; fi

  if api groups "groups"; then
    check "groups databastion-admins, databastion-analysts, contractors" "$tmp/groups.json" \
      "{'databastion-admins', 'databastion-analysts', 'contractors'} <= {g['name'] for g in d}"
  else ko "groups readable"; fi

  # user <username> <email> <emailVerified> <group>
  user() {
    local name=$1 email=$2 verified=$3 group=$4 id
    if ! api "user-$name" "users?username=$name&exact=true"; then ko "user $name readable"; return; fi
    check "user $name: e-mail $email, email_verified $verified" "$tmp/user-$name.json" \
      "len(d) == 1 and d[0]['enabled'] and d[0]['email'] == '$email' and d[0]['emailVerified'] is $verified"
    id=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[0]["id"] if d else "")' "$tmp/user-$name.json")
    if [ -n "$id" ] && api "groups-$name" "users/$id/groups"; then
      check "user $name: member of $group only" "$tmp/groups-$name.json" "[g['name'] for g in d] == ['$group']"
    else ko "user $name groups readable"; fi
  }
  user admin.alice admin.alice@databastion.test True databastion-admins
  user analyst.bob analyst.bob@databastion.test True databastion-analysts
  user outsider.carol outsider.carol@databastion.test True contractors
  user unverified.dave unverified.dave@databastion.test False databastion-analysts
  user mallory admin.alice@databastion.test True databastion-analysts
else
  ko "admin API token (KEYCLOAK_ADMIN_PASSWORD from dev/.env)"
fi

exit "$fail"
