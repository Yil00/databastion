#!/usr/bin/env bash
# End-to-end OIDC login scenario (ROADMAP P8-D, ADR-0038 decisions 2, 3, 6 to 9, 11, 14, 15, 17):
# the console (production image) against Keycloak with the dev test realm, over HTTPS with a
# certificate from a throwaway CA generated here (DATABASTION_OIDC_CA_FILE on the console side).
# The scenario itself is e2e/oidc_scenario.py, run once per console configuration:
#   signup-off  sign-up off, group and domain filters: refused group, unverified e-mail, pending
#               logins and their approval, role from the group, the attribute-editing user
#               (mallory, renamed at runtime to the local administrator's username), self-service
#               link, logout (RP-initiated, Keycloak session ended)
#   signup-on   sign-up on, no filters, strict role mapping: no groups claim refused (role),
#               mallory refused (username) and never admin, a sign-up as positive control
# Then: no secret, authorization code, state, nonce, session token or CSRF token in the console's
# logs or database dump, and no secret in any log.
# See e2e/README.md. Requires: docker (compose v2), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
export E2E_KEYCLOAK_PORT="${E2E_KEYCLOAK_PORT:-8444}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-oidc}"
PROJECT="databastion-e2e-oidc"
HOSTNAME_CONSOLE="console.e2e.internal"
KC_DNS_NAME="keycloak.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
ISSUER="https://${KC_DNS_NAME}:${E2E_KEYCLOAK_PORT}/realms/databastion"
DEV_REALM="$HERE/../dev/keycloak/databastion-realm.json"
SCENARIO="$HERE/oidc_scenario.py"
KEYCLOAK_TIMEOUT_S=240

log() { printf '[e2e-oidc %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

T_RUN="$(date +%s)"
T_PHASE="$T_RUN"
TIMINGS=""
phase_done() {
  local now
  now="$(date +%s)"
  TIMINGS+="$1 $((now - T_PHASE))s; "
  T_PHASE="$now"
}

# The two console configurations are set below, never inherited from the caller's environment.
unset E2E_OIDC_ALLOW_SIGN_UP E2E_OIDC_ALLOWED_GROUPS E2E_OIDC_ALLOWED_DOMAINS E2E_OIDC_USE_REFRESH_TOKEN

for tool in docker openssl curl jq timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

# The Keycloak image is the one dev/docker-compose.yml pins (tag and index digest; its provenance
# against quay.io is checked by the dev-env workflow).
dev_pin="$(sed -n 's/.*DATABASTION_DEV_KEYCLOAK_IMAGE:-\(keycloak\/keycloak:[^}]*\)}.*/\1/p' "$HERE/../dev/docker-compose.yml")"
e2e_pin="$(sed -n 's/.*E2E_KEYCLOAK_IMAGE:-\(keycloak\/keycloak:[^}]*\)}.*/\1/p' "$HERE/docker-compose.oidc.yml")"
if ! [[ "$dev_pin" == keycloak/keycloak:*@sha256:* && "$dev_pin" == "$e2e_pin" ]]; then
  fail "the Keycloak image of docker-compose.oidc.yml must be the one pinned in dev/docker-compose.yml"
fi
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_KEYCLOAK_IMAGE
elif [ -n "${E2E_KEYCLOAK_IMAGE:-}" ]; then
  # Local runs (e.g. a registry mirror): the same index digest.
  [[ "$E2E_KEYCLOAK_IMAGE" == *"@${dev_pin#*@}" ]] || fail "E2E_KEYCLOAK_IMAGE must carry the pinned digest ${dev_pin#*@}"
fi

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-oidc.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"

# --------------------------------------------------------------------------- secret registry
# As in run.sh: one file per secret ($P/<name>, its value only), read by grep -Ff and awk so that
# no value is ever on a command line; masked in the GitHub Actions log. The scenario adds the
# one-time values it sees on the wire to $OP (session tokens, CSRF tokens, Keycloak admin token),
# $OP/url (authorization codes, states, nonces: they travel in URLs, so the TLS proxy's access log
# holds them by design and is not scanned for them) and $OP/sid (Keycloak's session ids, the
# provider `sid`: in the callback URLs too, and kept with the console session by design, so looked
# for in every log but the proxy's, not in the database).
P="$E2E_WORK_DIR/secret-patterns"
OP="$E2E_WORK_DIR/oidc-patterns"
mkdir -p "$P" "$OP/url" "$OP/sid"
register_secret() {
  local name="$1" value="$2"
  [ -n "$value" ] && [ "$value" != null ] || return 0
  printf '%s\n' "$value" >"$P/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}

# leak_scan TARGET PATTERN_DIR: prints "<name>: <files>" for every pattern of PATTERN_DIR found in
# TARGET (a file or a directory; fixed strings; only the pattern's name is printed). Returns 1 if
# any is found.
leak_scan() {
  local target="$1" pdir="$2" f files found=0
  for f in "$pdir"/*; do
    [ -f "$f" ] || continue
    files="$(LC_ALL=C grep -rlFf "$f" -- "$target" 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ' || true)"
    if [ -n "$files" ]; then
      printf '%s: %s\n' "$(basename "$f")" "$files"
      found=1
    fi
  done
  return "$found"
}

# shellcheck disable=SC2016 # awk program, not shell
REDACT_AWK='
BEGIN { if ((getline s < ENVIRON["SECRET_FILE"]) <= 0 || s == "") exit 2; rep = ENVIRON["REDACTION"] }
{
  out = ""; line = $0
  while ((i = index(line, s)) > 0) { out = out substr(line, 1, i - 1) rep; line = substr(line, i + length(s)) }
  print out line
}'

# redact_dir DIR PATTERN_DIR: as in run.sh (in place; a file that cannot be redacted is deleted).
redact_dir() {
  local dir="$1" pdir="$2" f name file tmp="$E2E_WORK_DIR/redact.tmp"
  local -a hits
  [ -d "$dir" ] && [ -d "$pdir" ] || return 0
  for f in "$pdir"/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    mapfile -t hits < <(LC_ALL=C grep -rlFf "$f" -- "$dir" 2>/dev/null)
    for file in "${hits[@]}"; do
      if LC_ALL=C SECRET_FILE="$f" REDACTION="<REDACTED:$name>" awk "$REDACT_AWK" "$file" >"$tmp" \
          && ! LC_ALL=C grep -qFf "$f" -- "$tmp" && mv -f "$tmp" "$file"; then
        log "redacted $name in $(basename "$file")"
      else
        rm -f -- "$file" "$tmp"
        log "deleted $(basename "$file") (could not redact $name)"
      fi
    done
  done
}

COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.oidc.yml")
compose() { timeout 120 docker compose "${COMPOSE_ARGS[@]}" "$@"; }
SERVICES=(db migrate web proxy keycloak)

dump_logs() {
  local svc suffix="${1:-}"
  for svc in "${SERVICES[@]}"; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc$suffix.log" 2>&1 || true
  done
}

cleanup() {
  local status=$?
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  redact_dir "$E2E_LOG_DIR" "$P"
  redact_dir "$E2E_LOG_DIR" "$OP"
  redact_dir "$E2E_LOG_DIR" "$OP/url"
  redact_dir "$E2E_LOG_DIR" "$OP/sid"
  log "tearing down"
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$E2E_WORK_DIR"
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --------------------------------------------------------------------------- secrets
rand_hex() { openssl rand -hex "$1"; }
mkdir -p "$E2E_WORK_DIR/secrets" "$E2E_WORK_DIR/tls" "$E2E_WORK_DIR/keycloak"
S="$E2E_WORK_DIR/secrets"
# 0644 files inside a 0700 directory: readable by the containers' users through the bind mounts.
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; register_secret "$1" "$2"; }
DB_OWNER_PASSWORD="$(rand_hex 24)"
DB_APP_PASSWORD="$(rand_hex 24)"
put_secret db_password "$(rand_hex 24)"
put_secret db_owner_password "$DB_OWNER_PASSWORD"
put_secret db_app_password "$DB_APP_PASSWORD"
put_secret encryption_key "$(openssl rand -base64 32)"
put_secret metrics_token "$(rand_hex 32)"
put_secret admin_password "$(rand_hex 24)"            # e2e-admin, the local (break-glass) administrator
put_secret linker_password "$(rand_hex 24)"           # e2e-linker, local administrator of the link case
put_secret analyst_password "$(rand_hex 24)"          # e2e-analyst, local analyst (refused: LOCAL_LOGIN=admins)
put_secret keycloak_admin_password "$(rand_hex 24)"   # temporary administrator of Keycloak's master realm
put_secret oidc_client_secret "$(rand_hex 32)"        # databastion-console client (console and Keycloak)
put_secret keycloak_user_password "$(rand_hex 24)"    # every user of the test realm
# Not registered as such: they hold registered passwords.
umask 022
printf 'postgresql://databastion_owner:%s@db:5432/databastion' "$DB_OWNER_PASSWORD" >"$S/db_owner_url"
printf 'postgresql://databastion_runtime:%s@db:5432/databastion' "$DB_APP_PASSWORD" >"$S/db_url"
umask 077
# The OIDC client secret as it crosses the wire to the token endpoint (client_secret_basic).
register_secret oidc_client_basic "$(printf 'databastion-console:%s' "$(cat "$S/oidc_client_secret")" | base64 -w0)"
unset DB_OWNER_PASSWORD DB_APP_PASSWORD
chmod 0700 "$S"

# --------------------------------------------------------------------------- test CA
log "generating the throwaway test CA, the proxy and the Keycloak certificates"
T="$E2E_WORK_DIR/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion e2e OIDC test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$T/ca.key" -out "$T/ca.crt" 2>/dev/null
# leaf NAME HOST: a P-256 server certificate for HOST, issued by the test CA.
leaf() {
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$2" -keyout "$T/$1.key" -out "$T/$1.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
    "$2" >"$T/$1.ext"
  openssl x509 -req -in "$T/$1.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial \
    -days 1 -sha256 -extfile "$T/$1.ext" -out "$T/$1.crt" 2>/dev/null
  rm -f "$T/$1.csr" "$T/$1.ext"
}
leaf server "$HOSTNAME_CONSOLE"     # TLS proxy (docker-compose.yml mounts server.crt / .key)
leaf keycloak "$KC_DNS_NAME"
rm -f "$T/ca.key" "$T/ca.srl"
chmod 0644 "$T/ca.crt" "$T/server.crt" "$T/server.key" "$T/keycloak.crt" "$T/keycloak.key"
# Every service of docker-compose.yml is interpolated, even those this run never starts: their
# bind-mount sources must name something (empty files, never mounted).
for f in mysql-ca.pem mariadb-ca.pem ldap-ca.pem; do : >"$T/$f"; done

# --------------------------------------------------------------------------- realm
# From the committed dev realm: the console's e2e redirect URIs, HTTPS required for every client,
# and one more user for the self-service link (link.grace, like admin.alice). The client secret and
# the users' password stay ${...} placeholders, resolved by Keycloak from its secrets at import.
log "generating the e2e realm from dev/keycloak/databastion-realm.json"
jq --arg base "$BASE_URL" '
  .displayName = "DataBastion (e2e test realm, generated by e2e/oidc.sh)"
  | .sslRequired = "all"
  | .clients |= map(if .clientId == "databastion-console" then
      .rootUrl = $base
      | .redirectUris = [$base + "/api/auth/oidc/callback"]
      | .attributes["post.logout.redirect.uris"] = ($base + "/login")
      | .description = "e2e confidential client; the secret is generated by e2e/oidc.sh for each run"
    else . end)
  | .users += [.users[] | select(.username == "admin.alice")
      | .username = "link.grace" | .email = "link.grace@databastion.test"
      | .firstName = "Grace" | .lastName = "Link"]
' "$DEV_REALM" >"$E2E_WORK_DIR/keycloak/databastion-realm.json"
R="$E2E_WORK_DIR/keycloak/databastion-realm.json"
jq -e --arg base "$BASE_URL" '
  ([.clients[] | select(.clientId == "databastion-console")] | length == 1)
  and (.clients[] | select(.clientId == "databastion-console")
       | .secret == "${KEYCLOAK_CONSOLE_CLIENT_SECRET}" and .redirectUris == [$base + "/api/auth/oidc/callback"]
         and .publicClient == false and .directAccessGrantsEnabled == false)
  and ([.users[].credentials[].value] | all(. == "${KEYCLOAK_DEV_USER_PASSWORD}"))
  and ([.users[].username] | sort == ["admin.alice", "analyst.bob", "link.grace", "mallory", "nogroup.erin", "outsider.carol", "unverified.dave"])
' "$R" >/dev/null || fail "unexpected realm (client, placeholders or users)"
chmod 0755 "$E2E_WORK_DIR/keycloak"
chmod 0644 "$R"

# --------------------------------------------------------------------------- build + start
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing console image ${E2E_CONSOLE_IMAGE:-databastion-console:e2e}"
  docker image inspect "${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" >/dev/null 2>&1 \
    || fail "E2E_SKIP_BUILD=1 but the console image is missing"
else
  log "building the console image"
  # Within the outer budget (CI step and make e2e-oidc: timeout 1320 s, job 25 min).
  timeout 900 docker compose "${COMPOSE_ARGS[@]}" build web
fi
# ADR-0038 decision 2: the plain-HTTP issuer exception never applies to a production build. The
# image must be one, and nothing may switch the web container to another mode.
docker image inspect "${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" --format '{{json .Config.Env}}' \
  | jq -e 'index("NODE_ENV=production") != null' >/dev/null || fail "the console image is not a production build"
phase_done build

log "starting Keycloak (HTTPS only, realm import)"
compose up -d keycloak
CURL=(curl -sS --noproxy '*' --max-time 10 --proto '=https' --cacert "$T/ca.crt"
  --resolve "${KC_DNS_NAME}:${E2E_KEYCLOAK_PORT}:127.0.0.1"
  --resolve "${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}:127.0.0.1")
deadline=$(( $(date +%s) + KEYCLOAK_TIMEOUT_S ))
until "${CURL[@]}" -f -o "$E2E_WORK_DIR/discovery.json" "$ISSUER/.well-known/openid-configuration" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "Keycloak discovery not reachable within ${KEYCLOAK_TIMEOUT_S} s"
  sleep 2
done
jq -e --arg iss "$ISSUER" '.issuer == $iss
  and ([.authorization_endpoint, .token_endpoint, .jwks_uri, .end_session_endpoint] | all(startswith($iss + "/")))
  and .authorization_response_iss_parameter_supported == true' "$E2E_WORK_DIR/discovery.json" >/dev/null \
  || fail "unexpected Keycloak discovery document"
# Keycloak's only listener is HTTPS: the issuer port refuses plain HTTP.
! curl -sS --noproxy '*' --max-time 5 -o /dev/null --resolve "${KC_DNS_NAME}:${E2E_KEYCLOAK_PORT}:127.0.0.1" \
  "http://${KC_DNS_NAME}:${E2E_KEYCLOAK_PORT}/realms/databastion" 2>/dev/null \
  || fail "Keycloak answers plain HTTP"
phase_done keycloak

start_console() {
  log "starting the console (web, TLS proxy): $1"
  # The proxy is created once; a configuration change recreates web only.
  timeout 400 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps web proxy
  local deadline=$(( $(date +%s) + 120 ))
  until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
    sleep 1
  done
  local env
  env="$(docker inspect "$(compose ps -q web)" --format '{{json .Config.Env}}')"
  jq -e '[.[] | select(startswith("NODE_ENV="))] == ["NODE_ENV=production"]' <<<"$env" >/dev/null \
    || fail "the web container does not run with NODE_ENV=production"
  jq -e 'any(startswith("DATABASTION_INSECURE_COOKIES=")) | not' <<<"$env" >/dev/null || fail "insecure cookies in the web container"
  jq -e 'any(startswith("DATABASTION_OIDC_CLIENT_SECRET=")) | not' <<<"$env" >/dev/null || fail "client secret in the web environment"
}

log "starting the console database and migrations"
# Attached to migrate only: returns once it exits, after db became healthy (depends_on).
timeout 400 docker compose "${COMPOSE_ARGS[@]}" up migrate >"$E2E_LOG_DIR/migrate-run.log" 2>&1 \
  || fail "migrate failed"
[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"
start_console "sign-up off, group and domain filters"

log "bootstrapping the local administrator"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps bootstrap-admin \
  >"$E2E_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"
phase_done start

# --------------------------------------------------------------------------- scenario
# Superuser psql in the db container, read-only (every transaction; the scenario checks it).
E2E_PSQL="$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' timeout 30 docker compose \
  "${COMPOSE_ARGS[@]}" exec -T -e "PGOPTIONS=-c default_transaction_read_only=on" db \
  psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion)"
export E2E_PSQL
scenario() {
  timeout 600 python3 "$SCENARIO" "$1" --console-url "$BASE_URL" --issuer "$ISSUER" --ca-file "$T/ca.crt" \
    --secrets "$S" --patterns "$OP" --state "$E2E_WORK_DIR/scenario-state.json"
}

log "scenario, sign-up off"
scenario signup-off || fail "OIDC scenario (sign-up off) failed"
phase_done signup-off

# The logs of the first web container go before it is replaced.
dump_logs -signup-off
# ADR-0038 decision 11: started before bootstrap-admin, with no local administrator yet, the web
# process logged the break-glass error; restarted afterwards, it must not.
BREAK_GLASS_ERROR="no enabled local administrator with a password exists"
grep -qF "$BREAK_GLASS_ERROR" "$E2E_LOG_DIR/web-signup-off.log" || fail "no break-glass startup error without a local administrator"
grep -qF '"msg":"OIDC provider discovered"' "$E2E_LOG_DIR/web-signup-off.log" || fail "the console did not log the provider discovery"
log "restarting the console: sign-up on, no group or domain filter, refresh tokens kept"
export E2E_OIDC_ALLOW_SIGN_UP=1 E2E_OIDC_ALLOWED_GROUPS="" E2E_OIDC_ALLOWED_DOMAINS="" E2E_OIDC_USE_REFRESH_TOKEN=1
start_console "sign-up on, no filters"
log "scenario, sign-up on"
scenario signup-on || fail "OIDC scenario (sign-up on) failed"
phase_done signup-on

# --------------------------------------------------------------------------- secret hygiene
log "checking the logs and the console database for secrets and one-time OIDC values"
dump_logs
! grep -qF "$BREAK_GLASS_ERROR" "$E2E_LOG_DIR/web.log" || fail "break-glass startup error although e2e-admin exists"
D="$E2E_WORK_DIR/dump"
mkdir -p "$D"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T db pg_dump -U postgres --no-owner databastion \
  >"$D/console.sql" || fail "pg_dump of the console database failed"
grep -q 'user_identities' "$D/console.sql" || fail "empty console database dump"
# Positive controls: the dump holds what the scenario stored (the issuer of the bound identities),
# and the scenario recorded the one-time values it saw.
grep -qF "$ISSUER" "$D/console.sql" || fail "issuer not found in the console database dump (scan control)"
[ "$(find "$OP" -type f | wc -l)" -ge 20 ] || fail "too few one-time values recorded by the scenario"
# The proxy's access log records the callback URLs: the scan must find their codes and states there.
! leak_scan "$E2E_LOG_DIR/proxy.log" "$OP/url" >/dev/null || fail "no authorization code or state in the proxy log (scan control)"
leaks=0
leak_scan "$E2E_LOG_DIR" "$P" || leaks=1
leak_scan "$D" "$P" || leaks=1
# One-time values: everywhere but the TLS proxy's access log for those carried in URLs.
leak_scan "$E2E_LOG_DIR" "$OP" || leaks=1
leak_scan "$D" "$OP" || leaks=1
leak_scan "$D" "$OP/url" || leaks=1
for f in "$E2E_LOG_DIR"/{web,db,migrate,keycloak}*.log "$E2E_LOG_DIR/bootstrap-admin.log"; do
  [ -f "$f" ] || continue
  leak_scan "$f" "$OP/url" || leaks=1
  leak_scan "$f" "$OP/sid" || leaks=1
done
# Tokens the scenario never sees (the console exchanges the code itself): id_token, access and
# refresh tokens, all JWTs at Keycloak. No JWT may appear in the console's or Keycloak's logs nor in
# the console database (the refresh tokens of DATABASTION_OIDC_USE_REFRESH_TOKEN=1 are stored as
# AES-256-GCM blobs, bytea, so their dump is hex), except the scenario's own Keycloak admin tokens,
# reported by the scan above if they leaked anywhere.
JWT_RE='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'
cat "$OP"/keycloak_admin_token_* | grep -oE "$JWT_RE" | sort -u >"$E2E_WORK_DIR/admin-jwt-prefixes"
[ -s "$E2E_WORK_DIR/admin-jwt-prefixes" ] || fail "the JWT scan does not recognize the Keycloak admin token (scan control)"
jwts="$(LC_ALL=C grep -ohE "$JWT_RE" "$E2E_LOG_DIR"/web*.log "$E2E_LOG_DIR"/keycloak*.log "$D/console.sql" 2>/dev/null \
  | grep -cvxFf "$E2E_WORK_DIR/admin-jwt-prefixes" || true)"
if [ "$jwts" != 0 ]; then
  log "JWT-shaped values found in: $(LC_ALL=C grep -lE "$JWT_RE" "$E2E_LOG_DIR"/web*.log "$E2E_LOG_DIR"/keycloak*.log "$D/console.sql" \
    2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')"
  leaks=1
fi
# Nor a token field in clear in the database.
! LC_ALL=C grep -qE '"(id_token|access_token|refresh_token)"' "$D/console.sql" || { log "token field in the console database dump"; leaks=1; }
[ "$leaks" = 0 ] || fail "secret or one-time OIDC value found (pattern names and files above)"
phase_done hygiene
