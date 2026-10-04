#!/usr/bin/env bash
# End-to-end CAS target (ROADMAP P8-D, ADR-0041 decisions 3, 5, 6, 10 and 14; ADR-0042, ADR-0043):
# the console and the agent (the e2e images) with the CAS 8.0 dev overlay (dev/cas) and the
# PostgreSQL that holds its JPA ticket registry. Compose: docker-compose.yml merged with
# docker-compose.cas.yml (project databastion-e2e-cas); the CAS traffic comes from
# e2e/cas_scenario.py on the host. Checks:
#   - the console lists `engine.cas`: the agent reports the `cas` target (engine `cas`, reachable),
#     audit level None before any record, then Partial with the honest notes (never Full); the
#     PostgreSQL target `casdb-e2e` holding the ticket table;
#   - Discovery of the registry and of the audit trail against dev/ground-truth.json (every
#     expected classifier, no negative control, the audit trail's `who`), and
#     `security.client_secrets_in_clear`;
#   - Audit: successful logins (`connect`, principals fingerprinted, `svc-monitoring` in clear),
#     service tickets (`read` on the service `Intranet`, the object-form `what` of CAS 8.0), a
#     credential-stuffing burst from one address (`auth_failure`, the `*` aggregate with
#     `volume.failed_logins_many_accounts`), client addresses truncated to their /24; incidents from
#     two access_event policies;
#   - the CAS store guard on the real JPA table `cas_tickets` (ADR-0041 decisions 5, 6): metadata
#     only, tickets encrypted, column grants only (no `privilege.ticket_credentials_readable`, no
#     `security.ticket_registry_unencrypted`); then, CAS restarted with clear tickets, a copy of the
#     table under another name readable in full (recognized by its column shape, never sampled:
#     `privilege.ticket_credentials_readable`), a plain table holding the run's service tickets (the
#     tripwire: `coverage.cas_guard_tripped`) and `security.ticket_registry_unencrypted`;
#   - I2: no ground-truth value of the `cas` engine (`never_sampled` client secrets and header
#     included) in the console database, the console and agent logs, the findings page or the Audit
#     pages; no ticket id, ticket-granting cookie, nor SHA-256 / SHA-512 of a ticket of this run in the
#     console database, the console and agent logs or the agent's state (spool, cursors); no typed name
#     of a failed login (fingerprints only), no password; no generated secret anywhere.
# See e2e/README.md "CAS target". Requires: docker (compose v2.24+), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
export E2E_CAS_PORT="${E2E_CAS_PORT:-8281}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-cas}"
PROJECT="databastion-e2e-cas"
HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
CAS_BASE="http://127.0.0.1:${E2E_CAS_PORT}/cas"
I2_CHECK="$HERE/i2_check.py"
SCENARIO="$HERE/cas_scenario.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
CAS_TARGET="cas-e2e"
DB_TARGET="casdb-e2e"
# The registered CAS service of the logins (dev/cas/services/Intranet-1001.json) and the static
# users of dev/cas/config/cas.properties: the e-mail logins are ground-truth values (the audit
# trail's `who`), svc-monitoring is declared in `clear_principals`.
SERVICE="https://intranet.example.org/login"
SERVICE_NAME="Intranet"
USERS=(camille.martin@example.org hugo.durand@example.net olivia.smith@example.com)
CLEAR_PRINCIPAL="svc-monitoring"
FAILURES=20               # distinct names: 16 own events, the 16th signalled, then the `*` aggregate
POLICY_READS="e2e cas service tickets"
POLICY_STUFFING="e2e cas credential stuffing"
CAS_TIMEOUT_S=300         # CAS start (overlay war, JPA, OIDC keystore)
TABLE_TIMEOUT_S=180       # cas_tickets created by CAS (lazily)
SCAN_TIMEOUT_S=300
EVENTS_TIMEOUT_S=240
SPOOL_TIMEOUT_S=90
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log() { printf '[e2e-cas %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
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

unset E2E_CAS_TICKET_CRYPTO
for tool in docker openssl curl jq timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

# The CAS image is the dev service's (dev/docker-compose.yml): the same tag, built from dev/cas.
dev_cas="$(sed -n 's/^    image: \(databastion-dev\/cas:[^ ]*\)$/\1/p' "$HERE/../dev/docker-compose.yml")"
e2e_cas="$(sed -n 's/.*E2E_CAS_IMAGE:-\(databastion-dev\/cas:[^}]*\)}.*/\1/p' "$HERE/docker-compose.cas.yml")"
[ -n "$dev_cas" ] && [ "$dev_cas" = "$e2e_cas" ] \
  || fail "the CAS image of docker-compose.cas.yml must be the one of dev/docker-compose.yml"
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_CAS_IMAGE
fi

# I2 scanner positive control, before anything starts: every searchable `cas` value of the ground
# truth is in the committed sources CAS and the agent read (the registry, and the static users of
# cas.properties for the audit trail's `who`).
timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine cas \
  "$HERE/../dev/cas/services" "$HERE/../dev/cas/config/cas.properties" >&2 \
  || fail "I2 scanner positive control failed for cas (see above)"

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-cas.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"

# --------------------------------------------------------------------------- registries
# As in run.sh: one file per value, read by grep -Ff and awk, never on a command line.
#   $P   generated secrets and the passwords typed at failed logins (masked in the job log)
#   $TP  one-time values of this run: service tickets, their SHA-256 / SHA-512, the
#        ticket-granting cookies (cas_scenario.py logins)
#   $NP  names typed at the failed logins: they reach the console as fingerprints only
P="$E2E_WORK_DIR/secret-patterns"
TP="$E2E_WORK_DIR/ticket-patterns"
NP="$E2E_WORK_DIR/name-patterns"
mkdir -p "$P" "$TP" "$NP"
register_secret() {
  local name="$1" value="$2"
  [ -n "$value" ] && [ "$value" != null ] || return 0
  printf '%s\n' "$value" >"$P/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}
# Values written by the scenario: masked in the job log too.
mask_dir() {
  local f
  [ "${GITHUB_ACTIONS:-}" = true ] || return 0
  for f in "$1"/*; do [ -f "$f" ] && echo "::add-mask::$(head -n 1 "$f")"; done
}

# leak_scan TARGET PATTERN_DIR: "<name>: <files>" per pattern found (fixed strings; names only).
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

COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.cas.yml")
compose() { timeout 120 docker compose "${COMPOSE_ARGS[@]}" "$@"; }
SERVICES=(db migrate web worker proxy cas-db cas agent)

dump_logs() {
  local svc
  for svc in "${SERVICES[@]}"; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc.log" 2>&1 || true
  done
}

# redact_cas_keys DIR: the keys CAS logs as `Generated ... key [<key>]` in the CAS logs of DIR.
redact_cas_keys() {
  local f
  for f in "$1"/cas*.log; do
    [ -f "$f" ] || continue
    sed -E -i 's/(Generated [A-Za-z ]*key )\[[^]]*\]/\1[<REDACTED:cas_generated_key>]/g' "$f" || rm -f -- "$f"
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
  redact_dir "$E2E_LOG_DIR" "$TP"
  redact_dir "$E2E_LOG_DIR" "$NP"
  # CAS prints the ticket, cookie and webflow keys it generates at each start (no key is configured:
  # dev only); they die with the container, but are not kept in the logs either.
  redact_cas_keys "$E2E_LOG_DIR"
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
mkdir -p "$E2E_WORK_DIR/secrets" "$E2E_WORK_DIR/tls" "$E2E_WORK_DIR/agent"
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
put_secret admin_password "$(rand_hex 24)"
put_secret target_agent_password "$(rand_hex 24)"   # databastion_agent on cas-db (ADR-0012 minimal)
put_secret cas_db_admin_password "$(rand_hex 24)"   # cas-db superuser: stays in cas-db
put_secret cas_db_password "$(rand_hex 24)"         # role `cas` (the JPA ticket registry's)
put_secret cas_user_password "$(rand_hex 24)"       # every static CAS user
umask 022
printf 'postgresql://databastion_owner:%s@db:5432/databastion' "$DB_OWNER_PASSWORD" >"$S/db_owner_url"
printf 'postgresql://databastion_runtime:%s@db:5432/databastion' "$DB_APP_PASSWORD" >"$S/db_url"
umask 077
unset DB_OWNER_PASSWORD DB_APP_PASSWORD
chmod 0700 "$S"

# --------------------------------------------------------------------------- test CA
log "generating the throwaway test CA and the proxy certificate"
T="$E2E_WORK_DIR/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion e2e CAS test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$T/ca.key" -out "$T/ca.crt" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=${HOSTNAME_CONSOLE}" -keyout "$T/server.key" -out "$T/server.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
  "$HOSTNAME_CONSOLE" >"$T/server.ext"
openssl x509 -req -in "$T/server.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$T/server.ext" -out "$T/server.crt" 2>/dev/null
rm -f "$T/ca.key" "$T/server.csr" "$T/server.ext" "$T/ca.srl"
chmod 0644 "$T/ca.crt" "$T/server.crt" "$T/server.key"
# Every service of docker-compose.yml is interpolated, even those this run never starts: their
# bind-mount sources must name something (empty files, never mounted).
for f in mysql-ca.pem mariadb-ca.pem ldap-ca.pem mailpit.crt mailpit.key; do : >"$T/$f"; done

# --------------------------------------------------------------------------- agent.yaml
# cas-e2e: the registry and the audit log, read-only mounts of the CAS volumes (the agent's group
# reads them, nothing is writable by it: ADR-0041 decision 3, ADR-0043). casdb-e2e: the ticket
# registry's database, as the ADR-0012 minimal role; no TLS on the internal network (explicit opt-in).
# The CAS store guard is on by default: `cas_tickets` is one of its built-in names.
cat >"$E2E_WORK_DIR/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  max_sample_rows: 100
  statement_timeout_ms: 5000
  max_scan_duration_s: 300
targets:
  - id: ${CAS_TARGET}
    engine: cas
    cas:
      service_registry:
        json_dir: /srv/cas/services
      audit_log:
        path: /var/log/cas/cas_audit.log
      clear_principals: [${CLEAR_PRINCIPAL}]
  - id: ${DB_TARGET}
    engine: postgres
    host: cas-db
    port: 5432
    account: databastion_agent
    secret:
      file: /run/databastion-secrets/target_agent_password
    postgres:
      databases: [cas]
      tls: disable_insecure
EOF
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# --------------------------------------------------------------------------- HTTP helpers
CURL=(curl -sS --noproxy '*' --max-time 40 --cacert "$T/ca.crt"
  --resolve "${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}:127.0.0.1"
  -b "$E2E_WORK_DIR/cookies" -c "$E2E_WORK_DIR/cookies")
CSRF=""
# api METHOD PATH [BODY_FILE] -> prints "<status>\n<body>"; body never logged.
api() {
  local method="$1" path="$2" body="${3:-}" out="$E2E_WORK_DIR/resp" code
  local args=(-X "$method" -o "$out" -w '%{http_code}' -H "Origin: ${BASE_URL}")
  [ -n "$CSRF" ] && args+=(-H "@$E2E_WORK_DIR/csrf.hdr")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  code="$("${CURL[@]}" "${args[@]}" "${BASE_URL}${path}")" || code="000"
  printf '%s\n' "$code"
  cat "$out" 2>/dev/null || true
}
status_of() { head -n1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }
api_json() { printf '%s' "$3" >"$E2E_WORK_DIR/req.json"; api "$1" "$2" "$E2E_WORK_DIR/req.json"; }
console_sql() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" exec -T db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
# casdb_sql SQL: as the superuser of cas-db (database cas).
casdb_sql() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" exec -T cas-db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d cas -c "$1"
}
files_root() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    --entrypoint /bin/sh agent-files -euc "$1"
}
files_agent() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    --user 10001:10001 --entrypoint /bin/sh agent-files -euc "$1"
}
# cas_files USER SHELL: busybox with the two CAS volumes (cas-files service), no network.
cas_files() {
  local caps=()
  [ "${1%%:*}" = 0 ] || caps=(--cap-drop ALL)
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps "${caps[@]}" \
    -u "$1" --entrypoint sh cas-files -euc "$2"
}
scenario() { timeout 600 python3 "$SCENARIO" "$@" --base "$CAS_BASE"; }

# --------------------------------------------------------------------------- build + start
# E2E_SKIP_BUILD=1 (local runs only): the console, agent and CAS images as already built
# (E2E_CONSOLE_IMAGE / E2E_AGENT_IMAGE / E2E_CAS_IMAGE name other tags). CI always builds; the CAS
# overlay build resolves its modules from Maven Central (locked, SHA-256 verified, dev/cas).
IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}"
  "${E2E_CAS_IMAGE:-databastion-dev/cas:8.0.2-overlay}")
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing images ${IMAGES[*]}"
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "E2E_SKIP_BUILD=1 but image $img is missing"
  done
else
  log "building images (web, agent, cas)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent cas
fi
phase_done build

log "staging the CAS registry and audit log volumes (ADR-0041 decision 6 permissions)"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps cas-files \
  >"$E2E_LOG_DIR/cas-files.log" 2>&1 || fail "cas-files failed (see cas-files.log)"
log "starting the console, cas-db and CAS"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy cas-db cas
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done
[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"
# No secret in the CAS container's environment (the wrapper exports them to the CAS process only).
docker inspect "$(compose ps -q cas)" --format '{{json .Config.Env}}' \
  | jq -e 'any(test("PASSWORD")) | not' >/dev/null || fail "a password in the CAS container's environment"
phase_done start

# --------------------------------------------------------------------------- admin + token
log "bootstrapping the administrator and logging in"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps bootstrap-admin \
  >"$E2E_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"
jq -n --rawfile p "$S/admin_password" '{username: "e2e-admin", password: $p}' >"$E2E_WORK_DIR/login.json"
r="$(api POST /api/auth/login "$E2E_WORK_DIR/login.json")"
rm -f "$E2E_WORK_DIR/login.json"
[ "$(status_of "$r")" = 200 ] || fail "login: HTTP $(status_of "$r")"
CSRF="$(body_of "$r" | jq -r '.csrf_token')"
register_secret csrf_token "$CSRF"
printf 'X-CSRF-Token: %s\n' "$CSRF" >"$E2E_WORK_DIR/csrf.hdr"
register_secret session_cookie "$(awk '$6 ~ /databastion_session$/ {print $7}' "$E2E_WORK_DIR/cookies")"
printf '{"label":"e2e-cas"}' >"$E2E_WORK_DIR/token-req.json"
r="$(api POST /api/enrollment-tokens "$E2E_WORK_DIR/token-req.json")"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
register_secret enrollment_token "$ENROLLMENT_TOKEN"

# --------------------------------------------------------------------------- CAS ready
log "waiting for CAS (at most ${CAS_TIMEOUT_S} s) and for its ticket table"
deadline=$(( $(date +%s) + CAS_TIMEOUT_S ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q cas)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "CAS not healthy within ${CAS_TIMEOUT_S} s"
  sleep 3
done
# CAS creates cas_tickets lazily (its ticket cleaner's first run, about 30 s after the start): no
# login before the agent's Audit stream runs, so the trail starts with this run's actions.
deadline=$(( $(date +%s) + TABLE_TIMEOUT_S ))
until [ "$(casdb_sql "SELECT to_regclass('public.cas_tickets') IS NOT NULL")" = t ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no table cas_tickets in cas-db within ${TABLE_TIMEOUT_S} s"
  sleep 2
done
# ADR-0041 decision 6: column grants only, never the table.
casdb_sql "REVOKE ALL ON public.cas_tickets FROM PUBLIC, databastion_agent;
  GRANT SELECT (type, creation_time, expiration_time) ON public.cas_tickets TO databastion_agent" >/dev/null \
  || fail "cannot set the agent's column grants on cas_tickets"
grants="$(casdb_sql "SELECT concat_ws(',', has_table_privilege('databastion_agent', 'public.cas_tickets', 'SELECT'),
    has_column_privilege('databastion_agent', 'public.cas_tickets', 'type', 'SELECT'),
    (SELECT count(*) FROM pg_attribute a WHERE a.attrelid = 'public.cas_tickets'::regclass AND a.attnum > 0
       AND NOT a.attisdropped AND a.attname NOT IN ('type', 'creation_time', 'expiration_time')
       AND has_column_privilege('databastion_agent', a.attrelid, a.attnum, 'SELECT')),
    (SELECT string_agg(attname, '+' ORDER BY attname) FROM pg_attribute WHERE attrelid = 'public.cas_tickets'::regclass
       AND attnum > 0 AND NOT attisdropped AND attname IN ('id', 'type', 'body', 'principal_id', 'parent_id')))")" \
  || fail "cannot read the grants on cas_tickets"
[ "$grants" = "f,t,0,body+id+parent_id+principal_id+type" ] \
  || fail "unexpected cas_tickets shape or grants ($grants): the JPA mapping changed?"
# The registry and the audit log as staged (ADR-0041 decision 6): owner the CAS user (10041), group
# the agent's (10001); directories 0750 (the log directory setgid), files 0640 with one link.
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
cas_files 0:0 'stat -c "%n %a %u %g %h" /state/cas/services /state/logs/cas /state/logs/cas/cas_audit.log /state/cas/services/*' \
  >"$E2E_WORK_DIR/perms.txt" || fail "cannot stat the CAS files"
n_files=0
while read -r name mode uid gid links; do
  case "$name" in
    /state/cas/services) want=750 ;;
    /state/logs/cas) want=2750 ;;
    *) want=640; [ "$links" = 1 ] || fail "CAS file $name has $links links"
       [[ "$name" == /state/cas/services/*.json ]] && n_files=$((n_files + 1)) ;;
  esac
  [ "$mode $uid $gid" = "$want 10041 10001" ] || fail "CAS file $name is '$mode $uid $gid', expected '$want 10041 10001'"
done <"$E2E_WORK_DIR/perms.txt"
[ "$n_files" = "$(find "$HERE/../dev/cas/services" -name '*.json' | wc -l)" ] || fail "the registry holds $n_files definition(s)"
rm -f -- "$E2E_WORK_DIR/perms.txt"
phase_done cas

# --------------------------------------------------------------------------- enroll + run
log "enrolling the agent"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent --version \
  >"$E2E_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
files_agent 'umask 077; cat > /secrets/target_agent_password' <"$S/target_agent_password"
printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'
timeout 120 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent \
  enroll --config /etc/databastion/agent.yaml --token-file /run/databastion-secrets/enrollment_token \
  >"$E2E_LOG_DIR/agent-enroll.log" 2>&1 || fail "agent enroll failed (see agent-enroll.log)"
files_agent 'rm -f /secrets/enrollment_token'
identity="$(files_agent 'cat /state/identity.json')"
AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
register_secret agent_secret "$(jq -r '.agent_secret' <<<"$identity")"
unset identity
[[ "$AGENT_ID" =~ $UUID_RE ]] || fail "no agent id"
log "enrolled agent $AGENT_ID; starting it"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent

agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}
target_json() { agent_json | jq -c --arg t "$1" '.targets[] | select(.targetId == $t)'; }
notes_of() { jq -r '[.notes[]?.code] | sort | join(" ")' <<<"$1"; }
# The console lists engine.cas: the agent reports the cas target (ADR-0042 decision 1 holds it back
# from a console that does not). Before any login, the trail has no record: level None.
log "waiting for the agent to be online with ${CAS_TARGET} (engine cas) and ${DB_TARGET} reachable"
deadline=$(( $(date +%s) + 90 ))
until a="$(agent_json 2>/dev/null)" && jq -e --arg c "$CAS_TARGET" --arg d "$DB_TARGET" '.status == "online"
    and any(.targets[]; .targetId == $c and .engine == "cas" and .present and .reachable == true and .auditLevel != null)
    and any(.targets[]; .targetId == $d and .engine == "postgres" and .present and .reachable == true)' \
    <<<"$a" >/dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "agent not online with ${CAS_TARGET} and ${DB_TARGET} within 90 s ($(jq -c '[.targets[]? | {targetId, engine, present, reachable, lastError}]' <<<"${a:-{\}}" 2>/dev/null || true))"
  sleep 2
done
t="$(jq -c --arg c "$CAS_TARGET" '.targets[] | select(.targetId == $c)' <<<"$a")"
log "target ${CAS_TARGET}: $(jq -c '{engine, reachable, auditLevel, auditSource, notes: [.notes[]?.code]}' <<<"$t")"
jq -e '.auditLevel == "none"' <<<"$t" >/dev/null || fail "${CAS_TARGET}: audit level $(jq -r .auditLevel <<<"$t") before any audit record, expected none"
[[ " $(notes_of "$t") " == *" audit.limited_pending_first_record "* ]] \
  || fail "${CAS_TARGET}: no audit.limited_pending_first_record before any audit record"
log "target ${DB_TARGET}: $(target_json "$DB_TARGET" | jq -c '{engine, reachable, auditLevel, notes: [.notes[]?.code]}')"
phase_done enroll

# --------------------------------------------------------------------------- Audit setup
log "Audit: access_event policies '${POLICY_READS}' (read) and '${POLICY_STUFFING}' (volume.failed_logins_many_accounts)"
r="$(api_json POST /api/policies "$(jq -nc --arg n "$POLICY_READS" --arg t "$CAS_TARGET" '{name: $n,
  description: "Service tickets issued by the CAS e2e target", source: "access_event",
  conditions: {event_actions: ["read"], target_ids: [$t]},
  actions: [{type: "create_incident", severity: "medium"}]}')")"
[ "$(status_of "$r")" = 201 ] || fail "policy '${POLICY_READS}': HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
r="$(api_json POST /api/policies "$(jq -nc --arg n "$POLICY_STUFFING" --arg t "$CAS_TARGET" '{name: $n,
  description: "Credential stuffing on the CAS e2e target", source: "access_event",
  conditions: {signals: ["volume.failed_logins_many_accounts"], target_ids: [$t]},
  actions: [{type: "create_incident", severity: "critical"}]}')")"
[ "$(status_of "$r")" = 201 ] || fail "policy '${POLICY_STUFFING}': HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"

agent_log_count() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
    | grep -F "$1" | grep -cF "\"target_id\":\"$2\"" || true
}
wait_job() {
  local id="$1" label="$2" deadline job
  deadline=$(( $(date +%s) + $3 ))
  while :; do
    job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '$id'")" \
      || fail "cannot read the status of the $label job"
    case "$job" in
      succeeded,*) return 0 ;;
      failed,* | cancelled,* | expired,*) fail "$label job ended '$job'" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "$label job not succeeded within $3 s (status '$job')"
    sleep 1
  done
}
log "Audit: enabling Audit on ${CAS_TARGET}"
prev="$(agent_log_count "audit stream started" "$CAS_TARGET")"
r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${CAS_TARGET}/audit" '{"enabled":true,"derive_from_findings":true}')"
if [ "$(status_of "$r")" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
  digest="$(body_of "$r" | jq -r '.digest')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "audit.configure: no confirmation digest"
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${CAS_TARGET}/audit" \
    "{\"enabled\":true,\"derive_from_findings\":true,\"confirm\":\"${digest}\"}")"
fi
[ "$(status_of "$r")" = 202 ] || fail "audit.configure: HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
job_id="$(body_of "$r" | jq -r '.job_id')"
[[ "$job_id" =~ $UUID_RE ]] || fail "audit.configure: no job id"
wait_job "$job_id" "audit.configure" 90
deadline=$(( $(date +%s) + 90 ))
until [ "$(agent_log_count "audit stream started" "$CAS_TARGET")" -gt "$prev" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the agent did not start the Audit stream of ${CAS_TARGET} within 90 s"
  sleep 1
done
# The stream opens the log right after that line, at its end: leave it that moment.
sleep 5
phase_done audit-setup

# --------------------------------------------------------------------------- CAS traffic
# One login per user and round, each with a validated service ticket for Intranet; the clear
# principal once; then the credential-stuffing burst from this host (one client address).
log "CAS: logins with service tickets (${#USERS[@]} users x 2 rounds, ${CLEAR_PRINCIPAL} once), then ${FAILURES} failed logins"
user_args=()
for u in "${USERS[@]}"; do user_args+=(--user "$u"); done
out="$(scenario logins --password-file "$S/cas_user_password" "${user_args[@]}" --service "$SERVICE" \
  --rounds 2 --patterns "$TP")" || fail "CAS logins failed (see above)"
log "CAS logins: $out"
out="$(scenario logins --password-file "$S/cas_user_password" --user "$CLEAR_PRINCIPAL" --service "$SERVICE" \
  --patterns "$TP")" || fail "CAS login of ${CLEAR_PRINCIPAL} failed (see above)"
out="$(scenario failures --count "$FAILURES" --patterns "$P" --names "$NP")" || fail "CAS failed logins (see above)"
log "CAS failures: $out"
mask_dir "$TP"
mask_dir "$NP"
mask_dir "$P"
N_ST="$(find "$TP" -name 'st_*' ! -name '*_sha*' | wc -l)"
[ "$N_ST" = $(( ${#USERS[@]} * 2 + 1 )) ] || fail "expected $(( ${#USERS[@]} * 2 + 1 )) service tickets, got $N_ST"
[ "$(find "$NP" -type f | wc -l)" = "$FAILURES" ] || fail "expected ${FAILURES} typed names"
T_TRAFFIC="$(date +%s)"
phase_done traffic

# --------------------------------------------------------------------------- Discovery
SCAN_REQ="$E2E_WORK_DIR/scan-req.json"
printf '{"sample_rows":100,"max_duration_s":300,"statement_timeout_ms":5000}' >"$SCAN_REQ"
# scan TARGET...: one discovery.scan per target (together), each must succeed; then a heartbeat
# after the last one reports an empty spool, nothing dropped.
scan() {
  local target job_id job ids=() deadline spool
  for target in "$@"; do
    r="$(api POST "/api/agents/${AGENT_ID}/targets/${target}/scan" "$SCAN_REQ")"
    [ "$(status_of "$r")" = 202 ] || fail "scan request ($target): HTTP $(status_of "$r")"
    job_id="$(body_of "$r" | jq -r '.job_id')"
    [[ "$job_id" =~ $UUID_RE ]] || fail "scan request ($target): no job id"
    ids+=("$job_id")
  done
  deadline=$(( $(date +%s) + SCAN_TIMEOUT_S ))
  for job_id in "${ids[@]}"; do
    while :; do
      job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '$job_id'")"
      case "$job" in
        succeeded,*) break ;;
        failed,* | cancelled,* | expired,*) fail "scan job $job_id ended '$job'" ;;
      esac
      [ "$(date +%s)" -lt "$deadline" ] || fail "scan job $job_id not succeeded within ${SCAN_TIMEOUT_S} s ('$job')"
      sleep 2
    done
  done
  local list
  list="$(printf "'%s'," "${ids[@]}")"
  deadline=$(( $(date +%s) + SPOOL_TIMEOUT_S ))
  while :; do
    spool="$(console_sql "SELECT concat_ws(',', a.last_seen_at > max(j.finished_at) + interval '1 second',
        coalesce(a.spool->>'batches', 'none'), coalesce(a.spool->>'dropped_batches', '0'),
        coalesce(a.spool->>'dropped_items', '0'), coalesce(a.spool->>'held_batches', '0'))
      FROM agents a JOIN jobs j ON j.agent_id = a.id
      WHERE a.id = '${AGENT_ID}' AND j.id IN (${list%,}) GROUP BY a.id HAVING count(j.finished_at) = ${#ids[@]}")"
    case "$spool" in
      t,0,0,0,*) break ;;
      t,*,*,*,*) IFS=, read -r _ _ db di _ <<<"$spool"
        [ "$db" = 0 ] && [ "$di" = 0 ] || fail "the agent dropped results ($spool)" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "no heartbeat with an empty spool within ${SPOOL_TIMEOUT_S} s after the scans ('$spool')"
    sleep 2
  done
}
log "Discovery: ${CAS_TARGET} and ${DB_TARGET}"
scan "$CAS_TARGET" "$DB_TARGET"
findings_json() {
  console_sql "SELECT coalesce(json_agg(json_build_object('database_name', database_name,
      'schema_name', schema_name, 'object_name', object_name, 'field_name', field_name,
      'classifier', classifier) ORDER BY location_key, classifier), '[]')
    FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'"
}
findings_json "$CAS_TARGET" >"$E2E_WORK_DIR/findings-cas.json" || fail "cannot read the findings"
timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine cas \
  --require-expected-classifiers --forbid-negative-controls "$E2E_WORK_DIR/findings-cas.json" >&2 \
  || fail "findings check of ${CAS_TARGET} failed (see above)"
# Every non-negative location of the ground truth found (registry and audit trail; ADR-0041 decision
# 14: contacts, a static release value, a required-attribute value, the trail's `who`), and none
# on a credential field (never_sampled).
jq -e --slurpfile gt "$GROUND_TRUTH" '
  . as $f
  | [$gt[0].locations[] | select(.engine == "cas" and (.expected_classifiers | length) > 0)
     | . as $l | any($f[]; .database_name == $l.database and .schema_name == $l.container
         and .object_name == $l.object and .field_name == $l.field
         and (.classifier as $c | $l.expected_classifiers | index($c)))] | all
  and ([$gt[0].locations[] | select(.engine == "cas" and .never_sampled == true)
     | . as $l | any($f[]; .field_name == $l.field and .object_name == $l.object)] | any | not)' \
  "$E2E_WORK_DIR/findings-cas.json" >/dev/null \
  || fail "${CAS_TARGET}: a ground-truth location has no finding, or a credential field has one"
log "${CAS_TARGET}: $(jq length "$E2E_WORK_DIR/findings-cas.json") finding(s), every expected location found, none on a credential field"
rm -f -- "$E2E_WORK_DIR/findings-cas.json"
phase_done discovery

# --------------------------------------------------------------------------- Audit checks
# Heartbeat level and notes once the stream has read the records: Partial (an authentication and a
# service ticket in the last 24 h, failures seen), never Full.
log "Audit: waiting for the heartbeat level of ${CAS_TARGET} (Partial)"
FORBIDDEN_NOTES="audit.limited_pending_first_record audit.auth_records_not_seen audit.service_ticket_records_not_seen
  audit.auth_failures_not_seen audit.log_not_readable audit.log_format_unsupported audit.records_dropped
  audit.stream_stopped security.audit_headers_logged privilege.registry_writable privilege.config_readable
  coverage.registry_files_skipped check.stage_failed check.timed_out"
deadline=$(( $(date +%s) + 120 ))
while :; do
  t="$(target_json "$CAS_TARGET")"
  notes="$(notes_of "$t")"
  bad=""
  # shellcheck disable=SC2086 # a list of note codes
  for c in $FORBIDDEN_NOTES; do [[ " $notes " != *" $c "* ]] || bad+=" $c"; done
  if jq -e '.auditLevel == "partial" and .auditSource == "cas_audit_log"' <<<"$t" >/dev/null \
      && [[ " $notes " == *" security.client_secrets_in_clear "* ]] && [ -z "$bad" ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "${CAS_TARGET}: level $(jq -r .auditLevel <<<"$t") / source $(jq -r .auditSource <<<"$t"), notes '${notes}' (expected partial, cas_audit_log, security.client_secrets_in_clear, none of:${bad:- the forbidden notes})"
  sleep 3
done
log "${CAS_TARGET}: audit level partial (cas_audit_log); notes: $notes"
jq -e '[.notes[]? | select(.code == "security.client_secrets_in_clear")][0].count == 1' <<<"$t" >/dev/null \
  || fail "${CAS_TARGET}: security.client_secrets_in_clear should count the one clear client secret (HR-Portal)"

events_state() {
  console_sql "SELECT concat_ws(',',
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
       AND action = 'connect' AND db_user IS NULL AND db_user_fingerprint IS NOT NULL),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
       AND action = 'connect' AND db_user = '${CLEAR_PRINCIPAL}'),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
       AND action = 'read' AND objects @> '[{\"database\": \"service_registry\", \"object\": \"${SERVICE_NAME}\"}]'),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
       AND action = 'auth_failure' AND db_user IS NULL AND db_user_fingerprint IS NOT NULL),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
       AND action = 'auth_failure' AND db_user = '*' AND signals ? 'volume.failed_logins_many_accounts'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}' AND policy_name = '${POLICY_READS}'),
    (SELECT count(DISTINCT i.id) FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id
       JOIN access_events e ON e.id = ie.event_id
       WHERE i.agent_id = '${AGENT_ID}' AND i.target_id = '${CAS_TARGET}' AND i.policy_name = '${POLICY_STUFFING}'
         AND e.db_user = '*' AND i.event_signals ? 'volume.failed_logins_many_accounts'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND evaluated_at IS NULL))"
}
# Expected: every login a connect (fingerprinted, the clear principal by name), every service
# ticket a read of Intranet, 16 failures with their own (fingerprinted) principal, the 4 others in
# the `*` aggregate; one incident per policy at least, the stuffing one linked to the `*` aggregate
# (failed logins are deduplicated per client network, ADR-0031 decision 1: the 16th name's event and
# the aggregate share one incident).
N_LOGINS=$(( ${#USERS[@]} * 2 ))
log "Audit: waiting for the events and incidents (at most ${EVENTS_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + EVENTS_TIMEOUT_S ))
while :; do
  st="$(events_state)" || fail "cannot read the Audit state"
  IFS=, read -r n_conn n_clear n_read n_fail n_star n_inc_r n_inc_s n_pending <<<"$st"
  if [ "$n_conn" -ge "$N_LOGINS" ] && [ "$n_clear" -ge 1 ] && [ "$n_read" -ge "$N_ST" ] \
      && [ "$n_fail" -ge 16 ] && [ "$n_star" -ge $(( FAILURES - 16 )) ] && [ "$n_inc_r" -ge 1 ] \
      && [ "$n_inc_s" -ge 1 ] && [ "$n_pending" = 0 ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "Audit: events / incidents incomplete within ${EVENTS_TIMEOUT_S} s: connect ${n_conn}/${N_LOGINS}, ${CLEAR_PRINCIPAL} ${n_clear}/1, reads of ${SERVICE_NAME} ${n_read}/${N_ST}, own failures ${n_fail}/16, '*' aggregate ${n_star}/$(( FAILURES - 16 )), incidents ${n_inc_r} + ${n_inc_s}, not evaluated ${n_pending}"
  sleep 3
done
log "Audit: connect ${n_conn} (fingerprinted) + ${n_clear} (${CLEAR_PRINCIPAL}), reads of ${SERVICE_NAME} ${n_read}, auth_failure ${n_fail} own + ${n_star} in '*', incidents: reads ${n_inc_r}, stuffing ${n_inc_s} ($(( $(date +%s) - T_TRAFFIC )) s after the traffic)"
# Exact counts once everything is in: nothing lost, nothing counted twice.
[ "$n_conn" = "$N_LOGINS" ] && [ "$n_clear" = 1 ] && [ "$n_read" = "$N_ST" ] \
  && [ $(( n_fail + n_star )) = "$FAILURES" ] || fail "Audit: event counts differ from the traffic ($st)"
# The 16th distinct name carries the signal; the aggregate's principal is `*` (ADR-0041 decision 7).
[ "$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'
    AND action = 'auth_failure' AND db_user_fingerprint IS NOT NULL AND signals ? 'volume.failed_logins_many_accounts'")" -ge 1 ] \
  || fail "Audit: no own auth_failure event with volume.failed_logins_many_accounts (the 16th distinct name)"
# Client addresses: IPv4 cut to the /24 (ADR-0041 decision 7, `client_addr: truncated` default).
addrs="$(console_sql "SELECT coalesce(string_agg(DISTINCT coalesce(client_addr, '-'), ' '), '') FROM access_events
    WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'")"
[ -n "$addrs" ] || fail "Audit: no event of ${CAS_TARGET}"
for a in $addrs; do
  [[ "$a" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.0$ ]] || fail "Audit: client address '$a' is not truncated to its /24"
done
# The addresses CAS itself logged (the trail, read as root): never stored in full.
cas_files 0:0 'cat /state/logs/cas/cas_audit.log' >"$E2E_WORK_DIR/cas-audit.log" || fail "cannot read the CAS audit log"
mapfile -t full_ips < <(python3 -c 'import json, sys
ips = set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if isinstance(r, dict) and isinstance(r.get("clientIpAddress"), str):
        ips.add(r["clientIpAddress"])
print("\n".join(sorted(ips)))' "$E2E_WORK_DIR/cas-audit.log")
[ "${#full_ips[@]}" -ge 1 ] || fail "no client address in the CAS audit log"
for ip in "${full_ips[@]}"; do
  [[ "$ip" =~ \.0$ ]] && continue
  [[ " $addrs " != *" $ip "* ]] || fail "Audit: a client address is stored in full"
done
log "Audit: client addresses stored as ${addrs} (CAS logged ${full_ips[*]})"
# Events and incidents through i2_check.py audit: the incidents of both policies, principals as
# fingerprints but the clear one and `*`. The agent has no CAS account (no own-account event).
console_sql "SELECT coalesce(json_agg(json_build_object('db_user', db_user, 'db_user_fingerprint', db_user_fingerprint,
    'action', action, 'objects', objects, 'signals', signals, 'rows', rows, 'source', source,
    'aggregated_count', aggregated_count) ORDER BY ts), '[]')
  FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'" >"$E2E_WORK_DIR/events.json"
console_sql "SELECT coalesce(json_agg(json_build_object('policy_name', policy_name, 'principal', principal,
    'event_signals', event_signals, 'severity', severity) ORDER BY created_at), '[]')
  FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${CAS_TARGET}'" >"$E2E_WORK_DIR/incidents.json"
jq -e 'all(.[]; .source == "cas_audit_log") and all(.[]; .db_user == null or .db_user == "'"$CLEAR_PRINCIPAL"'"
    or (.db_user == "*" and .action == "auth_failure" and (.signals | index("volume.failed_logins_many_accounts"))))' \
  "$E2E_WORK_DIR/events.json" >/dev/null || fail "Audit: an event of ${CAS_TARGET} names a principal in clear (not printed)"
timeout 60 python3 "$I2_CHECK" audit --ground-truth "$GROUND_TRUTH" --engine cas --agent-account databastion \
  --events "$E2E_WORK_DIR/events.json" --incidents "$E2E_WORK_DIR/incidents.json" \
  --require-event "@fingerprint" --require-event "${CLEAR_PRINCIPAL}" \
  --require-event "*:volume.failed_logins_many_accounts" \
  --require-action "@fingerprint:read" --require-action "@fingerprint:auth_failure" \
  --require-incident "${POLICY_READS}:@fingerprint" --require-incident "${POLICY_READS}:${CLEAR_PRINCIPAL}" >&2 \
  || fail "Audit check of ${CAS_TARGET} failed (see above)"
rm -f -- "$E2E_WORK_DIR/events.json" "$E2E_WORK_DIR/incidents.json"
phase_done audit

# --------------------------------------------------------------------------- CAS store guard
# Real JPA table, tickets encrypted (CAS 8.0 default), column grants only.
guard_notes() { notes_of "$(target_json "$DB_TARGET")"; }
log "CAS store guard (${DB_TARGET}): the JPA table cas_tickets, tickets encrypted, column grants only"
rows="$(casdb_sql "SELECT count(*) || ',' || count(*) FILTER (WHERE type ILIKE '%encoded%') FROM public.cas_tickets")"
IFS=, read -r n_rows n_encoded <<<"$rows"
[ "$n_rows" -gt 0 ] && [ "$n_rows" = "$n_encoded" ] \
  || fail "cas_tickets: $n_rows row(s), $n_encoded encoded: expected encoded tickets only (crypto on)"
line="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
  | grep -F 'CAS ticket registry: metadata only' | grep -F "\"target_id\":\"${DB_TARGET}\"" | tail -n 1)"
[ -n "$line" ] || fail "${DB_TARGET}: no 'CAS ticket registry: metadata only' line in the agent log"
python3 -c 'import json, re, sys
m = re.search(r"\{.*\}", sys.argv[1]); d = json.loads(m.group(0)) if m else {}
f = d.get("fields", d)
sys.exit(0 if int(f.get("encrypted", 0)) > 0 and int(f.get("unencrypted", -1)) == 0 else 1)' "$line" \
  || fail "${DB_TARGET}: the ticket counts are not 'encrypted > 0, unencrypted 0'"
grep -qF '"CAS ticket registry: not sampled' <(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null) \
  || fail "${DB_TARGET}: no 'CAS ticket registry: not sampled' line in the agent log"
# The next heartbeat after the scan: no unencrypted note, no readable credential column.
sleep 35
notes="$(guard_notes)"
for c in security.ticket_registry_unencrypted privilege.ticket_credentials_readable coverage.cas_guard_tripped; do
  [[ " $notes " != *" $c "* ]] || fail "${DB_TARGET}: the heartbeat reports $c with encrypted tickets and column grants (notes: $notes)"
done
[ "$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${DB_TARGET}'
    AND object_name = 'cas_tickets'")" = 0 ] || fail "${DB_TARGET}: a finding on cas_tickets"
log "${DB_TARGET}: metadata only (encrypted tickets), notes: ${notes:-none}"
phase_done guard-real

# Clear tickets: CAS restarted with crypto off (its JPA table is kept; the encrypted tickets of the
# previous keys are removed first, as dev/cas/db-init.sh does at each start). Then, with full SELECT,
# a copy of the table under another name (column shape: a ticket registry, never sampled) and a
# plain table holding the run's service tickets (the tripwire).
log "CAS store guard: CAS restarted with clear tickets; a renamed copy of the table and a tripwire table"
casdb_sql "TRUNCATE public.cas_tickets" >/dev/null || fail "cannot empty cas_tickets"
# The first CAS container's log (recreating it drops it from `compose logs`): kept, scanned, redacted.
compose logs --no-color --timestamps cas >"$E2E_LOG_DIR/cas-encrypted-tickets.log" 2>&1 || true
E2E_CAS_TICKET_CRYPTO=false timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps cas
deadline=$(( $(date +%s) + CAS_TIMEOUT_S ))
sleep 5
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q cas)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "CAS (clear tickets) not healthy within ${CAS_TIMEOUT_S} s"
  sleep 3
done
docker inspect "$(compose ps -q cas)" --format '{{json .Config.Env}}' | jq -e 'index("DEV_CAS_TICKET_CRYPTO=false") != null' >/dev/null \
  || fail "CAS was not restarted with clear tickets"
# Service tickets left unvalidated, so that they stay in the table (in clear) for the copy below.
out="$(scenario logins --password-file "$S/cas_user_password" "${user_args[@]}" --service "$SERVICE" \
  --no-validate --patterns "$TP")" || fail "CAS logins (clear tickets) failed (see above)"
# The tripwire table: the service tickets of the whole run, next to plain contact e-mails (positive
# control: the table is sampled, its contact column found). The copy: the ticket table as it is now,
# clear ids, bodies and principals included, under a name the guard does not know.
{
  printf 'CREATE TABLE public.sso_archive AS SELECT * FROM public.cas_tickets;\n'
  printf 'CREATE TABLE public.app_sessions (session_ref text, contact text);\n'
  printf "INSERT INTO public.app_sessions VALUES\n"
  i=0
  for f in "$TP"/st_*; do
    case "$f" in *_sha256|*_sha512) continue ;; esac
    [ "$i" = 0 ] || printf ',\n'
    printf "('%s', 'e2e.contact.%02d@example.org')" "$(head -n 1 "$f")" "$i"
    i=$((i + 1))
  done
  printf ';\nGRANT SELECT ON public.app_sessions, public.sso_archive TO databastion_agent;\n'
} >"$E2E_WORK_DIR/guard.sql"
timeout 30 docker compose "${COMPOSE_ARGS[@]}" exec -T cas-db psql -XAq -v ON_ERROR_STOP=1 -U postgres -d cas \
  <"$E2E_WORK_DIR/guard.sql" >/dev/null || fail "cannot create the renamed copy and the tripwire table"
rm -f -- "$E2E_WORK_DIR/guard.sql"
rows="$(casdb_sql "SELECT count(*) || ',' || count(*) FILTER (WHERE type ILIKE '%encoded%') || ',' ||
    count(*) FILTER (WHERE id LIKE 'TGT-%') || ',' || count(*) FILTER (WHERE id LIKE 'ST-%') FROM public.sso_archive")"
IFS=, read -r n_rows n_encoded n_tgt n_st <<<"$rows"
[ "$n_encoded" = 0 ] && [ "$n_tgt" -ge "${#USERS[@]}" ] && [ "$n_st" -ge "${#USERS[@]}" ] \
  || fail "the copy of cas_tickets: $n_rows row(s), $n_encoded encoded, $n_tgt TGT, $n_st ST: expected clear tickets of every login"
# The run's ticket-granting tickets (in clear in the table now): ticket ids of the run too, searched
# with the service tickets (never printed).
i=0
while IFS= read -r id; do
  [ -n "$id" ] || continue
  printf '%s\n' "$id" >"$TP/tgt_$i"
  printf '%s' "$id" | sha256sum | cut -d' ' -f1 >"$TP/tgt_${i}_sha256"
  printf '%s' "$id" | sha512sum | cut -d' ' -f1 >"$TP/tgt_${i}_sha512"
  i=$((i + 1))
done < <(casdb_sql "SELECT id FROM public.sso_archive WHERE id LIKE 'TGT-%'")
mask_dir "$TP"
# Positive control of the ticket scans: the copy holds service tickets of the run.
casdb_sql "COPY (SELECT id FROM public.sso_archive) TO STDOUT" >"$E2E_WORK_DIR/tickets-control.txt"
grep -c . "$E2E_WORK_DIR/tickets-control.txt" >/dev/null || fail "empty ticket copy"
leak_scan "$E2E_WORK_DIR/tickets-control.txt" "$TP" >/dev/null \
  && fail "ticket scan positive control: no ticket of the run found in the copy of cas_tickets"
rm -f -- "$E2E_WORK_DIR/tickets-control.txt"
scan "$DB_TARGET"
deadline=$(( $(date +%s) + 90 ))
while :; do
  t="$(target_json "$DB_TARGET")"
  notes="$(notes_of "$t")"
  ok=1
  for c in security.ticket_registry_unencrypted privilege.ticket_credentials_readable coverage.cas_guard_tripped; do
    [[ " $notes " == *" $c "* ]] || ok=0
  done
  [ "$ok" = 1 ] && break
  [ "$(date +%s)" -lt "$deadline" ] || fail "${DB_TARGET}: notes '$notes', expected security.ticket_registry_unencrypted, privilege.ticket_credentials_readable and coverage.cas_guard_tripped"
  sleep 3
done
log "${DB_TARGET}: $(jq -c '[.notes[]? | {code, count}]' <<<"$t")"
jq -e '[.notes[] | select(.code == "privilege.ticket_credentials_readable")][0].count == 1' <<<"$t" >/dev/null \
  || fail "${DB_TARGET}: privilege.ticket_credentials_readable should count the renamed copy only (cas_tickets keeps its column grants)"
f="$(console_sql "SELECT concat_ws(',',
    (SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${DB_TARGET}'
       AND object_name IN ('cas_tickets', 'sso_archive')),
    (SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${DB_TARGET}'
       AND object_name = 'app_sessions' AND field_name = 'session_ref'),
    (SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${DB_TARGET}'
       AND object_name = 'app_sessions' AND field_name = 'contact' AND classifier = 'pii.email'))")"
[ "$f" = "0,0,1" ] || fail "${DB_TARGET}: findings on the ticket tables / the tripped column / the contact column: $f (expected 0,0,1)"
log "${DB_TARGET}: no finding on cas_tickets, sso_archive nor app_sessions.session_ref; app_sessions.contact found (positive control)"
phase_done guard-clear

# --------------------------------------------------------------------------- I2 and secret hygiene
log "I2: the console database, the logs, the pages and the agent's state"
dump_logs
for f in agent.log web.log worker.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the scans would prove nothing"
done
D="$E2E_WORK_DIR/dump"
mkdir -p "$D/pages" "$D/state"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T db pg_dump -U postgres -d databastion \
  >"$D/console.sql" 2>/dev/null || fail "pg_dump of the console database failed"
grep -q '^COPY public.findings ' "$D/console.sql" || fail "the console database dump has no findings table"
grep -q '^COPY public.access_events ' "$D/console.sql" || fail "the console database dump has no access_events table"
for table in access_events incidents incident_events principal_baselines audit_configs agent_targets; do
  console_sql "SELECT coalesce(json_agg(t), '[]') FROM ${table} t" >"$D/${table}.json" || fail "cannot export $table"
done
fetch_page() {
  local code
  code="$("${CURL[@]}" -o "$D/pages/$1.html" -w '%{http_code}' "${BASE_URL}$2")" || code=000
  [ "$code" = 200 ] || fail "page $2: HTTP $code"
}
fetch_page findings /findings
fetch_page events /events
fetch_page incidents "/incidents?status=all"
fetch_page agent "/agents/${AGENT_ID}"
fetch_page api-agents /api/agents
# The agent's state volume (spool, audit cursors and settings, identity), read as the agent.
files_agent 'tar -C /state -cf - .' >"$D/state.tar" || fail "cannot read the agent's state"
tar -C "$D/state" -xf "$D/state.tar" && rm -f "$D/state.tar"
log "agent state: $(find "$D/state" -type f | wc -l) file(s)"

i2_failed=0
# Ground-truth values of the cas engine (never_sampled secrets and header included).
# Positive control: one value of the ground truth planted in a canary file must be reported.
mkdir -p "$E2E_WORK_DIR/canary"
jq -r '[.locations[] | select(.engine == "cas" and .never_sampled == true) | .values[]?] | .[0]' "$GROUND_TRUTH" \
  >"$E2E_WORK_DIR/canary/zz-canary.log"
rc=0
timeout 60 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine cas --label canary \
  "$E2E_WORK_DIR/canary" >"$E2E_WORK_DIR/canary.out" 2>&1 || rc=$?
if [ "$rc" != 1 ] || ! grep -q 'file=zz-canary.log$' "$E2E_WORK_DIR/canary.out"; then
  cat "$E2E_WORK_DIR/canary.out" >&2
  fail "I2 scan positive control: canary not detected"
fi
rm -rf -- "$E2E_WORK_DIR/canary" "$E2E_WORK_DIR/canary.out"
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine cas --label "cas console side" \
  "$D" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine cas --label "cas logs" \
  --exclude 'cas.log' --exclude 'cas-encrypted-tickets.log' --exclude 'cas-db.log' --exclude 'cas-files.log' \
  "$E2E_LOG_DIR" >&2 || i2_failed=1
# Ticket ids, ticket-granting cookies and their digests; typed names of failed logins; secrets.
# Positive control of the pattern scans: the canary as in run.sh.
mkdir -p "$E2E_WORK_DIR/canary-pattern"
printf 'e2e-canary-%s\n' "$(rand_hex 16)" >"$E2E_WORK_DIR/canary-pattern/canary"
cp "$E2E_WORK_DIR/canary-pattern/canary" "$E2E_LOG_DIR/zz-canary.log"
[ "$(leak_scan "$E2E_LOG_DIR" "$E2E_WORK_DIR/canary-pattern" || true)" = "canary: zz-canary.log " ] \
  || fail "leak scan positive control: canary not detected"
rm -rf -- "$E2E_LOG_DIR/zz-canary.log" "$E2E_WORK_DIR/canary-pattern"
leaks=0
for pdir in "$TP" "$NP"; do
  if ! leaked="$(leak_scan "$D" "$pdir")"; then
    while IFS= read -r l; do log "LEAK (console side or agent state): $l"; done <<<"$leaked"
    leaks=1
  fi
done
# The generated secrets: everywhere but where they belong by design (the agent's own identity in its
# state; the session's CSRF token in the pages it renders).
mkdir -p "$E2E_WORK_DIR/scan-secrets"
cp "$D"/*.sql "$D"/*.json "$E2E_WORK_DIR/scan-secrets/"
(cd "$D/state" && find . -type f ! -name identity.json -exec cp --parents {} "$E2E_WORK_DIR/scan-secrets/" \;)
[ -f "$D/state/identity.json" ] || fail "no identity.json in the agent's state: the state scan would prove nothing"
if ! leaked="$(leak_scan "$E2E_WORK_DIR/scan-secrets" "$P")"; then
  while IFS= read -r l; do log "LEAK (console database or agent state): $l"; done <<<"$leaked"
  leaks=1
fi
rm -rf -- "$E2E_WORK_DIR/scan-secrets"
for f in "$D"/pages/*; do
  leaked="$(leak_scan "$f" "$P" | grep -v '^csrf_token: ' || true)"
  if [ -n "$leaked" ]; then
    while IFS= read -r l; do log "LEAK (pages): $l"; done <<<"$leaked"
    leaks=1
  fi
done
# Logs: every container but CAS's own and its database (the target side: CAS logs its generated
# keys at start, dev only; cas-db holds the tickets by design).
mkdir -p "$E2E_WORK_DIR/scan-logs"
for f in "$E2E_LOG_DIR"/*; do
  case "$(basename "$f")" in cas.log | cas-encrypted-tickets.log | cas-db.log | cas-files.log) ;; *) cp "$f" "$E2E_WORK_DIR/scan-logs/" ;; esac
done
for pdir in "$TP" "$NP" "$P"; do
  if ! leaked="$(leak_scan "$E2E_WORK_DIR/scan-logs" "$pdir")"; then
    while IFS= read -r l; do log "LEAK (logs): $l"; done <<<"$leaked"
    leaks=1
  fi
done
# The generated secrets are nowhere in the CAS-side logs either.
if ! leaked="$(leak_scan "$E2E_LOG_DIR" "$P")"; then
  while IFS= read -r l; do log "LEAK (CAS-side logs): $l"; done <<<"$leaked"
  leaks=1
fi
rm -rf -- "$E2E_WORK_DIR/scan-logs"
log "I2: $(find "$TP" -type f | wc -l) ticket value(s), $(find "$NP" -type f | wc -l) typed name(s), $(find "$P" -type f | wc -l) secret(s) searched"
rm -rf -- "$D" "$E2E_WORK_DIR/cas-audit.log"
[ "$i2_failed" = 0 ] || fail "invariant I2: ground-truth value(s) of the cas engine in clear text (ids above)"
[ "$leaks" = 0 ] || fail "a ticket, a typed name or a secret reached the console, a log or the agent's state (names above)"
phase_done i2
log "all checks passed"
