#!/usr/bin/env bash
# End-to-end enrollment / revocation test (phase 1 exit criterion):
#   "end-to-end enrollment in containers; revocation effective in < 60 s",
# invariant I2 test (P2-E): a Discovery scan of each seeded target (PostgreSQL, MySQL, MariaDB)
# leaves no ground-truth value in clear text in the console database, the container logs or the
# findings page; and the Audit path (P4-D, phase 4 exit criterion "pg_dump in dev -> incident in
# under 2 minutes"): a real pg_dump of the PostgreSQL target opens an incident through an
# access_event policy in less than 120 s, the agent's own Discovery reads open none, and no
# ground-truth value (including literals put in query text) reaches access events, incidents,
# notifications (the e-mail in Mailpit), the console pages or any log.
# See e2e/README.md. Requires: docker (compose v2), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit. Logs of every container are written to $E2E_LOG_DIR and
# checked for secrets before teardown; whatever the exit path, every registered secret is then
# redacted from them in place (or the file is deleted) before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs}"
REVOCATION_LIMIT_MS=60000
HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
AGENT_401_MESSAGE="console rejected the current secret (401)"
I2_CHECK="$HERE/i2_check.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
SEED_DIR="$HERE/../dev/seed/out"
# Declared targets: "<target id> <ground-truth engine> <committed seed>". The scans run in parallel.
E2E_TARGETS=("pg-e2e postgresql postgres.sql" "mysql-e2e mysql mysql.sql" "mariadb-e2e mariadb mariadb.sql")
# Audit targets (P4-D): "<target id> <ground-truth engine> <client> <agent account> <dump signal>".
# <client> selects the audit_client_<client> helpers below (dump, literal queries, the target's own
# audit log). MariaDB (P4-B, ADR-0023): the server_audit log file, read by the agent. MySQL
# Community has only performance_schema, which needs a grant the minimal e2e account must not have
# (ADR-0023 decision 3); Percona's audit_log_filter would need a fourth target (not covered here).
E2E_AUDIT_TARGETS=("pg-e2e postgresql pg databastion_agent signature.pg_dump"
  "mariadb-e2e mariadb my databastion signature.mysqldump")
AUDIT_POLICY_DUMP="e2e dump signature"    # access_event policy: the target's dump signal
AUDIT_POLICY_READS="e2e reads"            # access_event policy: every read of an Audit target
AUDIT_CHANNEL="e2e-mail"                  # e-mail channel to Mailpit
DUMP_INCIDENT_LIMIT_MS=120000             # phase 4 exit criterion: dump -> incident < 2 min
AUDIT_EVENTS_TIMEOUT_S=240                # client queries -> events stored and evaluated
# Audit source of target-pg. `pgaudit` (default, required under GitHub Actions): the dev image
# (dev/postgres), check() must reach Partial or Full from the pgaudit jsonlog. `pss` (local runs
# only, for hosts whose proxy blocks the apt mirrors that dev/postgres needs): the plain pinned
# image with pg_stat_statements only, Limited level; the Audit path runs the same way, except the
# pgaudit-only checks (source, level, literal positive control in the target's log).
E2E_PG_AUDIT="${E2E_PG_AUDIT:-pgaudit}"
SCAN_TIMEOUT_S=360   # every scan, launched together
TARGET_TIMEOUT_S=240 # target-mysql / target-mariadb initialization (seed, account, TLS)
SPOOL_TIMEOUT_S=90   # three heartbeat intervals (console HEARTBEAT_INTERVAL_S = 30)
MAX_LISTED_FINDINGS=500  # console/src/server/findings.ts: the page lists at most this many
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log() { printf '[e2e %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }

# Phase timings, printed on exit (CI job time budget).
T_RUN="$(date +%s)"
T_PHASE="$T_RUN"
TIMINGS=""
phase_done() {
  local now
  now="$(date +%s)"
  TIMINGS+="$1 $((now - T_PHASE))s; "
  T_PHASE="$now"
}

case "$E2E_PG_AUDIT" in
  pgaudit)
    PG_AUDIT_LEVELS="partial full"; PG_AUDIT_SOURCE="pgaudit"
    PG_AUDIT_STARTED="audit source: pgaudit log" ;;
  pss)
    [ "${GITHUB_ACTIONS:-}" != true ] || fail "E2E_PG_AUDIT=pss is for local runs only"
    # The plain pinned image (no pgaudit): pg_stat_statements only.
    export E2E_TARGET_PG_IMAGE="postgres:17.11-bookworm@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
    export E2E_PG_PRELOAD="pg_stat_statements"
    PG_AUDIT_LEVELS="limited"; PG_AUDIT_SOURCE="pg_stat_statements"
    PG_AUDIT_STARTED="audit source: pg_stat_statements (Limited)" ;;
  *) fail "E2E_PG_AUDIT must be pgaudit or pss" ;;
esac

for tool in docker openssl curl jq timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

# Invariant I2 scanner positive control, before anything starts: for each engine, every searchable
# value of the ground truth (and every value-bearing name) must be visible in the committed seed
# that its target loads. Counts and ids only are printed.
for t in "${E2E_TARGETS[@]}"; do
  read -r _ engine seed <<<"$t"
  timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine "$engine" \
    "$SEED_DIR/$seed" >&2 || fail "I2 scanner positive control failed for $engine (see above)"
done

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"

# --------------------------------------------------------------------------- secret registry
# Every secret is registered as soon as it is generated or obtained: one file per secret,
# $P/<name>, holding its value only. grep -Ff and awk read the value from that file, so it never
# appears on a command line. Under GitHub Actions the value is also masked in the job log.
P="$E2E_WORK_DIR/secret-patterns"
mkdir -p "$P"
register_secret() {
  local name="$1" value="$2"
  # An empty pattern would match every line; "null" is jq's output for a missing field.
  [ -n "$value" ] && [ "$value" != null ] || return 0
  printf '%s\n' "$value" >"$P/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}

# leak_scan DIR PATTERN_DIR: prints "<name>: <files>" for every secret of PATTERN_DIR found in
# DIR (fixed strings; only the secret's name is printed). Returns 1 if any is found.
leak_scan() {
  local dir="$1" pdir="$2" f files found=0
  for f in "$pdir"/*; do
    [ -f "$f" ] || continue
    files="$(LC_ALL=C grep -rlFf "$f" -- "$dir" 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ' || true)"
    if [ -n "$files" ]; then
      printf '%s: %s\n' "$(basename "$f")" "$files"
      found=1
    fi
  done
  return "$found"
}

# Literal (not regex) replacement of the secret read from $SECRET_FILE by $REDACTION.
# shellcheck disable=SC2016 # awk program, not shell
REDACT_AWK='
BEGIN { if ((getline s < ENVIRON["SECRET_FILE"]) <= 0 || s == "") exit 2; rep = ENVIRON["REDACTION"] }
{
  out = ""; line = $0
  while ((i = index(line, s)) > 0) { out = out substr(line, 1, i - 1) rep; line = substr(line, i + length(s)) }
  print out line
}'

# redact_dir DIR PATTERN_DIR: replaces every secret of PATTERN_DIR in the files of DIR, in place,
# by <REDACTED:name>. A file that cannot be rewritten, or still matches afterwards, is deleted.
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

# Every docker call is bounded (`timeout`): a hung daemon cannot stall the job.
compose() { timeout 120 docker compose -f "$HERE/docker-compose.yml" "$@"; }

dump_logs() {
  local svc
  compose logs --no-color --timestamps >"$E2E_LOG_DIR/all.log" 2>&1 || true
  for svc in db migrate web worker proxy mailpit target-pg target-mysql target-mariadb agent; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc.log" 2>&1 || true
  done
}

cleanup() {
  local status=$?
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  # Before teardown and before $E2E_WORK_DIR (the registry) goes away, whatever the exit path.
  redact_dir "$E2E_LOG_DIR" "$P"
  log "tearing down"
  timeout 120 docker compose -f "$HERE/docker-compose.yml" --profile tools down -v --remove-orphans \
    >/dev/null 2>&1
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
# Secret files are bind-mounted into containers running as other uids (postgres, 10001): they
# are 0644 inside a 0700 directory, so only this user (and the containers) can reach them.
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; }
DB_PASSWORD="$(rand_hex 24)"
DB_OWNER_PASSWORD="$(rand_hex 24)"
DB_APP_PASSWORD="$(rand_hex 24)"
ENCRYPTION_KEY="$(openssl rand -base64 32)"
METRICS_TOKEN="$(rand_hex 32)"
ADMIN_PASSWORD="$(rand_hex 24)"
TARGET_PG_PASSWORD="$(rand_hex 24)"     # target superuser: stays in target-pg
TARGET_AGENT_PASSWORD="$(rand_hex 24)"  # databastion_agent (least privilege, read-only)
TARGET_CLIENT_PASSWORD="$(rand_hex 24)" # e2e_exporter / e2e_analyst (Audit test clients)
MAILPIT_PASSWORD="$(rand_hex 24)"       # SMTP AUTH of the console's e-mail channel to Mailpit
TARGET_MYSQL_PASSWORD="$(rand_hex 24)"         # MySQL root: stays in target-mysql
TARGET_MYSQL_AGENT_PASSWORD="$(rand_hex 24)"   # MySQL `databastion` (ADR-0018 minimal)
TARGET_MARIADB_PASSWORD="$(rand_hex 24)"       # MariaDB root: stays in target-mariadb
TARGET_MARIADB_AGENT_PASSWORD="$(rand_hex 24)" # MariaDB `databastion` (ADR-0018 minimal)
register_secret db_password "$DB_PASSWORD"
register_secret db_owner_password "$DB_OWNER_PASSWORD"
register_secret db_app_password "$DB_APP_PASSWORD"
register_secret encryption_key "$ENCRYPTION_KEY"
register_secret metrics_token "$METRICS_TOKEN"
register_secret admin_password "$ADMIN_PASSWORD"
register_secret target_pg_password "$TARGET_PG_PASSWORD"
register_secret target_agent_password "$TARGET_AGENT_PASSWORD"
register_secret target_client_password "$TARGET_CLIENT_PASSWORD"
register_secret mailpit_password "$MAILPIT_PASSWORD"
# As they cross the wire and could be logged: the AUTH PLAIN token and the AUTH LOGIN password.
register_secret mailpit_auth_plain "$(printf '\0e2e-smtp\0%s' "$MAILPIT_PASSWORD" | base64 -w0)"
register_secret mailpit_auth_login "$(printf '%s' "$MAILPIT_PASSWORD" | base64 -w0)"
register_secret target_mysql_password "$TARGET_MYSQL_PASSWORD"
register_secret target_mysql_agent_password "$TARGET_MYSQL_AGENT_PASSWORD"
register_secret target_mariadb_password "$TARGET_MARIADB_PASSWORD"
register_secret target_mariadb_agent_password "$TARGET_MARIADB_AGENT_PASSWORD"
put_secret db_password "$DB_PASSWORD"
put_secret db_owner_password "$DB_OWNER_PASSWORD"
put_secret db_app_password "$DB_APP_PASSWORD"
put_secret db_owner_url "postgresql://databastion_owner:${DB_OWNER_PASSWORD}@db:5432/databastion"
put_secret db_url "postgresql://databastion_runtime:${DB_APP_PASSWORD}@db:5432/databastion"
put_secret encryption_key "$ENCRYPTION_KEY"
put_secret metrics_token "$METRICS_TOKEN"
put_secret admin_password "$ADMIN_PASSWORD"
put_secret target_pg_password "$TARGET_PG_PASSWORD"
put_secret target_agent_password "$TARGET_AGENT_PASSWORD"
put_secret target_client_password "$TARGET_CLIENT_PASSWORD"
put_secret mailpit_auth "e2e-smtp:${MAILPIT_PASSWORD}"
put_secret mailpit_password "$MAILPIT_PASSWORD"
put_secret target_mysql_password "$TARGET_MYSQL_PASSWORD"
put_secret target_mysql_agent_password "$TARGET_MYSQL_AGENT_PASSWORD"
put_secret target_mariadb_password "$TARGET_MARIADB_PASSWORD"
put_secret target_mariadb_agent_password "$TARGET_MARIADB_AGENT_PASSWORD"
chmod 0700 "$S"

# --------------------------------------------------------------------------- test CA
log "generating the throwaway test CA and the proxy certificate"
T="$E2E_WORK_DIR/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion e2e test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$T/ca.key" -out "$T/ca.crt" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=${HOSTNAME_CONSOLE}" -keyout "$T/server.key" -out "$T/server.csr" 2>/dev/null
cat >"$T/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${HOSTNAME_CONSOLE}
EOF
openssl x509 -req -in "$T/server.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$T/server.ext" -out "$T/server.crt" 2>/dev/null
# Mailpit's STARTTLS certificate (the console's e-mail channel verifies it: worker
# NODE_EXTRA_CA_CERTS = this CA).
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=mailpit" -keyout "$T/mailpit.key" -out "$T/mailpit.csr" 2>/dev/null
sed 's/^subjectAltName=.*/subjectAltName=DNS:mailpit/' "$T/server.ext" >"$T/mailpit.ext"
openssl x509 -req -in "$T/mailpit.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$T/mailpit.ext" -out "$T/mailpit.crt" 2>/dev/null
rm -f "$T/ca.key" "$T/server.csr" "$T/server.ext" "$T/mailpit.csr" "$T/mailpit.ext" "$T/ca.srl"
# Readable by the proxy, Mailpit (uid 10001), the worker and the agent through the bind mounts; $T
# itself is 0700.
chmod 0644 "$T/ca.crt" "$T/server.crt" "$T/server.key" "$T/mailpit.crt" "$T/mailpit.key"

# --------------------------------------------------------------------------- agent.yaml
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
  - id: pg-e2e
    engine: postgres
    host: target-pg
    port: 5432
    account: databastion_agent
    secret:
      file: /run/databastion-secrets/target_agent_password
    # target-pg has no TLS; it sits on the internal agent network only: explicit insecure
    # opt-in (the connector still refuses cleartext / MD5 passwords, SCRAM only).
    # Audit (P4-D): the target's jsonlog, mounted read-only from the target-pg-log volume.
    postgres:
      databases: [shop]
      tls: disable_insecure
      audit_log: {path: /var/log/target-pg/postgresql.json, format: jsonlog}
  # ADR-0018 minimal accounts, TLS verified (default verify_full) against the CA that dev's
  # initdb/30-tls.sh created in each target (copied out by this script); the host names are the
  # targets' network aliases, named in their certificates.
  - id: mysql-e2e
    engine: mysql
    host: mysql
    port: 3306
    account: databastion
    secret:
      file: /run/databastion-secrets/target_mysql_agent_password
    mysql:
      tls: verify_full
      ca_file: /etc/databastion/mysql-ca.pem
  - id: mariadb-e2e
    engine: mariadb
    host: mariadb
    port: 3306
    account: databastion
    secret:
      file: /run/databastion-secrets/target_mariadb_agent_password
    mysql:
      tls: verify_full
      ca_file: /etc/databastion/mariadb-ca.pem
      # Audit (P4-D): the server_audit log, mounted read-only from the target-mariadb-log volume.
      audit_log: {path: /var/log/target-mariadb/server_audit.log, format: server_audit}
EOF
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# --------------------------------------------------------------------------- HTTP helpers
CURL=(curl -sS --max-time 40 --cacert "$T/ca.crt"
  --resolve "${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}:127.0.0.1"
  -b "$E2E_WORK_DIR/cookies" -c "$E2E_WORK_DIR/cookies")
CSRF=""
# api METHOD PATH [BODY_FILE] -> prints "<status>\n<body>" ; body never logged.
api() {
  local method="$1" path="$2" body="${3:-}" out="$E2E_WORK_DIR/resp"
  local args=(-X "$method" -o "$out" -w '%{http_code}' -H "Origin: ${BASE_URL}")
  # The CSRF header is read from a 0600 file (curl -H @file) so the token is never on a command line.
  [ -n "$CSRF" ] && args+=(-H "@$E2E_WORK_DIR/csrf.hdr")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  local code
  code="$("${CURL[@]}" "${args[@]}" "${BASE_URL}${path}")" || code="000"
  printf '%s\n' "$code"
  cat "$out" 2>/dev/null || true
}
status_of() { head -n1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }

# --------------------------------------------------------------------------- build + start
# E2E_SKIP_BUILD=1 (local runs only): use the console, agent and (pgaudit mode) target PostgreSQL
# images as already built, e.g. behind a TLS-intercepting proxy that the Dockerfiles cannot trust;
# E2E_CONSOLE_IMAGE / E2E_AGENT_IMAGE / E2E_TARGET_PG_IMAGE name other tags. CI always builds.
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_TARGET_PG_IMAGE
fi
BUILT_IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}")
BUILD_SERVICES=(web agent)
if [ "$E2E_PG_AUDIT" = pgaudit ]; then
  BUILT_IMAGES+=("${E2E_TARGET_PG_IMAGE:-databastion-dev/postgres:17.11-pgaudit}")
  BUILD_SERVICES+=(target-pg)
fi
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing images ${BUILT_IMAGES[*]}"
  for img in "${BUILT_IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "E2E_SKIP_BUILD=1 but image $img is missing"
  done
else
  log "building images (${BUILD_SERVICES[*]})"
  timeout 1500 docker compose -f "$HERE/docker-compose.yml" build "${BUILD_SERVICES[@]}"
fi
log "target-pg Audit source: $E2E_PG_AUDIT"
phase_done build

files_root() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    agent-files "$1"
}
files_agent() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    --user 10001:10001 agent-files "$1"
}

# The target-pg and target-mariadb log volumes belong to the server user of the target (postgres /
# mysql, uid / gid 999 in both images), 0750: the servers write their 0640 audit logs there, the
# agent reads them through its supplementary group 999.
log "preparing the target-pg and target-mariadb log volumes (999:999, 0750)"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
files_root 'for d in /pglog /mylog; do chmod 0750 "$d" && chown 999:999 "$d" && stat -c "%u:%g %a" "$d"; done' \
  | tr '\n' ' ' | grep -qx '999:999 750 999:999 750 ' || fail "cannot prepare the target log volumes"

log "starting console DB, migrate, web, worker, TLS proxy, Mailpit and the target PostgreSQL, MySQL, MariaDB"
# No `--wait`: it treats the exited one-shot `migrate` as a failure on some Compose versions.
# `up` itself blocks on the depends_on conditions (db healthy, migrate done, web healthy).
timeout 400 docker compose -f "$HERE/docker-compose.yml" up -d db web worker proxy mailpit \
  target-pg target-mysql target-mariadb

log "waiting for console readiness through the TLS proxy"
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done

[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"

# The MySQL / MariaDB targets initialize in parallel with the console (seed, agent account, TLS
# material); their CA must exist before any agent container is created (bind mounts).
log "waiting for target-mysql and target-mariadb to be healthy (at most ${TARGET_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + TARGET_TIMEOUT_S ))
for svc in target-mysql target-mariadb; do
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$svc")" 2>/dev/null)" = healthy ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$svc not healthy within ${TARGET_TIMEOUT_S} s"
    sleep 2
  done
done
log "copying the CA of target-mysql and target-mariadb (dev initdb/30-tls.sh) for the agent"
compose exec -T target-mysql cat /var/lib/mysql/ca.pem >"$T/mysql-ca.pem" \
  || fail "cannot read the CA of target-mysql"
compose exec -T target-mariadb cat /var/lib/mysql/databastion-tls/ca.pem >"$T/mariadb-ca.pem" \
  || fail "cannot read the CA of target-mariadb"
for ca in mysql mariadb; do
  # A CA certificate (not MySQL's auto-generated material) with no private key next to it.
  openssl x509 -in "$T/$ca-ca.pem" -noout -subject 2>/dev/null | grep -q "DataBastion dev CA ($ca)" \
    || fail "$ca-ca.pem is not the dev CA of target-$ca"
  ! grep -q 'PRIVATE KEY' "$T/$ca-ca.pem" || fail "$ca-ca.pem holds a private key"
  chmod 0644 "$T/$ca-ca.pem"
done

phase_done start

# --------------------------------------------------------------------------- admin + token
log "bootstrapping the administrator"
timeout 120 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T \
  bootstrap-admin >"$E2E_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"

log "logging in through the user API"
jq -n --rawfile p "$S/admin_password" '{username: "e2e-admin", password: $p}' \
  >"$E2E_WORK_DIR/login.json"
r="$(api POST /api/auth/login "$E2E_WORK_DIR/login.json")"
rm -f "$E2E_WORK_DIR/login.json"
[ "$(status_of "$r")" = 200 ] || fail "login: HTTP $(status_of "$r")"
CSRF="$(body_of "$r" | jq -r '.csrf_token')"
[ -n "$CSRF" ] && [ "$CSRF" != null ] || fail "login: no CSRF token"
register_secret csrf_token "$CSRF"
printf 'X-CSRF-Token: %s\n' "$CSRF" >"$E2E_WORK_DIR/csrf.hdr"
SESSION_COOKIE="$(awk '$6 ~ /databastion_session$/ {print $7}' "$E2E_WORK_DIR/cookies")"
register_secret session_cookie "$SESSION_COOKIE"
[ -n "$SESSION_COOKIE" ] || fail "login: no session cookie"

log "creating an enrollment token"
printf '{"label":"e2e"}' >"$E2E_WORK_DIR/token-req.json"
r="$(api POST /api/enrollment-tokens "$E2E_WORK_DIR/token-req.json")"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
register_secret enrollment_token "$ENROLLMENT_TOKEN"
[[ "$ENROLLMENT_TOKEN" == dbe_* ]] || fail "enrollment token: unexpected format"

# --------------------------------------------------------------------------- agent files
log "creating the agent state volume from the image (checks its owner and mode)"
timeout 60 docker compose -f "$HERE/docker-compose.yml" run --rm -T --no-deps agent --version \
  >"$E2E_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
state_mode="$(files_root 'stat -c "%u:%g %a" /state')"
[ "$state_mode" = "10001:10001 700" ] || fail "state volume is '$state_mode', expected '10001:10001 700'"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
printf '%s' "$TARGET_AGENT_PASSWORD" | files_agent 'umask 077; cat > /secrets/target_agent_password'
printf '%s' "$TARGET_MYSQL_AGENT_PASSWORD" \
  | files_agent 'umask 077; cat > /secrets/target_mysql_agent_password'
printf '%s' "$TARGET_MARIADB_AGENT_PASSWORD" \
  | files_agent 'umask 077; cat > /secrets/target_mariadb_agent_password'
printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'

# --------------------------------------------------------------------------- enroll + run
log "enrolling the agent (databastion-agent enroll)"
timeout 120 docker compose -f "$HERE/docker-compose.yml" run --rm -T agent \
  enroll --config /etc/databastion/agent.yaml \
  --token-file /run/databastion-secrets/enrollment_token \
  >"$E2E_LOG_DIR/agent-enroll.log" 2>&1 || {
  # A failed enrollment may still have written (or logged) the agent secret: register it so the
  # cleanup redacts it from the uploaded logs.
  register_secret agent_secret "$(files_agent 'cat /state/identity.json' 2>/dev/null \
    | jq -r '.agent_secret // empty' 2>/dev/null)"
  fail "agent enroll failed (see agent-enroll.log)"
}
files_agent 'rm -f /secrets/enrollment_token'
identity_mode="$(files_agent 'stat -c "%u:%g %a" /state/identity.json')"
[ "$identity_mode" = "10001:10001 600" ] \
  || fail "identity.json is '$identity_mode', expected '10001:10001 600'"

identity="$(files_agent 'cat /state/identity.json')"
AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
AGENT_SECRET="$(jq -r '.agent_secret' <<<"$identity")"
register_secret agent_secret "$AGENT_SECRET"
unset identity
[ -n "$AGENT_ID" ] && [ "$AGENT_ID" != null ] || fail "no agent_id in identity.json"
[ -n "$AGENT_SECRET" ] && [ "$AGENT_SECRET" != null ] || fail "no agent_secret in identity.json"
log "enrolled agent $AGENT_ID"

log "starting databastion-agent run"
timeout 60 docker compose -f "$HERE/docker-compose.yml" up -d --no-deps agent

agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}

log "waiting for the agent to be online with its targets reported"
deadline=$(( $(date +%s) + 90 ))
online=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  a="$(agent_json || true)"
  # The PostgreSQL connector (P2-B) connects with the least-privilege role: the target must be
  # reachable. Its audit level (`none`: no pg_stat_statements on target-pg) is printed, not asserted.
  # The MySQL / MariaDB connector (P2-C) connects with the ADR-0018 minimal account over verified
  # TLS: both targets must be reachable too (audit level `none` without a performance_schema grant).
  if [ -n "$a" ] && jq -e '.status == "online"
      and any(.targets[]; .targetId == "pg-e2e" and .engine == "postgres" and .present and .reachable == true)
      and any(.targets[]; .targetId == "mysql-e2e" and .engine == "mysql" and .present and .reachable == true)
      and any(.targets[]; .targetId == "mariadb-e2e" and .engine == "mariadb" and .present and .reachable == true)' \
      <<<"$a" >/dev/null; then
    online="$a"
    break
  fi
  sleep 2
done
if [ -z "$online" ]; then
  # Reachability and error codes only (lastError is a code, never a server message).
  log "last agent state: $(jq -c '{status, targets: [.targets[]? | {targetId, engine, present, reachable, lastError}]}' <<<"${a:-{\}}" 2>/dev/null || true)"
  fail "agent not online with targets pg-e2e, mysql-e2e and mariadb-e2e reachable within 90 s"
fi
for t in pg-e2e mysql-e2e mariadb-e2e; do
  log "agent online; target $t: $(jq -c --arg t "$t" '.targets[] | select(.targetId == $t) | {reachable, auditLevel, lastError}' <<<"$online")"
done

log "checking the agent's target account (ADR-0012 minimal variant, read-only: I4)"
role="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T target-pg \
  psql -XAt -v ON_ERROR_STOP=1 -U postgres -d shop -c "SELECT concat_ws(',', rolcanlogin, rolsuper,
    rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolconnlimit,
    pg_has_role(r.oid, 'pg_read_all_data', 'MEMBER'), pg_has_role(r.oid, 'pg_monitor', 'MEMBER'),
    pg_has_role(r.oid, 'pg_read_all_stats', 'MEMBER'),
    has_database_privilege(r.oid, 'shop', 'CONNECT'),
    (SELECT string_agg(b.rolname, '+' ORDER BY b.rolname) FROM pg_auth_members m
       JOIN pg_roles b ON b.oid = m.roleid WHERE m.member = r.oid),
    (SELECT string_agg(c, '+' ORDER BY c COLLATE \"C\") FROM pg_db_role_setting s,
       unnest(s.setconfig) AS c WHERE s.setrole = r.oid))
    FROM pg_roles r WHERE rolname = 'databastion_agent'")" || fail "cannot inspect databastion_agent"
# psql renders booleans as t / f. Direct memberships must be exactly pg_read_all_stats: a later
# grant of pg_read_all_data / pg_monitor or of a write-capable role would otherwise pass
# (default_transaction_read_only is only a session default). The role settings (every database)
# must be exactly the four ADR-0012 defaults.
expected_role="t,f,f,f,f,f,5,f,f,t,t,pg_read_all_stats"
expected_role+=",default_transaction_read_only=on+idle_in_transaction_session_timeout=60s"
expected_role+="+lock_timeout=2s+statement_timeout=30s"
[ "$role" = "$expected_role" ] || fail "databastion_agent has unexpected attributes: $role"
# Logs in over TCP with its own password (read by the shell inside the container, never on a
# command line) and checks, in its own session, the role defaults (read-only transactions,
# timeouts) and that the credential-bearing catalogs are denied (no pg_read_all_data).
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
ro="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T target-pg sh -c \
  'PGPASSWORD="$(cat /run/secrets/target_agent_password)" exec psql -XAt -h 127.0.0.1 \
     -U databastion_agent -d shop -c "SELECT concat_ws(\$\$,\$\$,
       current_setting(\$\$default_transaction_read_only\$\$),
       current_setting(\$\$statement_timeout\$\$)::interval = interval \$\$30s\$\$,
       current_setting(\$\$lock_timeout\$\$)::interval = interval \$\$2s\$\$,
       current_setting(\$\$idle_in_transaction_session_timeout\$\$)::interval = interval \$\$60s\$\$,
       has_table_privilege(\$\$pg_catalog.pg_authid\$\$, \$\$SELECT\$\$),
       has_table_privilege(\$\$pg_catalog.pg_user_mapping\$\$, \$\$SELECT\$\$))"')" \
  || fail "databastion_agent cannot log in to the target"
[ "$ro" = "on,t,t,t,f,f" ] \
  || fail "databastion_agent session defaults / catalog privileges are unexpected ($ro)"
# Discovery grants (target-initdb/20-discovery-grants.sql): USAGE without CREATE on the seeded
# schemas, SELECT on every table there, and no write privilege on any relation outside the system
# schemas (pg_catalog.pg_settings is UPDATE-able by PUBLIC by design: SET, not a table write).
grants="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T target-pg \
  psql -XAt -v ON_ERROR_STOP=1 -U postgres -d shop -c "SELECT concat_ws(',',
    bool_and(has_schema_privilege('databastion_agent', n.nspname, 'USAGE')),
    bool_or(has_schema_privilege('databastion_agent', n.nspname, 'CREATE')),
    (SELECT bool_and(has_table_privilege('databastion_agent', c.oid, 'SELECT')) FROM pg_class c
       JOIN pg_namespace s ON s.oid = c.relnamespace
       WHERE s.nspname IN ('crm', 'billing', 'ops') AND c.relkind IN ('r', 'p')),
    (SELECT count(*) FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace
       WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND s.nspname <> 'information_schema' AND s.nspname NOT LIKE 'pg\_%'
         AND has_table_privilege('databastion_agent', c.oid,
               'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')))
    FROM pg_namespace n WHERE n.nspname IN ('crm', 'billing', 'ops')")" \
  || fail "cannot inspect the Discovery grants of databastion_agent"
[ "$grants" = "t,f,t,0" ] || fail "databastion_agent Discovery grants are unexpected ($grants)"
unset role expected_role ro grants

# MySQL / MariaDB agent accounts: ADR-0018 minimal variant (dev/{mysql,mariadb}/initdb/
# 20-databastion.sh; ADR-0020). Inspected as root, whose password is read inside the target from its
# Docker secret (never on a command line). Exactly USAGE on *.* and SELECT on the application
# database, REQUIRE SSL, MAX_USER_CONNECTIONS 5 (MariaDB: MAX_STATEMENT_TIME 30), no role, no other
# account named `databastion`; a session without TLS is refused.
# my_sql SERVICE CLIENT SQL: runs SQL as root in SERVICE, one row per line, tab-separated.
my_sql() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T "$1" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/root_password)" exec '"$2"' -h 127.0.0.1 -u root -N -B -e "$0"' "$3"
}
check_my_account() {
  local svc="$1" client="$2" db="$3" expected_opts="$4" grants opts
  grants="$(my_sql "$svc" "$client" "SHOW GRANTS FOR 'databastion'@'%'" | sort | tr '\n' '|')" \
    || fail "$svc: cannot read the grants of databastion"
  grants="${grants//\`/}"
  case "$grants" in
    "GRANT SELECT ON ${db}.* TO databastion@%|GRANT USAGE ON *.* TO databastion@%"*"|") ;;
    *) fail "$svc: databastion has unexpected grants (not printed: SHOW GRANTS holds the password hash)" ;;
  esac
  [ "$(grep -o 'GRANT' <<<"$grants" | wc -l)" = 2 ] || fail "$svc: databastion has extra grants (not printed)"
  opts="$(my_sql "$svc" "$client" "$5")" || fail "$svc: cannot read the options of databastion"
  [ "$opts" = "$expected_opts" ] || fail "$svc: databastion has unexpected account options: $opts"
  # The account logs in over TLS, and is refused without it (REQUIRE SSL: error 1045, the same
  # command otherwise). The password is read inside the target, never on a command line.
  my_agent_login "$svc" "$client" "$6" >/dev/null 2>&1 \
    || fail "$svc: databastion cannot log in over TLS"
  if my_agent_login "$svc" "$client" "$7" >"$E2E_WORK_DIR/no-tls.err" 2>&1; then
    fail "$svc: databastion logged in without TLS"
  fi
  grep -q '^ERROR 1045 ' "$E2E_WORK_DIR/no-tls.err" \
    || fail "$svc: the login without TLS failed for another reason than the account (not 1045)"
  rm -f -- "$E2E_WORK_DIR/no-tls.err"
}
# my_agent_login SERVICE CLIENT TLS_OPTION: `SELECT 1` as databastion over TCP.
my_agent_login() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T "$1" sh -c \
    'MYSQL_PWD="$(cat /run/secrets/agent_password)" exec '"$2"' -h 127.0.0.1 -u databastion '"$3"' -N -e "SELECT 1"'
}
log "checking the agents' MySQL / MariaDB accounts (ADR-0018 minimal variant, read-only: I4)"
check_my_account target-mysql mysql hr "ANY	5	0	0" \
  "SELECT ssl_type, max_user_connections,
     (SELECT count(*) FROM mysql.user WHERE user = 'databastion') - 1,
     (SELECT count(*) FROM mysql.role_edges WHERE to_user = 'databastion')
   FROM mysql.user WHERE user = 'databastion' AND host = '%'" --ssl-mode=REQUIRED --ssl-mode=DISABLED
check_my_account target-mariadb mariadb support "ANY	5	30.000000	0	0" \
  "SELECT ssl_type, max_user_connections, max_statement_time,
     (SELECT count(*) FROM mysql.user WHERE user = 'databastion') - 1,
     (SELECT count(*) FROM mysql.roles_mapping WHERE user = 'databastion')
   FROM mysql.user WHERE user = 'databastion' AND host = '%'" --ssl --skip-ssl
# The Audit test accounts of target-mariadb (35-mariadb-clients.sh): exactly USAGE and SELECT on
# support.* (not printed on failure: SHOW GRANTS holds the password hash).
for u in e2e_exporter e2e_analyst; do
  grants="$(my_sql target-mariadb mariadb "SHOW GRANTS FOR '$u'@'%'" | sort | tr '\n' '|')" \
    || fail "target-mariadb: cannot read the grants of $u"
  grants="${grants//\`/}"
  case "$grants" in
    "GRANT SELECT ON support.* TO $u@%|GRANT USAGE ON *.* TO $u@%"*"|") ;;
    *) fail "target-mariadb: $u has unexpected grants" ;;
  esac
  [ "$(grep -o 'GRANT' <<<"$grants" | wc -l)" = 2 ] || fail "target-mariadb: $u has extra grants"
done
unset grants

log "checking /metrics (scraped inside the console network, not through the proxy)"
metrics="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T web node -e '
  const t = require("fs").readFileSync("/run/secrets/metrics_token", "utf8").trim();
  fetch("http://127.0.0.1:3000/metrics", { headers: { authorization: "Bearer " + t } })
    .then(async (r) => { if (!r.ok) process.exit(2); process.stdout.write(await r.text()); })
    .catch(() => process.exit(3));')" || fail "/metrics scrape failed"
grep -Eq "^databastion_agent_up\{agent_id=\"${AGENT_ID}\"\} 1\$" <<<"$metrics" \
  || fail "/metrics: databastion_agent_up{agent_id=\"$AGENT_ID\"} 1 not found"
unset metrics
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/metrics")"
[ "$code" = 404 ] || fail "/metrics is reachable through the proxy (HTTP $code)"

phase_done enroll

# --------------------------------------------------------------------------- Discovery (P2-E)
# Read-only queries on the console database (the harness inspects state the user API does not
# expose as JSON: job status, stored finding locations). Ids are checked before interpolation.
console_sql() {
  timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
[[ "$AGENT_ID" =~ $UUID_RE ]] || fail "agent id is not a UUID"

# --------------------------------------------------------------------------- Audit clients (P4-D)
# Per <client> of E2E_AUDIT_TARGETS: how the agent reports its Audit stream, the expected audit
# level(s) and source, the database accesses of the test (run from a separate one-shot container,
# never with the agent's account), and the target's own audit log (source side).
#
# audit_client_<c>_started        agent log message of a started Audit stream
# audit_client_<c>_levels         heartbeat audit levels accepted once events flow (space-separated)
# audit_client_<c>_source         heartbeat audit source expected
# audit_client_<c>_principals     "<dump principal> <query principal>" (test roles on the target)
# audit_client_<c>_object_sets    distinct object sets the queries read (events to wait for)
# audit_client_<c>_query_statements  read statements the queries run (sum of aggregated_count)
# audit_client_<c>_query_signal   signal the query principal's events must carry, or empty
# audit_client_<c>_dump           runs the dump tool on the whole seeded database, output discarded
# audit_client_<c>_queries ENGINE queries whose text holds ground-truth literals; on failure
#                                 returns the failing step (1 queries, 2 INTO OUTFILE check), whose
#                                 error code only is printed (client_error_code). (PostgreSQL: a
#                                 filtered and a whole-table COPY too; MariaDB: a refused INTO
#                                 OUTFILE);
#                                 prints the needle ids of the literals
# audit_client_<c>_target_log OUT copies the target's own audit log (the file the agent reads,
#                                 rotations included) to OUT; returns 3 when that source keeps no
#                                 statement text (no literal positive control possible)
# audit_client_<c>_log_user_records FILE ACCOUNT START  audit records of ACCOUNT since START
# audit_client_<c>_time           current time in the log's timestamp format
# Client output never reaches a log: result rows go to /dev/null in the container, and errors
# (which may echo a statement holding a literal) to a private file; only exit codes are printed.

# client_error_code: the error code of the last client failure (client.err), never its text (it
# can echo a statement holding a literal, or rows): `ERROR 1227` (mariadb), `ERROR 42P01` (psql with
# VERBOSITY=sqlstate), `mariadb-dump: Got error: 1045`, `pg_dump: error`; `none` otherwise.
client_error_code() {
  local code
  code="$(grep -m 1 -oE '^ERROR [0-9]+|ERROR: +[0-9A-Z]{5}$|^(pg_dump|mariadb-dump|mysqldump): (Got )?error(: [0-9]+)?' \
    "$E2E_WORK_DIR/client.err" 2>/dev/null | head -n 1 | tr -s ' ')"
  printf '%s' "${code:-none}"
}
pg_client() {
  timeout 300 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    pg-client "$1"
}
audit_client_pg_started() { printf '%s' "$PG_AUDIT_STARTED"; }
audit_client_pg_levels() { printf '%s' "$PG_AUDIT_LEVELS"; }
audit_client_pg_source() { printf '%s' "$PG_AUDIT_SOURCE"; }
audit_client_pg_principals() { printf 'e2e_exporter e2e_analyst'; }
audit_client_pg_object_sets() { printf 3; }  # filtered SELECT, filtered COPY, whole-table COPY
audit_client_pg_query_statements() { printf 3; }  # the same three statements
audit_client_pg_query_signal() { printf ''; }
audit_client_pg_dump() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  pg_client 'PGPASSWORD="$(cat /run/secrets/target_client_password)" exec pg_dump -U e2e_exporter -f /dev/null' \
    </dev/null >/dev/null 2>"$E2E_WORK_DIR/client.err"
}
# gt_needle ENGINE CONTAINER OBJECT FIELD [INDEX]: "L<i>.v<INDEX><TAB><value>" of a value of a
# location (CONTAINER `-` for an engine without schemas).
gt_needle() {
  jq -r --arg e "$1" --arg c "$2" --arg o "$3" --arg f "$4" --argjson n "${5:-0}" '.locations
    | to_entries[]
    | select(.value.engine == $e and (.value.container // "-") == $c and .value.object == $o
             and .value.field == $f and ((.value.values // []) | length) > $n)
    | "L\(.key).v\($n)\t\(.value.values[$n])"' "$GROUND_TRUTH" | head -n 1
}
audit_client_pg_queries() {
  local engine="$1" email iban email_id iban_id sql="$E2E_WORK_DIR/client.sql"
  IFS=$'\t' read -r email_id email < <(gt_needle "$engine" crm customers email)
  IFS=$'\t' read -r iban_id iban < <(gt_needle "$engine" billing payment_methods iban)
  [ -n "$email" ] && [ -n "$iban" ] || fail "no ground-truth e-mail / IBAN for the literal queries"
  # Written to the private work directory, fed on stdin: the literals are on no command line.
  {
    printf "SELECT * FROM crm.customers WHERE email = '%s';\n" "${email//\'/\'\'}"
    printf "COPY (SELECT * FROM billing.payment_methods WHERE iban = '%s') TO STDOUT;\n" "${iban//\'/\'\'}"
    printf "COPY ops.app_credentials TO STDOUT;\n"
  } >"$sql"
  unset email iban
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  pg_client 'PGPASSWORD="$(cat /run/secrets/target_client_password)" exec psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -U e2e_analyst -f -' \
    <"$sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" || return 1
  rm -f -- "$sql"
  printf '%s %s' "$email_id" "$iban_id"
}
audit_client_pg_target_log() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" exec -T target-pg \
    cat /var/log/databastion/postgresql.json >"$1" || return 1
  # pg_stat_statements normalizes the literals of a SELECT and keeps no per-execution text.
  [ "$E2E_PG_AUDIT" = pgaudit ] || return 3
}
audit_client_pg_log_user_records() {
  # pgaudit READ records (jsonlog) of ACCOUNT at or after START (YYYY-MM-DD HH:MM:SS, UTC) naming a
  # relation of the seeded schemas: "AUDIT: SESSION|OBJECT,<n>,<n>,READ,<command>,<type>,<schema.rel>,…"
  # (pgaudit.log_relation = on), so probes and catalog reads do not count.
  jq -rc --arg u "$2" --arg t "$3" 'select(.user == $u and .dbname == "shop"
    and ((.message // "") | test("^AUDIT: (SESSION|OBJECT),[0-9]+,[0-9]+,READ,[^,]*,[^,]*,\"?(crm|billing|ops)\\."))
    and (.timestamp[0:19] >= $t))' "$1" 2>/dev/null | wc -l
}
audit_client_pg_time() { date -u +'%Y-%m-%d %H:%M:%S'; }

# MariaDB (target-mariadb, server_audit log). The accounts e2e_exporter / e2e_analyst come from
# target-initdb/35-mariadb-clients.sh; the client verifies the server's TLS certificate.
my_client() {
  timeout 300 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    my-client "$1"
}
# my_root SQL_FILE: runs SQL (stdin) as root inside target-mariadb (password read there).
my_root() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 60 docker compose -f "$HERE/docker-compose.yml" exec -T target-mariadb sh -c \
    'MYSQL_PWD="$(cat /run/secrets/root_password)" exec mariadb -h 127.0.0.1 -u root -N -B' <"$1"
}
audit_client_my_started() { printf 'audit source: audit log file'; }
# File sources are Limited until the stream parsed a record, then Partial; never Full (ADR-0023).
audit_client_my_levels() { printf 'partial'; }
audit_client_my_source() { printf 'mariadb_server_audit'; }
audit_client_my_principals() { printf 'e2e_exporter e2e_analyst'; }
audit_client_my_object_sets() { printf 1; }  # support.tickets (filtered SELECTs, INTO OUTFILE)
audit_client_my_query_statements() { printf 3; }  # two filtered SELECTs and the INTO OUTFILE
audit_client_my_query_signal() { printf 'signature.into_outfile'; }
audit_client_my_dump() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  my_client 'MYSQL_PWD="$(cat /run/secrets/target_client_password)" exec mariadb-dump -h mariadb --ssl-ca=/etc/e2e/mariadb-ca.pem -u e2e_exporter --single-transaction --no-tablespaces support' \
    </dev/null >/dev/null 2>"$E2E_WORK_DIR/client.err"
}
audit_client_my_queries() {
  local engine="$1" email phone email_id phone_id rc sql="$E2E_WORK_DIR/client.sql"
  IFS=$'\t' read -r email_id email < <(gt_needle "$engine" - tickets requester_email 0)
  IFS=$'\t' read -r phone_id phone < <(gt_needle "$engine" - tickets requester_phone 0)
  [ -n "$email" ] && [ -n "$phone" ] || fail "no ground-truth e-mail / phone for the MariaDB literal queries"
  # Written to the private work directory, fed on stdin: the literals are on no command line.
  {
    printf "SELECT * FROM tickets WHERE requester_email = '%s';\n" "${email//\'/\'\'}"
    printf "SELECT id, subject FROM tickets WHERE requester_phone = '%s';\n" "${phone//\'/\'\'}"
  } >"$sql"
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  my_client 'MYSQL_PWD="$(cat /run/secrets/target_client_password)" exec mariadb -h mariadb --ssl-ca=/etc/e2e/mariadb-ca.pem -u e2e_analyst support' \
    <"$sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" || return 1
  # INTO OUTFILE: must be refused (no FILE privilege), and still carry signature.into_outfile.
  printf "SELECT * FROM tickets INTO OUTFILE '/tmp/e2e-outfile.txt';\n" >"$sql"
  rc=0
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  my_client 'MYSQL_PWD="$(cat /run/secrets/target_client_password)" exec mariadb -h mariadb --ssl-ca=/etc/e2e/mariadb-ca.pem -u e2e_analyst support' \
    <"$sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" || rc=$?
  # ER_SPECIFIC_ACCESS_DENIED_ERROR (1227, "you need (at least one of) the FILE privilege(s)"):
  # MariaDB 11.4 checks FILE with check_global_access() before running an INTO OUTFILE
  # (sql/sql_parse.cc, mysql_execute_command). Not 1290 (secure_file_priv) and not a success.
  [ "$rc" = 1 ] && grep -qE '^ERROR 1227 ' "$E2E_WORK_DIR/client.err" || return 2
  unset email phone
  rm -f -- "$sql"
  printf '%s %s' "$email_id" "$phone_id"
}
# The server_audit log and its rotations (server_audit_file_rotations, dev/mariadb), only: the
# source the agent reads. Not performance_schema, which the agent's account cannot read.
audit_client_my_target_log() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" exec -T target-mariadb \
    sh -c 'cat /var/log/databastion/server_audit.log /var/log/databastion/server_audit.log.[0-9]* 2>/dev/null; test -s /var/log/databastion/server_audit.log' \
    >"$1"
}
audit_client_my_log_user_records() {
  # READ (TABLE event) or QUERY records of ACCOUNT on the seeded database `support` at or after
  # START (YYYYMMDD HH:MM:SS, server time: UTC in the image). CSV:
  # timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode.
  awk -F, -v u="$2" -v t="$3" '$3 == u && ($7 == "READ" || $7 == "QUERY") && $8 == "support" \
    && substr($1, 1, 17) >= t' "$1" | wc -l
}
audit_client_my_time() { date -u +'%Y%m%d %H:%M:%S'; }

# --------------------------------------------------------------------------- Audit setup (P4-D)
# As a user would, through the user API (admin session + CSRF): an e-mail channel to Mailpit, two
# access_event policies, and Audit enabled on every Audit target *before* the Discovery scan, so
# that the agent's own Discovery reads go through the Audit stream (they must not surface as events
# or incidents). The sensitive objects are derived from the findings, so Audit is configured again
# after the scan (then they cover the seeded tables).

# api_json METHOD PATH JSON: api() with an inline JSON body (identifiers and settings only).
api_json() {
  printf '%s' "$3" >"$E2E_WORK_DIR/req.json"
  api "$1" "$2" "$E2E_WORK_DIR/req.json"
}

# agent_log_count MESSAGE TARGET: agent log lines holding MESSAGE (fixed string) for TARGET.
agent_log_count() {
  timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color agent 2>/dev/null \
    | grep -F "$1" | grep -cF "\"target_id\":\"$2\"" || true
}

# wait_job ID LABEL TIMEOUT_S: waits for a console job to succeed.
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

# audit_configure TARGET: Audit on, defaults (aggregation 60 s, poll 10 s, no min_rows), sensitive
# objects derived from the findings. A change the console asks to confirm (409
# confirmation_required) is confirmed with the digest it returned, as the UI does. Waits for the
# audit.configure job to succeed; prints the console's answer (counts only).
audit_configure() {
  local target="$1" r code digest job_id
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" '{"enabled":true,"derive_from_findings":true}')"
  code="$(status_of "$r")"
  if [ "$code" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
    digest="$(body_of "$r" | jq -r '.digest')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "audit.configure ($target): no confirmation digest"
    log "audit.configure ($target): confirming the change the console flagged"
    r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" \
      "{\"enabled\":true,\"derive_from_findings\":true,\"confirm\":\"${digest}\"}")"
    code="$(status_of "$r")"
  fi
  [ "$code" = 202 ] || fail "audit.configure ($target): HTTP $code ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
  job_id="$(body_of "$r" | jq -r '.job_id')"
  [[ "$job_id" =~ $UUID_RE ]] || fail "audit.configure ($target): no job id"
  AUDIT_ANSWER="$(body_of "$r" | jq -c '{previous_objects, next_objects, added_objects, removed_objects, warning, truncated_objects}')"
  log "audit.configure ($target) queued: $AUDIT_ANSWER"
  wait_job "$job_id" "audit.configure ($target)" 90
}

# wait_audit_stream TARGET PREVIOUS CLIENT: waits until the agent logs that the Audit stream of
# TARGET (re)started on the expected source, more than PREVIOUS times in total.
wait_audit_stream() {
  local target="$1" prev="$2" msg deadline
  msg="$("audit_client_${3}_started")"
  deadline=$(( $(date +%s) + 90 ))
  until [ "$(agent_log_count "$msg" "$target")" -gt "$prev" ]; do
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "the agent did not start the Audit stream of $target ('$msg') within 90 s"
    sleep 1
  done
  # The stream opens its source right after that line (end of the log; the pg_stat_statements
  # baseline poll): leave it that moment before any access it must see.
  sleep 3
}

# Policy-engine wake-up (bug fixed in #63, ADR-0021 "wake-up and 2 s worker polling"): after a
# policy change or an accepted events batch (action at database time T), the web process sends a
# `policies.evaluate` pg-boss job. Per action, WAKEUP_STATUS_SQL answers:
# - `sent`: a job created in (T, T + 5 s] that the worker's schedule did not produce. pg-boss sends
#   scheduled jobs from a `__pgboss__send-it` job whose data names the queue; a policies.evaluate
#   job created while such a job ran is the schedule's and is not counted;
# - `coalesced`: none sent, but a job (not cancelled, created in (T - 60 s, T + 5 s], the schedule's
#   included) was waiting at T or right after it (not started by T): the queue is stately (one
#   waiting job), so the web's send legitimately joined it;
# - `lost` otherwise. Any `lost` fails; each kind of action must have at least one `sent`, and web.log
#   must hold no "wake-up not sent" warning. (The worker's own start-up and budget re-queue sends
#   are not told apart: they are rare and not near these actions.)
WAKEUP_STATUS_SQL="CASE
  WHEN EXISTS (SELECT 1 FROM pgboss.job j WHERE j.name = 'policies.evaluate'
    AND j.created_on > @T@ AND j.created_on <= @T@ + interval '5 seconds'
    AND NOT EXISTS (SELECT 1 FROM pgboss.job s WHERE s.name = '__pgboss__send-it'
      AND s.data->>'name' = 'policies.evaluate'
      AND j.created_on BETWEEN s.started_on AND coalesce(s.completed_on, now()))) THEN 'sent'
  WHEN EXISTS (SELECT 1 FROM pgboss.job j WHERE j.name = 'policies.evaluate'
    AND j.state <> 'cancelled'
    AND j.created_on > @T@ - interval '60 seconds' AND j.created_on <= @T@ + interval '5 seconds'
    AND (j.started_on IS NULL OR j.started_on > @T@)) THEN 'coalesced'
  ELSE 'lost' END"
db_now() { console_sql "SELECT now()"; }
# assert_wakeup LABEL T: waits up to 6 s for the wake-up of an action at database time T.
assert_wakeup() {
  local label="$1" t="$2" st deadline
  deadline=$(( $(date +%s) + 6 ))
  while :; do
    st="$(console_sql "SELECT ${WAKEUP_STATUS_SQL//@T@/\'$t\'::timestamptz}")" \
      || fail "cannot read the pg-boss jobs"
    [ "$st" = sent ] && break
    if [ "$(date +%s)" -ge "$deadline" ]; then
      [ "$st" = coalesced ] && break
      fail "no policies.evaluate job within 5 s of $label (policy-engine wake-up lost)"
    fi
    sleep 1
  done
  log "policy-engine wake-up after $label: $st"
  WAKEUP_POLICY_STATUS+=" $st"
}
WAKEUP_POLICY_STATUS=""

log "Audit: creating the e-mail channel ${AUDIT_CHANNEL} (Mailpit, STARTTLS verified against the test CA, SMTP AUTH)"
# The SMTP password is read by jq from its secret file (never on a command line); the request body
# stays in the private work directory.
jq -nc --arg slug "$AUDIT_CHANNEL" --rawfile pw "$S/mailpit_password" '{slug: $slug,
  type: "email", config: {host: "mailpit", port: 2525, tls: "starttls",
  from: "databastion@e2e.example", recipients: ["soc@e2e.example"], username: "e2e-smtp"},
  password: $pw}' >"$E2E_WORK_DIR/channel.json"
r="$(api POST /api/notification-channels "$E2E_WORK_DIR/channel.json")"
rm -f -- "$E2E_WORK_DIR/channel.json"
[ "$(status_of "$r")" = 201 ] \
  || fail "channel: HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"

AUDIT_TARGET_IDS="$(for at in "${E2E_AUDIT_TARGETS[@]}"; do read -r t _ <<<"$at"; printf '%s\n' "$t"; done \
  | jq -Rsc 'split("\n") | map(select(length > 0))')"
AUDIT_SIGNALS="$(for at in "${E2E_AUDIT_TARGETS[@]}"; do read -r _ _ _ _ sig _ <<<"$at"; printf '%s\n' "$sig"; done \
  | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
log "Audit: creating the access_event policies '${AUDIT_POLICY_DUMP}' (critical) and '${AUDIT_POLICY_READS}' (medium)"
t_policy="$(db_now)"
r="$(api_json POST /api/policies "$(jq -nc --arg name "$AUDIT_POLICY_DUMP" --arg ch "$AUDIT_CHANNEL" \
  --argjson targets "$AUDIT_TARGET_IDS" --argjson signals "$AUDIT_SIGNALS" '{name: $name,
  description: "Dump tool signature on an Audit target (e2e)", source: "access_event",
  conditions: {signals: $signals, target_ids: $targets},
  actions: [{type: "create_incident", severity: "critical"}, {type: "notify", channel: $ch}]}')")"
[ "$(status_of "$r")" = 201 ] \
  || fail "policy '${AUDIT_POLICY_DUMP}': HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
assert_wakeup "the creation of policy '${AUDIT_POLICY_DUMP}'" "$t_policy"
# Every read of an Audit target, whoever reads: the agent's own Discovery reads would open one too
# if they surfaced as events.
t_policy="$(db_now)"
r="$(api_json POST /api/policies "$(jq -nc --arg name "$AUDIT_POLICY_READS" --arg ch "$AUDIT_CHANNEL" \
  --argjson targets "$AUDIT_TARGET_IDS" '{name: $name,
  description: "Any read on an Audit target (e2e)", source: "access_event",
  conditions: {event_actions: ["read"], target_ids: $targets},
  actions: [{type: "create_incident", severity: "medium"}, {type: "notify", channel: $ch}]}')")"
[ "$(status_of "$r")" = 201 ] \
  || fail "policy '${AUDIT_POLICY_READS}': HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
assert_wakeup "the creation of policy '${AUDIT_POLICY_READS}'" "$t_policy"

for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r target _ client _ <<<"$at"
  prev="$(agent_log_count "$("audit_client_${client}_started")" "$target")"
  log "Audit: enabling Audit on $target before the Discovery scan (no finding yet: no sensitive object)"
  audit_configure "$target"
  wait_audit_stream "$target" "$prev" "$client"
  log "Audit stream of $target started ($("audit_client_${client}_started"))"
done
phase_done audit-setup

# One scan per declared target, launched together: the MySQL / MariaDB / PostgreSQL scans overlap.
printf '{"sample_rows":100,"max_duration_s":300,"statement_timeout_ms":5000}' \
  >"$E2E_WORK_DIR/scan-req.json"
declare -A SCAN_JOB_IDS=()
# Start of the Discovery scans, per Audit target, in its audit log's time format (own-account
# positive control, below).
declare -A SCAN_START=()
for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r target _ client _ <<<"$at"
  SCAN_START[$target]="$("audit_client_${client}_time")"
done
for t in "${E2E_TARGETS[@]}"; do
  read -r target _ _ <<<"$t"
  log "launching a discovery.scan of $target through the user API"
  r="$(api POST "/api/agents/${AGENT_ID}/targets/${target}/scan" "$E2E_WORK_DIR/scan-req.json")"
  [ "$(status_of "$r")" = 202 ] \
    || fail "scan request ($target): HTTP $(status_of "$r") ($(body_of "$r" | jq -r '.error // empty' 2>/dev/null || true))"
  job_id="$(body_of "$r" | jq -r '.job_id')"
  [[ "$job_id" =~ $UUID_RE ]] || fail "scan request ($target): no job id"
  SCAN_JOB_IDS[$target]="$job_id"
done
SCAN_JOB_LIST="$(printf "'%s'," "${SCAN_JOB_IDS[@]}")"
SCAN_JOB_LIST="${SCAN_JOB_LIST%,}"

log "waiting for the ${#SCAN_JOB_IDS[@]} scan jobs to succeed (at most ${SCAN_TIMEOUT_S} s)"
t_scan="$(date +%s)"
deadline=$(( t_scan + SCAN_TIMEOUT_S ))
for target in "${!SCAN_JOB_IDS[@]}"; do
  while :; do
    job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '${SCAN_JOB_IDS[$target]}'")" \
      || fail "cannot read the scan job status ($target)"
    case "$job" in
      succeeded,*) break ;;
      failed,* | cancelled,* | expired,*) fail "scan job of $target ended '$job'" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "scan job of $target not succeeded within ${SCAN_TIMEOUT_S} s (status '$job')"
    sleep 2
  done
  log "scan job of $target succeeded ($(( $(date +%s) - t_scan )) s since launch)"
done

# The agent reports the job status before its spooled findings batches are uploaded (the console
# accepts them in a late window). Deterministic signal: a heartbeat received after the last job
# ended (its SpoolStatus is stored in agents.spool) reports an empty spool and no dropped batch or
# item. Findings are spooled before the status is sent, so that heartbeat saw them all.
log "waiting for a heartbeat after the scans that reports an empty spool (at most ${SPOOL_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + SPOOL_TIMEOUT_S ))
while :; do
  spool="$(console_sql "SELECT concat_ws(',', a.last_seen_at > max(j.finished_at) + interval '1 second',
      coalesce(a.spool->>'batches', 'none'), coalesce(a.spool->>'dropped_batches', '0'),
      coalesce(a.spool->>'dropped_items', '0'))
    FROM agents a JOIN jobs j ON j.agent_id = a.id
    WHERE a.id = '${AGENT_ID}' AND j.id IN (${SCAN_JOB_LIST})
    GROUP BY a.id HAVING count(j.finished_at) = ${#SCAN_JOB_IDS[@]}")" \
    || fail "cannot read the agent spool status"
  case "$spool" in
    t,*,*,*) IFS=, read -r _ batches dropped_batches dropped_items <<<"$spool"
      [ "$dropped_batches" = 0 ] && [ "$dropped_items" = 0 ] \
        || fail "the agent dropped findings ($dropped_batches batch(es), $dropped_items item(s))"
      [ "$batches" = 0 ] && break ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "no heartbeat with an empty spool within ${SPOOL_TIMEOUT_S} s after the scans ('$spool')"
  sleep 2
done
# Secondary: the agent log has no lost, dropped or rejected result batch.
lost="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|rejected batch items|unreadable spool file' || true)"
[ "$lost" = 0 ] || fail "the agent log shows $lost lost / dropped / rejected result batch line(s)"
unset spool batches dropped_batches dropped_items lost

# Secondary: the stored findings of every target are non-zero and stable for 6 s.
deadline=$(( $(date +%s) + 60 ))
prev=""
stable=0
while :; do
  n="$(console_sql "SELECT string_agg(t.id || '=' || (SELECT count(*) FROM findings f
        WHERE f.agent_id = '${AGENT_ID}' AND f.target_id = t.id), ',' ORDER BY t.id)
      FROM (VALUES ('pg-e2e'), ('mysql-e2e'), ('mariadb-e2e')) AS t(id)")" \
    || fail "cannot count the findings"
  if [[ ! "$n" =~ =0(,|$) ]] && [ "$n" = "$prev" ]; then stable=$((stable + 1)); else stable=0; fi
  [ "$stable" -ge 3 ] && break
  [ "$(date +%s)" -lt "$deadline" ] || fail "findings not stable (or none for a target) within 60 s ($n)"
  prev="$n"
  sleep 2
done
log "findings stored per target: $n"

# findings_check TARGET ENGINE [i2_check options...]: the target's findings against the ground truth.
findings_check() {
  local target="$1" engine="$2"
  shift 2
  # Written under the private work directory, never into the uploaded logs.
  console_sql "SELECT coalesce(json_agg(json_build_object('database_name', database_name,
      'schema_name', schema_name, 'object_name', object_name, 'field_name', field_name,
      'classifier', classifier) ORDER BY location_key, classifier), '[]')
    FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}'" \
    >"$E2E_WORK_DIR/findings-$target.json" || fail "cannot read the findings of $target"
  timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine "$engine" "$@" \
    "$E2E_WORK_DIR/findings-$target.json" >&2 || fail "findings check of $target failed (see above)"
  rm -f -- "$E2E_WORK_DIR/findings-$target.json"
}
log "checking the ingested findings against dev/ground-truth.json (normalized value-bearing names)"
findings_check pg-e2e postgresql \
  --require-classifier pii.email --require-classifier pii.card_number \
  --require-classifier pii.iban --require-classifier secret.aws_key
# MySQL / MariaDB: every classifier the ground truth expects for the engine must have a finding
# (the connector's seed recall is 100 %, agent/crates/connector-mysql integration tests), and no
# finding may stand on a negative-control location. MariaDB's value-bearing table (an e-mail in the
# table name) is a negative control: its raw name must not be stored anywhere.
findings_check mysql-e2e mysql --require-expected-classifiers --forbid-negative-controls
findings_check mariadb-e2e mariadb --require-expected-classifiers --forbid-negative-controls

# The findings page renders the masked samples decrypted (they are encrypted at rest, so the
# database dump cannot show a masking failure): it is scanned too, below. It must be complete
# (every finding of every target listed, under the listing cap; every finding with samples shows
# them; none `unavailable`) and no masked sample may keep more than 4 digits (partial masking
# regression).
listed="$(console_sql "SELECT count(*) FROM findings WHERE false_positive_at IS NULL")" \
  || fail "cannot count the listed findings"
sampled="$(console_sql "SELECT count(*) FROM findings WHERE false_positive_at IS NULL
  AND masked_samples IS NOT NULL")" || fail "cannot count the findings with masked samples"
[ "$listed" -lt "$MAX_LISTED_FINDINGS" ] \
  || fail "$listed findings: over the page listing cap, the page scan would be partial"
[ "$sampled" -gt 0 ] || fail "no finding with masked samples: the page scan would prove nothing"
code="$("${CURL[@]}" -o "$E2E_WORK_DIR/findings-page.html" -w '%{http_code}' "${BASE_URL}/findings")" \
  || code=000
[ "$code" = 200 ] || fail "findings page: HTTP $code"
timeout 60 python3 "$I2_CHECK" page --expected-rows "$listed" --min-sampled-rows "$sampled" \
  "$E2E_WORK_DIR/findings-page.html" >&2 || fail "findings page check failed (see above)"
unset listed sampled

phase_done discovery

# --------------------------------------------------------------------------- Audit (P4-D)
# Per Audit target, after the Discovery scan: sensitive objects derived from the findings, a real
# dump from a separate client container (the phase 4 exit criterion is timed from its start to the
# incident on the console's incidents page), queries whose text holds ground-truth literals, then
# the stored events, incidents, heartbeat audit level and e-mail notifications are checked. The
# value search on all of it runs with the other I2 scans, below.
declare -A AUDIT_LITERALS=()  # ground-truth engine -> needle ids of the literals put in query text
AUDIT_LATENCIES=""
AUDIT_DIR="$E2E_WORK_DIR/audit"  # private: may hold what the console stores and renders
mkdir -p "$AUDIT_DIR/pages"
# fetch_page NAME PATH: a console page (or user API answer) with the admin session, HTTP 200 required.
fetch_page() {
  local code
  code="$("${CURL[@]}" -o "$AUDIT_DIR/pages/$1.html" -w '%{http_code}' "${BASE_URL}$2")" || code=000
  [ "$code" = 200 ] || fail "page $2: HTTP $code"
}

# critical_incidents: the "Active: N critical" count of the incidents page (console UI, session,
# through the TLS proxy). Only the dump policy opens critical incidents.
critical_incidents() {
  local code
  code="$("${CURL[@]}" -o "$E2E_WORK_DIR/incidents-poll.html" -w '%{http_code}' "${BASE_URL}/incidents")" \
    || code=000
  [ "$code" = 200 ] || return 1
  sed 's/<!-- -->//g' "$E2E_WORK_DIR/incidents-poll.html" | grep -oE 'Active: [0-9]+ critical' \
    | head -n 1 | grep -oE '[0-9]+'
}

# mailpit_fetch OUT: every message of Mailpit as JSON (list summary, decoded message with its text
# and HTML parts, raw source), read from the web container (Mailpit is on console-net only).
mailpit_fetch() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" exec -T web node -e '
    const base = "http://mailpit:8025/api/v1";
    const get = async (p, text) => { const r = await fetch(base + p); if (!r.ok) process.exit(2); return text ? r.text() : r.json(); };
    (async () => {
      const list = await get("/messages?limit=500");
      const out = [];
      for (const m of list.messages || []) {
        out.push({ summary: m, message: await get("/message/" + m.ID), raw: await get("/message/" + m.ID + "/raw", true) });
      }
      process.stdout.write(JSON.stringify(out));
    })().catch(() => process.exit(3));' >"$1"
}

audit_run() {
  local target="$1" engine="$2" client="$3" account="$4" signal="$5"
  local dump_p query_p prev cover n_sent n_missing n0 n t0 t_dump t_inc latency ids deadline st
  local n_sets n_pending n_inc n_notif level source rc min_sets query_signal min_stmts n_stmts
  local inc_ms db_latency
  read -r dump_p query_p <<<"$("audit_client_${client}_principals")"
  min_sets="$("audit_client_${client}_object_sets")"
  min_stmts="$("audit_client_${client}_query_statements")"
  query_signal="$("audit_client_${client}_query_signal")"

  prev="$(agent_log_count "$("audit_client_${client}_started")" "$target")"
  log "Audit ($target): configuring Audit again, sensitive objects derived from the findings"
  audit_configure "$target"
  cover="$(console_sql "SELECT jsonb_array_length(c.sent_objects) || ',' || (SELECT count(*) FROM
      (SELECT DISTINCT database_name, schema_name, object_name FROM findings f
        WHERE f.agent_id = c.agent_id AND f.target_id = c.target_id AND f.false_positive_at IS NULL) f
      WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements(c.sent_objects) o
        WHERE o->>'database' = f.database_name AND o->>'object' = f.object_name
          AND coalesce(o->>'schema', '') = coalesce(f.schema_name, '')))
    FROM audit_configs c WHERE c.agent_id = '${AGENT_ID}' AND c.target_id = '${target}'")" \
    || fail "cannot read the Audit settings of $target"
  IFS=, read -r n_sent n_missing <<<"$cover"
  [ "${n_sent:-0}" -gt 0 ] && [ "$n_missing" = 0 ] \
    || fail "Audit ($target): sensitive_objects do not cover the objects with findings (sent ${n_sent:-?}, missing ${n_missing:-?})"
  log "Audit ($target): $n_sent sensitive object(s) sent, every object with a finding covered"
  wait_audit_stream "$target" "$prev" "$client"

  n0="$(critical_incidents)" || fail "cannot read the critical incident count on the incidents page"
  log "Audit ($target): dump of the seeded database as $dump_p, from the ${client}-client container"
  t0="$(now_ms)"
  "audit_client_${client}_dump" \
    || fail "the dump of $target failed (exit $?, $(client_error_code); client output kept private)"
  t_dump="$(now_ms)"
  log "Audit ($target): dump finished in $((t_dump - t0)) ms; waiting for its incident on the incidents page"
  # The page count must rise AND the console must hold the incident of this target, this principal
  # and the dump policy, opened after the dump started (the count alone could be another incident).
  t_inc=""
  inc_ms=""
  deadline=$(( t0 + DUMP_INCIDENT_LIMIT_MS + 120000 ))  # past the limit: to print the actual time
  while [ "$(now_ms)" -lt "$deadline" ]; do
    n="$(critical_incidents || true)"
    if [ -n "$n" ] && [ "$n" -gt "$n0" ]; then
      [ -n "$t_inc" ] || t_inc="$(now_ms)"
      inc_ms="$(console_sql "SELECT floor(extract(epoch FROM min(created_at)) * 1000)::bigint
        FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}'
          AND principal = '${dump_p}' AND policy_name = '${AUDIT_POLICY_DUMP}'
          AND event_signals ? '${signal}' AND created_at >= to_timestamp(${t0} / 1000.0)")" \
        || fail "cannot read the incidents of $target"
      [ -n "$inc_ms" ] && break
    fi
    sleep 1
  done
  [ -n "$t_inc" ] && [ -n "$inc_ms" ] \
    || fail "Audit ($target): no '${AUDIT_POLICY_DUMP}' incident of $dump_p with $signal on the console within $(( (deadline - t0) / 1000 )) s of the dump"
  latency=$((t_inc - t0))
  db_latency=$((inc_ms - t0))
  log "Audit ($target): dump start -> incident: ${latency} ms on the incidents page, ${db_latency} ms by incidents.created_at (limit ${DUMP_INCIDENT_LIMIT_MS} ms)"
  AUDIT_LATENCIES+="$target ${latency} ms (created_at ${db_latency} ms); "
  [ "$latency" -lt "$DUMP_INCIDENT_LIMIT_MS" ] && [ "$db_latency" -lt "$DUMP_INCIDENT_LIMIT_MS" ] \
    || fail "Audit ($target): dump -> incident took ${latency} ms (page) / ${db_latency} ms (created_at), not under ${DUMP_INCIDENT_LIMIT_MS} ms"

  log "Audit ($target): queries with ground-truth literals as $query_p (see audit_client_${client}_queries)"
  ids="$("audit_client_${client}_queries" "$engine")" \
    || fail "the literal queries on $target failed (step $?, $(client_error_code); client output kept private)"
  [ -n "$ids" ] || fail "the literal queries on $target returned no needle id"
  AUDIT_LITERALS[$engine]="${AUDIT_LITERALS[$engine]:-} $ids"

  log "Audit ($target): waiting for the events of $query_p, their evaluation and the notifications (at most ${AUDIT_EVENTS_TIMEOUT_S} s)"
  deadline=$(( $(date +%s) + AUDIT_EVENTS_TIMEOUT_S ))
  while :; do
    st="$(console_sql "SELECT concat_ws(',',
        (SELECT count(DISTINCT objects::text) FROM access_events
          WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}' AND db_user = '${query_p}'),
        (SELECT coalesce(sum(aggregated_count), 0) FROM access_events
          WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}' AND db_user = '${query_p}'
            AND action = 'read'),
        (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND evaluated_at IS NULL),
        (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}'
          AND principal = '${query_p}' AND policy_name = '${AUDIT_POLICY_READS}'),
        (SELECT count(*) FROM notification_deliveries WHERE status IN ('pending', 'sending')))")" \
      || fail "cannot read the Audit state of $target"
    IFS=, read -r n_sets n_stmts n_pending n_inc n_notif <<<"$st"
    # Every literal-bearing statement was ingested: the positive control below then shows the
    # literals were in the source the agent read.
    [ "$n_sets" -ge "$min_sets" ] && [ "$n_stmts" -ge "$min_stmts" ] && [ "$n_pending" = 0 ] && [ "$n_inc" -ge 1 ] && [ "$n_notif" = 0 ] && break
    [ "$(date +%s)" -lt "$deadline" ] || fail "Audit ($target): events of $query_p not all stored, evaluated and notified within ${AUDIT_EVENTS_TIMEOUT_S} s (object sets $n_sets/$min_sets, read statements $n_stmts/$min_stmts, not evaluated $n_pending, incidents $n_inc, notifications pending $n_notif)"
    sleep 2
  done
  log "Audit ($target): $n_stmts read statement(s) on $n_sets object set(s) of $query_p stored and evaluated"

  # check() level and source, from a heartbeat (every 30 s) once the stream has read events.
  deadline=$(( $(date +%s) + 90 ))
  while :; do
    read -r level source < <(agent_json | jq -r --arg t "$target" \
      '.targets[] | select(.targetId == $t) | "\(.auditLevel) \(.auditSource)"')
    if [[ " $("audit_client_${client}_levels") " == *" ${level:-?} "* ]] \
        && [ "${source:-}" = "$("audit_client_${client}_source")" ]; then break; fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "Audit ($target): heartbeat audit level '${level:-?}' / source '${source:-?}', expected one of '$("audit_client_${client}_levels")' / '$("audit_client_${client}_source")'"
    sleep 3
  done
  log "Audit ($target): heartbeat audit level $level, source $source"

  # Notifications: every delivery sent, and the dump incident's e-mail received by Mailpit.
  st="$(console_sql "SELECT count(*) FILTER (WHERE status = 'delivered') || ',' ||
      count(*) FILTER (WHERE status NOT IN ('delivered')) || ',' ||
      coalesce(string_agg(DISTINCT last_error, ' ') FILTER (WHERE status <> 'delivered'), '-')
    FROM notification_deliveries WHERE channel_slug = '${AUDIT_CHANNEL}'")" \
    || fail "cannot read the notification deliveries"
  IFS=, read -r n_sent n_notif rc <<<"$st"
  [ "$n_sent" -ge 1 ] && [ "$n_notif" = 0 ] \
    || fail "notifications to ${AUDIT_CHANNEL}: $n_sent delivered, $n_notif not delivered (error codes: $rc)"
  mailpit_fetch "$AUDIT_DIR/mail.json" || fail "cannot read the Mailpit messages"
  jq -e --arg p "$AUDIT_POLICY_DUMP" 'any(.[]; (.summary.Subject // "") | contains($p))' \
    "$AUDIT_DIR/mail.json" >/dev/null || fail "Mailpit has no e-mail for the '$AUDIT_POLICY_DUMP' incident"
  log "Audit ($target): $n_sent notification(s) delivered; Mailpit holds $(jq length "$AUDIT_DIR/mail.json") message(s), the dump incident's included"

  # Events and incidents of the target against the ground truth and the agent's own account.
  console_sql "SELECT coalesce(json_agg(json_build_object('db_user', db_user,
      'db_user_fingerprint', db_user_fingerprint, 'action', action, 'objects', objects,
      'signals', signals, 'rows', rows, 'source', source) ORDER BY ts), '[]')
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}'" \
    >"$E2E_WORK_DIR/audit-events.json" || fail "cannot read the access events of $target"
  console_sql "SELECT coalesce(json_agg(json_build_object('policy_name', policy_name,
      'principal', principal, 'event_signals', event_signals, 'severity', severity) ORDER BY created_at), '[]')
    FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${target}'" \
    >"$E2E_WORK_DIR/audit-incidents.json" || fail "cannot read the incidents of $target"
  timeout 60 python3 "$I2_CHECK" audit --ground-truth "$GROUND_TRUTH" --engine "$engine" \
    --agent-account "$account" --events "$E2E_WORK_DIR/audit-events.json" \
    --incidents "$E2E_WORK_DIR/audit-incidents.json" \
    --require-event "${dump_p}:${signal}" --require-event "${query_p}${query_signal:+:$query_signal}" \
    --require-incident "${AUDIT_POLICY_DUMP}:${dump_p}:${signal}" \
    --require-incident "${AUDIT_POLICY_READS}:${query_p}" >&2 \
    || fail "Audit check of $target failed (see above)"
  rm -f -- "$E2E_WORK_DIR/audit-events.json" "$E2E_WORK_DIR/audit-incidents.json"

  # Positive control of the literal search: the literals are in the target's own audit log (the
  # source side, which keeps statement text), so the queries did carry them to the agent.
  rc=0
  "audit_client_${client}_target_log" "$E2E_WORK_DIR/target-audit.log" || rc=$?
  if [ "$rc" = 3 ]; then
    log "Audit ($target): the $E2E_PG_AUDIT source keeps no statement text: no literal positive control"
  else
    [ "$rc" = 0 ] || fail "cannot read the audit log of $target"
    local -a needles=()
    for id in $ids; do needles+=(--needle "$id"); done
    rc=0
    timeout 120 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$engine" \
      --label "$engine target audit log (positive control)" "${needles[@]}" \
      "$E2E_WORK_DIR/target-audit.log" >"$E2E_WORK_DIR/literal-control.out" 2>&1 || rc=$?
    for id in $ids; do
      if [ "$rc" != 1 ] || ! grep -q "^LEAK ${id//./\\.} " "$E2E_WORK_DIR/literal-control.out"; then
        fail "Audit ($target): literal $id not found in the target's audit log (positive control)"
      fi
    done
    log "Audit ($target): the literals ($ids) are in the target's own audit log (positive control)"
  fi
  rm -f -- "$E2E_WORK_DIR/target-audit.log" "$E2E_WORK_DIR/literal-control.out"
}

for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r target engine client account signal <<<"$at"
  audit_run "$target" "$engine" "$client" "$account" "$signal"
done
log "Audit: dump -> incident latency: ${AUDIT_LATENCIES}"
# Pages and user API answers that show the agent and its targets' Audit state (target notes, audit
# level, settings), fetched while the agent is enrolled; scanned with the other pages (I2, below).
fetch_page agent "/agents/${AGENT_ID}"
fetch_page api-agents /api/agents
for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r target _ <<<"$at"
  fetch_page "audit-settings-$target" "/agents/${AGENT_ID}/targets/${target}/audit"
done
# No event of this run carries a db_user_fingerprint (no failed or unknown login was made while
# Audit ran: one would mean a principal the agent could not name).
n="$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND db_user_fingerprint IS NOT NULL")" \
  || fail "cannot count the fingerprinted events"
[ "$n" = 0 ] || fail "$n access event(s) carry a db_user_fingerprint"
# Every accepted events batch woke the policy engine (see assert_wakeup).
wake="$(console_sql "SELECT count(*) || ',' || count(*) FILTER (WHERE st = 'sent') || ',' ||
    count(*) FILTER (WHERE st = 'lost') FROM (SELECT ${WAKEUP_STATUS_SQL//@T@/b.received_at} AS st
    FROM events_batches b WHERE b.agent_id = '${AGENT_ID}') x")" \
  || fail "cannot check the wake-ups of the events batches"
IFS=, read -r n_batches n_woke n_lost <<<"$wake"
[ "$n_batches" -gt 0 ] || fail "no events batch stored: the wake-up check would prove nothing"
[ "$n_lost" = 0 ] || fail "$n_lost of $n_batches events batch(es): no policies.evaluate job within 5 s (policy-engine wake-up lost)"
[ "$n_woke" -gt 0 ] || fail "no events batch was followed by a wake-up job (all coalesced: nothing proven)"
[[ "$WAKEUP_POLICY_STATUS" == *sent* ]] || fail "no policy creation was followed by a wake-up job (all coalesced: nothing proven)"
n="$(console_sql "SELECT count(*) FROM pgboss.job WHERE name = '__pgboss__send-it' AND data->>'name' = 'policies.evaluate'")" \
  || fail "cannot count the scheduled sends"
[ "$n" -gt 0 ] || fail "no scheduled policies.evaluate send found: schedule jobs cannot be told apart from wake-ups"
log "policy-engine wake-up: events batches $n_batches ($n_woke sent, $((n_batches - n_woke)) coalesced), policies:${WAKEUP_POLICY_STATUS}; $n scheduled send(s) excluded"
lost="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color web 2>/dev/null \
  | grep -c 'wake-up not sent' || true)"
[ "$lost" = 0 ] || fail "web.log shows $lost 'wake-up not sent' warning(s)"
phase_done audit

# --------------------------------------------------------------------------- revocation
agent_401_count() {
  timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color agent 2>/dev/null \
    | grep -cF "$AGENT_401_MESSAGE" || true
}
before_401="$(agent_401_count)"
log "revoking the agent through the user API"
t0="$(now_ms)"
r="$(api POST "/api/agents/${AGENT_ID}/revoke")"
[ "$(status_of "$r")" = 204 ] || fail "revoke: HTTP $(status_of "$r")"

t_401=""
while [ $(( $(now_ms) - t0 )) -lt "$REVOCATION_LIMIT_MS" ]; do
  if [ "$(agent_401_count)" -gt "$before_401" ]; then t_401="$(now_ms)"; break; fi
  sleep 0.5
done
[ -n "$t_401" ] || fail "the agent did not log a fatal 401 within 60 s of the revocation"
latency=$(( t_401 - t0 ))
log "revocation latency (revoke call -> agent fatal 401): ${latency} ms"
[ "$latency" -lt "$REVOCATION_LIMIT_MS" ] || fail "revocation latency ${latency} ms >= 60 s"
[ "$(agent_json | jq -r '.status')" = revoked ] || fail "console does not show the agent as revoked"

log "checking that the agent stops polling /jobs (10 s window)"
sleep 2
window_start="$(date +%s)"
sleep 10
polls="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color proxy 2>/dev/null \
  | sed -n 's/^[^{]*\({.*\)$/\1/p' \
  | jq -R 'fromjson? // empty' 2>/dev/null \
  | jq -s --argjson from "$window_start" \
      '[.[] | select((.request.uri // "") | startswith("/api/agent/v1/jobs")) | select(.ts >= $from)] | length')"
[ "$polls" = 0 ] || fail "the agent still polled /jobs $polls time(s) after the revocation"

phase_done revocation

# --------------------------------------------------------------------------- secret hygiene
log "checking that no secret appears in any log (I2 / secret hygiene)"
dump_logs
for f in agent.log web.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the leak scan would prove nothing"
done

# Positive control: a random canary written to the log directory must be found by the scan and
# redacted by the same code path that cleanup() uses; then it is removed.
C="$E2E_WORK_DIR/canary-pattern"
mkdir -p "$C"
printf 'e2e-canary-%s\n' "$(rand_hex 16)" >"$C/canary"
{ printf 'before '; cat "$C/canary"; printf 'after\n'; } >"$E2E_LOG_DIR/zz-canary.log"
canary_hits="$(leak_scan "$E2E_LOG_DIR" "$C" || true)"
[ "$canary_hits" = "canary: zz-canary.log " ] || fail "leak scan positive control: canary not detected"
redact_dir "$E2E_LOG_DIR" "$C" 2>/dev/null
if ! grep -qF '<REDACTED:canary>' "$E2E_LOG_DIR/zz-canary.log" \
    || grep -qFf "$C/canary" -- "$E2E_LOG_DIR/zz-canary.log"; then
  fail "redaction positive control: canary not redacted"
fi
rm -rf -- "$E2E_LOG_DIR/zz-canary.log" "$C"

if ! leaked="$(leak_scan "$E2E_LOG_DIR" "$P")"; then
  while IFS= read -r line; do log "LEAK: $line"; done <<<"$leaked"
  fail "secret(s) found in container logs"
fi

# I3: the target passwords set by target-initdb/ are not in the statement texts that
# pg_stat_statements keeps on target-pg (readable by the agent account through pg_read_all_stats).
# I3 on the audit logs the agent reads (targets' side): no registered secret in them, and they are
# not empty. Own-account positive control: they hold records of the agent's own account since the
# Discovery scan started (so "no own-account event" above means filtered, not unseen).
log "checking the targets' audit logs: no secret, and the agent's own reads recorded"
mkdir -p "$E2E_WORK_DIR/target-logs"
for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r target _ client account _ <<<"$at"
  rc=0
  "audit_client_${client}_target_log" "$E2E_WORK_DIR/target-logs/$target.log" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 3 ] || fail "cannot copy the audit log of $target"
  [ -s "$E2E_WORK_DIR/target-logs/$target.log" ] || fail "the audit log of $target is empty"
  if [ "$rc" = 3 ]; then
    log "$target: the $E2E_PG_AUDIT source writes no audit record: no own-account positive control"
  else
    n="$("audit_client_${client}_log_user_records" "$E2E_WORK_DIR/target-logs/$target.log" "$account" \
      "${SCAN_START[$target]}")"
    [ "${n:-0}" -gt 0 ] \
      || fail "$target: no audit record of the agent's account $account since the scan started (positive control)"
    log "$target: $n audit record(s) of the agent's account $account since the scan started, none surfaced"
  fi
done
if ! leaked="$(leak_scan "$E2E_WORK_DIR/target-logs" "$P")"; then
  while IFS= read -r line; do log "LEAK: $line"; done <<<"$leaked"
  fail "secret(s) found in the targets' audit logs"
fi
rm -rf -- "$E2E_WORK_DIR/target-logs"

log "checking that no target password is in target-pg's pg_stat_statements"
timeout 60 docker compose -f "$HERE/docker-compose.yml" exec -T target-pg \
  psql -XAt -v ON_ERROR_STOP=1 -U postgres -d shop -c "SELECT query FROM pg_stat_statements" \
  >"$E2E_WORK_DIR/pgss.txt" || fail "cannot read pg_stat_statements on target-pg"
[ -s "$E2E_WORK_DIR/pgss.txt" ] || fail "pg_stat_statements on target-pg is empty: the check would prove nothing"
for name in target_pg_password target_agent_password target_client_password; do
  if LC_ALL=C grep -qFf "$P/$name" -- "$E2E_WORK_DIR/pgss.txt"; then
    fail "$name is in a statement text kept by pg_stat_statements on target-pg"
  fi
done
rm -f -- "$E2E_WORK_DIR/pgss.txt"

log "checking that no secret is stored in clear text in the console database"
# Written under the private work directory (removed on exit), never into the uploaded logs.
db_dump="$E2E_WORK_DIR/console-db.sql"
timeout 120 docker compose -f "$HERE/docker-compose.yml" exec -T db \
  pg_dump -U postgres -d databastion >"$db_dump" 2>"$E2E_WORK_DIR/pg_dump.err" \
  || fail "pg_dump of the console database failed"
grep -q '^CREATE TABLE ' "$db_dump" || fail "the console database dump holds no table"
for name in agent_secret enrollment_token admin_password target_pg_password target_agent_password \
    target_client_password target_mysql_password target_mysql_agent_password \
    target_mariadb_password target_mariadb_agent_password mailpit_password; do
  [ -s "$P/$name" ] || fail "secret $name was never registered"
done
# Every registered secret (the whole registry, not a list).
db_leaks=0
for f in "$P"/*; do
  [ -s "$f" ] || continue
  if LC_ALL=C grep -qFf "$f" -- "$db_dump"; then
    log "LEAK: $(basename "$f") stored in clear text in the console database"
    db_leaks=$((db_leaks + 1))
  fi
done
[ "$db_leaks" -eq 0 ] || fail "$db_leaks secret(s) in clear text in the console database"

# --------------------------------------------------------------------------- invariant I2 (P2-E)
# For each engine (postgresql, mysql, mariadb): no value of dev/ground-truth.json, and no
# value-bearing table name, in clear text (definition in i2_check.py) in: the plain pg_dump of the
# whole console database (every schema: public, pgboss...), every console / agent / proxy log, and
# the rendered findings page. The targets' own logs (the source databases) and all.log (which
# includes them) are not console or agent output. Only counts, needle ids and file names are
# printed, never a value.
log "invariant I2: no ground-truth value in clear text in the console database, logs or findings page"
i2_scan() {
  local engine="$1"
  shift
  timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$engine" "$@" >&2
}
grep -q '^CREATE SCHEMA pgboss;' "$db_dump" || fail "the console database dump has no pgboss schema"
grep -q '^COPY public.findings ' "$db_dump" || fail "the console database dump has no findings table"
i2_failed=0
for t in "${E2E_TARGETS[@]}"; do
  read -r _ engine _ <<<"$t"
  i2_scan "$engine" --label "$engine console-db" "$db_dump" || i2_failed=1
  # Positive control of the log scan: a canary file holding one ground-truth e-mail of the engine
  # (long enough to be a needle), next to the logs (in the private work directory), must be reported.
  mkdir -p "$E2E_WORK_DIR/i2-canary"
  jq -r --arg e "$engine" '[.locations[] | select(.engine == $e and any(.expected_classifiers[]?; . == "pii.email"))
      | .values[]?] | .[0]' "$GROUND_TRUTH" \
    >"$E2E_WORK_DIR/i2-canary/zz-i2-canary.log"
  canary_rc=0
  i2_scan "$engine" --label "$engine log-canary" --exclude 'target-*.log' --exclude all.log \
    "$E2E_LOG_DIR" "$E2E_WORK_DIR/i2-canary" 2>"$E2E_WORK_DIR/i2-canary.out" || canary_rc=$?
  if [ "$canary_rc" -ne 1 ] || ! grep -q 'file=zz-i2-canary.log$' "$E2E_WORK_DIR/i2-canary.out"; then
    fail "I2 log scan positive control ($engine): canary not detected"
  fi
  rm -rf -- "$E2E_WORK_DIR/i2-canary" "$E2E_WORK_DIR/i2-canary.out"
  i2_scan "$engine" --label "$engine logs" --exclude 'target-*.log' --exclude all.log "$E2E_LOG_DIR" \
    || i2_failed=1
  i2_scan "$engine" --label "$engine findings-page" "$E2E_WORK_DIR/findings-page.html" || i2_failed=1
done
# Invariant I2 on the Audit path (P4-D), for each engine with an Audit target: every column of the
# console's Audit tables (access_events, incidents and their links, notification outbox, principal
# baselines, Audit settings), the rendered events, principal, incidents (list and each incident)
# and notifications pages, and the e-mails Mailpit received (list, decoded text / HTML parts and raw
# source). Then the literals the test put in query text are searched alone, on every console-side
# artifact: they must be nowhere (their positive control ran on the target's own audit log).
log "invariant I2 (Audit path): events, incidents, notifications, pages and e-mails"
mkdir -p "$AUDIT_DIR/tables"
for table in access_events incidents incident_events notification_deliveries principal_baselines \
    audit_configs; do
  # Every column, as the console stores it (row_to_json of the whole row).
  console_sql "SELECT coalesce(json_agg(t), '[]') FROM ${table} t" >"$AUDIT_DIR/tables/${table}.json" \
    || fail "cannot export $table"
done
for table in access_events incidents notification_deliveries; do
  [ "$(jq length "$AUDIT_DIR/tables/${table}.json")" -gt 0 ] \
    || fail "$table is empty: the I2 scan of the Audit path would prove nothing"
done
fetch_page events /events
fetch_page incidents "/incidents?status=all"
fetch_page notifications /notifications
n_pages=0
while IFS= read -r id; do
  [[ "$id" =~ $UUID_RE ]] || fail "incident id is not a UUID"
  fetch_page "incident-$id" "/incidents/$id"
  n_pages=$((n_pages + 1))
done < <(console_sql "SELECT id FROM incidents WHERE access_event_id IS NOT NULL OR principal IS NOT NULL ORDER BY created_at")
while IFS=, read -r target key; do
  [[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "principal key is not a SHA-256"
  fetch_page "principal-$key" "/events/principal?agent=${AGENT_ID}&target=${target}&principal=${key}"
  n_pages=$((n_pages + 1))
done < <(console_sql "SELECT target_id || ',' || principal_key FROM principal_baselines WHERE agent_id = '${AGENT_ID}'")
[ "$n_pages" -gt 0 ] || fail "no incident or principal page to scan"
# The events and incidents pages list what the test did (the query principal is shown).
for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r _ _ client _ <<<"$at"
  read -r _ query_p <<<"$("audit_client_${client}_principals")"
  for page in events incidents; do
    grep -qF "$query_p" "$AUDIT_DIR/pages/$page.html" || fail "the $page page does not list $query_p"
  done
done
mailpit_fetch "$AUDIT_DIR/mail.json" || fail "cannot read the Mailpit messages"
[ "$(jq length "$AUDIT_DIR/mail.json")" -gt 0 ] || fail "Mailpit holds no message: the I2 scan would prove nothing"
# Every message is an incident e-mail of this run: a text part naming an Audit target or principal
# (so the scan reads real notification bodies).
AUDIT_WORDS="$(for at in "${E2E_AUDIT_TARGETS[@]}"; do
    read -r t _ c _ <<<"$at"; printf '%s\n' "$t"; "audit_client_${c}_principals" | tr ' ' '\n'; echo
  done | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
jq -e --argjson w "$AUDIT_WORDS" 'all(.[]; (.message.Text // "") as $t
    | ($t | length) > 0 and any($w[]; . as $x | $t | contains($x)))' "$AUDIT_DIR/mail.json" >/dev/null \
  || fail "a Mailpit message has no text part naming an Audit target or principal"
log "Audit path: $(find "$AUDIT_DIR/pages" -type f | wc -l) page(s), $(jq length "$AUDIT_DIR/mail.json") e-mail(s), 6 table export(s)"
declare -A AUDIT_ENGINES=()
for at in "${E2E_AUDIT_TARGETS[@]}"; do
  read -r _ engine _ <<<"$at"
  AUDIT_ENGINES[$engine]=1
done
for engine in "${!AUDIT_ENGINES[@]}"; do
  i2_scan "$engine" --label "$engine audit-tables" "$AUDIT_DIR/tables" || i2_failed=1
  i2_scan "$engine" --label "$engine audit-pages" "$AUDIT_DIR/pages" || i2_failed=1
  i2_scan "$engine" --label "$engine e-mails" "$AUDIT_DIR/mail.json" || i2_failed=1
  needles=()
  for id in ${AUDIT_LITERALS[$engine]}; do needles+=(--needle "$id"); done
  [ "${#needles[@]}" -gt 0 ] || fail "no query literal recorded for $engine"
  i2_scan "$engine" --label "$engine query literals" "${needles[@]}" \
    --exclude 'target-*.log' --exclude all.log \
    "$db_dump" "$E2E_LOG_DIR" "$E2E_WORK_DIR/findings-page.html" "$AUDIT_DIR" || i2_failed=1
done
rm -rf -- "$AUDIT_DIR"
rm -f -- "$db_dump" "$E2E_WORK_DIR/pg_dump.err" "$E2E_WORK_DIR/findings-page.html"
[ "$i2_failed" -eq 0 ] || fail "invariant I2: ground-truth value(s) in clear text (ids above)"

phase_done i2
log "all checks passed (revocation latency ${latency} ms; dump -> incident: ${AUDIT_LATENCIES})"
