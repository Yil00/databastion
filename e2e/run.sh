#!/usr/bin/env bash
# End-to-end enrollment / revocation test (phase 1 exit criterion):
#   "end-to-end enrollment in containers; revocation effective in < 60 s",
# and invariant I2 test (P2-E): a Discovery scan of the seeded target leaves no ground-truth value
# in clear text in the console database, the container logs or the findings page.
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
TARGET_SEED="$HERE/../dev/seed/out/postgres.sql"
SCAN_TIMEOUT_S=240
SPOOL_TIMEOUT_S=90   # three heartbeat intervals (console HEARTBEAT_INTERVAL_S = 30)
MAX_LISTED_FINDINGS=500  # console/src/server/findings.ts: the page lists at most this many
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log() { printf '[e2e %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }

for tool in docker openssl curl jq timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

# Invariant I2 scanner positive control, before anything starts: every searchable PostgreSQL
# value of the ground truth (and every value-bearing name) must be visible in the committed seed
# that target-pg loads. Counts and ids only are printed.
timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine postgresql \
  "$TARGET_SEED" >&2 || fail "I2 scanner positive control failed (see above)"

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
  for svc in db migrate web worker proxy target-pg agent; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc.log" 2>&1 || true
  done
}

cleanup() {
  local status=$?
  set +e
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  # Before teardown and before $E2E_WORK_DIR (the registry) goes away, whatever the exit path.
  redact_dir "$E2E_LOG_DIR" "$P"
  log "tearing down"
  timeout 120 docker compose -f "$HERE/docker-compose.yml" --profile tools down -v --remove-orphans \
    >/dev/null 2>&1
  rm -rf "$E2E_WORK_DIR"
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
register_secret db_password "$DB_PASSWORD"
register_secret db_owner_password "$DB_OWNER_PASSWORD"
register_secret db_app_password "$DB_APP_PASSWORD"
register_secret encryption_key "$ENCRYPTION_KEY"
register_secret metrics_token "$METRICS_TOKEN"
register_secret admin_password "$ADMIN_PASSWORD"
register_secret target_pg_password "$TARGET_PG_PASSWORD"
register_secret target_agent_password "$TARGET_AGENT_PASSWORD"
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
rm -f "$T/ca.key" "$T/server.csr" "$T/server.ext" "$T/ca.srl"
# Readable by the proxy (uid 10001) and the agent through the bind mounts; $T itself is 0700.
chmod 0644 "$T/ca.crt" "$T/server.crt" "$T/server.key"

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
    postgres:
      databases: [shop]
      tls: disable_insecure
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
log "building images (console, agent)"
timeout 1500 docker compose -f "$HERE/docker-compose.yml" build

log "starting console DB, migrate, web, worker, TLS proxy and the target PostgreSQL"
# No `--wait`: it treats the exited one-shot `migrate` as a failure on some Compose versions.
# `up` itself blocks on the depends_on conditions (db healthy, migrate done, web healthy).
timeout 400 docker compose -f "$HERE/docker-compose.yml" up -d db web worker proxy target-pg

log "waiting for console readiness through the TLS proxy"
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done

[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"

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
files_root() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    agent-files "$1"
}
files_agent() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    --user 10001:10001 agent-files "$1"
}

log "creating the agent state volume from the image (checks its owner and mode)"
timeout 60 docker compose -f "$HERE/docker-compose.yml" run --rm -T --no-deps agent --version \
  >"$E2E_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
state_mode="$(files_root 'stat -c "%u:%g %a" /state')"
[ "$state_mode" = "10001:10001 700" ] || fail "state volume is '$state_mode', expected '10001:10001 700'"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
printf '%s' "$TARGET_AGENT_PASSWORD" | files_agent 'umask 077; cat > /secrets/target_agent_password'
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

log "waiting for the agent to be online with its target reported"
deadline=$(( $(date +%s) + 90 ))
online=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  a="$(agent_json || true)"
  # The PostgreSQL connector (P2-B) connects with the least-privilege role: the target must be
  # reachable. Its audit level (`none`: no pg_stat_statements on target-pg) is printed, not asserted.
  if [ -n "$a" ] && jq -e '.status == "online" and any(.targets[]; .targetId == "pg-e2e" and .engine == "postgres" and .present and .reachable == true)' \
      <<<"$a" >/dev/null; then
    online="$a"
    break
  fi
  sleep 2
done
[ -n "$online" ] || fail "agent not online with target pg-e2e reachable within 90 s"
log "agent online; target pg-e2e: $(jq -c '.targets[] | select(.targetId == "pg-e2e") | {reachable, auditLevel, lastError}' <<<"$online")"

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
expected_role="t,f,f,f,f,f,4,f,f,t,t,pg_read_all_stats"
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

# --------------------------------------------------------------------------- Discovery (P2-E)
# Read-only queries on the console database (the harness inspects state the user API does not
# expose as JSON: job status, stored finding locations). Ids are checked before interpolation.
console_sql() {
  timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
[[ "$AGENT_ID" =~ $UUID_RE ]] || fail "agent id is not a UUID"

log "launching a discovery.scan of pg-e2e through the user API"
printf '{"sample_rows":100,"max_duration_s":300,"statement_timeout_ms":5000}' \
  >"$E2E_WORK_DIR/scan-req.json"
r="$(api POST "/api/agents/${AGENT_ID}/targets/pg-e2e/scan" "$E2E_WORK_DIR/scan-req.json")"
[ "$(status_of "$r")" = 202 ] \
  || fail "scan request: HTTP $(status_of "$r") ($(body_of "$r" | jq -r '.error // empty' 2>/dev/null || true))"
SCAN_JOB_ID="$(body_of "$r" | jq -r '.job_id')"
[[ "$SCAN_JOB_ID" =~ $UUID_RE ]] || fail "scan request: no job id"

log "waiting for scan job $SCAN_JOB_ID to succeed (at most ${SCAN_TIMEOUT_S} s)"
t_scan="$(date +%s)"
deadline=$(( t_scan + SCAN_TIMEOUT_S ))
while :; do
  job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '${SCAN_JOB_ID}'")" \
    || fail "cannot read the scan job status"
  case "$job" in
    succeeded,*) break ;;
    failed,* | cancelled,* | expired,*) fail "scan job ended '$job'" ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "scan job not succeeded within ${SCAN_TIMEOUT_S} s (status '$job')"
  sleep 2
done
log "scan job succeeded in $(( $(date +%s) - t_scan )) s"

# The agent reports the job status before its spooled findings batches are uploaded (the console
# accepts them in a late window). Deterministic signal: a heartbeat received after the job ended
# (its SpoolStatus is stored in agents.spool) reports an empty spool and no dropped batch or item.
# Findings are spooled before the status is sent, so that heartbeat saw them.
log "waiting for a heartbeat after the scan that reports an empty spool (at most ${SPOOL_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + SPOOL_TIMEOUT_S ))
while :; do
  spool="$(console_sql "SELECT concat_ws(',', a.last_seen_at > j.finished_at + interval '1 second',
      coalesce(a.spool->>'batches', 'none'), coalesce(a.spool->>'dropped_batches', '0'),
      coalesce(a.spool->>'dropped_items', '0'))
    FROM agents a JOIN jobs j ON j.agent_id = a.id
    WHERE a.id = '${AGENT_ID}' AND j.id = '${SCAN_JOB_ID}' AND j.finished_at IS NOT NULL")" \
    || fail "cannot read the agent spool status"
  case "$spool" in
    t,*,*,*) IFS=, read -r _ batches dropped_batches dropped_items <<<"$spool"
      [ "$dropped_batches" = 0 ] && [ "$dropped_items" = 0 ] \
        || fail "the agent dropped findings ($dropped_batches batch(es), $dropped_items item(s))"
      [ "$batches" = 0 ] && break ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "no heartbeat with an empty spool within ${SPOOL_TIMEOUT_S} s after the scan ('$spool')"
  sleep 2
done
# Secondary: the agent log has no lost, dropped or rejected result batch.
lost="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|rejected batch items|unreadable spool file' || true)"
[ "$lost" = 0 ] || fail "the agent log shows $lost lost / dropped / rejected result batch line(s)"
unset spool batches dropped_batches dropped_items lost

# Secondary: the stored findings are non-zero and stable for 6 s.
deadline=$(( $(date +%s) + 60 ))
prev=-1
stable=0
while :; do
  n="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = 'pg-e2e'")" \
    || fail "cannot count the findings"
  if [ "$n" -gt 0 ] && [ "$n" = "$prev" ]; then stable=$((stable + 1)); else stable=0; fi
  [ "$stable" -ge 3 ] && break
  [ "$(date +%s)" -lt "$deadline" ] || fail "findings not stable within 60 s ($n stored)"
  prev="$n"
  sleep 2
done
log "$n finding(s) stored for pg-e2e"

log "checking the ingested findings against dev/ground-truth.json (normalized value-bearing names)"
# Written under the private work directory, never into the uploaded logs.
console_sql "SELECT coalesce(json_agg(json_build_object('database_name', database_name,
    'schema_name', schema_name, 'object_name', object_name, 'field_name', field_name,
    'classifier', classifier) ORDER BY location_key, classifier), '[]')
  FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = 'pg-e2e'" \
  >"$E2E_WORK_DIR/findings.json" || fail "cannot read the findings"
timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine postgresql \
  --require-classifier pii.email --require-classifier pii.card_number \
  --require-classifier pii.iban --require-classifier secret.aws_key \
  "$E2E_WORK_DIR/findings.json" >&2 || fail "findings check failed (see above)"

# The findings page renders the masked samples decrypted (they are encrypted at rest, so the
# database dump cannot show a masking failure): it is scanned too, below. It must be complete
# (every finding listed, under the listing cap; every finding with samples shows them; none
# `unavailable`) and no masked sample may keep more than 4 digits (partial masking regression).
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

log "checking that no secret is stored in clear text in the console database"
# Written under the private work directory (removed on exit), never into the uploaded logs.
db_dump="$E2E_WORK_DIR/console-db.sql"
timeout 120 docker compose -f "$HERE/docker-compose.yml" exec -T db \
  pg_dump -U postgres -d databastion >"$db_dump" 2>"$E2E_WORK_DIR/pg_dump.err" \
  || fail "pg_dump of the console database failed"
grep -q '^CREATE TABLE ' "$db_dump" || fail "the console database dump holds no table"
db_leaks=0
for name in agent_secret enrollment_token admin_password target_pg_password target_agent_password; do
  [ -s "$P/$name" ] || fail "secret $name was never registered"
  if LC_ALL=C grep -qFf "$P/$name" -- "$db_dump"; then
    log "LEAK: $name stored in clear text in the console database"
    db_leaks=$((db_leaks + 1))
  fi
done
[ "$db_leaks" -eq 0 ] || fail "$db_leaks secret(s) in clear text in the console database"

# --------------------------------------------------------------------------- invariant I2 (P2-E)
# No value of dev/ground-truth.json (engine postgresql), and no value-bearing table name, in clear
# text (definition in i2_check.py) in: the plain pg_dump of the whole console database (every
# schema: public, pgboss...), every console / agent / proxy log, and the rendered findings page.
# target-pg's own log (the source database) and all.log (which includes it) are not console or
# agent output. Only counts, needle ids and file names are printed, never a value.
log "invariant I2: no ground-truth value in clear text in the console database, logs or findings page"
i2_scan() {
  timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine postgresql "$@" >&2
}
grep -q '^CREATE SCHEMA pgboss;' "$db_dump" || fail "the console database dump has no pgboss schema"
grep -q '^COPY public.findings ' "$db_dump" || fail "the console database dump has no findings table"
i2_failed=0
i2_scan --label console-db "$db_dump" || i2_failed=1
# Positive control of the log scan: a canary file holding one ground-truth value, next to the
# logs (in the private work directory), must be reported.
mkdir -p "$E2E_WORK_DIR/i2-canary"
jq -r '[.locations[] | select(.engine == "postgresql") | .values[]?] | .[0]' "$GROUND_TRUTH" \
  >"$E2E_WORK_DIR/i2-canary/zz-i2-canary.log"
canary_rc=0
i2_scan --label log-canary --exclude target-pg.log --exclude all.log \
  "$E2E_LOG_DIR" "$E2E_WORK_DIR/i2-canary" 2>"$E2E_WORK_DIR/i2-canary.out" || canary_rc=$?
if [ "$canary_rc" -ne 1 ] || ! grep -q 'file=zz-i2-canary.log$' "$E2E_WORK_DIR/i2-canary.out"; then
  fail "I2 log scan positive control: canary not detected"
fi
rm -rf -- "$E2E_WORK_DIR/i2-canary" "$E2E_WORK_DIR/i2-canary.out"
i2_scan --label logs --exclude target-pg.log --exclude all.log "$E2E_LOG_DIR" || i2_failed=1
i2_scan --label findings-page "$E2E_WORK_DIR/findings-page.html" || i2_failed=1
rm -f -- "$db_dump" "$E2E_WORK_DIR/pg_dump.err" "$E2E_WORK_DIR/findings-page.html" \
  "$E2E_WORK_DIR/findings.json"
[ "$i2_failed" -eq 0 ] || fail "invariant I2: ground-truth value(s) in clear text (ids above)"

log "all checks passed (revocation latency ${latency} ms)"
