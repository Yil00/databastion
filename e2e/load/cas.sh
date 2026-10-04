#!/usr/bin/env bash
# Load run of the CAS target (ROADMAP P8-D, ADR-0041 decision 14 "Load"; e2e/load/README.md "CAS
# target"): the console, the agent and the CAS 8.0 dev overlay with its JPA ticket registry
# (e2e/docker-compose.yml + e2e/docker-compose.cas.yml + docker-compose.cas.yml here, project
# databastion-load-cas). The CAS connector reads local files only (ADR-0041 decision 2): there is no
# database to measure for its sources, so this run measures
#   1. the Audit path under a CAS login workload (e2e/cas_scenario.py load, from the host): a fixed
#      rate of successful logins (each with a validated service ticket) and of failed ones (random
#      names, one client address), without then with Audit: every audit record that gives an event
#      reaches the console (connect, read, auth_failure: within 1 %, the `*` aggregate included),
#      nothing dropped, the spool drained, the CAS login latency (p95) with and without Audit, and
#      the CAS container's CPU (the agent only reads its audit log);
#   2. the agent's CPU and RSS while it tails the busy audit log (rotations included), bounded and
#      without monotonic growth;
#   3. the CAS store guard's ticket aggregate (ADR-0041 decision 5) on the JPA ticket table the
#      workload filled: the database CPU impact of a Discovery scan of the PostgreSQL target holding
#      it (< 2 %, as e2e/load/run.sh).
# The report is loadlib.py's (same checks, limits and format as run.sh).
#
# Requires: docker (compose v2.24+), openssl, curl, jq, python3. Every secret is generated at run time,
# registered, masked under GitHub Actions, redacted from the collected logs and removed on exit.
# Nothing listens outside 127.0.0.1.
# shellcheck disable=SC2016 # jq programs (fact, jq -c) are single-quoted on purpose, file-wide
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="$HERE/.."
LOADLIB="$HERE/loadlib.py"
SCENARIO="$E2E/cas_scenario.py"
PROJECT="databastion-load-cas"
COMPOSE_ARGS=(-p "$PROJECT" -f "$E2E/docker-compose.yml" -f "$E2E/docker-compose.cas.yml" -f "$HERE/docker-compose.cas.yml")

# ------------------------------------------------------------------------------ settings
export E2E_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
export E2E_CAS_PORT="${LOAD_CAS_PORT:-8282}"
export LOAD_CAS_CPUS="${LOAD_CAS_CPUS:-2}"         # CPU limit of CAS
export LOAD_DB_CPUS="${LOAD_DB_CPUS:-2}"           # CPU limit of its ticket database (scan impact)
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs-cas}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results-cas}"
LOAD_IDLE_S="${LOAD_IDLE_S:-45}"
LOAD_CAS_RATE="${LOAD_CAS_RATE:-4}"                # successful logins per second
LOAD_CAS_FAIL_RATE="${LOAD_CAS_FAIL_RATE:-1}"      # failed logins per second
LOAD_CAS_WORKERS="${LOAD_CAS_WORKERS:-16}"
LOAD_CAS_WARMUP_S="${LOAD_CAS_WARMUP_S:-90}"       # unmeasured workload first (CAS's JIT warm-up)
LOAD_BASELINE_S="${LOAD_BASELINE_S:-120}"          # workload without Audit
LOAD_SOAK_S="${LOAD_SOAK_S:-600}"                  # workload with Audit (also the agent resource run)
LOAD_DRAIN_TIMEOUT_S="${LOAD_DRAIN_TIMEOUT_S:-300}"
LOAD_SAMPLE_INTERVAL="${LOAD_SAMPLE_INTERVAL:-0.5}"
for v in LOAD_IDLE_S LOAD_CAS_RATE LOAD_CAS_WORKERS LOAD_CAS_WARMUP_S LOAD_BASELINE_S LOAD_SOAK_S LOAD_DRAIN_TIMEOUT_S \
    E2E_HTTPS_PORT E2E_CAS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
[[ "$LOAD_CAS_FAIL_RATE" =~ ^[0-9]+$ ]] || { echo "LOAD_CAS_FAIL_RATE must be an integer" >&2; exit 2; }
[ "$LOAD_SOAK_S" -le 1800 ] || { echo "LOAD_SOAK_S must be at most 1800 seconds" >&2; exit 2; }
CAS_TARGET="cas-load"
DB_TARGET="casdb-load"
HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
CAS_BASE="http://127.0.0.1:${E2E_CAS_PORT}/cas"
SERVICE="https://intranet.example.org/login"
USERS=(camille.martin@example.org hugo.durand@example.net olivia.smith@example.com)
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SPOOL_TIMEOUT_S=120

log() { printf '[load-cas %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
now_s() { date +%s.%3N; }
T_RUN="$(date +%s)"
T_PHASE="$T_RUN"
TIMINGS=""
phase_done() {
  local now
  now="$(date +%s)"
  TIMINGS+="$1 $((now - T_PHASE))s; "
  T_PHASE="$now"
}
for tool in docker openssl curl jq timeout python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
unset E2E_CAS_TICKET_CRYPTO

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load-cas.XXXXXX")"
W="$LOAD_WORK_DIR"
# The e2e compose files read their run directory from E2E_WORK_DIR.
export E2E_WORK_DIR="$W"
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/secrets" "$W/tls" "$W/agent" "$W/out"
FACTS="$W/out/facts.jsonl"
HEARTBEATS="$W/out/heartbeats.jsonl"
SAMPLES_DB="$W/out/samples-db.jsonl"
SAMPLES_AGENT="$W/out/samples-agent.jsonl"
: >"$FACTS"
: >"$HEARTBEATS"
fact() { jq -nc "$@" >>"$FACTS"; }

# ------------------------------------------------------------------------------ secret registry
P="$W/secret-patterns"
mkdir -p "$P"
register_secret() {
  local name="$1" value="$2"
  if [ -z "$value" ] || [ "$value" = null ]; then return 0; fi
  printf '%s\n' "$value" >"$P/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}
# shellcheck disable=SC2016 # awk program, not shell
REDACT_AWK='
BEGIN { if ((getline s < ENVIRON["SECRET_FILE"]) <= 0 || s == "") exit 2; rep = ENVIRON["REDACTION"] }
{
  out = ""; line = $0
  while ((i = index(line, s)) > 0) { out = out substr(line, 1, i - 1) rep; line = substr(line, i + length(s)) }
  print out line
}'
leak_scan() {
  local dir="$1" pdir="$2" f files found=0
  [ -d "$dir" ] || return 0
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
redact_dir() {
  local dir="$1" pdir="${2:-$P}" f name file tmp="$W/redact.tmp"
  local -a hits
  [ -d "$dir" ] || return 0
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

compose() { timeout 120 docker compose "${COMPOSE_ARGS[@]}" "$@"; }
BG_PIDS=()
stop_background() {
  local pid
  for pid in "${BG_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${BG_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  BG_PIDS=()
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
  local status=$? svc canary_dir="$W/canary-pattern" canary_hits leaked line d
  set +e
  stop_background
  phase_done exit
  log "collecting logs into $LOAD_LOG_DIR"
  for svc in db migrate web worker proxy cas-db cas agent; do
    compose logs --no-color --timestamps "$svc" >"$LOAD_LOG_DIR/$svc.log" 2>&1
  done
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  cp -f "$W"/out/*.jsonl "$W"/out/*.json "$LOAD_LOG_DIR/" 2>/dev/null
  # Leak scan before redaction (as run.sh): canary first, then the registry.
  mkdir -p "$canary_dir"
  printf 'load-canary-%s\n' "$(openssl rand -hex 16)" >"$canary_dir/canary"
  { printf 'before '; cat "$canary_dir/canary"; printf 'after\n'; } >"$LOAD_LOG_DIR/zz-canary.log"
  canary_hits="$(leak_scan "$LOAD_LOG_DIR" "$canary_dir")"
  redact_dir "$LOAD_LOG_DIR" "$canary_dir" 2>/dev/null
  if [ "$canary_hits" != "canary: zz-canary.log " ] || ! grep -qF '<REDACTED:canary>' "$LOAD_LOG_DIR/zz-canary.log" \
      || grep -qFf "$canary_dir/canary" -- "$LOAD_LOG_DIR/zz-canary.log"; then
    log "FAIL: leak scan positive control: canary not detected or not redacted"
    status=1
  fi
  rm -rf -- "$LOAD_LOG_DIR/zz-canary.log" "$canary_dir"
  for d in "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR"; do
    if ! leaked="$(leak_scan "$d" "$P")"; then
      while IFS= read -r line; do log "LEAK: $line"; done <<<"$leaked"
      log "FAIL: secret(s) found in $d (redacted before being kept)"
      status=1
    fi
  done
  redact_dir "$LOAD_LOG_DIR"
  redact_dir "$LOAD_RESULTS_DIR"
  # CAS prints the ticket, cookie and webflow keys it generates at each start (no key is configured:
  # dev only); they die with the container, but are not kept in the logs either.
  redact_cas_keys "$LOAD_LOG_DIR"
  log "tearing down"
  timeout 180 docker compose "${COMPOSE_ARGS[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$W"
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------------------ secrets, CA, agent.yaml
rand_hex() { openssl rand -hex "$1"; }
S="$W/secrets"
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; register_secret "$1" "$2"; }
DB_OWNER_PASSWORD="$(rand_hex 24)"
DB_APP_PASSWORD="$(rand_hex 24)"
put_secret db_password "$(rand_hex 24)"
put_secret db_owner_password "$DB_OWNER_PASSWORD"
put_secret db_app_password "$DB_APP_PASSWORD"
put_secret encryption_key "$(openssl rand -base64 32)"
put_secret metrics_token "$(rand_hex 32)"
put_secret admin_password "$(rand_hex 24)"
put_secret target_agent_password "$(rand_hex 24)"
put_secret cas_db_admin_password "$(rand_hex 24)"
put_secret cas_db_password "$(rand_hex 24)"
put_secret cas_user_password "$(rand_hex 24)"
umask 022
printf 'postgresql://databastion_owner:%s@db:5432/databastion' "$DB_OWNER_PASSWORD" >"$S/db_owner_url"
printf 'postgresql://databastion_runtime:%s@db:5432/databastion' "$DB_APP_PASSWORD" >"$S/db_url"
umask 077
unset DB_OWNER_PASSWORD DB_APP_PASSWORD
chmod 0700 "$S"

log "generating the throwaway test CA and the proxy certificate"
T="$W/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion CAS load test CA" \
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
# Bind-mount sources of the e2e services this run never starts (interpolated anyway).
for f in mysql-ca.pem mariadb-ca.pem ldap-ca.pem mailpit.crt mailpit.key; do : >"$T/$f"; done

# The same targets as e2e/cas.sh: the registry and audit log (read-only mounts), and the ticket
# registry's database as the ADR-0012 minimal role with the ADR-0041 decision 6 column grants.
cat >"$W/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
targets:
  - id: ${CAS_TARGET}
    engine: cas
    cas:
      service_registry:
        json_dir: /srv/cas/services
      audit_log:
        path: /var/log/cas/cas_audit.log
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
chmod 0644 "$W/agent/agent.yaml"

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_CAS_IMAGE
fi
if [ "${LOAD_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  for img in "${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}" \
      "${E2E_CAS_IMAGE:-databastion-dev/cas:8.0.2-overlay}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "LOAD_SKIP_BUILD=1 but image $img is missing"
  done
  log "LOAD_SKIP_BUILD=1: using the existing images"
else
  log "building images (web, agent, cas)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent cas
fi
phase_done build

log "staging the CAS registry and audit log volumes; starting the console, cas-db and CAS (${LOAD_CAS_CPUS} / ${LOAD_DB_CPUS} CPUs)"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps cas-files \
  >"$LOAD_LOG_DIR/cas-files.log" 2>&1 || fail "cas-files failed"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy cas-db cas
CURL=(curl -sS --noproxy '*' --max-time 40 --cacert "$T/ca.crt" --resolve "${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}:127.0.0.1"
  -b "$W/cookies" -c "$W/cookies")
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done
deadline=$(( $(date +%s) + 300 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q cas)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "CAS not healthy within 300 s"
  sleep 3
done
casdb_sql() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" exec -T cas-db psql -XAt -v ON_ERROR_STOP=1 -U postgres -d cas -c "$1"
}
# The same in read-only transactions, for the queries that only read.
casdb_ro() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" exec -T -e "PGOPTIONS=-c default_transaction_read_only=on" cas-db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d cas -c "$1"
}
deadline=$(( $(date +%s) + 180 ))
until [ "$(casdb_ro "SELECT to_regclass('public.cas_tickets') IS NOT NULL")" = t ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no table cas_tickets within 180 s"
  sleep 2
done
casdb_sql "REVOKE ALL ON public.cas_tickets FROM PUBLIC, databastion_agent;
  GRANT SELECT (type, creation_time, expiration_time) ON public.cas_tickets TO databastion_agent" >/dev/null \
  || fail "cannot set the agent's column grants on cas_tickets"
phase_done start

# ------------------------------------------------------------------------------ samplers
declare -A CID=()
for svc in cas cas-db; do
  CID[$svc]="$(compose ps -q "$svc")"
  [ -n "${CID[$svc]}" ] || fail "no container for $svc"
done
log "sampling the cgroup CPU counters of cas and cas-db every ${LOAD_SAMPLE_INTERVAL} s"
python3 "$LOADLIB" sample --out "$SAMPLES_DB" --interval "$LOAD_SAMPLE_INTERVAL" \
  "cas=${CID[cas]}" "cas-db=${CID[cas-db]}" 2>"$W/out/sampler-db.err" &
BG_PIDS+=("$!")
sleep 3
head -n -1 "$SAMPLES_DB" | jq -e 'select(.c["cas"].cpu_usec != null and .c["cas-db"].cpu_usec != null)' >/dev/null 2>&1 \
  || fail "cannot read the cgroup CPU counters (see sampler-db.err)"
fact --arg t "$CAS_TARGET" '{kind: "target", target: $t, container: "cas"}'
fact --arg t "$DB_TARGET" '{kind: "target", target: $t, container: "cas-db"}'
fact --argjson r "$LOAD_CAS_RATE" --argjson f "$LOAD_CAS_FAIL_RATE" --argjson soak "$LOAD_SOAK_S" \
  --argjson base "$LOAD_BASELINE_S" --argjson cpus "$LOAD_CAS_CPUS" \
  '{kind: "config", harness: "cas", cas_login_rate: $r, cas_failed_login_rate: $f, soak_s: $soak, baseline_s: $base, cas_cpus: $cpus}'

# ------------------------------------------------------------------------------ admin, token, enroll
CSRF=""
api() {
  local method="$1" path="$2" body="${3:-}" out="$W/resp" code
  local args=(-X "$method" -o "$out" -w '%{http_code}' -H "Origin: ${BASE_URL}")
  [ -n "$CSRF" ] && args+=(-H "@$W/csrf.hdr")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  code="$("${CURL[@]}" "${args[@]}" "${BASE_URL}${path}")" || code="000"
  printf '%s\n' "$code"
  cat "$out" 2>/dev/null || true
}
status_of() { head -n1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }
api_json() { printf '%s' "$3" >"$W/req.json"; api "$1" "$2" "$W/req.json"; }
# Read-only transactions: the harness only reads the console database.
console_sql() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" exec -T -e "PGOPTIONS=-c default_transaction_read_only=on" db psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
files_root() { timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps agent-files "$1"; }
files_agent() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps --user 10001:10001 agent-files "$1"
}
log "bootstrapping the administrator, enrolling the agent"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps bootstrap-admin \
  >"$LOAD_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"
jq -n --rawfile p "$S/admin_password" '{username: "e2e-admin", password: $p}' >"$W/login.json"
r="$(api POST /api/auth/login "$W/login.json")"
rm -f "$W/login.json"
[ "$(status_of "$r")" = 200 ] || fail "login: HTTP $(status_of "$r")"
CSRF="$(body_of "$r" | jq -r '.csrf_token')"
register_secret csrf_token "$CSRF"
printf 'X-CSRF-Token: %s\n' "$CSRF" >"$W/csrf.hdr"
register_secret session_cookie "$(awk '$6 ~ /databastion_session$/ {print $7}' "$W/cookies")"
r="$(api_json POST /api/enrollment-tokens '{"label":"load-cas"}')"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
register_secret enrollment_token "$ENROLLMENT_TOKEN"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent --version \
  >"$LOAD_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
files_agent 'umask 077; cat > /secrets/target_agent_password' <"$S/target_agent_password"
printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'
unset ENROLLMENT_TOKEN
timeout 120 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent \
  enroll --config /etc/databastion/agent.yaml --token-file /run/databastion-secrets/enrollment_token \
  >"$LOAD_LOG_DIR/agent-enroll.log" 2>&1 || fail "agent enroll failed (see agent-enroll.log)"
files_agent 'rm -f /secrets/enrollment_token'
identity="$(files_agent 'cat /state/identity.json')"
AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
register_secret agent_secret "$(jq -r '.agent_secret' <<<"$identity")"
unset identity
[[ "$AGENT_ID" =~ $UUID_RE ]] || fail "no agent id"
phase_done enroll

# ------------------------------------------------------------------------------ idle baseline A
log "idle baseline without the agent (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_no_agent", t0: $t0, t1: $t1}'

# ------------------------------------------------------------------------------ agent run
log "starting databastion-agent run"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
CID[agent]="$(compose ps -q agent)"
python3 "$LOADLIB" sample --out "$SAMPLES_AGENT" --interval 1 "agent=${CID[agent]}" 2>"$W/out/sampler-agent.err" &
BG_PIDS+=("$!")
agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}
deadline=$(( $(date +%s) + 120 ))
until a="$(agent_json 2>/dev/null)" && [ -n "$a" ] && jq -e --arg c "$CAS_TARGET" --arg d "$DB_TARGET" '.status == "online"
    and (([$c, $d] - [.targets[] | select(.present and .reachable == true) | .targetId]) == [])' <<<"$a" >/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "agent not online with ${CAS_TARGET} and ${DB_TARGET} reachable within 120 s"
  sleep 2
done
log "agent online: $(jq -c '[.targets[] | {targetId, engine, reachable, auditLevel}]' <<<"$a")"
(
  while :; do
    console_sql "SELECT json_build_object('t', extract(epoch from now()), 'last_seen', extract(epoch from last_seen_at),
      'spool', spool, 'metrics', metrics) FROM agents WHERE id = '${AGENT_ID}'" >>"$HEARTBEATS" 2>/dev/null || true
    sleep 10
  done
) &
BG_PIDS+=("$!")
log "idle baseline with the agent running, no job (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_agent", t0: $t0, t1: $t1}'
phase_done agent

# ------------------------------------------------------------------------------ workloads
# run_workload PHASE DURATION: cas_scenario.py load from the host. issued = the records that give
# an event: per successful login a connect (AUTHENTICATION_SUCCESS) and a read
# (SERVICE_TICKET_CREATED), per failed login an auth_failure (AUTHENTICATION_FAILED).
user_args=()
for u in "${USERS[@]}"; do user_args+=(--user "$u"); done
run_workload() {
  local phase="$1" dur="$2" t_start rc=0
  WL_START_UTC="$(date -u +'%Y-%m-%dT%H:%M:%S')"
  log "workload ($phase): ${LOAD_CAS_RATE} logins/s and ${LOAD_CAS_FAIL_RATE} failed logins/s, ${dur} s"
  t_start="$(now_s)"
  timeout $((dur + 300)) python3 "$SCENARIO" load --base "$CAS_BASE" --password-file "$S/cas_user_password" \
    "${user_args[@]}" --service "$SERVICE" --rate "$LOAD_CAS_RATE" --fail-rate "$LOAD_CAS_FAIL_RATE" \
    --duration "$dur" --workers "$LOAD_CAS_WORKERS" --out "$W/out/cas-$phase.json" \
    >"$W/out/cas-$phase.stdout" 2>"$W/out/cas-$phase.stderr" || rc=$?
  WL_END="$(now_s)"
  [ "$rc" = 0 ] || { cat "$W/out/cas-$phase.stderr" >&2; fail "the CAS workload ($phase) exited $rc"; }
  # The window ends when the last login returned: a saturated CAS finishes after the schedule.
  fact --arg name "workload_audit_$phase" --argjson t0 "$(jq -n --argjson t "$t_start" '$t + 5')" \
    --argjson t1 "$WL_END" '{kind: "window", name: $name, t0: $t0, t1: $t1}'
  jq -c --arg phase "$phase" --arg t "$CAS_TARGET" --argjson rate "$LOAD_CAS_RATE" '{kind: "workload", target: $t,
      phase: $phase, tool: "cas_scenario", rate: $rate, issued: (2 * .logins + .failed_logins),
      failed: ((.errors | add) // 0), p95_ms: .post_ms.p95, p99_ms: .post_ms.p99,
      logins: .logins, failed_logins: .failed_logins, late_starts: .late_starts, elapsed_s: .elapsed_s}' \
    "$W/out/cas-$phase.json" >>"$FACTS"
  log "workload ($phase): $(jq -c '{logins, failed_logins, errors, late_starts, elapsed_s, post_ms}' "$W/out/cas-$phase.json")"
}
# A freshly started CAS (JIT compilation, caches) is several times slower for its first minute or
# two: an unmeasured warm-up first, so that the baseline compares with the Audit run.
log "warm-up workload (${LOAD_CAS_WARMUP_S} s, not measured)"
timeout $((LOAD_CAS_WARMUP_S + 300)) python3 "$SCENARIO" load --base "$CAS_BASE" --password-file "$S/cas_user_password" \
  "${user_args[@]}" --service "$SERVICE" --rate "$LOAD_CAS_RATE" --fail-rate "$LOAD_CAS_FAIL_RATE" \
  --duration "$LOAD_CAS_WARMUP_S" --workers "$LOAD_CAS_WORKERS" --out "$W/out/cas-warmup.json" \
  >/dev/null 2>"$W/out/cas-warmup.stderr" || { cat "$W/out/cas-warmup.stderr" >&2; fail "the CAS warm-up workload failed"; }
log "warm-up: $(jq -c '{logins, failed_logins, errors, elapsed_s, post_ms}' "$W/out/cas-warmup.json")"
phase_done warmup
run_workload off "$LOAD_BASELINE_S"
phase_done workload-off

# ------------------------------------------------------------------------------ Audit on
agent_log_count() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
    | grep -F "$1" | grep -cF "\"target_id\":\"$2\"" || true
}
prev="$(agent_log_count "audit stream started" "$CAS_TARGET")"
log "enabling Audit on ${CAS_TARGET}"
r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${CAS_TARGET}/audit" '{"enabled":true,"derive_from_findings":true}')"
if [ "$(status_of "$r")" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
  digest="$(body_of "$r" | jq -r '.digest')"
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${CAS_TARGET}/audit" \
    "{\"enabled\":true,\"derive_from_findings\":true,\"confirm\":\"${digest}\"}")"
fi
[ "$(status_of "$r")" = 202 ] || fail "audit.configure: HTTP $(status_of "$r")"
deadline=$(( $(date +%s) + 90 ))
until [ "$(agent_log_count "audit stream started" "$CAS_TARGET")" -gt "$prev" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the Audit stream of ${CAS_TARGET} did not start within 90 s"
  sleep 1
done
sleep 5
phase_done audit-setup

run_workload on "$LOAD_SOAK_S"
SOAK_END="$WL_END"
SOAK_START_UTC="$WL_START_UTC"
phase_done workload-on

# ------------------------------------------------------------------------------ drain
events_sql() {
  printf "FROM access_events WHERE agent_id = '%s' AND target_id = '%s' AND action IN ('connect', 'read', 'auth_failure')" \
    "$AGENT_ID" "$CAS_TARGET"
}
want="$(grep '"kind":"workload"' "$FACTS" | jq -s 'map(select(.phase == "on"))[0].issued // 0')"
log "waiting until every event of the Audit run is stored (${want} expected, at most ${LOAD_DRAIN_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + LOAD_DRAIN_TIMEOUT_S ))
while :; do
  got="$(console_sql "SELECT coalesce(sum(aggregated_count), 0) $(events_sql)")"
  [ "$got" -ge "$want" ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "WARNING: not every event stored within ${LOAD_DRAIN_TIMEOUT_S} s: ${got}/${want}"
    break
  fi
  sleep 5
done
log "events stored: ${got}/${want} ($(console_sql "SELECT string_agg(action || ' ' || n, ', ') FROM (SELECT action, sum(aggregated_count) AS n $(events_sql) GROUP BY 1) x"))"
console_sql "SELECT json_build_object('kind', 'events', 'target', '${CAS_TARGET}',
    'received', coalesce(sum(aggregated_count), 0), 'events', count(*),
    'lag_p95_s', round(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch from received_at - coalesce(ts_last, ts))::float8)::numeric, 1),
    'lag_max_s', round(max(extract(epoch from received_at - coalesce(ts_last, ts)))::numeric, 1),
    'drain_s', CASE WHEN coalesce(sum(aggregated_count), 0) >= $want
      THEN round((extract(epoch from max(received_at)) - $SOAK_END)::numeric, 1) END)
  $(events_sql)" >>"$FACTS"
console_sql "SELECT json_build_object('kind', 'events_timeline', 'target', '${CAS_TARGET}',
    'buckets', coalesce(json_agg(json_build_array(b, n) ORDER BY b), '[]'))
  FROM (SELECT (floor(extract(epoch from ts) / 10) * 10)::bigint AS b, sum(aggregated_count) AS n
        $(events_sql) GROUP BY 1) AS x" >>"$FACTS"
# Source side: the records that give an event in the CAS audit log since the Audit run started,
# rotations included (read as root from the log volume).
src="$(timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps --entrypoint sh cas-files -c \
  'ls /state/logs/cas | grep -c "^cas_audit-" || true; cat /state/logs/cas/cas_audit-*.log /state/logs/cas/cas_audit.log 2>/dev/null; true' \
  2>/dev/null | python3 -c 'import json, sys
rot = sys.stdin.readline().strip()
since = sys.argv[1]
n = 0
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if isinstance(r, dict) and str(r.get("when", ""))[:19] >= since and r.get("action") in (
            "AUTHENTICATION_SUCCESS", "SERVICE_TICKET_CREATED", "AUTHENTICATION_FAILED"):
        n += 1
print(rot, n)' "$SOAK_START_UTC")" || src=""
read -r src_rot src_n <<<"$src"
if [[ "${src_n:-}" =~ ^[0-9]+$ ]]; then
  fact --arg t "$CAS_TARGET" --argjson n "$src_n" --argjson r "${src_rot:-0}" \
    '{kind: "source", target: $t, statements: $n, rotated_files: $r}'
  log "CAS audit log: ${src_n} records that give an event since the Audit run started, ${src_rot:-0} rotated file(s)"
fi

wait_spool_empty() {
  local since="$1" spool batches db di deadline
  deadline=$(( $(date +%s) + SPOOL_TIMEOUT_S ))
  while :; do
    spool="$(console_sql "SELECT concat_ws(',', last_seen_at > to_timestamp($since) + interval '1 second',
        coalesce(spool->>'batches', 'none'), coalesce(spool->>'dropped_batches', '0'),
        coalesce(spool->>'dropped_items', '0')) FROM agents WHERE id = '${AGENT_ID}'")" || return 1
    case "$spool" in
      t,*,*,*) IFS=, read -r _ batches db di <<<"$spool"
        if [ "$db" != 0 ] || [ "$di" != 0 ]; then return 1; fi
        if [ "$batches" = 0 ]; then return 0; fi ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}
if wait_spool_empty "$(now_s)"; then fact '{kind: "spool_drained", ok: true, batches: 0}'
else fact '{kind: "spool_drained", ok: false}'; fi
phase_done drain

# ------------------------------------------------------------------------------ ticket aggregate
# The CAS store guard's only read of the JPA ticket table the workload filled (ADR-0041 decision 5):
# a Discovery scan of the PostgreSQL target, measured as run.sh measures its scans.
n_tickets="$(casdb_ro "SELECT count(*) FROM public.cas_tickets")"
log "Discovery scan of ${DB_TARGET} (the ticket aggregate over ${n_tickets} tickets)"
printf '{"sample_rows":200,"max_duration_s":900,"statement_timeout_ms":30000}' >"$W/scan-req.json"
sleep 2
r="$(api POST "/api/agents/${AGENT_ID}/targets/${DB_TARGET}/scan" "$W/scan-req.json")"
[ "$(status_of "$r")" = 202 ] || fail "scan request: HTTP $(status_of "$r")"
job_id="$(body_of "$r" | jq -r '.job_id')"
[[ "$job_id" =~ $UUID_RE ]] || fail "scan request: no job id"
deadline=$(( $(date +%s) + 960 ))
while :; do
  status="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")"
  case "$status" in succeeded | failed | cancelled | expired) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "scan of ${DB_TARGET} not finished in time ($status)"
  sleep 1
done
sleep 2
read -r s0 s1 <<<"$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at) FROM jobs WHERE id = '$job_id'")"
[[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of ${DB_TARGET}: no delivery / end time ($status)"
fact --arg target "$DB_TARGET" --arg status "$status" --argjson t0 "$s0" --argjson t1 "$s1" --argjson rows "$n_tickets" \
  '{kind: "scan", target: $target, status: $status, t0: $t0, t1: $t1, tables: 1, rows: $rows}'
log "scan of ${DB_TARGET}: $status in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s"
[ "$status" = succeeded ] || fail "scan of ${DB_TARGET} ended '$status'"
wait_spool_empty "$s1" || log "WARNING: no heartbeat with an empty spool after the scan"
fact --arg target "$DB_TARGET" --argjson n "$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${DB_TARGET}'")" \
  '{kind: "findings", target: $target, count: $n}'
lost="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|events dropped|rejected batch items|unreadable spool file' || true)"
fact --argjson n "$lost" '{kind: "agent_log", lost: $n}'
sleep 12
stop_background
phase_done scan

# ------------------------------------------------------------------------------ report
log "computing the results"
set +e
python3 "$LOADLIB" report --facts "$FACTS" --samples "$SAMPLES_DB" "$SAMPLES_AGENT" \
  --heartbeats "$HEARTBEATS" --out "$LOAD_RESULTS_DIR"
rc=$?
set -e
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$LOAD_RESULTS_DIR/results.md" ]; then
  { echo "# CAS target"; cat "$LOAD_RESULTS_DIR/results.md"; } >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
