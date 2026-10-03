#!/usr/bin/env bash
# Load / database impact test (ROADMAP phase 7, "Load / database impact tests"; MVP criterion of
# docs/04-mvp-scope.md: "Impact on the monitored database < 2 % CPU during Discovery (bounded
# sampling)"). See e2e/load/README.md for what is measured, against what, and the limits.
#
#   1. Discovery: the database server's CPU attributable to a full Discovery scan of a scaled-up seed
#      (generated here, never committed), per target (PostgreSQL, MariaDB, MongoDB), as a share of the
#      server's CPU capacity: must be < 2 %.
#   2. Audit under load: a fixed-rate point-select workload (pgbench on PostgreSQL, sysbench on
#      MariaDB) without, then with Audit: every statement must reach the console as access events,
#      nothing dropped, the spool drained; the workload's p95 latency with and without Audit.
#   3. Agent resources: CPU and RSS of the agent over the Audit run, bounded, no monotonic growth.
#
# Requires: docker (compose v2), openssl, curl, jq, python3. Every secret is generated at run time
# under a private temporary directory, registered, masked under GitHub Actions, redacted from the
# collected logs and removed on exit, as in e2e/run.sh. Nothing listens outside 127.0.0.1.
# shellcheck disable=SC2016 # jq programs (fact, jq -c) are single-quoted on purpose, file-wide
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$HERE/docker-compose.yml"
LOADLIB="$HERE/loadlib.py"
SEED="$HERE/seed.py"

# ------------------------------------------------------------------------------ settings
export LOAD_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
export LOAD_DB_CPUS="${LOAD_DB_CPUS:-2}"          # CPU limit of each target = its "capacity"
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results}"
# Sampling is bounded per object: a scan's length (and its fixed costs' share) depends on the number
# of objects, not rows. Hundreds of objects make the scan long enough to measure.
LOAD_TABLES="${LOAD_TABLES:-400}"                 # PostgreSQL / MariaDB tables
LOAD_ROWS="${LOAD_ROWS:-1000000}"                 # rows over those tables, per engine
LOAD_MONGO_TABLES="${LOAD_MONGO_TABLES:-200}"     # MongoDB collections
LOAD_MONGO_ROWS="${LOAD_MONGO_ROWS:-500000}"      # documents over those collections
LOAD_SAMPLE_ROWS="${LOAD_SAMPLE_ROWS:-200}"       # scan parameters: the console defaults
LOAD_SCAN_MAX_S="${LOAD_SCAN_MAX_S:-900}"
LOAD_STATEMENT_TIMEOUT_MS="${LOAD_STATEMENT_TIMEOUT_MS:-30000}"
LOAD_IDLE_S="${LOAD_IDLE_S:-45}"                  # idle baselines (without / with the agent)
LOAD_CLIENTS="${LOAD_CLIENTS:-4}"                 # workload connections per engine
LOAD_WORKLOAD_TABLES="${LOAD_WORKLOAD_TABLES:-40}" # tables the workload reads (the first ones)
LOAD_PG_RATE="${LOAD_PG_RATE:-300}"               # statements per second (pgbench -R)
LOAD_MARIADB_RATE="${LOAD_MARIADB_RATE:-300}"     # statements per second (sysbench --rate)
LOAD_BASELINE_S="${LOAD_BASELINE_S:-120}"         # workload without Audit
LOAD_SOAK_S="${LOAD_SOAK_S:-600}"                 # workload with Audit (also the RSS / CPU run)
LOAD_DRAIN_TIMEOUT_S="${LOAD_DRAIN_TIMEOUT_S:-300}"
LOAD_SAMPLE_INTERVAL="${LOAD_SAMPLE_INTERVAL:-0.5}"
# Discovery targets: "<target id> <container (sample name)> <engine> <tables> <rows>".
DISCOVERY_TARGETS=("pg-load target-pg postgresql $LOAD_TABLES $LOAD_ROWS"
  "mariadb-load target-mariadb mariadb $LOAD_TABLES $LOAD_ROWS"
  "mongo-load target-mongo mongodb $LOAD_MONGO_TABLES $LOAD_MONGO_ROWS")
# Audit source of target-pg. `pgaudit` (default, required under GitHub Actions): the dev image
# (dev/postgres). `pss` (local runs only, for hosts that cannot build dev/postgres, as e2e's
# E2E_PG_AUDIT=pss): the plain pinned image with pg_stat_statements only (Limited level).
LOAD_PG_AUDIT="${LOAD_PG_AUDIT:-pgaudit}"
case "$LOAD_PG_AUDIT" in
  pgaudit) PG_AUDIT_STARTED="audit source: pgaudit log" ;;
  pss)
    [ "${GITHUB_ACTIONS:-}" != true ] || { echo "LOAD_PG_AUDIT=pss is for local runs only" >&2; exit 2; }
    export LOAD_TARGET_PG_IMAGE="postgres:17.11-bookworm@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
    export LOAD_PG_PRELOAD="pg_stat_statements"
    PG_AUDIT_STARTED="audit source: pg_stat_statements (Limited)" ;;
  *) echo "LOAD_PG_AUDIT must be pgaudit or pss" >&2; exit 2 ;;
esac
# Audit targets: "<target id> <agent log line of a started stream>".
AUDIT_TARGETS=("pg-load $PG_AUDIT_STARTED" "mariadb-load audit source: audit log file")
HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${LOAD_HTTPS_PORT}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SPOOL_TIMEOUT_S=120

for v in LOAD_TABLES LOAD_ROWS LOAD_MONGO_TABLES LOAD_MONGO_ROWS LOAD_SAMPLE_ROWS LOAD_SCAN_MAX_S \
    LOAD_STATEMENT_TIMEOUT_MS LOAD_IDLE_S LOAD_CLIENTS LOAD_WORKLOAD_TABLES LOAD_PG_RATE LOAD_MARIADB_RATE LOAD_BASELINE_S \
    LOAD_SOAK_S LOAD_DRAIN_TIMEOUT_S LOAD_HTTPS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
[[ "$LOAD_DB_CPUS" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "LOAD_DB_CPUS must be a number" >&2; exit 2; }
# The Audit run is bounded (the job's time budget, the targets' log volumes): 30 minutes at most.
LOAD_SOAK_MAX_S=1800
[ "$LOAD_SOAK_S" -le "$LOAD_SOAK_MAX_S" ] \
  || { echo "LOAD_SOAK_S must be at most $LOAD_SOAK_MAX_S seconds (got $LOAD_SOAK_S)" >&2; exit 2; }

log() { printf '[load %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
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

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load.XXXXXX")"
export LOAD_WORK_DIR
W="$LOAD_WORK_DIR"
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/secrets" "$W/tls" "$W/agent" "$W/out"
FACTS="$W/out/facts.jsonl"
HEARTBEATS="$W/out/heartbeats.jsonl"
SAMPLES_DB="$W/out/samples-db.jsonl"
SAMPLES_AGENT="$W/out/samples-agent.jsonl"
: >"$FACTS"
: >"$HEARTBEATS"

# fact JQ_ARGS... : appends one JSON object (built by jq -n) to the facts file.
fact() { jq -nc "$@" >>"$FACTS"; }

# ------------------------------------------------------------------------------ secret registry
# As in e2e/run.sh: one file per secret, matched with grep -Ff (never on a command line), masked
# under GitHub Actions, redacted from the collected logs on exit.
P="$W/secret-patterns"
mkdir -p "$P"
register_secret() {
  local name="$1" value="$2"
  [ -n "$value" ] && [ "$value" != null ] || return 0
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
# leak_scan DIR PATTERN_DIR: prints "<name>: <files>" for every secret of PATTERN_DIR found in DIR
# (fixed strings; only the secret's name is printed). Returns 1 if any is found (as e2e/run.sh).
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
# redact_dir DIR [PATTERN_DIR]: replaces every secret (default: the registry) in the files of DIR.
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

compose() { timeout 120 docker compose -f "$COMPOSE_FILE" "$@"; }

BG_PIDS=()
stop_background() {
  local pid
  for pid in "${BG_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${BG_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  BG_PIDS=()
}

cleanup() {
  local status=$? svc d
  set +e
  stop_background
  phase_done exit
  log "collecting logs into $LOAD_LOG_DIR"
  compose logs --no-color --timestamps >"$LOAD_LOG_DIR/all.log" 2>&1
  for svc in db migrate web worker proxy target-pg target-mariadb target-mongo agent; do
    compose logs --no-color --timestamps "$svc" >"$LOAD_LOG_DIR/$svc.log" 2>&1
  done
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  # Measurement inputs (counters, timestamps, the raw pgbench / sysbench summaries), for a failed
  # run's investigation: logs only, never in the results artifact.
  cp -f "$W"/out/*.jsonl "$W"/out/*.summary "$LOAD_LOG_DIR/" 2>/dev/null
  # Leak scan before redaction (as e2e/run.sh): positive control first, a random canary written to
  # the log directory must be found and redacted; then no registered secret may be in the logs or
  # the results. A leak fails the run (the files are still redacted below before being kept).
  local canary_dir="$W/canary-pattern" canary_hits leaked line
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
  log "tearing down"
  timeout 180 docker compose -f "$COMPOSE_FILE" --profile tools down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$W"
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------------------ secrets
rand_hex() { openssl rand -hex "$1"; }
S="$W/secrets"
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; }
DB_OWNER_PASSWORD="$(rand_hex 24)"
DB_APP_PASSWORD="$(rand_hex 24)"
declare -A SECRETS=(
  [db_password]="$(rand_hex 24)"
  [db_owner_password]="$DB_OWNER_PASSWORD"
  [db_app_password]="$DB_APP_PASSWORD"
  [encryption_key]="$(openssl rand -base64 32)"
  [admin_password]="$(rand_hex 24)"
  [target_pg_password]="$(rand_hex 24)"
  [target_agent_password]="$(rand_hex 24)"
  [target_client_password]="$(rand_hex 24)"
  [load_client_password]="$(rand_hex 24)"
  [target_mariadb_password]="$(rand_hex 24)"
  [target_mariadb_agent_password]="$(rand_hex 24)"
  [target_mongo_password]="$(rand_hex 24)"
  [target_mongo_agent_password]="$(rand_hex 24)"
)
for name in "${!SECRETS[@]}"; do
  register_secret "$name" "${SECRETS[$name]}"
  put_secret "$name" "${SECRETS[$name]}"
done
put_secret db_owner_url "postgresql://databastion_owner:${DB_OWNER_PASSWORD}@db:5432/databastion"
put_secret db_url "postgresql://databastion_runtime:${DB_APP_PASSWORD}@db:5432/databastion"
unset DB_OWNER_PASSWORD DB_APP_PASSWORD
chmod 0700 "$S"

log "generating the throwaway test CA and the proxy certificate"
T="$W/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion load test CA" \
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

# ------------------------------------------------------------------------------ agent.yaml
cat >"$W/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  max_sample_rows: 1000
  statement_timeout_ms: 30000
  max_scan_duration_s: 1800
targets:
  # Same accounts and settings as the e2e targets (e2e/run.sh): ADR-0012 minimal role, pgaudit
  # jsonlog; ADR-0018 minimal account over verified TLS, server_audit log; ADR-0026 account.
  - id: pg-load
    engine: postgres
    host: target-pg
    port: 5432
    account: databastion_agent
    secret:
      file: /run/databastion-secrets/target_agent_password
    postgres:
      databases: [shop]
      tls: disable_insecure
      audit_log: {path: /var/log/target-pg/postgresql.json, format: jsonlog}
  - id: mariadb-load
    engine: mariadb
    host: mariadb
    port: 3306
    account: databastion
    secret:
      file: /run/databastion-secrets/target_mariadb_agent_password
    mysql:
      tls: verify_full
      ca_file: /etc/databastion/mariadb-ca.pem
      audit_log: {path: /var/log/target-mariadb/server_audit.log, format: server_audit}
  - id: mongo-load
    engine: mongodb
    host: target-mongo
    port: 27017
    account: databastion
    secret:
      file: /run/databastion-secrets/target_mongo_agent_password
    mongodb:
      tls: disable_insecure
      auth_source: admin
EOF
chmod 0644 "$W/agent/agent.yaml"

# ------------------------------------------------------------------------------ workload scripts
mkdir -p "$W/workload/pg" "$W/workload/mariadb"
python3 "$SEED" pgbench --tables "$LOAD_TABLES" --rows "$LOAD_ROWS" --workload-tables "$LOAD_WORKLOAD_TABLES" \
  --out "$W/workload/pg"
python3 "$SEED" sysbench --tables "$LOAD_TABLES" --rows "$LOAD_ROWS" --workload-tables "$LOAD_WORKLOAD_TABLES" \
  >"$W/workload/mariadb/point_select.lua"
chmod 0755 "$W/workload" "$W/workload/pg" "$W/workload/mariadb"
chmod 0644 "$W/workload/pg/"*.sql "$W/workload/mariadb/point_select.lua"

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset LOAD_CONSOLE_IMAGE LOAD_AGENT_IMAGE LOAD_TARGET_PG_IMAGE
fi
if [ "${LOAD_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  # (pss mode: the plain PostgreSQL image is pulled by `up` like the other pinned images.)
  SKIP_IMAGES=("${LOAD_CONSOLE_IMAGE:-databastion-console:e2e}" "${LOAD_AGENT_IMAGE:-databastion-agent:e2e}")
  [ "$LOAD_PG_AUDIT" = pss ] || SKIP_IMAGES+=("${LOAD_TARGET_PG_IMAGE:-databastion-dev/postgres:17.11-pgaudit}")
  for img in "${SKIP_IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "LOAD_SKIP_BUILD=1 but image $img is missing"
  done
  log "LOAD_SKIP_BUILD=1: using the existing images"
else
  BUILD_SERVICES=(web agent)
  [ "$LOAD_PG_AUDIT" = pss ] || BUILD_SERVICES+=(target-pg)
  log "building images (${BUILD_SERVICES[*]})"
  timeout 1800 docker compose -f "$COMPOSE_FILE" build "${BUILD_SERVICES[@]}"
fi
log "target-pg Audit source: $LOAD_PG_AUDIT"
phase_done build

files_root() {
  timeout 60 docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T --no-deps agent-files "$1"
}
files_agent() {
  timeout 60 docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T --no-deps \
    --user 10001:10001 agent-files "$1"
}
log "preparing the target-pg and target-mariadb log volumes (999:999, 0750)"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
files_root 'for d in /pglog /mylog; do chmod 0750 "$d" && chown 999:999 "$d" && stat -c "%u:%g %a" "$d"; done' \
  | tr '\n' ' ' | grep -qx '999:999 750 999:999 750 ' || fail "cannot prepare the target log volumes"

log "starting the console, the TLS proxy and the targets (CPU limit ${LOAD_DB_CPUS} each)"
timeout 400 docker compose -f "$COMPOSE_FILE" up -d db web worker proxy target-pg target-mariadb target-mongo
CURL=(curl -sS --max-time 40 --cacert "$T/ca.crt" --resolve "${HOSTNAME_CONSOLE}:${LOAD_HTTPS_PORT}:127.0.0.1"
  -b "$W/cookies" -c "$W/cookies")
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done
[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"
deadline=$(( $(date +%s) + 240 ))
for svc in target-pg target-mariadb target-mongo; do
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$svc")" 2>/dev/null)" = healthy ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$svc not healthy within 240 s"
    sleep 2
  done
done
compose exec -T target-mariadb cat /var/lib/databastion-tls/ca.pem >"$T/mariadb-ca.pem" \
  || fail "cannot read the CA of target-mariadb"
openssl x509 -in "$T/mariadb-ca.pem" -noout -subject 2>/dev/null | grep -q "DataBastion dev CA (mariadb)" \
  || fail "mariadb-ca.pem is not the dev CA of target-mariadb"
! grep -q 'PRIVATE KEY' "$T/mariadb-ca.pem" || fail "mariadb-ca.pem holds a private key"
chmod 0644 "$T/mariadb-ca.pem"
phase_done start

# ------------------------------------------------------------------------------ samplers
declare -A CID=()
for svc in target-pg target-mariadb target-mongo; do
  CID[$svc]="$(compose ps -q "$svc")"
  [ -n "${CID[$svc]}" ] || fail "no container for $svc"
done
log "sampling the targets' cgroup CPU counters every ${LOAD_SAMPLE_INTERVAL} s"
python3 "$LOADLIB" sample --out "$SAMPLES_DB" --interval "$LOAD_SAMPLE_INTERVAL" \
  "target-pg=${CID[target-pg]}" "target-mariadb=${CID[target-mariadb]}" "target-mongo=${CID[target-mongo]}" \
  2>"$W/out/sampler-db.err" &
BG_PIDS+=("$!")
sleep 3
# (The last line may be half written: it is left out.)
head -n -1 "$SAMPLES_DB" | jq -e 'select(.c["target-pg"].cpu_usec != null and .c["target-mariadb"].cpu_usec != null
  and .c["target-mongo"].cpu_usec != null)' >/dev/null 2>&1 \
  || fail "cannot read the targets' cgroup CPU counters (cgroup v2 cpu.stat or v1 cpuacct.usage; see sampler-db.err)"
log "targets' CPU capacity: $(head -n -1 "$SAMPLES_DB" | tail -n 1 | jq -c '[.c | to_entries[] | {(.key): .value.cap}] | add')"
for t in "${DISCOVERY_TARGETS[@]}"; do
  read -r target cont _ <<<"$t"
  fact --arg t "$target" --arg c "$cont" '{kind: "target", target: $t, container: $c}'
done

# ------------------------------------------------------------------------------ scaled seed
log "loading the scaled seed: PostgreSQL / MariaDB ${LOAD_TABLES} tables, ${LOAD_ROWS} rows each; MongoDB ${LOAD_MONGO_TABLES} collections, ${LOAD_MONGO_ROWS} documents"
# Synthetic, deterministic values generated by the servers themselves (seed.py); as the superuser
# of each target, whose password is read inside the container. Before the agent exists.
seed_pg() {
  python3 "$SEED" pg --tables "$LOAD_TABLES" --rows "$LOAD_ROWS" \
    | timeout 900 docker compose -f "$COMPOSE_FILE" exec -T target-pg \
        psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d shop -f -
}
seed_mariadb() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  python3 "$SEED" mariadb --tables "$LOAD_TABLES" --rows "$LOAD_ROWS" \
    | timeout 900 docker compose -f "$COMPOSE_FILE" exec -T target-mariadb sh -c \
        'MYSQL_PWD="$(cat /run/secrets/root_password)" exec mariadb -h 127.0.0.1 -u root -N -B'
}
MONGO_ROOT='const c = connect("mongodb://root:" + encodeURIComponent(require("fs").readFileSync("/run/secrets/root_password", "utf8")) + "@127.0.0.1:27017/admin?authSource=admin");'
seed_mongo() {
  local js
  js="$(python3 "$SEED" mongo --tables "$LOAD_MONGO_TABLES" --rows "$LOAD_MONGO_ROWS")"
  timeout 900 docker compose -f "$COMPOSE_FILE" exec -T -e HOME=/tmp -e DO_NOT_TRACK=1 target-mongo \
    mongosh --nodb --quiet --norc --eval "${MONGO_ROOT}${js}"
}
t_seed="$(date +%s)"
declare -A SEED_PID=()
for e in pg mariadb mongo; do
  "seed_$e" >"$W/out/seed-$e.out" 2>&1 &
  SEED_PID[$e]=$!
done
for e in pg mariadb mongo; do
  if ! wait "${SEED_PID[$e]}"; then
    tail -n 5 "$W/out/seed-$e.out" >&2 || true
    fail "loading the scaled seed into $e failed"
  fi
  log "seed $e: $(tail -n 1 "$W/out/seed-$e.out") ($(( $(date +%s) - t_seed )) s)"
done
grep -qx "$LOAD_TABLES tables" "$W/out/seed-pg.out" || fail "target-pg: unexpected table count"
grep -qx "$LOAD_TABLES tables" "$W/out/seed-mariadb.out" || fail "target-mariadb: unexpected table count"
grep -qx "$LOAD_MONGO_ROWS documents" "$W/out/seed-mongo.out" || fail "target-mongo: unexpected document count"
fact --argjson tables "$LOAD_TABLES" --argjson rows "$LOAD_ROWS" --argjson mt "$LOAD_MONGO_TABLES" \
  --argjson mr "$LOAD_MONGO_ROWS" --arg cpus "$LOAD_DB_CPUS" --argjson sample "$LOAD_SAMPLE_ROWS" \
  --argjson pgr "$LOAD_PG_RATE" --argjson myr "$LOAD_MARIADB_RATE" --argjson clients "$LOAD_CLIENTS" \
  --argjson wt "$LOAD_WORKLOAD_TABLES" \
  --argjson base "$LOAD_BASELINE_S" --argjson soak "$LOAD_SOAK_S" --argjson idle "$LOAD_IDLE_S" \
  --arg host_cpus "$(nproc)" --arg pg_audit "$LOAD_PG_AUDIT" \
  '{kind: "config", pg_audit: $pg_audit, tables: $tables, rows: $rows, mongo_collections: $mt, mongo_documents: $mr,
    db_cpus: ($cpus | tonumber), sample_rows: $sample, pg_rate: $pgr, mariadb_rate: $myr,
    clients: $clients, workload_tables: $wt, baseline_s: $base, soak_s: $soak, idle_s: $idle, host_cpus: ($host_cpus | tonumber)}'
phase_done seed

# wait_quiet: the targets finish the background work of the load (checkpoints, purge, flushes).
wait_quiet() {
  local r
  if r="$(python3 "$LOADLIB" quiet --samples "$SAMPLES_DB" --names target-pg,target-mariadb,target-mongo \
      --below 0.02 --window 10 --timeout 180)"; then
    log "targets quiet: $r"
  else
    log "WARNING: targets still busy after 180 s: $r (the idle baseline absorbs it)"
  fi
}
wait_quiet

# ------------------------------------------------------------------------------ admin, token, enroll
log "bootstrapping the administrator and logging in"
timeout 120 docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T bootstrap-admin \
  >"$LOAD_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"
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
api_json() {
  printf '%s' "$3" >"$W/req.json"
  api "$1" "$2" "$W/req.json"
}
jq -n --rawfile p "$S/admin_password" '{username: "load-admin", password: $p}' >"$W/login.json"
r="$(api POST /api/auth/login "$W/login.json")"
rm -f "$W/login.json"
[ "$(status_of "$r")" = 200 ] || fail "login: HTTP $(status_of "$r")"
CSRF="$(body_of "$r" | jq -r '.csrf_token')"
if [ -z "$CSRF" ] || [ "$CSRF" = null ]; then fail "login: no CSRF token"; fi
register_secret csrf_token "$CSRF"
printf 'X-CSRF-Token: %s\n' "$CSRF" >"$W/csrf.hdr"
register_secret session_cookie "$(awk '$6 ~ /databastion_session$/ {print $7}' "$W/cookies")"
r="$(api_json POST /api/enrollment-tokens '{"label":"load"}')"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
register_secret enrollment_token "$ENROLLMENT_TOKEN"
[[ "$ENROLLMENT_TOKEN" == dbe_* ]] || fail "enrollment token: unexpected format"

log "preparing the agent's state and secrets volumes, enrolling"
timeout 60 docker compose -f "$COMPOSE_FILE" run --rm -T --no-deps agent --version \
  >"$LOAD_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
for name in target_agent_password target_mariadb_agent_password target_mongo_agent_password; do
  files_agent "umask 077; cat > /secrets/$name" <"$S/$name"
done
printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'
unset ENROLLMENT_TOKEN
timeout 120 docker compose -f "$COMPOSE_FILE" run --rm -T agent \
  enroll --config /etc/databastion/agent.yaml --token-file /run/databastion-secrets/enrollment_token \
  >"$LOAD_LOG_DIR/agent-enroll.log" 2>&1 || {
  register_secret agent_secret "$(files_agent 'cat /state/identity.json' 2>/dev/null | jq -r '.agent_secret // empty' 2>/dev/null)"
  fail "agent enroll failed (see agent-enroll.log)"
}
files_agent 'rm -f /secrets/enrollment_token'
identity="$(files_agent 'cat /state/identity.json')"
AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
register_secret agent_secret "$(jq -r '.agent_secret' <<<"$identity")"
unset identity
[[ "$AGENT_ID" =~ $UUID_RE ]] || fail "no agent id in identity.json"
log "enrolled agent $AGENT_ID"
phase_done enroll

# ------------------------------------------------------------------------------ idle baseline A
# The targets alone (their healthchecks included), before the agent starts: the baseline that is
# subtracted from the Discovery measurements.
log "idle baseline without the agent (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
t1="$(now_s)"
fact --argjson t0 "$t0" --argjson t1 "$t1" '{kind: "window", name: "idle_no_agent", t0: $t0, t1: $t1}'

# ------------------------------------------------------------------------------ agent run
log "starting databastion-agent run"
timeout 60 docker compose -f "$COMPOSE_FILE" up -d --no-deps agent
CID[agent]="$(compose ps -q agent)"
python3 "$LOADLIB" sample --out "$SAMPLES_AGENT" --interval 1 "agent=${CID[agent]}" \
  2>"$W/out/sampler-agent.err" &
BG_PIDS+=("$!")

console_sql() {
  timeout 30 docker compose -f "$COMPOSE_FILE" exec -T db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}
deadline=$(( $(date +%s) + 120 ))
until a="$(agent_json 2>/dev/null)" && [ -n "$a" ] && jq -e '.status == "online"
    and ((["pg-load", "mariadb-load", "mongo-load"] - [.targets[] | select(.present and .reachable == true) | .targetId]) == [])' \
    <<<"$a" >/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "agent not online with its three targets reachable within 120 s ($(jq -c '[.targets[]? | {targetId, reachable, lastError}]' <<<"${a:-{\}}" 2>/dev/null || true))"
  sleep 2
done
log "agent online: $(jq -c '[.targets[] | {targetId, reachable, auditLevel}]' <<<"$a")"

# Heartbeat poller: the agent's spool status and counters as the console stored them.
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
t1="$(now_s)"
fact --argjson t0 "$t0" --argjson t1 "$t1" '{kind: "window", name: "idle_agent", t0: $t0, t1: $t1}'
phase_done agent

# ------------------------------------------------------------------------------ 1. Discovery
# Statement statistics of the agent's account (informational cross-check of the CPU measurement):
# PostgreSQL pg_stat_statements (execution + planning time), MariaDB performance_schema. They run
# inside the target containers, so never within a measured scan (2 s margins around it).
stmt_stats() {
  case "$1" in
    pg-load)
      timeout 30 docker compose -f "$COMPOSE_FILE" exec -T target-pg psql -XAt -U postgres -d shop -c \
        "SELECT coalesce(round(sum(total_exec_time + total_plan_time)::numeric, 3), 0) || ' ' || coalesce(sum(calls), 0)
           FROM pg_stat_statements s JOIN pg_roles r ON r.oid = s.userid WHERE r.rolname = 'databastion_agent'" ;;
    mariadb-load)
      # shellcheck disable=SC2016 # expanded by the container shell, on purpose
      timeout 30 docker compose -f "$COMPOSE_FILE" exec -T target-mariadb sh -c \
        'MYSQL_PWD="$(cat /run/secrets/root_password)" exec mariadb -h 127.0.0.1 -u root -N -B -e "$0"' \
        "SELECT CONCAT(COALESCE(ROUND(SUM(SUM_TIMER_WAIT) / 1000000000, 3), 0), ' ', COALESCE(SUM(COUNT_STAR), 0))
           FROM performance_schema.events_statements_summary_by_user_by_event_name WHERE USER = 'databastion'" ;;
    *) printf '0 0' ;;
  esac
}
printf '{"sample_rows":%s,"max_duration_s":%s,"statement_timeout_ms":%s}' \
  "$LOAD_SAMPLE_ROWS" "$LOAD_SCAN_MAX_S" "$LOAD_STATEMENT_TIMEOUT_MS" >"$W/scan-req.json"
SCAN_JOB_IDS=()
for t in "${DISCOVERY_TARGETS[@]}"; do
  read -r target cont engine tables rows <<<"$t"
  before="$(stmt_stats "$target" 2>/dev/null || printf '0 0')"
  sleep 2
  log "Discovery scan of $target ($engine, $tables tables, $rows rows)"
  r="$(api POST "/api/agents/${AGENT_ID}/targets/${target}/scan" "$W/scan-req.json")"
  [ "$(status_of "$r")" = 202 ] || fail "scan request ($target): HTTP $(status_of "$r")"
  job_id="$(body_of "$r" | jq -r '.job_id')"
  [[ "$job_id" =~ $UUID_RE ]] || fail "scan request ($target): no job id"
  SCAN_JOB_IDS+=("$job_id")
  deadline=$(( $(date +%s) + LOAD_SCAN_MAX_S + 60 ))
  while :; do
    status="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")" || fail "cannot read the scan job"
    case "$status" in succeeded | failed | cancelled | expired) break ;; esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "scan of $target not finished in time (status $status)"
    sleep 1
  done
  sleep 2
  window="$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at)
    FROM jobs WHERE id = '$job_id'")"
  read -r s0 s1 <<<"$window"
  [[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of $target: no delivery / end time ($status)"
  after="$(stmt_stats "$target" 2>/dev/null || printf '0 0')"
  read -r b_ms b_calls <<<"$before"
  read -r a_ms a_calls <<<"$after"
  # Unreadable statistics count as 0 (informational only).
  [[ "${b_ms:-}" =~ ^[0-9.]+$ && "${b_calls:-}" =~ ^[0-9]+$ ]] || { b_ms=0; b_calls=0; }
  [[ "${a_ms:-}" =~ ^[0-9.]+$ && "${a_calls:-}" =~ ^[0-9]+$ ]] || { a_ms=0; a_calls=0; }
  fact --arg target "$target" --arg status "$status" --argjson t0 "$s0" --argjson t1 "$s1" \
    --argjson tables "$tables" --argjson rows "$rows" \
    --argjson ms "$(jq -n --argjson a "$a_ms" --argjson b "$b_ms" '$a - $b | . * 1000 | round / 1000')" \
    --argjson calls "$(( a_calls - b_calls ))" \
    '{kind: "scan", target: $target, status: $status, t0: $t0, t1: $t1, tables: $tables, rows: $rows,
      stmt_exec_ms: $ms, stmt_calls: $calls}'
  log "scan of $target: $status in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s"
  [ "$status" = succeeded ] || fail "scan of $target ended '$status'"
  sleep 3
done
SCAN_JOB_LIST="$(printf "'%s'," "${SCAN_JOB_IDS[@]}")"
SCAN_JOB_LIST="${SCAN_JOB_LIST%,}"

# The findings batches are uploaded after the job status: wait for a heartbeat after the last scan
# that reports an empty spool, and nothing dropped (as e2e/run.sh).
wait_spool_empty() {
  local since="$1" label="$2" spool batches db di deadline
  deadline=$(( $(date +%s) + SPOOL_TIMEOUT_S ))
  while :; do
    spool="$(console_sql "SELECT concat_ws(',', last_seen_at > to_timestamp($since) + interval '1 second',
        coalesce(spool->>'batches', 'none'), coalesce(spool->>'dropped_batches', '0'),
        coalesce(spool->>'dropped_items', '0')) FROM agents WHERE id = '${AGENT_ID}'")" \
      || fail "cannot read the agent spool status"
    case "$spool" in
      t,*,*,*) IFS=, read -r _ batches db di <<<"$spool"
        if [ "$db" != 0 ] || [ "$di" != 0 ]; then fail "the agent dropped results ($db batch(es), $di item(s)) $label"; fi
        if [ "$batches" = 0 ]; then return 0; fi ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}
last_end="$(console_sql "SELECT extract(epoch from max(finished_at)) FROM jobs WHERE id IN (${SCAN_JOB_LIST})")"
wait_spool_empty "$last_end" "after the scans" || fail "no heartbeat with an empty spool within ${SPOOL_TIMEOUT_S} s after the scans"
for t in "${DISCOVERY_TARGETS[@]}"; do
  read -r target _ <<<"$t"
  n="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '$target'")"
  fact --arg target "$target" --argjson n "$n" '{kind: "findings", target: $target, count: $n}'
  log "findings stored for $target: $n"
  [ "$n" -gt 0 ] || fail "no finding stored for $target"
done
phase_done discovery

# ------------------------------------------------------------------------------ 2. workloads
# run_workload PHASE DURATION: pgbench (target-pg) and sysbench (target-mariadb) together, at fixed
# rates, as load_app. Outputs: $W/out/<engine>-<phase>.{summary,tx}. Records the window.
PG_SCRIPTS=""
for f in "$W"/workload/pg/*.sql; do PG_SCRIPTS+=" -f /load/$(basename "$f")@1"; done
run_workload() {
  local phase="$1" dur="$2" t_start pg_pid sb_pid pg_rc=0 sb_rc=0
  WL_START_UTC="$(date -u +'%Y-%m-%d %H:%M:%S')"
  log "workload ($phase): pgbench ${LOAD_PG_RATE}/s and sysbench ${LOAD_MARIADB_RATE}/s, ${LOAD_CLIENTS} clients each, ${dur} s"
  t_start="$(now_s)"
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout $((dur + 300)) docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T --no-deps pg-bench \
    'PGPASSWORD="$(cat /run/secrets/load_client_password)"; export PGPASSWORD; rc=0
     pgbench -n -M simple -c '"$LOAD_CLIENTS"' -j 2 -R '"$LOAD_PG_RATE"' -T '"$dur"' '"$PG_SCRIPTS"' \
       -l --log-prefix=/tmp/tx >/tmp/summary 2>&1 || rc=$?
     cat /tmp/summary >&2; cat /tmp/tx.* 2>/dev/null || true; exit "$rc"' \
    >"$W/out/pg-$phase.tx" 2>"$W/out/pg-$phase.summary" &
  pg_pid=$!
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout $((dur + 300)) docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T --no-deps sb-client \
    'umask 077; printf "mysql-password=%s\n" "$(cat /run/secrets/load_client_password)" >/tmp/sb.cfg
     exec sysbench /load/point_select.lua --config-file=/tmp/sb.cfg --db-driver=mysql \
       --mysql-host=mariadb --mysql-port=3306 --mysql-user=load_app --mysql-db=support \
       --threads='"$LOAD_CLIENTS"' --rate='"$LOAD_MARIADB_RATE"' --time='"$dur"' --percentile=95 run' \
    >"$W/out/mariadb-$phase.summary" 2>&1 &
  sb_pid=$!
  wait "$pg_pid" || pg_rc=$?
  wait "$sb_pid" || sb_rc=$?
  WL_T0="$(jq -n --argjson t "$t_start" '$t + 5')"
  WL_T1="$(jq -n --argjson t "$t_start" --argjson d "$dur" '$t + $d')"
  WL_END="$(now_s)"
  [ "$pg_rc" = 0 ] || { tail -n 20 "$W/out/pg-$phase.summary" >&2; fail "pgbench ($phase) exited $pg_rc"; }
  [ "$sb_rc" = 0 ] || { tail -n 20 "$W/out/mariadb-$phase.summary" >&2; fail "sysbench ($phase) exited $sb_rc"; }
  fact --arg name "workload_audit_$phase" --argjson t0 "$WL_T0" --argjson t1 "$WL_T1" \
    '{kind: "window", name: $name, t0: $t0, t1: $t1}'
  python3 "$LOADLIB" pgbench --summary "$W/out/pg-$phase.summary" --log "$W/out/pg-$phase.tx" \
    | jq -c --arg phase "$phase" --argjson rate "$LOAD_PG_RATE" '{kind: "workload", target: "pg-load",
        phase: $phase, tool: "pgbench", rate: $rate, issued: .processed, failed: .failed, p95_ms, p99_ms,
        service_p95_ms, logged}' >>"$FACTS"
  python3 "$LOADLIB" sysbench --summary "$W/out/mariadb-$phase.summary" \
    | jq -c --arg phase "$phase" --argjson rate "$LOAD_MARIADB_RATE" '{kind: "workload", target: "mariadb-load",
        phase: $phase, tool: "sysbench", rate: $rate, issued: .reads, failed: .errors, p95_ms, avg_ms}' >>"$FACTS"
  log "workload ($phase): $(grep '"kind":"workload"' "$FACTS" | jq -sc --arg p "$phase" \
    'map(select(.phase == $p) | {target, issued, failed, p95_ms})')"
}

run_workload off "$LOAD_BASELINE_S"
phase_done workload-off

# ------------------------------------------------------------------------------ Audit on
agent_log_count() {
  timeout 30 docker compose -f "$COMPOSE_FILE" logs --no-color agent 2>/dev/null \
    | grep -F "$1" | grep -cF "\"target_id\":\"$2\"" || true
}
wait_job() {
  local id="$1" label="$2" deadline job
  deadline=$(( $(date +%s) + $3 ))
  while :; do
    job="$(console_sql "SELECT status FROM jobs WHERE id = '$id'")" || fail "cannot read the $label job"
    case "$job" in
      succeeded) return 0 ;;
      failed | cancelled | expired) fail "$label job ended '$job'" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "$label job not succeeded within $3 s ($job)"
    sleep 1
  done
}
# audit_configure TARGET: Audit on with the contract defaults (aggregation 60 s, poll 10 s, no
# min_rows: every event is reported), sensitive objects derived from the findings; a change the
# console asks to confirm is confirmed with its digest, as the UI does (e2e/run.sh).
audit_configure() {
  local target="$1" r code digest job_id
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" '{"enabled":true,"derive_from_findings":true}')"
  code="$(status_of "$r")"
  if [ "$code" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
    digest="$(body_of "$r" | jq -r '.digest')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "audit.configure ($target): no confirmation digest"
    r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" \
      "{\"enabled\":true,\"derive_from_findings\":true,\"confirm\":\"${digest}\"}")"
    code="$(status_of "$r")"
  fi
  [ "$code" = 202 ] || fail "audit.configure ($target): HTTP $code"
  job_id="$(body_of "$r" | jq -r '.job_id')"
  [[ "$job_id" =~ $UUID_RE ]] || fail "audit.configure ($target): no job id"
  wait_job "$job_id" "audit.configure ($target)" 90
}
for at in "${AUDIT_TARGETS[@]}"; do
  read -r target msg <<<"$at"
  prev="$(agent_log_count "$msg" "$target")"
  log "enabling Audit on $target"
  audit_configure "$target"
  deadline=$(( $(date +%s) + 90 ))
  until [ "$(agent_log_count "$msg" "$target")" -gt "$prev" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "the Audit stream of $target did not start within 90 s ('$msg')"
    sleep 1
  done
  log "Audit stream of $target started ($msg)"
done
sleep 5
phase_done audit-setup

run_workload on "$LOAD_SOAK_S"
SOAK_END="$WL_END"
SOAK_START_UTC="$WL_START_UTC"
phase_done workload-on

# ------------------------------------------------------------------------------ drain
# Every statement of the Audit run must reach the console: the sum of aggregated_count of load_app's
# read events equals the statements issued. Drain time: from the end of the workload to the last
# such event stored (received_at).
events_sql() {
  printf "FROM access_events WHERE agent_id = '%s' AND target_id = '%s' AND db_user = 'load_app' AND action = 'read'" \
    "$AGENT_ID" "$1"
}
issued_of() {
  grep '"kind":"workload"' "$FACTS" | jq -s --arg t "$1" 'map(select(.target == $t and .phase == "on"))[0].issued // 0'
}
log "waiting until every statement of the Audit run is stored (at most ${LOAD_DRAIN_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + LOAD_DRAIN_TIMEOUT_S ))
while :; do
  done_all=1
  status_line=""
  for at in "${AUDIT_TARGETS[@]}"; do
    read -r target _ <<<"$at"
    got="$(console_sql "SELECT coalesce(sum(aggregated_count), 0) $(events_sql "$target")")"
    want="$(issued_of "$target")"
    status_line+="$target $got/$want; "
    [ "$got" -ge "$want" ] || done_all=0
  done
  [ "$done_all" = 1 ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "WARNING: not every statement stored within ${LOAD_DRAIN_TIMEOUT_S} s: $status_line"
    break
  fi
  sleep 5
done
log "events stored: $status_line"
for at in "${AUDIT_TARGETS[@]}"; do
  read -r target _ <<<"$at"
  want="$(issued_of "$target")"
  console_sql "SELECT json_build_object('kind', 'events', 'target', '$target',
      'received', coalesce(sum(aggregated_count), 0), 'events', count(*),
      'lag_p95_s', round(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch from received_at - coalesce(ts_last, ts))::float8)::numeric, 1),
      'lag_max_s', round(max(extract(epoch from received_at - coalesce(ts_last, ts)))::numeric, 1),
      'drain_s', CASE WHEN coalesce(sum(aggregated_count), 0) >= $want
        THEN round((extract(epoch from max(received_at)) - $SOAK_END)::numeric, 1) END)
    $(events_sql "$target")" >>"$FACTS"
done
# Diagnosis: the workload principal's statements per 10 s of event time, as stored.
for at in "${AUDIT_TARGETS[@]}"; do
  read -r target _ <<<"$at"
  console_sql "SELECT json_build_object('kind', 'events_timeline', 'target', '$target',
      'buckets', coalesce(json_agg(json_build_array(b, n) ORDER BY b), '[]'))
    FROM (SELECT (floor(extract(epoch from ts) / 10) * 10)::bigint AS b, sum(aggregated_count) AS n
          $(events_sql "$target") GROUP BY 1) AS x" >>"$FACTS"
done
# Source side: the workload's statements in the target's own audit log since the Audit run started
# (the file the agent reads, rotations included). events received > source statements means the
# agent counted some twice; source statements > issued, that the server logged more. The target is
# no longer measured at this point. Not available in pss mode (pg_stat_statements keeps no records).
SOAK_START_MY="$(tr -d '-' <<<"$SOAK_START_UTC")"   # server_audit: 20260930 04:01:03
# shellcheck disable=SC2016 # awk programs, expanded by the container shell on purpose
my_src="$(timeout 120 docker compose -f "$COMPOSE_FILE" exec -T target-mariadb sh -c \
  'ls /var/log/databastion | grep -c "^server_audit\.log\.[0-9]" || true
   cat /var/log/databastion/server_audit.log.[0-9]* /var/log/databastion/server_audit.log 2>/dev/null \
     | awk -F, -v t="$0" '"'"'$1 >= t && $3 == "load_app" && $7 == "QUERY" { n++ } END { print n + 0 }'"'"'' \
  "$SOAK_START_MY" 2>/dev/null | tr '\n' ' ')" || my_src=""
read -r my_rot my_n <<<"$my_src"
if [[ "${my_n:-}" =~ ^[0-9]+$ ]]; then
  fact --argjson n "$my_n" --argjson r "${my_rot:-0}" \
    '{kind: "source", target: "mariadb-load", statements: $n, rotated_files: $r}'
fi
if [ "$LOAD_PG_AUDIT" = pgaudit ]; then
  # shellcheck disable=SC2016 # awk program, expanded by the container shell on purpose
  pg_n="$(timeout 120 docker compose -f "$COMPOSE_FILE" exec -T target-pg sh -c \
    'awk -v t="$0" '"'"'index($0, "\"user\":\"load_app\"") && index($0, "\"message\":\"AUDIT: SESSION,") \
       { if (substr($0, 15, 19) >= t) n++ } END { print n + 0 }'"'"' /var/log/databastion/postgresql.json' \
    "$SOAK_START_UTC" 2>/dev/null)" || pg_n=""
  if [[ "${pg_n:-}" =~ ^[0-9]+$ ]]; then
    fact --argjson n "$pg_n" '{kind: "source", target: "pg-load", statements: $n, rotated_files: 0}'
  fi
fi
if wait_spool_empty "$(now_s)" "after the Audit run"; then
  fact '{kind: "spool_drained", ok: true, batches: 0}'
else
  fact '{kind: "spool_drained", ok: false}'
fi
lost="$(timeout 30 docker compose -f "$COMPOSE_FILE" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|events dropped|rejected batch items|unreadable spool file' || true)"
fact --argjson n "$lost" '{kind: "agent_log", lost: $n}'
# A last heartbeat sample, then stop the samplers and the poller.
sleep 12
stop_background
phase_done drain

# ------------------------------------------------------------------------------ report
log "computing the results"
set +e
python3 "$LOADLIB" report --facts "$FACTS" --samples "$SAMPLES_DB" "$SAMPLES_AGENT" \
  --heartbeats "$HEARTBEATS" --out "$LOAD_RESULTS_DIR"
rc=$?
set -e
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$LOAD_RESULTS_DIR/results.md" ]; then
  cat "$LOAD_RESULTS_DIR/results.md" >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
