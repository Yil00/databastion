#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Load run of the SQL Server target (ROADMAP P9-D, ADR-0051 "End-to-end and load"; e2e/load/README.md
# "SQL Server target"): the console, the agent and the dev SQL Server 2022 Express service
# (e2e/docker-compose.yml + e2e/docker-compose.sqlserver.yml + docker-compose.sqlserver.yml here,
# project databastion-load-sqlserver). Measures, as e2e/load/run.sh does for the other engines:
#   1. the database CPU impact of a paced Discovery scan of a scaled seed (< 2 % of the server's
#      CPU capacity, LOAD_DB_CPUS);
#   2. the Audit path (SQL Server Audit through sys.fn_get_audit_file) under a fixed-rate point-select
#      workload (sqlcmd sessions in the mssql-client container), without then with Audit: every
#      statement an event (within 1 %), nothing dropped, the spool drained, the latency per
#      statement with and without Audit, the server's CPU;
#   3. the agent's CPU and RSS over the Audit run, bounded and without monotonic growth.
# The report is loadlib.py's (same checks, limits and format as run.sh).
# LOAD_SQLSERVER_AUDIT_SOURCE=sqlserver_xevents (ROADMAP phase 9 follow-up "#282 review N3: measure the
# catch-up noise under load"): the same run with the Extended Events source (the dev session
# `databastion_xe`, as e2e/sqlserver.sh with E2E_SQLSERVER_AUDIT_SOURCE), the agent login given that
# source's grant only, and the catch-up measurement (loadlib.py xe-catchup) after the drain; with
# LOAD_SQLSERVER_STATS_RESET_S=N, the auto-created statistics of the load schema are dropped every N
# seconds of the Audit run, so that the ORM-style session builds them again under load; with
# LOAD_SQLSERVER_LARGE_EVERY_S=N (Extended Events only; ADR-0051 refinement of 2026-10-22, load step 4),
# a burst of LOAD_SQLSERVER_LARGE_BURST statements near the 128 KiB event bound every N seconds of the
# Audit run, and the checks on the reads cancelled above 12 MiB and at the statement timeout.
#
# Requires: docker (compose v2.24+), openssl, curl, jq, python3. Every secret is generated at run time,
# registered, masked under GitHub Actions, redacted from the collected logs and removed on exit.
# Nothing listens outside 127.0.0.1.
# shellcheck disable=SC2016 # jq programs (fact, jq -c) are single-quoted on purpose, file-wide
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="$HERE/.."
LOADLIB="$HERE/loadlib.py"
SEED="$HERE/seed.py"
PROJECT="databastion-load-sqlserver"
LOG_TAG="load-sqlserver"  # read by ../lib.sh

# ------------------------------------------------------------------------------ settings
export E2E_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
export LOAD_DB_CPUS="${LOAD_DB_CPUS:-2}"
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs-sqlserver}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results-sqlserver}"
LOAD_IDLE_S="${LOAD_IDLE_S:-45}"
# SQL Server runs start-up background work for its first minutes (bursts of about 5 CPU-seconds seen
# up to 5 minutes after the start, none in the 9 minutes after): the baselines and the scan start
# once the server has been up this long.
LOAD_MSSQL_SETTLE_S="${LOAD_MSSQL_SETTLE_S:-480}"
LOAD_MSSQL_TABLES="${LOAD_MSSQL_TABLES:-100}"
LOAD_MSSQL_ROWS="${LOAD_MSSQL_ROWS:-500000}"
# Audit source: sqlserver_audit (SQL Server Audit, the default) or sqlserver_xevents (the Extended
# Events session, #282 review N3). Every statement of the workload's T-SQL loop (SET, IF, WAITFOR,
# the table variable insert: about 30 per workload SELECT) is an Extended Events event, so the
# default rate with that source is lower: 50 SELECTs/s, about 1 500 events/s, within the session's
# 8 x 64 MB of files over a 600 s run.
LOAD_SQLSERVER_AUDIT_SOURCE="${LOAD_SQLSERVER_AUDIT_SOURCE:-sqlserver_audit}"
case "$LOAD_SQLSERVER_AUDIT_SOURCE" in
  sqlserver_audit) AUDIT_YAML="{source: sqlserver_audit, audit_name: databastion_audit}" default_rate=300 ;;
  sqlserver_xevents) AUDIT_YAML="{source: sqlserver_xevents, xe_session: databastion_xe}" default_rate=50 ;;
  *) echo "LOAD_SQLSERVER_AUDIT_SOURCE must be sqlserver_audit or sqlserver_xevents" >&2; exit 2 ;;
esac
LOAD_MSSQL_RATE="${LOAD_MSSQL_RATE:-$default_rate}"          # workload statements per second
if ! [[ "$LOAD_MSSQL_RATE" =~ ^[1-9][0-9]{0,3}$ ]] || [ "$LOAD_MSSQL_RATE" -gt 2000 ]; then
  echo "LOAD_MSSQL_RATE must be between 1 and 2000 statements per second" >&2; exit 2
fi
# Seconds between two drops of the load schema's auto-created statistics during the Audit run
# (0: never, the default).
LOAD_SQLSERVER_STATS_RESET_S="${LOAD_SQLSERVER_STATS_RESET_S:-0}"
[[ "$LOAD_SQLSERVER_STATS_RESET_S" =~ ^(0|[1-9][0-9]{0,3})$ ]] \
  || { echo "LOAD_SQLSERVER_STATS_RESET_S must be 0 or a number of seconds (at most 9999)" >&2; exit 2; }
# ADR-0051 refinement of 2026-10-22 (load step 4, "at 50/s with a share of large events"): every
# LOAD_SQLSERVER_LARGE_EVERY_S seconds of the Audit run (0: never, the default), the login load_big runs
# LOAD_SQLSERVER_LARGE_BURST (default 60) reads of one load table whose statement text holds a comment of
# about 60 000 characters (an Extended Events event of about 120 KiB, near the poll's 128 KiB bound),
# 20 ms apart (back to back, the session's buffers would drop events). A burst meets a read of the
# sized bound (up to 2 000 events) with more than 12 MiB: the read is cancelled and read again smaller,
# and reads stay at 500 or less for 10 minutes. Extended Events source only.
LOAD_SQLSERVER_LARGE_EVERY_S="${LOAD_SQLSERVER_LARGE_EVERY_S:-0}"
LOAD_SQLSERVER_LARGE_BURST="${LOAD_SQLSERVER_LARGE_BURST:-60}"
if ! [[ "$LOAD_SQLSERVER_LARGE_EVERY_S" =~ ^(0|[1-9][0-9]{0,2})$ ]] || [ "$LOAD_SQLSERVER_LARGE_EVERY_S" -gt 600 ]; then
  echo "LOAD_SQLSERVER_LARGE_EVERY_S must be 0 or a number of seconds (at most 600)" >&2; exit 2
fi
if ! [[ "$LOAD_SQLSERVER_LARGE_BURST" =~ ^[1-9][0-9]{0,2}$ ]] || [ "$LOAD_SQLSERVER_LARGE_BURST" -gt 200 ]; then
  echo "LOAD_SQLSERVER_LARGE_BURST must be between 1 and 200 statements" >&2; exit 2
fi
if [ "$LOAD_SQLSERVER_LARGE_EVERY_S" -gt 0 ] && [ "$LOAD_SQLSERVER_AUDIT_SOURCE" != sqlserver_xevents ]; then
  echo "LOAD_SQLSERVER_LARGE_EVERY_S needs LOAD_SQLSERVER_AUDIT_SOURCE=sqlserver_xevents" >&2; exit 2
fi
LOAD_CLIENTS="${LOAD_CLIENTS:-4}"
LOAD_WORKLOAD_TABLES="${LOAD_WORKLOAD_TABLES:-40}"
LOAD_SAMPLE_ROWS="${LOAD_SAMPLE_ROWS:-200}"
LOAD_WARMUP_S="${LOAD_WARMUP_S:-30}"               # unmeasured workload first (plan compilation)
LOAD_BASELINE_S="${LOAD_BASELINE_S:-120}"
LOAD_SOAK_S="${LOAD_SOAK_S:-600}"
LOAD_DRAIN_TIMEOUT_S="${LOAD_DRAIN_TIMEOUT_S:-300}"
LOAD_SAMPLE_INTERVAL="${LOAD_SAMPLE_INTERVAL:-0.5}"
for v in LOAD_IDLE_S LOAD_MSSQL_SETTLE_S LOAD_MSSQL_TABLES LOAD_MSSQL_ROWS LOAD_MSSQL_RATE LOAD_CLIENTS LOAD_WORKLOAD_TABLES \
    LOAD_SAMPLE_ROWS LOAD_WARMUP_S LOAD_BASELINE_S LOAD_SOAK_S LOAD_DRAIN_TIMEOUT_S E2E_HTTPS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
[ "$LOAD_SOAK_S" -le 1800 ] || { echo "LOAD_SOAK_S must be at most 1800 seconds" >&2; exit 2; }
TARGET="mssql-load"
SPOOL_TIMEOUT_S=120
SQLCMD=/opt/mssql-tools18/bin/sqlcmd

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load-sqlserver.XXXXXX")"
W="$LOAD_WORK_DIR"
export E2E_WORK_DIR="$W"
E2E_LOG_DIR="$LOAD_LOG_DIR"
CENSUS_OUT_DIR="$LOAD_RESULTS_DIR"  # read by ../lib.sh (print_census): the results artifact
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/out"
COMPOSE_ARGS=(-p "$PROJECT" -f "$E2E/docker-compose.yml" -f "$E2E/docker-compose.sqlserver.yml" -f "$HERE/docker-compose.sqlserver.yml")
# shellcheck source=../lib.sh
. "$E2E/lib.sh"
FACTS="$W/out/facts.jsonl"
HEARTBEATS="$W/out/heartbeats.jsonl"
SAMPLES_DB="$W/out/samples-db.jsonl"
SAMPLES_AGENT="$W/out/samples-agent.jsonl"
: >"$FACTS"
: >"$HEARTBEATS"
fact() { jq -nc "$@" >>"$FACTS"; }

BG_PIDS=()
stop_background() {
  local pid
  for pid in "${BG_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${BG_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  BG_PIDS=()
}
cleanup() {
  local status=$? canary_dir="$W/canary-pattern" canary_hits leaked line d
  set +e
  stop_background
  phase_done exit
  log "collecting logs into $LOAD_LOG_DIR"
  dump_logs db migrate web worker proxy target-mssql agent
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  print_census "load-sqlserver"
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
  redact_dir "$LOAD_LOG_DIR" "$P"
  redact_dir "$LOAD_RESULTS_DIR" "$P"
  # The census (and catch-up) Markdown, redacted above, into the job summary.
  summary_append "$LOAD_RESULTS_DIR"/census-*.md "$LOAD_RESULTS_DIR"/xe-catchup.md
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
console_secrets
put_secret target_mssql_password "$(rand_password 20)"
put_secret target_agent_password "$(rand_password 20)"
put_secret target_client_password "$(rand_password 20)"   # login load_app
test_ca "SQL Server load"
: >"$T/sqlserver-ca.pem"
cat >"$W/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
targets:
  - id: ${TARGET}
    engine: sqlserver
    host: sqlserver
    port: 1433
    account: databastion
    secret:
      file: /run/databastion-secrets/target_agent_password
    sqlserver:
      tls: auto
      ca_file: /etc/databastion/sqlserver-ca.pem
      databases: [retail]
      rls_visibility: view_definition
      audit: ${AUDIT_YAML}
EOF
chmod 0644 "$W/agent/agent.yaml"

# mssql_sa: SQL on stdin as `sa` inside the target (dev tooling), certificate verified on localhost.
mssql_sa() {
  timeout 600 docker compose "${COMPOSE_ARGS[@]}" exec -T -e SSL_CERT_FILE=/var/opt/mssql/databastion-tls/ca.pem \
    target-mssql bash -c 'SQLCMDPASSWORD="$(cat /run/secrets/target_mssql_password)" exec '"$SQLCMD"' -S localhost -U sa -b -I -W -h -1 -i /dev/stdin'
}
mssql_sa_q() { printf 'SET NOCOUNT ON;\n%s\n' "$1" | mssql_sa; }

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_MSSQL_IMAGE
fi
if [ "${LOAD_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  for img in "${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "LOAD_SKIP_BUILD=1 but image $img is missing"
  done
  log "LOAD_SKIP_BUILD=1: using the existing images"
else
  log "building images (web, agent)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent
fi
phase_done build

log "starting the console and SQL Server 2022 Express (${LOAD_DB_CPUS} CPUs; Audit source ${LOAD_SQLSERVER_AUDIT_SOURCE})"
timeout 900 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy target-mssql
start_console
deadline=$(( $(date +%s) + 420 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q target-mssql)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "target-mssql not healthy within 420 s"
  sleep 3
done
compose exec -T target-mssql cat /var/opt/mssql/databastion-tls/ca.pem >"$T/sqlserver-ca.pem" || fail "cannot copy the dev CA"
chmod 0644 "$T/sqlserver-ca.pem"
# The Extended Events source's grant set (as e2e/sqlserver.sh, docs/08 "Extended Events: source and
# grants"): the two SQL Server Audit grants revoked, VIEW SERVER PERFORMANCE STATE granted, before the
# agent starts.
if [ "$LOAD_SQLSERVER_AUDIT_SOURCE" = sqlserver_xevents ]; then
  log "Extended Events source: the agent login gets VIEW SERVER PERFORMANCE STATE, not the SQL Server Audit grants"
  mssql_sa_q "REVOKE VIEW SERVER SECURITY AUDIT FROM databastion; REVOKE VIEW ANY SECURITY DEFINITION FROM databastion;
    GRANT VIEW SERVER PERFORMANCE STATE TO databastion;" >/dev/null || fail "cannot set the Extended Events grant of the agent login"
fi
phase_done start

# ------------------------------------------------------------------------------ sampler, seed
declare -A CID=()
CID[target-mssql]="$(compose ps -q target-mssql)"
log "sampling the cgroup CPU counter of target-mssql every ${LOAD_SAMPLE_INTERVAL} s"
python3 "$LOADLIB" sample --out "$SAMPLES_DB" --interval "$LOAD_SAMPLE_INTERVAL" \
  "target-mssql=${CID[target-mssql]}" 2>"$W/out/sampler-db.err" &
BG_PIDS+=("$!")
sleep 3
head -n -1 "$SAMPLES_DB" | jq -e 'select(.c["target-mssql"].cpu_usec != null)' >/dev/null 2>&1 \
  || fail "cannot read the cgroup CPU counter (see sampler-db.err)"
fact --arg t "$TARGET" '{kind: "target", target: $t, container: "target-mssql"}'
fact --argjson r "$LOAD_MSSQL_RATE" --argjson soak "$LOAD_SOAK_S" --argjson base "$LOAD_BASELINE_S" \
  --argjson cpus "$LOAD_DB_CPUS" --argjson tables "$LOAD_MSSQL_TABLES" --argjson rows "$LOAD_MSSQL_ROWS" \
  --arg src "$LOAD_SQLSERVER_AUDIT_SOURCE" --argjson reset "$LOAD_SQLSERVER_STATS_RESET_S" \
  --argjson large "$LOAD_SQLSERVER_LARGE_EVERY_S" --argjson burst "$LOAD_SQLSERVER_LARGE_BURST" \
  '{kind: "config", harness: "sqlserver", rate: $r, soak_s: $soak, baseline_s: $base, db_cpus: $cpus,
    tables: $tables, rows: $rows, audit_source: $src, stats_reset_s: $reset, large_every_s: $large,
    large_burst: (if $large > 0 then $burst else 0 end)}'

log "creating the workload logins load_app and load_orm; seeding ${LOAD_MSSQL_TABLES} tables, ${LOAD_MSSQL_ROWS} rows (schema load of retail)"
# shellcheck disable=SC2016 # sqlcmd variable (from the environment: never on a command line)
# load_orm (ADR-0053 decision 6): the ORM-style reader, same password; SELECT on the load schema is
# granted with load_app's (seed.py).
printf '%s\n' 'SET NOCOUNT ON;' "CREATE LOGIN load_app WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
  "CREATE LOGIN load_orm WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
  'GO' 'USE retail;' 'CREATE USER load_app FOR LOGIN load_app;' 'CREATE USER load_orm FOR LOGIN load_orm;' 'GO' \
  | timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T -e SSL_CERT_FILE=/var/opt/mssql/databastion-tls/ca.pem \
    target-mssql bash -c 'SQLCMDPASSWORD="$(cat /run/secrets/target_mssql_password)" PW="$(cat /run/secrets/target_client_password)" exec '"$SQLCMD"' -S localhost -U sa -b -I -i /dev/stdin' \
    >/dev/null || fail "cannot create the workload login"
if [ "$LOAD_SQLSERVER_LARGE_EVERY_S" -gt 0 ]; then
  # load_big (ADR-0051 refinement of 2026-10-22, load step 4): the large-event reader, same password;
  # SELECT on the load schema is granted after the seed.
  # shellcheck disable=SC2016 # sqlcmd variable (from the environment: never on a command line)
  printf '%s\n' 'SET NOCOUNT ON;' "CREATE LOGIN load_big WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
    'GO' 'USE retail;' 'CREATE USER load_big FOR LOGIN load_big;' 'GO' \
    | timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T -e SSL_CERT_FILE=/var/opt/mssql/databastion-tls/ca.pem \
      target-mssql bash -c 'SQLCMDPASSWORD="$(cat /run/secrets/target_mssql_password)" PW="$(cat /run/secrets/target_client_password)" exec '"$SQLCMD"' -S localhost -U sa -b -I -i /dev/stdin' \
      >/dev/null || fail "cannot create the large-event login"
fi
t0="$(date +%s)"
python3 "$SEED" sqlserver --tables "$LOAD_MSSQL_TABLES" --rows "$LOAD_MSSQL_ROWS" | mssql_sa >"$W/out/seed.out" 2>&1 \
  || { tail -n 5 "$W/out/seed.out" >&2; fail "the scaled seed failed"; }
if [ "$LOAD_SQLSERVER_LARGE_EVERY_S" -gt 0 ]; then
  mssql_sa_q "USE retail; GRANT SELECT ON SCHEMA::load TO load_big;" >/dev/null || fail "cannot grant the large-event login"
fi
log "seeded: $(grep -E '^[0-9]+ tables$' "$W/out/seed.out" | tail -n 1) in $(( $(date +%s) - t0 )) s"
if r="$(python3 "$LOADLIB" quiet --samples "$SAMPLES_DB" --names target-mssql --below 0.05 --window 10 --timeout 180)"; then
  log "target quiet: $r"
else
  log "WARNING: target still busy after 180 s: $r (the idle baseline absorbs it)"
fi
phase_done seed

# ------------------------------------------------------------------------------ admin, enroll, idle A
log "bootstrapping the administrator, enrolling the agent"
admin_login load-sqlserver
enroll_agent target_agent_password
phase_done enroll
started="$(docker inspect -f '{{.State.StartedAt}}' "${CID[target-mssql]}")"
up_s=$(( $(date +%s) - $(date -d "$started" +%s) ))
if [ "$up_s" -lt "$LOAD_MSSQL_SETTLE_S" ]; then
  log "letting SQL Server's start-up background work settle ($(( LOAD_MSSQL_SETTLE_S - up_s )) s, up ${up_s} s)"
  sleep $(( LOAD_MSSQL_SETTLE_S - up_s ))
fi
phase_done settle
log "idle baseline without the agent (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_no_agent", t0: $t0, t1: $t1}'

# ------------------------------------------------------------------------------ agent run, idle B
log "starting databastion-agent run"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
CID[agent]="$(compose ps -q agent)"
python3 "$LOADLIB" sample --out "$SAMPLES_AGENT" --interval 1 "agent=${CID[agent]}" 2>"$W/out/sampler-agent.err" &
BG_PIDS+=("$!")
wait_online 120 "${TARGET}:sqlserver"
log "agent online: $(target_summary "$(target_json "$TARGET")")"
(
  while :; do
    console_sql "SELECT json_build_object('t', extract(epoch from now()), 'last_seen', extract(epoch from last_seen_at),
      'spool', spool, 'metrics', metrics) FROM agents WHERE id = '${AGENT_ID}'" >>"$HEARTBEATS" 2>/dev/null || true
    sleep 10
  done
) &
BG_PIDS+=("$!")
inspect_scan "with the agent"
log "idle baseline with the agent running, no job (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_agent", t0: $t0, t1: $t1}'
phase_done agent

# ------------------------------------------------------------------------------ Discovery
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
# The server's statement CPU from its plan cache (every cached statement: nothing else runs during
# the scan), read before and after, at least 2 s outside the scan window (these reads run inside the
# target's cgroup): the share of the scan's CPU spent in statements (a cross-check, as run.sh's
# stmt_exec_ms; worker time, in ms).
plan_cache_cpu() {
  mssql_sa_q "SELECT CONCAT(COALESCE(SUM(total_worker_time), 0) / 1000, ' ', COALESCE(SUM(execution_count), 0)) FROM sys.dm_exec_query_stats"
}
# LOAD_MSSQL_DIAG=1 (local runs only): the 15 statements that used the most CPU during the scan, their
# first 70 characters, into a private file of the log directory (table names may hold seeded values).
if [ "${LOAD_MSSQL_DIAG:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then MSSQL_DIAG=1; else MSSQL_DIAG=0; fi
diag_snapshot() {
  mssql_sa_q "SELECT CONCAT(CONVERT(varchar(64), qs.sql_handle, 1), ':', qs.statement_start_offset, CHAR(9), qs.total_worker_time,
      CHAR(9), qs.execution_count, CHAR(9), REPLACE(REPLACE(LEFT(SUBSTRING(st.text, qs.statement_start_offset / 2 + 1, 400), 70), CHAR(10), ' '), CHAR(13), ' '))
    FROM sys.dm_exec_query_stats qs CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st" >"$1"
}
[ "$MSSQL_DIAG" = 0 ] || diag_snapshot "$W/diag-before.tsv"
read -r cpu_ms0 calls0 <<<"$(plan_cache_cpu)"
log "Discovery scan of ${TARGET} (paced, the console defaults: ${LOAD_SAMPLE_ROWS} rows, 900 s)"
printf '{"sample_rows":%d,"max_duration_s":900,"statement_timeout_ms":30000}' "$LOAD_SAMPLE_ROWS" >"$W/scan-req.json"
sleep 2
r="$(api POST "/api/agents/${AGENT_ID}/targets/${TARGET}/scan" "$W/scan-req.json")"
[ "$(status_of "$r")" = 202 ] || fail "scan request: HTTP $(status_of "$r")"
job_id="$(body_of "$r" | jq -r '.job_id')"
[[ "$job_id" =~ $UUID_RE ]] || fail "scan request: no job id"
deadline=$(( $(date +%s) + 960 ))
while :; do
  status="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")"
  case "$status" in succeeded | failed | cancelled | expired) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "scan of ${TARGET} not finished in time ($status)"
  sleep 1
done
sleep 2
read -r cpu_ms1 calls1 <<<"$(plan_cache_cpu)"
if [ "$MSSQL_DIAG" = 1 ]; then
  diag_snapshot "$W/diag-after.tsv"
  python3 - "$W/diag-before.tsv" "$W/diag-after.tsv" >"$LOAD_LOG_DIR/diag-top-statements.txt" <<'PY'
import sys
def load(p):
    out = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 4 and parts[1].isdigit():
            out[parts[0]] = (int(parts[1]), int(parts[2]), parts[3])
    return out
b, a = load(sys.argv[1]), load(sys.argv[2])
rows = []
for k, (cpu, n, text) in a.items():
    c0, n0, _ = b.get(k, (0, 0, ""))
    rows.append((cpu - c0, n - n0, text))
rows.sort(reverse=True)
for cpu, n, text in rows[:15]:
    print(f"{cpu / 1000:10.1f} ms  {n:6d} x  {text}")
PY
  chmod 0600 "$LOAD_LOG_DIR/diag-top-statements.txt"
fi
read -r s0 s1 <<<"$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at) FROM jobs WHERE id = '$job_id'")"
[[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of ${TARGET}: no delivery / end time ($status)"
n_tables="$(mssql_sa_q "SELECT COUNT(*) FROM retail.sys.tables WHERE is_ms_shipped = 0")"
fact --arg target "$TARGET" --arg status "$status" --argjson t0 "$s0" --argjson t1 "$s1" --argjson tables "$n_tables" \
  --argjson rows "$LOAD_MSSQL_ROWS" --argjson ms "$(( cpu_ms1 - cpu_ms0 ))" --argjson calls "$(( calls1 - calls0 ))" \
  '{kind: "scan", target: $target, status: $status, t0: $t0, t1: $t1, tables: $tables, rows: $rows,
    stmt_exec_ms: $ms, stmt_calls: $calls}'
log "scan of ${TARGET}: $status in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s (${n_tables} tables)"
[ "$status" = succeeded ] || fail "scan of ${TARGET} ended '$status'"
wait_spool_empty "$s1" || log "WARNING: no heartbeat with an empty spool after the scan"
n_findings="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
fact --arg target "$TARGET" --argjson n "$n_findings" '{kind: "findings", target: $target, count: $n}'
log "findings: ${n_findings}"
phase_done discovery

# ------------------------------------------------------------------------------ workloads
python3 "$SEED" tsql --tables "$LOAD_MSSQL_TABLES" --rows "$LOAD_MSSQL_ROWS" \
  --workload-tables "$LOAD_WORKLOAD_TABLES" >"$W/workload.sql"
# ADR-0053 decision 6: the ORM-style cycle of load_orm (seed.py orm: lazy loads, eager-loading
# joins, select_related chains, reporting queries over 16 to 24 tables), every 2 s in one session,
# in a T-SQL loop of $(CYCLES) cycles; prints `ORM <statements issued>`.
python3 "$SEED" orm --tables "$LOAD_MSSQL_TABLES" --rows "$LOAD_MSSQL_ROWS" --dialect tsql >"$W/orm-stmts.sql"
ORM_PER_CYCLE="$(wc -l <"$W/orm-stmts.sql")"
# shellcheck disable=SC2016 # sqlcmd variable, literal on purpose
{ printf 'SET NOCOUNT ON;\nUSE retail;\nGO\nDECLARE @i int = 0;\nWHILE @i < $(CYCLES)\nBEGIN\n'
  cat "$W/orm-stmts.sql"
  printf "  WAITFOR DELAY '00:00:02';\n  SET @i += 1;\nEND\nSELECT CONCAT('ORM ', @i * %d);\n" "$ORM_PER_CYCLE"
} >"$W/orm.sql"
rm -f -- "$W/orm-stmts.sql"
# run_orm DURATION OUT: the load_orm session for about DURATION seconds (a cycle takes 2 s and more).
run_orm() {
  local cycles=$(( $1 * 10 / 21 > 0 ? $1 * 10 / 21 : 1 ))
  timeout $(( $1 + 300 )) docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    -e "CYCLES=$cycles" mssql-client '
      cat > /tmp/orm.sql
      export SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)"
      '"$SQLCMD"' -S sqlserver -d retail -U load_orm -b -I -W -h -1 -v CYCLES="$CYCLES" -i /tmp/orm.sql \
        | grep -E "^(ORM [0-9]+|Msg [0-9]+.*)$" || true' <"$W/orm.sql" >"$2" 2>&1
}
# ADR-0051 refinement of 2026-10-22, load step 4: the large-event bursts of load_big (see the settings),
# $(BURSTS) bursts of $(BURST) statements, one every $(EVERY) seconds; prints `LARGE <statements run>`.
# The statement is built on the server (the comment, about 60 000 characters, and the first load table).
# shellcheck disable=SC2016 # sqlcmd variables, literal on purpose
LARGE_SQL='SET NOCOUNT ON;
DECLARE @t nvarchar(300) = (SELECT TOP (1) QUOTENAME(SCHEMA_NAME(schema_id)) + N'"'.'"' + QUOTENAME(name)
  FROM sys.tables WHERE schema_id = SCHEMA_ID(N'"'load'"') ORDER BY name);
DECLARE @q nvarchar(max) = N'"'SELECT @n = COUNT(*) /* '"' + REPLICATE(CONVERT(nvarchar(max), N'"'x'"'), 60000)
  + N'"' */ FROM '"' + @t + N'"' WHERE id = @i'"';
DECLARE @d varchar(12) = CONVERT(varchar(12), DATEADD(second, $(EVERY), CAST('"'00:00:00'"' AS time(0))), 108);
DECLARE @b int = 0, @i int, @n int, @done int = 0;
WHILE @b < $(BURSTS)
BEGIN
  WAITFOR DELAY @d;
  SET @i = 0;
  WHILE @i < $(BURST)
  BEGIN
    EXEC sys.sp_executesql @q, N'"'@i int, @n int OUTPUT'"', @i, @n OUTPUT;
    SET @i += 1; SET @done += 1;
    WAITFOR DELAY '"'00:00:00.020'"';
  END
  SET @b += 1;
END
SELECT CONCAT('"'LARGE '"', @done);'
# run_large DURATION OUT: the load_big session for about DURATION seconds.
run_large() {
  local bursts=$(( $1 / LOAD_SQLSERVER_LARGE_EVERY_S ))
  [ "$bursts" -gt 0 ] || { echo "LARGE 0" >"$2"; return 0; }
  printf '%s\n' "$LARGE_SQL" | timeout $(( $1 + 300 )) docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    -e "BURSTS=$bursts" -e "BURST=$LOAD_SQLSERVER_LARGE_BURST" -e "EVERY=$LOAD_SQLSERVER_LARGE_EVERY_S" mssql-client '
      cat > /tmp/large.sql
      export SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)"
      '"$SQLCMD"' -S sqlserver -d retail -U load_big -b -I -W -h -1 -v BURSTS="$BURSTS" BURST="$BURST" EVERY="$EVERY" \
        -i /tmp/large.sql | grep -E "^(LARGE [0-9]+|Msg [0-9]+.*)$" || true' >"$2" 2>&1
}
# #282 review N3: the auto-created statistics of the load schema (the ORM-style reporting queries'
# GROUP BY columns), dropped as `sa` every LOAD_SQLSERVER_STATS_RESET_S seconds of the Audit run, so
# that the next ORM cycle builds them again in load_orm's session (statistics builds under load).
# Each drop: one line `<unix time> <statistics dropped>` in stats-resets.txt.
STATS_RESET_SQL="USE retail;
DECLARE @s nvarchar(max) = N'', @n int = 0;
SELECT @s += N'DROP STATISTICS ' + QUOTENAME(SCHEMA_NAME(o.schema_id)) + N'.' + QUOTENAME(o.name) + N'.'
    + QUOTENAME(st.name) + N'; ', @n += 1
  FROM sys.stats st JOIN sys.objects o ON o.object_id = st.object_id
  WHERE st.auto_created = 1 AND o.schema_id = SCHEMA_ID(N'load');
IF @n > 0 EXEC (@s);
SELECT @n;"
stats_reset_loop() {
  local n
  while :; do
    sleep "$LOAD_SQLSERVER_STATS_RESET_S"
    n="$(mssql_sa_q "$STATS_RESET_SQL" 2>/dev/null | tail -n 1)" || n=""
    [[ "$n" =~ ^[0-9]+$ ]] || n=error
    printf '%s %s\n' "$(date +%s)" "$n" >>"$W/out/stats-resets.txt"
  done
}
# run_workload PHASE DURATION: LOAD_CLIENTS sqlcmd sessions as load_app in one mssql-client
# container, LOAD_MSSQL_RATE statements per second in total (absolute schedule per session), and
# the load_orm session next to them (run_orm).
run_workload() {
  local phase="$1" dur="$2" per iv t_start rc=0 orm_pid reset_pid="" large_pid=""
  per=$(( LOAD_MSSQL_RATE * dur / LOAD_CLIENTS ))
  iv=$(( LOAD_CLIENTS * 1000000 / LOAD_MSSQL_RATE ))
  log "workload ($phase): ${LOAD_MSSQL_RATE} statements/s over ${LOAD_CLIENTS} sessions, ${dur} s"
  WL_START_UTC="$(date -u +'%Y-%m-%dT%H:%M:%S')"
  t_start="$(now_s)"
  run_orm "$dur" "$W/out/orm-$phase.out" &
  orm_pid=$!
  if [ "$phase" = on ] && [ "$LOAD_SQLSERVER_LARGE_EVERY_S" -gt 0 ]; then
    log "large events: a burst of ${LOAD_SQLSERVER_LARGE_BURST} statements of about 120 KiB every ${LOAD_SQLSERVER_LARGE_EVERY_S} s (load_big)"
    run_large "$dur" "$W/out/large-$phase.out" &
    large_pid=$!
  fi
  if [ "$phase" = on ] && [ "$LOAD_SQLSERVER_STATS_RESET_S" -gt 0 ]; then
    log "dropping the load schema's auto-created statistics every ${LOAD_SQLSERVER_STATS_RESET_S} s (#282 review N3)"
    stats_reset_loop &
    reset_pid=$!
    BG_PIDS+=("$reset_pid")
  fi
  timeout $((dur + 300)) docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    -e "N=$per" -e "IV_US=$iv" -e "CLIENTS=$LOAD_CLIENTS" mssql-client '
      cat > /tmp/w.sql
      export SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)"
      for s in $(seq 1 "$CLIENTS"); do
        ctx="$(printf "0x%016x%016x%016x" "$N" "$IV_US" "$s")"
        '"$SQLCMD"' -S sqlserver -d retail -U load_app -b -I -W -h -1 -v CTX="$ctx" \
          -i /tmp/w.sql >/tmp/out.$s 2>&1 &
      done
      rc=0
      for j in $(jobs -p); do wait "$j" || rc=1; done
      grep -h "^RESULT " /tmp/out.* || true
      echo "ERRORS $(cat /tmp/out.* | grep -cE "^Msg [0-9]+" || true)"
      exit $rc' <"$W/workload.sql" >"$W/out/mssql-$phase.out" 2>"$W/out/mssql-$phase.err" || rc=$?
  WL_END="$(now_s)"
  if [ -n "$reset_pid" ]; then
    kill "$reset_pid" 2>/dev/null || true
    wait "$reset_pid" 2>/dev/null || true
    # Not stopped again by stop_background (the pid may be reused by then).
    local -a kept=()
    local pid
    for pid in "${BG_PIDS[@]}"; do [ "$pid" = "$reset_pid" ] || kept+=("$pid"); done
    BG_PIDS=("${kept[@]}")
  fi
  wait "$orm_pid" || true
  log "ORM session ($phase): $(tr '\n' ' ' <"$W/out/orm-$phase.out" | cut -c1-200)"
  if [ -n "$large_pid" ]; then
    wait "$large_pid" || true
    log "large-event session ($phase): $(tr '\n' ' ' <"$W/out/large-$phase.out" | cut -c1-200)"
  fi
  [ "$rc" = 0 ] || { tail -n 5 "$W/out/mssql-$phase.out" "$W/out/mssql-$phase.err" >&2; fail "the workload ($phase) exited $rc"; }
  fact --arg name "workload_audit_$phase" --argjson t0 "$(jq -n --argjson t "$t_start" '$t + 5')" \
    --argjson t1 "$WL_END" '{kind: "window", name: $name, t0: $t0, t1: $t1}'
  python3 - "$W/out/mssql-$phase.out" "$phase" "$TARGET" "$LOAD_MSSQL_RATE" "$LOAD_CLIENTS" >>"$FACTS" <<'PY'
import json, sys
path, phase, target, rate, clients = sys.argv[1:6]
lines = open(path, encoding="utf-8").read().splitlines()
res = [l.split() for l in lines if l.startswith("RESULT ") and len(l.split()) == 8]
errors = [l.split()[1] for l in lines if l.startswith("ERRORS ")]
issued = sum(int(r[1]) for r in res)
late = sum(int(r[2]) for r in res)
# The sessions' mean in-loop time, weighted by their statements (see seed.py tsql_workload).
mean_us = sum(int(r[1]) * float(r[7]) for r in res) / issued if issued else None
sched = sorted(int(r[6]) for r in res)
print(json.dumps({"kind": "workload", "target": target, "phase": phase, "tool": "sqlcmd", "rate": int(rate),
    "issued": issued, "failed": (int(clients) - len(res)) + (int(errors[0]) if errors and errors[0].isdigit() else 0),
    "p95_ms": round(mean_us / 1000.0, 4) if mean_us is not None else None,
    "latency_metric": "mean in-loop duration per workload statement (server clock in 4.1 ms steps: an unbiased mean, no percentile)",
    "late_starts": late, "schedule_lag_p95_ms": round(sched[-1] / 1000.0, 2) if sched else None,
    "sessions": len(res)}, separators=(",", ":")))
PY
  log "workload ($phase): $(tail -n 1 "$FACTS" | jq -c '{issued, failed, p95_ms, late_starts, schedule_lag_p95_ms}')"
}
# Unmeasured warm-up: the batch is compiled and its plan settles (statistics built on first use
# recompile it, which resets the plan cache counters the latency figure is read from).
log "warm-up workload (${LOAD_WARMUP_S} s, not measured)"
timeout $((LOAD_WARMUP_S + 300)) docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
  -e "N=$(( LOAD_MSSQL_RATE * LOAD_WARMUP_S / LOAD_CLIENTS ))" -e "IV_US=$(( LOAD_CLIENTS * 1000000 / LOAD_MSSQL_RATE ))" \
  -e "CLIENTS=$LOAD_CLIENTS" mssql-client '
    cat > /tmp/w.sql
    export SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)"
    for s in $(seq 1 "$CLIENTS"); do
      ctx="$(printf "0x%016x%016x%016x" "$N" "$IV_US" "$s")"
      '"$SQLCMD"' -S sqlserver -d retail -U load_app -b -I -W -h -1 -v CTX="$ctx" -i /tmp/w.sql >/dev/null 2>&1 &
    done
    rc=0
    for j in $(jobs -p); do wait "$j" || rc=1; done
    exit $rc' <"$W/workload.sql" >/dev/null 2>&1 || fail "the warm-up workload failed"
phase_done warmup
run_workload off "$LOAD_BASELINE_S"
phase_done workload-off

# The latency probe (the catch-up impact, review M1 of the read-throughput fix): as `sa`, blocks of
# 100 constant SELECTs (no table: no access event on either source; about 60 Extended Events events/s),
# one `PROBE <µs per statement>` line per block every 5 s, for 30 s per call (server clock: a block's
# mean, not a statement's latency). Run once before Audit (phase off) and during the drain, while the
# stream may still catch up and no workload runs (phase drain); compared as the `probe` facts and
# checked by loadlib.py (`drain_probe_p95_us`, with `db_cores_drain`) when the stream was behind.
PROBE_SQL="DECLARE @end datetime2 = DATEADD(second, 30, SYSUTCDATETIME()), @t0 datetime2, @i int, @v int;
WHILE SYSUTCDATETIME() < @end BEGIN
  SET @t0 = SYSUTCDATETIME(); SET @i = 0;
  WHILE @i < 100 BEGIN SELECT @v = COUNT(*) FROM (VALUES (1), (2), (3)) AS v(x); SET @i += 1; END;
  PRINT CONCAT('PROBE ', DATEDIFF_BIG(microsecond, @t0, SYSUTCDATETIME()) / 100);
  WAITFOR DELAY '00:00:05';
END"
probe_chunk() { mssql_sa_q "$PROBE_SQL" >>"$1" 2>/dev/null || true; }
# probe_loop OUT STOP_FILE: 30 s chunks until STOP_FILE exists.
probe_loop() { while [ ! -e "$2" ]; do probe_chunk "$1"; done; }
log "latency probe before Audit (30 s, as sa, constant SELECTs)"
: >"$W/out/probe-off.txt"
probe_chunk "$W/out/probe-off.txt"
python3 "$LOADLIB" probe --out-file "$W/out/probe-off.txt" --target "$TARGET" --phase off >>"$FACTS"
log "probe (off): $(tail -n 1 "$FACTS" | jq -c '{blocks, mean_us, p95_us}')"

# ------------------------------------------------------------------------------ Audit on
log "enabling Audit on ${TARGET} (${LOAD_SQLSERVER_AUDIT_SOURCE})"
AUDIT_START="$(date +%s)"
AUDIT_START_UTC="$(date -u -d "@$AUDIT_START" +'%Y-%m-%dT%H:%M:%S')"
enable_audit "$TARGET"
sleep 5
phase_done audit-setup
run_workload on "$LOAD_SOAK_S"
SOAK_END="$WL_END"
SOAK_START_UTC="$WL_START_UTC"
phase_done workload-on

# ------------------------------------------------------------------------------ drain
events_sql() {
  printf "FROM access_events WHERE agent_id = '%s' AND target_id = '%s' AND db_user = 'load_app' AND action = 'read'" \
    "$AGENT_ID" "$TARGET"
}
want="$(grep '"kind":"workload"' "$FACTS" | jq -s 'map(select(.phase == "on"))[0].issued // 0')"
log "waiting until every statement of the Audit run is stored (${want} expected, at most ${LOAD_DRAIN_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + LOAD_DRAIN_TIMEOUT_S ))
# The stream lag: statements stored against the time since the last workload statement, sampled every
# 5 s and logged every 30 s; the `drain` fact keeps the samples, the count stored when the workload
# ended and the rate during the drain (statements/s), so a stream that falls behind its source shows
# how far and how fast it catches up even when the drain times out (drain_s is then null).
drain_samples=()
last_log=0
DRAIN_T0="$(now_s)"
: >"$W/out/probe-drain.txt"
rm -f -- "$W/out/probe-stop"
probe_loop "$W/out/probe-drain.txt" "$W/out/probe-stop" &
probe_pid=$!
BG_PIDS+=("$probe_pid")
while :; do
  got="$(console_sql "SELECT coalesce(sum(aggregated_count), 0) $(events_sql)")"
  since="$(jq -n --argjson a "$SOAK_END" --argjson b "$(now_s)" '$b - $a | . * 10 | round / 10')"
  drain_samples+=("[${since},${got}]")
  [ "$got" -ge "$want" ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "WARNING: not every statement stored within ${LOAD_DRAIN_TIMEOUT_S} s: ${got}/${want}"
    break
  fi
  if [ "$(date +%s)" -ge $(( last_log + 30 )) ]; then
    log "drain: ${got}/${want} statements stored ${since} s after the workload"
    last_log="$(date +%s)"
  fi
  sleep 5
done
log "statements stored: ${got}/${want}"
DRAIN_T1="$(now_s)"
fact --arg name "drain_${TARGET}" --argjson t0 "$DRAIN_T0" --argjson t1 "$DRAIN_T1" '{kind: "window", name: $name, t0: $t0, t1: $t1}'
# The probe's current chunk ends within 30 s.
touch "$W/out/probe-stop"
wait "$probe_pid" 2>/dev/null || true
kept_pids=()
for pid in "${BG_PIDS[@]}"; do [ "$pid" = "$probe_pid" ] || kept_pids+=("$pid"); done
BG_PIDS=("${kept_pids[@]}")
python3 "$LOADLIB" probe --out-file "$W/out/probe-drain.txt" --target "$TARGET" --phase drain >>"$FACTS"
log "probe (drain): $(tail -n 1 "$FACTS" | jq -c '{blocks, mean_us, p95_us}')"
fact --arg target "$TARGET" --argjson want "$want" --argjson got "$got" \
  --argjson samples "[$(IFS=,; printf '%s' "${drain_samples[*]}")]" \
  '{kind: "drain", target: $target, want: $want, stored: $got, samples: $samples,
    stored_at_workload_end: $samples[0][1],
    rate_per_s: (if ($samples | length) > 1 and ($samples[-1][0] - $samples[0][0]) > 0
      then (($samples[-1][1] - $samples[0][1]) / ($samples[-1][0] - $samples[0][0]) | . * 10 | round / 10) else null end)}'
log "drain: $(tail -n 1 "$FACTS" | jq -c '{want, stored, stored_at_workload_end, rate_per_s}')"
console_sql "SELECT json_build_object('kind', 'events', 'target', '${TARGET}',
    'received', coalesce(sum(aggregated_count), 0), 'events', count(*),
    'lag_p95_s', round(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch from received_at - coalesce(ts_last, ts))::float8)::numeric, 1),
    'lag_max_s', round(max(extract(epoch from received_at - coalesce(ts_last, ts)))::numeric, 1),
    'drain_s', CASE WHEN coalesce(sum(aggregated_count), 0) >= $want
      THEN round((extract(epoch from max(received_at)) - $SOAK_END)::numeric, 1) END)
  $(events_sql)" >>"$FACTS"
console_sql "SELECT json_build_object('kind', 'events_timeline', 'target', '${TARGET}',
    'buckets', coalesce(json_agg(json_build_array(b, n) ORDER BY b), '[]'))
  FROM (SELECT (floor(extract(epoch from ts) / 10) * 10)::bigint AS b, sum(aggregated_count) AS n
        $(events_sql) GROUP BY 1) AS x" >>"$FACTS"
other="$(console_sql "SELECT coalesce(string_agg(coalesce(db_user, '-') || ' ' || action || ' ' || aggregated_count, '; '), 'none')
  FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND (db_user IS DISTINCT FROM 'load_app' OR action <> 'read')
    AND db_user IS DISTINCT FROM 'load_orm'")"
log "other events of ${TARGET}: ${other}"
log "target notes after the run: $(target_json "$TARGET" | jq -c '[.notes[]? | {code, count}]')"
# Source side: the workload's SELECT records in the audit file since the Audit run started.
if [ "$LOAD_SQLSERVER_AUDIT_SOURCE" = sqlserver_audit ]; then
  src="$(mssql_sa_q "SELECT COUNT(*) FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)
    WHERE server_principal_name = N'load_app' AND action_id = 'SL' AND event_time >= CAST(N'${SOAK_START_UTC}' AS datetime2)")" || src=""
else
  # #282 review N3, source side (as `sa`, counts only): in the session's files, the statistics
  # builds (`sp_statement_completed` whose text is the server's StatMan grammar) since Audit started,
  # per principal, and the workload's SELECTs of load_app since the soak started.
  log "Extended Events: counting the statistics builds and workload SELECTs in the session's files"
  mssql_sa_q "SELECT CONCAT(s.k, ' ', REPLACE(COALESCE(s.p, N'-'), N' ', N'_'), ' ', COUNT(*)) FROM (
      SELECT CASE WHEN f.object_name = N'sp_statement_completed' THEN 'build' ELSE 'select' END AS k,
        CAST(f.event_data AS xml).value('(event/action[@name=\"server_principal_name\"]/value)[1]', 'nvarchar(128)') AS p
      FROM sys.fn_xe_file_target_read_file(N'/var/opt/mssql/xe/databastion_xe*.xel', NULL, NULL, NULL) f
      WHERE (f.object_name = N'sp_statement_completed' AND f.event_data LIKE N'%StatMan%'
          AND f.timestamp_utc >= CAST(N'${AUDIT_START_UTC}' AS datetime2))
        OR (f.object_name = N'sql_statement_completed' AND f.event_data LIKE N'%load[_]app%'
          AND f.event_data LIKE N'%SELECT @v = note FROM%' AND f.timestamp_utc >= CAST(N'${SOAK_START_UTC}' AS datetime2))
    ) s GROUP BY s.k, s.p" >"$W/out/xe-source.txt" 2>/dev/null || : >"$W/out/xe-source.txt"
  src="$(awk '$1 == "select" && $2 == "load_app" { print $3 }' "$W/out/xe-source.txt")"
  # Agent and console side: the agent's cut lines (debug), the workload principals' events.
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent >"$W/out/agent-xe.log" 2>/dev/null || true
  console_sql "SELECT coalesce(json_agg(x ORDER BY x.db_user), '[]') FROM (
      SELECT db_user, count(*) AS events, sum(aggregated_count) AS statements,
        coalesce(sum(aggregated_count) FILTER (WHERE action = 'read'), 0) AS read_statements,
        count(*) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb AND objects_overflowed IS NOT TRUE) AS unknown_star_events,
        coalesce(sum(aggregated_count) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb
          AND objects_overflowed IS NOT TRUE), 0) AS unknown_star_statements,
        count(*) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb AND jsonb_array_length(objects) = 1) AS star_only_events,
        coalesce(sum(aggregated_count) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb
          AND jsonb_array_length(objects) = 1), 0) AS star_only_statements,
        count(*) FILTER (WHERE objects_overflowed IS TRUE) AS overflowed_events
      FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user IN ('load_app', 'load_orm')
      GROUP BY db_user) AS x" >"$W/out/xe-noise.json" 2>/dev/null || rm -f -- "$W/out/xe-noise.json"
  orm_on="$(sed -n 's/^ORM \([0-9][0-9]*\)$/\1/p' "$W/out/orm-on.out" | tail -n 1)"
  python3 "$LOADLIB" xe-catchup --log "$W/out/agent-xe.log" --builds "$W/out/xe-source.txt" \
    --console "$W/out/xe-noise.json" --issued "load_app=${want}" ${orm_on:+--issued "load_orm=${orm_on}"} \
    --since "$AUDIT_START" --label load-sqlserver --json "$LOAD_RESULTS_DIR/xe-catchup.json" \
    --md "$LOAD_RESULTS_DIR/xe-catchup.md" 2>&1 | while IFS= read -r line; do log "$line"; done || true
  rm -f -- "$W/out/agent-xe.log"
  # ADR-0051 refinement of 2026-10-22: the reads cancelled above 12 MiB and at the statement timeout
  # (from the agent's log, xe-catchup), checked by loadlib.py report (`xe_cancels_per_10min`,
  # `xe_timeouts`); null counts when the log could not be read (no data: failed).
  # No large-event workload: no file (and, under pipefail, no failing sed).
  large_done=""
  if [ -f "$W/out/large-on.out" ]; then
    large_done="$(sed -n 's/^LARGE \([0-9][0-9]*\)$/\1/p' "$W/out/large-on.out" | tail -n 1)"
  fi
  large_bursts=$(( ${large_done:-0} / LOAD_SQLSERVER_LARGE_BURST ))
  if ! jq -c --arg t "$TARGET" --argjson b "$large_bursts" \
      '{kind: "xe_reads", target: $t, cancels: .reads.cancels, timeouts: .reads.timeouts,
        max_cancels_per_10min: .reads.max_cancels_per_10min, large_bursts: $b}' \
      "$LOAD_RESULTS_DIR/xe-catchup.json" >>"$FACTS" 2>/dev/null; then
    fact --arg t "$TARGET" --argjson b "$large_bursts" \
      '{kind: "xe_reads", target: $t, cancels: null, timeouts: null, max_cancels_per_10min: null, large_bursts: $b}'
  fi
  log "Extended Events reads: $(tail -n 1 "$FACTS" | jq -c '{cancels, timeouts, max_cancels_per_10min, large_bursts}')"
  if [ -s "$W/out/stats-resets.txt" ]; then
    log "statistics resets: $(wc -l <"$W/out/stats-resets.txt"), statistics dropped: $(awk '$2 ~ /^[0-9]+$/ { n += $2 } END { print n + 0 }' "$W/out/stats-resets.txt"), failed: $(grep -c ' error$' "$W/out/stats-resets.txt" || true)"
  fi
fi
if [[ "${src:-}" =~ ^[0-9]+$ ]]; then
  fact --arg t "$TARGET" --argjson n "$src" '{kind: "source", target: $t, statements: $n, rotated_files: 0}'
  log "source (${LOAD_SQLSERVER_AUDIT_SOURCE}): ${src} SELECT record(s) of load_app since the Audit run started"
fi
# ADR-0053 decision 6: the console's per-principal counts and `*` events are read by print_census
# (cleanup), with the agent's census.
if wait_spool_empty "$(now_s)"; then fact '{kind: "spool_drained", ok: true, batches: 0}'
else fact '{kind: "spool_drained", ok: false}'; fi
lost="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|events dropped|rejected batch items|unreadable spool file' || true)"
fact --argjson n "$lost" '{kind: "agent_log", lost: $n}'
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
  { echo "# SQL Server target"; cat "$LOAD_RESULTS_DIR/results.md"; } >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
