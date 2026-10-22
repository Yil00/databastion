#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Load run of a Valkey or Redis target (ROADMAP P9-D, ADR-0052 decision 13 "Load"; e2e/load/README.md
# "Valkey and Redis targets"): the console, the agent and one dev service (LOAD_REDIS_ENGINE: valkey,
# the default, or redis) (e2e/docker-compose.yml + e2e/docker-compose.redis.yml +
# docker-compose.redis.yml here, project databastion-load-redis). Measures, as e2e/load/run.sh does
# for the other engines:
#   1. the server's CPU impact of a paced Discovery scan of a scaled keyspace (LOAD_REDIS_KEYS keys,
#      default 1 000 000; the agent walks at most `redis.max_keys` per database, default 100 000)
#      against the < 2 % criterion (LOAD_DB_CPUS);
#   2. the Audit path (the slow log at every command, `slowlog-log-slower-than 0`, read every
#      LOAD_REDIS_POLL_S seconds) under a fixed-rate GET workload from the host
#      (e2e/redis_scenario.py load), without then with Audit: every command an event (within 1 %),
#      nothing dropped, the spool drained, the GET service time with and without Audit, the server's
#      CPU (the cost of the agent's polls);
#   3. the agent's CPU and RSS over the Audit run, bounded and without monotonic growth.
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
SEED="$HERE/seed.py"
SCENARIO="$E2E/redis_scenario.py"
PROJECT="databastion-load-redis"
LOG_TAG="load-redis"  # read by ../lib.sh

# ------------------------------------------------------------------------------ settings
export E2E_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
export E2E_VALKEY_PORT="${LOAD_VALKEY_PORT:-16479}"
export E2E_REDIS_PORT="${LOAD_REDIS_PORT:-16489}"
export LOAD_DB_CPUS="${LOAD_DB_CPUS:-2}"
# Room for the entries between two polls (the agent reads at most 512 per poll).
export E2E_REDIS_SLOWLOG_MAX_LEN="${LOAD_REDIS_SLOWLOG_MAX_LEN:-4096}"
LOAD_REDIS_ENGINE="${LOAD_REDIS_ENGINE:-valkey}"
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs-redis}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results-redis}"
LOAD_IDLE_S="${LOAD_IDLE_S:-45}"
LOAD_REDIS_KEYS="${LOAD_REDIS_KEYS:-1000000}"
LOAD_REDIS_RATE="${LOAD_REDIS_RATE:-200}"          # GETs per second
LOAD_REDIS_POLL_S="${LOAD_REDIS_POLL_S:-1}"        # Audit poll interval (audit.configure)
LOAD_CLIENTS="${LOAD_CLIENTS:-4}"
LOAD_SAMPLE_ROWS="${LOAD_SAMPLE_ROWS:-200}"
LOAD_BASELINE_S="${LOAD_BASELINE_S:-120}"
LOAD_SOAK_S="${LOAD_SOAK_S:-600}"
LOAD_DRAIN_TIMEOUT_S="${LOAD_DRAIN_TIMEOUT_S:-300}"
LOAD_SAMPLE_INTERVAL="${LOAD_SAMPLE_INTERVAL:-0.5}"
for v in LOAD_IDLE_S LOAD_REDIS_KEYS LOAD_REDIS_RATE LOAD_REDIS_POLL_S LOAD_CLIENTS LOAD_SAMPLE_ROWS \
    LOAD_BASELINE_S LOAD_SOAK_S LOAD_DRAIN_TIMEOUT_S E2E_HTTPS_PORT E2E_VALKEY_PORT E2E_REDIS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
[ "$LOAD_SOAK_S" -le 1800 ] || { echo "LOAD_SOAK_S must be at most 1800 seconds" >&2; exit 2; }
case "$LOAD_REDIS_ENGINE" in
  valkey) SVC=target-valkey ALIAS=valkey CLI=valkey-cli PORT="$E2E_VALKEY_PORT" ;;
  redis) SVC=target-redis ALIAS=redis CLI=redis-cli PORT="$E2E_REDIS_PORT" ;;
  *) echo "LOAD_REDIS_ENGINE must be valkey or redis" >&2; exit 2 ;;
esac
TARGET="${LOAD_REDIS_ENGINE}-load"
SPOOL_TIMEOUT_S=120

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load-redis.XXXXXX")"
W="$LOAD_WORK_DIR"
export E2E_WORK_DIR="$W"
E2E_LOG_DIR="$LOAD_LOG_DIR"
CENSUS_OUT_DIR="$LOAD_RESULTS_DIR"  # read by ../lib.sh (print_census): the results artifact
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/out" "$W/redis"
COMPOSE_ARGS=(-p "$PROJECT" -f "$E2E/docker-compose.yml" -f "$E2E/docker-compose.redis.yml" -f "$HERE/docker-compose.redis.yml")
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
  dump_logs db migrate web worker proxy redis-tls-init "$SVC" agent
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  print_census "load-${LOAD_REDIS_ENGINE}"
  cp -f "$W"/out/*.jsonl "$W"/out/*.json "$LOAD_LOG_DIR/" 2>/dev/null
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

# ------------------------------------------------------------------------------ secrets, CA, ACL, agent.yaml
console_secrets
put_secret target_agent_password "$(rand_hex 24)"
put_secret target_redis_admin_password "$(rand_hex 24)"
put_secret target_client_password "$(rand_hex 24)"   # ACL user load_app
test_ca "Redis load"
: >"$T/redis-ca.pem"
client_sha="$(printf '%s' "$(cat "$S/target_client_password")" | sha256sum | cut -d' ' -f1)"
umask 022
echo "user load_app on #${client_sha} ~load:* resetchannels -@all +get +ping" >"$W/redis/clients.acl"
umask 077
unset client_sha
cat >"$W/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  min_audit_poll_interval_s: 1
targets:
  - id: ${TARGET}
    engine: ${LOAD_REDIS_ENGINE}
    host: ${ALIAS}
    port: 6379
    account: databastion
    secret:
      file: /run/databastion-secrets/target_agent_password
    redis:
      tls: verify_full
      ca_file: /etc/databastion/redis-ca.pem
EOF
chmod 0644 "$W/agent/agent.yaml"

# admin_cli ARGS...: as `admin` on the server's Unix socket (dev tooling, never the agent).
admin_cli() {
  timeout 300 docker compose "${COMPOSE_ARGS[@]}" exec -T "$SVC" bash -c \
    'REDISCLI_AUTH="$(cat /run/secrets/target_redis_admin_password)" exec "$0" -s /tmp/databastion-dev.sock --user admin --no-auth-warning "$@"' \
    "$CLI" "$@"
}
info_field() { admin_cli INFO "$1" | tr -d '\r' | sed -n "s/^$2:\\(.*\\)$/\\1/p"; }

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_VALKEY_IMAGE E2E_REDIS_IMAGE
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

log "starting the console and ${SVC} (${LOAD_DB_CPUS} CPUs)"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy "$SVC"
start_console
deadline=$(( $(date +%s) + 180 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$SVC")" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "$SVC not healthy within 180 s"
  sleep 2
done
compose exec -T "$SVC" cat /tls/ca.pem >"$T/redis-ca.pem" || fail "cannot copy the dev CA"
chmod 0644 "$T/redis-ca.pem"
phase_done start

# ------------------------------------------------------------------------------ sampler, seed
declare -A CID=()
CID[$SVC]="$(compose ps -q "$SVC")"
python3 "$LOADLIB" sample --out "$SAMPLES_DB" --interval "$LOAD_SAMPLE_INTERVAL" \
  "${SVC}=${CID[$SVC]}" 2>"$W/out/sampler-db.err" &
BG_PIDS+=("$!")
sleep 3
head -n -1 "$SAMPLES_DB" | jq -e --arg s "$SVC" 'select(.c[$s].cpu_usec != null)' >/dev/null 2>&1 \
  || fail "cannot read the cgroup CPU counter (see sampler-db.err)"
fact --arg t "$TARGET" --arg c "$SVC" '{kind: "target", target: $t, container: $c}'
fact --argjson r "$LOAD_REDIS_RATE" --argjson soak "$LOAD_SOAK_S" --argjson base "$LOAD_BASELINE_S" \
  --argjson cpus "$LOAD_DB_CPUS" --argjson keys "$LOAD_REDIS_KEYS" --argjson poll "$LOAD_REDIS_POLL_S" \
  --arg engine "$LOAD_REDIS_ENGINE" \
  '{kind: "config", harness: "redis", engine: $engine, rate: $r, soak_s: $soak, baseline_s: $base, db_cpus: $cpus,
    keys: $keys, poll_interval_s: $poll}'
log "seeding ${LOAD_REDIS_KEYS} keys (load:s:<n> strings, every tenth load:h:<n> a hash) server-side"
python3 "$SEED" redis --rows "$LOAD_REDIS_KEYS" >"$W/seed.lua"
t0="$(date +%s)"
chunk=100000
for ((a = 1; a <= LOAD_REDIS_KEYS; a += chunk)); do
  b=$(( a + chunk - 1 ))
  [ "$b" -le "$LOAD_REDIS_KEYS" ] || b="$LOAD_REDIS_KEYS"
  n="$(admin_cli EVAL "$(cat "$W/seed.lua")" 0 "$a" "$b" | tr -d '\r')"
  [ "$n" = $(( b - a + 1 )) ] || fail "seed chunk $a..$b wrote '$n' keys"
done
admin_cli BGSAVE >/dev/null || true
DBSIZE="$(admin_cli DBSIZE | tr -d '\r')"
log "seeded in $(( $(date +%s) - t0 )) s: dbsize ${DBSIZE}, used_memory $(info_field memory used_memory_human)"
# The databases holding keys (the dev keyspace's db0 and db1 next to the load keys of db0). Slow-log
# entries record no database, so with more than one, a key's object is a pattern learned in every
# one of them, else `*` (docs/08-engine-capabilities.md, "Redis / Valkey Audit"): the load GETs are
# reads of `*` in `*` here, `load:*:*` being learned in db0 only.
KEYSPACE_DBS="$(admin_cli INFO keyspace | tr -d '\r' | sed -n 's/^\(db[0-9]*\):keys=\([0-9]*\),.*/\1=\2/p' | paste -sd ' ' -)"
log "databases with keys: ${KEYSPACE_DBS:-none}"
fact --arg t "$TARGET" --arg dbs "$KEYSPACE_DBS" '{kind: "keyspace", target: $t, databases: ($dbs | split(" ") | map(select(. != "")))}'
if r="$(python3 "$LOADLIB" quiet --samples "$SAMPLES_DB" --names "$SVC" --below 0.02 --window 10 --timeout 180)"; then
  log "target quiet: $r"
else
  log "WARNING: target still busy after 180 s: $r (the idle baseline absorbs it)"
fi
phase_done seed

# ------------------------------------------------------------------------------ admin, enroll, idle A
log "bootstrapping the administrator, enrolling the agent"
admin_login load-redis
enroll_agent target_agent_password
phase_done enroll
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
wait_online 120 "${TARGET}:${LOAD_REDIS_ENGINE}"
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
log "Discovery scan of ${TARGET} (paced; ${LOAD_SAMPLE_ROWS} keys sampled per pattern, 900 s)"
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
read -r s0 s1 <<<"$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at) FROM jobs WHERE id = '$job_id'")"
[[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of ${TARGET}: no delivery / end time ($status)"
# Objects of a keyspace walk: the keys (`tables`, for the per-object figures; the walk stops at
# redis.max_keys per database, default 100 000).
fact --arg target "$TARGET" --arg status "$status" --argjson t0 "$s0" --argjson t1 "$s1" --argjson keys "$DBSIZE" \
  '{kind: "scan", target: $target, status: $status, t0: $t0, t1: $t1, tables: $keys, rows: $keys}'
log "scan of ${TARGET}: $status in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s"
[ "$status" = succeeded ] || fail "scan of ${TARGET} ended '$status'"
wait_spool_empty "$s1" || log "WARNING: no heartbeat with an empty spool after the scan"
n_findings="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
fact --arg target "$TARGET" --argjson n "$n_findings" '{kind: "findings", target: $target, count: $n}'
log "findings: ${n_findings}; target notes: $(notes_of "$(target_json "$TARGET")")"
phase_done discovery

# ------------------------------------------------------------------------------ workloads
# GETs of 1000 string keys of the scaled keyspace (load_app may read load:* only).
for ((i = 1; i <= 1000; i++)); do
  n=$(( (i * 7919) % LOAD_REDIS_KEYS + 1 ))
  [ $(( n % 10 )) = 0 ] && n=$(( n + 1 ))
  [ "$n" -le "$LOAD_REDIS_KEYS" ] || n=1
  printf 'load:s:%d\n' "$n"
done >"$W/load.keys"
gets() { admin_cli INFO commandstats | tr -d '\r' | sed -n 's/^cmdstat_get:calls=\([0-9]*\),.*/\1/p'; }
run_workload() {
  local phase="$1" dur="$2" t_start rc=0 g0 g1
  g0="$(gets)"
  log "workload ($phase): ${LOAD_REDIS_RATE} GETs/s over ${LOAD_CLIENTS} connections, ${dur} s"
  WL_START="$(now_s)"
  t_start="$WL_START"
  timeout $((dur + 120)) python3 "$SCENARIO" load --port "$PORT" --ca "$T/redis-ca.pem" --user load_app \
    --password-file "$S/target_client_password" --keys-file "$W/load.keys" --rate "$LOAD_REDIS_RATE" \
    --duration "$dur" --clients "$LOAD_CLIENTS" --linger $(( LOAD_REDIS_POLL_S * 3 + 2 )) \
    --out "$W/out/redis-$phase.json" >"$W/out/redis-$phase.stdout" 2>"$W/out/redis-$phase.stderr" || rc=$?
  g1="$(gets)"
  [ "$rc" = 0 ] || { cat "$W/out/redis-$phase.stderr" >&2; fail "the workload ($phase) exited $rc"; }
  # The last command, not the end of the client's linger: the schedule starts 1 s after the start.
  WL_END="$(jq -r --argjson t "$t_start" '$t + 1 + .elapsed_s' "$W/out/redis-$phase.json")"
  fact --arg name "workload_audit_$phase" --argjson t0 "$(jq -n --argjson t "$t_start" '$t + 5')" \
    --argjson t1 "$WL_END" '{kind: "window", name: $name, t0: $t0, t1: $t1}'
  jq -c --arg phase "$phase" --arg t "$TARGET" --argjson rate "$LOAD_REDIS_RATE" --argjson g "$(( ${g1:-0} - ${g0:-0} ))" \
    '{kind: "workload", target: $t, phase: $phase, tool: "redis_scenario", rate: $rate, issued: .commands,
      failed: ((.errors | add) // 0), p95_ms: .service_p95_ms, p99_ms: .latency_ms.p99,
      latency_metric: "service time of a GET (sent to reply, client-measured)",
      schedule_latency_p95_ms: .latency_ms.p95, late_starts: .late_starts, elapsed_s: .elapsed_s,
      server_get_calls: $g}' "$W/out/redis-$phase.json" >>"$FACTS"
  log "workload ($phase): $(tail -n 1 "$FACTS" | jq -c '{issued, failed, p95_ms, schedule_latency_p95_ms, late_starts, server_get_calls}')"
}
run_workload off "$LOAD_BASELINE_S"
phase_done workload-off

log "enabling Audit on ${TARGET} (poll every ${LOAD_REDIS_POLL_S} s)"
enable_audit "$TARGET" "{\"poll_interval_s\":${LOAD_REDIS_POLL_S}}"
sleep 5
phase_done audit-setup
run_workload on "$LOAD_SOAK_S"
SOAK_END="$WL_END"
phase_done workload-on

# ------------------------------------------------------------------------------ drain
events_sql() {
  printf "FROM access_events WHERE agent_id = '%s' AND target_id = '%s' AND db_user = 'load_app' AND action = 'read'" \
    "$AGENT_ID" "$TARGET"
}
want="$(grep '"kind":"workload"' "$FACTS" | jq -s 'map(select(.phase == "on"))[0].issued // 0')"
log "waiting until every GET of the Audit run is stored (${want} expected, at most ${LOAD_DRAIN_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + LOAD_DRAIN_TIMEOUT_S ))
while :; do
  got="$(console_sql "SELECT coalesce(sum(aggregated_count), 0) $(events_sql)")"
  [ "$got" -ge "$want" ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "WARNING: not every GET stored within ${LOAD_DRAIN_TIMEOUT_S} s: ${got}/${want}"
    break
  fi
  sleep 5
done
log "GETs stored: ${got}/${want}"
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
other="$(console_sql "SELECT coalesce(string_agg(coalesce(db_user, CASE WHEN account_not_recorded THEN 'not_recorded' ELSE 'fp' END)
    || ' ' || action || ' ' || aggregated_count, '; '), 'none')
  FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND (db_user IS DISTINCT FROM 'load_app' OR action <> 'read')")"
log "other events of ${TARGET}: ${other}"
log "target notes after the run: $(target_json "$TARGET" | jq -c '[.notes[]? | {code, count}]')"
# Source side: the server's GET calls during the Audit run (INFO commandstats).
src="$(grep '"kind":"workload"' "$FACTS" | jq -s 'map(select(.phase == "on"))[0].server_get_calls // empty')"
if [[ "${src:-}" =~ ^[0-9]+$ ]]; then
  fact --arg t "$TARGET" --argjson n "$src" '{kind: "source", target: $t, statements: $n, rotated_files: 0}'
fi
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
  { echo "# ${LOAD_REDIS_ENGINE} target"; cat "$LOAD_RESULTS_DIR/results.md"; } >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
