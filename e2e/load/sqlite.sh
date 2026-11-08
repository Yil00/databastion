#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Load run of the SQLite targets (ROADMAP P10-D, ADR-0059 decision 10 "Load"; e2e/load/README.md
# "SQLite targets"): the console, the agent and two database files of about LOAD_SQLITE_SIZE_MB
# (default 1024) each, one in WAL mode (held open by sqlite-holder, as an application's idle
# connection) and one in rollback-journal mode (LOAD_SQLITE_ROLLBACK_JOURNAL, default delete,
# declared `rollback_mode: read`), mounted read-only into the agent (e2e/docker-compose.yml +
# docker-compose.sqlite.yml here, project databastion-load-sqlite). SQLite has no server whose CPU
# a scan could cost: what is measured is the impact on a concurrent writer, the application
# (sqlite_writer.py run: LOAD_SQLITE_RATE transactions per second, each one INSERT and one UPDATE),
# in each mode, with its busy timeout at 0 and at 5 s, without then during a paced Discovery scan
# (the agent's default 1 % duty cycle):
#   - the writer's commit latency (p50, p95, p99), its SQLITE_BUSY count and its failed commits;
#   - the -wal size (peak, end: checkpoint starvation);
#   - the CPU share of one core and the memory of the agent's container (the agent and its reader
#     processes) during each scan.
# The checks and limits are sqliteload.py's (the ADR's proposed criteria). Depends on the console
# listing `engine.sqlite` (P10-E): without it the agent holds the targets' items and the run stops
# at its first wait.
#
# Requires: docker (compose v2.24+), openssl, curl, jq, python3. Every secret is generated at run time,
# registered, masked under GitHub Actions, redacted from the collected logs and removed on exit.
# Nothing listens outside 127.0.0.1.
# shellcheck disable=SC2016 # jq programs (fact, jq -c) are single-quoted on purpose, file-wide
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="$HERE/.."
SQLITELOAD="$HERE/sqliteload.py"
LOADLIB="$HERE/loadlib.py"
PROJECT="databastion-load-sqlite"
LOG_TAG="load-sqlite"  # read by ../lib.sh

# ------------------------------------------------------------------------------ settings
export E2E_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs-sqlite}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results-sqlite}"
LOAD_IDLE_S="${LOAD_IDLE_S:-30}"
LOAD_SQLITE_SIZE_MB="${LOAD_SQLITE_SIZE_MB:-1024}"
LOAD_SQLITE_TABLES="${LOAD_SQLITE_TABLES:-8}"
LOAD_SQLITE_RATE="${LOAD_SQLITE_RATE:-200}"            # writer transactions per second
LOAD_SQLITE_BASELINE_S="${LOAD_SQLITE_BASELINE_S:-60}"  # each baseline run, without scan
LOAD_SQLITE_ROLLBACK_JOURNAL="${LOAD_SQLITE_ROLLBACK_JOURNAL:-delete}"
LOAD_SAMPLE_ROWS="${LOAD_SAMPLE_ROWS:-200}"
LOAD_SCAN_TIMEOUT_S="${LOAD_SCAN_TIMEOUT_S:-900}"
for v in LOAD_IDLE_S LOAD_SQLITE_SIZE_MB LOAD_SQLITE_TABLES LOAD_SQLITE_RATE LOAD_SQLITE_BASELINE_S \
    LOAD_SAMPLE_ROWS LOAD_SCAN_TIMEOUT_S E2E_HTTPS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
case "$LOAD_SQLITE_ROLLBACK_JOURNAL" in
  delete | truncate | persist) ;;
  *) echo "LOAD_SQLITE_ROLLBACK_JOURNAL must be delete, truncate or persist" >&2; exit 2 ;;
esac
[ "$LOAD_SQLITE_SIZE_MB" -le 4096 ] || { echo "LOAD_SQLITE_SIZE_MB must be at most 4096" >&2; exit 2; }
DATA=/srv/sqlite/data
# mode, target id, file, journal mode, rollback_mode
TARGETS=("wal load-wal load-wal.db wal skip"
  "rollback load-rollback load-rollback.db ${LOAD_SQLITE_ROLLBACK_JOURNAL} read")

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load-sqlite.XXXXXX")"
W="$LOAD_WORK_DIR"
export E2E_WORK_DIR="$W"
E2E_LOG_DIR="$LOAD_LOG_DIR"
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/out"
# The only host directory a container writes to: the writer's records (uid 10020), inside the
# private 0700 run directory.
mkdir -m 0777 "$W/writer"
COMPOSE_ARGS=(-p "$PROJECT" -f "$E2E/docker-compose.yml" -f "$HERE/docker-compose.sqlite.yml")
# shellcheck source=../lib.sh
. "$E2E/lib.sh"
FACTS="$W/out/facts.jsonl"
SAMPLES_AGENT="$W/out/samples-agent.jsonl"
: >"$FACTS"
fact() { jq -nc "$@" >>"$FACTS"; }
writer() { timeout "$1" docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps sqlite-writer "${@:2}"; }

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
  dump_logs db migrate web worker proxy sqlite-holder agent
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  cp -f "$W"/out/*.jsonl "$W"/writer/*.json "$LOAD_LOG_DIR/" 2>/dev/null
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
test_ca "SQLite load"
{
  cat <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  max_scan_duration_s: ${LOAD_SCAN_TIMEOUT_S}
targets:
EOF
  for spec in "${TARGETS[@]}"; do
    read -r _ id file _ rb <<<"$spec"
    printf '  - id: %s\n    engine: sqlite\n    sqlite:\n      path: %s/%s\n      rollback_mode: %s\n' \
      "$id" "$DATA" "$file" "$rb"
  done
} >"$W/agent/agent.yaml"
chmod 0644 "$W/agent/agent.yaml"

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE
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
timeout 600 docker compose "${COMPOSE_ARGS[@]}" --profile tools pull --quiet sqlite-writer sqlite-files-init
phase_done build

log "starting the console"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy
start_console
phase_done start

# ------------------------------------------------------------------------------ seed
fact --argjson r "$LOAD_SQLITE_RATE" --argjson base "$LOAD_SQLITE_BASELINE_S" --argjson mb "$LOAD_SQLITE_SIZE_MB" \
  --argjson tables "$LOAD_SQLITE_TABLES" --argjson rows "$LOAD_SAMPLE_ROWS" --arg rj "$LOAD_SQLITE_ROLLBACK_JOURNAL" \
  '{kind: "config", harness: "sqlite", rate: $r, baseline_s: $base, size_mb: $mb, tables: $tables,
    sample_rows: $rows, rollback_journal: $rj, duty_cycle_percent: 1, busy_timeouts_ms: [0, 5000]}'
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps sqlite-files-init >&2 \
  || fail "sqlite-files-init failed"
for spec in "${TARGETS[@]}"; do
  read -r mode _ file jm _ <<<"$spec"
  log "seeding ${file} (${jm}, about ${LOAD_SQLITE_SIZE_MB} MiB in ${LOAD_SQLITE_TABLES} tables)"
  out="$(writer 1800 seed --out "$DATA/$file" --size-mb "$LOAD_SQLITE_SIZE_MB" --tables "$LOAD_SQLITE_TABLES" \
    --journal-mode "$jm")" || fail "seeding ${file} failed"
  jq -c --arg m "$mode" '{kind: "seed", mode: $m} + .' <<<"$out" >>"$FACTS"
  log "seeded: $(tail -n 1 "$FACTS")"
done
timeout 120 docker compose "${COMPOSE_ARGS[@]}" up -d --wait --wait-timeout 120 sqlite-holder
phase_done seed

# ------------------------------------------------------------------------------ enroll, agent, idle
log "bootstrapping the administrator, enrolling the agent"
admin_login load-sqlite
# shellcheck disable=SC2119 # no target secret: the agent's only secret is its own identity
enroll_agent
log "starting databastion-agent run"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
AGENT_CID="$(compose ps -q agent)"
python3 "$LOADLIB" sample --out "$SAMPLES_AGENT" --interval 1 "agent=${AGENT_CID}" 2>"$W/out/sampler-agent.err" &
BG_PIDS+=("$!")
specs=()
for spec in "${TARGETS[@]}"; do read -r _ id _ <<<"$spec"; specs+=("${id}:sqlite"); done
# P10-E: the console lists engine.sqlite.
wait_online 120 "${specs[@]}"
for spec in "${TARGETS[@]}"; do
  read -r _ id _ <<<"$spec"
  log "target ${id}: $(target_summary "$(target_json "$id")")"
done
inspect_scan "with the agent"
log "idle baseline with the agent running, no job (${LOAD_IDLE_S} s)"
t0="$(now_s)"
sleep "$LOAD_IDLE_S"
fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_agent", t0: $t0, t1: $t1}'
phase_done agent

# ------------------------------------------------------------------------------ workloads
# workload NAME FILE BUSY DURATION [STOP]: one writer run; its summary into writer/NAME.json.
workload() {
  local name="$1" file="$2" busy="$3" dur="$4" stop="${5:-}"
  local -a extra=()
  [ -n "$stop" ] && extra=(--stop-file "/out/$stop")
  writer $(( dur + 120 )) run --db "$DATA/$file" --rate "$LOAD_SQLITE_RATE" --duration "$dur" \
    --busy-timeout-ms "$busy" --records "/out/$name.csv" --wal "/out/$name-wal.csv" "${extra[@]}" \
    >"$W/writer/$name.json"
}
printf '{"sample_rows":%d,"max_duration_s":%d,"statement_timeout_ms":5000}' "$LOAD_SAMPLE_ROWS" "$LOAD_SCAN_TIMEOUT_S" \
  >"$W/scan-req.json"
for spec in "${TARGETS[@]}"; do
  read -r mode id file _ <<<"$spec"
  for busy in 0 5000; do
    name="${mode}-b${busy}"
    log "${name}: baseline, ${LOAD_SQLITE_RATE} transactions/s for ${LOAD_SQLITE_BASELINE_S} s, no scan"
    workload "$name-base" "$file" "$busy" "$LOAD_SQLITE_BASELINE_S" || fail "the writer (${name}, baseline) failed"
    python3 "$SQLITELOAD" window --records "$W/writer/$name-base.csv" --wal "$W/writer/$name-base-wal.csv" \
      --summary "$W/writer/$name-base.json" --mode "$mode" --busy-timeout-ms "$busy" --phase baseline >>"$FACTS"
    log "${name}: baseline $(tail -n 1 "$FACTS" | jq -c '.summary | {issued, committed, busy, failed}') $(tail -n 1 "$FACTS" | jq -c '.stats | {p95_ms, p99_ms, wal_peak_bytes}')"
    log "${name}: the writer again, with a paced Discovery scan of ${id}"
    workload "$name-scan" "$file" "$busy" $(( LOAD_SCAN_TIMEOUT_S + 60 )) "stop-$name" &
    wpid=$!
    sleep 5
    r="$(api POST "/api/agents/${AGENT_ID}/targets/${id}/scan" "$W/scan-req.json")"
    [ "$(status_of "$r")" = 202 ] || fail "scan request (${id}): HTTP $(status_of "$r")"
    job_id="$(body_of "$r" | jq -r '.job_id')"
    [[ "$job_id" =~ $UUID_RE ]] || fail "scan request (${id}): no job id"
    deadline=$(( $(date +%s) + LOAD_SCAN_TIMEOUT_S + 60 ))
    while :; do
      st="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")"
      case "$st" in succeeded | failed | cancelled | expired) break ;; esac
      [ "$(date +%s)" -lt "$deadline" ] || fail "scan of ${id} not finished in time ($st)"
      sleep 1
    done
    sleep 3
    touch "$W/writer/stop-$name"
    wait "$wpid" || fail "the writer (${name}, scan) failed"
    read -r s0 s1 <<<"$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at) FROM jobs WHERE id = '$job_id'")"
    [[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of ${id}: no delivery / end time ($st)"
    progress="$(console_sql "SELECT coalesce(progress, '{}'::jsonb) FROM jobs WHERE id = '$job_id'")"
    n_findings="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${id}'")"
    fact --arg m "$mode" --argjson b "$busy" --arg t "$id" --arg st "$st" --argjson t0 "$s0" --argjson t1 "$s1" \
      --argjson p "$progress" --argjson n "$n_findings" \
      '{kind: "scan", mode: $m, busy_timeout_ms: $b, target: $t, status: $st, t0: $t0, t1: $t1, progress: $p, findings: $n}'
    python3 "$SQLITELOAD" window --records "$W/writer/$name-scan.csv" --wal "$W/writer/$name-scan-wal.csv" \
      --summary "$W/writer/$name-scan.json" --mode "$mode" --busy-timeout-ms "$busy" --phase scan \
      --t0 "$s0" --t1 "$s1" >>"$FACTS"
    log "${name}: scan ${st} in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s, coverage ${progress}; writer during the scan $(tail -n 1 "$FACTS" | jq -c '.stats | {transactions, busy, failed, p95_ms, p99_ms, wal_peak_bytes}')"
    phase_done "$name"
  done
done

# ------------------------------------------------------------------------------ report
lost="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
  | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|rejected batch items|unreadable spool file' || true)"
fact --argjson n "$lost" '{kind: "agent_log", lost: $n}'
sleep 2
stop_background
log "computing the results"
set +e
python3 "$SQLITELOAD" report --facts "$FACTS" --samples "$SAMPLES_AGENT" --out "$LOAD_RESULTS_DIR"
rc=$?
set -e
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$LOAD_RESULTS_DIR/results.md" ]; then
  cat "$LOAD_RESULTS_DIR/results.md" >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
