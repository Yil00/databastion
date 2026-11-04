#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Load run of the Firebird target (ROADMAP P10-D and P10-B; ADR-0060 decision 9 "End to end and
# load", R7 / 8g, R25 / 3m, R41 items 2 and 9, the implementation notes of 2026-11-01; RELEASE.md
# "Firebird Audit: the 10 000-object schema measurement"; e2e/load/README.md "Firebird target").
# The console, the agent in its container and Firebird 5.0.4 (4.0.7 with LOAD_FIREBIRD_VERSION), in
# the e2e-firebird layout (e2e/docker-compose.yml + e2e/docker-compose.firebird.yml + the run's
# hostid.yml + docker-compose.firebird.yml here, project databastion-load-firebird): the agent in the
# server's network and pid namespaces, the host's identity files declared and mounted read-only, the
# log volume's named-user ACLs, max_log_size = 0. Two parts (LOAD_FIREBIRD_PARTS):
#
# `load` (database crm from seed.py firebird: LOAD_FB_TABLES tables, LOAD_FB_ROWS rows, the 3m objects):
#   1. Discovery: the server's CPU added by a paced scan (< 2 % of its LOAD_DB_CPUS, run.sh's method);
#   2. Audit under load: LOAD_FB_RATE point reads per second for LOAD_SOAK_S seconds (fbload.py
#      workload, client-side latency), without then with Audit: every statement an event (the
#      workload principal's events against its statement records in the trace log), nothing
#      dropped, the agent's own records never reported, the agent's CPU and peak RSS, no added p95;
#   3. the checkpoint and ledger I/O (bytes written, writes, sizes over the run) from samples of the
#      agent's state volume;
#   4. 8g: LOAD_FB_BURSTS bursts of LOAD_FB_BURST_SIZE concurrent attaches that open the database:
#      the largest id inversion and the latest late record within 256 ids and 10 s (R7), and the
#      agent's ambiguous-record count unchanged;
#   5. 3m: per-row statements under concurrent sessions, open transactions with pending groups
#      within and past the group budget, block-ful-only groups held past 10 s, an agent restart
#      during a pending group: statements accounted for, the ambiguous-record count (report-only
#      past a bound).
# `schema` (database crm from seed.py firebird-schema, at least 10 000 objects):
#   6. the dependent-set read (R41 item 2): per read, the server-side time and the rows fetched, from
#      the trace log, against the 3 s statement timeout of check() and the 65 536-row bound; complete
#      or cut (the agent's warning);
#   7. the always-reported events of a per-category workload (plain, expression-index, check,
#      computed-column tables, views, procedures) with the complete set, with an invalidated set (a
#      DDL statement) and with a cut set (procedures added past 65 536 dependency rows).
# The report is loadlib.py's (run.sh's checks and format, with a Firebird section).
#
# Requires: docker (compose v2.24+), openssl, curl, jq, python3, sudo -n when not root (the
# root-owned copies of the configuration, as e2e/firebird.sh). Every secret is generated at run time,
# registered, masked under GitHub Actions, redacted from the collected logs and removed on exit; the
# trace log is never copied out (it holds the statement texts): fbload.py reads it in place and
# prints counts only. Nothing listens outside 127.0.0.1.
# shellcheck disable=SC2016 # jq programs and container scripts are single-quoted on purpose, file-wide
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="$HERE/.."
LOADLIB="$HERE/loadlib.py"
SEED="$HERE/seed.py"
HOSTID="$E2E/firebird_hostid.py"
PROJECT="databastion-load-firebird"
LOG_TAG="load-firebird"  # read by ../lib.sh

# ------------------------------------------------------------------------------ settings
export E2E_HTTPS_PORT="${LOAD_HTTPS_PORT:-8543}"
export LOAD_DB_CPUS="${LOAD_DB_CPUS:-2}"
LOAD_LOG_DIR="${LOAD_LOG_DIR:-$HERE/.logs-firebird}"
LOAD_RESULTS_DIR="${LOAD_RESULTS_DIR:-$HERE/.results-firebird}"
LOAD_FIREBIRD_VERSION="${LOAD_FIREBIRD_VERSION:-5.0.4}"
LOAD_FIREBIRD_PARTS="${LOAD_FIREBIRD_PARTS:-load,schema}"
# The pins of dev/firebird/it.sh (checked below): 5.0.4 is also the dev and e2e pin.
case "$LOAD_FIREBIRD_VERSION" in
  5.0.4) FB_DIGEST=sha256:1529560400fc7847f015c57fc9d70729c44d9a9d8f9000df19c5ce1950b4c202 ;;
  4.0.7) FB_DIGEST=sha256:456aeb748f6f70a4adbc910a2adc56f4d43270bcdf12808c47ca6e9603c6b17e ;;
  *) echo "LOAD_FIREBIRD_VERSION must be 5.0.4 or 4.0.7" >&2; exit 2 ;;
esac
grep -qF "firebirdsql/firebird@${FB_DIGEST}" "$HERE/../../dev/firebird/it.sh" \
  || { echo "the Firebird ${LOAD_FIREBIRD_VERSION} pin of firebird.sh must be the one of dev/firebird/it.sh" >&2; exit 1; }
export LOAD_FB_IMAGE="firebirdsql/firebird:${LOAD_FIREBIRD_VERSION}@${FB_DIGEST}"
case ",$LOAD_FIREBIRD_PARTS," in
  ,load, | ,schema, | ,load,schema, | ,schema,load,) ;;
  *) echo "LOAD_FIREBIRD_PARTS must be load, schema or load,schema" >&2; exit 2 ;;
esac
part() { [[ ",$LOAD_FIREBIRD_PARTS," == *",$1,"* ]]; }
LOAD_IDLE_S="${LOAD_IDLE_S:-45}"
LOAD_FB_TABLES="${LOAD_FB_TABLES:-200}"
LOAD_FB_ROWS="${LOAD_FB_ROWS:-500000}"
LOAD_FB_RATE="${LOAD_FB_RATE:-300}"
LOAD_CLIENTS="${LOAD_CLIENTS:-4}"
LOAD_WORKLOAD_TABLES="${LOAD_WORKLOAD_TABLES:-40}"
LOAD_SAMPLE_ROWS="${LOAD_SAMPLE_ROWS:-200}"
LOAD_WARMUP_S="${LOAD_WARMUP_S:-20}"
LOAD_BASELINE_S="${LOAD_BASELINE_S:-120}"
LOAD_SOAK_S="${LOAD_SOAK_S:-600}"
LOAD_DRAIN_TIMEOUT_S="${LOAD_DRAIN_TIMEOUT_S:-300}"
LOAD_SAMPLE_INTERVAL="${LOAD_SAMPLE_INTERVAL:-0.5}"
LOAD_FB_BURSTS="${LOAD_FB_BURSTS:-5}"
LOAD_FB_BURST_SIZE="${LOAD_FB_BURST_SIZE:-256}"
LOAD_FB_SCHEMA_SCALE="${LOAD_FB_SCHEMA_SCALE:-1}"
LOAD_FB_SCHEMA_RATE="${LOAD_FB_SCHEMA_RATE:-10}"      # per category principal, statements/s
LOAD_FB_SCHEMA_PHASE_S="${LOAD_FB_SCHEMA_PHASE_S:-120}"
for v in LOAD_IDLE_S LOAD_FB_TABLES LOAD_FB_ROWS LOAD_FB_RATE LOAD_CLIENTS LOAD_WORKLOAD_TABLES LOAD_SAMPLE_ROWS \
    LOAD_WARMUP_S LOAD_BASELINE_S LOAD_SOAK_S LOAD_DRAIN_TIMEOUT_S LOAD_FB_BURSTS LOAD_FB_BURST_SIZE \
    LOAD_FB_SCHEMA_RATE LOAD_FB_SCHEMA_PHASE_S E2E_HTTPS_PORT; do
  [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be a positive integer" >&2; exit 2; }
done
[ "$LOAD_SOAK_S" -le 1800 ] || { echo "LOAD_SOAK_S must be at most 1800 seconds" >&2; exit 2; }
[ "$LOAD_FB_RATE" -le 2000 ] || { echo "LOAD_FB_RATE must be at most 2000 statements per second" >&2; exit 2; }
[ "$LOAD_FB_BURST_SIZE" -le 1024 ] || { echo "LOAD_FB_BURST_SIZE must be at most 1024" >&2; exit 2; }
[[ "$LOAD_FB_SCHEMA_SCALE" =~ ^[0-4](\.[0-9]+)?$ ]] || { echo "LOAD_FB_SCHEMA_SCALE must be a number from 0.1 to 4" >&2; exit 2; }
TARGET="fb-load"
SERVER_UID=84
AGENT_UID=10001
HOST_DIR=/run/databastion/host
FB_DB=/var/lib/firebird/data/crm.fdb
FB_LOG=/var/lib/firebird/audit/audit.log
SPOOL_TIMEOUT_S=120
EVENTS_TIMEOUT_S=180
CLIENT_PW=/run/secrets/target_client_password
SYSDBA_PW=/run/secrets/target_fb_sysdba_password

umask 077
LOAD_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-load-firebird.XXXXXX")"
W="$LOAD_WORK_DIR"
export E2E_WORK_DIR="$W"
E2E_LOG_DIR="$LOAD_LOG_DIR"
CENSUS_OUT_DIR="$LOAD_RESULTS_DIR"  # read by ../lib.sh (print_census)
mkdir -p "$LOAD_LOG_DIR" "$LOAD_RESULTS_DIR" "$W/out" "$W/load/client"
chmod 0755 "$W/load" "$W/load/client"
HOSTID_YML="$W/hostid.yml"
: >"$HOSTID_YML"
COMPOSE_ARGS=(-p "$PROJECT" -f "$E2E/docker-compose.yml" -f "$E2E/docker-compose.firebird.yml" -f "$HOSTID_YML"
  -f "$HERE/docker-compose.firebird.yml")
# shellcheck source=../lib.sh
. "$E2E/lib.sh"
FACTS="$W/out/facts.jsonl"
HEARTBEATS="$W/out/heartbeats.jsonl"
SAMPLES_DB="$W/out/samples-db.jsonl"
SAMPLES_AGENT="$W/out/samples-agent.jsonl"
STATE_SAMPLES="$W/out/state-samples.jsonl"
: >"$FACTS"
: >"$HEARTBEATS"
fact() { jq -nc "$@" >>"$FACTS"; }
STATE_SAMPLER="${PROJECT}-state-sampler"

BG_PIDS=()
stop_background() {
  local pid
  for pid in "${BG_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${BG_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  BG_PIDS=()
}
HOSTID_FP=""
host_fingerprints() {
  local f
  for f in "${HOST_FILES[@]}"; do
    printf '%s %s\n' "$(stat -L -c '%i %a %u %g %Y' -- "$f")" "$(sha256sum -- "$f" | cut -d' ' -f1)"
  done
}
cleanup() {
  local status=$? canary_dir="$W/canary-pattern" canary_hits leaked line d
  set +e
  stop_background
  docker rm -f "$STATE_SAMPLER" >/dev/null 2>&1
  phase_done exit
  log "collecting logs into $LOAD_LOG_DIR"
  dump_logs db migrate web worker proxy firebird-audit-init firebird agent
  compose ps -a >"$LOAD_LOG_DIR/ps.txt" 2>&1
  print_census "load-firebird"
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
  summary_append "$LOAD_RESULTS_DIR"/census-*.md
  log "tearing down"
  timeout 180 docker compose "${COMPOSE_ARGS[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1
  if [ -s "$HOSTID_FP" ] && ! host_fingerprints | cmp -s - "$HOSTID_FP"; then
    log "FAIL: a host identity file changed during the run"
    status=1
  fi
  rm -rf "$W" 2>/dev/null
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ------------------------------------------------------------------------------ preconditions
# As e2e/firebird.sh (R52 item 2): the host's identity files qualify, or the run fails (never
# edited). No collision step here: only the server's and the agent's uids.
log "preconditions: the host's identity files (uids ${SERVER_UID} and ${AGENT_UID})"
timeout 60 python3 -I "$HOSTID" check --uid "$SERVER_UID" --uid "$AGENT_UID" --list "$W/hostid.list" >&2 \
  || fail "the host's identity files do not meet the preconditions of R52 item 2 (above)"
mapfile -t HOST_FILES <"$W/hostid.list"
HOSTID_FP="$W/hostid.fingerprints"
host_fingerprints >"$HOSTID_FP"
root_copy() {
  if [ "$(id -u)" = 0 ]; then install -o 0 -g 0 -m 0644 "$1" "$2"
  else timeout 30 sudo -n install -o 0 -g 0 -m 0644 "$1" "$2"; fi
}
mkdir -p "$W/firebird"
chmod 0755 "$W/firebird"
for f in firebird.conf fbtrace.conf; do
  root_copy "$HERE/../../dev/firebird/$f" "$W/firebird/$f" || fail "cannot make the root-owned copy of $f"
done
phase_done preconditions

# ------------------------------------------------------------------------------ secrets, CA, files
console_secrets
put_secret target_fb_sysdba_password "$(rand_password 20)"
put_secret target_agent_password "$(rand_password 20)"
put_secret target_client_password "$(rand_password 20)"
test_ca "Firebird load"
cat >"$W/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
targets:
  - id: ${TARGET}
    engine: firebird
    host: 127.0.0.1
    port: 3050
    account: DATABASTION_AGENT
    secret:
      file: /run/databastion-secrets/target_agent_password
    firebird:
      peer_uid: ${SERVER_UID}
      databases:
        - name: crm
          attach: ${FB_DB}
      audit:
        root: /opt/firebird
        firebird_conf: /opt/firebird/firebird.conf
        trace_config: /databastion/fbtrace.conf
        log: ${FB_LOG}
        databases_conf: /opt/firebird/databases.conf
        host_identity:
EOF
for f in "${HOST_FILES[@]}"; do
  n="$(basename "$f")"
  echo "          ${n%.conf}: ${HOST_DIR}/${n}" >>"$W/agent/agent.yaml"
done
chmod 0644 "$W/agent/agent.yaml"
{
  printf 'services:\n  agent:\n    volumes:\n'
  for f in "${HOST_FILES[@]}"; do
    printf '      - type: bind\n        source: %s\n        target: %s/%s\n        read_only: true\n        bind:\n          create_host_path: false\n' \
      "$f" "$HOST_DIR" "$(basename "$f")"
  done
} >"$HOSTID_YML"

# fbc ARGS...: fbload.py in a one-shot fb-client container (the server's network namespace).
fbc() {
  timeout "${FBC_TIMEOUT:-900}" docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps fb-client "$@"
}
# fbc_bg NAME ARGS...: the same, in the background, its JSON line into $W/out/NAME.json.
fbc_bg() {
  local name="$1"
  shift
  fbc "$@" >"$W/out/$name.json" 2>"$W/out/$name.err" &
}
# trace_ts EPOCH: a header time of the trace log (the server's clock, UTC in the image).
trace_ts() { date -u -d "@$1" +'%Y-%m-%dT%H:%M:%S.0000'; }
# checked_count: the agent's "Firebird checked" lines of the target so far.
checked_count() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix agent 2>/dev/null \
    | grep -F '"Firebird checked"' | grep -cF "\"target_id\":\"${TARGET}\"" || true
}
# wait_checks N: until N more checks of the target than now (at most 240 s).
wait_checks() {
  local n0 deadline
  n0="$(checked_count)"
  deadline=$(( $(date +%s) + 240 ))
  until [ "$(checked_count)" -ge $(( n0 + $1 )) ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "fewer than $1 new check(s) of ${TARGET} within 240 s"
    sleep 2
  done
}
# status_json: the target's status after a check that started at least 15 s after now (the stream
# has read the records written before now): {level, source, notes: [{code, count}]}.
status_json() {
  sleep 15
  wait_checks 1
  sleep 12
  target_json "$TARGET" | jq -c '{level: .auditLevel, source: .auditSource, notes: [.notes[]? | {code, count}]}'
}
ambiguous_of() { jq -r '[.notes[] | select(.code == "audit.log_records_ambiguous") | .count // 0] | add // 0' <<<"$1"; }
# events_of USER T0 T1: {events, statements, star_events, star_statements} of a principal's events
# whose time lies in [T0 - 2 s, T1 + 2 s].
events_of() {
  console_sql "SELECT json_build_object('events', count(*), 'statements', coalesce(sum(aggregated_count), 0),
      'star_events', count(*) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb),
      'star_statements', coalesce(sum(aggregated_count) FILTER (WHERE objects @> '[{\"object\": \"*\"}]'::jsonb), 0))
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user = '$1'
      AND coalesce(ts_last, ts) >= to_timestamp($2) - interval '2 seconds' AND ts <= to_timestamp($3) + interval '2 seconds'"
}
# wait_events USER T0 T1 WANT: until the principal's statements in the window reach WANT (at most
# EVENTS_TIMEOUT_S), then prints events_of.
wait_events() {
  local deadline got
  deadline=$(( $(date +%s) + EVENTS_TIMEOUT_S ))
  while :; do
    got="$(events_of "$1" "$2" "$3")"
    [ "$(jq -r .statements <<<"$got")" -ge "$4" ] && break
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 5
  done
  printf '%s\n' "$got"
}
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
# start_firebird SEED_FILE: the server from a fresh data, root and log volume, its database crm
# created from SEED_FILE at the first start (embedded, before the server listens; the log emptied).
start_firebird() {
  cp -f "$1" "$W/load/seed.sql"
  chmod 0644 "$W/load/seed.sql"
  local t0 deadline
  t0="$(date +%s)"
  timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d firebird
  deadline=$(( $(date +%s) + 900 ))
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q firebird)" 2>/dev/null)" = healthy ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "firebird not healthy within 900 s"
    sleep 3
  done
  [ "$(compose ps -a --format '{{.ExitCode}}' firebird-audit-init)" = "0" ] || fail "firebird-audit-init did not succeed"
  FB_CID="$(compose ps -q firebird)"
  docker inspect "$FB_CID" --format '{{json .Config.Env}}' | jq -e 'any(test("PASSWORD")) | not' >/dev/null \
    || fail "a password in the firebird container's environment"
  log "firebird ${LOAD_FIREBIRD_VERSION}: healthy $(( $(date +%s) - t0 )) s after its start (seed and accounts included)"
}
# check_layout: the agent's container in the layout of e2e-firebird (R52 item 2, R50).
check_layout() {
  local cid id
  cid="$(compose ps -q agent)"
  docker inspect "$cid" | jq -e --arg fb "$FB_CID" '.[0] as $c
      | $c.HostConfig.NetworkMode == "container:" + $fb and $c.HostConfig.PidMode == "container:" + $fb
      and ($c.HostConfig.CapDrop | index("ALL")) != null and $c.HostConfig.ReadonlyRootfs
      and ([$c.Mounts[] | select(.Destination == "/var/lib/firebird/data")] | length) == 0
      and all($c.Mounts[] | select(.Destination | startswith("/run/databastion/host/")); .RW == false)' >/dev/null \
    || fail "the agent's container is not in the e2e-firebird layout"
  for id in $(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}"); do
    docker inspect "$id" | jq -e --arg fb "$FB_CID" '.[0].HostConfig.NetworkMode != "container:" + $fb
        or ((.[0].HostConfig.CapDrop // []) | index("ALL")) != null' >/dev/null \
      || fail "a container of the server's network namespace keeps capabilities"
  done
}
# wait_partial TIMEOUT: until the target is Partial (firebird_audit_trace); records the level.
wait_partial() {
  local deadline t
  deadline=$(( $(date +%s) + $1 ))
  while :; do
    t="$(target_json "$TARGET")"
    if jq -e '.auditLevel == "partial" and .auditSource == "firebird_audit_trace"' <<<"$t" >/dev/null; then
      log "${TARGET}: Partial ($(notes_of "$t"))"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      log "WARNING: ${TARGET} not Partial within $1 s: $(target_summary "$t")"
      return 1
    fi
    sleep 3
  done
}

# ------------------------------------------------------------------------------ build + start
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE LOAD_FB_CLIENT_IMAGE
fi
IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}"
  databastion-dev/firebird-acl-init:5.0.4 "${LOAD_FB_CLIENT_IMAGE:-databastion-load/firebird-client:ci}")
if [ "${LOAD_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "LOAD_SKIP_BUILD=1 but image $img is missing"
  done
  log "LOAD_SKIP_BUILD=1: using the existing images"
else
  log "building images (web, agent, firebird-audit-init, fb-client)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" --profile tools build web agent firebird-audit-init fb-client
fi
phase_done build

log "seed plan: $(part load && echo "load (${LOAD_FB_TABLES} tables, ${LOAD_FB_ROWS} rows)") $(part schema && echo "schema (scale ${LOAD_FB_SCHEMA_SCALE})")"
python3 "$SEED" firebird --tables "$LOAD_FB_TABLES" --rows "$LOAD_FB_ROWS" >"$W/seed-load.sql"
python3 "$SEED" firebird-workload --tables "$LOAD_FB_TABLES" --rows "$LOAD_FB_ROWS" \
  --workload-tables "$LOAD_WORKLOAD_TABLES" >"$W/load/client/workload.tsv"
python3 "$SEED" firebird-schema --scale "$LOAD_FB_SCHEMA_SCALE" >"$W/seed-schema.sql"
python3 "$SEED" firebird-schema-workload --scale "$LOAD_FB_SCHEMA_SCALE" >"$W/schema-workload.json"
python3 "$SEED" firebird-schema-counts --scale "$LOAD_FB_SCHEMA_SCALE" >"$W/schema-counts.json"
for u in $(jq -r 'keys[]' "$W/schema-workload.json"); do
  jq -r --arg u "$u" '.[$u][] | "100\t" + .' "$W/schema-workload.json" >"$W/load/client/schema-$u.tsv"
done
chmod 0644 "$W"/load/client/*

log "starting the console"
start_console
if part load; then FIRST_SEED="$W/seed-load.sql"; else FIRST_SEED="$W/seed-schema.sql"; fi
start_firebird "$FIRST_SEED"
version="$(FBC_TIMEOUT=60 fbc sql --user SYSDBA --password-file "$SYSDBA_PW" \
  --statement "SELECT RDB\$GET_CONTEXT('SYSTEM', 'ENGINE_VERSION') FROM RDB\$DATABASE")" || fail "cannot read the server version"
log "firebird engine version ${version}"
[ "$version" = "$LOAD_FIREBIRD_VERSION" ] || fail "the server is ${version}, not ${LOAD_FIREBIRD_VERSION}"
phase_done start

# ------------------------------------------------------------------------------ sampler, enroll
declare -A CID=()
CID[firebird]="$FB_CID"
python3 "$LOADLIB" sample --out "$SAMPLES_DB" --interval "$LOAD_SAMPLE_INTERVAL" "firebird=${FB_CID}" \
  2>"$W/out/sampler-db.err" &
SAMPLER_DB_PID=$!
BG_PIDS+=("$SAMPLER_DB_PID")
sleep 3
head -n -1 "$SAMPLES_DB" | jq -e 'select(.c.firebird.cpu_usec != null)' >/dev/null 2>&1 \
  || fail "cannot read the cgroup CPU counter (see sampler-db.err)"
fact --arg t "$TARGET" '{kind: "target", target: $t, container: "firebird"}'
fact --argjson r "$LOAD_FB_RATE" --argjson soak "$LOAD_SOAK_S" --argjson base "$LOAD_BASELINE_S" \
  --argjson cpus "$LOAD_DB_CPUS" --argjson tables "$LOAD_FB_TABLES" --argjson rows "$LOAD_FB_ROWS" \
  --arg version "$LOAD_FIREBIRD_VERSION" --arg parts "$LOAD_FIREBIRD_PARTS" --argjson bursts "$LOAD_FB_BURSTS" \
  --argjson burst "$LOAD_FB_BURST_SIZE" --arg scale "$LOAD_FB_SCHEMA_SCALE" \
  '{kind: "config", harness: "firebird", rate: $r, soak_s: $soak, baseline_s: $base, db_cpus: $cpus,
    tables: $tables, rows: $rows, firebird_version: $version, parts: $parts, bursts: $bursts,
    burst_size: $burst, schema_scale: $scale}'
admin_login load-firebird
enroll_agent target_agent_password
# The heartbeats as the console stored them, every 10 s (spool, metrics).
(
  while :; do
    console_sql "SELECT json_build_object('t', extract(epoch from now()), 'last_seen', extract(epoch from last_seen_at),
      'spool', spool, 'metrics', metrics) FROM agents WHERE id = '${AGENT_ID}'" >>"$HEARTBEATS" 2>/dev/null || true
    sleep 10
  done
) &
BG_PIDS+=("$!")
phase_done enroll

start_agent() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
  CID[agent]="$(compose ps -q agent)"
  check_layout
  wait_online 180 "${TARGET}:firebird"
}

# ============================================================================== part 1: load
if part load; then
  if r="$(python3 "$LOADLIB" quiet --samples "$SAMPLES_DB" --names firebird --below 0.05 --window 10 --timeout 120)"; then
    log "target quiet: $r"
  fi
  log "idle baseline without the agent (${LOAD_IDLE_S} s)"
  t0="$(now_s)"; sleep "$LOAD_IDLE_S"
  fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_no_agent", t0: $t0, t1: $t1}'
  start_agent
  python3 "$LOADLIB" sample --out "$SAMPLES_AGENT" --interval 1 "agent=${CID[agent]}" 2>"$W/out/sampler-agent.err" &
  BG_PIDS+=("$!")
  log "agent online: $(target_summary "$(target_json "$TARGET")")"
  log "idle baseline with the agent running, no job (${LOAD_IDLE_S} s)"
  t0="$(now_s)"; sleep "$LOAD_IDLE_S"
  fact --argjson t0 "$t0" --argjson t1 "$(now_s)" '{kind: "window", name: "idle_agent", t0: $t0, t1: $t1}'
  phase_done agent

  # ---------------------------------------------------------------------------- 1. Discovery
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
  read -r s0 s1 <<<"$(console_sql "SELECT extract(epoch from first_delivered_at) || ' ' || extract(epoch from finished_at) FROM jobs WHERE id = '$job_id'")"
  [[ "$s0" =~ ^[0-9.]+$ && "$s1" =~ ^[0-9.]+$ ]] || fail "scan of ${TARGET}: no delivery / end time ($status)"
  n_tables=$(( LOAD_FB_TABLES + 3 ))
  fact --arg target "$TARGET" --arg status "$status" --argjson t0 "$s0" --argjson t1 "$s1" --argjson tables "$n_tables" \
    --argjson rows "$LOAD_FB_ROWS" '{kind: "scan", target: $target, status: $status, t0: $t0, t1: $t1, tables: $tables, rows: $rows}'
  log "scan of ${TARGET}: $status in $(jq -n --argjson a "$s0" --argjson b "$s1" '$b - $a | . * 10 | round / 10') s (${n_tables} tables)"
  [ "$status" = succeeded ] || fail "scan of ${TARGET} ended '$status'"
  wait_spool_empty "$s1" || log "WARNING: no heartbeat with an empty spool after the scan"
  n_findings="$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
  fact --arg target "$TARGET" --argjson n "$n_findings" '{kind: "findings", target: $target, count: $n}'
  log "findings: ${n_findings}"
  phase_done discovery

  # ---------------------------------------------------------------------------- 2. Audit under load
  # run_workload PHASE DURATION: fbload.py workload as LOAD_APP; the `workload` and `window` facts.
  run_workload() {
    local phase="$1" dur="$2" t_start out
    log "workload ($phase): ${LOAD_FB_RATE} statements/s over ${LOAD_CLIENTS} sessions, ${dur} s"
    t_start="$(now_s)"
    out="$(FBC_TIMEOUT=$(( dur + 300 )) fbc workload --user LOAD_APP --password-file "$CLIENT_PW" \
      --statements /databastion/in/workload.tsv --rate "$LOAD_FB_RATE" --duration "$dur" --sessions "$LOAD_CLIENTS" \
      2>"$W/out/workload-$phase.err")" || { tail -n 5 "$W/out/workload-$phase.err" >&2; fail "the workload ($phase) failed"; }
    WL_END="$(now_s)"
    printf '%s\n' "$out" >"$W/out/workload-$phase.json"
    jq -c --arg t "$TARGET" --arg ph "$phase" '{kind: "workload", target: $t, phase: $ph, tool: "fbload.py",
        rate, issued, failed, p95_ms, p99_ms, mean_ms, late_starts, schedule_lag_p95_ms, sessions,
        latency_metric: "client-side: execute, fetch and commit of one point read in its own read-only transaction"}' <<<"$out" >>"$FACTS"
    fact --arg name "workload_audit_$phase" --argjson t0 "$(jq -n --argjson t "$t_start" '$t + 5')" --argjson t1 "$WL_END" \
      '{kind: "window", name: $name, t0: $t0, t1: $t1}'
    log "workload ($phase): $(jq -c '{issued, failed, p95_ms, mean_ms, late_starts, errors}' <<<"$out")"
  }
  log "warm-up workload (${LOAD_WARMUP_S} s, not measured)"
  FBC_TIMEOUT=$(( LOAD_WARMUP_S + 300 )) fbc workload --user LOAD_APP --password-file "$CLIENT_PW" \
    --statements /databastion/in/workload.tsv --rate "$LOAD_FB_RATE" --duration "$LOAD_WARMUP_S" --sessions "$LOAD_CLIENTS" \
    >/dev/null 2>&1 || fail "the warm-up workload failed"
  run_workload off "$LOAD_BASELINE_S"
  phase_done workload-off

  log "enabling Audit on ${TARGET}"
  AUDIT_T0="$(date +%s)"
  enable_audit "$TARGET"
  # The state volume's audit files every 0.5 s until the end of part 1 (the checkpoint and ledger I/O).
  sampler_s=$(( LOAD_SOAK_S + LOAD_DRAIN_TIMEOUT_S + 2400 ))
  timeout $(( sampler_s + 60 )) docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    --name "$STATE_SAMPLER" fb-client state --root /state --interval 0.5 --duration "$sampler_s" \
    >"$STATE_SAMPLES" 2>"$W/out/state-sampler.err" &
  BG_PIDS+=("$!")
  if wait_partial 300; then level=partial; else level="$(target_json "$TARGET" | jq -r .auditLevel)"; fi
  fact --arg l "$level" --argjson s "$(( $(date +%s) - AUDIT_T0 ))" --arg n "$(notes_of "$(target_json "$TARGET")")" \
    '{kind: "fb_level", level: $l, after_s: $s, notes: $n}'
  sleep 20
  phase_done audit-setup
  SOAK_T0_EPOCH="$(date +%s)"
  run_workload on "$LOAD_SOAK_S"
  SOAK_END="$WL_END"
  phase_done workload-on

  want="$(jq -r .issued "$W/out/workload-on.json")"
  log "waiting until every statement of the Audit run is stored (${want} expected, at most ${LOAD_DRAIN_TIMEOUT_S} s)"
  deadline=$(( $(date +%s) + LOAD_DRAIN_TIMEOUT_S ))
  drain_samples=()
  DRAIN_T0="$(now_s)"
  events_sql="FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user = 'LOAD_APP' AND action = 'read' AND ts >= to_timestamp(${SOAK_T0_EPOCH})"
  while :; do
    got="$(console_sql "SELECT coalesce(sum(aggregated_count), 0) ${events_sql}")"
    since="$(jq -n --argjson a "$SOAK_END" --argjson b "$(now_s)" '$b - $a | . * 10 | round / 10')"
    drain_samples+=("[${since},${got}]")
    [ "$got" -ge "$want" ] && break
    if [ "$(date +%s)" -ge "$deadline" ]; then log "WARNING: not every statement stored: ${got}/${want}"; break; fi
    sleep 5
  done
  log "statements stored: ${got}/${want}"
  fact --arg name "drain_${TARGET}" --argjson t0 "$DRAIN_T0" --argjson t1 "$(now_s)" '{kind: "window", name: $name, t0: $t0, t1: $t1}'
  fact --arg target "$TARGET" --argjson want "$want" --argjson got "$got" \
    --argjson samples "[$(IFS=,; printf '%s' "${drain_samples[*]}")]" \
    '{kind: "fb_drain", target: $target, want: $want, stored: $got, samples: $samples, stored_at_workload_end: $samples[0][1]}'
  console_sql "SELECT json_build_object('kind', 'events', 'target', '${TARGET}',
      'received', coalesce(sum(aggregated_count), 0), 'events', count(*),
      'lag_p95_s', round(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch from received_at - coalesce(ts_last, ts))::float8)::numeric, 1),
      'lag_max_s', round(max(extract(epoch from received_at - coalesce(ts_last, ts)))::numeric, 1),
      'drain_s', CASE WHEN coalesce(sum(aggregated_count), 0) >= $want
        THEN round((extract(epoch from max(received_at)) - $SOAK_END)::numeric, 1) END) ${events_sql}" >>"$FACTS"
  # Source side: LOAD_APP's statement records in the trace log over the soak (header times).
  src="$(FBC_TIMEOUT=600 fbc trace statements --user LOAD_APP --since "$(trace_ts "$SOAK_T0_EPOCH")")" || src=""
  if [ -n "$src" ]; then
    jq -c --arg t "$TARGET" '{kind: "source", target: $t, statements: .statements, failed: .failed, rotated_files: 0}' <<<"$src" >>"$FACTS"
    log "source: $(jq -c '{statements, failed}' <<<"$src") LOAD_APP statement records in the trace log over the soak"
  fi
  # The agent's own records are never reported (the stream's own-statement rule, R13 / R23).
  own="$(console_sql "SELECT json_build_object('events', count(*), 'statements', coalesce(sum(aggregated_count), 0))
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user = 'DATABASTION_AGENT'")"
  jq -c '{kind: "fb_own_events"} + .' <<<"$own" >>"$FACTS"
  log "events under DATABASTION_AGENT: $own"
  other="$(console_sql "SELECT coalesce(string_agg(coalesce(db_user, '-') || ' ' || action || ' ' || aggregated_count, '; '), 'none')
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user IS DISTINCT FROM 'LOAD_APP'")"
  log "other events of ${TARGET}: ${other}"
  if wait_spool_empty "$(now_s)"; then fact '{kind: "spool_drained", ok: true, batches: 0}'
  else fact '{kind: "spool_drained", ok: false}'; fi
  lost="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color agent 2>/dev/null \
    | grep -cE 'cannot spool findings|batch dropped|; dropped|findings dropped|events dropped|rejected batch items|unreadable spool file' || true)"
  fact --argjson n "$lost" '{kind: "agent_log", lost: $n}'
  fbc trace size >>"$FACTS" 2>/dev/null || true
  phase_done drain

  # ---------------------------------------------------------------------------- 4. 8g attach bursts
  st="$(status_json)"
  amb0="$(ambiguous_of "$st")"
  log "8g: ${LOAD_FB_BURSTS} burst(s) of ${LOAD_FB_BURST_SIZE} concurrent attaches as LOAD_BURST (ambiguous records so far: ${amb0})"
  B_T0="$(date +%s)"
  for k in $(seq 1 "$LOAD_FB_BURSTS"); do
    # Right after a check (its session closed), so that the burst opens the database: nothing else
    # is attached then (the trace analysis below tells whether it did).
    wait_checks 1
    sleep 3
    out="$(FBC_TIMEOUT=300 fbc burst --user LOAD_BURST --password-file "$CLIENT_PW" --n "$LOAD_FB_BURST_SIZE" --hold 1)" \
      || log "WARNING: burst $k: not every attach succeeded"
    log "burst $k: $(jq -c '{attempted, connected, connect_p95_ms, connect_max_ms, errors}' <<<"$out")"
    printf '%s\n' "$out" >>"$W/out/bursts-client.jsonl"
    sleep 8
  done
  st="$(status_json)"
  amb1="$(ambiguous_of "$st")"
  order="$(FBC_TIMEOUT=600 fbc trace bursts --user LOAD_BURST --since "$(trace_ts "$B_T0")" --gap 5)" || order='{"bursts": null}'
  jq -c --argjson a0 "$amb0" --argjson a1 "$amb1" --slurpfile cl "$W/out/bursts-client.jsonl" --arg lvl "$(jq -r .level <<<"$st")" \
    '{kind: "fb_bursts", bursts: .bursts, clients: $cl, ambiguous_before: $a0, ambiguous_after: $a1, level_after: $lvl}' \
    <<<"$order" >>"$FACTS"
  log "8g: $(tail -n 1 "$FACTS" | jq -c '{bursts: [.bursts[]? | {attaches, max_inversion, latest_late_s, opened_database}], ambiguous_before, ambiguous_after}')"
  phase_done bursts

  # ---------------------------------------------------------------------------- 5. 3m
  # scenario NAME KIND COMMAND...: one 3m step; the ambiguous-record count before and after, the
  # principal's events in the step's window, the client's figures.
  scenario() {
    local name="$1" user="$2" want="$3" s1 c0 c1 t0 t1 out ev
    shift 3
    c0="$LAST_AMB"
    t0="$(now_s)"
    out="$(FBC_TIMEOUT=900 fbc "$@" --user "$user" --password-file "$CLIENT_PW" 2>"$W/out/3m-$name.err")" || log "WARNING: 3m ${name}: the client reported an error"
    t1="$(now_s)"
    [ -n "$out" ] || out='{}'
    ev="$(wait_events "$user" "$t0" "$t1" "$want")"
    s1="$(status_json)"
    c1="$(ambiguous_of "$s1")"
    LAST_AMB="$c1"
    jq -nc --arg n "$name" --arg u "$user" --argjson client "$out" --argjson ev "$ev" --argjson c0 "$c0" --argjson c1 "$c1" \
      --argjson want "$want" --arg lvl "$(jq -r .level <<<"$s1")" --argjson t0 "$t0" --argjson t1 "$t1" \
      '{kind: "fb_3m", scenario: $n, user: $u, client: $client, events: $ev, statements_expected: $want,
        ambiguous_before: $c0, ambiguous_after: $c1, level_after: $lvl, t0: $t0, t1: $t1}' >>"$FACTS"
    log "3m ${name}: $(tail -n 1 "$FACTS" | jq -c '{client: (.client | del(.kind, .t0, .t1)), events, ambiguous_before, ambiguous_after}')"
  }
  LAST_AMB="$amb1"
  log "3m: per-row statements under concurrent sessions (LOAD_APP at ${LOAD_FB_RATE}/s next to them)"
  FBC_TIMEOUT=900 fbc workload --user LOAD_APP --password-file "$CLIENT_PW" --statements /databastion/in/workload.tsv \
    --rate "$LOAD_FB_RATE" --duration 240 --sessions "$LOAD_CLIENTS" >"$W/out/3m-side.json" 2>&1 &
  side_pid=$!
  for spec in insert:10000 select:10000 insert:50000 select:50000 insert:200000; do
    scenario "perrow_${spec%%:*}_${spec#*:}" LOAD_ROW 1 perrow --what "${spec%%:*}" --rows "${spec#*:}"
  done
  wait "$side_pid" || log "WARNING: the concurrent LOAD_APP workload of the per-row steps failed"
  log "3m: open transactions with pending groups"
  scenario opentx_8x8_within LOAD_TX 64 opentx --connections 8 --tx 8 --fetch 50 --hold 5
  scenario opentx_2x24_per_binding LOAD_TX 48 opentx --connections 2 --tx 24 --fetch 50 --hold 5
  scenario opentx_4x4_hold15 LOAD_TX 16 opentx --connections 4 --tx 4 --fetch 50 --hold 15
  scenario opentx_260x16_stream_budget LOAD_TX 4160 opentx --connections 260 --tx 16 --fetch 20 --hold 5
  # A graceful agent restart while 16 groups pend (the checkpoint keeps block-ful groups, R25 item 7).
  log "3m: an agent restart during pending groups"
  (sleep 12; timeout 90 docker compose "${COMPOSE_ARGS[@]}" restart -t 30 agent >/dev/null 2>&1) &
  restart_pid=$!
  scenario opentx_4x4_restart LOAD_TX 16 opentx --connections 4 --tx 4 --fetch 50 --hold 40
  wait "$restart_pid" || true
  CID[agent]="$(compose ps -q agent)"
  restored="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix agent 2>/dev/null \
    | grep -cF 'Firebird parser checkpoint restored' || true)"
  refused="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix agent 2>/dev/null \
    | grep -cF 'Firebird parser checkpoint not used' || true)"
  fact --argjson r "$restored" --argjson n "$refused" '{kind: "fb_restart", checkpoint_restored: $r, checkpoint_refused: $n}'
  log "3m restart: checkpoint restored ${restored}, refused ${refused}"
  phase_done 3m
  docker rm -f "$STATE_SAMPLER" >/dev/null 2>&1 || true
  sleep 2
  fbc trace events >"$W/out/trace-events.json" 2>/dev/null || true
fi

# ============================================================================== part 2: schema
if part schema; then
  if part load; then
    log "schema: the server again, from fresh volumes, with the 10 000-object schema"
    timeout 120 docker compose "${COMPOSE_ARGS[@]}" stop -t 30 agent >/dev/null 2>&1 || true
    # Part 1's agent log (its container is recreated below): agent-load.log, redacted with the others.
    compose logs --no-color --timestamps agent >"$LOAD_LOG_DIR/agent-load.log" 2>&1 || true
    timeout 120 docker compose "${COMPOSE_ARGS[@]}" rm -sf agent firebird firebird-audit-init >/dev/null 2>&1 || true
    for v in firebird-root firebird-data firebird-audit; do
      docker volume rm "${PROJECT}_${v}" >/dev/null 2>&1 || fail "cannot remove the volume ${v}"
    done
    kill "$SAMPLER_DB_PID" 2>/dev/null || true
    start_firebird "$W/seed-schema.sql"
  fi
  counts="$(FBC_TIMEOUT=120 fbc sql --user SYSDBA --password-file "$SYSDBA_PW" --statement "SELECT
      (SELECT COUNT(*) FROM RDB\$RELATIONS WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0 AND RDB\$VIEW_BLR IS NULL) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$RELATIONS WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0 AND RDB\$VIEW_BLR IS NOT NULL) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$PROCEDURES WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$FUNCTIONS WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$PACKAGES WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$TRIGGERS WHERE COALESCE(RDB\$SYSTEM_FLAG, 0) = 0) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$TRIGGERS WHERE RDB\$SYSTEM_FLAG = 3) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$RELATION_FIELDS RF JOIN RDB\$FIELDS F ON F.RDB\$FIELD_NAME = RF.RDB\$FIELD_SOURCE
         WHERE COALESCE(RF.RDB\$SYSTEM_FLAG, 0) = 0 AND F.RDB\$COMPUTED_BLR IS NOT NULL) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$RELATION_CONSTRAINTS WHERE RDB\$CONSTRAINT_TYPE = 'CHECK') || ' ' ||
      (SELECT COUNT(*) FROM RDB\$INDICES WHERE RDB\$EXPRESSION_BLR IS NOT NULL) || ' ' ||
      (SELECT COUNT(*) FROM RDB\$DEPENDENCIES) FROM RDB\$DATABASE")" || fail "cannot count the schema's objects"
  read -r c_t c_v c_p c_f c_k c_tr c_ctr c_cc c_ck c_ix c_dep <<<"$counts"
  fact --argjson t "$c_t" --argjson v "$c_v" --argjson p "$c_p" --argjson f "$c_f" --argjson k "$c_k" --argjson tr "$c_tr" \
    --argjson ctr "$c_ctr" --argjson cc "$c_cc" --argjson ck "$c_ck" --argjson ix "$c_ix" --argjson dep "$c_dep" \
    --slurpfile plan "$W/schema-counts.json" \
    '{kind: "fb_schema", tables: $t, views: $v, procedures: $p, functions: $f, packages: $k, triggers: $tr,
      check_triggers: $ctr, computed_columns: $cc, check_constraints: $ck, expression_indexes: $ix,
      dependency_rows: $dep, objects: ($t + $v + $p + $f + $k + $tr + $cc + $ck + $ix), plan: $plan[0]}'
  log "schema: $(tail -n 1 "$FACTS" | jq -c 'del(.kind, .plan)')"
  if ! part load; then
    start_agent
  else
    timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
    CID[agent]="$(compose ps -q agent)"
    check_layout
  fi
  SCH_T0="$(date +%s)"
  if ! part load; then enable_audit "$TARGET"; fi
  wait_checks 3
  # (a) The dependent-set read on the complete schema.
  # catalog_phase NAME: the agent's four reads since SCH_PHASE_T0 (trace) and its cut warnings since then.
  catalog_phase() {
    local reads warn
    reads="$(FBC_TIMEOUT=600 fbc trace catalog --user DATABASTION_AGENT --since "$(trace_ts "$SCH_PHASE_T0")")" || reads='{}'
    warn="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix --since "$SCH_PHASE_T0" agent 2>/dev/null \
      | grep -cF 'dependent-set read cut or failed' || true)"
    checks="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix --since "$SCH_PHASE_T0" agent 2>/dev/null \
      | grep -F '"Firebird checked"' | grep -cF "\"target_id\":\"${TARGET}\"" || true)"
    jq -c --arg n "$1" --argjson w "$warn" --argjson c "$checks" '{kind: "fb_schema_read", phase: $n, cut_warnings: $w, checks: $c} + (del(.kind))' \
      <<<"$reads" >>"$FACTS"
    log "schema read ($1): $(tail -n 1 "$FACTS" | jq -c 'del(.kind)')"
  }
  # flood_phase NAME: the six category principals at LOAD_FB_SCHEMA_RATE each for LOAD_FB_SCHEMA_PHASE_S.
  # flood_phase NAME [ACTION]: ACTION (a function) runs 10 s into the workload.
  flood_phase() {
    local name="$1" action="${2:-}" u t0 t1 out ev amb st pid
    local -a pids=()
    st="$(status_json)"
    amb="$(ambiguous_of "$st")"
    t0="$(now_s)"
    log "schema flood ($name): ${LOAD_FB_SCHEMA_RATE}/s per category for ${LOAD_FB_SCHEMA_PHASE_S} s"
    for u in $(jq -r 'keys[]' "$W/schema-workload.json"); do
      fbc_bg "flood-$name-$u" workload --user "$u" --password-file "$CLIENT_PW" --statements "/databastion/in/schema-$u.tsv" \
        --rate "$LOAD_FB_SCHEMA_RATE" --duration "$LOAD_FB_SCHEMA_PHASE_S" --sessions 1
      pids+=("$!")
    done
    if [ -n "$action" ]; then sleep 10; "$action"; fi
    for pid in "${pids[@]}"; do wait "$pid" || log "WARNING: a flood client of phase ${name} failed"; done
    t1="$(now_s)"
    for u in $(jq -r 'keys[]' "$W/schema-workload.json"); do
      out="$(cat "$W/out/flood-$name-$u.json" 2>/dev/null)"
      [ -n "$out" ] || out='{"issued": 0, "failed": null}'
      ev="$(wait_events "$u" "$t0" "$t1" "$(jq -r '.issued // 0' <<<"$out")")"
      jq -nc --arg p "$name" --arg u "$u" --argjson c "$out" --argjson e "$ev" --argjson a "$amb" \
        '{kind: "fb_flood", phase: $p, user: $u, issued: $c.issued, failed: $c.failed, events: $e, ambiguous_before: $a}' >>"$FACTS"
    done
    log "schema flood ($name): $(grep '"kind":"fb_flood"' "$FACTS" | jq -sc --arg p "$name" '[.[] | select(.phase == $p) | {user, issued, star: .events.star_statements, stored: .events.statements}]')"
  }
  SCH_PHASE_T0="$SCH_T0"
  catalog_phase complete
  flood_phase complete
  phase_done schema-complete
  # (b) An invalidated set: a DDL statement (a view) committed; the sets stay invalidated until a check
  # whose catalog read started after its commit (R41 item 8; an early check is asked).
  printf 'CREATE VIEW LOAD_INVALIDATE_V (ID) AS SELECT ID FROM ERP_T00001\n' >"$W/load/client/invalidate.sql"
  chmod 0644 "$W/load/client/invalidate.sql"
  invalidate() {
    log "schema: invalidating the dependent set during the workload (CREATE VIEW as SYSDBA, committed)"
    INV_T="$(now_s)"
    fbc ddl --user SYSDBA --password-file "$SYSDBA_PW" --file /databastion/in/invalidate.sql >/dev/null || fail "the invalidating DDL failed"
    INV_T1="$(now_s)"
  }
  flood_phase invalidated invalidate
  # How long the set stayed invalidated: the `*` events of the view and procedure readers after the
  # DDL (their reads are always reported only while it lasts).
  console_sql "SELECT json_build_object('kind', 'fb_invalidation', 'ddl_t0', ${INV_T}, 'ddl_t1', ${INV_T1},
      'star_first_s', round((extract(epoch from min(ts)) - ${INV_T1})::numeric, 1),
      'star_last_s', round((extract(epoch from max(coalesce(ts_last, ts))) - ${INV_T1})::numeric, 1),
      'star_statements', coalesce(sum(aggregated_count), 0))
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}' AND db_user IN ('LOAD_VIEW', 'LOAD_PROC', 'LOAD_COMP')
      AND objects @> '[{\"object\": \"*\"}]'::jsonb AND ts >= to_timestamp(${INV_T}) - interval '2 seconds'" >>"$FACTS"
  log "schema invalidation: $(tail -n 1 "$FACTS" | jq -c 'del(.kind)')"
  phase_done schema-invalidated
  # (c) A cut set: procedures added past the 65 536 dependency rows of the read.
  dep="$(FBC_TIMEOUT=60 fbc sql --user SYSDBA --password-file "$SYSDBA_PW" --statement 'SELECT COUNT(*) FROM RDB$DEPENDENCIES')"
  need=$(( (65536 - dep + 4000) / 60 + 1 ))
  [ "$need" -ge 1 ] || need=1
  log "schema: ${dep} dependency rows; adding ${need} procedures (about 60 rows each) to pass 65 536"
  python3 "$SEED" firebird-schema-cut --scale "$LOAD_FB_SCHEMA_SCALE" --procedures "$need" >"$W/load/client/cut.sql"
  chmod 0644 "$W/load/client/cut.sql"
  FBC_TIMEOUT=900 fbc ddl --user SYSDBA --password-file "$SYSDBA_PW" --file /databastion/in/cut.sql >/dev/null || fail "the cut DDL failed"
  dep="$(FBC_TIMEOUT=60 fbc sql --user SYSDBA --password-file "$SYSDBA_PW" --statement 'SELECT COUNT(*) FROM RDB$DEPENDENCIES')"
  fact --argjson d "$dep" '{kind: "fb_schema_cut", dependency_rows: $d}'
  SCH_PHASE_T0="$(date +%s)"
  wait_checks 3
  catalog_phase cut
  flood_phase cut
  phase_done schema-cut
  # Without the load part, the drain phase did not run: wait for the spool here, after the floods.
  if ! part load; then
    if wait_spool_empty "$(now_s)"; then fact '{kind: "spool_drained", ok: true, batches: 0}'
    else fact '{kind: "spool_drained", ok: false}'; fi
  fi
fi

# ------------------------------------------------------------------------------ report
# Review N11 of lot 1: Audit stays blocked until a check of the agent process gives its verdict, so
# the stream's first open after an agent start fails once (permission_denied, retried after 10 s).
# Counted for the last agent process (the heartbeat counters are per process): those failures before
# its first "Firebird checked" line are expected; any other fails agent.audit_stream_failures_total.
timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix agent 2>/dev/null \
  | sed -n 's/^[^{]*//p' >"$W/out/agent-last.jsonl" || true
expected="$(jq -sr '(map(.fields.message == "databastion-agent starting") | rindex(true) // 0) as $s | .[$s:]
    | (map(.fields.message == "Firebird checked") | index(true) // length) as $c
    | [.[:$c][] | select(.fields.message == "audit stream failed; restarting" and .fields.code == "permission_denied")] | length' \
  "$W/out/agent-last.jsonl" 2>/dev/null || echo 0)"
rm -f -- "$W/out/agent-last.jsonl"
fact --argjson n "${expected:-0}" '{kind: "expected_stream_failures", n: $n,
  why: "the first stream open of the last agent process before its first check (Audit blocked until a check verdict, lot 1 review N11)"}'
sleep 5
stop_background
log "computing the results"
STATE_ARGS=()
[ -s "$STATE_SAMPLES" ] && STATE_ARGS=(--state-samples "$STATE_SAMPLES")
set +e
python3 "$LOADLIB" report --facts "$FACTS" --samples "$SAMPLES_DB" "$SAMPLES_AGENT" \
  --heartbeats "$HEARTBEATS" --out "$LOAD_RESULTS_DIR" "${STATE_ARGS[@]}"
rc=$?
set -e
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$LOAD_RESULTS_DIR/results.md" ]; then
  { echo "# Firebird target (${LOAD_FIREBIRD_VERSION})"; cat "$LOAD_RESULTS_DIR/results.md"; } >>"$GITHUB_STEP_SUMMARY"
fi
sed -n '1,/^## Checks/p' "$LOAD_RESULTS_DIR/results.md" >&2 || true
[ "$rc" = 0 ] || fail "some load checks failed (see $LOAD_RESULTS_DIR/results.md)"
