#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# End-to-end SQLite targets (ROADMAP P10-D, ADR-0059 decision 10): the console and the agent (the
# e2e images) with the dev seed's three SQLite files (dev/seed/out/sqlite.json: crm.db in rollback
# journal mode, app.db in WAL mode, intl.db in UTF-16le), written and held open by the application
# sidecar target-sqlite (dev/sqlite/build.py, the dev profile's). Compose: docker-compose.yml merged
# with docker-compose.sqlite.yml (project databastion-e2e-sqlite).
#   - The files' permissions (decision 2): owner the application's account, group the one the
#     agent reads through (not the agent's own), 0640 in a 2750 directory; mounted read-only (`:ro`)
#     into the agent, whose root file system is read-only too.
#   - Enrollment; the console lists `engine.sqlite` (P10-E): the three targets reported reachable,
#     Audit level None ("Discovery only", shown on the agent page), no refusal note.
#   - Discovery against dev/ground-truth.json, per file: every expected classifier, no negative
#     control, value-bearing names stored as `*`, never raw.
#   - An `audit.configure` attempt ends `unsupported` (refused by the console, or the job failed with
#     that code by the agent).
#   - A `-shm` truncated by the application during a scan of paced.db (a fourth target, WAL, many
#     small tables, no ground truth), once the scan read its catalog (SIGBUS in every
#     process mapping it): exactly one reader dies, its unit counted `skipped_error`, the agent
#     keeps running, the scan succeeds, the target is readable again once the application
#     restarted, and the next scan loses nothing.
#   - I2: no ground-truth value (names included) in the console database, the logs, the pages or the
#     agent's state; no generated secret in any container log.
# See e2e/README.md "SQLite targets". Requires: docker (compose v2.24+), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-sqlite}"
PROJECT="databastion-e2e-sqlite"
LOG_TAG="e2e-sqlite"  # read by lib.sh
I2_CHECK="$HERE/i2_check.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
MANIFEST="$HERE/../dev/seed/out/sqlite.json"
SCAN_TIMEOUT_S=600
# The files as the agent sees them (docker-compose.sqlite.yml) and the application's ids.
SQLITE_DIR=/srv/sqlite/data
APP_UID=10020
READ_GID=10030
# target id, file, rollback_mode: from the manifest (one dev target per file).
mapfile -t TARGETS < <(jq -r '.files[] | "\(.target) \(.file) \(.rollback_mode)"' "$MANIFEST")
[ "${#TARGETS[@]}" -eq 3 ] || { echo "expected 3 SQLite files in $MANIFEST" >&2; exit 1; }
WAL_TARGET="$(jq -r '.files[] | select(.journal_mode == "wal") | .target' "$MANIFEST")"
WAL_FILE="$(jq -r '.files[] | select(.journal_mode == "wal") | .file' "$MANIFEST")"
# The truncated -shm scenario's own file (build.py paced, written by target-sqlite with
# --paced-tables, docker-compose.sqlite.yml): WAL, held open, PACED_TABLES tables of integers, no
# ground truth. Its paced scan (about 3 units per table, each followed by a pause 99 times its
# length at the 1 % duty cycle) lasts long after its reader opened the file, which is the trigger.
PACED_TARGET=sqlite-paced
PACED_FILE=paced.db
PACED_TABLES=400

# The writer image is the dev sidecar's (dev/docker-compose.yml): the same pin.
dev_img="$(sed -n 's/.*DATABASTION_DEV_SQLITE_IMAGE:-\([^}]*\)}.*/\1/p' "$HERE/../dev/docker-compose.yml")"
e2e_img="$(sed -n 's/^x-python-image: &python-image \(.*\)$/\1/p' "$HERE/docker-compose.sqlite.yml")"
if [ -z "$dev_img" ] || [ "$dev_img" != "$e2e_img" ]; then
  echo "the writer image of docker-compose.sqlite.yml must be the one of dev/docker-compose.yml" >&2
  exit 1
fi
grep -qF "\"--paced-tables\", \"${PACED_TABLES}\"" "$HERE/docker-compose.sqlite.yml" || {
  echo "target-sqlite must write paced.db with --paced-tables ${PACED_TABLES} (docker-compose.sqlite.yml)" >&2
  exit 1
}
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE
fi

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-sqlite.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"
COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.sqlite.yml")
# shellcheck source=lib.sh
. "$HERE/lib.sh"
SERVICES=(db migrate web worker proxy sqlite-files-init target-sqlite agent)

cleanup() {
  local status=$?
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs "${SERVICES[@]}"
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  redact_dir "$E2E_LOG_DIR" "$P"
  log "tearing down"
  timeout 180 docker compose "${COMPOSE_ARGS[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$E2E_WORK_DIR"
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# I2 scanner positive control: every searchable value (names included) is in the committed seed.
timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine sqlite \
  "$HERE"/../dev/seed/out/sqlite-*.sql >&2 || fail "I2 scanner positive control failed for sqlite (see above)"

# truth_for FILE OUT: the ground truth with the SQLite locations of FILE only (one target per file;
# the findings check of a target must not expect another file's tables).
truth_for() {
  jq --arg f "$1" '.locations |= map(select(.engine != "sqlite" or .file == $f))' "$GROUND_TRUTH" >"$2"
}

# The application's log (every run of its container, restarts included), and its lines with TEXT.
app_logs() { timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color target-sqlite 2>/dev/null || true; }
app_log_count() { app_logs | grep -cF "$1" || true; }

# --------------------------------------------------------------------------- secrets, CA, agent.yaml
console_secrets
test_ca "e2e SQLite"
{
  cat <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  statement_timeout_ms: 5000
  max_scan_duration_s: 900
targets:
EOF
  for spec in "${TARGETS[@]}"; do
    read -r id file mode <<<"$spec"
    cat <<EOF
  - id: ${id}
    engine: sqlite
    sqlite:
      path: ${SQLITE_DIR}/${file}
      rollback_mode: ${mode}
EOF
  done
  cat <<EOF
  - id: ${PACED_TARGET}
    engine: sqlite
    sqlite:
      path: ${SQLITE_DIR}/${PACED_FILE}
EOF
} >"$E2E_WORK_DIR/agent/agent.yaml"
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# --------------------------------------------------------------------------- build + start
IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}")
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing images ${IMAGES[*]}"
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "E2E_SKIP_BUILD=1 but image $img is missing"
  done
else
  log "building images (web, agent)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent
fi
phase_done build

log "starting the console and the SQLite application (target-sqlite)"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy target-sqlite
start_console
deadline=$(( $(date +%s) + 180 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q target-sqlite)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "target-sqlite not healthy within 180 s"
  sleep 2
done
[ "$(compose ps -a --format '{{.ExitCode}}' sqlite-files-init)" = "0" ] || fail "sqlite-files-init did not succeed"
phase_done start

# The files (decision 2), as the application sees them: owner the application, group the one the
# agent reads through, 0640, directory 2750 with setgid; app.db held open (its -wal and -shm exist).
log "checking the files' permissions (ADR-0059 decision 2)"
listing="$(compose exec -T target-sqlite python3 -I -c '
import os, stat, sys
d = sys.argv[1]
for name in ["."] + sorted(os.listdir(d)):
    st = os.lstat(os.path.join(d, name))
    print(name, st.st_uid, st.st_gid, oct(stat.S_IMODE(st.st_mode)), stat.S_ISREG(st.st_mode) or name == ".")
' "$SQLITE_DIR")" || fail "cannot list the SQLite directory"
while read -r name uid gid mode regular; do
  [ "$uid" = "$APP_UID" ] && [ "$gid" = "$READ_GID" ] || fail "$name: owner ${uid}:${gid}, expected ${APP_UID}:${READ_GID}"
  [ "$regular" = True ] || fail "$name: not a regular file"
  if [ "$name" = . ]; then want=0o2750; else want=0o640; fi
  [ "$mode" = "$want" ] || fail "$name: mode $mode, expected $want"
done <<<"$listing"
for spec in "${TARGETS[@]}"; do
  read -r _ file _ <<<"$spec"
  grep -q "^${file} " <<<"$listing" || fail "${file} was not written"
done
for f in "$WAL_FILE" "$PACED_FILE"; do
  for side in "" -wal -shm; do
    grep -q "^${f}${side} " <<<"$listing" || fail "${f}${side} missing: the application does not hold it open"
  done
done
log "files: $(awk '{print $1}' <<<"$listing" | tr '\n' ' ')"

# --------------------------------------------------------------------------- enroll + run
log "bootstrapping the administrator; enrolling the agent"
admin_login e2e-sqlite
# shellcheck disable=SC2119 # no target secret: the agent's only secret is its own identity
enroll_agent
log "enrolled agent $AGENT_ID; starting it"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
# The agent's mount is read-only; its root file system too.
docker inspect "$(compose ps -q agent)" | jq -e '.[0].HostConfig.ReadonlyRootfs == true
    and any(.[0].Mounts[]; .Destination == "/srv/sqlite" and .RW == false)' >/dev/null \
  || fail "the agent does not see the SQLite files read-only (or its root file system is writable)"
# P10-E: the console lists engine.sqlite; without it the agent holds the targets' items (ADR-0042)
# and this wait fails.
specs=()
for spec in "${TARGETS[@]}"; do read -r id _ <<<"$spec"; specs+=("${id}:sqlite"); done
wait_online 120 "${specs[@]}" "${PACED_TARGET}:sqlite"
for spec in "${TARGETS[@]}" "$PACED_TARGET"; do
  read -r id _ <<<"$spec"
  t="$(target_json "$id")"
  log "target ${id}: $(target_summary "$t")"
  jq -e '.auditLevel == "none" and (.auditSource == null)' <<<"$t" >/dev/null \
    || fail "${id}: audit level $(jq -r .auditLevel <<<"$t") / source $(jq -r .auditSource <<<"$t"), expected none (Discovery only)"
  notes="$(notes_of "$t")"
  for c in coverage.filesystem_not_read_only coverage.file_path_refused coverage.reader_sandbox_unavailable \
      coverage.reader_process_failed coverage.wal_files_not_readable coverage.rollback_mode_not_read \
      privilege.database_file_writable check.stage_failed; do
    [[ " $notes " != *" $c "* ]] || fail "${id}: the heartbeat reports $c"
  done
done
inspect_scan "with the agent"
phase_done enroll

# The console shows the targets as "Discovery only" (P10-E).
code="$("${CURL[@]}" -o "$E2E_WORK_DIR/agent-page.html" -w '%{http_code}' "${BASE_URL}/agents/${AGENT_ID}")" || code=000
[ "$code" = 200 ] || fail "agent page: HTTP $code"
grep -qF 'Discovery only' "$E2E_WORK_DIR/agent-page.html" || fail "the agent page does not show \"Discovery only\" for the SQLite targets"
rm -f -- "$E2E_WORK_DIR/agent-page.html"

# --------------------------------------------------------------------------- Discovery
ids=()
for spec in "${TARGETS[@]}"; do read -r id _ <<<"$spec"; ids+=("$id"); done
log "Discovery: ${ids[*]}"
scan_targets "$SCAN_TIMEOUT_S" "${ids[@]}"
for spec in "${TARGETS[@]}"; do
  read -r id file _ <<<"$spec"
  truth_for "$file" "$E2E_WORK_DIR/truth.json"
  findings_json "$id" >"$E2E_WORK_DIR/findings.json" || fail "cannot read the findings of $id"
  timeout 60 python3 "$I2_CHECK" findings --ground-truth "$E2E_WORK_DIR/truth.json" --engine sqlite \
    --require-expected-classifiers --forbid-negative-controls "$E2E_WORK_DIR/findings.json" >&2 \
    || fail "findings check of ${id} failed (see above)"
  # Decision 6: database `main`, no schema, on every finding.
  jq -e 'all(.[]; .database_name == "main" and .schema_name == null)' "$E2E_WORK_DIR/findings.json" >/dev/null \
    || fail "${id}: a finding is not in database main without a schema"
  log "${id}: $(jq length "$E2E_WORK_DIR/findings.json") finding(s); coverage $(console_sql "SELECT progress FROM jobs WHERE agent_id = '${AGENT_ID}' AND target_id = '${id}' AND type = 'discovery.scan' ORDER BY created_at DESC LIMIT 1")"
done
rm -f -- "$E2E_WORK_DIR/findings.json" "$E2E_WORK_DIR/truth.json"
phase_done discovery

# --------------------------------------------------------------------------- audit.configure
# Decision 7: no Audit on SQLite. Either the console refuses the request with an `unsupported`
# error, or it queues the job and the agent answers `unsupported`.
log "audit.configure on ${WAL_TARGET}: must end unsupported"
body='{"enabled":true,"derive_from_findings":true}'
r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${WAL_TARGET}/audit" "$body")"
if [ "$(status_of "$r")" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
  digest="$(body_of "$r" | jq -r '.digest')"
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${WAL_TARGET}/audit" \
    "$(jq -c --arg d "$digest" '. + {confirm: $d}' <<<"$body")")"
fi
case "$(status_of "$r")" in
  202)
    job_id="$(body_of "$r" | jq -r '.job_id')"
    [[ "$job_id" =~ $UUID_RE ]] || fail "audit.configure: no job id"
    deadline=$(( $(date +%s) + 90 ))
    while :; do
      job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '$job_id'")"
      case "$job" in
        failed,unsupported) log "audit.configure: the job failed with unsupported"; break ;;
        succeeded,* | failed,* | cancelled,* | expired,*) fail "audit.configure: the job ended '$job', expected failed,unsupported" ;;
      esac
      [ "$(date +%s)" -lt "$deadline" ] || fail "audit.configure: the job did not end within 90 s ('$job')"
      sleep 1
    done ;;
  4??)
    err="$(body_of "$r" | jq -r '.error // empty' 2>/dev/null || true)"
    [[ "$err" == *unsupported* ]] || fail "audit.configure: HTTP $(status_of "$r") with error '${err}', expected an unsupported refusal"
    log "audit.configure: refused by the console (HTTP $(status_of "$r"), ${err})" ;;
  *) fail "audit.configure: HTTP $(status_of "$r")" ;;
esac
wait_target_state "$WAL_TARGET" 60 '.auditLevel == "none"' "audit level still none"
phase_done audit-configure

# --------------------------------------------------------------------------- truncated -shm
# The application truncates the -shm of paced.db during a scan of it: the reader, which maps it,
# gets SIGBUS at its next unit (ADR-0059 decision 4): one reader lost (its unit counted
# `skipped_error`), the agent unaffected. Until the application rebuilds its WAL index, the next
# readers find the file not readable (`wal_files_not_readable`) and count their tables
# `skipped_error` too, without dying (on this file every later table: the scan ends with all its
# tables `skipped_error` and none sampled, unless the application restarted during it). The
# application exits at its next heartbeat write (build.py: a -shm truncated under its connection)
# and is restarted (by Docker, restart: on-failure, or else by the run); the restarted process's
# open rebuilds the WAL index. No cadence decides when either: once the scan ended, the run
# triggers that write (SIGUSR1), waits for the restarted process's "paced.db: held open, -shm N
# bytes" line (the WAL index rebuilt), then for an agent heartbeat reported after it, before the
# next scan.
# No delay decides when to truncate: the trigger is the agent's "sqlite catalog read" line for this
# target, logged when the scan's first unit is done (the catalog read, whose failure fails the whole
# scan, so it must not be the unit that meets the truncation; the reader has mapped the -shm then and
# is paused until its next unit). The scan must still be running once the truncation is done
# (checked after it: a scan that had already ended fails the run, it never passes it). PACED_TABLES
# keeps the scan running long after that line: its remaining units (about 3 per table), each
# followed by a pause, far outlast one `docker compose logs` poll on any runner.
log "truncated -shm: a scan of ${PACED_TARGET} (${PACED_TABLES} tables), the -shm truncated once its catalog was read"
agent_cid="$(compose ps -q agent)"
restarts0="$(docker inspect -f '{{.RestartCount}}' "$agent_cid")"
app_cid="$(compose ps -q target-sqlite)"
app_restarts0="$(docker inspect -f '{{.RestartCount}}' "$app_cid")"
app_opens0="$(app_log_count "${PACED_FILE}: held open")"
app_exits0="$(app_log_count "${PACED_FILE}-shm: truncated under the held connection")"
deaths0="$(agent_log_count "sqlite reader process lost" "$PACED_TARGET")"
catalogs0="$(agent_log_count "sqlite catalog read" "$PACED_TARGET")"
printf '%s' '{"sample_rows":100,"max_duration_s":600,"statement_timeout_ms":5000}' >"$E2E_WORK_DIR/scan-req.json"
r="$(api POST "/api/agents/${AGENT_ID}/targets/${PACED_TARGET}/scan" "$E2E_WORK_DIR/scan-req.json")"
[ "$(status_of "$r")" = 202 ] || fail "scan request (${PACED_TARGET}): HTTP $(status_of "$r")"
job_id="$(body_of "$r" | jq -r '.job_id')"
[[ "$job_id" =~ $UUID_RE ]] || fail "scan request (${PACED_TARGET}): no job id"
deadline=$(( $(date +%s) + 120 ))
until [ "$(agent_log_count "sqlite catalog read" "$PACED_TARGET")" -gt "$catalogs0" ]; do
  st="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")"
  case "$st" in
    succeeded | failed | cancelled | expired) fail "the scan of ${PACED_TARGET} ended (${st}) before its catalog was read" ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "the scan of ${PACED_TARGET} did not read its catalog within 120 s"
  sleep 0.2
done
compose exec -T target-sqlite python3 -I -B /opt/sqlite/build.py truncate-shm "${SQLITE_DIR}/${PACED_FILE}" >&2 \
  || fail "cannot truncate the -shm of ${PACED_FILE}"
st="$(console_sql "SELECT status FROM jobs WHERE id = '$job_id'")"
case "$st" in
  succeeded | failed | cancelled | expired)
    fail "the scan of ${PACED_TARGET} had ended (${st}) when the -shm was truncated: raise PACED_TABLES" ;;
esac
wait_job "$job_id" "scan (${PACED_TARGET}, truncated -shm)" "$SCAN_TIMEOUT_S"
[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$agent_cid")" = "true ${restarts0}" ] \
  || fail "the agent did not survive the truncated -shm ($(docker inspect -f '{{.State.Status}} restarts {{.RestartCount}}' "$agent_cid"))"
progress="$(console_sql "SELECT coalesce(progress, '{}'::jsonb) FROM jobs WHERE id = '$job_id'")"
lost="$(jq -r '.skipped_error // 0' <<<"$progress")"
deaths=$(( $(agent_log_count "sqlite reader process lost" "$PACED_TARGET") - deaths0 ))
log "truncated -shm: scan succeeded, coverage ${progress}, reader(s) lost ${deaths}; agent running, not restarted"
[ "$deaths" = 1 ] || fail "the truncated -shm cost ${deaths} reader(s), expected 1"
[ "$lost" -ge 1 ] || fail "the truncated -shm cost no unit (skipped_error ${lost})"
# The application's next write, triggered now (unless its 20 s cadence came first): it exits (75).
# The signal is sent from inside the container, not by `docker kill`: the daemon may take a killed
# container as stopped by hand and skip its restart policy (seen in CI: exited 75, restarts 0).
# Either Docker restarts it (restart: on-failure) or, once it is seen exited, the run starts it, as
# an operator or a supervisor would: what the scenario proves is the agent's recovery once the
# application rebuilt its index, not Docker's restart. The proof of that rebuild is the restarted
# process's "held open, -shm N bytes" line, with N at least one WAL-index region.
if [ "$(docker inspect -f '{{.State.Running}}' "$app_cid")" = true ]; then
  # Not fatal: a write at its cadence may have just made it exit (the wait below decides).
  compose exec -T target-sqlite python3 -I -B -c 'import os, signal; os.kill(1, signal.SIGUSR1)' \
    || log "target-sqlite not signalled (SIGUSR1): already exiting?"
fi
started=0
deadline=$(( $(date +%s) + 90 ))
until [ "$(docker inspect -f '{{.State.Running}}' "$app_cid")" = true ] \
    && [ "$(app_log_count "${PACED_FILE}: held open")" -gt "$app_opens0" ]; do
  if [ "$started" = 0 ] && [ "$(docker inspect -f '{{.State.Status}}' "$app_cid")" = exited ]; then
    [ "$(app_log_count "${PACED_FILE}-shm: truncated under the held connection")" -gt "$app_exits0" ] \
      || fail "target-sqlite exited ($(docker inspect -f 'exit {{.State.ExitCode}}' "$app_cid")) without finding the truncated -shm of ${PACED_FILE}"
    log "target-sqlite exited ($(docker inspect -f 'exit {{.State.ExitCode}}, restarts {{.RestartCount}}' "$app_cid")), not restarted by Docker: starting it"
    compose start target-sqlite >&2 || fail "cannot start target-sqlite again"
    started=1
  fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "target-sqlite did not restart and reopen ${PACED_FILE} within 90 s \
($(docker inspect -f '{{.State.Status}} exit {{.State.ExitCode}} restarts {{.RestartCount}}' "$app_cid"), started by the run: ${started})"
  sleep 0.5
done
shm="$(app_logs | grep -F "${PACED_FILE}: held open, -shm " | tail -n1 | sed -n 's/.*-shm \([0-9]*\) bytes.*/\1/p')"
[ "${shm:-0}" -ge 32768 ] || fail "the restarted application did not rebuild the WAL index of ${PACED_FILE} (-shm ${shm:-?} bytes)"
log "application reopened ${PACED_FILE} (Docker restarts $(( $(docker inspect -f '{{.RestartCount}}' "$app_cid") - app_restarts0 )), started by the run ${started}), WAL index rebuilt (-shm ${shm} bytes)"
# Then an agent heartbeat whose checks all ran after that line: received at least 3 s (the 2 s check
# budget, and slack) after the time taken here, which is after the line.
reopened="$(console_sql "SELECT now() + interval '3 seconds'")"
deadline=$(( $(date +%s) + 120 ))
until [ "$(console_sql "SELECT count(*) FROM agent_targets WHERE agent_id = '${AGENT_ID}' AND target_id = '${PACED_TARGET}' AND last_reported_at > '${reopened}'::timestamptz")" = 1 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no agent heartbeat for ${PACED_TARGET} within 120 s of the application's reopening"
  sleep 1
done
wait_target_state "$PACED_TARGET" 60 '.reachable == true and ([.notes[]?.code] | index("coverage.wal_files_not_readable") | not)' \
  "reachable after the application's restart"
scan_targets "$SCAN_TIMEOUT_S" "$PACED_TARGET"
progress="$(console_sql "SELECT coalesce(progress, '{}'::jsonb) FROM jobs WHERE id = '${SCAN_JOB_IDS[0]}'")"
[ "$(jq -r '.skipped_error // 0' <<<"$progress")" = 0 ] || fail "the scan after the restart lost units ($progress)"
[ "$(console_sql "SELECT count(*) FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '${PACED_TARGET}'")" = 0 ] \
  || fail "${PACED_TARGET} holds no sensitive value, yet has findings"
phase_done shm

# --------------------------------------------------------------------------- I2 and secret hygiene
log "I2: the console database, the logs, the pages and the agent's state"
dump_logs "${SERVICES[@]}"
for f in agent.log web.log worker.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the scans would prove nothing"
done
# Decision 2: the path, the file names and the side-file names never reach the agent's logs.
for needle in "$SQLITE_DIR" "${WAL_FILE}-shm" "${PACED_FILE}-shm"; do
  ! grep -qF "$needle" "$E2E_LOG_DIR/agent.log" || fail "the agent logged a path or a file name"
done
D="$E2E_WORK_DIR/dump"
collect_console_side "$D" "${ids[@]}"
grep -qF "${ids[0]}" "$D/pages/findings.html" || fail "the findings page does not name ${ids[0]} (page scan control)"
for needle in "$SQLITE_DIR" ".db-wal" ".db-shm"; do
  ! grep -rqF "$needle" "$D" || fail "a path or a side-file name reached the console side"
done
i2_failed=0
i2_canary sqlite
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine sqlite --label "sqlite console side" \
  "$D" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine sqlite --label "sqlite logs" \
  "$E2E_LOG_DIR" >&2 || i2_failed=1
pattern_canary
leaks=0
secret_hygiene "$D" || leaks=1
log "I2: $(find "$P" -type f | wc -l) secret(s) searched"
rm -rf -- "$D"
[ "$i2_failed" = 0 ] || fail "invariant I2: ground-truth value(s) or name(s) of the SQLite targets in clear text (ids above)"
[ "$leaks" = 0 ] || fail "a secret reached the console, a log or the agent's state (names above)"
phase_done i2
log "all checks passed"
