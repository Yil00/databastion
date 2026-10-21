# shellcheck shell=bash
# Shared helpers of the phase 9 end-to-end scenarios (e2e/sqlserver.sh, e2e/redis.sh) and of their
# load runs (e2e/load/sqlserver.sh, e2e/load/redis.sh). Sourced, never run. The older scripts
# (run.sh, cas.sh, oidc.sh, load/run.sh, load/cas.sh) keep their own copies.
#
# The caller sets, before sourcing:
#   HERE         directory of e2e/ (compose files, i2_check.py)
#   LOG_TAG      prefix of the log lines (e2e-sqlserver, load-redis, ...)
#   COMPOSE_ARGS docker compose arguments (-p PROJECT -f ...)
#   E2E_WORK_DIR private run directory (0700, removed on exit), exported for the compose files
#   E2E_LOG_DIR  directory of the collected container logs
#   E2E_HTTPS_PORT port of the TLS proxy on 127.0.0.1
# Secrets are written to files of the private run directory and registered (masked in the job log,
# searched in every log, the console database and the agent's state, redacted on exit); they never
# go on a command line of the host.

HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log() { printf '[%s %s] %s\n' "$LOG_TAG" "$(date -u +%H:%M:%S)" "$*" >&2; }
# Under GitHub Actions the reason is also an error annotation (readable through the check-run API
# when the job log is not; registered secrets are masked in it as in the log).
# Workflow command escaping: the message (% CR LF) and the title property (also : and ,), so that a
# reason can neither end the annotation early nor start another workflow command.
gha_escape() {
  local s="$1"
  s="${s//%/%25}"; s="${s//$'\r'/%0D}"; s="${s//$'\n'/%0A}"
  [ "${2:-}" = property ] && { s="${s//:/%3A}"; s="${s//,/%2C}"; }
  printf '%s' "$s"
}
fail() {
  log "FAIL: $*"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    printf '::error title=%s::%s\n' "$(gha_escape "${LOG_TAG:-load}" property)" "$(gha_escape "$*")"
  fi
  exit 1
}
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

# --------------------------------------------------------------------------- registries
# One file per value, read by grep -Ff and awk, never on a command line.
#   $P   generated secrets (masked in the job log; nowhere but where they belong)
#   $NP  other values of the run that must not reach the console side (marker passwords of the DCL
#        test, ...): searched like the secrets
P="$E2E_WORK_DIR/secret-patterns"
NP="$E2E_WORK_DIR/value-patterns"
mkdir -p "$P" "$NP"
register_secret() {
  local name="$1" value="$2"
  if [ -z "$value" ] || [ "$value" = null ]; then return 0; fi
  printf '%s\n' "$value" >"$P/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}
register_value() {
  local name="$1" value="$2"
  [ -n "$value" ] || return 0
  printf '%s\n' "$value" >"$NP/$name"
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$value"; fi
}

# leak_scan TARGET PATTERN_DIR: "<name>: <files>" per pattern found (fixed strings; names only).
leak_scan() {
  local target="$1" pdir="$2" f files found=0
  [ -e "$target" ] || return 0
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

# redact_dir DIR PATTERN_DIR: in place; a file that cannot be redacted is deleted.
redact_dir() {
  local dir="$1" pdir="$2" f name file tmp="$E2E_WORK_DIR/redact.tmp"
  local -a hits
  if [ ! -d "$dir" ] || [ ! -d "$pdir" ]; then return 0; fi
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

# --------------------------------------------------------------------------- secrets
rand_hex() { openssl rand -hex "$1"; }
# A password that meets SQL Server's CHECK_POLICY (three character classes), harmless elsewhere.
rand_password() { printf 'Pw7%s' "$(rand_hex "${1:-20}")"; }
S="$E2E_WORK_DIR/secrets"
mkdir -p "$S" "$E2E_WORK_DIR/tls" "$E2E_WORK_DIR/agent"
# 0644 files inside a 0700 directory: readable by the containers' users through the bind mounts.
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; register_secret "$1" "$2"; }

# console_secrets: the console's secrets (as run.sh), and the URLs that embed them.
console_secrets() {
  local owner app
  owner="$(rand_hex 24)"
  app="$(rand_hex 24)"
  put_secret db_password "$(rand_hex 24)"
  put_secret db_owner_password "$owner"
  put_secret db_app_password "$app"
  put_secret encryption_key "$(openssl rand -base64 32)"
  put_secret metrics_token "$(rand_hex 32)"
  put_secret admin_password "$(rand_hex 24)"
  umask 022
  printf 'postgresql://databastion_owner:%s@db:5432/databastion' "$owner" >"$S/db_owner_url"
  printf 'postgresql://databastion_runtime:%s@db:5432/databastion' "$app" >"$S/db_url"
  umask 077
  chmod 0700 "$S"
}

# test_ca LABEL: the throwaway CA and the proxy certificate (as run.sh); empty files for the
# bind-mount sources of the e2e services this run never starts (interpolated anyway).
T="$E2E_WORK_DIR/tls"
test_ca() {
  log "generating the throwaway test CA and the proxy certificate"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=DataBastion $1 test CA" \
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
  local f
  for f in mysql-ca.pem mariadb-ca.pem ldap-ca.pem mailpit.crt mailpit.key; do : >"$T/$f"; done
}

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
# console_sql SQL: the harness only reads the console database (read-only transactions).
console_sql() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" exec -T -e "PGOPTIONS=-c default_transaction_read_only=on" db \
    psql -XAt -v ON_ERROR_STOP=1 -U postgres -d databastion -c "$1"
}
files_root() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps agent-files "$1"
}
files_agent() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps --user 10001:10001 agent-files "$1"
}

# start_console: db, migrate, web, worker, proxy; ready through the proxy.
start_console() {
  timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy
  local deadline=$(( $(date +%s) + 180 ))
  until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 180 s"
    sleep 1
  done
  [ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"
}

# admin_login LABEL: bootstrap the administrator, log in, create an enrollment token (ENROLLMENT_TOKEN).
admin_login() {
  local r
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
  r="$(api_json POST /api/enrollment-tokens "{\"label\":\"$1\"}")"
  [ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
  ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
  register_secret enrollment_token "$ENROLLMENT_TOKEN"
}

# enroll_agent SECRET_NAME...: the target passwords (secret files of $S) written to the agent's
# secrets volume as 0600 files of the agent user, then `enroll`; sets AGENT_ID. Not started.
enroll_agent() {
  local name identity
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent --version \
    >"$E2E_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
  files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
  for name in "$@"; do
    files_agent "umask 077; cat > /secrets/$name" <"$S/$name"
  done
  printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'
  unset ENROLLMENT_TOKEN
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps agent \
    enroll --config /etc/databastion/agent.yaml --token-file /run/databastion-secrets/enrollment_token \
    >"$E2E_LOG_DIR/agent-enroll.log" 2>&1 || fail "agent enroll failed (see agent-enroll.log)"
  files_agent 'rm -f /secrets/enrollment_token'
  identity="$(files_agent 'cat /state/identity.json')"
  AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
  register_secret agent_secret "$(jq -r '.agent_secret' <<<"$identity")"
  unset identity
  [[ "$AGENT_ID" =~ $UUID_RE ]] || fail "no agent id"
}

agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}
target_json() { agent_json | jq -c --arg t "$1" '.targets[] | select(.targetId == $t)'; }
notes_of() { jq -r '[.notes[]?.code] | sort | join(" ")' <<<"$1"; }
target_summary() { jq -c '{engine, reachable, auditLevel, auditSource, notes: [.notes[]?.code]}' <<<"$1"; }

# wait_online TIMEOUT TARGET:ENGINE...: the agent online with every target present and reachable.
wait_online() {
  local timeout_s="$1" deadline a spec want='[]'
  shift
  for spec in "$@"; do want="$(jq -c --arg t "${spec%%:*}" --arg e "${spec#*:}" '. + [[$t, $e]]' <<<"$want")"; done
  deadline=$(( $(date +%s) + timeout_s ))
  until a="$(agent_json 2>/dev/null)" && [ -n "$a" ] && jq -e --argjson w "$want" '. as $a | .status == "online"
      and all($w[]; . as [$t, $e] | any($a.targets[]; .targetId == $t and .engine == $e and .present
        and .reachable == true and .auditLevel != null))' <<<"$a" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "agent not online with $* within ${timeout_s} s ($(jq -c '{status, targets: [.targets[]? | {targetId, engine, present, reachable, auditLevel, lastError}]}' <<<"${a:-{\}}" 2>/dev/null || true))"
    sleep 2
  done
}

# wait_target_state TARGET TIMEOUT JQ_FILTER DESCRIPTION: until the target's JSON passes the filter.
wait_target_state() {
  local target="$1" deadline t
  deadline=$(( $(date +%s) + $2 ))
  while :; do
    t="$(target_json "$target" 2>/dev/null || true)"
    if [ -n "$t" ] && jq -e "$3" <<<"$t" >/dev/null 2>&1; then
      # shellcheck disable=SC2034 # read by the callers
      TARGET_STATE="$t"
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "$target: $4 not reached within $2 s (now $(target_summary "${t:-{\}}" 2>/dev/null || true))"
    sleep 3
  done
}

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

# create_policy NAME SEVERITY CONDITIONS_JSON: an access_event policy creating incidents.
create_policy() {
  local r
  r="$(api_json POST /api/policies "$(jq -nc --arg n "$1" --arg s "$2" --argjson c "$3" '{name: $n,
    description: "e2e", source: "access_event", conditions: $c,
    actions: [{type: "create_incident", severity: $s}]}')")"
  [ "$(status_of "$r")" = 201 ] || fail "policy '$1': HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
}

# enable_audit TARGET [SETTINGS_JSON]: audit.configure (confirmed), then the agent's
# "audit stream started" line for the target. Settings: the contract defaults unless given
# (e.g. '{"poll_interval_s":1}').
enable_audit() {
  local target="$1" extra="${2:-{\}}" prev r digest job_id body deadline
  prev="$(agent_log_count "audit stream started" "$target")"
  body="$(jq -c --argjson x "$extra" '{enabled: true, derive_from_findings: true} + $x' <<<'{}')"
  r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" "$body")"
  if [ "$(status_of "$r")" = 409 ] && [ "$(body_of "$r" | jq -r '.error')" = confirmation_required ]; then
    digest="$(body_of "$r" | jq -r '.digest')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "audit.configure ($target): no confirmation digest"
    r="$(api_json POST "/api/agents/${AGENT_ID}/targets/${target}/audit" \
      "$(jq -c --arg d "$digest" '. + {confirm: $d}' <<<"$body")")"
  fi
  [ "$(status_of "$r")" = 202 ] || fail "audit.configure ($target): HTTP $(status_of "$r") ($(body_of "$r" | jq -c '{error, field}' 2>/dev/null || true))"
  job_id="$(body_of "$r" | jq -r '.job_id')"
  [[ "$job_id" =~ $UUID_RE ]] || fail "audit.configure ($target): no job id"
  wait_job "$job_id" "audit.configure ($target)" 90
  deadline=$(( $(date +%s) + 90 ))
  until [ "$(agent_log_count "audit stream started" "$target")" -gt "$prev" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "the agent did not start the Audit stream of ${target} within 90 s"
    sleep 1
  done
}

# scan_targets TIMEOUT TARGET...: one discovery.scan per target (together), each must succeed; then
# a heartbeat after the last one reports an empty spool, nothing dropped. SCAN_REQ overrides the
# request body.
scan_targets() {
  local timeout_s="$1" target job_id job ids=() deadline spool list r
  shift
  local req="$E2E_WORK_DIR/scan-req.json"
  printf '%s' "${SCAN_REQ:-{\"sample_rows\":100,\"max_duration_s\":600,\"statement_timeout_ms\":5000\}}" >"$req"
  for target in "$@"; do
    r="$(api POST "/api/agents/${AGENT_ID}/targets/${target}/scan" "$req")"
    [ "$(status_of "$r")" = 202 ] || fail "scan request ($target): HTTP $(status_of "$r")"
    job_id="$(body_of "$r" | jq -r '.job_id')"
    [[ "$job_id" =~ $UUID_RE ]] || fail "scan request ($target): no job id"
    ids+=("$job_id")
  done
  deadline=$(( $(date +%s) + timeout_s ))
  for job_id in "${ids[@]}"; do
    while :; do
      job="$(console_sql "SELECT status || ',' || coalesce(error->>'code', '') FROM jobs WHERE id = '$job_id'")"
      case "$job" in
        succeeded,*) break ;;
        failed,* | cancelled,* | expired,*) fail "scan job $job_id ended '$job'" ;;
      esac
      [ "$(date +%s)" -lt "$deadline" ] || fail "scan job $job_id not succeeded within ${timeout_s} s ('$job')"
      sleep 2
    done
  done
  list="$(printf "'%s'," "${ids[@]}")"
  deadline=$(( $(date +%s) + 120 ))
  while :; do
    spool="$(console_sql "SELECT concat_ws(',', a.last_seen_at > max(j.finished_at) + interval '1 second',
        coalesce(a.spool->>'batches', 'none'), coalesce(a.spool->>'dropped_batches', '0'),
        coalesce(a.spool->>'dropped_items', '0'))
      FROM agents a JOIN jobs j ON j.agent_id = a.id
      WHERE a.id = '${AGENT_ID}' AND j.id IN (${list%,}) GROUP BY a.id HAVING count(j.finished_at) = ${#ids[@]}")"
    case "$spool" in
      t,0,0,0) break ;;
      t,*,*,*) IFS=, read -r _ _ db di <<<"$spool"
        if [ "$db" != 0 ] || [ "$di" != 0 ]; then fail "the agent dropped results ($spool)"; fi ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || fail "no heartbeat with an empty spool within 120 s after the scans ('$spool')"
    sleep 2
  done
  # shellcheck disable=SC2034 # read by the callers
  SCAN_JOB_IDS=("${ids[@]}")
}

# findings_json TARGET: the findings rows of a target as i2_check.py findings reads them.
findings_json() {
  console_sql "SELECT coalesce(json_agg(json_build_object('database_name', database_name,
      'schema_name', schema_name, 'object_name', object_name, 'field_name', field_name,
      'classifier', classifier) ORDER BY location_key, classifier), '[]')
    FROM findings WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'"
}

# events_json TARGET / incidents_json TARGET: as run.sh exports them for i2_check.py audit.
events_json() {
  console_sql "SELECT coalesce(json_agg(json_build_object('db_user', db_user,
      'db_user_fingerprint', db_user_fingerprint, 'account_not_recorded', account_not_recorded,
      'action', action, 'objects', objects, 'signals', signals, 'rows', rows, 'bytes', bytes,
      'source', source, 'aggregated_count', aggregated_count, 'client_addr', client_addr)
      ORDER BY ts), '[]')
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'"
}
incidents_json() {
  console_sql "SELECT coalesce(json_agg(json_build_object('policy_name', policy_name,
      'principal', principal, 'event_signals', event_signals, 'severity', severity,
      'events_account_not_recorded', (SELECT bool_and(e.account_not_recorded) FROM access_events e
        WHERE e.id = incidents.access_event_id
           OR e.id IN (SELECT ie.event_id FROM incident_events ie WHERE ie.incident_id = incidents.id)))
      ORDER BY created_at), '[]')
    FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'"
}

# inspect_scan WHEN: `docker inspect` of every container of the project, running or exited
# (environment, command, entrypoint, labels, mounts), into a private work file: no registered
# secret may be in it (names logged, never values).
inspect_scan() {
  local f="$E2E_WORK_DIR/inspect.json" leaked l
  local -a ids
  mapfile -t ids < <(compose ps -aq)
  [ "${#ids[@]}" -gt 0 ] || fail "no container to inspect ($1)"
  timeout 60 docker inspect "${ids[@]}" >"$f" || fail "docker inspect failed ($1)"
  if ! leaked="$(leak_scan "$f" "$P")"; then
    while IFS= read -r l; do log "LEAK (docker inspect, $1): $l"; done <<<"$leaked"
    rm -f -- "$f"
    fail "a secret is in the containers' configuration ($1)"
  fi
  rm -f -- "$f"
  log "docker inspect of ${#ids[@]} container(s) ($1): no secret"
}

# objects_summary TARGET ENGINE SQL_CONDITION: the event objects of a target's events matching the
# condition, for the job log, never as stored: each object mapped to `*`, to the name of a
# ground-truth location of ENGINE without a value in its name (its normalized pattern included), or
# to `<other>`; "<mapped form> x<count>" per form. A raw object name (which may hold a value) is
# never printed.
objects_summary() {
  local known
  known="$(jq -r --arg e "$2" '[.locations[] | select(.engine == $e and (.name_contains_value | not)) | .object]
      + [.locations[] | select(.engine == $e) | .expected_normalized_name // empty]
    | unique | map("'"'"'" + gsub("'"'"'"; "'"''"'") + "'"'"'") | join(", ")' "$GROUND_TRUTH")"
  console_sql "SELECT coalesce(string_agg(m || ' x' || n, ' ' ORDER BY m), 'none') FROM (
      SELECT CASE WHEN o->>'object' = '*' THEN '*'
                  WHEN o->>'object' IN (${known:-''}) THEN o->>'object' ELSE '<other>' END AS m, count(*) AS n
      FROM access_events e, jsonb_array_elements(e.objects) o
      WHERE e.agent_id = '${AGENT_ID}' AND e.target_id = '$1' AND ($3) GROUP BY 1) x"
}

# --------------------------------------------------------------------------- I2 collection
# collect_console_side DIR TARGET...: the console database dump, the Audit tables as JSON, the
# pages (findings, events, incidents, agent, each target's settings) and the agent's state.
collect_console_side() {
  local D="$1" table code page target
  shift
  mkdir -p "$D/pages" "$D/state"
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T db pg_dump -U postgres -d databastion \
    >"$D/console.sql" 2>/dev/null || fail "pg_dump of the console database failed"
  grep -q '^COPY public.findings ' "$D/console.sql" || fail "the console database dump has no findings table"
  for table in access_events incidents incident_events principal_baselines audit_configs agent_targets findings; do
    console_sql "SELECT coalesce(json_agg(t), '[]') FROM ${table} t" >"$D/${table}.json" || fail "cannot export $table"
  done
  fetch() {
    code="$("${CURL[@]}" -o "$D/pages/$1.html" -w '%{http_code}' "${BASE_URL}$2")" || code=000
    [ "$code" = 200 ] || fail "page $2: HTTP $code"
  }
  fetch findings /findings
  fetch events /events
  fetch incidents "/incidents?status=all"
  fetch agent "/agents/${AGENT_ID}"
  fetch api-agents /api/agents
  for target in "$@"; do
    fetch "audit-$target" "/agents/${AGENT_ID}/targets/${target}/audit"
  done
  # Each incident page.
  page=0
  while IFS= read -r id; do
    [[ "$id" =~ $UUID_RE ]] || continue
    fetch "incident-$page" "/incidents/$id"
    page=$((page + 1))
  done < <(console_sql "SELECT id FROM incidents WHERE agent_id = '${AGENT_ID}' ORDER BY created_at")
  unset -f fetch
  files_agent 'tar -C /state -cf - .' >"$D/state.tar" || fail "cannot read the agent's state"
  tar -C "$D/state" -xf "$D/state.tar" && rm -f "$D/state.tar"
  [ -f "$D/state/identity.json" ] || fail "no identity.json in the agent's state: the state scan would prove nothing"
}

# i2_canary ENGINE: positive control of the ground-truth scan (a value of the engine planted in a
# canary file must be reported).
i2_canary() {
  local engine="$1" rc=0
  mkdir -p "$E2E_WORK_DIR/canary"
  jq -r --arg e "$engine" '[.locations[] | select(.engine == $e and (.values | length) > 0
      and (.expected_classifiers | index("pii.email"))) | .values[]] | .[0]' "$GROUND_TRUTH" \
    >"$E2E_WORK_DIR/canary/zz-canary.log"
  timeout 60 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$engine" --label canary \
    "$E2E_WORK_DIR/canary" >"$E2E_WORK_DIR/canary.out" 2>&1 || rc=$?
  if [ "$rc" != 1 ] || ! grep -q 'file=zz-canary.log$' "$E2E_WORK_DIR/canary.out"; then
    cat "$E2E_WORK_DIR/canary.out" >&2
    fail "I2 scan positive control ($engine): canary not detected"
  fi
  rm -rf -- "$E2E_WORK_DIR/canary" "$E2E_WORK_DIR/canary.out"
}

# pattern_canary: positive control of the fixed-string leak scans on the log directory.
pattern_canary() {
  mkdir -p "$E2E_WORK_DIR/canary-pattern"
  printf 'e2e-canary-%s\n' "$(rand_hex 16)" >"$E2E_WORK_DIR/canary-pattern/canary"
  cp "$E2E_WORK_DIR/canary-pattern/canary" "$E2E_LOG_DIR/zz-canary.log"
  [ "$(leak_scan "$E2E_LOG_DIR" "$E2E_WORK_DIR/canary-pattern" || true)" = "canary: zz-canary.log " ] \
    || fail "leak scan positive control: canary not detected"
  rm -rf -- "$E2E_LOG_DIR/zz-canary.log" "$E2E_WORK_DIR/canary-pattern"
}

# secret_hygiene D TARGET_LOG_GLOB...: the generated secrets nowhere in the console database, the
# exports, the agent's state (but its identity), the pages (but the session's CSRF token) and every
# log; the run's other registered values (NP) nowhere either, but in the target-side logs given
# (glob patterns of file names). Returns 1 on a leak (names logged, values never).
secret_hygiene() {
  local D="$1" leaks=0 leaked f l
  shift
  mkdir -p "$E2E_WORK_DIR/scan-secrets"
  cp "$D"/*.sql "$D"/*.json "$E2E_WORK_DIR/scan-secrets/"
  (cd "$D/state" && find . -type f ! -name identity.json -exec cp --parents {} "$E2E_WORK_DIR/scan-secrets/" \;)
  for pdir in "$P" "$NP"; do
    if ! leaked="$(leak_scan "$E2E_WORK_DIR/scan-secrets" "$pdir")"; then
      while IFS= read -r l; do log "LEAK (console database or agent state): $l"; done <<<"$leaked"
      leaks=1
    fi
  done
  rm -rf -- "$E2E_WORK_DIR/scan-secrets"
  for f in "$D"/pages/*; do
    leaked="$( { leak_scan "$f" "$P"; leak_scan "$f" "$NP"; } | grep -v '^csrf_token: ' || true)"
    if [ -n "$leaked" ]; then
      while IFS= read -r l; do log "LEAK (pages): $l"; done <<<"$leaked"
      leaks=1
    fi
  done
  if ! leaked="$(leak_scan "$E2E_LOG_DIR" "$P")"; then
    while IFS= read -r l; do log "LEAK (logs): $l"; done <<<"$leaked"
    leaks=1
  fi
  mkdir -p "$E2E_WORK_DIR/scan-logs"
  for f in "$E2E_LOG_DIR"/*; do
    local keep=1 g
    for g in "$@"; do
      # shellcheck disable=SC2053 # glob match on purpose
      [[ "$(basename "$f")" == $g ]] && keep=0
    done
    [ "$keep" = 1 ] && cp "$f" "$E2E_WORK_DIR/scan-logs/"
  done
  if ! leaked="$(leak_scan "$E2E_WORK_DIR/scan-logs" "$NP")"; then
    while IFS= read -r l; do log "LEAK (logs): $l"; done <<<"$leaked"
    leaks=1
  fi
  rm -rf -- "$E2E_WORK_DIR/scan-logs"
  return "$leaks"
}

# dump_logs SERVICE...: every service's log into the log directory.
dump_logs() {
  local svc
  for svc in "$@"; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc.log" 2>&1 || true
  done
}

# print_census LABEL: ADR-0053 decision 6 measurement. The agent's last event census line per engine
# (counts only: events spooled, overflowed, naming an unknown-object `*`) from the collected agent
# log; the console's per-target and per-principal counts (overflow flag included) and its events
# naming `*` by kind (source, action, principal kind, signals, databases; no other object name),
# read here from the console database (read-only; nothing when it is down); to the log and to
# census-LABEL.json / .md in CENSUS_OUT_DIR (default $E2E_LOG_DIR/census, uploaded by the CI jobs).
# Call after dump_logs; once that directory is redacted, summary_append adds the .md to the job
# summary. Never fails the run.
# summary_append FILE...: appends the existing files to the job summary (under GitHub Actions), only
# called on files already redacted (redact_dir / leak_scan in cleanup).
summary_append() {
  local f
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  for f in "$@"; do
    [ -f "$f" ] && cat -- "$f" >>"$GITHUB_STEP_SUMMARY"
  done
  return 0
}
print_census() {
  local line lib con="$E2E_WORK_DIR/census-console.json" star="$E2E_WORK_DIR/census-star.json" id=""
  lib="$(dirname "${BASH_SOURCE[0]}")/load/loadlib.py"
  [[ "${AGENT_ID:-}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] && id="$AGENT_ID"
  console_sql "$(python3 "$lib" census-sql ${id:+--agent-id "$id"})" >"$con" 2>/dev/null || rm -f -- "$con"
  console_sql "$(python3 "$lib" census-sql --star ${id:+--agent-id "$id"})" >"$star" 2>/dev/null || rm -f -- "$star"
  python3 "$lib" census --log "$E2E_LOG_DIR/agent.log" --label "$1" --console "$con" --star "$star" \
    --out-dir "${CENSUS_OUT_DIR:-$E2E_LOG_DIR/census}" 2>&1 \
    | while IFS= read -r line; do log "$line"; done || true
}
