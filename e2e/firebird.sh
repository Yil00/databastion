#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# End-to-end Firebird target (ROADMAP P10-D; ADR-0060 R39 (j), the host-identity refinement of
# 2026-10-31 R43 to R52, R52 item 2; the RELEASE.md gate "Firebird Audit end to end"): the console
# and the agent (the e2e images) with the dev Firebird 5.0.4 service (dev/firebird: uid 84, loopback
# only, WireCrypt Required, the system audit trace meeting the Partial proofs, the seed as `crm`).
# Compose: docker-compose.yml, docker-compose.firebird.yml and the run's generated
# $E2E_WORK_DIR/hostid.yml (project databastion-e2e-firebird). In order:
#   - Preconditions on the host's own identity files (e2e/firebird_hostid.py; in CI the runner's),
#     before anything starts: uids 84 and 10001 absent from its passwd file, outside its
#     subordinate and systemd ranges; its nsswitch.conf accepted (R47); the uid of the collision
#     step (1001 in CI) present. The run fails otherwise; it never edits a file nor picks other uids.
#   - The log volume's ACLs (R52 item 1): the file system keeps them; and, on a throwaway engine
#     with a 1 MB max_log_size, what the next log file gets after a rotation (measured, recorded).
#   - The layout (R52 item 2, R50): the agent in its container in the server's network and pid
#     namespaces, every container of that namespace without NET_RAW / NET_ADMIN, the Firebird root,
#     configuration and log directory read-only at the server's paths, the host identity files as
#     single-file read-only bind mounts; the server listening on loopback only.
#   - Discovery against dev/ground-truth.json; Audit enabled; `firebird.audit` reaching Partial
#     (`firebird_audit_trace`) through `firebird.audit.host_identity`, the readers check holding;
#     the agent's own statements never reported.
#   - A full read of seeded tables (`SELECT *`, `shape.full_table_read`) by E2E_EXPORTER raising a
#     critical incident (read -> incident time printed, limit 120 s); filtered SELECTs whose
#     literals are ground-truth values by E2E_ANALYST; the #82 marker cases: CREATE / ALTER USER
#     with marker passwords by E2E_ADMIN, a routine's returned marker, an EXECUTE STATEMENT inner
#     marker, a marker client process name.
#   - I2: no ground-truth value (names included), literal or marker in the console database, the
#     console and agent logs, the pages or the agent's state; no generated secret in any log.
#   - The real-kernel negative steps (R52 item 2, security review L7), after the gate's checks,
#     each asserting that the target is not Partial, the note `audit.log_readable_by_others`, and the
#     reason of the agent's local detail ("Firebird checked"): without `host_identity`
#     (`agent_in_container`); a declared path naming a file of the agent image itself
#     (`host_identity_refused (passwd: mount)`); the host's passwd mounted read-write (same reason);
#     the agent run as the host user's uid 1001 (`uid_collision`, its own enrollment).
# See e2e/README.md "Firebird target". Requires: docker (compose v2.24+), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-firebird}"
PROJECT="${E2E_FIREBIRD_PROJECT:-databastion-e2e-firebird}"
LOG_TAG="e2e-firebird"  # read by lib.sh
I2_CHECK="$HERE/i2_check.py"
HOSTID="$HERE/firebird_hostid.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
TARGET="fb-e2e"
ENGINE="firebird"
SOURCE="firebird_audit_trace"
POLICY_FULL="e2e firebird full read"
POLICY_READS="e2e firebird reads"
FULL_INCIDENT_LIMIT_S=120
SCAN_TIMEOUT_S=900
PARTIAL_TIMEOUT_S=300
EVENTS_TIMEOUT_S=240
STEP_TIMEOUT_S=240
SERVER_UID=84
AGENT_UID=10001
# The host user's uid of the collision step: the runner's (1001) in CI, never another one there.
COLLISION_UID="${E2E_FIREBIRD_COLLISION_UID:-1001}"
HOST_DIR=/run/databastion/host
FB_DB=/var/lib/firebird/data/crm.fdb
FB_LOG=/var/lib/firebird/audit/audit.log
# Tables the exporter reads whole (granted to E2E_READER, target-initdb/firebird-20-clients.sh).
EXPORT_TABLES=(CUSTOMERS PAYMENT_CARDS)
# The note of a failed readers check (R4, R48 item 5) and the notes Partial must not carry.
READERS_NOTE="audit.log_readable_by_others"
FORBIDDEN_NOTES="audit.log_readable_by_others audit.log_not_readable audit.trace_config_not_evaluated
  audit.records_dropped audit.log_records_ambiguous audit.partial_pending_first_record
  audit.source_not_configured audit.stream_stopped check.stage_failed check.timed_out privilege.refused"

# The Firebird image is the dev service's (dev/docker-compose.yml): the same pin.
dev_img="$(sed -n 's/.*DATABASTION_DEV_FIREBIRD_IMAGE:-\([^}]*\)}.*/\1/p' "$HERE/../dev/docker-compose.yml")"
e2e_img="$(sed -n 's/^x-firebird-image: &firebird-image \(.*\)$/\1/p' "$HERE/docker-compose.firebird.yml")"
if [ -z "$dev_img" ] || [ "$dev_img" != "$e2e_img" ]; then
  echo "the Firebird image of docker-compose.firebird.yml must be the one of dev/docker-compose.yml" >&2
  exit 1
fi
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_FIREBIRD_PROJECT
  [ "$COLLISION_UID" = 1001 ] || { echo "E2E_FIREBIRD_COLLISION_UID is for local runs only" >&2; exit 2; }
fi
case "$COLLISION_UID" in
  '' | *[!0-9]* | 0 | "$SERVER_UID" | "$AGENT_UID")
    echo "E2E_FIREBIRD_COLLISION_UID must be a host user's uid other than 0, 84 and 10001" >&2; exit 2 ;;
esac
export E2E_FB_COLLISION_UID="$COLLISION_UID"
umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-firebird.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"
HOSTID_YML="$E2E_WORK_DIR/hostid.yml"
COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.firebird.yml" -f "$HOSTID_YML")
# shellcheck source=lib.sh
. "$HERE/lib.sh"
SERVICES=(db migrate web worker proxy firebird-audit-init firebird)  # the agent: dump_agent
STEP="main"      # the agent container's step, for its log file
AGENT_SVC=agent  # the service of the agent container running now

# dump_agent: the running agent container's log as agent-<step>.log (agent.log for the main one).
dump_agent() {
  local f="agent-${STEP}.log"
  [ "$STEP" = main ] && f=agent.log
  compose logs --no-color --timestamps "$AGENT_SVC" >"$E2E_LOG_DIR/$f" 2>&1 || true
}

cleanup() {
  local status=$?
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs "${SERVICES[@]}"
  dump_agent
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  print_census e2e-firebird
  redact_dir "$E2E_LOG_DIR" "$P"
  redact_dir "$E2E_LOG_DIR" "$NP"
  summary_append "$E2E_LOG_DIR"/census/*.md "$E2E_LOG_DIR/acl.md"
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

# --------------------------------------------------------------------------- preconditions
# R52 item 2: the host's own identity files qualify, or the run fails here (never edited, no other
# uid picked). Counts and verdicts only in the log: no name, no content.
log "preconditions: the host's identity files (R45, R47, R48; uids ${SERVER_UID} and ${AGENT_UID}, collision uid ${COLLISION_UID})"
timeout 60 python3 -I "$HOSTID" check --uid "$SERVER_UID" --uid "$AGENT_UID" --present-uid "$COLLISION_UID" \
  --list "$E2E_WORK_DIR/hostid.list" >&2 || fail "the host's identity files do not meet the preconditions of R52 item 2 (above): the job fails, it never edits them nor picks other uids"
mapfile -t HOST_FILES <"$E2E_WORK_DIR/hostid.list"
log "identity files mounted: ${HOST_FILES[*]}"
kernel="$(uname -r)"
IFS=. read -r kmaj kmin _ <<<"$kernel"
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "${kmin%%[!0-9]*}" -lt 8 ]; }; then
  fail "kernel $kernel: openat2 and STATX_MNT_ID need Linux 5.8 or later (implementation note of 2026-10-31 b, item 7)"
fi
phase_done preconditions

# P10-E: the console must list `engine.firebird`, or the agent holds the target's items (ADR-0042)
# and the run cannot pass. Checked on the console sources the image is built from (a local run with
# a prebuilt E2E_CONSOLE_IMAGE trusts that image instead), after the preconditions above.
if [ -z "${E2E_CONSOLE_IMAGE:-}" ] \
    && ! sed -n '/^export const CONSOLE_ACCEPTS = \[/,/\]/p' "$HERE/../console/src/server/agent-api/capabilities.ts" \
      | grep -qF '"engine.firebird"'; then
  fail "the console does not list engine.firebird in CONSOLE_ACCEPTS (ROADMAP P10-E, Firebird part): the agent holds every item of a firebird target until it does (ADR-0042)"
fi

# I2 scanner positive control: every searchable value of the engine is in the committed seed.
timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  "$HERE/../dev/seed/out/firebird.sql" >&2 || fail "I2 scanner positive control failed for $ENGINE (see above)"

# --------------------------------------------------------------------------- secrets, CA, files
console_secrets
put_secret target_fb_sysdba_password "$(rand_password 20)"  # SYSDBA: seeding and the markers only
put_secret target_agent_password "$(rand_password 20)"      # DATABASTION_AGENT (decision 4)
put_secret target_client_password "$(rand_password 20)"     # E2E_EXPORTER / E2E_ANALYST / E2E_ADMIN
# The #82 marker cases: values that must reach no console-side artifact and no log but the server's.
MARK_PW1="Fbpw1$(rand_hex 12)"
MARK_PW2="Fbpw2$(rand_hex 12)"
MARK_RET="fbret$(rand_hex 12)"
MARK_ES="fbexs$(rand_hex 12)"
MARK_PROC="fbproc$(rand_hex 12)"
register_value dcl_marker_1 "$MARK_PW1"
register_value dcl_marker_2 "$MARK_PW2"
register_value routine_marker "$MARK_RET"
register_value execute_statement_marker "$MARK_ES"
register_value process_marker "$MARK_PROC"
test_ca "e2e Firebird"
mkdir -p "$E2E_WORK_DIR/firebird"

# agent_yaml FILE HOST_IDENTITY: the agent's configuration; HOST_IDENTITY: `declared` (the mounted
# files), `image` (passwd naming the agent image's own /etc/passwd) or `none` (no block).
agent_yaml() {
  local f="$E2E_WORK_DIR/agent/$1" n
  {
    cat <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  max_sample_rows: 100
  statement_timeout_ms: 5000
  max_scan_duration_s: 900
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
EOF
    if [ "$2" != none ]; then
      echo "        host_identity:"
      for n in "${HOST_FILES[@]}"; do
        n="$(basename "$n")"
        if [ "$n" = passwd ] && [ "$2" = image ]; then
          echo "          passwd: /etc/passwd"
        else
          echo "          ${n%.conf}: ${HOST_DIR}/${n}"
        fi
      done
    fi
  } >"$f"
  chmod 0644 "$f"
}
agent_yaml agent.yaml declared
agent_yaml agent-noid.yaml none
agent_yaml agent-image.yaml image
agent_yaml agent-uid.yaml declared

# hostid_yml SERVICE PASSWD_MODE: the host identity files as single-file bind mounts of SERVICE,
# read-only (`ro`), or the passwd file read-write (`rw`, a negative step); never a created path.
hostid_yml() {
  local f n ro
  {
    printf 'services:\n  %s:\n    volumes:\n' "$1"
    for f in "${HOST_FILES[@]}"; do
      n="$(basename "$f")"
      ro=true
      [ "$n" = passwd ] && [ "$2" = rw ] && ro=false
      printf '      - type: bind\n        source: %s\n        target: %s/%s\n        read_only: %s\n        bind:\n          create_host_path: false\n' \
        "$f" "$HOST_DIR" "$n" "$ro"
    done
  } >"$HOSTID_YML"
}
hostid_yml agent ro

# The rotation measurement's trace configuration (firebird-rotation): every database of the
# throwaway engine, 1 MB per log file.
cat >"$E2E_WORK_DIR/firebird/rotation-fbtrace.conf" <<'EOF'
database
{
	enabled = true
	log_filename = /var/lib/firebird/audit/audit.log
	max_log_size = 1
	log_statement_finish = true
	print_perf = true
	time_threshold = 0
}
EOF
chmod 0755 "$E2E_WORK_DIR/firebird"
chmod 0644 "$E2E_WORK_DIR/firebird/rotation-fbtrace.conf"

# --------------------------------------------------------------------------- helpers
# fb_isql USER SECRET [ISQL_ARGS...] < SQL: the image's isql inside the server's container (its
# account, uid 84; no capability), over loopback TCP to crm (wire encryption required by the
# server), as USER; the password read there from the secret file into ISC_PASSWORD, never on a
# command line. Output: none kept; errors to a private file.
fb_isql() {
  local user="$1" secret="$2"
  shift 2
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 180 docker compose "${COMPOSE_ARGS[@]}" exec -T firebird bash -c \
    'ISC_PASSWORD="$(cat "/run/secrets/$1")"; export ISC_PASSWORD; u="$2"; shift 2
     exec /opt/firebird/bin/isql -q -b -user "$u" "$@" "127.0.0.1/3050:'"$FB_DB"'"' \
    bash "$secret" "$user" "$@" >/dev/null 2>"$E2E_WORK_DIR/client.err"
}
client_error_code() {
  local code
  code="$(grep -m 1 -oE 'SQLSTATE = [0-9A-Z]+' "$E2E_WORK_DIR/client.err" 2>/dev/null | head -n 1)"
  printf '%s' "${code:-none}"
}
# last_checked SERVICE: the agent's last "Firebird checked" line of the target (its local detail:
# the readers check's reason, never a path or content), from SERVICE's current container.
last_checked() {
  timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix "$1" 2>/dev/null \
    | grep -F '"Firebird checked"' | grep -F "\"target_id\":\"${TARGET}\"" | tail -n 1 || true
}
# readers_detail LINE: the readers check's reason of a "Firebird checked" line, or `holds`.
readers_detail() {
  local d
  d="$(jq -r '.fields.detail // .detail // empty' <<<"$1" 2>/dev/null | tr ';' '\n' \
    | sed -n 's/^ *readers check: //p' | head -n 1)"
  printf '%s' "${d:-holds}"
}
# status_after AGENT_ID TIME: the target's status as the console stored it from a heartbeat
# received after TIME: "level|source|notes", empty before.
status_after() {
  console_sql "SELECT audit_level || '|' || coalesce(audit_source, '') || '|' ||
      coalesce((SELECT string_agg(n->>'code', ' ' ORDER BY n->>'code') FROM jsonb_array_elements(coalesce(notes, '[]'::jsonb)) n), '')
    FROM agent_targets WHERE agent_id = '$1' AND target_id = '${TARGET}' AND last_reported_at > '$2'::timestamptz"
}

# --------------------------------------------------------------------------- build + start
IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}"
  databastion-dev/firebird-acl-init:5.0.4)
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing images ${IMAGES[*]}"
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "E2E_SKIP_BUILD=1 but image $img is missing"
  done
else
  log "building images (web, agent, firebird-audit-init)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent firebird-audit-init
fi
phase_done build

# --------------------------------------------------------------------------- ACLs of the volume
# R52 item 1: whether the log volume's file system keeps ACLs (the layout's entries read back), and,
# on a throwaway embedded engine of the same image with a 1 MB max_log_size, what the next log file
# gets from the directory's default ACL after a rotation (measured and recorded in acl.md).
log "ACLs: a rotation on a throwaway engine (firebird-rotation, no network)"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T firebird-rotation-init \
  >"$E2E_LOG_DIR/firebird-rotation-init.log" 2>&1 || fail "firebird-rotation-init failed"
# shellcheck disable=SC2016 # the container shell's script
timeout 300 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T firebird-rotation '
  printf "CREATE DATABASE '\''/tmp/rotation.fdb'\'';\nEXIT;\n" | /opt/firebird/bin/isql -q -b -user SYSDBA
  for i in $(seq 1 8000); do echo "SELECT $i FROM RDB\$DATABASE;"; done \
    | /opt/firebird/bin/isql -q -b -user SYSDBA /tmp/rotation.fdb >/dev/null
  echo "rotation directory:"; ls -ln /var/lib/firebird/audit | sed "s/^/  /"' \
  >"$E2E_LOG_DIR/firebird-rotation.log" 2>&1 || fail "the rotation run failed (firebird-rotation.log)"
# shellcheck disable=SC2016 # the container shell's script
acls="$(timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T firebird-acl-inspect '
  for d in /r; do
    echo "fs $(stat -f -c %T "$d")"
    for f in "$d"/*; do echo "file $(basename "$f") $(stat -c "%a %u %g %s" "$f")"; getfacl -cpn "$f" | sed "s/^/  /"; done
    echo "dir"; getfacl -cpn "$d" | sed "s/^/  /"
  done' 2>&1)" || fail "cannot read the rotation volume's ACLs"
printf '%s\n' "$acls" >>"$E2E_LOG_DIR/firebird-rotation.log"
rotated="$(grep -E '^file ' <<<"$acls" | grep -cvE '^file audit\.log ' || true)"
# The rotated files' names, digits masked (the agent examines `<log>.*` and `<log>-*` next to it, R4).
rot_names="$(grep -E '^file ' <<<"$acls" | grep -vE '^file audit\.log ' | awk '{print $2}' | sed 's/[0-9]/N/g' | sort -u | tr '\n' ' ')"
[ "$rotated" -ge 1 ] || fail "the throwaway engine did not rotate its log at max_log_size = 1 (firebird-rotation.log)"
# The next log file (audit.log, created by the engine after the rotation) and its named entry.
next="$(awk '/^file audit\.log /{f=1; next} /^(file|dir)/{f=0} f' <<<"$acls")"
grep -qE '^  user:10001:r--' <<<"$next" || fail "the next log file after a rotation has no user:10001 entry: the default ACL was not inherited"
eff="r--"
if grep -qE '^  user:10001:r--[[:space:]]+#effective:' <<<"$next"; then
  eff="$(sed -n 's/^  user:10001:r--[[:space:]]*#effective:\(...\).*/\1/p' <<<"$next" | head -n 1)"
fi
# shellcheck disable=SC2016 # Markdown code spans
{
  printf '### e2e-firebird: audit log ACLs (ADR-0060 R52 item 1)\n\n'
  printf -- '- Rotation on a throwaway 5.0.4 engine (`max_log_size = 1`): %s rotated file(s); the next `audit.log` inherits `user:10001:r--` from the default ACL, effective `%s` (`%s`).\n' \
    "$rotated" "$eff" "$(grep -E '^  (user::|mask::|group::|other::)' <<<"$next" | tr -d ' ' | tr '\n' ' ')"
  # shellcheck disable=SC2016 # Markdown code spans
  printf -- '- Rotated file names (digits as N): `%s`; the agent examines `audit.log.*` and `audit.log-*` next to the log (ADR-0060 R4).\n' "${rot_names% }"
} >"$E2E_LOG_DIR/acl.md"
log "ACLs: after a rotation the next log file inherits user:10001:r-- (effective ${eff}); ${rotated} rotated file(s): ${rot_names}"
if [ "$eff" != "r--" ] && [ "${GITHUB_ACTIONS:-}" = true ]; then
  echo "::warning title=e2e-firebird ACLs::the next log file after a rotation inherits user:10001 with effective rights ${eff} (the server's create mode masks the default ACL)"
fi

log "starting the console and Firebird (first start: the ACL layout, the seed, the accounts)"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy firebird
start_console
deadline=$(( $(date +%s) + 300 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q firebird)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "firebird not healthy within 300 s"
  sleep 2
done
[ "$(compose ps -a --format '{{.ExitCode}}' firebird-audit-init)" = "0" ] || fail "firebird-audit-init did not succeed"
FB_CID="$(compose ps -q firebird)"
docker inspect "$FB_CID" --format '{{json .Config.Env}}' | jq -e 'any(test("PASSWORD")) | not' >/dev/null \
  || fail "a password in the firebird container's environment"
# The layout on the server's volume (R52 item 1): the file system keeps the ACLs.
# shellcheck disable=SC2016 # the container shell's script
acls="$(timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T firebird-acl-inspect '
  echo "fs $(stat -f -c %T /a)"; echo "dir"; getfacl -cpn /a; echo "log"; getfacl -cpn /a/audit.log' 2>&1)" \
  || fail "cannot read the log volume's ACLs"
printf '%s\n' "$acls" >"$E2E_LOG_DIR/firebird-acl.log"
fs="$(sed -n 's/^fs //p' <<<"$acls")"
for want in 'user:10001:r-x' 'default:user:10001:r--' 'default:mask::r--' 'user:10001:r--' 'mask::r--'; do
  grep -qxF "$want" <<<"$acls" || fail "the log volume (${fs}) does not keep the layout's ACL entry ${want} (firebird-acl.log)"
done
for bad in 'group::r' 'other::r' 'default:group::r' 'default:other::r'; do
  ! grep -q "^${bad}" <<<"$acls" || fail "the log volume grants ${bad} (firebird-acl.log)"
done
# shellcheck disable=SC2016 # Markdown code spans
printf -- '- The log volume (`%s`) keeps the named-user ACLs of the layout (access and default entries read back).\n' "$fs" >>"$E2E_LOG_DIR/acl.md"
log "ACLs: the log volume's file system (${fs}) keeps the layout's named-user ACLs"
# Loopback only (decision 3): every listening TCP socket of the namespace is on 127.0.0.0/8 (the
# server on 127.0.0.1, Docker's embedded DNS resolver on 127.0.0.11) or ::1.
# shellcheck disable=SC2016 # the container shell's script
sockets="$(compose exec -T firebird sh -c 'cat /proc/net/tcp; if [ -e /proc/net/tcp6 ]; then cat /proc/net/tcp6; fi')" \
  || fail "cannot read the server namespace's sockets"
listen="$(awk '$4 == "0A" { split($2, a, ":"); print a[1] }' <<<"$sockets" | sort -u | tr '\n' ' ')"
for a in $listen; do
  case "$a" in
    ??????7F | 00000000000000000000000001000000) ;;
    *) fail "a socket of the server's namespace listens on another address than the loopback ($a)" ;;
  esac
done
[ -n "$listen" ] || fail "nothing listens in the server's namespace"
log "firebird: listening on the loopback only ($(wc -w <<<"$listen") address(es))"
inspect_scan "after the start"
phase_done start

# --------------------------------------------------------------------------- enroll + layout
log "bootstrapping the administrator; enrolling the agent"
admin_login e2e-firebird
enroll_agent target_agent_password
log "enrolled agent $AGENT_ID; starting it in the server's network and pid namespaces"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
STEP_T="$(console_sql "SELECT now()")"
AGENT_CID="$(compose ps -q agent)"
# R52 item 2, R50: the namespaces, the capabilities, the read-only mounts at the server's paths and
# the single-file read-only bind mounts of the host's own identity files.
layout() { # container uid passwd_rw
  local want_rw="${3:-false}" f n
  docker inspect "$1" | jq -e --arg fb "$FB_CID" --arg user "$2:$2" '.[0] as $c
      | $c.HostConfig.NetworkMode == "container:" + $fb and $c.HostConfig.PidMode == "container:" + $fb
      and ($c.HostConfig.CapDrop | index("ALL")) != null and ($c.HostConfig.CapAdd // [] | length) == 0
      and $c.HostConfig.ReadonlyRootfs and ($c.HostConfig.GroupAdd // [] | length) == 0
      and $c.Config.User == $user
      and all(["/opt/firebird", "/opt/firebird/firebird.conf", "/databastion/fbtrace.conf",
               "/var/lib/firebird/audit"][]; . as $d | any($c.Mounts[]; .Destination == $d and .RW == false))
      and ([$c.Mounts[] | select(.Destination == "/var/lib/firebird/data")] | length) == 0' >/dev/null \
    || fail "the agent's container is not in the layout of R52 item 2 (namespaces, capabilities, read-only mounts)"
  for f in "${HOST_FILES[@]}"; do
    n="$(basename "$f")"
    rw=false
    [ "$n" = passwd ] && rw="$want_rw"
    docker inspect "$1" | jq -e --arg s "$f" --arg d "${HOST_DIR}/${n}" --argjson rw "$rw" \
      'any(.[0].Mounts[]; .Type == "bind" and .Source == $s and .Destination == $d and .RW == $rw)' >/dev/null \
      || fail "the host's ${f} is not a single-file bind mount at ${HOST_DIR}/${n} (RW ${rw})"
  done
  # Every container of the server's network namespace drops NET_RAW and NET_ADMIN (decision 3).
  docker inspect "$FB_CID" | jq -e '(.[0].HostConfig.CapDrop | index("ALL")) != null' >/dev/null \
    || fail "the firebird container keeps capabilities"
  local id
  for id in $(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}"); do
    docker inspect "$id" | jq -e --arg fb "$FB_CID" '.[0].HostConfig.NetworkMode != "container:" + $fb
        or ((.[0].HostConfig.CapDrop // []) as $d | ($d | index("ALL")) != null
            or (($d | index("NET_RAW")) != null and ($d | index("NET_ADMIN")) != null))' >/dev/null \
      || fail "a container of the server's network namespace keeps NET_RAW or NET_ADMIN"
  done
}
layout "$AGENT_CID" "$AGENT_UID"
log "layout: the agent in the server's network and pid namespaces, no capability, read-only root, mounts at the server's paths; ${#HOST_FILES[@]} host file(s) bind-mounted read-only"
wait_online 180 "${TARGET}:firebird"
t="$(target_json "$TARGET")"
log "target ${TARGET}: $(target_summary "$t")"
# Before the Audit stream runs: never Partial (no probe read back yet), and the readers check holds
# with the declared files from the first check.
jq -e '.auditLevel != "partial" and .auditLevel != "full"' <<<"$t" >/dev/null \
  || fail "${TARGET}: level $(jq -r .auditLevel <<<"$t") before the Audit stream"
deadline=$(( $(date +%s) + 120 ))
until line="$(last_checked agent)" && [ -n "$line" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no \"Firebird checked\" line of ${TARGET} in the agent log within 120 s"
  sleep 2
done
why="$(readers_detail "$line")"
[ "$why" = holds ] || fail "${TARGET}: the readers check fails with the declared host files (${why})"
log "${TARGET}: the readers check holds with the declared host identity files"
inspect_scan "with the agent"
phase_done enroll

# --------------------------------------------------------------------------- Discovery
log "Discovery: ${TARGET}"
scan_targets "$SCAN_TIMEOUT_S" "$TARGET"
findings_json "$TARGET" >"$E2E_WORK_DIR/findings.json" || fail "cannot read the findings"
timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  --require-expected-classifiers --forbid-negative-controls "$E2E_WORK_DIR/findings.json" >&2 \
  || fail "findings check of ${TARGET} failed (see above)"
log "${TARGET}: $(jq length "$E2E_WORK_DIR/findings.json") finding(s)"
rm -f -- "$E2E_WORK_DIR/findings.json"
phase_done discovery

# --------------------------------------------------------------------------- Audit: Partial
log "Audit: policies '${POLICY_FULL}' (shape.full_table_read), '${POLICY_READS}' (read)"
create_policy "$POLICY_FULL" critical "$(jq -nc --arg t "$TARGET" '{signals: ["shape.full_table_read"], target_ids: [$t]}')"
create_policy "$POLICY_READS" medium "$(jq -nc --arg t "$TARGET" '{event_actions: ["read"], target_ids: [$t]}')"
log "Audit: enabling Audit on ${TARGET}"
enable_audit "$TARGET"
log "Audit: waiting for Partial (${SOURCE}, at most ${PARTIAL_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + PARTIAL_TIMEOUT_S ))
while :; do
  t="$(target_json "$TARGET")"
  notes="$(notes_of "$t")"
  bad=""
  # shellcheck disable=SC2086 # a list of note codes
  for c in $FORBIDDEN_NOTES; do [[ " $notes " != *" $c "* ]] || bad+=" $c"; done
  if jq -e --arg s "$SOURCE" '.auditLevel == "partial" and .auditSource == $s' <<<"$t" >/dev/null \
      && [ -z "$bad" ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "${TARGET}: level $(jq -r .auditLevel <<<"$t") / source $(jq -r .auditSource <<<"$t"), notes '${notes}' (expected partial, ${SOURCE}, none of:${bad:- the forbidden notes}); agent detail: readers check $(readers_detail "$(last_checked agent)")"
  sleep 3
done
why="$(readers_detail "$(last_checked agent)")"
[ "$why" = holds ] || fail "${TARGET}: Partial while the agent's last check reports the readers check '${why}'"
log "${TARGET}: audit level partial (${SOURCE}) through firebird.audit.host_identity; notes: ${notes}"
# The agent's own statements (check() and its read-back probe, the stream's catalog reads) are never
# reported: two heartbeats later, no event at all (nobody else used the server since the stream
# started).
sleep 30
n="$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
if [ "$n" != 0 ]; then
  console_sql "SELECT string_agg(DISTINCT coalesce(db_user, 'fp') || ' ' || action, '; ')
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'" >&2 || true
  fail "${TARGET}: $n event(s) before any client statement: the agent's own activity surfaced"
fi
log "Audit: no event before the first client statement"
phase_done partial

# --------------------------------------------------------------------------- client traffic
# The exporter: a whole-table SELECT of each granted table (shape.full_table_read).
log "Audit: full reads of ${EXPORT_TABLES[*]} as E2E_EXPORTER"
T0_MS="$(date +%s%3N)"
printf 'SELECT * FROM %s;\n' "${EXPORT_TABLES[@]}" | fb_isql E2E_EXPORTER target_client_password \
  || fail "the exporter's full reads failed ($(client_error_code))"
deadline=$(( $(date +%s) + FULL_INCIDENT_LIMIT_S ))
until [ "$(console_sql "SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
    AND policy_name = '${POLICY_FULL}' AND principal = 'E2E_EXPORTER'")" -ge 1 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no '${POLICY_FULL}' incident of E2E_EXPORTER within ${FULL_INCIDENT_LIMIT_S} s of the full read"
  sleep 1
done
FULL_LATENCY_MS=$(( $(date +%s%3N) - T0_MS ))
log "Audit: full read -> critical incident: ${FULL_LATENCY_MS} ms (limit ${FULL_INCIDENT_LIMIT_S} s)"

# The analyst: filtered SELECTs whose literals are ground-truth values (in the statement texts the
# trace keeps; the agent must drop them), from a client process whose path is a marker.
gt_needle() { # OBJECT FIELD: "L<i>.v0<TAB><value>" of the first value of a location
  jq -r --arg e "$ENGINE" --arg o "$1" --arg f "$2" '.locations | to_entries[]
    | select(.value.engine == $e and .value.object == $o and .value.field == $f
             and ((.value.values // []) | length) > 0)
    | "L\(.key).v0\t\(.value.values[0])"' "$GROUND_TRUTH" | head -n 1
}
IFS=$'\t' read -r email_id email < <(gt_needle CUSTOMERS EMAIL)
IFS=$'\t' read -r iban_id iban < <(gt_needle PAYMENT_CARDS IBAN)
if [ -z "${email:-}" ] || [ -z "${iban:-}" ]; then fail "no ground-truth e-mail / IBAN for the literal queries"; fi
LITERAL_IDS="$email_id $iban_id"
{
  printf "SELECT FIRST_NAME, LAST_NAME FROM CUSTOMERS WHERE EMAIL = '%s';\n" "${email//\'/\'\'}"
  printf "SELECT CARD_HOLDER FROM PAYMENT_CARDS WHERE IBAN = '%s';\n" "${iban//\'/\'\'}"
} >"$E2E_WORK_DIR/analyst.sql"
unset email iban
log "Audit: filtered SELECTs with ground-truth literals as E2E_ANALYST ($LITERAL_IDS), from a marker client path"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
timeout 180 docker compose "${COMPOSE_ARGS[@]}" exec -T firebird bash -c '
  d="/tmp/$1"; mkdir -p "$d"; cp /opt/firebird/bin/isql "$d/isql"
  ISC_PASSWORD="$(cat /run/secrets/target_client_password)"; export ISC_PASSWORD
  LD_LIBRARY_PATH=/opt/firebird/lib FIREBIRD=/opt/firebird "$d/isql" -q -b -user E2E_ANALYST "127.0.0.1/3050:$2"
  rc=$?; rm -rf "$d"; exit "$rc"' bash "$MARK_PROC" "$FB_DB" \
  <"$E2E_WORK_DIR/analyst.sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" \
  || fail "the analyst's queries failed ($(client_error_code))"
rm -f -- "$E2E_WORK_DIR/analyst.sql"

# The admin: password-bearing DCL (the #82 rule; decision 6): CREATE and ALTER USER with marker
# passwords, then DROP USER, with the security database's admin role (RDB$ADMIN).
log "Audit: CREATE / ALTER / DROP USER with marker passwords as E2E_ADMIN"
{
  printf "CREATE USER E2E_DCL_PROBE PASSWORD '%s' USING PLUGIN Srp;\nCOMMIT;\n" "$MARK_PW1"
  printf "ALTER USER E2E_DCL_PROBE PASSWORD '%s' USING PLUGIN Srp;\nCOMMIT;\n" "$MARK_PW2"
  printf 'DROP USER E2E_DCL_PROBE USING PLUGIN Srp;\nCOMMIT;\n'
} | fb_isql E2E_ADMIN target_client_password -role "RDB\$ADMIN" || fail "the admin's DCL failed ($(client_error_code))"

# SYSDBA: a routine's returned marker and an EXECUTE STATEMENT inner marker (the #82 cases the stock
# tools can write, as dev/firebird/it.sh), the function dropped afterwards.
log "Audit: a routine's returned marker and an EXECUTE STATEMENT marker as SYSDBA"
{
  printf 'SET TERM ^ ;\n'
  printf "CREATE FUNCTION F_E2E_MARKER RETURNS VARCHAR(40) AS BEGIN RETURN '%s'; END^\n" "$MARK_RET"
  printf "EXECUTE BLOCK AS DECLARE X VARCHAR(40); BEGIN EXECUTE STATEMENT 'SELECT ''%s'' FROM RDB\$DATABASE' INTO X; END^\n" "$MARK_ES"
  printf 'SET TERM ; ^\nCOMMIT;\n'
  # shellcheck disable=SC2016 # a Firebird name
  printf 'SELECT F_E2E_MARKER() FROM RDB$DATABASE;\nDROP FUNCTION F_E2E_MARKER;\nCOMMIT;\n'
} | fb_isql SYSDBA target_fb_sysdba_password || fail "the SYSDBA marker statements failed ($(client_error_code))"
rm -f -- "$E2E_WORK_DIR/client.err"
phase_done traffic

# --------------------------------------------------------------------------- Audit checks
events_state() {
  console_sql "SELECT concat_ws(',',
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'E2E_EXPORTER' AND signals ? 'shape.full_table_read'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'E2E_ANALYST' AND action = 'read'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'E2E_ADMIN'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'SYSDBA'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND policy_name = '${POLICY_READS}' AND principal = 'E2E_ANALYST'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND evaluated_at IS NULL))"
}
log "Audit: waiting for the events and incidents (at most ${EVENTS_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + EVENTS_TIMEOUT_S ))
while :; do
  st="$(events_state)" || fail "cannot read the Audit state"
  IFS=, read -r n_full n_reads n_admin n_sysdba n_inc_r n_pending <<<"$st"
  if [ "$n_full" -ge 1 ] && [ "$n_reads" -ge 1 ] && [ "$n_admin" -ge 1 ] && [ "$n_sysdba" -ge 1 ] \
      && [ "$n_inc_r" -ge 1 ] && [ "$n_pending" = 0 ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "Audit: events / incidents incomplete within ${EVENTS_TIMEOUT_S} s: full_table_read ${n_full}, analyst reads ${n_reads}, admin ${n_admin}, SYSDBA ${n_sysdba}, incidents reads ${n_inc_r}, not evaluated ${n_pending}"
  sleep 3
done
log "Audit: exporter events with shape.full_table_read ${n_full}; analyst reads ${n_reads}; admin ${n_admin}; SYSDBA ${n_sysdba}"
# The exporter's full reads and the analyst's events name the tables they read (compared in SQL:
# only the verdict reaches the job log, never an object name).
objs="$(console_sql "SELECT concat_ws(',',
    bool_or(e.db_user = 'E2E_EXPORTER' AND o->>'object' = 'CUSTOMERS'),
    bool_or(e.db_user = 'E2E_EXPORTER' AND o->>'object' = 'PAYMENT_CARDS'),
    bool_or(e.db_user = 'E2E_ANALYST' AND o->>'object' = 'CUSTOMERS'),
    bool_or(e.db_user = 'E2E_ANALYST' AND o->>'object' = 'PAYMENT_CARDS'))
  FROM access_events e, jsonb_array_elements(e.objects) o WHERE e.agent_id = '${AGENT_ID}'
  AND e.target_id = '${TARGET}'")"
[ "$objs" = "t,t,t,t" ] \
  || fail "Audit: the exporter's and the analyst's events should name CUSTOMERS and PAYMENT_CARDS (${objs}; $(objects_summary "$TARGET" "$ENGINE" "e.db_user IN ('E2E_EXPORTER', 'E2E_ANALYST')"))"
events_json "$TARGET" >"$E2E_WORK_DIR/events.json" || fail "cannot read the access events"
incidents_json "$TARGET" >"$E2E_WORK_DIR/incidents.json" || fail "cannot read the incidents"
jq -e --arg s "$SOURCE" 'all(.[]; .source == $s)' "$E2E_WORK_DIR/events.json" >/dev/null \
  || fail "Audit: an event of ${TARGET} has another source"
log "Audit: principals $(jq -c '[.[] | (.db_user // "-")] | unique' "$E2E_WORK_DIR/events.json"), actions $(jq -c '[.[].action] | unique' "$E2E_WORK_DIR/events.json")"
timeout 60 python3 "$I2_CHECK" audit --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --agent-account DATABASTION_AGENT \
  --events "$E2E_WORK_DIR/events.json" --incidents "$E2E_WORK_DIR/incidents.json" \
  --require-event "E2E_EXPORTER:shape.full_table_read" --require-event E2E_ANALYST --require-event E2E_ADMIN \
  --require-incident "${POLICY_FULL}:E2E_EXPORTER" --require-incident "${POLICY_READS}:E2E_ANALYST" >&2 \
  || fail "Audit check of ${TARGET} failed (see above)"
rm -f -- "$E2E_WORK_DIR/events.json" "$E2E_WORK_DIR/incidents.json"

# The source side (positive control of the scans below): the server's trace log holds the analyst's
# literals (read as the server's account, kept private, never uploaded); which markers it holds is
# recorded (the trace may mask a password).
timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T firebird cat "$FB_LOG" >"$E2E_WORK_DIR/target-audit.log" \
  || fail "cannot read the server's trace log"
needles=()
for id in $LITERAL_IDS; do needles+=(--needle "$id"); done
rc=0
timeout 120 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  --label "firebird trace log (positive control)" "${needles[@]}" "$E2E_WORK_DIR/target-audit.log" \
  >"$E2E_WORK_DIR/literal-control.out" 2>&1 || rc=$?
for id in $LITERAL_IDS; do
  if [ "$rc" != 1 ] || ! grep -q "^LEAK ${id//./\\.} " "$E2E_WORK_DIR/literal-control.out"; then
    fail "Audit: literal $id not in the server's trace log (positive control)"
  fi
done
in_trace=""
for m in "$NP"/*; do
  if LC_ALL=C grep -qFf "$m" "$E2E_WORK_DIR/target-audit.log"; then in_trace+=" $(basename "$m")"; fi
done
grep -qF "$MARK_PROC" "$E2E_WORK_DIR/target-audit.log" || fail "Audit: the marker client path is not in the server's trace log (positive control)"
log "Audit: the trace log holds the literals ($LITERAL_IDS) and the markers:${in_trace:- none} (positive controls; the agent must drop them all)"
rm -f -- "$E2E_WORK_DIR/target-audit.log" "$E2E_WORK_DIR/literal-control.out"
phase_done audit

# --------------------------------------------------------------------------- I2 and secret hygiene
log "I2: the console database, the logs, the pages and the agent's state"
dump_logs "${SERVICES[@]}"
dump_agent
for f in agent.log web.log worker.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the scans would prove nothing"
done
# Decision 6 and R44 item 4: no path of the target's files reaches the agent's log.
for needle in "$FB_DB" "$FB_LOG" "$HOST_DIR"; do
  ! grep -qF "$needle" "$E2E_LOG_DIR/agent.log" || fail "the agent logged a path of the target's files"
done
D="$E2E_WORK_DIR/dump"
collect_console_side "$D" "$TARGET"
grep -qF 'E2E_EXPORTER' "$D/pages/incidents.html" || fail "the incidents page does not list E2E_EXPORTER (page scan control)"
grep -qF "$TARGET" "$D/pages/findings.html" || fail "the findings page does not name ${TARGET} (page scan control)"
i2_failed=0
i2_canary "$ENGINE"
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "firebird console side" \
  "$D" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "firebird logs" \
  --exclude 'firebird.log' "$E2E_LOG_DIR" >&2 || i2_failed=1
needles=()
for id in $LITERAL_IDS; do needles+=(--needle "$id"); done
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "firebird literals" \
  "${needles[@]}" --exclude 'firebird.log' "$D" "$E2E_LOG_DIR" >&2 || i2_failed=1
secret_files=()
for m in "$NP"/*; do secret_files+=(--secret-file "$m"); done
timeout 300 python3 "$I2_CHECK" scan --label "firebird #82 markers" "${secret_files[@]}" \
  --exclude 'firebird.log' "$D" "$E2E_LOG_DIR" >&2 || i2_failed=1
pattern_canary
leaks=0
secret_hygiene "$D" 'firebird.log' || leaks=1
log "I2: $(find "$P" -type f | wc -l) secret(s) and $(find "$NP" -type f | wc -l) marker(s) searched"
rm -rf -- "$D"
[ "$i2_failed" = 0 ] || fail "invariant I2: ground-truth value(s), literal(s) or marker(s) of the firebird target in clear text (ids above)"
[ "$leaks" = 0 ] || fail "a secret or a marker reached the console, a log or the agent's state (names above)"
phase_done i2

# --------------------------------------------------------------------------- negative steps
# R52 item 2 (security review L7), on the real kernel, after the gate's checks: each step replaces
# the agent's container (the same identity, or for the uid step its own), waits for a "Firebird
# checked" line with the expected reason and for a heartbeat after the step's start, and asserts:
# not Partial, the note audit.log_readable_by_others. Control first: the main agent's last check
# holds the readers check and its stored status has no such note.
why="$(readers_detail "$(last_checked agent)")"
[ "$why" = holds ] || fail "control: the main agent's readers check fails (${why}) before the negative steps"
ctl="$(status_after "$AGENT_ID" "$STEP_T")"
[[ " ${ctl##*|} " != *" ${READERS_NOTE} "* ]] || fail "control: the main agent's status already has ${READERS_NOTE}"
log "negative steps: control holds (readers check holds; level ${ctl%%|*}; no ${READERS_NOTE})"

# step NAME SERVICE AGENT_ID CONFIG PASSWD_MODE REASON: one negative step.
step() {
  local name="$1" svc="$2" id="$3" config="$4" mode="$5" reason="$6" deadline line why st cid
  dump_agent
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools rm -sf agent agent-uid >/dev/null 2>&1 || true
  STEP="$name" AGENT_SVC="$svc"
  hostid_yml "$svc" "$mode"
  export E2E_FB_AGENT_CONFIG="$config"
  STEP_T="$(console_sql "SELECT now()")"
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools up -d --no-deps "$svc" >/dev/null
  cid="$(compose --profile tools ps -q "$svc")"
  [ -n "$cid" ] || fail "step ${name}: the agent's container did not start"
  if [ "$svc" = agent-uid ]; then
    layout "$cid" "$COLLISION_UID" "$([ "$mode" = rw ] && echo true || echo false)"
  else
    layout "$cid" "$AGENT_UID" "$([ "$mode" = rw ] && echo true || echo false)"
  fi
  deadline=$(( $(date +%s) + STEP_TIMEOUT_S ))
  while :; do
    line="$(last_checked "$svc")"
    why="$(readers_detail "$line")"
    st="$(status_after "$id" "$STEP_T")"
    if [ -n "$line" ] && [ -n "$st" ] && [ "$why" != holds ]; then break; fi
    [ "$(date +%s)" -lt "$deadline" ] \
      || fail "step ${name}: no check with a failed readers check and a heartbeat within ${STEP_TIMEOUT_S} s (readers check '${why}', status '${st}')"
    sleep 3
  done
  [ "$why" = "$reason" ] || fail "step ${name}: the readers check fails with '${why}', expected '${reason}'"
  [ "${st%%|*}" != partial ] || fail "step ${name}: the target is Partial"
  [[ " ${st##*|} " == *" ${READERS_NOTE} "* ]] || fail "step ${name}: no ${READERS_NOTE} note (${st##*|})"
  log "step ${name}: level ${st%%|*}, ${READERS_NOTE}, local reason '${why}'"
  inspect_scan "step ${name}"
}
step no-host-identity agent "$AGENT_ID" agent-noid.yaml ro agent_in_container
step image-file agent "$AGENT_ID" agent-image.yaml ro "host_identity_refused (passwd: mount)"
step passwd-rw agent "$AGENT_ID" agent.yaml rw "host_identity_refused (passwd: mount)"

# The uid step: its own enrollment, state and secrets volumes owned by that uid (0700, files 0600).
log "step uid-collision: enrolling a second agent identity running as uid ${COLLISION_UID}"
r="$(api_json POST /api/enrollment-tokens '{"label":"e2e-firebird-uid"}')"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token (uid step): HTTP $(status_of "$r")"
token="$(body_of "$r" | jq -r '.token')"
register_secret enrollment_token_uid "$token"
files_uid() {
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps \
    --user "${COLLISION_UID}:${COLLISION_UID}" agent-files "$1"
}
files_root "chmod 0700 /state-uid /secrets-uid && chown ${COLLISION_UID}:${COLLISION_UID} /state-uid /secrets-uid"
files_uid 'umask 077; cat > /secrets-uid/target_agent_password' <"$S/target_agent_password"
printf '%s' "$token" | files_uid 'umask 077; cat > /secrets-uid/enrollment_token'
unset token
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps agent-uid \
  enroll --config /etc/databastion/agent.yaml --token-file /run/databastion-secrets/enrollment_token \
  >"$E2E_LOG_DIR/agent-uid-enroll.log" 2>&1 || fail "the uid step's enrollment failed (agent-uid-enroll.log)"
files_uid 'rm -f /secrets-uid/enrollment_token'
identity="$(files_uid 'cat /state-uid/identity.json')"
AGENT2_ID="$(jq -r '.agent_id' <<<"$identity")"
register_secret agent_secret_uid "$(jq -r '.agent_secret' <<<"$identity")"
unset identity
[[ "$AGENT2_ID" =~ $UUID_RE ]] || fail "no agent id (uid step)"
step uid-collision agent-uid "$AGENT2_ID" agent-uid.yaml ro uid_collision
dump_agent
phase_done negative-steps

# The steps' logs and their agents' states: no secret, marker or ground-truth value either.
for f in "$E2E_LOG_DIR"/agent-*.log; do [ -s "$f" ] || fail "$(basename "$f") is empty"; done
i2_failed=0
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "firebird step logs" \
  "$E2E_LOG_DIR" --exclude 'firebird.log' >&2 || i2_failed=1
[ "$i2_failed" = 0 ] || fail "invariant I2: a ground-truth value in a step's log"
if ! leaked="$(leak_scan "$E2E_LOG_DIR" "$P")"; then
  while IFS= read -r l; do log "LEAK (logs): $l"; done <<<"$leaked"
  fail "a secret reached a step's log (names above)"
fi
log "all checks passed (full read -> incident ${FULL_LATENCY_MS} ms)"
