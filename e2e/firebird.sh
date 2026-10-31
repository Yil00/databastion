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
#   - The log volume's ACLs (R52 item 1): its file system keeps them. The trace configuration (the
#     dev one) has max_log_size = 0 in every section writing the log (R54: no server rotation).
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

# host_fingerprints: sha256, inode, mode, owner and mtime of every mounted host identity file.
HOSTID_FP=""
host_fingerprints() {
  local f
  for f in "${HOST_FILES[@]}"; do
    printf '%s %s\n' "$(stat -L -c '%i %a %u %g %Y' -- "$f")" "$(sha256sum -- "$f" | cut -d' ' -f1)"
  done
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
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  # L1 (review of #394): the host's identity files are never changed by the run.
  if [ -s "$HOSTID_FP" ]; then
    if ! host_fingerprints | cmp -s - "$HOSTID_FP"; then
      log "FAIL: a host identity file changed during the run (sha256, inode, mode, owner or mtime)"
      status=1
    fi
  fi
  rm -rf "$E2E_WORK_DIR" 2>/dev/null || true
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
HOSTID_FP="$E2E_WORK_DIR/hostid.fingerprints"
host_fingerprints >"$HOSTID_FP"
# The read-write negative step binds a root-owned copy of the passwd file, never the host's own file
# read-write (review L1; R52 item 2 names the host's file: the mount rule refused is the same).
PASSWD_COPY="$E2E_WORK_DIR/hostcopy/passwd"
mkdir -p "$(dirname "$PASSWD_COPY")"
chmod 0755 "$(dirname "$PASSWD_COPY")"
# root_copy SOURCE DEST: a root-owned 0644 copy (sudo -n when not root, as in CI).
root_copy() {
  if [ "$(id -u)" = 0 ]; then
    install -o 0 -g 0 -m 0644 "$1" "$2"
  else
    timeout 30 sudo -n install -o 0 -g 0 -m 0644 "$1" "$2"
  fi
}
root_copy /etc/passwd "$PASSWD_COPY" || fail "cannot make the root-owned passwd copy of the read-write step"
# The server's firebird.conf and trace configuration, mounted read-only into the server and every
# agent at the same paths: root-owned copies of the dev files, made before the server starts (their
# change time must precede its start, proof 2). Not the checkout's files: those are owned by the
# user running the job (uid 1001 on the runner), and an agent running as that uid (the collision
# step) refuses a file it owns (ADR-0043: writable by the agent), which would add
# audit.trace_config_not_evaluated to that step only.
mkdir -p "$E2E_WORK_DIR/firebird"
chmod 0755 "$E2E_WORK_DIR/firebird"
for f in firebird.conf fbtrace.conf; do
  root_copy "$HERE/../dev/firebird/$f" "$E2E_WORK_DIR/firebird/$f" || fail "cannot make the root-owned copy of $f"
done
log "identity files mounted: ${HOST_FILES[*]}"
kernel="$(uname -r)"
IFS=. read -r kmaj kmin _ <<<"$kernel"
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "${kmin%%[!0-9]*}" -lt 8 ]; }; then
  fail "kernel $kernel: openat2 and STATX_MNT_ID need Linux 5.8 or later (implementation note of 2026-10-31 b, item 7)"
fi
phase_done preconditions

# R54 (ADR-0060 refinement of 2026-10-31 c): Partial needs max_log_size = 0 (absent: the server's
# default, 0) in every section of the trace configuration that writes the declared log (no server
# rotation); the database section of crm sets it explicitly. A convenience check of the dev file's
# own layout (one key per line, `{` and `}` on their own lines): the agent's check() is what decides,
# and Partial below fails without it.
awk -v log_file="$FB_LOG" '
  /^[[:space:]]*\{/ { in_s = 1; writes = 0; size = 0; next }
  /^[[:space:]]*\}/ { if (in_s && writes && size != 0) bad = 1; if (in_s && writes) n++; in_s = 0; next }
  in_s && $1 == "log_filename" && $3 == log_file { writes = 1 }
  in_s && $1 == "max_log_size" { size = $3; if ($3 == "0") explicit++ }
  END { if (bad || n == 0 || !explicit) exit 1; print n }
' "$HERE/../dev/firebird/fbtrace.conf" >"$E2E_WORK_DIR/r54.txt" \
  || fail "dev/firebird/fbtrace.conf: a section writing ${FB_LOG} has a max_log_size other than 0, or none sets 0 (ADR-0060 R54)"
log "trace configuration: max_log_size = 0 in the $(cat "$E2E_WORK_DIR/r54.txt") section(s) writing the declared log (R54)"

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
# M3 (review of #394; ADR-0060 decision 6, R4): the #82 cases the ADR lists beyond these, written
# with the stock isql: a literal cut at max_sql_length, an ON EXTERNAL password, the user name of a
# failed attachment (upper case: Firebird folds unquoted user names).
MARK_CUT="fbcut$(rand_hex 12)"
MARK_EXT="Fbext$(rand_hex 12)"
MARK_USER="FBUSR$(openssl rand -hex 12 | tr 'a-f' 'A-F')"
register_value cut_literal_marker "$MARK_CUT"
register_value external_password_marker "$MARK_EXT"
register_value failed_user_marker "$MARK_USER"
test_ca "e2e Firebird"

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
      ro=true src="$f"
      if [ "$n" = passwd ] && [ "$2" = rw ]; then ro=false src="$PASSWD_COPY"; fi
      printf '      - type: bind\n        source: %s\n        target: %s/%s\n        read_only: %s\n        bind:\n          create_host_path: false\n' \
        "$src" "$HOST_DIR" "$n" "$ro"
    done
  } >"$HOSTID_YML"
}
hostid_yml agent ro

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
# A line without a `detail` field gives `no-detail`, never `holds`.
readers_detail() {
  local d
  if ! jq -e '.fields.detail | type == "string"' <<<"$1" >/dev/null 2>&1; then
    printf 'no-detail'
    return 0
  fi
  d="$(jq -r '.fields.detail' <<<"$1" | tr ';' '\n' | sed -n 's/^ *readers check: //p' | head -n 1)"
  printf '%s' "${d:-holds}"
}
# quiesce_agent SERVICE: stops the agent of SERVICE between two checks, the way an operator restarts
# one: after a new "Firebird checked" line, two Audit poll intervals and a margin (25 s; the
# contract's default poll_interval_s is 10) for its stream to read that check's records, its last
# TRACE_FINI included, then a graceful stop. An agent stopped in the middle of a check leaves records of its own attachments
# that the next process reads with no state (ADR-0060 R39 (a), an accepted residual: reported as the
# agent account's reads, or ambiguous); the negative steps test the readers check, not that.
quiesce_agent() {
  local n0 deadline
  [ -n "$(compose --profile tools ps -q "$1")" ] || return 0
  n0="$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix "$1" 2>/dev/null \
    | grep -F '"Firebird checked"' | grep -cF "\"target_id\":\"${TARGET}\"" || true)"
  deadline=$(( $(date +%s) + 120 ))
  until [ "$(timeout 30 docker compose "${COMPOSE_ARGS[@]}" logs --no-color --no-log-prefix "$1" 2>/dev/null \
      | grep -F '"Firebird checked"' | grep -cF "\"target_id\":\"${TARGET}\"" || true)" -gt "$n0" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "no new check of ${TARGET} by ${1} within 120 s before its restart"
    sleep 2
  done
  sleep 25
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools stop -t 30 "$1" >/dev/null 2>&1 || true
}
# withholding NOTES: the notes of NOTES that withhold Partial (FORBIDDEN_NOTES), sorted.
withholding() {
  local c out=()
  # shellcheck disable=SC2086 # lists of note codes
  for c in $FORBIDDEN_NOTES; do [[ " $1 " != *" $c "* ]] || out+=("$c"); done
  printf '%s\n' "${out[@]}" | sort | tr '\n' ' ' | sed 's/ $//'
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
printf -- '### e2e-firebird: audit log ACLs (ADR-0060 R52 item 1)\n\n- The log volume (`%s`) keeps the named-user ACLs of the layout (access and default entries read back).\n' "$fs" >"$E2E_LOG_DIR/acl.md"
log "ACLs: the log volume's file system (${fs}) keeps the layout's named-user ACLs"
# Loopback only (decision 3): every listening TCP socket of the namespace is on 127.0.0.0/8 (the
# server on 127.0.0.1, Docker's embedded DNS resolver on 127.0.0.11) or ::1, owned by the server
# (84) or root (the resolver), never by the agent's or a host user's uid (review L4).
check_listeners() { # WHEN
  local sockets listen a u
  # shellcheck disable=SC2016 # the container shell's script
  sockets="$(compose exec -T firebird sh -c 'cat /proc/net/tcp; if [ -e /proc/net/tcp6 ]; then cat /proc/net/tcp6; fi')" \
    || fail "cannot read the server namespace's sockets ($1)"
  listen="$(awk '$4 == "0A" { split($2, a, ":"); print a[1] " " $8 }' <<<"$sockets" | sort -u)"
  [ -n "$listen" ] || fail "nothing listens in the server's namespace ($1)"
  while read -r a u; do
    case "$a" in
      ??????7F | 00000000000000000000000001000000) ;;
      *) fail "a socket of the server's namespace listens on another address than the loopback ($a, $1)" ;;
    esac
    case "$u" in
      "$SERVER_UID" | 0) ;;
      *) fail "a listening socket of the server's namespace is owned by uid $u, not the server's or root's ($1)" ;;
    esac
  done <<<"$listen"
  log "firebird: listening on the loopback only, uids 84 / 0 ($(wc -l <<<"$listen") socket(s), $1)"
}
check_listeners "after the start"
# Review L3: the security database and the image's SYSDBA.password file in the Firebird root, which
# the agent sees read-only, are not readable by the agent's uid.
# shellcheck disable=SC2016 # the container shell's script
timeout 60 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T firebird-root-probe \
  'n=0; for f in /opt/firebird/security*.fdb /opt/firebird/SYSDBA.password; do [ -e "$f" ] || continue; n=$((n + 1)); if [ -r "$f" ]; then echo "readable: $(basename "$f")"; exit 1; fi; done; [ "$n" -ge 1 ] || { echo "no security database in the root"; exit 2; }; echo "$n file(s) not readable"' \
  >"$E2E_LOG_DIR/firebird-root-probe.log" 2>&1 \
  || fail "the agent's uid can read the security database or SYSDBA.password in the Firebird root (firebird-root-probe.log)"
log "firebird root: the security database is not readable by uid ${AGENT_UID} ($(tail -n 1 "$E2E_LOG_DIR/firebird-root-probe.log"))"
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
      and ($c.HostConfig.SecurityOpt // [] | index("no-new-privileges:true")) != null
      and $c.Config.User == $user
      and all(["/opt/firebird", "/opt/firebird/firebird.conf", "/databastion/fbtrace.conf",
               "/var/lib/firebird/audit"][]; . as $d | any($c.Mounts[]; .Destination == $d and .RW == false))
      and ([$c.Mounts[] | select(.Destination == "/var/lib/firebird/data")] | length) == 0' >/dev/null \
    || fail "the agent's container is not in the layout of R52 item 2 (namespaces, capabilities, read-only mounts)"
  for f in "${HOST_FILES[@]}"; do
    n="$(basename "$f")"
    rw=false src="$f"
    if [ "$n" = passwd ] && [ "$want_rw" = true ]; then rw=true src="$PASSWD_COPY"; fi
    docker inspect "$1" | jq -e --arg s "$src" --arg d "${HOST_DIR}/${n}" --argjson rw "$rw" \
      'any(.[0].Mounts[]; .Type == "bind" and .Source == $s and .Destination == $d and .RW == $rw)' >/dev/null \
      || fail "${src} is not a single-file bind mount at ${HOST_DIR}/${n} (RW ${rw})"
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
check_listeners "with the agent"
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
T_AUDIT="$(date +%s)"
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
PARTIAL_TOOK_S=$(( $(date +%s) - T_AUDIT ))
# The negative steps watch at least this long, plus a heartbeat and a check (review M1).
PARTIAL_WINDOW_S=$(( PARTIAL_TOOK_S + 60 ))
log "${TARGET}: audit level partial (${SOURCE}) through firebird.audit.host_identity after ${PARTIAL_TOOK_S} s; notes: ${notes}"
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

# --------------------------------------------------------------------------- negative steps
# R52 item 2 (security review L7), on the real kernel, with uid 10001, right after the main agent
# first reached Partial and before any client traffic (re-review of #394): the traffic's DCL, PSQL
# and EXECUTE STATEMENT records are ambiguous and leave the target Limited for 24 h, as ADR-0060
# accepts, which would make "never Partial" prove nothing. Here nothing but the readers check can
# withhold Partial: each step replaces the agent's container (the same identity), waits for a check
# with the expected reason and a heartbeat after its start, watches the window, and requires the
# withholding notes to be exactly audit.log_readable_by_others. Control first: the main agent's
# readers check holds and nothing withholds Partial (an empty baseline, or the run fails).
why="$(readers_detail "$(last_checked agent)")"
[ "$why" = holds ] || fail "control: the main agent's readers check fails (${why}) before the negative steps"
ctl="$(status_after "$AGENT_ID" "$STEP_T")"
[ "${ctl%%|*}" = partial ] || fail "control: the main agent is not Partial before the negative steps (${ctl})"
BASELINE="$(withholding "${ctl##*|}")"
[ -z "$BASELINE" ] || fail "control: '${BASELINE}' withholds Partial before the negative steps: the steps would prove nothing"
log "negative steps: control holds (readers check holds; Partial; nothing withholds it)"

# step NAME SERVICE AGENT_ID CONFIG PASSWD_MODE REASON EXPECTED_WITHHOLDING: one negative step. It
# watches at least the main agent's time to Partial plus a minute (PARTIAL_WINDOW_S, review M1): the
# level is never partial in that window, and at its end the notes that withhold Partial are exactly
# EXPECTED_WITHHOLDING.
step() {
  local name="$1" svc="$2" id="$3" config="$4" mode="$5" reason="$6" expected="$7" deadline line why st cid end t_start
  quiesce_agent "$AGENT_SVC"
  dump_agent
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools rm -sf agent agent-uid >/dev/null 2>&1 || true
  STEP="$name" AGENT_SVC="$svc"
  hostid_yml "$svc" "$mode"
  export E2E_FB_AGENT_CONFIG="$config"
  STEP_T="$(console_sql "SELECT now()")"
  t_start="$(date +%s)"
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
  end=$(( t_start + PARTIAL_WINDOW_S ))
  while :; do
    st="$(status_after "$id" "$STEP_T")"
    [ "${st%%|*}" != partial ] || fail "step ${name}: the target became Partial"
    why="$(readers_detail "$(last_checked "$svc")")"
    [ "$why" = "$reason" ] || fail "step ${name}: the readers check now gives '${why}', expected '${reason}'"
    [ "$(date +%s)" -lt "$end" ] || break
    sleep 3
  done
  [[ " ${st##*|} " == *" ${READERS_NOTE} "* ]] || fail "step ${name}: no ${READERS_NOTE} note (${st##*|})"
  local got
  got="$(withholding "${st##*|}")"
  [ "$got" = "$expected" ] \
    || fail "step ${name}: the notes withholding Partial are '${got}', expected exactly '${expected}'"
  log "step ${name}: never partial over ${PARTIAL_WINDOW_S} s; level ${st%%|*}; withholding notes '${got}'; local reason '${why}'"
  inspect_scan "step ${name}"
}
STEP=initial  # the main agent's log until now: agent-initial.log
step no-host-identity agent "$AGENT_ID" agent-noid.yaml ro agent_in_container "$READERS_NOTE"
step image-file agent "$AGENT_ID" agent-image.yaml ro "host_identity_refused (passwd: mount)" "$READERS_NOTE"
step passwd-rw agent "$AGENT_ID" agent.yaml rw "host_identity_refused (passwd: mount)" "$READERS_NOTE"
quiesce_agent agent
dump_agent
# Positive control of the steps (review M1): the main agent again, its own configuration and the
# read-only host files: Partial again, with nothing withholding it, within the same window. It is the
# agent of the traffic phase that follows.
log "positive control: the main agent with host_identity again, Partial within ${PARTIAL_WINDOW_S} s"
timeout 120 docker compose "${COMPOSE_ARGS[@]}" --profile tools rm -sf agent agent-uid >/dev/null 2>&1 || true
STEP=main AGENT_SVC=agent
hostid_yml agent ro
export E2E_FB_AGENT_CONFIG=agent.yaml
STEP_T="$(console_sql "SELECT now()")"
T_FINAL="$(date +%s)"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent >/dev/null
AGENT_CID="$(compose ps -q agent)"
layout "$AGENT_CID" "$AGENT_UID"
while :; do
  st="$(status_after "$AGENT_ID" "$STEP_T")"
  if [ "${st%%|*}" = partial ] && [ -z "$(withholding "${st##*|}")" ]; then break; fi
  [ "$(date +%s)" -lt $(( T_FINAL + PARTIAL_WINDOW_S )) ] \
    || fail "positive control: not Partial within ${PARTIAL_WINDOW_S} s of the restart (status '${st}', readers check '$(readers_detail "$(last_checked agent)")')"
  sleep 3
done
why="$(readers_detail "$(last_checked agent)")"
[ "$why" = holds ] || fail "positive control: Partial while the readers check reports '${why}'"
log "positive control: Partial again $(( $(date +%s) - T_FINAL )) s after the restart"
# The restarts surfaced none of the agent's own statements (they would be reported under its account).
n="$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
[ "$n" = 0 ] || fail "${TARGET}: $n event(s) after the negative steps and before any client statement: the agents' own activity surfaced"
log "negative steps: still no event before the first client statement"
phase_done negative-steps

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

# M3: a literal cut at max_sql_length (65 000 in fbtrace.conf): nine literals of 8 000 characters
# (each under the 32 765-byte literal bound in UTF-8; compared with a constant, not cast to a
# column) make a text of about 72 000 characters, the marker at the start of the first, inside the
# part the trace keeps.
log "Audit: a statement cut at max_sql_length, a marker in its literal, as E2E_ANALYST"
python3 -I -c 'import sys
m = sys.argv[1]
lits = [m + "a" * (8000 - len(m))] + [chr(98 + i) * 8000 for i in range(8)]
print("SELECT COUNT(*) FROM CUSTOMERS WHERE \x27z\x27 IN (" + ", ".join("\x27%s\x27" % l for l in lits) + ");")' \
  "$MARK_CUT" | fb_isql E2E_ANALYST target_client_password || fail "the cut statement failed ($(client_error_code))"
# M3: EXECUTE STATEMENT ... ON EXTERNAL with a marker password (wrong: the inner attachment fails,
# the outer statement's text, marker included, is traced all the same).
log "Audit: EXECUTE STATEMENT ON EXTERNAL with a marker password as SYSDBA (fails, as intended)"
{
  printf 'SET TERM ^ ;
'
  printf "EXECUTE BLOCK AS DECLARE X INTEGER; BEGIN EXECUTE STATEMENT 'SELECT 1 FROM RDB\$DATABASE' ON EXTERNAL '127.0.0.1/3050:%s' AS USER 'E2E_ANALYST' PASSWORD '%s' INTO X; END^\n" "$FB_DB" "$MARK_EXT"
  printf 'SET TERM ; ^\n'
} | fb_isql SYSDBA target_fb_sysdba_password && fail "EXECUTE STATEMENT ON EXTERNAL with a wrong password succeeded"
# Review L5: refused for the reason intended, the inner attachment's login (measured on 5.0.4:
# SQLSTATE 42000, "Execute statement error at attach", then gds 335544472), not any other error.
if ! { grep -qF 'Execute statement error at attach' "$E2E_WORK_DIR/client.err" \
    && grep -qE '^335544472 : ' "$E2E_WORK_DIR/client.err"; }; then
  fail "EXECUTE STATEMENT ON EXTERNAL failed for another reason than the inner attachment's login ($(client_error_code))"
fi
log "Audit: ON EXTERNAL refused at the inner attachment's login, as intended ($(client_error_code), gds 335544472)"
# M3: a failed attachment whose user name is a marker (a wrong password for an unknown user).
log "Audit: a failed attachment as a marker user name"
# shellcheck disable=SC2016 # a Firebird name
printf 'SELECT 1 FROM RDB$DATABASE;\n' | fb_isql "$MARK_USER" target_client_password \
  && fail "the attachment as an unknown user succeeded"
# Review L5: a login failure (SQLSTATE 28000, the server's "user name and password are not
# defined"), not any other error.
if ! { grep -qF 'SQLSTATE = 28000' "$E2E_WORK_DIR/client.err" \
    && grep -qF 'Your user name and password are not defined' "$E2E_WORK_DIR/client.err"; }; then
  fail "the marker user's attachment failed for another reason than its login ($(client_error_code))"
fi
log "Audit: the marker user's attachment refused at login, as intended ($(client_error_code))"
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
# Review M2 / M3: every marker of the #82 cases is in the server's trace log (matched without case:
# the server prints user names in upper case), measured on 5.0.4: the passwords of CREATE / ALTER
# USER and of ON EXTERNAL are not masked by the server, the cut text keeps its first 65 000
# characters.
# The failed attachment is the exception, measured on 5.0.4 and deterministic (ADR-0060 R10): the
# authentication fails before any attachment to crm exists, so crm's section writes no record of it
# and its user name is not in the log; the I2 scans still search every artifact for it.
missing=""
for m in "$NP"/*; do
  [ "$(basename "$m")" = failed_user_marker ] && continue
  LC_ALL=C grep -qiFf "$m" "$E2E_WORK_DIR/target-audit.log" || missing+=" $(basename "$m")"
done
[ -z "$missing" ] || fail "Audit: marker(s) not in the server's trace log (positive control):${missing}"
! LC_ALL=C grep -qiFf "$NP/failed_user_marker" "$E2E_WORK_DIR/target-audit.log" \
  || fail "Audit: the failed attachment's user name is in crm's trace log (R10 expects no record): fingerprinting it is then untested here"
# The cut record is the server's (the text ends with `...` at max_sql_length).
grep -qE "^SELECT COUNT\\(\\*\\) FROM CUSTOMERS WHERE 'z' IN .*\\.\\.\\.\$" "$E2E_WORK_DIR/target-audit.log" \
  || fail "Audit: the long statement is not cut at max_sql_length in the trace log (positive control)"
# PLG$SRP_VIEW parameter records (the security database's user rows, written by CREATE / ALTER USER
# with the password parameters) are not in this log: the trace configuration's only enabled database
# section is crm's (proof 11), so the security database is never traced; the parser fixtures cover
# that record. Checked: no record reads or writes PLG$SRP / PLG$SRP_VIEW (no table-block row, no
# INSERT / UPDATE text); the relation's name appears only in the agent's own catalog reads (R9).
# shellcheck disable=SC2016 # Firebird names
! grep -qE '^PLG\$SRP(_VIEW)? |(INSERT INTO|UPDATE) "?PLG\$SRP' "$E2E_WORK_DIR/target-audit.log" \
  || fail "Audit: a record reads or writes PLG\$SRP_VIEW: the security database is traced, which the crm-only configuration excludes"
log "Audit: the trace log holds the literals ($LITERAL_IDS) and $(( $(find "$NP" -type f | wc -l) - 1 )) markers (positive controls; the agent must drop them all); no record of the failed attachment (R10) and no PLG\$SRP_VIEW record (security database not traced)"
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
  for f in "$E2E_LOG_DIR"/agent.log "$E2E_LOG_DIR"/agent-*.log; do
    ! grep -qF "$needle" "$f" || fail "the agent logged a path of the target's files ($(basename "$f"))"
  done
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

# --------------------------------------------------------------------------- uid step
# R52 item 2: the agent run as a host user's uid, after the traffic (its own identity, never given
# Audit: its notes do not depend on the main agent's). See "negative steps" for step().
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
# The uid step's agent cannot read the log either (the layout grants uid 10001 only), so it also
# reports audit.log_not_readable and never reads a record (audit.partial_pending_first_record).
step uid-collision agent-uid "$AGENT2_ID" agent-uid.yaml ro uid_collision \
  "audit.log_not_readable ${READERS_NOTE} audit.partial_pending_first_record"
dump_agent
phase_done uid-step

# After the steps (review L2): the console side again (a second database dump, the pages, the main
# agent's state), the uid step's agent state and every log: no ground-truth value, marker or secret.
for f in "$E2E_LOG_DIR"/agent-*.log; do [ -s "$f" ] || fail "$(basename "$f") is empty"; done
dump_logs "${SERVICES[@]}"
D="$E2E_WORK_DIR/dump2"
collect_console_side "$D" "$TARGET"
mkdir -p "$E2E_WORK_DIR/state-uid"
files_uid 'tar -C /state-uid -cf - .' | tar -C "$E2E_WORK_DIR/state-uid" -xf - \
  || fail "cannot read the uid step's agent state"
[ -f "$E2E_WORK_DIR/state-uid/identity.json" ] || fail "no identity.json in the uid step's state: the scan would prove nothing"
i2_failed=0
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "firebird after the steps" \
  --exclude 'firebird.log' "$D" "$E2E_WORK_DIR/state-uid" "$E2E_LOG_DIR" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --label "firebird #82 markers after the steps" "${secret_files[@]}" \
  --exclude 'firebird.log' "$D" "$E2E_WORK_DIR/state-uid" "$E2E_LOG_DIR" >&2 || i2_failed=1
[ "$i2_failed" = 0 ] || fail "invariant I2: a ground-truth value or a marker after the negative steps"
leaks=0
secret_hygiene "$D" 'firebird.log' || leaks=1
rm -f -- "$E2E_WORK_DIR/state-uid/identity.json"
for pdir in "$P" "$NP"; do
  if ! leaked="$(leak_scan "$E2E_WORK_DIR/state-uid" "$pdir")"; then
    while IFS= read -r l; do log "LEAK (uid step's state): $l"; done <<<"$leaked"
    leaks=1
  fi
done
[ "$leaks" = 0 ] || fail "a secret or a marker after the negative steps (names above)"
rm -rf -- "$D" "$E2E_WORK_DIR/state-uid"
log "all checks passed (full read -> incident ${FULL_LATENCY_MS} ms)"
