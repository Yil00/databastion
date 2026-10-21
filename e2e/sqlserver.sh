#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# End-to-end SQL Server target (ROADMAP P9-D, ADR-0051 decisions 2, 4, 6, 9 and "End-to-end and
# load"): the console and the agent (the e2e images) with the dev SQL Server 2022 Express service
# (dev/sqlserver: dev CA, forced encryption, the committed seed, the agent login of the minimal
# variant, the server audit `databastion_audit`). Compose: docker-compose.yml merged with
# docker-compose.sqlserver.yml (project databastion-e2e-sqlserver). Checks:
#   - the agent login is the minimal variant (no sysadmin nor refused permission, the two
#     SQL Server Audit grants of 2022, schema SELECT and the RLS opt-in in `retail`: I4);
#   - enrollment; the console lists `engine.sqlserver`: the target is reported, reachable, over a
#     verified TLS session, with the honest audit level: Limited before the Audit stream runs, then
#     Partial from SQL Server Audit (never Full), with `audit.log_without_row_counts`;
#   - Discovery (while the Audit stream runs) against dev/ground-truth.json: every expected
#     classifier, no negative control, the value-bearing table name stored normalized;
#   - the agent's own reads (check(), Discovery, the audit polls) are never reported: no event at
#     all before the first client statement, and no event of the agent's login;
#   - Audit: `bcp out` of the seeded tables (signature.bcp) and a whole-table SELECT
#     (shape.full_table_read) as e2e_exporter raise a critical incident (dump -> incident time
#     printed, limit 120 s); filtered SELECTs whose literals are ground-truth values as e2e_analyst;
#     CREATE / ALTER LOGIN with marker passwords as e2e_admin (dcl, kind only);
#   - I2: no ground-truth value (values in table names included) in the console database, the
#     console and agent logs, the pages or the agent's state; the literals of the analyst's queries
#     nowhere on the console side (positive control: they are in SQL Server's own audit file); the
#     DCL marker passwords nowhere either; no generated secret in any container log.
# Version and source (ROADMAP P9-D follow-up): E2E_SQLSERVER_VERSION 2022 (default: the dev pin), 2019
# or 2025 (the engine matrix pins, Express); E2E_SQLSERVER_AUDIT_SOURCE sqlserver_audit (default on
# 2022 and 2025) or sqlserver_xevents (the dev session `databastion_xe`; the only source on 2019,
# and its default there). With sqlserver_xevents the agent login holds the session's grant only
# (VIEW SERVER STATE on 2019, VIEW SERVER PERFORMANCE STATE on 2022+: the two SQL Server Audit
# grants are revoked before the agent starts), the level is Partial without
# audit.log_without_row_counts, and the positive controls read the session's files.
# See e2e/README.md "SQL Server target". Requires: docker (compose v2.24+), openssl, curl, jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-sqlserver}"
PROJECT="databastion-e2e-sqlserver"
LOG_TAG="e2e-sqlserver"  # read by lib.sh
I2_CHECK="$HERE/i2_check.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
TARGET="mssql-e2e"
BADCA="mssql-e2e-wrong-ca"   # the negative TLS control (the console test CA as ca_file)
ENGINE="sqlserver"
POLICY_DUMP="e2e sqlserver export"
POLICY_READS="e2e sqlserver reads"
POLICY_DCL="e2e sqlserver dcl"
DUMP_INCIDENT_LIMIT_S=120
SCAN_TIMEOUT_S=600
EVENTS_TIMEOUT_S=240
SQLCMD=/opt/mssql-tools18/bin/sqlcmd
BCP=/opt/mssql-tools18/bin/bcp
# Tables the exporter copies out with bcp (the value-bearing name included): every table of the
# monitored schemas the test logins can read (crm and finance; cas is not granted to them).
EXPORT_TABLES=(crm.customers crm.customer_notes crm.regional_contacts finance.payment_cards
  finance.salaries finance.app_credentials finance.invoices)

# The SQL Server image is the dev service's (dev/docker-compose.yml): the same pin.
dev_img="$(sed -n 's/.*DATABASTION_DEV_SQLSERVER_IMAGE:-\([^}]*\)}.*/\1/p' "$HERE/../dev/docker-compose.yml")"
e2e_img="$(sed -n 's/.*E2E_MSSQL_IMAGE:-\([^}]*\)}.*/\1/p' "$HERE/docker-compose.sqlserver.yml")"
if [ -z "$dev_img" ] || [ "$dev_img" != "$e2e_img" ]; then
  echo "the SQL Server image of docker-compose.sqlserver.yml must be the one of dev/docker-compose.yml" >&2
  exit 1
fi
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_MSSQL_IMAGE
fi

# The version under test and its Audit source. 2019 and 2025: the engine matrix's pins (the same
# strings as engine-matrix.yml, checked below), which override E2E_MSSQL_IMAGE.
MSSQL_VERSION="${E2E_SQLSERVER_VERSION:-2022}"
MSSQL_PIN=""
case "$MSSQL_VERSION" in
  2019) MSSQL_MAJOR=15 default_source=sqlserver_xevents
    MSSQL_PIN="mcr.microsoft.com/mssql/server:2019-latest@sha256:07d7dedecdbfcf6776035dc5eefb5bfd9aa1804b2f6b99f7dedb397d8a599069" ;;
  2022) MSSQL_MAJOR=16 default_source=sqlserver_audit ;;
  2025) MSSQL_MAJOR=17 default_source=sqlserver_audit
    MSSQL_PIN="mcr.microsoft.com/mssql/server:2025-latest@sha256:742481d1b1186cccc81220a1eaacef244ca8d0f7d19c8e5c70df8ae541ffbab2" ;;
  *) echo "E2E_SQLSERVER_VERSION must be 2019, 2022 or 2025 (got '$MSSQL_VERSION')" >&2; exit 2 ;;
esac
AUDIT_SOURCE="${E2E_SQLSERVER_AUDIT_SOURCE:-$default_source}"
case "$AUDIT_SOURCE" in
  sqlserver_audit)
    # SQL Server Audit is a source on 2022 and later only (ADR-0051 decision 6).
    [ "$MSSQL_MAJOR" -ge 16 ] || { echo "sqlserver_audit is not a source on SQL Server $MSSQL_VERSION" >&2; exit 2; }
    AUDIT_YAML="{source: sqlserver_audit, audit_name: databastion_audit}" ;;
  sqlserver_xevents) AUDIT_YAML="{source: sqlserver_xevents, xe_session: databastion_xe}" ;;
  *) echo "E2E_SQLSERVER_AUDIT_SOURCE must be sqlserver_audit or sqlserver_xevents (got '$AUDIT_SOURCE')" >&2; exit 2 ;;
esac
if [ -n "$MSSQL_PIN" ]; then
  grep -qF "sqlserver_image: $MSSQL_PIN" "$HERE/../.github/workflows/engine-matrix.yml" || {
    echo "the SQL Server $MSSQL_VERSION pin of sqlserver.sh must be the one of engine-matrix.yml" >&2
    exit 1
  }
  export E2E_MSSQL_IMAGE="$MSSQL_PIN"
fi
# The statement events of the session's files (the positive controls on sqlserver_xevents): text and
# login of each sql_statement_completed / sp_statement_completed, read as `sa`.
XE_STATEMENTS="SELECT CONVERT(nvarchar(4000), x.value('(event/data[@name=\"statement\"]/value)[1]', 'nvarchar(4000)')) AS stmt_text,
    CONVERT(nvarchar(128), x.value('(event/action[@name=\"server_principal_name\"]/value)[1]', 'nvarchar(128)')) AS principal_name
  FROM sys.fn_xe_file_target_read_file(N'/var/opt/mssql/xe/databastion_xe*.xel', NULL, NULL, NULL) f
  CROSS APPLY (SELECT CONVERT(xml, f.event_data)) e(x)
  WHERE f.object_name IN (N'sql_statement_completed', N'sp_statement_completed')"

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-sqlserver.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"
COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.sqlserver.yml")
# shellcheck source=lib.sh
. "$HERE/lib.sh"
SERVICES=(db migrate web worker proxy target-mssql agent)

cleanup() {
  local status=$? line
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs "${SERVICES[@]}"
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  print_census e2e-sqlserver
  # #282 review N3 (informational): the agent's cut lines before unpaired statistics builds.
  if [ "$AUDIT_SOURCE" = sqlserver_xevents ]; then
    mkdir -p "$E2E_LOG_DIR/census"
    python3 "$HERE/load/loadlib.py" xe-catchup --log "$E2E_LOG_DIR/agent.log" --label "e2e-sqlserver-${MSSQL_VERSION}" \
      --md "$E2E_LOG_DIR/census/xe-catchup.md" --json "$E2E_LOG_DIR/census/xe-catchup.json" 2>&1 \
      | while IFS= read -r line; do log "$line"; done
  fi
  redact_dir "$E2E_LOG_DIR" "$P"
  redact_dir "$E2E_LOG_DIR" "$NP"
  # The census Markdown, redacted above, into the job summary (never written there before).
  summary_append "$E2E_LOG_DIR"/census/*.md
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

# I2 scanner positive control, before anything starts: every searchable value of the engine is in
# the committed seed the target loads.
timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  "$HERE/../dev/seed/out/sqlserver.sql" >&2 || fail "I2 scanner positive control failed for $ENGINE (see above)"

# --------------------------------------------------------------------------- secrets, CA, agent.yaml
console_secrets
put_secret target_mssql_password "$(rand_password 20)"   # sa: stays in the target container
put_secret target_agent_password "$(rand_password 20)"   # login databastion (ADR-0051 decision 4)
put_secret target_client_password "$(rand_password 20)"  # test logins e2e_exporter / e2e_analyst / e2e_admin
# Marker passwords of the DCL test: they must reach no console-side artifact and no log.
DCL_MARKER_1="Dcl1-$(rand_hex 12)"
DCL_MARKER_2="Dcl2-$(rand_hex 12)"
register_value dcl_marker_1 "$DCL_MARKER_1"
register_value dcl_marker_2 "$DCL_MARKER_2"
test_ca "e2e SQL Server"
: >"$T/sqlserver-ca.pem"   # the target's dev CA, copied out once it started

cat >"$E2E_WORK_DIR/agent/agent.yaml" <<EOF
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
  - id: ${BADCA}
    engine: sqlserver
    host: sqlserver
    port: 1433
    account: databastion
    secret:
      file: /run/databastion-secrets/target_agent_password
    sqlserver:
      tls: auto
      ca_file: /etc/databastion/console-ca.pem
      databases: [retail]
EOF
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# --------------------------------------------------------------------------- SQL helpers
# mssql_sa [SQLCMD_ARGS...] < SQL: as `sa` inside the target (dev tooling, never the agent), the
# server certificate verified against the dev CA on `localhost` (in its SAN); the password is read
# inside the container. Output: tab-free rows, no header.
mssql_sa() {
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T -e SSL_CERT_FILE=/var/opt/mssql/databastion-tls/ca.pem \
    target-mssql bash -c 'SQLCMDPASSWORD="$(cat /run/secrets/target_mssql_password)" exec '"$SQLCMD"' -S localhost -U sa -b -I -W -h -1 -i /dev/stdin'
}
mssql_sa_q() { printf 'SET NOCOUNT ON;\n%s\n' "$1" | mssql_sa; }
# mssql_client SCRIPT: the one-shot client container (stdin passed through); errors to a private file.
mssql_client() {
  timeout 300 docker compose "${COMPOSE_ARGS[@]}" --profile tools run --rm -T --no-deps mssql-client "$1"
}
client_error_code() {
  local code
  code="$(grep -m 1 -oE '^Msg [0-9]+|SQLState = [0-9A-Z]+, NativeError = [0-9]+|Sqlcmd: Error' \
    "$E2E_WORK_DIR/client.err" 2>/dev/null | head -n 1)"
  printf '%s' "${code:-none}"
}

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

log "starting the console and SQL Server ${MSSQL_VERSION} Express (first start: seed, agent login, audit; source ${AUDIT_SOURCE})"
timeout 900 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy target-mssql
start_console
deadline=$(( $(date +%s) + 420 ))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q target-mssql)" 2>/dev/null)" = healthy ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "target-mssql not healthy within 420 s"
  sleep 3
done
docker inspect "$(compose ps -q target-mssql)" --format '{{json .Config.Env}}' \
  | jq -e 'any(test("PASSWORD")) | not' >/dev/null || fail "a password in target-mssql's environment"
compose exec -T target-mssql cat /var/opt/mssql/databastion-tls/ca.pem >"$T/sqlserver-ca.pem" \
  || fail "cannot copy the dev CA of target-mssql"
grep -q 'BEGIN CERTIFICATE' "$T/sqlserver-ca.pem" || fail "no dev CA in target-mssql"
inspect_scan "after the start"
chmod 0644 "$T/sqlserver-ca.pem"
version="$(mssql_sa_q "SELECT CONCAT(CONVERT(nvarchar(64), SERVERPROPERTY('ProductVersion')), ' ', CONVERT(nvarchar(128), SERVERPROPERTY('Edition')), ' engine ', CONVERT(int, SERVERPROPERTY('EngineEdition')))")" \
  || fail "cannot read the server version"
log "target-mssql: $version"
[[ "$version" == "${MSSQL_MAJOR}".* ]] || fail "target-mssql is not SQL Server ${MSSQL_VERSION} ($version)"
[[ "$version" == *" engine 4" ]] || fail "target-mssql is not the Express edition ($version)"
phase_done start

# --------------------------------------------------------------------------- the agent login (I4)
# ADR-0051 decision 4, minimal variant (dev/sqlserver/initdb/20-databastion.sql): server-level
# exactly CONNECT SQL and the two SQL Server Audit grants of 2022 (refinement item 1, option (a')),
# no server role; in `retail` CONNECT, the RLS opt-in VIEW DEFINITION, SELECT on the schemas crm and
# finance, the three columns of cas.cas_tickets, no database role. On 2019 the dev script grants
# VIEW SERVER STATE instead (the Extended Events grant of 2019). With the Extended Events source on
# 2022+, the operator's grant set of that source (docs/08 "Extended Events: source and grants"): the
# two SQL Server Audit grants revoked, VIEW SERVER PERFORMANCE STATE granted, before the agent
# starts (an unused Audit grant would be reported as privilege.audit_grant_without_audit).
if [ "$AUDIT_SOURCE" = sqlserver_xevents ] && [ "$MSSQL_MAJOR" -ge 16 ]; then
  log "Extended Events source on ${MSSQL_VERSION}: the agent login gets VIEW SERVER PERFORMANCE STATE, not the SQL Server Audit grants"
  mssql_sa_q "REVOKE VIEW SERVER SECURITY AUDIT FROM databastion; REVOKE VIEW ANY SECURITY DEFINITION FROM databastion;
    GRANT VIEW SERVER PERFORMANCE STATE TO databastion;" >/dev/null || fail "cannot set the Extended Events grant of the agent login"
fi
case "${AUDIT_SOURCE}:${MSSQL_MAJOR}" in
  sqlserver_audit:*) want_perms="CONNECT SQL+VIEW ANY SECURITY DEFINITION+VIEW SERVER SECURITY AUDIT" ;;
  sqlserver_xevents:15) want_perms="CONNECT SQL+VIEW SERVER STATE" ;;
  sqlserver_xevents:*) want_perms="CONNECT SQL+VIEW SERVER PERFORMANCE STATE" ;;
esac
log "checking the agent login (ADR-0051 minimal variant, read-only: I4)"
perms="$(mssql_sa_q "SELECT STRING_AGG(permission_name, '+') WITHIN GROUP (ORDER BY permission_name)
  FROM sys.server_permissions p JOIN sys.server_principals s ON s.principal_id = p.grantee_principal_id
  WHERE s.name = N'databastion' AND p.state IN ('G', 'W')")"
[ "$perms" = "$want_perms" ] \
  || fail "unexpected server permissions of the agent login: $perms (expected $want_perms)"
roles="$(mssql_sa_q "SELECT COUNT(*) FROM sys.server_role_members m JOIN sys.server_principals s
  ON s.principal_id = m.member_principal_id WHERE s.name = N'databastion'")"
[ "$roles" = 0 ] || fail "the agent login is a member of $roles server role(s)"
dbperms="$(mssql_sa_q "USE retail; SELECT STRING_AGG(CONCAT(p.permission_name, ':', p.class_desc, ':',
    COALESCE(SCHEMA_NAME(CASE WHEN p.class = 3 THEN p.major_id END), OBJECT_SCHEMA_NAME(CASE WHEN p.class = 1 THEN p.major_id END), '-'),
    CASE WHEN p.minor_id > 0 THEN ':col' ELSE '' END), '+') WITHIN GROUP (ORDER BY p.permission_name, p.class, p.major_id, p.minor_id)
  FROM sys.database_permissions p JOIN sys.database_principals d ON d.principal_id = p.grantee_principal_id
  WHERE d.name = N'databastion' AND p.state IN ('G', 'W');
  SELECT COUNT(*) FROM sys.database_role_members m JOIN sys.database_principals d
    ON d.principal_id = m.member_principal_id WHERE d.name = N'databastion'" \
  | grep -v '^Changed database context' | tr '\n' ' ')"
expected="CONNECT:DATABASE:-+SELECT:OBJECT_OR_COLUMN:cas:col+SELECT:OBJECT_OR_COLUMN:cas:col"
expected+="+SELECT:OBJECT_OR_COLUMN:cas:col+SELECT:SCHEMA:crm+SELECT:SCHEMA:finance+VIEW DEFINITION:DATABASE:- 0 "
[ "$dbperms" = "$expected" ] || fail "unexpected permissions of the agent in retail: $dbperms"

# --------------------------------------------------------------------------- test logins
# Created before the agent starts, so the Audit stream (which skips the audit's history at its
# first start) never sees these statements. e2e_exporter and e2e_analyst: SELECT on crm and finance;
# e2e_admin: ALTER ANY LOGIN only (the DCL test), no table privilege.
log "creating the test logins e2e_exporter, e2e_analyst, e2e_admin"
# shellcheck disable=SC2016 # sqlcmd variables (PW from the environment: never on a command line)
printf '%s\n' 'SET NOCOUNT ON;' \
  "CREATE LOGIN e2e_exporter WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
  "CREATE LOGIN e2e_analyst WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
  "CREATE LOGIN e2e_admin WITH PASSWORD = N'\$(PW)', CHECK_POLICY = OFF, DEFAULT_DATABASE = retail;" \
  'GRANT ALTER ANY LOGIN TO e2e_admin;' 'GO' 'USE retail;' \
  'CREATE USER e2e_exporter FOR LOGIN e2e_exporter;' 'CREATE USER e2e_analyst FOR LOGIN e2e_analyst;' \
  'CREATE USER e2e_admin FOR LOGIN e2e_admin;' \
  'GRANT SELECT ON SCHEMA::crm TO e2e_exporter, e2e_analyst;' \
  'GRANT SELECT ON SCHEMA::finance TO e2e_exporter, e2e_analyst;' 'GO' \
  | timeout 120 docker compose "${COMPOSE_ARGS[@]}" exec -T -e SSL_CERT_FILE=/var/opt/mssql/databastion-tls/ca.pem \
    target-mssql bash -c 'SQLCMDPASSWORD="$(cat /run/secrets/target_mssql_password)" PW="$(cat /run/secrets/target_client_password)" exec '"$SQLCMD"' -S localhost -U sa -b -I -i /dev/stdin' \
    >/dev/null 2>"$E2E_WORK_DIR/client.err" || fail "cannot create the test logins ($(client_error_code))"
phase_done logins

# --------------------------------------------------------------------------- enroll + run
log "bootstrapping the administrator; enrolling the agent"
admin_login e2e-sqlserver
enroll_agent target_agent_password
log "enrolled agent $AGENT_ID; starting it"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
# The console lists engine.sqlserver (capabilities.ts): the agent reports the target.
wait_online 120 "${TARGET}:sqlserver"
t="$(target_json "$TARGET")"
log "target ${TARGET}: $(target_summary "$t")"
# Before any Audit stream: Limited at most (no stream runs), never Partial or Full; and not None
# (every other proof holds on the dev audit).
jq -e --arg s "$AUDIT_SOURCE" '.auditLevel == "limited" and .auditSource == $s' <<<"$t" >/dev/null \
  || fail "${TARGET}: level $(jq -r .auditLevel <<<"$t") / source $(jq -r .auditSource <<<"$t") before the Audit stream, expected limited / ${AUDIT_SOURCE}"
# TLS: SQL Server 2019 and 2022 on Linux have no TDS 8.0 strict mode: the `auto` mode falls back to
# the mandatory (TDS 7.x) encryption, certificate verified (ADR-0051 refinement item 3). 2025 runs
# here without network.forcestrict (the engine matrix covers forced strict): `auto` tries strict
# first; the mode it reaches is printed (a measurement: no CI entry ran 2025 unforced before).
line="$(compose logs --no-color agent 2>/dev/null | grep -F '"SQL Server checked"' | grep -F "\"target_id\":\"${TARGET}\"" | tail -n 1)"
if [ "$MSSQL_MAJOR" -ge 17 ]; then
  [[ "$line" == *"(edition 4), strict encryption"* || "$line" == *"(edition 4), mandatory encryption"* ]] \
    || fail "${TARGET}: no 'SQL Server checked' line with the Express edition and strict or mandatory encryption in the agent log"
  mode=mandatory
  [[ "$line" != *"(edition 4), strict encryption"* ]] || mode=strict
  log "${TARGET}: SQL Server ${MSSQL_VERSION} without forced strict: \`auto\` reached ${mode} encryption (certificate verified against the dev CA)"
  # Accepted until a first run has measured the mode (e2e/README.md); then asserted strict.
  if [ "$mode" = mandatory ] && [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::warning title=SQL Server ${MSSQL_VERSION} TLS::tls auto reached mandatory, not strict, on SQL Server ${MSSQL_VERSION} without forced strict"
  fi
else
  [[ "$line" == *"(edition 4), mandatory encryption"* ]] \
    || fail "${TARGET}: no 'SQL Server checked' line with the Express edition and mandatory encryption in the agent log"
  log "${TARGET}: checked over mandatory encryption (TDS 7.x, certificate verified against the dev CA)"
fi
# Negative TLS control: the same server declared with a CA that did not sign its certificate (the
# console's test CA): the target must be reported unreachable, failing at the TLS stage
# (`check.stage_failed` with `stage_tls`; the contract has no TLS failure code), never connected.
log "negative TLS control: ${BADCA} (the console test CA as ca_file) must fail at the TLS stage"
wait_target_state "$BADCA" 120 '.present and .reachable == false
    and any(.notes[]?; .code == "check.stage_failed" and ((.labels // []) | index("stage_tls")))' \
  "unreachable with check.stage_failed stage_tls"
log "${BADCA}: $(jq -c '{reachable, lastError, notes: [.notes[]? | {code, labels}]}' <<<"$TARGET_STATE")"
phase_done enroll

# --------------------------------------------------------------------------- Audit setup
log "Audit: policies '${POLICY_DUMP}' (signature.bcp, shape.full_table_read), '${POLICY_READS}' (read), '${POLICY_DCL}' (dcl)"
create_policy "$POLICY_DUMP" critical "$(jq -nc --arg t "$TARGET" '{signals: ["signature.bcp", "shape.full_table_read"], target_ids: [$t]}')"
create_policy "$POLICY_READS" medium "$(jq -nc --arg t "$TARGET" '{event_actions: ["read"], target_ids: [$t]}')"
create_policy "$POLICY_DCL" medium "$(jq -nc --arg t "$TARGET" '{event_actions: ["dcl"], target_ids: [$t]}')"
log "Audit: enabling Audit on ${TARGET}"
enable_audit "$TARGET"
phase_done audit-setup

# --------------------------------------------------------------------------- Discovery
# With the Audit stream running: the agent's own catalog reads and samples are in the audit file,
# and must not come back as events.
log "Discovery: ${TARGET} (Audit on)"
scan_targets "$SCAN_TIMEOUT_S" "$TARGET"
findings_json "$TARGET" >"$E2E_WORK_DIR/findings.json" || fail "cannot read the findings"
timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  --require-expected-classifiers --forbid-negative-controls "$E2E_WORK_DIR/findings.json" >&2 \
  || fail "findings check of ${TARGET} failed (see above)"
log "${TARGET}: $(jq length "$E2E_WORK_DIR/findings.json") finding(s)"
rm -f -- "$E2E_WORK_DIR/findings.json"
phase_done discovery

# Partial once the stream read a record (its own polls count: refinement, last proof), never Full.
log "Audit: waiting for the heartbeat level of ${TARGET} (partial, ${AUDIT_SOURCE})"
FORBIDDEN_NOTES="audit.partial_pending_first_record audit.records_dropped audit.reads_not_logged
  audit.audit_changes_not_audited audit.server_audit_filtered audit.source_not_configured
  privilege.refused privilege.audit_grant_without_audit audit.stream_stopped check.stage_failed check.timed_out"
# SQL Server Audit has no row counts (audit.log_without_row_counts, required); Extended Events has
# them (never noted), and its own proofs must hold (docs/08 "Extended Events: proofs and level").
if [ "$AUDIT_SOURCE" = sqlserver_xevents ]; then
  FORBIDDEN_NOTES+=" audit.log_without_row_counts audit.xe_events_missing audit.xe_session_filtered audit.xe_causality_off"
  REQUIRED_NOTE=""
else
  REQUIRED_NOTE="audit.log_without_row_counts"
fi
deadline=$(( $(date +%s) + 120 ))
while :; do
  t="$(target_json "$TARGET")"
  notes="$(notes_of "$t")"
  bad=""
  # shellcheck disable=SC2086 # a list of note codes
  for c in $FORBIDDEN_NOTES; do [[ " $notes " != *" $c "* ]] || bad+=" $c"; done
  if jq -e --arg s "$AUDIT_SOURCE" '.auditLevel == "partial" and .auditSource == $s' <<<"$t" >/dev/null \
      && { [ -z "$REQUIRED_NOTE" ] || [[ " $notes " == *" $REQUIRED_NOTE "* ]]; } && [ -z "$bad" ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "${TARGET}: level $(jq -r .auditLevel <<<"$t") / source $(jq -r .auditSource <<<"$t"), notes '${notes}' (expected partial, ${AUDIT_SOURCE}${REQUIRED_NOTE:+, $REQUIRED_NOTE}, none of:${bad:- the forbidden notes})"
  sleep 3
done
log "${TARGET}: audit level partial (${AUDIT_SOURCE}); notes: $notes"

# The agent's own statements are never reported: after the scan and two poll intervals, no event at
# all on the target (nobody else used the server since the stream started).
sleep 25
n="$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'")"
if [ "$n" != 0 ]; then
  console_sql "SELECT string_agg(DISTINCT coalesce(db_user, 'fp') || ' ' || action || ' ' || source, '; ')
    FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'" >&2 || true
  fail "${TARGET}: $n event(s) before any client statement: the agent's own activity surfaced"
fi
log "Audit: no event before the first client statement (check(), Discovery and the polls left out)"

# --------------------------------------------------------------------------- client traffic
# The exporter: bcp out of every readable table (application name `bcp`: signature.bcp), then a
# whole-table SELECT (shape.full_table_read). The table list and the password go on stdin, never
# on a command line (bcp reads the password from stdin when -P is absent).
log "Audit: bcp out of ${#EXPORT_TABLES[@]} tables and a whole-table SELECT as e2e_exporter"
T0_MS="$(date +%s%3N)"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
printf '%s\n' "${EXPORT_TABLES[@]}" | mssql_client '
  cat > /tmp/tables
  while IFS= read -r t; do
    '"$BCP"' "$t" out /dev/null -c -S sqlserver -d retail -U e2e_exporter </run/secrets/target_client_password >/dev/null
  done </tmp/tables
  SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)" '"$SQLCMD"' -S sqlserver -d retail -U e2e_exporter -b \
    -Q "SET NOCOUNT ON; SELECT * FROM crm.customers" >/dev/null' \
  2>"$E2E_WORK_DIR/client.err" || fail "the exporter's bcp / SELECT failed ($(client_error_code))"

# Dump -> incident: the critical incident of the exporter on the console.
deadline=$(( $(date +%s) + DUMP_INCIDENT_LIMIT_S ))
until [ "$(console_sql "SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
    AND policy_name = '${POLICY_DUMP}' AND principal = 'e2e_exporter'")" -ge 1 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "no '${POLICY_DUMP}' incident of e2e_exporter within ${DUMP_INCIDENT_LIMIT_S} s of the bcp"
  sleep 1
done
DUMP_LATENCY_MS=$(( $(date +%s%3N) - T0_MS ))
log "Audit: bcp start -> critical incident: ${DUMP_LATENCY_MS} ms (limit ${DUMP_INCIDENT_LIMIT_S} s)"

# The analyst: filtered SELECTs whose literals are ground-truth values (in the statement text that
# SQL Server Audit keeps; the agent must drop them).
# gt_needle CONTAINER OBJECT FIELD: "L<i>.v0<TAB><value>" of the first value of a location.
gt_needle() {
  jq -r --arg e "$ENGINE" --arg c "$1" --arg o "$2" --arg f "$3" '.locations | to_entries[]
    | select(.value.engine == $e and .value.container == $c and .value.object == $o and .value.field == $f
             and ((.value.values // []) | length) > 0)
    | "L\(.key).v0\t\(.value.values[0])"' "$GROUND_TRUTH" | head -n 1
}
IFS=$'\t' read -r email_id email < <(gt_needle crm customers email)
IFS=$'\t' read -r iban_id iban < <(gt_needle finance payment_cards iban)
if [ -z "${email:-}" ] || [ -z "${iban:-}" ]; then fail "no ground-truth e-mail / IBAN for the literal queries"; fi
LITERAL_IDS="$email_id $iban_id"
{
  printf 'SET NOCOUNT ON;\n'
  printf "SELECT first_name, last_name FROM crm.customers WHERE email = N'%s';\n" "${email//\'/\'\'}"
  printf "SELECT card_holder FROM finance.payment_cards WHERE iban = N'%s';\n" "${iban//\'/\'\'}"
} >"$E2E_WORK_DIR/analyst.sql"
unset email iban
log "Audit: filtered SELECTs with ground-truth literals as e2e_analyst ($LITERAL_IDS)"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
mssql_client 'SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)" exec '"$SQLCMD"' -S sqlserver -d retail -U e2e_analyst -b -i /dev/stdin' \
  <"$E2E_WORK_DIR/analyst.sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" \
  || fail "the analyst's queries failed ($(client_error_code))"
rm -f -- "$E2E_WORK_DIR/analyst.sql"

# The admin: password-bearing DCL (the #82 rule; ADR-0051 decision 6): CREATE and ALTER LOGIN with
# marker passwords, then DROP LOGIN. The markers go on stdin.
log "Audit: CREATE / ALTER / DROP LOGIN with marker passwords as e2e_admin"
{
  printf 'SET NOCOUNT ON;\n'
  printf "CREATE LOGIN e2e_dcl_probe WITH PASSWORD = N'%s', CHECK_POLICY = OFF;\n" "$DCL_MARKER_1"
  printf "ALTER LOGIN e2e_dcl_probe WITH PASSWORD = N'%s';\n" "$DCL_MARKER_2"
  printf 'DROP LOGIN e2e_dcl_probe;\n'
} >"$E2E_WORK_DIR/admin.sql"
# shellcheck disable=SC2016 # expanded by the container shell, on purpose
mssql_client 'SQLCMDPASSWORD="$(cat /run/secrets/target_client_password)" exec '"$SQLCMD"' -S sqlserver -d retail -U e2e_admin -b -i /dev/stdin' \
  <"$E2E_WORK_DIR/admin.sql" >/dev/null 2>"$E2E_WORK_DIR/client.err" \
  || fail "the admin's DCL failed ($(client_error_code))"
rm -f -- "$E2E_WORK_DIR/admin.sql" "$E2E_WORK_DIR/client.err"
phase_done traffic

# --------------------------------------------------------------------------- Audit checks
events_state() {
  console_sql "SELECT concat_ws(',',
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'e2e_exporter' AND signals ? 'signature.bcp'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND db_user = 'e2e_exporter' AND signals ? 'shape.full_table_read'),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}'
       AND target_id = '${TARGET}' AND db_user = 'e2e_analyst' AND action = 'read'),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}'
       AND target_id = '${TARGET}' AND db_user = 'e2e_admin' AND action = 'dcl'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND policy_name = '${POLICY_READS}' AND principal = 'e2e_analyst'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '${TARGET}'
       AND policy_name = '${POLICY_DCL}' AND principal = 'e2e_admin'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND evaluated_at IS NULL))"
}
log "Audit: waiting for the events and incidents (at most ${EVENTS_TIMEOUT_S} s)"
deadline=$(( $(date +%s) + EVENTS_TIMEOUT_S ))
while :; do
  st="$(events_state)" || fail "cannot read the Audit state"
  IFS=, read -r n_bcp n_full n_reads n_dcl n_inc_r n_inc_d n_pending <<<"$st"
  if [ "$n_bcp" -ge 1 ] && [ "$n_full" -ge 1 ] && [ "$n_reads" -ge 2 ] && [ "$n_dcl" -ge 3 ] \
      && [ "$n_inc_r" -ge 1 ] && [ "$n_inc_d" -ge 1 ] && [ "$n_pending" = 0 ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "Audit: events / incidents incomplete within ${EVENTS_TIMEOUT_S} s: bcp ${n_bcp}, full_table_read ${n_full}, analyst reads ${n_reads}/2, dcl ${n_dcl}/3, incidents reads ${n_inc_r} dcl ${n_inc_d}, not evaluated ${n_pending}"
  sleep 3
done
log "Audit: exporter events with signature.bcp ${n_bcp}, shape.full_table_read ${n_full}; analyst reads ${n_reads}; admin dcl ${n_dcl}"
[ "$n_reads" = 2 ] || fail "Audit: the analyst ran 2 statements, ${n_reads} read(s) counted"
[ "$n_dcl" = 3 ] || fail "Audit: the admin ran 3 DCL statements, ${n_dcl} counted"
# The analyst's events name the two tables it read, nothing else.
# Compared in SQL: only the verdict and counts reach the job log, never an object name.
objs="$(console_sql "SELECT concat_ws(',', count(DISTINCT o->>'schema' || '.' || (o->>'object')),
    bool_or(o->>'schema' = 'crm' AND o->>'object' = 'customers'),
    bool_or(o->>'schema' = 'finance' AND o->>'object' = 'payment_cards'))
  FROM access_events e, jsonb_array_elements(e.objects) o WHERE e.agent_id = '${AGENT_ID}'
  AND e.target_id = '${TARGET}' AND e.db_user = 'e2e_analyst'")"
[ "$objs" = "2,t,t" ] \
  || fail "Audit: the analyst's events should name exactly crm.customers and finance.payment_cards ($(objects_summary "$TARGET" "$ENGINE" "e.db_user = 'e2e_analyst'"))"
# Every event is the configured source's.
events_json "$TARGET" >"$E2E_WORK_DIR/events.json" || fail "cannot read the access events"
incidents_json "$TARGET" >"$E2E_WORK_DIR/incidents.json" || fail "cannot read the incidents"
jq -e --arg s "$AUDIT_SOURCE" 'all(.[]; .source == $s)' "$E2E_WORK_DIR/events.json" >/dev/null \
  || fail "Audit: an event of ${TARGET} has another source"
log "Audit: principals $(jq -c '[.[] | (.db_user // "-")] | unique' "$E2E_WORK_DIR/events.json"), actions $(jq -c '[.[].action] | unique' "$E2E_WORK_DIR/events.json")"
timeout 60 python3 "$I2_CHECK" audit --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --agent-account databastion \
  --events "$E2E_WORK_DIR/events.json" --incidents "$E2E_WORK_DIR/incidents.json" \
  --require-event "e2e_exporter:signature.bcp" --require-event "e2e_exporter:shape.full_table_read" \
  --require-event e2e_analyst --require-action "e2e_admin:dcl" \
  --require-incident "${POLICY_DUMP}:e2e_exporter" --require-incident "${POLICY_READS}:e2e_analyst" \
  --require-incident "${POLICY_DCL}:e2e_admin" >&2 || fail "Audit check of ${TARGET} failed (see above)"
rm -f -- "$E2E_WORK_DIR/events.json" "$E2E_WORK_DIR/incidents.json"

# The source side (positive control of the literal scan below): the source's own files hold the
# analyst's statements with their literals, and the DCL statements (read as sa, kept private).
# SQL Server Audit: the audit file. Extended Events: the session's files, where a password-bearing
# statement is a placeholder (`-- CREATE LOGIN`, `-- ALTER LOGIN`, docs/08 "Extended Events: what
# is kept"); the agent reports both, and the DROP LOGIN, as DCL.
if [ "$AUDIT_SOURCE" = sqlserver_xevents ]; then
  SRC_LABEL="the Extended Events files"
  mssql_sa_q "SELECT s.stmt_text FROM (${XE_STATEMENTS}) s WHERE s.principal_name IN (N'e2e_analyst', N'e2e_admin')" \
    >"$E2E_WORK_DIR/target-audit.log" || fail "cannot read the Extended Events files"
else
  SRC_LABEL="SQL Server's audit file"
  mssql_sa_q "SELECT statement FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)
    WHERE server_principal_name IN (N'e2e_analyst', N'e2e_admin')" >"$E2E_WORK_DIR/target-audit.log" \
    || fail "cannot read the server audit"
fi
needles=()
for id in $LITERAL_IDS; do needles+=(--needle "$id"); done
rc=0
timeout 120 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" \
  --label "sqlserver ${AUDIT_SOURCE} files (positive control)" "${needles[@]}" "$E2E_WORK_DIR/target-audit.log" \
  >"$E2E_WORK_DIR/literal-control.out" 2>&1 || rc=$?
for id in $LITERAL_IDS; do
  if [ "$rc" != 1 ] || ! grep -q "^LEAK ${id//./\\.} " "$E2E_WORK_DIR/literal-control.out"; then
    fail "Audit: literal $id not in ${SRC_LABEL} (positive control)"
  fi
done
# The agent's own statements are in the source's files too (seen and left out, not missed).
if [ "$AUDIT_SOURCE" = sqlserver_xevents ]; then
  n_own="$(mssql_sa_q "SELECT COUNT(*) FROM (${XE_STATEMENTS}) s WHERE s.principal_name = N'databastion'")" \
    || fail "cannot count the agent's own statement events"
  grep -qiE 'CREATE LOGIN' "$E2E_WORK_DIR/target-audit.log" \
    || fail "Audit: no CREATE LOGIN (or its placeholder) in ${SRC_LABEL}"
  grep -qiE 'ALTER LOGIN' "$E2E_WORK_DIR/target-audit.log" \
    || fail "Audit: no ALTER LOGIN (or its placeholder) in ${SRC_LABEL}"
  grep -qiE 'DROP LOGIN .*e2e_dcl_probe' "$E2E_WORK_DIR/target-audit.log" \
    || fail "Audit: no DROP LOGIN of e2e_dcl_probe in ${SRC_LABEL}"
else
  n_own="$(mssql_sa_q "SELECT COUNT(*) FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)
    WHERE server_principal_name = N'databastion' AND action_id = 'SL'")" || fail "cannot count the agent's own audit records"
  grep -qiE 'CREATE LOGIN .*e2e_dcl_probe' "$E2E_WORK_DIR/target-audit.log" \
    || fail "Audit: no CREATE LOGIN of e2e_dcl_probe in ${SRC_LABEL}"
fi
[ "${n_own:-0}" -ge 1 ] || fail "Audit: no statement of the agent's login in ${SRC_LABEL} (positive control of 'no own event')"
log "Audit: ${SRC_LABEL} hold ${n_own} statement(s) of the agent's login (left out)"
if leak_scan "$E2E_WORK_DIR/target-audit.log" "$NP" >/dev/null; then
  log "Audit: the DCL statements are in ${SRC_LABEL}, their passwords masked by the server"
else
  log "Audit: note: ${SRC_LABEL} keep a DCL marker password (the agent must still drop it)"
fi
log "Audit: the literals ($LITERAL_IDS) are in ${SRC_LABEL} (positive control)"
rm -f -- "$E2E_WORK_DIR/target-audit.log" "$E2E_WORK_DIR/literal-control.out"
phase_done audit

# --------------------------------------------------------------------------- I2 and secret hygiene
log "I2: the console database, the logs, the pages and the agent's state"
dump_logs "${SERVICES[@]}"
for f in agent.log web.log worker.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the scans would prove nothing"
done
inspect_scan "with the agent"
D="$E2E_WORK_DIR/dump"
collect_console_side "$D" "$TARGET"
grep -qF 'e2e_exporter' "$D/pages/incidents.html" || fail "the incidents page does not list e2e_exporter (page scan control)"
grep -qF "$TARGET" "$D/pages/findings.html" || fail "the findings page does not name ${TARGET} (page scan control)"
i2_failed=0
i2_canary "$ENGINE"
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "sqlserver console side" \
  "$D" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "sqlserver logs" \
  --exclude 'target-mssql.log' "$E2E_LOG_DIR" >&2 || i2_failed=1
# The literals alone (also caught above; named here) and the DCL markers in every view (whole,
# 16-character windows, base64 / hex encodings).
needles=()
for id in $LITERAL_IDS; do needles+=(--needle "$id"); done
timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$ENGINE" --label "sqlserver literals" \
  "${needles[@]}" --exclude 'target-mssql.log' "$D" "$E2E_LOG_DIR" >&2 || i2_failed=1
timeout 300 python3 "$I2_CHECK" scan --label "sqlserver DCL markers" --secret-file "$NP/dcl_marker_1" \
  --secret-file "$NP/dcl_marker_2" --exclude 'target-mssql.log' "$D" "$E2E_LOG_DIR" >&2 || i2_failed=1
pattern_canary
leaks=0
secret_hygiene "$D" 'target-mssql.log' || leaks=1
log "I2: $(find "$P" -type f | wc -l) secret(s) and $(find "$NP" -type f | wc -l) marker(s) searched"
rm -rf -- "$D"
[ "$i2_failed" = 0 ] || fail "invariant I2: ground-truth value(s), literal(s) or marker(s) of the sqlserver target in clear text (ids above)"
[ "$leaks" = 0 ] || fail "a secret or a marker password reached the console, a log or the agent's state (names above)"
phase_done i2
log "all checks passed (bcp -> incident ${DUMP_LATENCY_MS} ms)"
