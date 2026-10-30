#!/usr/bin/env bash
# Firebird connector integration tests (ADR-0060 decision 10: lot 1, the wire client, SRP-256,
# ChaCha, the loopback, peer-uid and forwarder rules, check(); lot 2, Discovery and the CAS store
# guard; lot 3, the Audit parsers against the server's own trace log). This script starts
# throwaway servers from the pinned images, seeds fake accounts and the dev seed
# (dev/seed/out/firebird.sql, loaded by dev/firebird/seed.sh as the database `crm`, the one of the
# dev service), and runs agent/crates/connector-firebird's it.rs tests against them:
#
#   dev/firebird/it.sh [5|4]        # Firebird 5.0.4 (default) or 4.0.7
#   FIREBIRD_IT_FILTER=it::discovery dev/firebird/it.sh 5   # a subset of the tests
#
# Network (review L3): every container joins one dedicated network namespace, owned by a
# placeholder container started with `--network none` (loopback only, nothing reachable from the
# host or another container), and drops NET_RAW and NET_ADMIN. The test binary is built first, then
# run inside that namespace with nsenter (root, or sudo, for the namespace only: the tests run as
# the calling user). So the tests see the servers on 127.0.0.1 and read the namespace's own
# /proc/net/tcp, as the agent does next to its server.
#
# The main server runs as uid 84 (`firebird`), as on a distribution, not as the image's root: the
# image is initialized once as root (its entrypoint), committed to a local image without the
# SYSDBA password in its configuration, then restarted as 84:84 on the same data volume. A `socat`
# forwarder is started too, so the forwarder rule is exercised (refused without `tunnel: true`).
# The other servers (ChaCha only, Arc4 only, no wire encryption, Firebird 3.0, mappings to SYSDBA
# and RDB$ADMIN) run as the image's root: the tests declare uid 0 with peer_uid_root for them.
#
# Secrets (review L4): random passwords, generated after the build, in 0600 files of a 0700
# temporary directory. The containers read the SYSDBA password through --env-file and the seed
# from a read-only bind mount (the entrypoint runs as root); the tests read the agent passwords
# from their files (FIREBIRD_IT_*_PASSWORD_FILE, `secret: {file: …}`). No password is on a command
# line, in an environment variable of the build, or in a committed image's configuration.
# Everything is removed at exit. Ports, all inside the namespace: FIREBIRD_PORT (default 13050),
# + 1 to + 5 for the variants, + 10 for the forwarder. COMPOSE_PROJECT_NAME prefixes the
# container names, so parallel runs do not collide.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAJOR="${1:-5}"
case "$MAJOR" in
  5) IMAGE="firebirdsql/firebird@sha256:1529560400fc7847f015c57fc9d70729c44d9a9d8f9000df19c5ce1950b4c202"; SECDB=security5.fdb ;;
  4) IMAGE="firebirdsql/firebird@sha256:456aeb748f6f70a4adbc910a2adc56f4d43270bcdf12808c47ca6e9603c6b17e"; SECDB=security4.fdb ;;
  *) echo "usage: $0 [5|4]" >&2; exit 2 ;;
esac
SOCAT="alpine/socat@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e"
# Firebird 3.0, which the connector refuses at connection (decision 2).
IMAGE3="firebirdsql/firebird@sha256:13208a06d768e957e029f3a544c658bfb1c1031cdf322f4e5fa9bb9368ce6015"
PORT="${FIREBIRD_PORT:-13050}"
FWD_PORT="$((PORT + 10))"
NAME="${COMPOSE_PROJECT_NAME:-databastion}-it-firebird${MAJOR}"
LOCAL_IMAGE="databastion-it/${NAME}:local"
VOLUME="${NAME}-data"
AUDIT_VOLUME="${NAME}-audit"
NET="$NAME-net"
VARIANTS="chacha arc4 nocrypt fb3 mapping"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

# 1. The test binary, before any secret exists.
cd "$ROOT/agent"
EXE="$(timeout 900 cargo test -p databastion-connector-firebird --all-features --locked --lib \
  --no-run --message-format=json \
  | jq -r 'select(.reason == "compiler-artifact" and .target.name == "databastion_connector_firebird"
             and .profile.test == true and .executable != null) | .executable' | tail -n 1)"
[ -x "$EXE" ] || { echo "[it] the test binary was not built" >&2; exit 1; }

umask 077
WORK="$(mktemp -d)"
cleanup() {
  local c=("$NAME-init" "$NAME" "$NAME-socat" "$NAME-secdb")
  for n in $VARIANTS; do c+=("$NAME-$n"); done
  # -v: the anonymous volumes of the image's VOLUME declarations too.
  timeout 60 docker rm -f -v "${c[@]}" "$NET" >/dev/null 2>&1 || true
  timeout 60 docker volume rm "$VOLUME" "$AUDIT_VOLUME" >/dev/null 2>&1 || true
  timeout 60 docker rmi "$LOCAL_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 2. Secrets: 0600 files only.
pw() { head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32; }
for f in agent root wrong; do pw > "$WORK/$f.pw"; done
AGENT_PW="$(cat "$WORK/agent.pw")"
printf 'FIREBIRD_ROOT_PASSWORD=%s\n' "$(cat "$WORK/root.pw")" > "$WORK/env"
mkdir -p "$WORK/init" "$WORK/init-mapping"
# The seed: the minimal variant (ADR-0060 decision 4), the extended variant's role, an account with
# no grant, a refused right through a role not in use, and two tables (one granted, one not).
# Fake values only.
cat > "$WORK/init/10-seed.sql" <<SQL
CREATE TABLE CUSTOMERS (ID INTEGER, EMAIL VARCHAR(100));
INSERT INTO CUSTOMERS VALUES (1, 'it-fake@example.test');
CREATE TABLE NOGRANT (ID INTEGER);
CREATE USER DATABASTION_AGENT PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE USER AGENT_EXT PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE USER AGENT_NONE PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE ROLE DATABASTION_READER;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE DATABASTION_READER;
GRANT DEFAULT DATABASTION_READER TO USER DATABASTION_AGENT;
CREATE ROLE EXT_READER SET SYSTEM PRIVILEGES TO SELECT_ANY_OBJECT_IN_DATABASE;
GRANT DEFAULT EXT_READER TO USER AGENT_EXT;
CREATE USER AGENT_NESTED PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE ROLE DBI_NESTED SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
CREATE ROLE DBI_OUTER;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE DBI_OUTER;
GRANT DBI_NESTED TO ROLE DBI_OUTER;
GRANT DBI_OUTER TO USER AGENT_NESTED;
CREATE USER AGENT_ADMIN_OPT PASSWORD '$AGENT_PW' USING PLUGIN Srp;
GRANT DATABASTION_READER TO USER AGENT_ADMIN_OPT WITH ADMIN OPTION;
CREATE USER AGENT_SYSDBA_MAPPED PASSWORD '$AGENT_PW' USING PLUGIN Srp;
COMMIT;
SQL
# The dev seed, as the database `crm` (its own reader role, and the mapping of AGENT_SYSDBA_MAPPED
# to SYSDBA): run by the image's entrypoint as an init script, over an embedded connection.
install -m 0700 "$ROOT/dev/firebird/seed.sh" "$WORK/init/40-crm.sh"
# The drift test of the system-privilege bit table (decision 4): one role per privilege of the
# version, DBI_P_<name>.
privileges="USER_MANAGEMENT READ_RAW_PAGES CREATE_USER_TYPES USE_NBACKUP_UTILITY CHANGE_SHUTDOWN_MODE
TRACE_ANY_ATTACHMENT MONITOR_ANY_ATTACHMENT ACCESS_SHUTDOWN_DATABASE CREATE_DATABASE DROP_DATABASE
USE_GBAK_UTILITY USE_GSTAT_UTILITY USE_GFIX_UTILITY IGNORE_DB_TRIGGERS CHANGE_HEADER_SETTINGS
SELECT_ANY_OBJECT_IN_DATABASE ACCESS_ANY_OBJECT_IN_DATABASE MODIFY_ANY_OBJECT_IN_DATABASE
CHANGE_MAPPING_RULES USE_GRANTED_BY_CLAUSE GRANT_REVOKE_ON_ANY_OBJECT GRANT_REVOKE_ANY_DDL_RIGHT
CREATE_PRIVILEGED_ROLES GET_DBCRYPT_INFO MODIFY_EXT_CONN_POOL REPLICATE_INTO_DATABASE"
[ "$MAJOR" = 5 ] && privileges="$privileges PROFILE_ANY_ATTACHMENT"
for p in $privileges; do
  printf 'CREATE ROLE DBI_P_%s SET SYSTEM PRIVILEGES TO %s;\n' "$p" "$p"
done > "$WORK/init/20-privilege-roles.sql"
echo "COMMIT;" >> "$WORK/init/20-privilege-roles.sql"
# The mapping server (review L2): a local mapping to SYSDBA for one account through the `Srp`
# plugin name, a global one to RDB$ADMIN for another account restricted to another database, and
# two that cannot match the agent's login (another user; the Legacy_Auth plugin).
cp "$WORK/init/10-seed.sql" "$WORK/init-mapping/10-seed.sql"
cat > "$WORK/init-mapping/30-mappings.sql" <<SQL
CREATE USER MAP_LOCAL PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE USER MAP_GLOBAL PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE USER OTHER_U PASSWORD '$AGENT_PW' USING PLUGIN Srp;
CREATE MAPPING IT_MAP_LOCAL USING PLUGIN SRP FROM USER MAP_LOCAL TO USER SYSDBA;
CREATE GLOBAL MAPPING IT_MAP_GLOBAL USING ANY PLUGIN IN "/var/lib/firebird/data/other.fdb"
  FROM USER MAP_GLOBAL TO ROLE RDB\$ADMIN;
CREATE MAPPING IT_MAP_OTHER USING PLUGIN SRP FROM USER OTHER_U TO USER SYSDBA;
CREATE GLOBAL MAPPING IT_MAP_LEGACY USING PLUGIN LEGACY_AUTH FROM ANY USER TO USER SYSDBA;
COMMIT;
SQL
unset AGENT_PW

# 3. The namespace and the servers.
HARDEN=(--cap-drop NET_RAW --cap-drop NET_ADMIN)
JOIN=(--network "container:$NET" "${HARDEN[@]}")
timeout 120 docker run -d --name "$NET" --network none "${HARDEN[@]}" --entrypoint sleep \
  "$SOCAT" infinity >/dev/null
# Log checks read the whole log (`grep >/dev/null`, never `grep -q`): with pipefail, `grep -q`
# exits at its first match and `docker logs` then fails on the closed pipe, so a check could fail
# on a log that has the line (seen 2 runs in 20 on the seeded server's long log).
started() { # container: waits for the server's start line
  for _ in $(seq 1 120); do
    if timeout 10 docker logs "$1" 2>&1 | grep -F "Starting Firebird" >/dev/null; then return 0; fi
    sleep 1
  done
  echo "[it] $1 did not start" >&2
  return 1
}
seeded() { # container: the seed must not have failed
  if timeout 10 docker logs "$1" 2>&1 | grep -F "Statement failed" >/dev/null; then
    echo "[it] the seed of $1 failed" >&2
    return 1
  fi
}

echo "[it] Firebird $MAJOR: initializing" >&2
timeout 300 docker run -d --name "$NAME-init" "${JOIN[@]}" --env-file "$WORK/env" \
  -e FIREBIRD_DATABASE=app.fdb -e FIREBIRD_CONF_RemoteServicePort="$PORT" \
  -e FIREBIRD_CONF_RemoteBindAddress=127.0.0.1 -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_AuthServer=Srp256 \
  -e "FIREBIRD_CONF_ExternalFileAccess=Restrict /var/lib/firebird/data/external" \
  -v "$VOLUME:/var/lib/firebird/data" -v "$WORK/init:/docker-entrypoint-initdb.d:ro" \
  -v "$ROOT/dev/seed/out/firebird.sql:/databastion/seed/firebird.sql:ro" "$IMAGE" >/dev/null
started "$NAME-init"
seeded "$NAME-init"
if ! timeout 10 docker logs "$NAME-init" 2>&1 | grep -F "crm.fdb seeded" >/dev/null; then
  echo "[it] the dev seed (crm) was not loaded" >&2
  exit 1
fi
timeout 60 docker stop "$NAME-init" >/dev/null
# The system audit trace (lot 3, decision 6): the image's firebird.conf (with its entrypoint's
# settings) plus AuditTraceConfigFile, and a trace configuration meeting the Partial proofs for
# app.fdb and crm.fdb (the dev one, with a section for each), the log on its own volume. Mounted
# read-only over the main server's; copies are kept for the configuration tests.
timeout 60 docker cp "$NAME-init:/opt/firebird/firebird.conf" "$WORK/firebird.conf"
timeout 60 docker cp "$NAME-init:/opt/firebird/databases.conf" "$WORK/databases.conf"
printf '\nAuditTraceConfigFile = /databastion/fbtrace.conf\n' >> "$WORK/firebird.conf"
awk -v app=/var/lib/firebird/data/app.fdb '
  /^database = \/var\/lib\/firebird\/data\/crm.fdb$/ { s = 1 }
  s { sec = sec $0 "\n" }
  { print }
  s && /^}$/ { s = 0; sub(/crm\.fdb/, "app.fdb", sec); printf "\n%s", sec }
' "$ROOT/dev/firebird/fbtrace.conf" > "$WORK/fbtrace.conf"
chmod 0644 "$WORK/firebird.conf" "$WORK/fbtrace.conf"
timeout 120 docker commit --change 'ENV FIREBIRD_ROOT_PASSWORD=' "$NAME-init" "$LOCAL_IMAGE" >/dev/null
timeout 60 docker rm -v "$NAME-init" >/dev/null
timeout 60 docker run --rm --network none "${HARDEN[@]}" -v "$VOLUME:/d" --entrypoint chown \
  "$LOCAL_IMAGE" -R 84:84 /d
timeout 60 docker run --rm --network none "${HARDEN[@]}" -v "$AUDIT_VOLUME:/a" --entrypoint chown \
  "$LOCAL_IMAGE" 84:84 /a
timeout 60 docker run -d --name "$NAME" "${JOIN[@]}" --user 84:84 \
  -v "$VOLUME:/var/lib/firebird/data" -v "$AUDIT_VOLUME:/var/lib/firebird/audit" \
  -v "$WORK/firebird.conf:/opt/firebird/firebird.conf:ro" \
  -v "$WORK/fbtrace.conf:/databastion/fbtrace.conf:ro" \
  --entrypoint /opt/firebird/bin/firebird "$LOCAL_IMAGE" >/dev/null
timeout 60 docker run -d --name "$NAME-socat" "${JOIN[@]}" "$SOCAT" \
  "TCP-LISTEN:$FWD_PORT,bind=127.0.0.1,fork,reuseaddr" "TCP:127.0.0.1:$PORT" >/dev/null
# The variants: ChaCha when ChaCha64 is not offered, Arc4 only and no encryption refused (decision
# 1), Firebird 3.0 refused at op_connect (decision 2), the mappings (review L2). The 3.0 server
# gets no seed: the seed's syntax is 4.0+ (system privileges, DEFAULT roles), and the connector is
# refused at op_connect, before any account is used.
variant() { # name port image extra-env...
  local n="$1" p="$2" img="$3" init=(-v "$WORK/init:/docker-entrypoint-initdb.d:ro")
  shift 3
  case "$n" in
    fb3) init=() ;;
    mapping) init=(-v "$WORK/init-mapping:/docker-entrypoint-initdb.d:ro") ;;
  esac
  timeout 300 docker run -d --name "$NAME-$n" "${JOIN[@]}" --env-file "$WORK/env" \
    -e FIREBIRD_DATABASE=app.fdb -e FIREBIRD_CONF_RemoteServicePort="$p" \
    -e FIREBIRD_CONF_RemoteBindAddress=127.0.0.1 "$@" "${init[@]}" "$img" >/dev/null
}
variant chacha "$((PORT + 1))" "$IMAGE" -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_WireCryptPlugin=ChaCha -e FIREBIRD_CONF_AuthServer=Srp256
variant arc4 "$((PORT + 2))" "$IMAGE" -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_WireCryptPlugin=Arc4 -e FIREBIRD_CONF_AuthServer=Srp256
variant nocrypt "$((PORT + 3))" "$IMAGE" -e FIREBIRD_CONF_WireCrypt=Disabled \
  -e FIREBIRD_CONF_AuthServer=Srp256
variant fb3 "$((PORT + 4))" "$IMAGE3" -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_AuthServer=Srp256
variant mapping "$((PORT + 5))" "$IMAGE" -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_AuthServer=Srp256
for n in $VARIANTS; do started "$NAME-$n"; done
seeded "$NAME-mapping"
# Every server and the forwarder must listen before the tests start (a test that connects too
# early would see "connection refused" instead of the rule it checks): a LISTEN row (state 0A) on
# 127.0.0.1:<port> in the namespace's own /proc/net/tcp.
NETPID="$(timeout 30 docker inspect -f '{{.State.Pid}}' "$NET")"
listening() { # port
  local hex
  hex="$(printf '0100007F:%04X' "$1")"
  for _ in $(seq 1 120); do
    if timeout 10 $SUDO nsenter --net="/proc/$NETPID/ns/net" cat /proc/net/tcp \
      | awk -v a="$hex" '$2 == a && $4 == "0A" { found = 1 } END { exit !found }'; then
      return 0
    fi
    sleep 1
  done
  echo "[it] nothing listens on 127.0.0.1:$1" >&2
  return 1
}
for p in "$PORT" "$((PORT + 1))" "$((PORT + 2))" "$((PORT + 3))" "$((PORT + 4))" "$((PORT + 5))" \
  "$FWD_PORT"; do
  listening "$p"
done
# Every relation of the image's own security database (security review L5), for the drift test:
# an embedded read of a fresh copy (the image's file, no network), as the server's account.
# shellcheck disable=SC2016 # Firebird names, not shell expansions.
printf 'SET HEADING OFF;\nSELECT TRIM(RDB$RELATION_NAME) FROM RDB$RELATIONS ORDER BY 1;\n' \
  | timeout 120 docker run -i --rm --name "$NAME-secdb" --network none "${HARDEN[@]}" \
    --user 84:84 --entrypoint /opt/firebird/bin/isql "$IMAGE" \
    -q -b -user SYSDBA "/opt/firebird/$SECDB" \
  | awk 'NF { print $1 }' > "$WORK/secdb.txt"
[ "$(wc -l < "$WORK/secdb.txt")" -ge 8 ] || { echo "[it] $SECDB: relation list not read" >&2; exit 1; }

# The Audit workload (lot 3), over loopback TCP as SYSDBA with the image's own tools, as the
# server's account: the password on the tool's standard input (its first line, then ISC_PASSWORD),
# never on a command line. Fake markers only: a literal and a password.
as_sysdba() { # tool args...: stdin = the password line, then the tool's input
  timeout 120 docker exec -i --user 84:84 "$NAME" bash -c \
    'IFS= read -r ISC_PASSWORD; export ISC_PASSWORD; exec "$@"' bash "$@"
}
{
  cat "$WORK/root.pw"
  cat <<SQL
SELECT * FROM CUSTOMERS;
SELECT COUNT(*) FROM CUSTOMERS;
SELECT * FROM CUSTOMERS WHERE EMAIL = 'it-marker-lit-7';
CREATE USER IT_MARKER_USER PASSWORD 'it-marker-pw-7' USING PLUGIN Srp;
COMMIT;
DROP USER IT_MARKER_USER USING PLUGIN Srp;
COMMIT;
ALTER DATABASE BEGIN BACKUP;
ALTER DATABASE END BACKUP;
COMMIT;
SQL
} | as_sysdba /opt/firebird/bin/isql -q -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/app.fdb" \
  >/dev/null
# The #82 marker cases the stock tools can write (ADR-0060 item 5): a routine's returned value,
# `EXECUTE STATEMENT`'s inner text, a client process name, and a database-trigger record's process
# name (an `ON CONNECT` trigger on crm.fdb while the renamed client attaches). A BLR literal
# (`print_blr` is off in the proved trace configuration) and a parameter (isql sends none) are
# parser fixtures (`trace_events_tests::markers_never_reach_an_event`).
{
  cat "$WORK/root.pw"
  cat <<'SQL'
SET TERM ^ ;
CREATE FUNCTION F_IT_MARKER RETURNS VARCHAR(20) AS BEGIN RETURN 'it-marker-ret-7'; END^
EXECUTE BLOCK AS DECLARE X VARCHAR(20); BEGIN EXECUTE STATEMENT 'SELECT ''it-marker-es-7'' FROM RDB$DATABASE' INTO X; END^
SET TERM ; ^
COMMIT;
SELECT F_IT_MARKER() FROM RDB$DATABASE;
DROP FUNCTION F_IT_MARKER;
COMMIT;
SQL
} | as_sysdba /opt/firebird/bin/isql -q -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/app.fdb" \
  >/dev/null
{
  cat "$WORK/root.pw"
  cat <<'SQL'
SET TERM ^ ;
CREATE TRIGGER T_IT_CONNECT ON CONNECT AS BEGIN END^
SET TERM ; ^
COMMIT;
SQL
} | as_sysdba /opt/firebird/bin/isql -q -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/crm.fdb" \
  >/dev/null
timeout 60 docker exec --user 84:84 "$NAME" sh -c \
  'mkdir -p /tmp/it-marker-proc-7 && cp /opt/firebird/bin/isql /tmp/it-marker-proc-7/isql'
{
  cat "$WORK/root.pw"
  # shellcheck disable=SC2016 # A Firebird name, not a shell expansion.
  echo 'SELECT COUNT(*) FROM RDB$DATABASE;'
} | as_sysdba env LD_LIBRARY_PATH=/opt/firebird/lib FIREBIRD=/opt/firebird \
  /tmp/it-marker-proc-7/isql -q -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/crm.fdb" >/dev/null
{
  cat "$WORK/root.pw"
  printf 'DROP TRIGGER T_IT_CONNECT;\nCOMMIT;\n'
} | as_sysdba /opt/firebird/bin/isql -q -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/crm.fdb" \
  >/dev/null
timeout 60 docker exec "$NAME" rm -rf /tmp/it-marker-proc-7
as_sysdba /opt/firebird/bin/gbak -b -se "127.0.0.1/$PORT:service_mgr" \
  /var/lib/firebird/data/app.fdb /tmp/it-app.fbk -user SYSDBA < "$WORK/root.pw" >/dev/null
timeout 60 docker exec "$NAME" rm -f /tmp/it-app.fbk

# ADR-0060 R41 item 9: a database outside the trace (deps.fdb) with the review's cases, for the
# dependent-set read on the server: a procedure over MON$STATEMENTS, a computed column (dependent
# type 3), a call cycle, a standalone P next to a packaged PKG.P, a view calling a packaged
# function, ON CONNECT and row triggers, a check constraint and a domain check over virtual
# relations; then whether an expression index can depend on a virtual relation.
{
  cat "$WORK/root.pw"
  printf "CREATE DATABASE '127.0.0.1/%s:/var/lib/firebird/data/deps.fdb' DEFAULT CHARACTER SET UTF8;\n" "$PORT"
  cat <<'SQL'
CREATE TABLE T (ID INTEGER, X VARCHAR(10));
CREATE TABLE T_COMP (ID INTEGER, C COMPUTED BY ((SELECT COUNT(*) FROM MON$STATEMENTS)));
CREATE DOMAIN D_CHK AS INTEGER CHECK (VALUE > (SELECT COUNT(*) FROM MON$CALL_STACK));
CREATE TABLE T_DOM (ID D_CHK);
CREATE TABLE T_CHK (ID INTEGER CHECK (ID > (SELECT COUNT(*) FROM MON$CONTEXT_VARIABLES)));
SET TERM ^ ;
CREATE PROCEDURE P_MON RETURNS (S VARCHAR(100)) AS BEGIN FOR SELECT CAST(MON$SQL_TEXT AS VARCHAR(100)) FROM MON$STATEMENTS INTO :S DO SUSPEND; END^
CREATE PROCEDURE P_OK RETURNS (I INTEGER) AS BEGIN FOR SELECT ID FROM T INTO :I DO SUSPEND; END^
CREATE PROCEDURE P1 (N INTEGER) RETURNS (I INTEGER) AS BEGIN I = 0; END^
CREATE PROCEDURE P2 (N INTEGER) RETURNS (I INTEGER) AS BEGIN I = 0; END^
ALTER PROCEDURE P1 (N INTEGER) RETURNS (I INTEGER) AS BEGIN IF (N > 0) THEN EXECUTE PROCEDURE P2 (N - 1) RETURNING_VALUES :I; SELECT COUNT(*) FROM SEC$USERS INTO :I; END^
ALTER PROCEDURE P2 (N INTEGER) RETURNS (I INTEGER) AS BEGIN IF (N > 0) THEN EXECUTE PROCEDURE P1 (N - 1) RETURNING_VALUES :I; END^
CREATE PROCEDURE P RETURNS (I INTEGER) AS BEGIN I = 1; SUSPEND; END^
CREATE PACKAGE PKG AS BEGIN FUNCTION F RETURNS INTEGER; PROCEDURE P RETURNS (I INTEGER); END^
CREATE PACKAGE BODY PKG AS BEGIN FUNCTION F RETURNS INTEGER AS BEGIN RETURN (SELECT COUNT(*) FROM MON$STATEMENTS); END PROCEDURE P RETURNS (I INTEGER) AS BEGIN I = 1; SUSPEND; END END^
CREATE VIEW V_PKG (N) AS SELECT PKG.F() FROM RDB$DATABASE^
CREATE TRIGGER TR_CONN ON CONNECT AS DECLARE N INTEGER; BEGIN SELECT COUNT(*) FROM MON$STATEMENTS INTO :N; END^
CREATE TRIGGER TR_ROW FOR T BEFORE INSERT AS DECLARE N INTEGER; BEGIN SELECT COUNT(*) FROM MON$CONTEXT_VARIABLES INTO :N; END^
SET TERM ; ^
COMMIT;
SQL
} | as_sysdba /opt/firebird/bin/isql -q -user SYSDBA >/dev/null
if {
  cat "$WORK/root.pw"
  cat <<'SQL'
CREATE INDEX IX_EXPR ON T COMPUTED BY ((SELECT COUNT(*) FROM MON$STATEMENTS));
COMMIT;
SQL
} | as_sysdba /opt/firebird/bin/isql -q -b -user SYSDBA "127.0.0.1/$PORT:/var/lib/firebird/data/deps.fdb" \
  >/dev/null 2>&1; then
  echo "[measure] expression index over a virtual relation: accepted" >&2
else
  echo "[measure] expression index over a virtual relation: refused" >&2
fi

# The tests run in the network namespace, as the calling user.
PID="$(timeout 30 docker inspect -f '{{.State.Pid}}' "$NET")"
run_tests() { # filter, then extra NAME=value settings
  local filter="$1"
  shift
  timeout 900 $SUDO nsenter --net="/proc/$PID/ns/net" --setuid "$(id -u)" --setgid "$(id -g)" -- \
  env -i PATH=/usr/bin:/bin RUST_BACKTRACE=1 DATABASTION_IT_FIREBIRD=1 "$@" \
  FIREBIRD_PORT="$PORT" FIREBIRD_IT_PEER_UID=84 FIREBIRD_IT_MAJOR="$MAJOR" \
  FIREBIRD_IT_ATTACH=/var/lib/firebird/data/app.fdb \
  FIREBIRD_IT_CRM_ATTACH=/var/lib/firebird/data/crm.fdb \
  FIREBIRD_IT_AGENT_PASSWORD_FILE="$WORK/agent.pw" \
  FIREBIRD_IT_SYSDBA_PASSWORD_FILE="$WORK/root.pw" \
  FIREBIRD_IT_WRONG_PASSWORD_FILE="$WORK/wrong.pw" \
  FIREBIRD_IT_FORWARDER_PORT="$FWD_PORT" FIREBIRD_IT_FORWARDER_UID=0 \
  FIREBIRD_IT_CHACHA_PORT="$((PORT + 1))" FIREBIRD_IT_ARC4_PORT="$((PORT + 2))" \
  FIREBIRD_IT_NOCRYPT_PORT="$((PORT + 3))" FIREBIRD_IT_FB3_PORT="$((PORT + 4))" \
  FIREBIRD_IT_MAPPING_PORT="$((PORT + 5))" \
  FIREBIRD_IT_SECDB_RELATIONS_FILE="$WORK/secdb.txt" \
  FIREBIRD_IT_FIREBIRD_CONF="$WORK/firebird.conf" FIREBIRD_IT_DATABASES_CONF="$WORK/databases.conf" \
  FIREBIRD_IT_TRACE_CONF="$WORK/fbtrace.conf" \
  "$EXE" "$filter" --nocapture
}
# The own-statement matrix test of R20, phase 1: the agent's own reads while the trace runs, its
# ledger (attachment ids, ports, statement texts and counts; no value) written for phase 2.
run_tests it::own_reads_for_the_matrix FIREBIRD_IT_MATRIX_OUT="$WORK/matrix.txt" >&2
[ -s "$WORK/matrix.txt" ] || { echo "[it] the matrix ledger was not written" >&2; exit 1; }
sleep 3
# The log is the server's (0600, uid 84): read through the container, written here by the caller.
timeout 60 docker exec --user 84:84 "$NAME" cat /var/lib/firebird/audit/audit.log > "$WORK/audit.log"
[ -s "$WORK/audit.log" ] || { echo "[it] the audit log is empty" >&2; exit 1; }

# Security review N5 of 2026-10-30: what the server applies for each boolean spelling, from a user
# trace session (`log_connections = <spelling>`) around one attachment: `true` (traced), `false`
# (not traced) or `refused` (the session does not start). After the log is copied.
# shellcheck disable=SC2016 # The script's variables are the inner shell's.
for spelling in true false TRUE False yes no on off 1 0 Yes ON enabled 2 '"true"' "'true'"; do
  verdict="$({
    cat "$WORK/root.pw"
  } | timeout 60 docker exec -i --user 84:84 "$NAME" bash -c '
    IFS= read -r ISC_PASSWORD; export ISC_PASSWORD
    printf "database\n{\n\tenabled = true\n\tlog_connections = %s\n}\n" "$1" > /tmp/it-bool.conf
    timeout 8 /opt/firebird/bin/fbtracemgr -se "127.0.0.1/$2:service_mgr" -user SYSDBA -start \
      -name it-bool -config /tmp/it-bool.conf > /tmp/it-bool.out 2>&1 &
    sleep 2
    echo "SELECT 1 FROM RDB\$DATABASE;" | /opt/firebird/bin/isql -q -user SYSDBA \
      "127.0.0.1/$2:/var/lib/firebird/data/crm.fdb" > /dev/null 2>&1
    sleep 2
    wait
    if grep -q ATTACH_DATABASE /tmp/it-bool.out; then echo true
    elif grep -qiE "error|wrong|invalid|unknown" /tmp/it-bool.out; then echo refused
    else echo false; fi
    rm -f /tmp/it-bool.conf /tmp/it-bool.out' bash "$spelling" "$PORT")"
  echo "$spelling $verdict" >> "$WORK/booleans.txt"
done
cat "$WORK/booleans.txt" | sed 's/^/[measure] trace boolean (server) /' >&2

# Security review N4 of 94530b3: the server's command line (argv[0] must be absolute for the
# layout check, R40 item 6); it holds no secret.
# shellcheck disable=SC2016 # The inner shell's variables.
timeout 30 docker exec "$NAME" sh -c \
  'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = firebird ] && tr "\0" " " < "$p/cmdline" && echo; done; true' \
  | sed 's/^/[measure] server command line: /' >&2

# 4. The tests.
echo "[it] Firebird $MAJOR: running the tests ($SECDB, uid 84, port $PORT)" >&2
run_tests "${FIREBIRD_IT_FILTER:-it::}" FIREBIRD_IT_AUDIT_LOG="$WORK/audit.log" \
  FIREBIRD_IT_MATRIX_FILE="$WORK/matrix.txt" FIREBIRD_IT_BOOLEANS_FILE="$WORK/booleans.txt"
