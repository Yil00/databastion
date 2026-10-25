#!/usr/bin/env bash
# Firebird connector integration tests, lot 1 (ADR-0060 decision 10: the wire client, SRP-256,
# ChaCha, the loopback, peer-uid and forwarder rules, check()). The full dev service and its seed
# come with lot 2; until then this script starts a throwaway server from the pinned image, on the
# host's loopback only, seeds three fake accounts, and runs agent/crates/connector-firebird's
# it.rs tests against it:
#
#   dev/firebird/it.sh [5|4]        # Firebird 5.0.4 (default) or 4.0.7
#
# The server runs as uid 84 (`firebird`), as on a distribution, not as the image's root: the
# image is initialized once as root (its entrypoint), committed to a local image, then restarted
# as 84:84 on the same data volume. A `socat` forwarder on loopback is started too, so the
# forwarder rule is exercised (refused without `tunnel: true`). Every container shares the host's
# network namespace (as the agent shares the server's in production) and binds 127.0.0.1 only.
#
# The passwords are random, written to private files of a temporary directory and passed to the
# containers through --env-file and a read-only init script, never on a command line (ADR-0060
# security review N4). Everything is removed at exit. Ports: FIREBIRD_PORT (default 13050) and
# FIREBIRD_PORT + 10 for the forwarder, + 1 to + 4 for the wire-encryption variants and Firebird
# 3.0 (servers run as the image's root there: the peer rule then needs peer_uid_root, which the
# tests set for uid 0); COMPOSE_PROJECT_NAME prefixes the container names, so
# parallel runs do not collide.
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
WORK="$(mktemp -d)"
chmod 700 "$WORK"

cleanup() {
  timeout 60 docker rm -f "$NAME-init" "$NAME" "$NAME-socat" "$NAME-chacha" "$NAME-arc4" \
    "$NAME-nocrypt" "$NAME-fb3" >/dev/null 2>&1 || true
  timeout 60 docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  timeout 60 docker rmi "$LOCAL_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pw() { head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32; }
AGENT_PW="$(pw)"
ROOT_PW="$(pw)"
WRONG_PW="$(pw)"
umask 077
mkdir -p "$WORK/init"
printf 'FIREBIRD_ROOT_PASSWORD=%s\n' "$ROOT_PW" > "$WORK/env"
# The seed: the minimal variant (ADR-0060 decision 4), the extended variant's role, an account with
# no grant, and two tables (one granted, one not). Fake values only.
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
COMMIT;
SQL
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
chmod 755 "$WORK" "$WORK/init"
chmod 644 "$WORK/init/20-privilege-roles.sql"
chmod 644 "$WORK/init/10-seed.sql"

echo "[it] Firebird $MAJOR: initializing" >&2
timeout 300 docker run -d --name "$NAME-init" --network host --env-file "$WORK/env" \
  -e FIREBIRD_DATABASE=app.fdb -e FIREBIRD_CONF_RemoteServicePort="$PORT" \
  -e FIREBIRD_CONF_RemoteBindAddress=127.0.0.1 -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_AuthServer=Srp256 -v "$VOLUME:/var/lib/firebird/data" \
  -v "$WORK/init:/docker-entrypoint-initdb.d:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 120); do
  if timeout 10 docker logs "$NAME-init" 2>&1 | grep -q "Starting Firebird"; then break; fi
  sleep 1
done
timeout 10 docker logs "$NAME-init" 2>&1 | grep -q "Starting Firebird" \
  || { echo "[it] the server did not start" >&2; exit 1; }
if timeout 10 docker logs "$NAME-init" 2>&1 | grep -q "Statement failed"; then
  echo "[it] the seed failed" >&2; exit 1
fi
timeout 60 docker stop "$NAME-init" >/dev/null
timeout 120 docker commit "$NAME-init" "$LOCAL_IMAGE" >/dev/null
timeout 60 docker rm "$NAME-init" >/dev/null
timeout 60 docker run --rm -v "$VOLUME:/d" --entrypoint chown "$LOCAL_IMAGE" -R 84:84 /d
timeout 60 docker run -d --name "$NAME" --network host --user 84:84 \
  -v "$VOLUME:/var/lib/firebird/data" --entrypoint /opt/firebird/bin/firebird "$LOCAL_IMAGE" >/dev/null
timeout 60 docker run -d --name "$NAME-socat" --network host "$SOCAT" \
  "TCP-LISTEN:$FWD_PORT,bind=127.0.0.1,fork,reuseaddr" "TCP:127.0.0.1:$PORT" >/dev/null
# The wire-encryption variants (decision 1: ChaCha when ChaCha64 is not offered; Arc4 only and no
# encryption refused) and Firebird 3.0 (refused at op_connect, decision 2), each on its own port.
# The 3.0 server gets no seed: the seed's syntax is 4.0+ (system privileges, DEFAULT roles), and
# the connector is refused at op_connect, before any account is used.
variant() { # name port image extra-env...
  local n="$1" p="$2" img="$3" init=(-v "$WORK/init:/docker-entrypoint-initdb.d:ro")
  shift 3
  [ "$n" = fb3 ] && init=()
  timeout 300 docker run -d --name "$NAME-$n" --network host --env-file "$WORK/env" \
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
for n in chacha arc4 nocrypt fb3; do
  for _ in $(seq 1 120); do
    if timeout 10 docker logs "$NAME-$n" 2>&1 | grep -q "Starting Firebird"; then break; fi
    sleep 1
  done
done
sleep 3
echo "[it] Firebird $MAJOR: running the tests ($SECDB, uid 84, port $PORT)" >&2

export DATABASTION_IT_FIREBIRD=1 FIREBIRD_PORT="$PORT" FIREBIRD_IT_PEER_UID=84 \
  FIREBIRD_IT_MAJOR="$MAJOR" FIREBIRD_IT_ATTACH=/var/lib/firebird/data/app.fdb \
  FIREBIRD_IT_AGENT_PASSWORD="$AGENT_PW" FIREBIRD_IT_SYSDBA_PASSWORD="$ROOT_PW" \
  FIREBIRD_IT_WRONG_PASSWORD="$WRONG_PW" FIREBIRD_IT_FORWARDER_PORT="$FWD_PORT" \
  FIREBIRD_IT_FORWARDER_UID=0 FIREBIRD_IT_CHACHA_PORT="$((PORT + 1))" \
  FIREBIRD_IT_ARC4_PORT="$((PORT + 2))" FIREBIRD_IT_NOCRYPT_PORT="$((PORT + 3))" \
  FIREBIRD_IT_FB3_PORT="$((PORT + 4))"
cd "$ROOT/agent"
timeout 900 cargo test -p databastion-connector-firebird --all-features --locked --lib it:: -- --nocapture
