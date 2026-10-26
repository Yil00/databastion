#!/usr/bin/env bash
# Firebird connector integration tests, lot 1 (ADR-0060 decision 10: the wire client, SRP-256,
# ChaCha, the loopback, peer-uid and forwarder rules, check()). The full dev service and its seed
# come with lot 2; until then this script starts throwaway servers from the pinned images, seeds
# fake accounts, and runs agent/crates/connector-firebird's it.rs tests against them:
#
#   dev/firebird/it.sh [5|4]        # Firebird 5.0.4 (default) or 4.0.7
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
  local c=("$NAME-init" "$NAME" "$NAME-socat")
  for n in $VARIANTS; do c+=("$NAME-$n"); done
  # -v: the anonymous volumes of the image's VOLUME declarations too.
  timeout 60 docker rm -f -v "${c[@]}" "$NET" >/dev/null 2>&1 || true
  timeout 60 docker volume rm "$VOLUME" >/dev/null 2>&1 || true
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
started() { # container: waits for the server's start line
  for _ in $(seq 1 120); do
    if timeout 10 docker logs "$1" 2>&1 | grep -q "Starting Firebird"; then return 0; fi
    sleep 1
  done
  echo "[it] $1 did not start" >&2
  return 1
}
seeded() { # container: the seed must not have failed
  if timeout 10 docker logs "$1" 2>&1 | grep -q "Statement failed"; then
    echo "[it] the seed of $1 failed" >&2
    return 1
  fi
}

echo "[it] Firebird $MAJOR: initializing" >&2
timeout 300 docker run -d --name "$NAME-init" "${JOIN[@]}" --env-file "$WORK/env" \
  -e FIREBIRD_DATABASE=app.fdb -e FIREBIRD_CONF_RemoteServicePort="$PORT" \
  -e FIREBIRD_CONF_RemoteBindAddress=127.0.0.1 -e FIREBIRD_CONF_WireCrypt=Required \
  -e FIREBIRD_CONF_AuthServer=Srp256 -v "$VOLUME:/var/lib/firebird/data" \
  -v "$WORK/init:/docker-entrypoint-initdb.d:ro" "$IMAGE" >/dev/null
started "$NAME-init"
seeded "$NAME-init"
timeout 60 docker stop "$NAME-init" >/dev/null
timeout 120 docker commit --change 'ENV FIREBIRD_ROOT_PASSWORD=' "$NAME-init" "$LOCAL_IMAGE" >/dev/null
timeout 60 docker rm -v "$NAME-init" >/dev/null
timeout 60 docker run --rm --network none "${HARDEN[@]}" -v "$VOLUME:/d" --entrypoint chown \
  "$LOCAL_IMAGE" -R 84:84 /d
timeout 60 docker run -d --name "$NAME" "${JOIN[@]}" --user 84:84 \
  -v "$VOLUME:/var/lib/firebird/data" --entrypoint /opt/firebird/bin/firebird "$LOCAL_IMAGE" >/dev/null
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
sleep 3

# 4. The tests, in the namespace, as the calling user.
echo "[it] Firebird $MAJOR: running the tests ($SECDB, uid 84, port $PORT)" >&2
PID="$(timeout 30 docker inspect -f '{{.State.Pid}}' "$NET")"
timeout 900 $SUDO nsenter --net="/proc/$PID/ns/net" --setuid "$(id -u)" --setgid "$(id -g)" -- \
  env -i PATH=/usr/bin:/bin RUST_BACKTRACE=1 DATABASTION_IT_FIREBIRD=1 \
  FIREBIRD_PORT="$PORT" FIREBIRD_IT_PEER_UID=84 FIREBIRD_IT_MAJOR="$MAJOR" \
  FIREBIRD_IT_ATTACH=/var/lib/firebird/data/app.fdb \
  FIREBIRD_IT_AGENT_PASSWORD_FILE="$WORK/agent.pw" \
  FIREBIRD_IT_SYSDBA_PASSWORD_FILE="$WORK/root.pw" \
  FIREBIRD_IT_WRONG_PASSWORD_FILE="$WORK/wrong.pw" \
  FIREBIRD_IT_FORWARDER_PORT="$FWD_PORT" FIREBIRD_IT_FORWARDER_UID=0 \
  FIREBIRD_IT_CHACHA_PORT="$((PORT + 1))" FIREBIRD_IT_ARC4_PORT="$((PORT + 2))" \
  FIREBIRD_IT_NOCRYPT_PORT="$((PORT + 3))" FIREBIRD_IT_FB3_PORT="$((PORT + 4))" \
  FIREBIRD_IT_MAPPING_PORT="$((PORT + 5))" \
  "$EXE" "${FIREBIRD_IT_FILTER:-it::}" --nocapture
