#!/bin/bash
# DataBastion dev Valkey / Redis (opt-in profile `redis`, ADR-0052 decision 13). DEV-ONLY.
# Runs as the image's server user (uid 999) and serves the same keyspace on both engines:
# 1. An ACL file in /tmp (0600): `default` off; `admin` (seeding and manual inspection only);
#    `databastion`, the agent's user with the exact allow-list of ADR-0052 decision 4 (Discovery
#    plus the Audit reads, which dev enables), with the version-dependent parts of that decision;
#    `databastion_scoped`, the same rights on the patterns of DATABASTION_DEV_REDIS_SCOPED_PATTERNS
#    only (declared in agent.yaml as `redis.key_patterns`). Passwords are stored as `#<sha256>`.
# 2. TLS only on TCP (`--port 0`), with the dev CA of the one-shot `redis-tls-init`; client
#    certificates optional. A Unix socket in /tmp (0700) serves the seeding below.
#    DATABASTION_DEV_REDIS_EXTRA_ACL names a file of further `user` lines (the e2e and load test
#    clients), appended as is.
# 3. On the first start of the data volume, dev/seed/out/redis.txt is loaded by `admin` with the
#    slow log disabled; then the slow log threshold is set to DATABASTION_DEV_REDIS_SLOWLOG_US
#    (default 0: every command, the MongoDB `slowms 0` analogue) and the logs are reset. The slow
#    log keeps DATABASTION_DEV_REDIS_SLOWLOG_MAX_LEN entries (default 128).
# 4. The healthcheck reads a marker, so it never sends a command (no slow-log or ACL LOG noise).
set -euo pipefail

if command -v valkey-server >/dev/null 2>&1; then
  ENGINE=valkey SERVER=valkey-server CLI=valkey-cli
else
  ENGINE=redis SERVER=redis-server CLI=redis-cli
fi
VERSION="$("$SERVER" --version | sed -n 's/.* v=\([0-9][0-9.]*\).*/\1/p')"
IFS=. read -r MAJOR MINOR _ <<< "$VERSION"
at_least() { [ "$MAJOR" -gt "$1" ] || { [ "$MAJOR" -eq "$1" ] && [ "$MINOR" -ge "$2" ]; }; }
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

READ_PREFIX='%R~' DRYRUN='+acl|dryrun' NO_TOUCH='+client|no-touch' COMMANDLOG=''
if [ "$ENGINE" = redis ]; then
  # Redis 6.2: no read-only key patterns (7.0), no ACL DRYRUN (7.0), no CLIENT NO-TOUCH (7.2).
  at_least 7 0 || { READ_PREFIX='~'; DRYRUN=''; }
  at_least 7 2 || NO_TOUCH=''
else
  # Valkey: the command log (and its read) since 8.1.
  at_least 8 1 && COMMANDLOG='+commandlog|get'
fi
RIGHTS="-@all +select +scan +type +getrange +hrandfield +hstrlen +hmget +srandmember +zrandmember +lrange \
+xrevrange +info $DRYRUN +slowlog|get +acl|log +client|list $COMMANDLOG $NO_TOUCH"
SCOPED=''
for p in ${DATABASTION_DEV_REDIS_SCOPED_PATTERNS:-customer:* user:*}; do SCOPED="$SCOPED $READ_PREFIX$p"; done

ACL=/tmp/databastion-users.acl
(
  umask 077
  {
    echo "user default off resetkeys resetchannels -@all"
    echo "user admin on #$(sha "$REDIS_ADMIN_PASSWORD") ~* &* +@all"
    echo "user databastion on #$(sha "$DATABASTION_DB_PASSWORD") resetkeys ${READ_PREFIX}* resetchannels $RIGHTS"
    echo "user databastion_scoped on #$(sha "$DATABASTION_DB_PASSWORD") resetkeys$SCOPED resetchannels $RIGHTS"
    # Extra users (e2e and load test clients), `user` lines only, passwords as `#<sha256>`.
    if [ -n "${DATABASTION_DEV_REDIS_EXTRA_ACL:-}" ]; then
      if grep -qv '^user [A-Za-z0-9_-]* ' "$DATABASTION_DEV_REDIS_EXTRA_ACL"; then
        echo "databastion: $DATABASTION_DEV_REDIS_EXTRA_ACL holds a line that is not a user line" >&2
        exit 1
      fi
      cat "$DATABASTION_DEV_REDIS_EXTRA_ACL"
    fi
  } > "$ACL"
)

SOCK=/tmp/databastion-dev.sock
"$SERVER" --aclfile "$ACL" --port 0 --tls-port 6379 \
  --tls-cert-file /tls/server.pem --tls-key-file /tls/server.key --tls-ca-cert-file /tls/ca.pem \
  --tls-auth-clients optional --unixsocket "$SOCK" --unixsocketperm 700 \
  --save 60 1 --appendonly no --slowlog-log-slower-than -1 --slowlog-max-len "${DATABASTION_DEV_REDIS_SLOWLOG_MAX_LEN:-128}" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"' TERM INT

# The password through the environment of the client only, never on its command line.
cli() { REDISCLI_AUTH="$REDIS_ADMIN_PASSWORD" "$CLI" -s "$SOCK" --user admin --no-auth-warning "$@"; }
for _ in $(seq 1 60); do
  if [ -S "$SOCK" ] && cli PING >/dev/null 2>&1; then break; fi
  kill -0 "$pid" 2>/dev/null || { echo "$SERVER exited during startup" >&2; exit 1; }
  sleep 1
done

if [ ! -f /data/.databastion-seeded ]; then
  echo "databastion: loading the dev keyspace ($ENGINE $VERSION)"
  if grep -v '^#' /seed/redis.txt | cli 2>&1 | grep -E '^(\(error\) )?(ERR|WRONGTYPE|NOPERM)'; then
    echo "databastion: seeding failed" >&2
    exit 1
  fi
  cli SAVE >/dev/null
  touch /data/.databastion-seeded
fi
cli CONFIG SET slowlog-log-slower-than "${DATABASTION_DEV_REDIS_SLOWLOG_US:-0}" >/dev/null
cli SLOWLOG RESET >/dev/null
cli ACL LOG RESET >/dev/null
echo "databastion: $ENGINE $VERSION ready (TLS on 6379)"
touch /tmp/databastion-ready
wait "$pid"
