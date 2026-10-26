#!/usr/bin/env bash
# Entrypoint of the Firebird dev service (ADR-0060 decision 9), run as the server's own account
# (uid 84, `firebird`), never root: the agent's default `peer_uid: firebird` then matches the
# server's sockets. Before the server starts, over embedded connections of the image's own isql
# (no network, no password on any command line: the values come from the environment and reach
# isql on its standard input):
#   1. the accounts, in the security database of this container (again at every start, as the
#      security database lives in the container, not in the data volume): SYSDBA (seeding and
#      inspection only, never the agent), DATABASTION_AGENT (the minimal variant, decision 4) and
#      AGENT_SYSDBA_MAPPED (mapped to SYSDBA in the database: refused, for the refusal tests);
#   2. on the first start, the database `crm` from the generated seed (dev/firebird/seed.sh).
# Then the SuperServer in the foreground. Dev-only fake passwords (dev/.env).
set -euo pipefail

: "${FIREBIRD_SYSDBA_PASSWORD:?}" "${FIREBIRD_DATABASTION_PASSWORD:?}"
if [ "$(id -u)" -eq 0 ]; then
  echo "[firebird] refusing to run as root (ADR-0060 decision 9)" >&2
  exit 1
fi
SECDB="/opt/firebird/security${FIREBIRD_MAJOR:-5}.fdb"
DATA=/var/lib/firebird/data
sql_string() { printf "'%s'" "${1//\'/\'\'}"; }

/opt/firebird/bin/isql -q -b -user SYSDBA "$SECDB" <<SQL
CREATE OR ALTER USER SYSDBA PASSWORD $(sql_string "$FIREBIRD_SYSDBA_PASSWORD") USING PLUGIN Srp;
CREATE OR ALTER USER DATABASTION_AGENT PASSWORD $(sql_string "$FIREBIRD_DATABASTION_PASSWORD") USING PLUGIN Srp;
CREATE OR ALTER USER AGENT_SYSDBA_MAPPED PASSWORD $(sql_string "$FIREBIRD_DATABASTION_PASSWORD") USING PLUGIN Srp;
COMMIT;
EXIT;
SQL
unset FIREBIRD_SYSDBA_PASSWORD FIREBIRD_DATABASTION_PASSWORD
echo "[firebird] accounts ready"

if [ ! -f "$DATA/.databastion-seeded" ]; then
  FIREBIRD_SEED_DATABASE="$DATA/crm.fdb" bash /databastion/seed.sh
  touch "$DATA/.databastion-seeded"
fi
echo "[firebird] starting the server"
exec /opt/firebird/bin/firebird
