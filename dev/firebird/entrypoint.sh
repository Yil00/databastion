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
# The security database of the image's own major version: from FIREBIRD_MAJOR when set (Compose
# passes DATABASTION_DEV_FIREBIRD_MAJOR), otherwise from the image's isql, so that selecting the
# 4.0.7 image targets security4.fdb with no other setting.
MAJOR="${FIREBIRD_MAJOR:-}"
if [ -z "$MAJOR" ]; then
  MAJOR="$(/opt/firebird/bin/isql -z </dev/null 2>&1 | sed -n 's/.*Firebird \([0-9][0-9]*\)\..*/\1/p' | head -n 1 || true)"
fi
case "$MAJOR" in
  4 | 5) ;;
  *)
    echo "[firebird] unsupported or unknown major version '$MAJOR' (4 or 5)" >&2
    exit 1
    ;;
esac
SECDB="/opt/firebird/security${MAJOR}.fdb"
if [ ! -f "$SECDB" ]; then
  echo "[firebird] $SECDB is not in this image (FIREBIRD_MAJOR does not match the image)" >&2
  exit 1
fi
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
  # The seed ran over an embedded connection, whose engine reads the same AuditTraceConfigFile and
  # wrote the seed's statements (fake values) to the audit log under its own pid (ADR-0060 8e):
  # emptied once, before the server starts and before any agent reads it (dev only; never on a
  # monitored server, where a truncated log is a gap).
  if [ -f /var/lib/firebird/audit/audit.log ]; then : > /var/lib/firebird/audit/audit.log; fi
  touch "$DATA/.databastion-seeded"
fi
echo "[firebird] starting the server"
exec /opt/firebird/bin/firebird
