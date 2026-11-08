#!/usr/bin/env bash
# Creates the Firebird dev database `crm` and loads the generated seed (dev/seed/out/firebird.sql,
# ADR-0060 decision 9), inside the service's container, with the image's own isql over an
# embedded connection: no server, no network, no password (dev tooling, never the agent). Run by
# dev/firebird/entrypoint.sh on the first start of the dev service, and as an init script of the
# throwaway servers of dev/firebird/it.sh. Does nothing when the database exists.
#
#   FIREBIRD_SEED_DATABASE  the database file (default /var/lib/firebird/data/crm.fdb)
#   FIREBIRD_SEED_FILE      the seed (default /databastion/seed/firebird.sql)
set -euo pipefail

DB="${FIREBIRD_SEED_DATABASE:-/var/lib/firebird/data/crm.fdb}"
SEED="${FIREBIRD_SEED_FILE:-/databastion/seed/firebird.sql}"
# The directory of the external-file tables (ExternalFileAccess = Restrict, firebird.conf).
mkdir -p "$(dirname "$DB")/external"
if [ ! -r "$SEED" ]; then
  echo "[seed] no seed file: $DB not created"
  exit 0
fi
if [ -e "$DB" ]; then
  echo "[seed] $DB exists: not seeded again"
  exit 0
fi
echo "[seed] creating $DB"
/opt/firebird/bin/isql -q -b -ch UTF8 -user SYSDBA <<SQL
CREATE DATABASE '$DB' DEFAULT CHARACTER SET UTF8;
INPUT '$SEED';
EXIT;
SQL
echo "[seed] $DB seeded"
