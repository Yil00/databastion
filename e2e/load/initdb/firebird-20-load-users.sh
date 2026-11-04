#!/usr/bin/env bash
# First-start script of the Firebird load target (e2e/load/firebird.sh, docker-compose.firebird.yml
# here), run by dev/firebird/entrypoint.sh after the seed, as the server's account (uid 84) over an
# embedded connection of the image's isql (no server, no network), before the server starts: its
# statements are emptied from the audit log with the seed's. The load run's accounts, never the
# agent's; their grants come through the seed's roles (GRANT DEFAULT, e2e/load/seed.py):
#   LOAD_APP, LOAD_BURST, LOAD_ROW, LOAD_TX   the Audit workload, the attach bursts (8g), the
#                                              per-row statements and the open transactions (3m)
#   LOAD_PLAIN ... LOAD_PROC                   the categories of the 10 000-object schema run
# The password comes from the Docker secret file and reaches isql on its standard input, never on
# a command line.
set -euo pipefail

DB="${FIREBIRD_SEED_DATABASE:-/var/lib/firebird/data/crm.fdb}"
PW="$(cat /run/secrets/target_client_password)"
case "$PW" in
  '' | *[!A-Za-z0-9]*) echo "[load-users] the client password must be alphanumeric" >&2; exit 1 ;;
esac
{
  for u in LOAD_APP LOAD_BURST LOAD_ROW LOAD_TX LOAD_PLAIN LOAD_EXPR LOAD_CHECK LOAD_COMP LOAD_VIEW LOAD_PROC; do
    printf "CREATE OR ALTER USER %s PASSWORD '%s' USING PLUGIN Srp;\n" "$u" "$PW"
  done
  printf 'COMMIT;\nEXIT;\n'
} | /opt/firebird/bin/isql -q -b -user SYSDBA "$DB"
unset PW
echo "[load-users] load accounts ready"
