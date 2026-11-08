#!/usr/bin/env bash
# First-start script of the e2e Firebird target (e2e/firebird.sh, docker-compose.firebird.yml),
# run by dev/firebird/entrypoint.sh after the seed, as the server's account (uid 84) over an
# embedded connection of the image's isql (no server, no network), before the server starts: its
# statements are emptied from the audit log with the seed's. The Audit test's accounts, never the
# agent's:
#   E2E_EXPORTER, E2E_ANALYST  SELECT on CUSTOMERS and PAYMENT_CARDS, and EXECUTE on the function
#                              of PAYMENT_CARDS' computed column (a `SELECT *` calls it), through
#                              the role E2E_READER, granted DEFAULT (the full read and the literal
#                              queries);
#   E2E_ADMIN                  the admin role of the security database (`GRANT ADMIN ROLE`): user
#                              management when it connects with the role RDB$ADMIN (the
#                              password-bearing DCL); no grant in crm, so no table. A system
#                              privilege USER_MANAGEMENT granted in crm does not reach the security
#                              database's PLG$SRP_VIEW (measured on 5.0.4).
# The password comes from the Docker secret file and reaches isql on its standard input, never on
# a command line.
set -euo pipefail

DB="${FIREBIRD_SEED_DATABASE:-/var/lib/firebird/data/crm.fdb}"
PW="$(cat /run/secrets/target_client_password)"
case "$PW" in
  '' | *[!A-Za-z0-9]*) echo "[e2e-clients] the client password must be alphanumeric" >&2; exit 1 ;;
esac
/opt/firebird/bin/isql -q -b -user SYSDBA "$DB" <<SQL
CREATE OR ALTER USER E2E_EXPORTER PASSWORD '$PW' USING PLUGIN Srp;
CREATE OR ALTER USER E2E_ANALYST PASSWORD '$PW' USING PLUGIN Srp;
CREATE OR ALTER USER E2E_ADMIN PASSWORD '$PW' GRANT ADMIN ROLE USING PLUGIN Srp;
COMMIT;
CREATE ROLE E2E_READER;
GRANT SELECT ON TABLE CUSTOMERS TO ROLE E2E_READER;
GRANT SELECT ON TABLE PAYMENT_CARDS TO ROLE E2E_READER;
GRANT EXECUTE ON FUNCTION FN_IBAN_PREFIX TO ROLE E2E_READER;
GRANT DEFAULT E2E_READER TO USER E2E_EXPORTER;
GRANT DEFAULT E2E_READER TO USER E2E_ANALYST;
COMMIT;
EXIT;
SQL
unset PW
echo "[e2e-clients] E2E_EXPORTER, E2E_ANALYST, E2E_ADMIN ready"
