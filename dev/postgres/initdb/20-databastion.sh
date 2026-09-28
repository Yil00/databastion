#!/usr/bin/env bash
# Runs once, after the seed (10-seed.sql), on an empty data directory.
# - databastion: read-only account recommended in docs/05-security.md
# - pgaudit: session audit (read, write) on the application database only, plus object audit of the
#   seeded tables through the databastion_auditor role (docs/08-engine-capabilities.md: restrict
#   pgaudit to sensitive objects rather than auditing the whole server).
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ro_password="$DATABASTION_DB_PASSWORD" -v dbname="$POSTGRES_DB" <<'EOSQL'
CREATE EXTENSION IF NOT EXISTS pgaudit;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE ROLE databastion LOGIN PASSWORD :'ro_password';
GRANT pg_read_all_data TO databastion;   -- Discovery (sampling)
GRANT pg_monitor       TO databastion;   -- statistics, pg_stat_statements
ALTER ROLE databastion SET default_transaction_read_only = on;

CREATE ROLE databastion_auditor NOLOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA crm, billing, ops TO databastion_auditor;

ALTER DATABASE :"dbname" SET pgaudit.log = 'read, write';
EOSQL
