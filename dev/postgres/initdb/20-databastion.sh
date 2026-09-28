#!/usr/bin/env bash
# Runs once, after the seed (10-seed.sql), on an empty data directory.
# - databastion: the agent's read-only account, minimal grant variant of ADR-0012
#   (docs/adr/0012-postgresql-agent-grants.md), so that connector integration tests run with the
#   production grants:
#   - LOGIN, no superuser / createdb / createrole / replication / bypassrls, CONNECTION LIMIT 4;
#   - role defaults (a safety net only, the client can override them): read-only transactions,
#     statement / lock / idle-in-transaction timeouts;
#   - Discovery: USAGE + SELECT on the seeded application schemas (crm, billing, ops) and default
#     privileges FOR ROLE their owner (POSTGRES_USER, which ran 10-seed.sql), so tables it
#     creates later are readable too. A new schema, or tables created by another role, need
#     their own grants (the connector's check() lists them as not covered);
#   - Audit: pg_read_all_stats (other users' statements in pg_stat_statements / pg_stat_activity).
#   Never pg_read_all_data nor pg_monitor: they expose credential-bearing catalogs (pg_authid,
#   pg_user_mapping, pg_subscription), large objects and raw statistics.
# - pgaudit: session audit (read, write) on the application database only, plus object audit of the
#   seeded tables through the databastion_auditor role (docs/08-engine-capabilities.md: restrict
#   pgaudit to sensitive objects rather than auditing the whole server).
# - The server's log_file_mode=0644 (docker-compose.yml) is a dev-only convenience; production
#   uses 0640 plus an ACL for the agent's OS user (ADR-0012, "Audit log files").
#
# The password is read by psql itself from the environment (`\set` with a backquoted printenv):
# it is not on psql's command line. pg_stat_statements does not record this session's utility
# statements, so CREATE ROLE ... PASSWORD is not readable through pg_read_all_stats.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v dbname="$POSTGRES_DB" -v owner="$POSTGRES_USER" <<'EOSQL'
-- Test-only deviation from ADR-0012 (psql's password meta-command is interactive): the role password is set with a
-- PASSWORD literal. It is not recorded: track_utility is off for this session, pgaudit and
-- log_statement do not log ROLE statements here, and a failing statement is not logged either.
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
-- pgaudit is always available in the dev image; the host cluster of
-- dev/postgres/local-cluster.sh (no Docker) may not have it.
SELECT count(*) > 0 AS has_pgaudit FROM pg_available_extensions WHERE name = 'pgaudit' \gset
\if :has_pgaudit
CREATE EXTENSION IF NOT EXISTS pgaudit;
\endif
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

\set ro_password `printenv DATABASTION_DB_PASSWORD`
CREATE ROLE databastion LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD :'ro_password';
\unset ro_password
ALTER ROLE databastion SET default_transaction_read_only = on;
ALTER ROLE databastion SET statement_timeout = '30s';
ALTER ROLE databastion SET lock_timeout = '2s';
ALTER ROLE databastion SET idle_in_transaction_session_timeout = '60s';

GRANT CONNECT ON DATABASE :"dbname" TO databastion;

-- Discovery (sampling): per application schema, and per role that creates tables in it.
GRANT USAGE ON SCHEMA crm, billing, ops TO databastion;
GRANT SELECT ON ALL TABLES IN SCHEMA crm, billing, ops TO databastion;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA crm, billing, ops
  GRANT SELECT ON TABLES TO databastion;

-- Audit (Full and Limited): pg_stat_statements / pg_stat_activity of other users.
GRANT pg_read_all_stats TO databastion;

CREATE ROLE databastion_auditor NOLOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA crm, billing, ops TO databastion_auditor;

\if :has_pgaudit
ALTER DATABASE :"dbname" SET pgaudit.log = 'read, write';
\endif
EOSQL
