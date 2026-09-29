#!/bin/sh
# Runs once, after the dev seed (10-seed.sql) and the Discovery grants (20-discovery-grants.sql), as
# POSTGRES_USER on the `shop` database: the Audit side of the e2e target (P4-D).
#
# - Extensions: pgaudit when the image has it (dev/postgres; not the plain image of the local
#   E2E_PG_AUDIT=pss mode) and pg_stat_statements (preloaded by docker-compose.yml in both modes).
# - pgaudit, as dev/postgres/initdb/20-databastion.sh and dev/docker-compose.yml configure it, but
#   per database (ALTER DATABASE), so a server without pgaudit carries no pgaudit placeholder
#   setting: session audit of `read, write` on `shop`, object audit of the seeded tables through
#   databastion_auditor, one record per relation, rows per statement (volume, Full level), no
#   catalog statements, no bound parameters.
# - Two test client roles, used from the separate pg-client container (never the agent's account):
#   e2e_exporter runs pg_dump, e2e_analyst runs queries whose text holds ground-truth literals.
#   Read-only on the seeded schemas (USAGE, SELECT on tables and sequences). Their password is read
#   by psql itself from the Docker secret (`\set` with a backquoted `cat`), never on a command line.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
-- Test-only deviation from ADR-0012 (psql's password meta-command is interactive): the role
-- passwords are set with a PASSWORD literal. Not recorded: pgaudit.log is not set for this
-- database yet and never logs ROLE statements here, log_statement does not log them,
-- pg_stat_statements does not track this session's utility statements, and a failing statement
-- is not logged either.
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
SELECT count(*) > 0 AS has_pgaudit FROM pg_available_extensions WHERE name = 'pgaudit' \gset
\if :has_pgaudit
CREATE EXTENSION IF NOT EXISTS pgaudit;
\endif
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

\set client_password `cat /run/secrets/target_client_password`
CREATE ROLE e2e_exporter LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'client_password';
CREATE ROLE e2e_analyst LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'client_password';
\unset client_password
GRANT CONNECT ON DATABASE :"DBNAME" TO e2e_exporter, e2e_analyst;
GRANT USAGE ON SCHEMA crm, billing, ops TO e2e_exporter, e2e_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA crm, billing, ops TO e2e_exporter, e2e_analyst;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA crm, billing, ops TO e2e_exporter, e2e_analyst;

CREATE ROLE databastion_auditor NOLOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA crm, billing, ops TO databastion_auditor;

\if :has_pgaudit
ALTER DATABASE :"DBNAME" SET pgaudit.log = 'read, write';
ALTER DATABASE :"DBNAME" SET pgaudit.role = 'databastion_auditor';
ALTER DATABASE :"DBNAME" SET pgaudit.log_relation = on;
ALTER DATABASE :"DBNAME" SET pgaudit.log_catalog = off;
ALTER DATABASE :"DBNAME" SET pgaudit.log_parameter = off;
ALTER DATABASE :"DBNAME" SET pgaudit.log_rows = on;
\endif
SQL
