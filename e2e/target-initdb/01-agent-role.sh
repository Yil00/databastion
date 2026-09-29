#!/bin/sh
# Runs once, at the first initialization of the e2e target database (postgres image,
# /docker-entrypoint-initdb.d), as POSTGRES_USER. The superuser password stays in target-pg:
# the agent gets its own least-privilege, read-only account (invariant I4), with the minimal
# grant variant of ADR-0012 (docs/adr/0012-postgresql-agent-grants.md).
#
# databastion_agent: LOGIN, no superuser / createdb / createrole / replication / bypassrls,
# CONNECTION LIMIT 4; CONNECT on the database and pg_read_all_stats (Audit: other users'
# statements in pg_stat_statements / pg_stat_activity). Role defaults, a safety net only (the
# client can override them; the connector sets its own values in each transaction): read-only
# transactions, statement / lock / idle-in-transaction timeouts. Never pg_read_all_data nor
# pg_monitor: they expose credential-bearing catalogs and raw statistics (ADR-0012).
#
# Discovery grants are per application schema (USAGE, SELECT ON ALL TABLES, default privileges
# FOR ROLE the owner): 20-discovery-grants.sql adds them once the dev seed (10-seed.sql) has
# created the schemas.
#
# The password is read by psql itself (`\set` with a backquoted `cat`) from the Docker secret
# file and passed as a quoted literal (:'var'): it never appears on a command line, in the
# environment, nor interpolated by the shell (quoted heredoc).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
-- Test-only deviation from ADR-0012 (psql's password meta-command is interactive): the role
-- password is set with a PASSWORD literal. It is not recorded: pg_stat_statements (preloaded for
-- the Audit path, docker-compose.yml) does not track this session's utility statements, pgaudit
-- is not enabled for the database yet (target-initdb/30-audit.sh), log_statement does not log
-- ROLE statements, and a failing statement is not logged either.
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
\set agent_password `cat /run/secrets/target_agent_password`
CREATE ROLE databastion_agent LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 4 PASSWORD :'agent_password';
\unset agent_password
ALTER ROLE databastion_agent SET default_transaction_read_only = on;
ALTER ROLE databastion_agent SET statement_timeout = '30s';
ALTER ROLE databastion_agent SET lock_timeout = '2s';
ALTER ROLE databastion_agent SET idle_in_transaction_session_timeout = '60s';
GRANT CONNECT ON DATABASE :"DBNAME" TO databastion_agent;
GRANT pg_read_all_stats TO databastion_agent;
SQL
