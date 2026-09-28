#!/bin/sh
# Runs once, at the first initialization of the e2e target database (postgres image,
# /docker-entrypoint-initdb.d), as POSTGRES_USER. The superuser password stays in target-pg:
# the agent gets its own least-privilege, read-only account (invariant I4, docs/05-security.md).
#
# databastion_agent: LOGIN, no superuser / createdb / createrole / replication / bypassrls;
# CONNECT on the database, pg_read_all_data (SELECT everywhere, for Discovery sampling),
# pg_monitor (pg_stat_* views, for check() and Audit); every transaction is read-only by default.
#
# The password is read by psql itself (`\set` with a backquoted `cat`) from the Docker secret
# file and passed as a quoted literal (:'var'): it never appears on a command line, in the
# environment, nor interpolated by the shell (quoted heredoc).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\set agent_password `cat /run/secrets/target_agent_password`
CREATE ROLE databastion_agent LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'agent_password';
\unset agent_password
GRANT CONNECT ON DATABASE :"DBNAME" TO databastion_agent;
GRANT pg_read_all_data TO databastion_agent;
GRANT pg_monitor TO databastion_agent;
ALTER ROLE databastion_agent SET default_transaction_read_only = on;
SQL
