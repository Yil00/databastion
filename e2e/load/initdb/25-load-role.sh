#!/bin/sh
# Runs once, at the first initialization of target-pg (postgres image, /docker-entrypoint-initdb.d),
# as POSTGRES_USER on `shop`, after the e2e agent role and Discovery grants and before the e2e Audit
# setup (30-audit.sh): the workload role of the load harness (e2e/load/run.sh).
#
# load_app: LOGIN, no other attribute; pgbench connects with it (never with the agent's account).
# Its SELECT grants on the scaled tables are given by run.sh once it has created them.
# The password is read by psql itself from the Docker secret and passed as a quoted literal
# (as e2e/target-initdb/01-agent-role.sh): never on a command line nor in the environment, and
# not recorded (pgaudit is not set for the database yet, pg_stat_statements does not track this
# session's utility statements, a failing statement is not logged).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
\set load_password `cat /run/secrets/load_client_password`
CREATE ROLE load_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'load_password';
\unset load_password
GRANT CONNECT ON DATABASE :"DBNAME" TO load_app;
SQL
