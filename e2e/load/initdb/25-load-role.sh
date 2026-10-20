#!/bin/sh
# Runs once, at the first initialization of target-pg (postgres image, /docker-entrypoint-initdb.d),
# as POSTGRES_USER on `shop`, after the e2e agent role and Discovery grants and before the e2e Audit
# setup (30-audit.sh): the workload role of the load harness (e2e/load/run.sh).
#
# load_app: LOGIN, no other attribute; pgbench connects with it (never with the agent's account).
# Its SELECT grants on the scaled tables are given by run.sh once it has created them.
# load_pgmon (ADR-0048 load scenario, pg-side-clients.sh): a monitoring-like account, LOGIN and a
# member of pg_monitor, running a bloat estimate on pg_stats; same password.
# load_pgexp (ADR-0050 load scenario): an exporter-like account, LOGIN with no grant, reading
# pg_roles, pg_proc and pg_subscription without their secret columns; same password.
# load_pgbouncer (ADR-0050 load scenario): a PgBouncer-like account, LOGIN and a member of
# pg_read_all_data (to read pg_shadow), running PgBouncer's default auth_query; same password.
# load_orm (ADR-0053 decision 6, pg-side-clients.sh): an ORM-style application account, LOGIN with
# no other attribute; its SELECT grants on the scaled tables are given with load_app's; same password.
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
CREATE ROLE load_pgmon LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'load_password';
CREATE ROLE load_pgexp LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'load_password';
CREATE ROLE load_pgbouncer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'load_password';
CREATE ROLE load_orm LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'load_password';
\unset load_password
GRANT CONNECT ON DATABASE :"DBNAME" TO load_app, load_pgmon, load_pgexp, load_pgbouncer, load_orm;
GRANT pg_monitor TO load_pgmon;
GRANT pg_read_all_data TO load_pgbouncer;
SQL
