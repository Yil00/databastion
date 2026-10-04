#!/bin/sh
# One-shots of the opt-in CAS dev service, run with the PostgreSQL client image against the dev
# `postgres` service as its administrator (PGPASSWORD). Idempotent.
#   init    (service `cas-db-init`, before each CAS start) role `cas` (password
#           DEV_CAS_DB_PASSWORD) and database `cas` it owns, for the JPA ticket registry; CONNECT
#           and USAGE for the agent's account `databastion`, nothing else (no PUBLIC access).
#           Tickets left by an earlier start are deleted: CAS generates new ticket keys at each
#           start, so they can no longer be read (its cleaner would log decryption errors).
#   grants  (service `cas-db-grants`, once CAS is healthy) waits until CAS has created
#           `cas_tickets` (lazily, at the first ticket registry access: its ticket cleaner's first
#           run, about 30 s after start, or the first login), at most 180 s, then sets the
#           agent's grants of ADR-0041 decision 6 on the ticket table: SELECT on the columns
#           `type`, `creation_time` and `expiration_time` only, never the table, never `id`,
#           `body`, `parent_id`, `principal_id`, `service` nor `attributes`.
# The `cas` database is not audited by pgaudit (`pgaudit.log` is set on `shop` only).
set -eu
export PGHOST=postgres PGUSER=postgres PGCONNECT_TIMEOUT=10 PGAPPNAME=databastion-dev-cas-init
psql() { command psql -X -q -v ON_ERROR_STOP=1 "$@"; }

case "${1:-}" in
init)
  [ -n "${DEV_CAS_DB_PASSWORD:-}" ] || { echo "db-init: DEV_CAS_DB_PASSWORD is empty" >&2; exit 1; }
  # The password goes through a psql variable read from the environment, never a command line.
  psql -d postgres <<'SQL'
-- The password is not recorded: no utility statement in pg_stat_statements for this session, and
-- a failing statement is not logged (as dev/postgres/initdb/20-databastion.sh).
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
\getenv cas_password DEV_CAS_DB_PASSWORD
SELECT 'CREATE ROLE cas LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cas') \gexec
ALTER ROLE cas WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 20 PASSWORD :'cas_password';
SELECT 'CREATE DATABASE cas OWNER cas' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cas') \gexec
REVOKE ALL ON DATABASE cas FROM PUBLIC;
GRANT CONNECT ON DATABASE cas TO databastion;
SQL
  psql -d cas <<'SQL'
ALTER SCHEMA public OWNER TO cas;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO databastion;
SELECT 'TRUNCATE public.cas_tickets' WHERE to_regclass('public.cas_tickets') IS NOT NULL \gexec
SQL
  echo "db-init: role and database cas ready"
  ;;
grants)
  i=0
  until [ "$(psql -d cas -Atc "SELECT to_regclass('public.cas_tickets') IS NOT NULL")" = t ]; do
    i=$((i + 1))
    [ "$i" -le 90 ] || break
    sleep 2
  done
  psql -d cas <<'SQL'
SELECT to_regclass('public.cas_tickets') IS NOT NULL AS has_tickets \gset
\if :has_tickets
REVOKE ALL ON public.cas_tickets FROM PUBLIC, databastion;
GRANT SELECT (type, creation_time, expiration_time) ON public.cas_tickets TO databastion;
\else
DO $$ BEGIN RAISE EXCEPTION 'db-init: no table cas_tickets after 180 s (has CAS started?)'; END $$;
\endif
SQL
  echo "db-init: agent column grants on cas_tickets set (type, creation_time, expiration_time)"
  ;;
*)
  echo "usage: db-init.sh init|grants" >&2
  exit 2
  ;;
esac
