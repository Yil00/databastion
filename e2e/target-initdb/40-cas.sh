#!/bin/sh
# Runs once, at the first initialization of cas-db (docker-compose.cas.yml, e2e/cas.sh), as
# POSTGRES_USER, after 01-agent-role.sh (the agent's role databastion_agent, CONNECT on `cas`).
# As dev/cas/db-init.sh `init`: the role `cas` (the JPA ticket registry's account, password from the
# cas_db_password secret) owns the database `cas` and its `public` schema; no PUBLIC access; the
# agent gets USAGE on the schema and nothing else. Its column grants on `cas_tickets` (ADR-0041
# decision 6) are set by cas.sh once CAS has created the table (`ddl-auto=update`).
#
# The password is read by psql itself from the Docker secret file and passed as a quoted literal: it
# never appears on a command line, in the environment, nor interpolated by the shell.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
SET pg_stat_statements.track_utility = off;
SET log_min_error_statement = panic;
\set cas_password `cat /run/secrets/cas_db_password`
CREATE ROLE cas LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 20 PASSWORD :'cas_password';
\unset cas_password
ALTER DATABASE cas OWNER TO cas;
REVOKE ALL ON DATABASE cas FROM PUBLIC;
GRANT CONNECT ON DATABASE cas TO databastion_agent;
ALTER SCHEMA public OWNER TO cas;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO databastion_agent;
SQL
