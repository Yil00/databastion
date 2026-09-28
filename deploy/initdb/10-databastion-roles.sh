#!/bin/sh
# Runs once, at the first initialization of the console database (postgres image,
# /docker-entrypoint-initdb.d), as POSTGRES_USER: the bootstrap superuser, used ONLY here.
#
# Creates (security re-reviews R1 / N2):
# - databastion_owner: LOGIN, NOSUPERUSER, NOCREATEROLE. Owns the database and the public schema;
#   `migrate` connects as this role. Its search_path is pinned to `public`.
# - databastion_app: NOLOGIN group role. Its privileges are granted by the console migrations
#   (DML on the console tables, only SELECT + INSERT on audit_log, USAGE + CREATE on schema pgboss,
#   no CREATE on the database, no CREATE on public).
# - databastion_runtime: LOGIN, member of databastion_app; used by the web and worker processes.
#
# Passwords are read by psql itself (`\set` with a backquoted `cat`) from the Docker secret
# files: they never appear on a command line nor in the environment.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\set owner_password `cat /run/secrets/db_owner_password`
\set app_password `cat /run/secrets/db_app_password`
CREATE ROLE databastion_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  PASSWORD :'owner_password';
ALTER ROLE databastion_owner SET search_path = public;
CREATE ROLE databastion_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE databastion_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  IN ROLE databastion_app PASSWORD :'app_password';
SELECT pg_catalog.format('ALTER DATABASE %I OWNER TO databastion_owner', pg_catalog.current_database()) \gexec
ALTER SCHEMA public OWNER TO databastion_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO databastion_app;
SQL
