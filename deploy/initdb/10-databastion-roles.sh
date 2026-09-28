#!/bin/sh
# Runs once, at the first initialization of the console database (postgres image,
# /docker-entrypoint-initdb.d), as POSTGRES_USER (the OWNER role used by migrations).
# Creates the runtime roles used by the web and worker processes: non-superuser,
# not owner of any table, member of the group role `databastion_app` whose privileges are
# granted by the console migrations (INSERT + SELECT only on the append-only audit_log).
set -eu
APP_PASSWORD="$(cat /run/secrets/db_app_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_password="$APP_PASSWORD" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'databastion_app') THEN
    CREATE ROLE databastion_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;
CREATE ROLE databastion_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  IN ROLE databastion_app PASSWORD :'app_password';
SQL
