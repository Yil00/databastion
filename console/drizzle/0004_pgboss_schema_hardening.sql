-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name pgboss_schema_hardening`
-- (security re-review N2, CVE-2018-1058 pattern). Every name is schema-qualified.
--
-- 1. The runtime group role must not create schemas: a schema named after the owner role would
--    come first in the owner's default search path and could shadow functions or tables used by
--    later migrations. Migration 0003 granted CREATE on the database for pg-boss: revoked here.
DO $$
BEGIN
  EXECUTE pg_catalog.format('REVOKE CREATE ON DATABASE %I FROM databastion_app', pg_catalog.current_database());
END
$$;
--> statement-breakpoint
-- 2. Nobody but the owner creates objects in `public` (PostgreSQL >= 15 default, made explicit).
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
--> statement-breakpoint
-- 3. pg-boss (worker) gets its own schema, owned by the owner; the runtime role installs and
--    manages its tables there (pg-boss `schema: 'pgboss'`, `createSchema: false`). This schema is
--    never on the owner's search path.
CREATE SCHEMA IF NOT EXISTS pgboss;
--> statement-breakpoint
GRANT USAGE, CREATE ON SCHEMA pgboss TO databastion_app;
--> statement-breakpoint
-- 4. The trigger function never resolves names through the caller's search path.
ALTER FUNCTION public.audit_log_append_only() SET search_path = pg_catalog;
