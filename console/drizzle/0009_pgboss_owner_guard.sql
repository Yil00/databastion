-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name pgboss_owner_guard` (ROADMAP P1-D). Every name
-- is schema-qualified.
--
-- Refuses to migrate when the `pgboss` schema exists and is owned by a role other than the
-- migration role (the owner). A schema owned by another role (e.g. created by the runtime role in
-- an older or tampered deployment) lets that role plant objects the owner could later run with its
-- own rights (see console/README.md, "Database roles"). Migration 0004 is not edited (it has
-- shipped): this separate migration replaces the former "guard in 0004" follow-up. The migrations
-- run in one transaction, so nothing from this run is applied when it raises.
DO $$
DECLARE
  schema_owner pg_catalog.name;
BEGIN
  SELECT pg_catalog.pg_get_userbyid(n.nspowner) INTO schema_owner
    FROM pg_catalog.pg_namespace n
    WHERE n.nspname = 'pgboss';
  IF schema_owner IS NOT NULL AND schema_owner OPERATOR(pg_catalog.<>) CURRENT_USER THEN
    RAISE EXCEPTION 'schema pgboss is owned by role %, not by the migration role %', schema_owner, CURRENT_USER
      USING HINT = 'As a superuser: ALTER SCHEMA pgboss OWNER TO the migration (owner) role, after checking the schema for planted objects; see console/README.md, "Database roles".';
  END IF;
END
$$;
