-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name runtime_role_grants` (security re-review R1).
--
-- Role split: migrations run as the OWNER role (DATABASE_MIGRATION_URL), which owns every table
-- and the audit_log triggers. The web and worker processes connect with a LOGIN role that is a
-- member of the NOLOGIN group role `databastion_app` created here: not superuser, not owner, so it
-- cannot drop or disable the append-only triggers, and it gets only INSERT + SELECT on audit_log.
-- The LOGIN role itself (with its password) is created outside migrations: see console/README.md
-- ("Database roles") and deploy/initdb/.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'databastion_app') THEN
    BEGIN
      CREATE ROLE databastion_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
      NULL; -- created concurrently
    END;
  END IF;
END
$$;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON
  meta, users, sessions, agents, agent_targets, enrollment_tokens, jobs
  TO databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT ON audit_log TO databastion_app;
--> statement-breakpoint
-- Tables created by later migrations (run by the owner role) get plain DML by default.
-- A future append-only table must REVOKE UPDATE, DELETE explicitly, like audit_log above.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO databastion_app;
--> statement-breakpoint
-- pg-boss (worker) creates and manages its own schema at startup.
DO $$
BEGIN
  EXECUTE format('GRANT CREATE ON DATABASE %I TO databastion_app', current_database());
END
$$;
