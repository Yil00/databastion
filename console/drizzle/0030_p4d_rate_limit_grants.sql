-- Custom SQL migration file, put your code below! ---- Created with `drizzle-kit generate --custom --name p4d_rate_limit_grants` (P4-D). Every name is
-- schema-qualified.
--
-- Shared rate-limit counters (src/server/rate-limit.ts): the runtime role counts (INSERT ... ON
-- CONFLICT DO UPDATE), refunds (UPDATE), reads (SELECT) and prunes expired windows (DELETE, worker).
-- The default privileges of migration 0003 already give exactly this DML; it is granted explicitly
-- so the table does not depend on them, and nothing else (no TRUNCATE, REFERENCES or TRIGGER).
REVOKE ALL ON TABLE public.rate_limit_counters FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.rate_limit_counters TO databastion_app;
