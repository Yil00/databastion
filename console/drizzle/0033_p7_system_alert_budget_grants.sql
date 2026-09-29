-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p7_system_alert_budget_grants` (P7, #75 review
-- L4). Every name is schema-qualified.
--
-- Global hourly budget of system alerts per channel (src/server/notifications.ts): the runtime role
-- counts (INSERT ... ON CONFLICT DO UPDATE), reads (SELECT) and prunes past hours (DELETE, worker).
-- The default privileges of migration 0003 already give exactly this DML; it is granted explicitly
-- so the table does not depend on them, and nothing else (no TRUNCATE, REFERENCES or TRIGGER).
REVOKE ALL ON TABLE public.system_alert_budgets FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.system_alert_budgets TO databastion_app;
