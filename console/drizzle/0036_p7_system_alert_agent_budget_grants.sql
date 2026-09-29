-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p7_system_alert_agent_budget_grants` (P7, PR
-- #81 security review M1). Every name is schema-qualified.
--
-- Per-agent share of the hourly budget of system alerts (src/server/notifications.ts): the runtime
-- role counts (INSERT ... ON CONFLICT DO UPDATE), gives back a charge the channel budget refused
-- (UPDATE), reads (SELECT) and prunes past hours (DELETE, worker). Nothing else.
REVOKE ALL ON TABLE public.system_alert_agent_budgets FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.system_alert_agent_budgets TO databastion_app;
