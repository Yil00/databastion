-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name notification_deliveries_grants` (P3-C). Every
-- name is schema-qualified.
--
-- `notification_deliveries` is the outbox and the delivery record of every notification. The
-- runtime role inserts rows (policy engine, integrity events, silent-agent check) and updates their
-- delivery state (worker), but never deletes them nor rewrites what was sent to whom: DELETE and
-- TRUNCATE are revoked, UPDATE is limited to the delivery-state columns. Foreign-key
-- `ON DELETE SET NULL` actions (channel, incident, agent, security event) run as the table owner.
-- `notification_channels` keeps the plain DML of the default privileges (migration 0003):
-- administrators delete channels through the console, audited.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.notification_deliveries FROM databastion_app;
--> statement-breakpoint
GRANT UPDATE (
  status,
  attempts,
  next_attempt_at,
  lease_until,
  last_attempt_at,
  delivered_at,
  last_error
) ON TABLE public.notification_deliveries TO databastion_app;
