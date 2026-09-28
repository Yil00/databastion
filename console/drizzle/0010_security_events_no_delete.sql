-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name security_events_no_delete` (phase 1 security
-- review, L2). Every name is schema-qualified.
--
-- `security_events` got plain DML through the default privileges of migration 0003. The runtime
-- role only needs to INSERT them and, for the phase 3 acknowledgement, to set the acknowledgement
-- columns: DELETE (and UPDATE of any other column) is revoked, so a compromised console cannot erase
-- or rewrite an integrity alert. The owner role keeps full rights (foreign-key `ON DELETE SET NULL`
-- actions run as the table owner).
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.security_events FROM databastion_app;
--> statement-breakpoint
GRANT UPDATE (acknowledged_at, acknowledged_by) ON TABLE public.security_events TO databastion_app;
