-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p8a_oidc_grants` (P8-A, ADR-0038). Every name is
-- schema-qualified.
--
-- OIDC tables (src/server/oidc/): the default privileges of migration 0003 already give plain DML;
-- the grants are explicit so the tables do not depend on them, and nothing else is granted (no
-- TRUNCATE, REFERENCES or TRIGGER).
-- - user_identities: bound at sign-up, approval and self-service link (INSERT), display attributes
--   refreshed at login (UPDATE), removed with their user (DELETE).
-- - oidc_pending_logins: recorded and refreshed by refused logins, evicted at the cap, expired,
--   approved or discarded by an administrator.
-- - oidc_consumed_states: insert-once single-use records of OIDC states, pruned after expiry.
--   No UPDATE: a consumed state is never rewritten.
REVOKE ALL ON TABLE public.user_identities FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_identities TO databastion_app;
--> statement-breakpoint
REVOKE ALL ON TABLE public.oidc_pending_logins FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_pending_logins TO databastion_app;
--> statement-breakpoint
REVOKE ALL ON TABLE public.oidc_consumed_states FROM databastion_app;
--> statement-breakpoint
GRANT SELECT, INSERT, DELETE ON TABLE public.oidc_consumed_states TO databastion_app;
