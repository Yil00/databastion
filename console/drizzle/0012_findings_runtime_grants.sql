-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name findings_runtime_grants` (P2-D security
-- review, L3). Every name is schema-qualified.
--
-- `findings_batches` is an idempotency record: the runtime role only needs to INSERT and SELECT it,
-- so a compromised console cannot rewrite or erase which batches were accepted (UPDATE, DELETE and
-- TRUNCATE revoked). `findings` rows are updated by later scans and by false-positive marking, but
-- never deleted by the application: DELETE and TRUNCATE are revoked. Deletions cascade from the
-- agent / target rows (foreign-key actions run as the table owner). A future retention job runs as
-- the owner or gets its own grant.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.findings_batches FROM databastion_app;
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON TABLE public.findings FROM databastion_app;
