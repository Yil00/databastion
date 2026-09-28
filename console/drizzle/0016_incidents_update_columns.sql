-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name incidents_update_columns` (P3 security review,
-- L2). Every name is schema-qualified.
--
-- Migration 0015 left the runtime role a table-wide UPDATE on `incidents`. It only needs the
-- columns the application writes: the lifecycle (status and who / when of each transition) and the
-- re-match counters of the policy engine. The policy snapshot, severity, dedup key, finding / agent
-- / target / classifier and creation time can no longer be rewritten by a compromised console.
-- Foreign-key `ON DELETE SET NULL` actions still work (they run as the table owner).
REVOKE UPDATE ON TABLE public.incidents FROM databastion_app;
--> statement-breakpoint
GRANT UPDATE (
  status,
  updated_at,
  acknowledged_at,
  acknowledged_by,
  resolved_at,
  resolved_by,
  false_positive_at,
  false_positive_by,
  match_count,
  last_finding_seen_at,
  finding_matched,
  finding_classifiers_version
) ON TABLE public.incidents TO databastion_app;
