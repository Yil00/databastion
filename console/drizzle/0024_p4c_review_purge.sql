-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p4c_review_purge` (P4-C security review H1,
-- L1, L2). Every name is schema-qualified.
--
-- The retention function of migration 0022 is replaced:
-- - events not evaluated yet (`evaluated_at` null) are never purged: a backlog is scored first;
-- - the events batches (idempotency records) are kept 30 days longer than the events, so a batch
--   replayed from a spool just past the retention is still recognized as a duplicate;
-- - principal baselines not updated for longer than the retention period are deleted (a baseline
--   is updated each time one of its events is evaluated).
-- The retention bound stays clamped to [7, 3650] days.
CREATE OR REPLACE FUNCTION public.databastion_purge_access_events(retention_days integer, max_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  days integer := least(greatest(coalesce(retention_days, 90), 7), 3650);
  cutoff timestamptz := now() - make_interval(days => days);
  bound integer := least(greatest(coalesce(max_rows, 10000), 1), 100000);
  deleted integer;
BEGIN
  DELETE FROM public.access_events
  WHERE id IN (
    SELECT id FROM public.access_events
    WHERE ts < cutoff AND evaluated_at IS NOT NULL
    ORDER BY ts LIMIT bound);
  GET DIAGNOSTICS deleted = ROW_COUNT;
  DELETE FROM public.events_batches
  WHERE (agent_id, batch_id) IN (
    SELECT agent_id, batch_id FROM public.events_batches
    WHERE received_at < cutoff - interval '30 days'
    ORDER BY received_at LIMIT bound);
  DELETE FROM public.principal_baselines
  WHERE (agent_id, target_id, principal_key) IN (
    SELECT agent_id, target_id, principal_key FROM public.principal_baselines
    WHERE updated_at < cutoff
    ORDER BY updated_at LIMIT bound);
  RETURN deleted;
END
$$;
--> statement-breakpoint
-- Cap of baselines per target (H1): the worker evicts the least recently updated baselines of a
-- target before creating new ones past the cap. At most 1000 rows per call. The runtime role can
-- already rewrite baselines (they are aggregates it maintains), so this grants nothing more
-- sensitive than a bounded delete of the oldest ones.
CREATE FUNCTION public.databastion_evict_principal_baselines(p_agent_id uuid, p_target_id text, n integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  deleted integer;
BEGIN
  DELETE FROM public.principal_baselines
  WHERE (agent_id, target_id, principal_key) IN (
    SELECT agent_id, target_id, principal_key FROM public.principal_baselines
    WHERE agent_id = p_agent_id AND target_id = p_target_id
    ORDER BY updated_at, principal_key
    LIMIT least(greatest(coalesce(n, 0), 0), 1000));
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.databastion_evict_principal_baselines(uuid, text, integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.databastion_evict_principal_baselines(uuid, text, integer) TO databastion_app;
--> statement-breakpoint
GRANT UPDATE (event_anomaly) ON TABLE public.incidents TO databastion_app;
