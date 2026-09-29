-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p4c_events_grants` (P4-C). Every name is
-- schema-qualified.
--
-- Audit access events are what the agents reported: the runtime role inserts them (`POST /events`)
-- and the worker writes their evaluation (score, sensitivity, anomaly flag, baseline snapshot), but
-- the console process can neither rewrite what was reported nor delete it. `events_batches` and
-- `incident_events` are records: INSERT and SELECT only. Baselines and Audit settings are updated in
-- place but never deleted by the application.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.access_events FROM databastion_app;
--> statement-breakpoint
GRANT UPDATE (evaluated_at, sensitivity, score, anomaly, baseline_rows) ON TABLE public.access_events TO databastion_app;
--> statement-breakpoint
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.events_batches FROM databastion_app;
--> statement-breakpoint
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.incident_events FROM databastion_app;
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON TABLE public.principal_baselines FROM databastion_app;
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON TABLE public.audit_configs FROM databastion_app;
--> statement-breakpoint
-- Incidents raised from access events accumulate their matches (migration 0016 limits UPDATE to the
-- lifecycle and re-match columns; these are the re-match columns of the new source).
GRANT UPDATE (event_score, event_rows, event_signals, last_event_at) ON TABLE public.incidents TO databastion_app;
--> statement-breakpoint
-- Retention (P4-C). The only way for the runtime role to delete access events: this function,
-- owned by the migration (owner) role, deletes at most `max_rows` events whose `ts` is older than
-- the retention bound, and the events batches received before it. The bound is clamped to
-- [7, 3650] days, so a compromised console process can at worst purge events older than 7 days,
-- never recent ones. The links of a purged event go with it (`incident_events` cascade);
-- `incidents.access_event_id` is set to null. Returns the number of events deleted.
CREATE FUNCTION public.databastion_purge_access_events(retention_days integer, max_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  cutoff timestamptz := now() - make_interval(days => least(greatest(coalesce(retention_days, 90), 7), 3650));
  bound integer := least(greatest(coalesce(max_rows, 10000), 1), 100000);
  deleted integer;
BEGIN
  DELETE FROM public.access_events
  WHERE id IN (SELECT id FROM public.access_events WHERE ts < cutoff ORDER BY ts LIMIT bound);
  GET DIAGNOSTICS deleted = ROW_COUNT;
  DELETE FROM public.events_batches
  WHERE (agent_id, batch_id) IN (
    SELECT agent_id, batch_id FROM public.events_batches WHERE received_at < cutoff ORDER BY received_at LIMIT bound);
  RETURN deleted;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.databastion_purge_access_events(integer, integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.databastion_purge_access_events(integer, integer) TO databastion_app;
