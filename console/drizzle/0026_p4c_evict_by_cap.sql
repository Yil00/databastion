-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p4c_evict_by_cap` (P4-C re-review N4). Every
-- name is schema-qualified.
--
-- The eviction function of migration 0024 took a number of rows to delete, so a compromised
-- console process could empty the baselines of a target. It is replaced by one that takes the cap
-- (clamped to at least 10) and deletes only the rows beyond it, least recently updated first, at
-- most 1000 per call.
DROP FUNCTION public.databastion_evict_principal_baselines(uuid, text, integer);
--> statement-breakpoint
CREATE FUNCTION public.databastion_evict_principal_baselines(p_agent_id uuid, p_target_id text, p_cap integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  cap integer := greatest(coalesce(p_cap, 10), 10);
  excess integer;
  deleted integer;
BEGIN
  SELECT count(*) - cap INTO excess FROM public.principal_baselines
  WHERE agent_id = p_agent_id AND target_id = p_target_id;
  IF excess <= 0 THEN
    RETURN 0;
  END IF;
  DELETE FROM public.principal_baselines
  WHERE (agent_id, target_id, principal_key) IN (
    SELECT agent_id, target_id, principal_key FROM public.principal_baselines
    WHERE agent_id = p_agent_id AND target_id = p_target_id
    ORDER BY updated_at, principal_key
    LIMIT least(excess, 1000));
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.databastion_evict_principal_baselines(uuid, text, integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.databastion_evict_principal_baselines(uuid, text, integer) TO databastion_app;
