-- Custom SQL migration file, put your code below! --
-- Created with `drizzle-kit generate --custom --name p8a_oidc_state_prune` (P8-A security review,
-- info item). Every name is schema-qualified.
--
-- Consumed OIDC states become insert-only for the runtime role: a compromised console process can
-- no longer delete the record of a state still within its 10-minute lifetime (and so replay it).
-- Expired records are pruned through this function only, which deletes nothing unexpired.
CREATE FUNCTION public.databastion_prune_oidc_consumed_states(max_rows integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  bound integer := least(greatest(coalesce(max_rows, 1000), 1), 10000);
  deleted integer;
BEGIN
  DELETE FROM public.oidc_consumed_states
  WHERE state_hash IN (
    SELECT state_hash FROM public.oidc_consumed_states
    WHERE expires_at <= now()
    ORDER BY expires_at LIMIT bound);
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.databastion_prune_oidc_consumed_states(integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.databastion_prune_oidc_consumed_states(integer) TO databastion_app;
--> statement-breakpoint
REVOKE DELETE ON TABLE public.oidc_consumed_states FROM databastion_app;
