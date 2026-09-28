import type { Pool } from "pg";

/**
 * Startup check of the runtime database role (security re-review L3): the web and worker processes
 * must not connect as a superuser nor as the owner of `audit_log`, otherwise the append-only
 * trigger can be removed by a compromised console. Warnings only, no configuration values.
 */
export async function runtimeRoleWarnings(pool: Pick<Pool, "query">): Promise<string[]> {
  const { rows } = await pool.query<{ superuser: boolean; owns_audit_log: boolean | null }>(`
    select r.rolsuper as superuser,
           (select pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE')
              from pg_catalog.pg_class c
             where c.oid = pg_catalog.to_regclass('public.audit_log')) as owns_audit_log
      from pg_catalog.pg_roles r
     where r.rolname = current_user`);
  const row = rows[0];
  const warnings: string[] = [];
  // Incidents (migrations 0015, 0016): never deletable, only lifecycle / re-match columns updatable.
  const incidents = await pool.query<{ del: boolean | null; upd_snapshot: boolean | null }>(`
    select case when pg_catalog.to_regclass('public.incidents') is null then null
                else pg_catalog.has_table_privilege(current_user, 'public.incidents', 'DELETE') end as del,
           case when pg_catalog.to_regclass('public.incidents') is null then null
                else pg_catalog.has_column_privilege(current_user, 'public.incidents', 'severity', 'UPDATE') end as upd_snapshot`);
  const inc = incidents.rows[0];
  if (!row?.superuser && !row?.owns_audit_log && (inc?.del || inc?.upd_snapshot)) {
    warnings.push(
      "The console's database role can delete incidents or rewrite their policy snapshot: apply migrations 0015 and 0016 (README, Database roles).",
    );
  }
  // Access events (migration 0022): never deletable nor rewritable (only through the purge function).
  const events = await pool.query<{ del: boolean | null; upd: boolean | null }>(`
    select case when pg_catalog.to_regclass('public.access_events') is null then null
                else pg_catalog.has_table_privilege(current_user, 'public.access_events', 'DELETE') end as del,
           case when pg_catalog.to_regclass('public.access_events') is null then null
                else pg_catalog.has_column_privilege(current_user, 'public.access_events', 'objects', 'UPDATE') end as upd`);
  const ev = events.rows[0];
  if (!row?.superuser && !row?.owns_audit_log && (ev?.del || ev?.upd)) {
    warnings.push(
      "The console's database role can delete or rewrite access events: apply migration 0022 (README, Database roles).",
    );
  }
  if (row?.superuser) {
    warnings.push("The console connects to its database as a superuser: use the non-owner runtime role (README, Database roles).");
  }
  if (row?.owns_audit_log) {
    warnings.push("The console connects as the owner of audit_log: the append-only trigger could be removed. Use the non-owner runtime role (README, Database roles).");
  }
  return warnings;
}
