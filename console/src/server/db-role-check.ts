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
  if (row?.superuser) {
    warnings.push("The console connects to its database as a superuser: use the non-owner runtime role (README, Database roles).");
  }
  if (row?.owns_audit_log) {
    warnings.push("The console connects as the owner of audit_log: the append-only trigger could be removed. Use the non-owner runtime role (README, Database roles).");
  }
  return warnings;
}
