import type { components } from "@/generated/protocol/types.gen";

/**
 * Closed value lists of the contract (`shared/protocol/openapi.yaml`, generated into
 * `types.gen.ts`), for the views, hints and condition checks that need them at runtime.
 *
 * The lists are written out here rather than read from `schemas.gen.json` so that client
 * components can import them without shipping the whole schema bundle. They cannot go stale:
 * {@link exhaustive} makes `tsc` fail when the generated union gains or loses a member, and
 * `enums.test.ts` compares every list with the generated JSON Schema enum.
 */

type Schemas = components["schemas"];

/** Contract `AuditSource`. */
export type AuditSource = Schemas["AuditSource"];
/** Contract `Engine`. */
export type Engine = Schemas["Engine"];
/** Contract `AccessEvent.action`. */
export type EventAction = Schemas["AccessEvent"]["action"];

/**
 * Identity on a tuple of `U` values that only type-checks when the tuple lists every member of `U`
 * (a missing member shows up as `{ missing: ... }` in the error).
 */
export function exhaustive<U extends string>() {
  return <const T extends readonly U[]>(
    values: T & ([Exclude<U, T[number]>] extends [never] ? unknown : { missing: Exclude<U, T[number]> }),
  ): T => values;
}

/** Every contract `AuditSource`, in contract order. */
export const AUDIT_SOURCES = exhaustive<AuditSource>()([
  "pgaudit",
  "pg_stat_statements",
  "pg_stat_activity",
  "mariadb_server_audit",
  "mysql_audit_log",
  "performance_schema",
  "mongodb_audit_log",
  "mongodb_profiler",
  "mongodb_log",
  "openldap_accesslog",
  "cas_audit_log",
]);

/** Every contract `Engine`, in contract order. */
export const ENGINES = exhaustive<Engine>()(["postgres", "mysql", "mariadb", "mongodb", "openldap", "cas"]);

/** Every contract `AccessEvent.action`, in contract order. */
export const EVENT_ACTIONS = exhaustive<EventAction>()(["connect", "auth_failure", "read", "write", "ddl", "dcl"]);

/** `a, b, c or d`: a closed list rendered for a form hint. */
export function orList(values: readonly string[]): string {
  if (values.length <= 1) return values.join("");
  return `${values.slice(0, -1).join(", ")} or ${values[values.length - 1]}`;
}
