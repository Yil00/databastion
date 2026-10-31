/** Warning left on a target by a change that narrowed its Audit settings (P4-C, `audit_configs.warning`). */
export type AuditWarning = "disabled" | "emptied" | "shrunk";

export function auditWarningText(warning: AuditWarning, removed: number | null): string {
  switch (warning) {
    case "disabled":
      return "The last change turned Audit off for this target.";
    case "emptied":
      return `The last change emptied the sensitive objects (${removed ?? "?"} removed): only accesses with a signal or above the row threshold are reported.`;
    case "shrunk":
      return `The last change removed ${removed ?? "?"} sensitive objects: accesses to them are only reported with a signal or above the row threshold.`;
  }
}

/**
 * Warning on a `min_rows` setting that cannot work as intended on the target's engine (#235 review
 * N2), shown by the Audit settings page and returned by the API; it does not block the save.
 * `no_row_counts`: a key-pattern (Redis / Valkey) target. Its events carry no row count, so a
 * `min_rows` value makes the agent drop every read and write event of the target that carries no
 * signal, is not always reported and names no listed sensitive key pattern (none can be listed
 * for an agent that does not accept key patterns, phase 9 follow-ups).
 */
export type MinRowsWarning = "no_row_counts";

export function minRowsWarning(keyPatternEngine: boolean, minRows: number | null): MinRowsWarning | null {
  return keyPatternEngine && minRows !== null ? "no_row_counts" : null;
}

export const MIN_ROWS_WARNING_TEXT: Record<MinRowsWarning, string> = {
  no_row_counts:
    "A row threshold is set, but the events of this target carry no row count: the agent drops every read and write event of this target that carries no signal and names no listed sensitive key pattern (always-reported events, such as scripts, still pass; an agent that cannot receive key patterns gets none), and policy row conditions never match them. Leave the row threshold empty on this target, unless its sensitive objects cover every key pattern that matters.",
};

/**
 * Engines whose contract `Location` has no `schema` (security review L2 of #391). On Firebird and
 * SQLite the contract refuses a location `schema` (ADR-0060 decision 5, ADR-0059 decision 6), so a
 * manual sensitive object with one is refused (`invalid`). On MySQL / MariaDB and MongoDB the
 * contract text gives no schema either, but earlier consoles stored such objects without
 * complaint, and refusing them now would make a stored configuration fail at its next save after
 * the upgrade: the save goes through with a {@link SchemaObjectsWarning} instead.
 */
export const SCHEMA_REFUSED_ENGINES: readonly string[] = ["firebird", "sqlite"];
export const SCHEMA_WARNED_ENGINES: readonly string[] = ["mysql", "mariadb", "mongodb"];

/**
 * `schema_never_matches`: manual sensitive objects of a MySQL / MariaDB or MongoDB target name a
 * schema. The agent matches a listed schema only against an event's schema (a listed object
 * without a schema matches any), and events of these engines carry none, so those objects never
 * match: their accesses are not always reported.
 */
export type SchemaObjectsWarning = "schema_never_matches";

/** Number of `objects` that name a schema. */
export function objectsWithSchema(objects: readonly { schema?: string | null }[]): number {
  return objects.filter((o) => o.schema !== undefined && o.schema !== null).length;
}

/** The warning of manual objects with a schema on a target of `engine`, if any (never on the refused engines: those are refused). */
export function schemaObjectsWarning(engine: string, objects: readonly { schema?: string | null }[]): SchemaObjectsWarning | null {
  return SCHEMA_WARNED_ENGINES.includes(engine) && objectsWithSchema(objects) > 0 ? "schema_never_matches" : null;
}

export const SCHEMA_OBJECTS_WARNING_TEXT: Record<SchemaObjectsWarning, string> = {
  schema_never_matches:
    "Some sensitive objects name a schema, but this engine's locations have none (MySQL, MariaDB and MongoDB: database and object only): the agent never matches those objects, so their accesses are not always reported. Remove the schema part of those lines and save again.",
};
