import type { AuditSource, Engine } from "@/lib/protocol/enums";

/**
 * Engine-specific names of the contract `Location` parts and of principal fingerprints, for the
 * findings, events and incidents views (client-safe: no Node imports).
 *
 * OpenLDAP (ADR-0029 decision 6, contract `Location` text): `database` is the naming context,
 * `schema` the entry's container (a normalized DN of `ou` / `dc` / `o` / `c` / `l` / `st` RDNs,
 * never an entry DN), `object` the structural object class and `field` the attribute. Labelling
 * them "schema" or "table" would mislead: the views show the LDAP names instead.
 *
 * CAS (ADR-0041 decision 4, contract `Location` text): a service registry location is the store
 * (`service_registry`), the service type (`cas`, `oauth`, `oidc`, `saml`, `ws_federation`, `other`),
 * the normalized service name and the JSON path in the definition; the audit log location is the
 * store `audit_trail`, the log `audit_log` and the record field `who`. Principals are end users,
 * fingerprinted except `cas.clear_principals`, and `*` on an `auth_failure` event is the
 * several-accounts aggregate of a credential-stuffing burst (contract `Principal` text).
 *
 * SQL Server (ADR-0051 decision 5): database, schema, table, column.
 *
 * Redis / Valkey (ADR-0052 decision 7, contract `Location` text): `database` is `db<index>`,
 * `schema` the Redis type (`string`, `hash`, `list`, `set`, `zset`, `stream`), `object` the
 * normalized key pattern (`KeyPattern`, e.g. `user:*:email`) and `field` the hash or stream field,
 * `value` for strings and members, or `#key` / `#field` for values found in names. Key patterns
 * follow the contract's rendering rule (`KeyPattern`): escaped text only, never a link or `href`,
 * inline code in plain-text messages (`src/lib/key-pattern.ts`).
 *
 * SQLite (ADR-0059 decision 6, contract `Location` text): `database` is always `main` (SQLite's
 * name for the file's own database, the same on every target), no schema, `object` the table and
 * `field` the column. The views show the target, the table and the column, never `main` as if it
 * told files apart: the target id does (`locationDatabaseShown`).
 *
 * Firebird (ADR-0060 decision 5, contract `Location` text): database (the name declared in
 * `agent.yaml`, never a file path or alias), table, column; no schema (the contract refuses one).
 * Shown on one line, as for MySQL, without a schema part.
 */

export interface LocationPartLabels {
  database: string;
  schema: string;
  object: string;
  field: string;
}

const GENERIC: LocationPartLabels = { database: "database", schema: "schema", object: "object", field: "field" };
const LDAP: LocationPartLabels = { database: "naming context", schema: "container", object: "object class", field: "attribute" };
const CAS_REGISTRY: LocationPartLabels = { database: "store", schema: "service type", object: "service", field: "path" };
const CAS_AUDIT: LocationPartLabels = { database: "store", schema: "schema", object: "log", field: "field" };
const SQL_SERVER: LocationPartLabels = { database: "database", schema: "schema", object: "table", field: "column" };
const KEY_VALUE: LocationPartLabels = { database: "database", schema: "type", object: "key pattern", field: "field" };
const SQLITE: LocationPartLabels = { database: "database", schema: "schema", object: "table", field: "column" };
const FIREBIRD: LocationPartLabels = { database: "database", schema: "schema", object: "table", field: "column" };

/**
 * Display names of the contract engines. Exhaustive: a new contract engine fails `tsc` until it is
 * named here.
 */
const ENGINE_NAMES: Record<Engine, string> = {
  postgres: "PostgreSQL",
  mysql: "MySQL",
  mariadb: "MariaDB",
  mongodb: "MongoDB",
  openldap: "OpenLDAP",
  cas: "Apereo CAS",
  sqlserver: "Microsoft SQL Server",
  redis: "Redis",
  valkey: "Valkey",
  sqlite: "SQLite",
  firebird: "Firebird",
};

/** Display name of an engine; a string that is not a contract engine is returned as is. */
export function engineDisplayName(engine: string): string {
  return Object.hasOwn(ENGINE_NAMES, engine) ? ENGINE_NAMES[engine as Engine] : engine;
}

/** The `Location.database` of the CAS audit log (ADR-0041 decision 4). */
export const CAS_AUDIT_STORE = "audit_trail";

export function isLdapEngine(engine: string | null | undefined): boolean {
  return engine === "openldap";
}

export function isCasEngine(engine: string | null | undefined): boolean {
  return engine === "cas";
}

export function isSqliteEngine(engine: string | null | undefined): boolean {
  return engine === "sqlite";
}

/**
 * Engines with Discovery only: no server and Audit None by nature, so no audit source, server
 * version or edition, and no Audit settings (ADR-0059 decision 7; the agent ends an
 * `audit.configure` job `unsupported`, and the console never queues one). Shown as "Discovery only".
 */
export const DISCOVERY_ONLY_ENGINES: readonly Engine[] = ["sqlite"];

export function isDiscoveryOnlyEngine(engine: string | null | undefined): boolean {
  return (DISCOVERY_ONLY_ENGINES as readonly string[]).includes(engine ?? "");
}

/** What the views show for the audit level of a Discovery-only target. */
export const DISCOVERY_ONLY_LABEL = "Discovery only";
export const DISCOVERY_ONLY_TITLE =
  "This engine has no server and no access log: the agent reads the declared database file for Discovery only, and Audit is None by nature (ADR-0059). There are no Audit settings and no access events for such targets.";

/**
 * Whether the `database` part of a location tells anything: false on SQLite, where it is `main` on
 * every target (the target id tells files apart), so the views leave it out.
 */
export function locationDatabaseShown(engine: string | null | undefined): boolean {
  return !isSqliteEngine(engine);
}

/**
 * Engines whose location parts are shown with their own names rather than on one line: OpenLDAP,
 * CAS, Redis / Valkey (the key pattern is shown apart, as inline code) and SQLite (table and
 * column, without the constant database `main`).
 */
export function hasNamedLocationParts(engine: string | null | undefined): boolean {
  return isLdapEngine(engine) || isCasEngine(engine) || isKeyPatternEngine(engine) || isSqliteEngine(engine);
}

/** Names of the location parts; `database` tells the CAS service registry from its audit log. */
export function locationPartLabels(engine: string | null | undefined, database: string | null = null): LocationPartLabels {
  if (isLdapEngine(engine)) return LDAP;
  if (isCasEngine(engine)) return database === CAS_AUDIT_STORE ? CAS_AUDIT : CAS_REGISTRY;
  if (engine === "sqlserver") return SQL_SERVER;
  if (isKeyPatternEngine(engine)) return KEY_VALUE;
  if (isSqliteEngine(engine)) return SQLITE;
  if (engine === "firebird") return FIREBIRD;
  return GENERIC;
}

/**
 * Engines a contract `AuditSource` can serve: one engine, except the sources that MySQL and
 * MariaDB share and those that Redis and Valkey share (ADR-0052 decision 8). Exhaustive: a new
 * contract source fails `tsc` until it is listed. The agent API refuses an event whose source does
 * not serve its target's engine (P9-C review H1), and the engine-token gate of a source is the
 * union of its engines' tokens (`agent-api/capabilities.ts`).
 */
const SOURCE_ENGINES: Record<AuditSource, readonly Engine[]> = {
  pgaudit: ["postgres"],
  pg_stat_statements: ["postgres"],
  pg_stat_activity: ["postgres"],
  mariadb_server_audit: ["mysql", "mariadb"],
  mysql_audit_log: ["mysql", "mariadb"],
  performance_schema: ["mysql", "mariadb"],
  mongodb_audit_log: ["mongodb"],
  mongodb_profiler: ["mongodb"],
  mongodb_log: ["mongodb"],
  openldap_accesslog: ["openldap"],
  cas_audit_log: ["cas"],
  sqlserver_audit: ["sqlserver"],
  sqlserver_xevents: ["sqlserver"],
  sqlserver_query_stats: ["sqlserver"],
  redis_slowlog: ["redis", "valkey"],
  redis_commandlog: ["redis", "valkey"],
  redis_acl_log: ["redis", "valkey"],
  redis_sync: ["redis", "valkey"],
  firebird_audit_trace: ["firebird"],
};

/** Every contract `AuditSource` with its engines. */
export function auditSourceTable(): readonly (readonly [AuditSource, readonly Engine[]])[] {
  return Object.entries(SOURCE_ENGINES) as [AuditSource, readonly Engine[]][];
}

/** Engines served by a contract `AuditSource` (empty for a string that is not one). */
export function auditSourceEngines(source: string): readonly Engine[] {
  return Object.hasOwn(SOURCE_ENGINES, source) ? SOURCE_ENGINES[source as AuditSource] : [];
}

/**
 * Engine of a contract `AuditSource`, when the source alone tells it (`null` for the sources that
 * MySQL and MariaDB share, and for those Redis and Valkey share).
 */
export function auditSourceEngine(source: string): Engine | null {
  const engines = auditSourceEngines(source);
  return engines.length === 1 ? (engines[0] ?? null) : null;
}

/** Engines whose object names are `KeyPattern`s (contract `ObjectName`, ADR-0052 decision 7). */
export const KEY_PATTERN_ENGINES: readonly Engine[] = ["redis", "valkey"];

export function isKeyPatternEngine(engine: string | null | undefined): boolean {
  return (KEY_PATTERN_ENGINES as readonly string[]).includes(engine ?? "");
}

/** Contract `db_user_fingerprint` prefix (`^hmac-sha256:[0-9a-f]{64}$`). */
export const FINGERPRINT_PREFIX = "hmac-sha256:";

export function isFingerprint(principal: string): boolean {
  return principal.startsWith(FINGERPRINT_PREFIX);
}

/** The first 12 hex digits of a fingerprint, for display (the full value goes in the tooltip). */
export function shortFingerprint(fingerprint: string): string {
  const hex = isFingerprint(fingerprint) ? fingerprint.slice(FINGERPRINT_PREFIX.length) : fingerprint;
  return `${hex.slice(0, 12)}…`;
}

/** What a fingerprinted principal is called in the views. */
export function fingerprintNoun(engine: string | null | undefined): string {
  if (isLdapEngine(engine)) return "LDAP principal fingerprint";
  if (isCasEngine(engine)) return "CAS user fingerprint";
  return "fingerprint";
}

/**
 * Whether a principal sent in clear is the CAS several-accounts aggregate (`*`, contract
 * `Principal`): one client address failing for many accounts, never an account named `*`.
 */
export function isAggregatePrincipal(principal: string, engine: string | null | undefined): boolean {
  return isCasEngine(engine) && principal === "*";
}

export const AGGREGATE_PRINCIPAL_TITLE =
  "Several accounts: the agent aggregated the failed CAS authentications of one client address beyond 16 distinct accounts in 10 minutes (signal volume.failed_logins_many_accounts) into one event per address and minute. It is not an account name nor a wildcard; the event's count is the number of failures merged.";

/**
 * Tooltip of a fingerprinted principal: what it is (never a name), why the agent sent it, and the
 * full value (to compare or look up on the agent host).
 */
export function fingerprintTitle(fingerprint: string, engine: string | null | undefined): string {
  const why = isLdapEngine(engine)
    ? "The agent sent a keyed fingerprint (HMAC) of this LDAP principal instead of its DN: entry DNs usually name a person, so only anonymous, the agent's own DN and the DNs listed in openldap.clear_principals are sent in clear (ADR-0029). It is not a name; the same DN always gives the same fingerprint on one agent, and only the agent host can map it back to a DN."
    : isCasEngine(engine)
      ? "The agent sent a keyed fingerprint (HMAC) of this CAS user instead of the login: CAS principals are end users, so only the names listed in cas.clear_principals are sent in clear, and a failed login's name (possibly a mistyped password) is always fingerprinted (ADR-0041). It is not a name; the same login always gives the same fingerprint on one agent, and only the agent host can map it back."
      : "The agent sent a keyed fingerprint (HMAC) instead of the account name (unknown or non-conforming name, e.g. a failed login whose user name may be a mistyped password). It is not a name; the same name always gives the same fingerprint on one agent.";
  return `${why}\n${fingerprint}`;
}

/**
 * An event without a recorded account (contract `Principal.account_not_recorded`, Redis / Valkey
 * only, ADR-0052 decision 8): never a name nor a wildcard.
 */
export const UNRECORDED_PRINCIPAL_TITLE =
  "The source records no account for this access: a slow-log or command-log entry whose connection had closed before the agent could attribute it, or a full synchronization. It is not an account name nor a wildcard. Such events are grouped by client network for incidents, and no per-principal baseline is built for them.";
