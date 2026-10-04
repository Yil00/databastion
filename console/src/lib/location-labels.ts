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

/** The `Location.database` of the CAS audit log (ADR-0041 decision 4). */
export const CAS_AUDIT_STORE = "audit_trail";

export function isLdapEngine(engine: string | null | undefined): boolean {
  return engine === "openldap";
}

export function isCasEngine(engine: string | null | undefined): boolean {
  return engine === "cas";
}

/** Engines whose location parts are shown with their own names rather than database / schema / table. */
export function hasNamedLocationParts(engine: string | null | undefined): boolean {
  return isLdapEngine(engine) || isCasEngine(engine);
}

/** Names of the location parts; `database` tells the CAS service registry from its audit log. */
export function locationPartLabels(engine: string | null | undefined, database: string | null = null): LocationPartLabels {
  if (isLdapEngine(engine)) return LDAP;
  if (isCasEngine(engine)) return database === CAS_AUDIT_STORE ? CAS_AUDIT : CAS_REGISTRY;
  return GENERIC;
}

/**
 * Engine of a contract `AuditSource`, when the source alone tells it (`null` for the sources that
 * MySQL and MariaDB share). Exhaustive: a new contract source fails `tsc` until it is listed.
 */
const SOURCE_ENGINE: Record<AuditSource, Engine | null> = {
  pgaudit: "postgres",
  pg_stat_statements: "postgres",
  pg_stat_activity: "postgres",
  mariadb_server_audit: null,
  mysql_audit_log: null,
  performance_schema: null,
  mongodb_audit_log: "mongodb",
  mongodb_profiler: "mongodb",
  mongodb_log: "mongodb",
  openldap_accesslog: "openldap",
  cas_audit_log: "cas",
};

export function auditSourceEngine(source: string): Engine | null {
  return Object.hasOwn(SOURCE_ENGINE, source) ? SOURCE_ENGINE[source as AuditSource] : null;
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
