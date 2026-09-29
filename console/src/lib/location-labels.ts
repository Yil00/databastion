import type { AuditSource, Engine } from "@/lib/protocol/enums";

/**
 * Engine-specific names of the contract `Location` parts and of principal fingerprints, for the
 * findings, events and incidents views (client-safe: no Node imports).
 *
 * OpenLDAP (ADR-0029 decision 6, contract `Location` text): `database` is the naming context,
 * `schema` the entry's container (a normalized DN of `ou` / `dc` / `o` / `c` / `l` / `st` RDNs,
 * never an entry DN), `object` the structural object class and `field` the attribute. Labelling
 * them "schema" or "table" would mislead: the views show the LDAP names instead.
 */

export interface LocationPartLabels {
  database: string;
  schema: string;
  object: string;
  field: string;
}

const GENERIC: LocationPartLabels = { database: "database", schema: "schema", object: "object", field: "field" };
const LDAP: LocationPartLabels = { database: "naming context", schema: "container", object: "object class", field: "attribute" };

export function isLdapEngine(engine: string | null | undefined): boolean {
  return engine === "openldap";
}

export function locationPartLabels(engine: string | null | undefined): LocationPartLabels {
  return isLdapEngine(engine) ? LDAP : GENERIC;
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
  return isLdapEngine(engine) ? "LDAP principal fingerprint" : "fingerprint";
}

/**
 * Tooltip of a fingerprinted principal: what it is (never a name), why the agent sent it, and the
 * full value (to compare or look up on the agent host).
 */
export function fingerprintTitle(fingerprint: string, engine: string | null | undefined): string {
  const why = isLdapEngine(engine)
    ? "The agent sent a keyed fingerprint (HMAC) of this LDAP principal instead of its DN: entry DNs usually name a person, so only anonymous, the agent's own DN and the DNs listed in openldap.clear_principals are sent in clear (ADR-0029). It is not a name; the same DN always gives the same fingerprint on one agent, and only the agent host can map it back to a DN."
    : "The agent sent a keyed fingerprint (HMAC) instead of the account name (unknown or non-conforming name, e.g. a failed login whose user name may be a mistyped password). It is not a name; the same name always gives the same fingerprint on one agent.";
  return `${why}\n${fingerprint}`;
}
