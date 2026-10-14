import { engineDisplayName } from "@/lib/location-labels";
import type { Engine } from "@/lib/protocol/enums";
import { validateSchema, type Schemas } from "@/lib/protocol/validate";

/**
 * Engines the agent spotted on its own host but that are not declared in its `agent.yaml`
 * (contract `HeartbeatRequest.detected_targets`, ADR-0006): suggestions only. The agent never
 * connects to a detected server, and the console cannot configure one: targets, accounts and
 * secret references are declared on the agent host (I3: credentials never reach the console).
 * The views show each one with a setup hint for its engine.
 */

export type DetectedTarget = Schemas["DetectedTarget"];

/** Contract bound of `HeartbeatRequest.detected_targets`. */
const MAX_DETECTED = 16;

/**
 * Detected targets as stored (`agents.detected_targets`, the latest heartbeat), re-checked against
 * the contract schema (defense in depth: an entry of the wrong shape is dropped, never rendered).
 */
export function parseDetectedTargets(v: unknown): DetectedTarget[] {
  if (!Array.isArray(v)) return [];
  return v.slice(0, MAX_DETECTED).filter((d): d is DetectedTarget => validateSchema("DetectedTarget", d).ok);
}

/** How the agent spotted it: socket path, port and process name, as reported. */
export function detectedHow(d: DetectedTarget): string {
  const parts: string[] = [];
  if (d.unix_socket !== undefined) parts.push(`socket ${d.unix_socket}`);
  if (d.port !== undefined) parts.push(`port ${d.port}`);
  if (d.process !== undefined) parts.push(`process ${d.process}`);
  return parts.join(", ");
}

const ACCOUNT_HINTS: Record<Engine, string> = {
  postgres: "a dedicated read-only role with the minimal grants of ADR-0012",
  mysql: "a dedicated account with the minimal grant variant of ADR-0018",
  mariadb: "a dedicated account with the minimal grant variant of ADR-0018",
  mongodb: "a dedicated user with read-only roles (ADR-0026)",
  openldap: "a read-only service DN, or SASL EXTERNAL over the ldapi:// socket (ADR-0029)",
  cas: "the CAS service registry and audit log files, local to the agent (ADR-0041)",
  sqlserver:
    "a dedicated SQL Server login with the least-privilege grant set of ADR-0051; a login that is sa, sysadmin, db_owner or can administer audits is refused",
  redis:
    "an ACL user with an explicit command allow-list (ADR-0052 decision 4), never the default user. A port alone cannot tell Redis from Valkey: declare the engine the server runs",
  valkey:
    "an ACL user with an explicit command allow-list (ADR-0052 decision 4), never the default user",
};

/**
 * Setup hint of a detected target: what to declare in `agent.yaml` on the agent host, for its
 * engine. Plain text (rendered as a text node).
 */
export function setupHint(engine: Engine): string {
  return `To monitor it, declare it in agent.yaml on the agent host (engine: ${engine}) with ${ACCOUNT_HINTS[engine]}, keep the secret in a 0600 file or an environment variable there, then restart the agent. See docs/05-security.md for the recommended ${engineDisplayName(engine)} account.`;
}
