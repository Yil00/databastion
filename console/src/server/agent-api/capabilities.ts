import type { components } from "@/generated/protocol/types.gen";
import { auditSourceEngines } from "@/lib/location-labels";
import type { AuditSource, Engine } from "@/lib/protocol/enums";
import { MAX_VALIDATION_DETAILS, type ValidationDetail } from "@/lib/protocol/validate";

/**
 * Capability negotiation (ADR-0022, contract `HeartbeatResponse.accepts`).
 *
 * Every contract schema is closed: an agent that sends an optional request field this console does
 * not know gets `400` (for a heartbeat, the whole heartbeat is lost). The console therefore lists,
 * in every heartbeat response, the optional request fields introduced after protocol 0.1.0 that
 * it accepts, and a conforming agent sends such a field only when the latest list names it.
 *
 * Rule: a token is listed here in the same change that makes the console accept the field (its
 * schema regenerated). "Accepts" means schema-valid and not rejected; the console may still
 * ignore the value. Today `access_event.bytes` is stored and shown (not scored),
 * `target_status.notes` is stored for the latest heartbeat and rendered, and the
 * `job_progress.coverage` counters are stored with the job's progress and shown with the target's
 * latest scan (src/lib/scan-coverage.ts).
 *
 * `access_event.objects_overflowed` (ADR-0053 decisions 1 and 3) is stored with the event
 * (`access_events.objects_overflowed`) and gives every `*` object of a flagged event the meaning
 * "objects of its database the event does not name": policy selection on the bound score and on
 * the database, location exceptions only when they cover the whole database, display and the
 * `incident.opened` payload (src/lib/event-model.ts, src/server/event-engine.ts). As for every
 * token, a console running several replicas lists it only once every replica runs this build
 * (ADR-0022 decision 8): an agent sends the field as soon as one replica lists it, and an older
 * replica (0.8.0 or earlier) rejects it with `400`; the agent then strips it and resends
 * (ADR-0022 decision 9): no event is lost, but the events resent that way lose the flag.
 *
 * `target_status.name_case` (ADR-0055 decisions 5 to 8): the `mysql`, `mariadb` and `sqlserver`
 * targets' name case semantics (the engine gate is the schema's) are stored per target in canonical
 * form by a compare-and-set in the heartbeat's transaction (`storeNameCase`,
 * src/server/name-case-inventory.ts), never answered with `400` for their size (an `except` past
 * 8 KiB is stored in the strict form, #301 review L3), applied by location exceptions per part
 * (`exceptionPartOptions`, src/lib/name-case.ts), shown on the agent page, and each change of a
 * target's rule runs its debounced inventory. A heartbeat without it keeps today's rule for that
 * target. Multi-replica consoles: as for every token, list it only once every replica runs this
 * build (ADR-0022 decision 8); an older replica answers `400` to a heartbeat that carries it, the
 * agent strips the field and resends (decision 9), and the target falls back to today's rule
 * until the next heartbeat reaches a replica of this build.
 *
 * Engines added after protocol 0.1.0 are tokens too (`engine.<value>`, ADR-0039 decision 8): until
 * the console lists one, a conforming agent sends no `Engine`, `Connector` or `AuditSource` value of
 * that engine (no target, detected target, finding or event). `engine.cas` (ADR-0041 decision 12):
 * `cas` targets, connectors, findings (service registry and audit log locations) and `cas_audit_log`
 * events are validated, stored and rendered like those of any engine. `engine.sqlserver`
 * (ADR-0051 decision 8) and `engine.redis` with `engine.valkey` (ADR-0052 decision 12) are listed
 * since P9-E, Redis and Valkey together (the `redis` connector and the `redis_*` sources need both):
 * their targets, connectors, detected targets, findings (`KeyPattern` objects for Redis / Valkey)
 * and events (`account_not_recorded` principals included, ADR-0052 decision 8) are validated,
 * stored and rendered like those of any engine. The gate (`unlistedEngineDetails`, P9-C review H1)
 * stays for any engine token added to the contract later.
 *
 * `target_status.note_labels.2026_10` (ADR-0051 decision 4, ADR-0022 decision 4): the SQL Server
 * `TargetNoteLabel` values of that revision are accepted and rendered with their display names
 * (`src/lib/target-notes.ts`). `target_status.note_labels.2026_10_b` (ADR-0051 refinement of
 * 2026-10-14, items 5 to 7): the second SQL Server revision (database-scoped event-session
 * permissions, the other permissions the connector judges by name, and the `check()` reads named
 * with `privilege.not_evaluated`), accepted and rendered the same way.
 * `target_status.note_labels.2026_10_c` (ADR-0051 refinement option (a'), phase 9 follow-ups):
 * `on_failure_probe`, the `ON_FAILURE = CONTINUE` failure counter the agent's grants do not read,
 * accepted and rendered the same way.
 */
export const CONSOLE_ACCEPTS = [
  "access_event.bytes",
  "access_event.objects_overflowed",
  "engine.cas",
  "engine.redis",
  "engine.sqlserver",
  "engine.valkey",
  "job_progress.coverage",
  "target_status.name_case",
  "target_status.note_labels.2026_10",
  "target_status.note_labels.2026_10_b",
  "target_status.note_labels.2026_10_c",
  "target_status.notes",
] as const;

export type ConsoleCapability = (typeof CONSOLE_ACCEPTS)[number];

// ------------------------------------------------------------- console -> agent (ADR-0022 decision 3)

/**
 * The console -> agent fields and value forms added after protocol 0.1.0 that this console can send,
 * each only to an agent whose latest `HeartbeatRequest.accepts` listed its token (an agent built
 * before it cannot decode it and would lose the whole job):
 * - `sensitive_object.key_pattern`: a `KeyPattern` that is not an `Identifier` as
 *   `SensitiveObject.object` in `audit.configure` jobs of Redis / Valkey targets
 *   (`src/server/audit-config.ts`, checked again at delivery in `src/server/jobs.ts`).
 *
 * The console stores, per agent, the tokens of this list its latest heartbeat named
 * (`agents.accepts`); other tokens are ignored (ADR-0022: unknown tokens are ignored).
 */
export const AGENT_TOKENS = ["sensitive_object.key_pattern"] as const;

export type AgentCapability = (typeof AGENT_TOKENS)[number];

/** The tokens of {@link AGENT_TOKENS} that a heartbeat's `accepts` lists, sorted (stored as is). */
export function agentAcceptsToStore(accepts: readonly string[] | undefined): AgentCapability[] {
  const listed = new Set(accepts ?? []);
  return AGENT_TOKENS.filter((t) => listed.has(t)).sort();
}

/** Whether a stored agent capability list (`agents.accepts`) names `token`. */
export function agentAccepts(stored: unknown, token: AgentCapability): boolean {
  return Array.isArray(stored) && stored.includes(token);
}

// ------------------------------------------------------------------------------ engine tokens

type ProtocolSchemas = components["schemas"];
type Connector = ProtocolSchemas["Connector"];
type DetectedProcess = NonNullable<ProtocolSchemas["DetectedTarget"]["process"]>;

/** Every `engine.<value>` token of the contract, listed by this console or not yet. */
export type EngineToken = "engine.cas" | "engine.sqlserver" | "engine.redis" | "engine.valkey";

/**
 * The tokens gating each `Engine` value (ADR-0039 decision 8, ADR-0042): none for the engines of
 * protocol 0.1.0, otherwise the value is accepted only while {@link CONSOLE_ACCEPTS} lists every
 * one. The single table of the gate: connectors, audit sources and detected processes take the
 * union of the tokens of the engines they serve, as the agent's `capabilities.rs` does
 * (`engine_token`, `connector_token`, `audit_source_token`). Exhaustive: a new contract engine
 * fails `tsc` until it is given its token.
 */
const ENGINE_TOKENS: Record<Engine, readonly EngineToken[]> = {
  postgres: [],
  mysql: [],
  mariadb: [],
  mongodb: [],
  openldap: [],
  cas: ["engine.cas"],
  sqlserver: ["engine.sqlserver"],
  redis: ["engine.redis"],
  valkey: ["engine.valkey"],
};

/** Engines each `Connector` serves (`mysql` covers MySQL and MariaDB, `redis` Redis and Valkey). */
const CONNECTOR_ENGINES: Record<Connector, readonly Engine[]> = {
  postgres: ["postgres"],
  mysql: ["mysql", "mariadb"],
  mongodb: ["mongodb"],
  openldap: ["openldap"],
  cas: ["cas"],
  sqlserver: ["sqlserver"],
  redis: ["redis", "valkey"],
};

/** Engine of each `DetectedTarget.process`. */
const PROCESS_ENGINES: Record<DetectedProcess, readonly Engine[]> = {
  postgres: ["postgres"],
  mysqld: ["mysql", "mariadb"],
  mariadbd: ["mariadb"],
  mongod: ["mongodb"],
  slapd: ["openldap"],
  sqlservr: ["sqlserver"],
  "redis-server": ["redis"],
  "valkey-server": ["valkey"],
};

function tokensOf(engines: readonly Engine[]): readonly EngineToken[] {
  return [...new Set(engines.flatMap((e) => ENGINE_TOKENS[e] ?? []))];
}

/** Tokens gating an `Engine` value. */
export function engineTokens(engine: Engine): readonly EngineToken[] {
  return ENGINE_TOKENS[engine] ?? [];
}

/** Tokens gating a `Connector` value (both Redis and Valkey tokens for `redis`). */
export function connectorTokens(connector: Connector): readonly EngineToken[] {
  return tokensOf(CONNECTOR_ENGINES[connector] ?? []);
}

/** Tokens gating an `AuditSource` value (both Redis and Valkey tokens for the `redis_*` sources). */
export function auditSourceTokens(source: AuditSource): readonly EngineToken[] {
  return tokensOf(auditSourceEngines(source));
}

/** Tokens gating a `DetectedTarget.process` value. */
export function processTokens(process: DetectedProcess): readonly EngineToken[] {
  return tokensOf(PROCESS_ENGINES[process] ?? []);
}

/** The capability list a gate is checked against: {@link CONSOLE_ACCEPTS} (tests pass another). */
export type AcceptedList = readonly string[];

function accepted(tokens: readonly EngineToken[], accepts: AcceptedList): boolean {
  return tokens.every((t) => accepts.includes(t));
}

/**
 * Item pointers of the values whose engine token this console does not list (ADR-0042): keyword
 * `enum`, as a console built before the value answers. On `/findings/<i>/location/engine` and
 * `/events/<i>/source` it is exactly the pointer for which a conforming agent keeps the item and
 * holds it until a heartbeat response lists the token (ADR-0042 decision 3). A conforming agent
 * never sends such a value (it waits for the token), so a refusal is an agent-integrity event
 * (`batch_rejected`) on `/findings` and `/events`. Checked after `validateSchema` and
 * `checkSemantics`, before anything is read from or written to the database.
 */
export function unlistedEngineDetails(
  name: "EnrollRequest" | "HeartbeatRequest" | "FindingsBatch" | "EventsBatch",
  value: unknown,
  accepts: AcceptedList = CONSOLE_ACCEPTS,
): ValidationDetail[] {
  const details: ValidationDetail[] = [];
  const push = (pointer: string, tokens: readonly EngineToken[]) => {
    if (details.length < MAX_VALIDATION_DETAILS && !accepted(tokens, accepts)) details.push({ pointer, keyword: "enum" });
  };
  switch (name) {
    case "EnrollRequest":
      (value as ProtocolSchemas["EnrollRequest"]).connectors.forEach((c, i) => push(`/connectors/${i}`, connectorTokens(c)));
      break;
    case "HeartbeatRequest": {
      const hb = value as ProtocolSchemas["HeartbeatRequest"];
      hb.connectors.forEach((c, i) => push(`/connectors/${i}`, connectorTokens(c)));
      hb.targets.forEach((t, i) => {
        push(`/targets/${i}/engine`, engineTokens(t.engine));
        if (t.audit_source !== undefined) push(`/targets/${i}/audit_source`, auditSourceTokens(t.audit_source));
      });
      hb.detected_targets.forEach((d, i) => {
        push(`/detected_targets/${i}/engine`, engineTokens(d.engine));
        if (d.process !== undefined) push(`/detected_targets/${i}/process`, processTokens(d.process));
      });
      break;
    }
    case "FindingsBatch":
      (value as ProtocolSchemas["FindingsBatch"]).findings.forEach((f, i) =>
        push(`/findings/${i}/location/engine`, engineTokens(f.location.engine)),
      );
      break;
    case "EventsBatch":
      (value as ProtocolSchemas["EventsBatch"]).events.forEach((e, i) => push(`/events/${i}/source`, auditSourceTokens(e.source)));
      break;
  }
  return details;
}
