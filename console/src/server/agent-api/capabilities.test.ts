import { describe, expect, it } from "vitest";

import bundle from "@/generated/protocol/schemas.gen.json";
import { validateSchema } from "@/lib/protocol/validate";

import { auditSourceEngines } from "@/lib/location-labels";
import { AUDIT_SOURCES, ENGINES } from "@/lib/protocol/enums";
import { fixtures } from "@/test/helpers";

import {
  AGENT_TOKENS,
  agentAccepts,
  agentAcceptsToStore,
  auditSourceTokens,
  connectorTokens,
  CONSOLE_ACCEPTS,
  engineTokens,
  processTokens,
  RELEASE_ACCEPTS,
  unlistedEngineDetails,
  type EngineToken as ContractEngineToken,
} from "./capabilities";

type Def = { properties?: Record<string, unknown> };
const defs = bundle.$defs as Record<string, Def>;

type Token = (typeof CONSOLE_ACCEPTS)[number];
type EngineToken = Extract<Token, `engine.${string}`>;
/** Enum revision tokens (ADR-0022 decision 4): `<object>.<field>.<revision>`. */
type RevisionToken = Extract<Token, `target_status.note_labels.${string}`>;

/** The contract fields each field capability token stands for (ADR-0022). */
const FIELDS: Record<Exclude<Token, EngineToken | RevisionToken>, [schema: string, ...properties: string[]]> = {
  "access_event.bytes": ["AccessEvent", "bytes"],
  "access_event.objects_overflowed": ["AccessEvent", "objects_overflowed"],
  "job_progress.coverage": [
    "JobProgress",
    "objects_sampled",
    "skipped_not_readable",
    "skipped_row_level_security",
    "skipped_remote",
    "skipped_unsupported",
    "skipped_limit",
    "skipped_error",
  ],
  "location.altered": ["Location", "altered"],
  "object_ref.altered": ["ObjectRef", "altered"],
  "target_status.name_case": ["TargetStatus", "name_case"],
  "target_status.notes": ["TargetStatus", "notes"],
};

/** The contract values each engine token stands for (ADR-0039 decision 8, ADR-0041 decision 12). */
const ENGINE_TOKENS: Record<EngineToken, { engine: string; connector?: string; sources: string[] }> = {
  "engine.cas": { engine: "cas", connector: "cas", sources: ["cas_audit_log"] },
  "engine.sqlserver": { engine: "sqlserver", connector: "sqlserver", sources: ["sqlserver_audit", "sqlserver_xevents", "sqlserver_query_stats"] },
  // One connector and four sources serve both Redis and Valkey (ADR-0052 decision 12).
  "engine.redis": { engine: "redis", connector: "redis", sources: ["redis_slowlog", "redis_commandlog", "redis_acl_log", "redis_sync"] },
  "engine.valkey": { engine: "valkey", connector: "redis", sources: ["redis_slowlog", "redis_commandlog", "redis_acl_log", "redis_sync"] },
  // Discovery only (ADR-0059 decision 7): no Audit source.
  "engine.sqlite": { engine: "sqlite", connector: "sqlite", sources: [] },
  // ADR-0060 decision 8: listed since P10-E, with the note-label revision 2026_10_d.
  "engine.firebird": { engine: "firebird", connector: "firebird", sources: ["firebird_audit_trace"] },
};

function isEngineToken(token: Token): token is EngineToken {
  return token.startsWith("engine.");
}

function isRevisionToken(token: Token): token is RevisionToken {
  return token.startsWith("target_status.note_labels.");
}

function enumOf(schema: string): string[] {
  return ((defs[schema] as { enum?: string[] } | undefined)?.enum ?? []).slice();
}

describe("CONSOLE_ACCEPTS (ADR-0022)", () => {
  it("is a valid, sorted, duplicate-free CapabilityList", () => {
    expect(validateSchema("CapabilityList", [...CONSOLE_ACCEPTS]).ok).toBe(true);
    expect([...CONSOLE_ACCEPTS]).toEqual([...new Set(CONSOLE_ACCEPTS)].sort());
  });

  it("names only fields that the generated contract schemas accept", () => {
    for (const token of CONSOLE_ACCEPTS) {
      if (isEngineToken(token) || isRevisionToken(token)) continue;
      const [schema, ...properties] = FIELDS[token];
      const def = defs[schema];
      expect(def, schema).toBeDefined();
      for (const p of properties) expect(Object.keys(def?.properties ?? {}), `${token}: ${schema}.${p}`).toContain(p);
    }
  });

  it("names only engines that the generated contract enums accept (ADR-0039 decision 8)", () => {
    for (const token of CONSOLE_ACCEPTS) {
      if (!isEngineToken(token)) continue;
      const engine = ENGINE_TOKENS[token];
      expect(token).toBe(`engine.${engine.engine}`);
      expect(enumOf("Engine"), token).toContain(engine.engine);
      if (engine.connector) expect(enumOf("Connector"), token).toContain(engine.connector);
      for (const source of engine.sources) expect(enumOf("AuditSource"), token).toContain(source);
    }
  });

  it("lists every engine added after protocol 0.1.0 (engine.sqlite and engine.firebird since P10-E)", () => {
    const v010 = ["postgres", "mysql", "mariadb", "mongodb", "openldap"];
    const listed = CONSOLE_ACCEPTS.filter(isEngineToken).map((t) => ENGINE_TOKENS[t].engine);
    expect(enumOf("Engine").filter((e) => !v010.includes(e)).sort()).toEqual([...listed].sort());
    expect(CONSOLE_ACCEPTS).toContain("engine.sqlite");
    expect(CONSOLE_ACCEPTS).toContain("engine.firebird");
  });

  it("lists engine.firebird and target_status.note_labels.2026_10_d together, here and in every held release list", () => {
    const together = (list: readonly string[]) => list.includes("engine.firebird") === list.includes("target_status.note_labels.2026_10_d");
    expect(CONSOLE_ACCEPTS).toContain("target_status.note_labels.2026_10_d");
    expect(together(CONSOLE_ACCEPTS)).toBe(true);
    for (const [release, list] of Object.entries(RELEASE_ACCEPTS)) {
      expect(together(list), release).toBe(true);
      // No released line lists them: both are held by every hold value.
      expect(list, release).not.toContain("engine.firebird");
    }
  });

  it("lists engine.redis and engine.valkey together (ADR-0052 decision 12: the shared values need both)", () => {
    expect(CONSOLE_ACCEPTS).toContain("engine.redis");
    expect(CONSOLE_ACCEPTS).toContain("engine.valkey");
    expect(CONSOLE_ACCEPTS).toContain("engine.sqlserver");
  });

  it("lists location.altered and object_ref.altered together (ADR-0056 decision 1 item 5)", () => {
    expect(CONSOLE_ACCEPTS).toContain("location.altered");
    expect(CONSOLE_ACCEPTS).toContain("object_ref.altered");
  });

  it("lists the SQL Server and Firebird note-label revisions, whose labels are contract TargetNoteLabel values (ADR-0051 decision 4 and refinement, ADR-0060)", () => {
    expect(CONSOLE_ACCEPTS.filter(isRevisionToken)).toEqual([
      "target_status.note_labels.2026_10",
      "target_status.note_labels.2026_10_b",
      "target_status.note_labels.2026_10_c",
      "target_status.note_labels.2026_10_d",
    ]);
    for (const label of ["sysadmin", "db_owner", "ms_login_manager", "control_server", "password_hash_probe"]) {
      expect(enumOf("TargetNoteLabel"), label).toContain(label);
    }
    for (const label of [
      "alter_any_database_event_session",
      "alter_any_database_event_session_enable",
      "alter_any_database_event_session_disable",
      "alter_any_database_event_session_add_event",
      "alter_any_database_event_session_drop_event",
      "alter_any_database_event_session_add_target",
      "alter_any_database_event_session_drop_target",
      "alter_any_database_event_session_option",
      "create_any_database_event_session",
      "drop_any_database_event_session",
      "view_any_performance_definition",
      "view_security_definition",
      "view_performance_definition",
      "view_database_security_state",
      "view_database_performance_state",
      "view_any_column_encryption_key_definition",
      "view_any_column_master_key_definition",
      "logon_trigger_probe",
      "refusal_list_probe",
      "cas_store_guard_probe",
      "on_failure_probe",
    ]) {
      expect(enumOf("TargetNoteLabel"), label).toContain(label);
    }
  });

  it("is a valid HeartbeatResponse.accepts", () => {
    const body = { console_min_protocol: 1, heartbeat_interval_s: 30, server_time: new Date().toISOString(), accepts: [...CONSOLE_ACCEPTS] };
    expect(validateSchema("HeartbeatResponse", body).ok).toBe(true);
  });
});

/** Every engine token of the contract, all listed since P10-E. */
const ALL_ENGINE_TOKENS: ContractEngineToken[] = ["engine.cas", "engine.sqlserver", "engine.redis", "engine.valkey", "engine.sqlite", "engine.firebird"];

describe("AGENT_TOKENS (ADR-0022 decision 3)", () => {
  it("is a valid, sorted CapabilityList that the contract names in HeartbeatRequest.accepts", () => {
    expect(validateSchema("CapabilityList", [...AGENT_TOKENS]).ok).toBe(true);
    expect([...AGENT_TOKENS]).toEqual([...new Set(AGENT_TOKENS)].sort());
    const description = JSON.stringify(defs.HeartbeatRequest?.properties?.accepts ?? {});
    for (const token of AGENT_TOKENS) expect(description, token).toContain(token);
  });

  it("stores only the known tokens of a heartbeat, and reads them back", () => {
    expect(agentAcceptsToStore(undefined)).toEqual([]);
    expect(agentAcceptsToStore(["future.token", "sensitive_object.key_pattern"])).toEqual(["sensitive_object.key_pattern"]);
    expect(agentAccepts(["sensitive_object.key_pattern"], "sensitive_object.key_pattern")).toBe(true);
    expect(agentAccepts([], "sensitive_object.key_pattern")).toBe(false);
    expect(agentAccepts(null, "sensitive_object.key_pattern")).toBe(false);
    expect(agentAccepts("sensitive_object.key_pattern", "sensitive_object.key_pattern")).toBe(false);
  });
});

describe("engine token gate (ADR-0042, P9-C review H1)", () => {
  it("mirrors the agent's token functions (capabilities.rs)", () => {
    for (const e of ["postgres", "mysql", "mariadb", "mongodb", "openldap"] as const) expect(engineTokens(e)).toEqual([]);
    expect(engineTokens("cas")).toEqual(["engine.cas"]);
    expect(engineTokens("sqlserver")).toEqual(["engine.sqlserver"]);
    expect(engineTokens("redis")).toEqual(["engine.redis"]);
    expect(engineTokens("valkey")).toEqual(["engine.valkey"]);
    expect(connectorTokens("mysql")).toEqual([]);
    expect(connectorTokens("cas")).toEqual(["engine.cas"]);
    expect(connectorTokens("sqlserver")).toEqual(["engine.sqlserver"]);
    expect(connectorTokens("redis")).toEqual(["engine.redis", "engine.valkey"]);
    for (const s of ["pgaudit", "mariadb_server_audit", "performance_schema", "openldap_accesslog"] as const) expect(auditSourceTokens(s)).toEqual([]);
    expect(auditSourceTokens("cas_audit_log")).toEqual(["engine.cas"]);
    for (const s of ["sqlserver_audit", "sqlserver_xevents", "sqlserver_query_stats"] as const) expect(auditSourceTokens(s)).toEqual(["engine.sqlserver"]);
    for (const s of ["redis_slowlog", "redis_commandlog", "redis_acl_log", "redis_sync"] as const) {
      expect(auditSourceTokens(s)).toEqual(["engine.redis", "engine.valkey"]);
    }
    expect(processTokens("sqlservr")).toEqual(["engine.sqlserver"]);
    expect(processTokens("redis-server")).toEqual(["engine.redis"]);
    expect(processTokens("valkey-server")).toEqual(["engine.valkey"]);
    expect(processTokens("mysqld")).toEqual([]);
    expect(engineTokens("firebird")).toEqual(["engine.firebird"]);
    expect(connectorTokens("firebird")).toEqual(["engine.firebird"]);
    expect(auditSourceTokens("firebird_audit_trace")).toEqual(["engine.firebird"]);
    expect(processTokens("firebird")).toEqual(["engine.firebird"]);
  });

  it("names only contract tokens, each `engine.<value>` of an engine added after protocol 0.1.0", () => {
    for (const e of ENGINES) for (const t of engineTokens(e)) expect(t).toBe(`engine.${e}`);
    for (const s of AUDIT_SOURCES) for (const t of auditSourceTokens(s)) expect(ALL_ENGINE_TOKENS).toContain(t);
    expect(validateSchema("CapabilityList", ALL_ENGINE_TOKENS).ok).toBe(true);
  });

  it("lets every valid fixture through with CONSOLE_ACCEPTS (P10-E lists every engine token of the contract)", () => {
    for (const t of ALL_ENGINE_TOKENS) expect(CONSOLE_ACCEPTS as readonly string[]).toContain(t);
    for (const name of ["EnrollRequest", "HeartbeatRequest", "FindingsBatch", "EventsBatch"] as const) {
      for (const [file, body] of fixtures("valid", name)) expect(unlistedEngineDetails(name, body), file).toEqual([]);
    }
  });

  it("gates every firebird value on engine.firebird, listed since P10-E (ADR-0060 decision 8)", () => {
    const without = CONSOLE_ACCEPTS.filter((t) => t !== "engine.firebird");
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["postgres", "firebird"] }, without)).toEqual([{ pointer: "/connectors/1", keyword: "enum" }]);
    const hb = {
      connectors: ["firebird"],
      targets: [{ engine: "firebird", audit_source: "firebird_audit_trace" }],
      detected_targets: [{ engine: "firebird", process: "firebird" }],
    };
    expect(unlistedEngineDetails("HeartbeatRequest", hb, without)).toEqual([
      { pointer: "/connectors/0", keyword: "enum" },
      { pointer: "/targets/0/engine", keyword: "enum" },
      { pointer: "/targets/0/audit_source", keyword: "enum" },
      { pointer: "/detected_targets/0/engine", keyword: "enum" },
      { pointer: "/detected_targets/0/process", keyword: "enum" },
    ]);
    const findings = { findings: [{ location: { engine: "firebird" } }] };
    expect(unlistedEngineDetails("FindingsBatch", findings, without)).toEqual([{ pointer: "/findings/0/location/engine", keyword: "enum" }]);
    const events = { batch_id: "x", events: [{ source: "firebird_audit_trace" }] };
    expect(unlistedEngineDetails("EventsBatch", events, without)).toEqual([{ pointer: "/events/0/source", keyword: "enum" }]);
    // The lists of the released lines (held consoles list them; validation uses CONSOLE_ACCEPTS).
    for (const list of Object.values(RELEASE_ACCEPTS)) expect(unlistedEngineDetails("EventsBatch", events, list)).toHaveLength(1);
    // Listed by this console: nothing refused.
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["postgres", "firebird"] })).toEqual([]);
    expect(unlistedEngineDetails("HeartbeatRequest", hb)).toEqual([]);
    expect(unlistedEngineDetails("FindingsBatch", findings)).toEqual([]);
    expect(unlistedEngineDetails("EventsBatch", events)).toEqual([]);
  });

  it("gates every sqlite value on engine.sqlite, listed since P10-E (ADR-0059 decision 8)", () => {
    expect(engineTokens("sqlite")).toEqual(["engine.sqlite"]);
    expect(connectorTokens("sqlite")).toEqual(["engine.sqlite"]);
    for (const s of AUDIT_SOURCES) expect(auditSourceTokens(s), s).not.toContain("engine.sqlite");
    const without = CONSOLE_ACCEPTS.filter((t) => t !== "engine.sqlite");
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["postgres", "sqlite"] }, without)).toEqual([{ pointer: "/connectors/1", keyword: "enum" }]);
    const hb = { connectors: ["sqlite"], targets: [{ engine: "sqlite" }], detected_targets: [] };
    expect(unlistedEngineDetails("HeartbeatRequest", hb, without)).toEqual([
      { pointer: "/connectors/0", keyword: "enum" },
      { pointer: "/targets/0/engine", keyword: "enum" },
    ]);
    const findings = { findings: [{ location: { engine: "sqlite" } }] };
    expect(unlistedEngineDetails("FindingsBatch", findings, without)).toEqual([{ pointer: "/findings/0/location/engine", keyword: "enum" }]);
    // Listed by this console: nothing refused.
    expect(unlistedEngineDetails("EnrollRequest", { connectors: ["postgres", "sqlite"] })).toEqual([]);
    expect(unlistedEngineDetails("HeartbeatRequest", hb)).toEqual([]);
    expect(unlistedEngineDetails("FindingsBatch", findings)).toEqual([]);
  });

  it("still refuses, with enum, every value of an engine a token list leaves out (the gate for later engines)", () => {
    // The list of a console built before P9-E.
    const before = ["access_event.bytes", "engine.cas", "job_progress.coverage", "target_status.notes"];
    for (const name of ["EnrollRequest", "HeartbeatRequest", "FindingsBatch", "EventsBatch"] as const) {
      for (const [file, body] of fixtures("valid", name)) {
        const unlisted = unlistedEngineDetails(name, body, before);
        expect(unlisted.length > 0, file).toBe(/sqlserver|redis|valkey|sqlite|firebird/.test(file));
        for (const d of unlisted) expect(d.keyword).toBe("enum");
      }
    }
  });

  it("needs both Redis and Valkey tokens for the shared values", () => {
    const events = { batch_id: "x", events: [{ source: "redis_slowlog" }] };
    expect(unlistedEngineDetails("EventsBatch", events, ["engine.redis"])).toEqual([{ pointer: "/events/0/source", keyword: "enum" }]);
    expect(unlistedEngineDetails("EventsBatch", events, ["engine.valkey"])).toHaveLength(1);
    expect(unlistedEngineDetails("EventsBatch", events, ["engine.redis", "engine.valkey"])).toEqual([]);
    const enroll = { connectors: ["redis"] };
    expect(unlistedEngineDetails("EnrollRequest", enroll, ["engine.redis"])).toEqual([{ pointer: "/connectors/0", keyword: "enum" }]);
    const findings = { findings: [{ location: { engine: "valkey" } }] };
    expect(unlistedEngineDetails("FindingsBatch", findings, ["engine.valkey"])).toEqual([]);
    expect(unlistedEngineDetails("FindingsBatch", findings, ["engine.redis"])).toEqual([{ pointer: "/findings/0/location/engine", keyword: "enum" }]);
  });
});

describe("source-to-engine table (contract `AuditSource`, Heartbeat target checks, P9-E)", () => {
  it("the console's SOURCE_ENGINES is the contract's table, for every AuditSource value", () => {
    const description = String((defs.AuditSource as { description?: string } | undefined)?.description ?? "");
    const table = new Map<string, string[]>();
    for (const line of description.split("\n")) {
      const m = /^- (.+) -> (.+)[;.]$/.exec(line.trim());
      if (!m) continue;
      const engines = [...(m[2] ?? "").matchAll(/`([a-z_]+)`/g)].map((x) => x[1] ?? "");
      for (const s of (m[1] ?? "").matchAll(/`([a-z_]+)`/g)) table.set(s[1] ?? "", engines);
    }
    expect([...table.keys()].sort()).toEqual([...AUDIT_SOURCES].sort());
    for (const s of AUDIT_SOURCES) expect([...auditSourceEngines(s)].sort(), s).toEqual([...(table.get(s) ?? [])].sort());
  });
});
