import { describe, expect, it } from "vitest";

import bundle from "@/generated/protocol/schemas.gen.json";
import { validateSchema } from "@/lib/protocol/validate";

import { AUDIT_SOURCES, ENGINES } from "@/lib/protocol/enums";
import { fixtures } from "@/test/helpers";

import {
  auditSourceTokens,
  connectorTokens,
  CONSOLE_ACCEPTS,
  engineTokens,
  processTokens,
  unlistedEngineDetails,
  type EngineToken as ContractEngineToken,
} from "./capabilities";

type Def = { properties?: Record<string, unknown> };
const defs = bundle.$defs as Record<string, Def>;

type Token = (typeof CONSOLE_ACCEPTS)[number];
type EngineToken = Extract<Token, `engine.${string}`>;

/** The contract fields each field capability token stands for (ADR-0022). */
const FIELDS: Record<Exclude<Token, EngineToken>, [schema: string, ...properties: string[]]> = {
  "access_event.bytes": ["AccessEvent", "bytes"],
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
  "target_status.notes": ["TargetStatus", "notes"],
};

/** The contract values each engine token stands for (ADR-0039 decision 8, ADR-0041 decision 12). */
const ENGINE_TOKENS: Record<EngineToken, { engine: string; connector?: string; sources: string[] }> = {
  "engine.cas": { engine: "cas", connector: "cas", sources: ["cas_audit_log"] },
};

function isEngineToken(token: Token): token is EngineToken {
  return token.startsWith("engine.");
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
      if (isEngineToken(token)) continue;
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

  it("lists every engine added after protocol 0.1.0", () => {
    const v010 = ["postgres", "mysql", "mariadb", "mongodb", "openldap"];
    // In the contract since P9-C (ADR-0051, ADR-0052), listed by the console from P9-E on.
    const notListedYet = ["sqlserver", "redis", "valkey"];
    const listed = CONSOLE_ACCEPTS.filter(isEngineToken).map((t) => ENGINE_TOKENS[t].engine);
    expect(enumOf("Engine").filter((e) => !v010.includes(e) && !notListedYet.includes(e))).toEqual(listed);
    for (const e of notListedYet) expect(CONSOLE_ACCEPTS).not.toContain(`engine.${e}`);
  });

  it("is a valid HeartbeatResponse.accepts", () => {
    const body = { console_min_protocol: 1, heartbeat_interval_s: 30, server_time: new Date().toISOString(), accepts: [...CONSOLE_ACCEPTS] };
    expect(validateSchema("HeartbeatResponse", body).ok).toBe(true);
  });
});

/** Every engine token of the contract, as P9-E will list them. */
const ALL_ENGINE_TOKENS: ContractEngineToken[] = ["engine.cas", "engine.sqlserver", "engine.redis", "engine.valkey"];

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
  });

  it("names only contract tokens, each `engine.<value>` of an engine added after protocol 0.1.0", () => {
    for (const e of ENGINES) for (const t of engineTokens(e)) expect(t).toBe(`engine.${e}`);
    for (const s of AUDIT_SOURCES) for (const t of auditSourceTokens(s)) expect(ALL_ENGINE_TOKENS).toContain(t);
    expect(validateSchema("CapabilityList", ALL_ENGINE_TOKENS).ok).toBe(true);
  });

  it("refuses every value of an engine CONSOLE_ACCEPTS does not list, and nothing once every token is listed", () => {
    const all = [...CONSOLE_ACCEPTS, ...ALL_ENGINE_TOKENS];
    for (const name of ["EnrollRequest", "HeartbeatRequest", "FindingsBatch", "EventsBatch"] as const) {
      for (const [file, body] of fixtures("valid", name)) {
        expect(unlistedEngineDetails(name, body, all), file).toEqual([]);
        const unlisted = unlistedEngineDetails(name, body);
        expect(unlisted.length > 0, file).toBe(/sqlserver|redis|valkey/.test(file));
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
