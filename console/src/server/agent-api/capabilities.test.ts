import { describe, expect, it } from "vitest";

import bundle from "@/generated/protocol/schemas.gen.json";
import { validateSchema } from "@/lib/protocol/validate";

import { CONSOLE_ACCEPTS } from "./capabilities";

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
    const listed = CONSOLE_ACCEPTS.filter(isEngineToken).map((t) => ENGINE_TOKENS[t].engine);
    expect(enumOf("Engine").filter((e) => !v010.includes(e))).toEqual(listed);
  });

  it("is a valid HeartbeatResponse.accepts", () => {
    const body = { console_min_protocol: 1, heartbeat_interval_s: 30, server_time: new Date().toISOString(), accepts: [...CONSOLE_ACCEPTS] };
    expect(validateSchema("HeartbeatResponse", body).ok).toBe(true);
  });
});
