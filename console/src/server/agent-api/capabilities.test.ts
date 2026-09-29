import { describe, expect, it } from "vitest";

import bundle from "@/generated/protocol/schemas.gen.json";
import { validateSchema } from "@/lib/protocol/validate";

import { CONSOLE_ACCEPTS } from "./capabilities";

type Def = { properties?: Record<string, unknown> };
const defs = bundle.$defs as Record<string, Def>;

/** The contract fields each capability token stands for (ADR-0022). */
const FIELDS: Record<(typeof CONSOLE_ACCEPTS)[number], [schema: string, ...properties: string[]]> = {
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

describe("CONSOLE_ACCEPTS (ADR-0022)", () => {
  it("is a valid, sorted, duplicate-free CapabilityList", () => {
    expect(validateSchema("CapabilityList", [...CONSOLE_ACCEPTS]).ok).toBe(true);
    expect([...CONSOLE_ACCEPTS]).toEqual([...new Set(CONSOLE_ACCEPTS)].sort());
  });

  it("names only fields that the generated contract schemas accept", () => {
    for (const token of CONSOLE_ACCEPTS) {
      const [schema, ...properties] = FIELDS[token];
      const def = defs[schema];
      expect(def, schema).toBeDefined();
      for (const p of properties) expect(Object.keys(def?.properties ?? {}), `${token}: ${schema}.${p}`).toContain(p);
    }
  });

  it("is a valid HeartbeatResponse.accepts", () => {
    const body = { console_min_protocol: 1, heartbeat_interval_s: 30, server_time: new Date().toISOString(), accepts: [...CONSOLE_ACCEPTS] };
    expect(validateSchema("HeartbeatResponse", body).ok).toBe(true);
  });
});
