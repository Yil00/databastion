import { describe, expect, it } from "vitest";

import { POLICY_FIELD_ERRORS, policyErrorMessage } from "@/components/console/policy-form";
import bundle from "@/generated/protocol/schemas.gen.json";
import { parseEventConditions } from "@/lib/event-model";

import { AUDIT_SOURCES, ENGINES, EVENT_ACTIONS, exhaustive, orList } from "./enums";

type Defs = Record<string, { enum?: unknown; properties?: Record<string, { enum?: unknown }> }>;
const defs = (bundle as { $defs: Defs }).$defs;

describe("contract value lists", () => {
  it("match the generated JSON Schema enums exactly, in order", () => {
    expect(AUDIT_SOURCES).toEqual(defs.AuditSource?.enum);
    expect(ENGINES).toEqual(defs.Engine?.enum);
    expect(EVENT_ACTIONS).toEqual(defs.AccessEvent?.properties?.action?.enum);
  });

  it("include the MongoDB engine and audit sources", () => {
    expect(ENGINES).toContain("mongodb");
    expect(AUDIT_SOURCES).toEqual(expect.arrayContaining(["mongodb_audit_log", "mongodb_profiler", "mongodb_log"]));
  });

  it("reject a tuple that misses a member at compile time", () => {
    // @ts-expect-error "b" is missing
    expect(exhaustive<"a" | "b">()(["a"])).toEqual(["a"]);
    // @ts-expect-error "c" is not a member
    expect(exhaustive<"a" | "b">()(["a", "b", "c"])).toEqual(["a", "b", "c"]);
  });

  it("renders a closed list for a hint", () => {
    expect(orList([])).toBe("");
    expect(orList(["a"])).toBe("a");
    expect(orList(["a", "b", "c"])).toBe("a, b or c");
  });
});

describe("policy form hints", () => {
  it("list every audit source, engine and action of the contract", () => {
    for (const s of AUDIT_SOURCES) expect(POLICY_FIELD_ERRORS.sources).toContain(s);
    for (const e of ENGINES) expect(POLICY_FIELD_ERRORS.engines).toContain(e);
    for (const a of EVENT_ACTIONS) expect(POLICY_FIELD_ERRORS.event_actions).toContain(a);
    expect(policyErrorMessage(400, { error: "invalid_policy", field: "sources" })).toMatch(/mongodb_profiler/);
  });

  it("describe values the server accepts", () => {
    const r = parseEventConditions({ event_actions: [...EVENT_ACTIONS], sources: [...AUDIT_SOURCES], engines: [...ENGINES] });
    expect(r.ok).toBe(true);
  });
});
