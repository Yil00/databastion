import { readFileSync, readdirSync } from "node:fs";
import bundle from "@/generated/protocol/schemas.gen.json";
import { describe, expect, it } from "vitest";

import {
  MAX_POINTER_LENGTH,
  MAX_VALIDATION_DETAILS,
  type SchemaName,
  type Schemas,
  type ValidationDetail,
  checkSemantics,
  isSufficientlyMasked,
  schemaNames,
  validateEnrollRequest,
  validateHeartbeatRequest,
  validateSchema,
} from "./validate";

const FIXTURES = new URL("../../../../shared/protocol/fixtures/", import.meta.url);
const NAME = /^([A-Z][A-Za-z0-9]*)\.([a-z0-9][a-z0-9-]*)\.json$/;

function fixtures(kind: "valid" | "invalid"): { file: string; schema: SchemaName; body: unknown }[] {
  const dir = new URL(`${kind}/`, FIXTURES);
  return readdirSync(dir)
    .sort()
    .map((file) => {
      const match = NAME.exec(file);
      if (!match?.[1]) throw new Error(`bad fixture name ${kind}/${file}`);
      return {
        file,
        schema: match[1] as SchemaName,
        body: JSON.parse(readFileSync(new URL(file, dir), "utf8")) as unknown,
      };
    });
}

const valid = fixtures("valid");
const invalid = fixtures("invalid");

describe("protocol validator: fixtures", () => {
  it("finds the fixtures", () => {
    expect(valid.length).toBeGreaterThan(0);
    expect(invalid.length).toBeGreaterThan(0);
  });

  it.each(valid)("accepts valid/$file", ({ schema, body }) => {
    expect(schemaNames).toContain(schema);
    const result = validateSchema(schema, body);
    expect(result).toEqual({ ok: true, value: body });
  });

  it.each(invalid)("rejects invalid/$file", ({ schema, body }) => {
    expect(schemaNames).toContain(schema);
    const result = validateSchema(schema, body);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.details.length).toBeGreaterThan(0);
      expect(result.details.length).toBeLessThanOrEqual(MAX_VALIDATION_DETAILS);
    }
  });

  it("returns the very same object on success (never modified)", () => {
    const first = valid[0];
    if (!first) throw new Error("no valid fixture");
    const before = JSON.stringify(first.body);
    const result = validateSchema(first.schema, first.body);
    expect(result.ok && result.value).toBe(first.body);
    expect(JSON.stringify(first.body)).toBe(before);
  });

  it("throws on an unknown schema name", () => {
    expect(() => validateSchema("NoSuchSchema" as SchemaName, {})).toThrow();
  });
});

describe("protocol validator: error details never echo the body (L2)", () => {
  const base = valid.find((f) => f.file === "HeartbeatRequest.minimal.json");
  if (!base) throw new Error("missing HeartbeatRequest.minimal.json fixture");

  it("rejects an unknown field without naming it nor echoing its value", () => {
    const body = { ...(base.body as object), value: "jane.doe@example.com" };
    const result = validateHeartbeatRequest(body);
    expect(result.ok).toBe(false);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("jane.doe");
    expect(serialized).not.toContain("example.com");
    expect(serialized).not.toContain("value");
    expect(result).toEqual({ ok: false, details: [{ pointer: "", keyword: "additionalProperties" }] });
  });

  it("does not echo a submitted value that fails a format / pattern / type check", () => {
    const secret = "jane.doe@example.com\u0000<script>";
    for (const body of [
      { agent_version: secret },
      { ...(base.body as object), agent_version: secret },
      { ...(base.body as object), agent_version: { "jane.doe@example.com": secret } },
      [secret],
      secret,
    ]) {
      const result = validateHeartbeatRequest(body);
      expect(result.ok).toBe(false);
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain("jane.doe");
      expect(serialized).not.toContain("script");
    }
  });

  it("masks unknown keys in nested pointers", () => {
    const result = validateEnrollRequest({ "jane.doe@example.com": { nested: 1 } });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain("jane.doe");
  });

  it("masks a submitted metrics key (open-keyed map) in the pointer", () => {
    const body = { ...(base.body as object), metrics: { jane_doe_iban: "FR7630006000011234567890189" } };
    const result = validateHeartbeatRequest(body);
    expect(result).toEqual({ ok: false, details: [{ pointer: "/metrics", keyword: "type" }] });
    expect(JSON.stringify(result)).not.toContain("jane");
  });

  it("keeps contract property names and real array indices", () => {
    const body = { ...(base.body as object), connectors: ["postgres", 42] };
    const result = validateHeartbeatRequest(body);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.details[0]?.pointer).toBe("/connectors/1");
  });

  it("only reports pointer and keyword", () => {
    const result = validateEnrollRequest({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      for (const detail of result.details) {
        expect(Object.keys(detail).sort()).toEqual(["keyword", "pointer"]);
      }
    }
  });
});

describe("protocol validator: details conform to ErrorDetail (M1)", () => {
  const collected: ValidationDetail[] = [];
  const hb = valid.find((f) => f.file === "HeartbeatRequest.minimal.json")?.body as object;
  const deep: unknown[] = [];
  let nested: unknown = 1;
  for (let i = 0; i < 200; i++) nested = [nested];
  deep.push(nested);
  const probes: [SchemaName, unknown][] = [
    ["HeartbeatRequest", { ...hb, value: "jane.doe@example.com" }],
    ["HeartbeatRequest", { ...hb, metrics: { abc: "x" } }],
    ["HeartbeatRequest", { ...hb, connectors: ["postgres", 42] }],
    ["HeartbeatRequest", { ...hb, "Jane~/Doe": 1 }],
    ["HeartbeatRequest", { ...hb, connectors: deep }],
    ["EnrollRequest", { "jane.doe@example.com": { nested: 1 } }],
    ["EnrollRequest", []],
    ["EnrollRequest", null],
  ];

  it("every detail of every invalid fixture and probe is a valid ErrorDetail", () => {
    const inputs: [SchemaName, unknown][] = [...invalid.map((f) => [f.schema, f.body] as [SchemaName, unknown]), ...probes];
    for (const [schema, body] of inputs) {
      const result = validateSchema(schema, body);
      expect(result.ok).toBe(false);
      if (!result.ok) collected.push(...result.details);
    }
    expect(collected.length).toBeGreaterThan(inputs.length - 1);
    for (const detail of collected) {
      expect(detail.pointer.length).toBeLessThanOrEqual(MAX_POINTER_LENGTH);
      expect(validateSchema("ErrorDetail", detail), JSON.stringify(detail)).toEqual({ ok: true, value: detail });
    }
  });

  it("semantic details are valid ErrorDetails too", () => {
    for (const detail of [
      { pointer: "", keyword: "maxBytes" },
      { pointer: "/findings/0/masked_samples/1", keyword: "maskRatio" },
    ]) {
      expect(validateSchema("ErrorDetail", detail).ok).toBe(true);
    }
  });
});

describe("protocol semantics (checkSemantics, L1)", () => {
  it("accepts every valid fixture", () => {
    for (const { file, schema, body } of valid) {
      expect(checkSemantics(schema, body as Schemas[typeof schema]).ok, file).toBe(true);
    }
  });

  it("applies the 50 % mask rule of MaskedSample", () => {
    expect(isSufficientlyMasked("06 ** ** ** 78")).toBe(true);
    expect(isSufficientlyMasked("j*******@e******.com")).toBe(true);
    expect(isSufficientlyMasked("FR76 **** **** **** **** ***1 89")).toBe(true);
    expect(isSufficientlyMasked("jane*doe*")).toBe(false);
    expect(isSufficientlyMasked("06 12 ** 56 78")).toBe(false);
    expect(isSufficientlyMasked("-")).toBe(false);
  });

  it("rejects a schema-valid but under-masked sample, without echoing it", () => {
    const fixture = valid.find(
      (f) =>
        f.schema === "FindingsBatch" &&
        (f.body as Schemas["FindingsBatch"]).findings.some((x) => (x.masked_samples ?? []).length > 0),
    );
    if (!fixture) throw new Error("no FindingsBatch fixture with masked samples");
    const body = structuredClone(fixture.body) as Schemas["FindingsBatch"];
    const i = body.findings.findIndex((x) => (x.masked_samples ?? []).length > 0);
    const finding = body.findings[i];
    if (!finding?.masked_samples) throw new Error("unreachable");
    finding.masked_samples[0] = "jane*doe*";
    const schemaResult = validateSchema("FindingsBatch", body);
    expect(schemaResult.ok).toBe(true);
    const result = checkSemantics("FindingsBatch", body);
    expect(result).toEqual({
      ok: false,
      details: [{ pointer: `/findings/${i}/masked_samples/0`, keyword: "maskRatio" }],
    });
    expect(JSON.stringify(result)).not.toContain("jane");
  });

  it("rejects a value larger than x-databastion-max-bytes", () => {
    const fixture = valid.find((f) => f.schema === "EventsBatch");
    if (!fixture) throw new Error("no EventsBatch fixture");
    const max = (bundle.$defs.EventsBatch as Record<string, unknown>)["x-databastion-max-bytes"];
    expect(max).toBe(1048576);
    const big = { ...(fixture.body as object), padding: "x".repeat(1048576) } as unknown as Schemas["EventsBatch"];
    expect(checkSemantics("EventsBatch", big)).toEqual({ ok: false, details: [{ pointer: "", keyword: "maxBytes" }] });
  });

  it("MaskedSample is only used in FindingsBatch.findings[].masked_samples (else extend checkSemantics)", () => {
    const refsTo = (target: string): string[] => {
      const refs: string[] = [];
      const walk = (node: unknown, path: string): void => {
        if (Array.isArray(node)) node.forEach((n, i) => walk(n, `${path}/${i}`));
        else if (node !== null && typeof node === "object") {
          for (const [k, v] of Object.entries(node)) {
            if (k === "$ref" && v === `#/$defs/${target}`) refs.push(path);
            walk(v, `${path}/${k}`);
          }
        }
      };
      walk(bundle.$defs, "");
      return refs;
    };
    expect(refsTo("MaskedSample")).toEqual(["/Finding/properties/masked_samples/items"]);
    expect(refsTo("Finding")).toEqual(["/FindingsBatch/properties/findings/items"]);
  });
});
