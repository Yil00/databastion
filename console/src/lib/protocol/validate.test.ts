import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  MAX_VALIDATION_DETAILS,
  type SchemaName,
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
    expect(result).toEqual({ ok: false, details: [{ pointer: "/metrics/*", keyword: "type" }] });
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
