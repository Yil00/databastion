import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import {
  CLASSIFIERS_URL,
  SCHEMAS_URL,
  TYPES_URL,
  assertLocalRefs,
  renderArtifacts,
  renderClassifierRegistry,
} from "../../../scripts/protocol/generate";

// Drift check: the committed generated files must match shared/protocol/openapi.yaml.
describe("generated protocol artifacts", () => {
  it("are up to date with shared/protocol/openapi.yaml", async () => {
    const expected = await renderArtifacts();
    const hint = "generated protocol files are stale: run `pnpm protocol:generate` in console/";
    expect((await readFile(TYPES_URL, "utf8")) === expected.types, `types.gen.ts: ${hint}`).toBe(true);
    expect((await readFile(SCHEMAS_URL, "utf8")) === expected.schemas, `schemas.gen.json: ${hint}`).toBe(true);
    expect((await readFile(CLASSIFIERS_URL, "utf8")) === expected.classifiers, `classifiers.gen.ts: ${hint}`).toBe(
      true,
    );
  }, 60_000);
});

describe("generator ref guard (no remote refs)", () => {
  it("accepts local refs", () => {
    expect(() => assertLocalRefs({ a: { $ref: "#/components/schemas/X" }, b: [{ $ref: "#/x" }] })).not.toThrow();
  });

  it.each(["https://example.com/s.json", "other.yaml#/X", "./x.json", "//example.com/x", "#x"])(
    "rejects $ref %s",
    (ref) => {
      expect(() => assertLocalRefs({ components: { schemas: { A: { items: [{ $ref: ref }] } } } })).toThrow(
        /non-local \$ref/,
      );
    },
  );

  it("rejects a non-string $ref", () => {
    expect(() => assertLocalRefs({ $ref: 42 })).toThrow(/non-local \$ref/);
  });
});

describe("classifier registry rendering (fails closed)", () => {
  const patterns = { version: /^[0-9]{4}\.[0-9]{2}\.[0-9]{1,4}$/u, id: /^[a-z]+(\.[a-z0-9_]+)+$/u };

  it("renders a const", () => {
    expect(renderClassifierRegistry({ "2026.09.1": ["pii.email"] }, patterns)).toContain(
      "export const CLASSIFIER_REGISTRY",
    );
  });

  it.each([
    ["not an object", ["pii.email"]],
    ["empty", {}],
    ["bad version", { "2026.9.1": ["pii.email"] }],
    ["empty list", { "2026.09.1": [] }],
    ["bad id", { "2026.09.1": ["PII Email"] }],
    ["duplicate id", { "2026.09.1": ["pii.email", "pii.email"] }],
  ])("rejects %s", (_name, registry) => {
    expect(() => renderClassifierRegistry(registry, patterns)).toThrow();
  });
});
