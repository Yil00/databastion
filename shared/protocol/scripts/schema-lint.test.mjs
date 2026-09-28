// Self-test of scripts/schema-lint.mjs: the real contract passes, and each known way of
// opening or unbounding a schema is caught. Run with `node --test scripts/schema-lint.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { lintDocument } from "./schema-lint.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const original = parse(readFileSync(join(root, "openapi.yaml"), "utf8"));
const COUNT = { $ref: "#/components/schemas/Count" };

const mutate = (fn) => {
  const doc = structuredClone(original);
  fn(doc.components.schemas);
  return lintDocument(doc);
};

test("the contract passes the lint", () => {
  assert.deepEqual(lintDocument(original), []);
});

const mutations = {
  "empty schema property (raw: {})": (s) => { s.Finding.properties.raw = {}; },
  "boolean true property (raw: true)": (s) => { s.Finding.properties.raw = true; },
  "nullable string without maxLength": (s) => { s.Finding.properties.raw = { type: ["string", "null"] }; },
  "nullable object not closed": (s) => {
    s.Finding.properties.raw = { type: ["object", "null"], properties: { n: COUNT } };
  },
  "anyOf with an empty branch": (s) => { s.Finding.properties.raw = { anyOf: [COUNT, {}] }; },
  "oneOf with a true branch": (s) => { s.Finding.properties.raw = { oneOf: [COUNT, true] }; },
  "object schema opened": (s) => { s.Finding.additionalProperties = true; },
  "object schema without additionalProperties": (s) => { delete s.Location.additionalProperties; },
  "properties without type or closure": (s) => { s.Finding.properties.raw = { properties: { n: COUNT } }; },
  "untyped leaf": (s) => { s.Finding.properties.raw = { minLength: 1 }; },
  "string without maxLength": (s) => { delete s.Identifier.maxLength; },
  "array without maxItems": (s) => { delete s.Finding.properties.fingerprints.maxItems; },
  "number without maximum": (s) => { delete s.Finding.properties.confidence.maximum; },
  "integer without minimum": (s) => { delete s.Count.minimum; },
  "fragment opening its parent": (s) => { s.MaskedSample.allOf.push({ additionalProperties: true }); },
  "numeric map with string values": (s) => { s.MetricsMap.additionalProperties = { type: "string", maxLength: 8 }; },
  "numeric map without propertyNames": (s) => { delete s.MetricsMap.propertyNames; },
  "open map without the numeric-map mark": (s) => { delete s.MetricsMap["x-databastion-numeric-map"]; },
  "patternProperties on a closed object": (s) => {
    s.Finding.patternProperties = { ".*": { type: "string", maxLength: 4096 } };
  },
  "patternProperties in a fragment": (s) => {
    s.JobStatusUpdate.then.patternProperties = { ".*": { type: "string", maxLength: 8 } };
  },
  "unevaluatedProperties: true": (s) => { s.Location.unevaluatedProperties = true; },
  "propertyNames outside the numeric map": (s) => { s.Location.propertyNames = { type: "string", maxLength: 8 }; },
  "empty items schema": (s) => { s.Finding.properties.masked_samples.items = {}; },
};

for (const [name, fn] of Object.entries(mutations)) {
  test(`mutation is caught: ${name}`, () => {
    const problems = mutate(fn);
    assert.ok(problems.length > 0, `expected at least one problem for "${name}"`);
  });
}
