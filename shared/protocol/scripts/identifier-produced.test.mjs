// Self-test of identifier-produced.schema.json (ADR-0057 decision 1): the producer rule of every
// normalized name a conforming agent sends as an `Identifier`. The schema refines `Identifier`
// (one `$ref`, nothing restated), is referenced by nothing in openapi.yaml (no generator reads it),
// compiles under the contract's Ajv settings, and accepts and refuses the ADR's examples, each
// refusal for its intended rule. The agent side (the same patterns, verbatim, and every name the
// normalizer emits) is agent/crates/classifiers/tests/identifier_produced.rs.
// Run with `node --test scripts/identifier-produced.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { buildAjv, root } from "./contract-ajv.mjs";

const SCHEMA_ID = "https://databastion.invalid/protocol/v1/identifier-produced.schema.json";
const text = readFileSync(join(root, "openapi.yaml"), "utf8");
const doc = parse(text);
const schema = JSON.parse(readFileSync(join(root, "identifier-produced.schema.json"), "utf8"));
const ajv = buildAjv(doc);
ajv.addSchema(schema);
const validate = ajv.getSchema(SCHEMA_ID);
const rules = schema.not.anyOf.map((r) => [r.title.replace(/^rule /, ""), new RegExp(r.pattern, "u")]);

test("the schema refines Identifier and nothing in openapi.yaml refers to it", () => {
  assert.equal(schema.$id, SCHEMA_ID);
  assert.equal(schema.title, "IdentifierProduced");
  assert.deepEqual(schema.allOf, [{ $ref: "schemas.json#/$defs/Identifier" }]);
  assert.ok(!text.includes("IdentifierProduced"));
  assert.ok(!text.includes("identifier-produced"));
  const ids = rules.map(([id]) => id);
  assert.deepEqual(ids, ["1", "2", "3-ipv4", "3-mac-dashed", "3-mac-dotted", "4", "5-run", "5-total"]);
  for (const r of schema.not.anyOf) {
    assert.equal(r.type, "string");
    assert.ok(r.description.length > 0);
  }
});

const refused = {
  "06.12.34.56.78": "2",
  "06_12_34_56_78": "2",
  "1_2_3_4_5": "2",
  "v1-2-3-4-5": "2",
  "a1-2.3-4.5b": "2",
  "06\u00a012\u00a034\u00a056\u00a078": "2",
  "06\u201012\u201034\u201056\u201078": "2",
  "06\uff0e12\uff0e34\uff0e56\uff0e78": "2",
  "_________": "1",
  "ou=123456789,dc=x": "1",
  "host.10.0.0.1": "3-ipv4",
  "ou=10.0.0.1,dc=x": "3-ipv4",
  "00-1a-2b-3c-4d-5e": "3-mac-dashed",
  "001a.2b3c.4d5e": "3-mac-dotted",
  "device.001a.2b3c.4d5e.port": "3-mac-dotted",
  "%41": "4",
  "%u0041": "4",
  "a1234567": "5-run",
  "a\u0663\u0664\u0665\u0666\u0667\u0668\u0669": "5-run",
  "a12.b34.c56.d78.e9": "5-total",
  "ou=1234,dc=56789": "5-total",
};

test("the ADR's refused examples fail, each for its rule", () => {
  for (const [s, rule] of Object.entries(refused)) {
    assert.equal(validate(s), false, JSON.stringify(s));
    const hit = rules.filter(([, re]) => re.test(s)).map(([id]) => id);
    assert.ok(hit.includes(rule), `${JSON.stringify(s)}: ${hit}`);
  }
});

test("ordinary names, masked names and container DNs pass", () => {
  for (const s of [
    "face.cafe.beef",
    "orders",
    "orders[].email",
    "*",
    "*.phone",
    "v2.users",
    "events_2024_09",
    "first_name",
    "a.1.2.3",
    "matrix[][]",
    "ou=people,dc=example,dc=org",
    "\u7b2c\u4e00\u540d",
    "%zz",
    "%u00",
  ]) {
    assert.equal(validate(s), true, `${JSON.stringify(s)}: ${JSON.stringify(validate.errors)}`);
  }
});

test("what Identifier refuses stays refused", () => {
  for (const s of ["", "jane@example.com", "uid=jdoe,ou=people", "12345678901", "a".repeat(257), 7]) {
    assert.equal(validate(s), false, JSON.stringify(s));
  }
});
