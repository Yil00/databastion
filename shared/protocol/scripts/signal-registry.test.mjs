// Self-test of the signal registry checks: the real signals.json passes, and each known way of
// breaking it is caught. Run with `node --test scripts/signal-registry.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { fixtureSignalProblems, signalRegistryProblems } from "./signal-registry.mjs";
import { ROOT_ID, buildAjv, root } from "./contract-ajv.mjs";

const ajv = buildAjv(parse(readFileSync(join(root, "openapi.yaml"), "utf8")));
const registry = JSON.parse(readFileSync(join(root, "signals.json"), "utf8"));
const entry = { description: "A test signal.", engines: ["postgres"] };

test("signals.json passes", () => {
  assert.deepEqual(signalRegistryProblems(ajv, registry), []);
});

test("signals.json holds the six signals of the PostgreSQL connector", () => {
  for (const id of [
    "signature.pg_dump",
    "signature.copy_to_file",
    "signature.copy_to_program",
    "shape.full_table_copy",
    "shape.full_table_read",
    "volume.large_result",
  ]) {
    assert.ok(Object.hasOwn(registry, id), id);
  }
});

test("a new signal can be appended (additive extension)", () => {
  const extended = { ...registry, "signature.mysqldump": { description: "A mysqldump run.", engines: ["mysql", "mariadb"] } };
  const sorted = Object.fromEntries(Object.entries(extended).sort(([a], [b]) => (a < b ? -1 : 1)));
  assert.deepEqual(signalRegistryProblems(ajv, sorted), []);
});

const broken = {
  "empty registry": {},
  "list instead of map": [registry],
  "unknown family": { "exfil.dump": entry },
  "uppercase id": { "signature.PgDump": entry },
  "id without a family": { pg_dump: entry },
  "missing description": { "signature.x": { engines: ["postgres"] } },
  "empty description": { "signature.x": { ...entry, description: "" } },
  "description with a control character": { "signature.x": { ...entry, description: "a\nb" } },
  "description too long": { "signature.x": { ...entry, description: "x".repeat(513) } },
  "missing engines": { "signature.x": { description: "x" } },
  "empty engines": { "signature.x": { ...entry, engines: [] } },
  "unknown engine": { "signature.x": { ...entry, engines: ["oracle"] } },
  "duplicate engine": { "signature.x": { ...entry, engines: ["postgres", "postgres"] } },
  "unknown field": { "signature.x": { ...entry, threshold: 10000 } },
  "unsorted ids": { "volume.large_result": entry, "signature.pg_dump": entry },
};
for (const [name, value] of Object.entries(broken)) {
  test(`registry rejected: ${name}`, () => {
    assert.notDeepEqual(signalRegistryProblems(ajv, value), []);
  });
}

test("fixture consistency: registered signals pass, others fail", () => {
  const batch = (...signals) => ({ events: [{ signals }] });
  assert.deepEqual(fixtureSignalProblems(batch("signature.pg_dump", "volume.large_result"), registry, "x"), []);
  assert.equal(fixtureSignalProblems(batch("signature.pg_dump", "volume.above_baseline"), registry, "x").length, 1);
  assert.deepEqual(fixtureSignalProblems({ events: [{ action: "connect" }] }, registry, "x"), []);
});

test("the Signal schema checks the form only: a signal registered later is accepted", () => {
  const signal = ajv.getSchema(`${ROOT_ID}#/$defs/Signal`);
  assert.equal(signal("signature.mysqldump"), true);
  assert.equal(signal("signature.pg_dump"), true);
  assert.equal(signal("exfil.dump"), false);
  assert.equal(signal("signature.PgDump"), false);
});
