// Self-test of the id registry checks (signals.json, target-notes.json): the real registries pass,
// an appended id passes, and each known way of breaking a registry is caught. The contract schema
// of each id stays form-only. Run with `node --test scripts/id-registry.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { ID_REGISTRIES, fixtureIdProblems, idRegistryProblems } from "./id-registry.mjs";
import { ROOT_ID, buildAjv, root } from "./contract-ajv.mjs";

const ajv = buildAjv(parse(readFileSync(join(root, "openapi.yaml"), "utf8")));
const load = (kind) => JSON.parse(readFileSync(join(root, ID_REGISTRIES[kind].file), "utf8"));
const entry = { description: "A test entry.", engines: ["postgres"] };
const sortedObject = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1)));

const cases = {
  signals: {
    schema: "Signal",
    good: "signature.mysqldump",
    badForm: ["exfil.dump", "signature.PgDump", "pg_dump"],
    fixture: (...ids) => ({ events: [{ signals: ids }] }),
    required: [
      "signature.pg_dump",
      "signature.copy_to_file",
      "signature.copy_to_program",
      "shape.full_table_copy",
      "shape.full_table_read",
      "volume.large_result",
    ],
  },
  targetNotes: {
    schema: "TargetNoteCode",
    good: "audit.binlog_not_readable",
    badForm: ["note.x", "audit.Upper", "audit.", "audit"],
    fixture: (...ids) => ({ targets: [{ notes: ids.map((code) => ({ code })) }] }),
    required: ["security.tls_disabled", "coverage.relations_rls_skipped", "privilege.role_attributes", "check.timed_out"],
  },
};

for (const [kind, c] of Object.entries(cases)) {
  const registry = load(kind);
  const [someId] = Object.keys(registry);

  test(`${kind}: registry passes`, () => {
    assert.deepEqual(idRegistryProblems(ajv, kind, registry), []);
  });

  test(`${kind}: seeded ids are present`, () => {
    for (const id of c.required) assert.ok(Object.hasOwn(registry, id), id);
  });

  test(`${kind}: an id can be appended (additive extension)`, () => {
    assert.deepEqual(idRegistryProblems(ajv, kind, sortedObject({ ...registry, [c.good]: entry })), []);
  });

  const broken = {
    "empty registry": {},
    "list instead of map": [registry],
    "malformed id": { [c.badForm[0]]: entry },
    "missing description": { [someId]: { engines: ["postgres"] } },
    "empty description": { [someId]: { ...entry, description: "" } },
    "description with a control character": { [someId]: { ...entry, description: "a\nb" } },
    "description too long": { [someId]: { ...entry, description: "x".repeat(513) } },
    "missing engines": { [someId]: { description: "x" } },
    "empty engines": { [someId]: { ...entry, engines: [] } },
    "unknown engine": { [someId]: { ...entry, engines: ["oracle"] } },
    "duplicate engine": { [someId]: { ...entry, engines: ["postgres", "postgres"] } },
    "unknown field": { [someId]: { ...entry, threshold: 10000 } },
    "unsorted ids": Object.fromEntries(Object.keys(registry).slice(0, 2).reverse().map((id) => [id, entry])),
  };
  for (const [name, value] of Object.entries(broken)) {
    test(`${kind}: registry rejected: ${name}`, () => {
      assert.notDeepEqual(idRegistryProblems(ajv, kind, value), []);
    });
  }

  test(`${kind}: fixture consistency: registered ids pass, others fail`, () => {
    assert.deepEqual(fixtureIdProblems(c.fixture(someId), kind, registry, "x"), []);
    assert.equal(fixtureIdProblems(c.fixture(someId, c.good), kind, registry, "x").length, 1);
  });

  test(`${kind}: the ${c.schema} schema checks the form only (an id registered later is accepted)`, () => {
    const validate = ajv.getSchema(`${ROOT_ID}#/$defs/${c.schema}`);
    assert.equal(validate(c.good), true);
    assert.equal(validate(someId), true);
    for (const bad of c.badForm) assert.equal(validate(bad), false, bad);
  });
}
