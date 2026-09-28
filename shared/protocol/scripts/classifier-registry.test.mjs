// Self-test of the classifier registry checks: the real classifiers.json passes, and each known
// way of breaking it is caught. Run with `node --test scripts/classifier-registry.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { fixtureRegistryProblems, registryProblems } from "./classifier-registry.mjs";
import { buildAjv, root } from "./contract-ajv.mjs";

const ajv = buildAjv(parse(readFileSync(join(root, "openapi.yaml"), "utf8")));
const registry = JSON.parse(readFileSync(join(root, "classifiers.json"), "utf8"));
const [version] = Object.keys(registry);

test("classifiers.json passes", () => {
  assert.deepEqual(registryProblems(ajv, registry), []);
});

const broken = {
  "empty registry": {},
  "malformed version key": { "2026.9.1": ["pii.email"] },
  "empty id list": { [version]: [] },
  "id not matching ClassifierId": { [version]: ["PII Email"] },
  "id without a dot": { [version]: ["email"] },
  "duplicate id": { [version]: ["pii.email", "pii.email"] },
  "non-string id": { [version]: [42] },
  "list instead of map": [registry[version]],
  "unsorted ids": { [version]: ["pii.phone", "pii.email"] },
};
for (const [name, value] of Object.entries(broken)) {
  test(`registry rejected: ${name}`, () => {
    assert.notDeepEqual(registryProblems(ajv, value), []);
  });
}

test("fixture consistency: registered ids pass, others fail", () => {
  const batch = (classifiers_version, classifier) => ({ classifiers_version, findings: [{ classifier }] });
  assert.deepEqual(fixtureRegistryProblems(batch(version, "pii.email"), registry, "x"), []);
  assert.equal(fixtureRegistryProblems(batch(version, "pii.unknown"), registry, "x").length, 1);
  assert.equal(fixtureRegistryProblems(batch("1999.01.1", "pii.email"), registry, "x").length, 1);
  const job = { jobs: [{ classifiers_version: version, params: { classifiers: ["pii.email", "pii.nope"] } }] };
  assert.equal(fixtureRegistryProblems(job, registry, "x").length, 1);
});
