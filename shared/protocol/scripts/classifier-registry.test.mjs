// Self-test of the classifier registry checks: the real classifiers.json passes, and each known
// way of breaking it is caught. Run with `node --test scripts/classifier-registry.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { fixtureRegistryProblems, lockProblems, registryProblems, versionHash } from "./classifier-registry.mjs";
import { buildAjv, root } from "./contract-ajv.mjs";

const ajv = buildAjv(parse(readFileSync(join(root, "openapi.yaml"), "utf8")));
const registry = JSON.parse(readFileSync(join(root, "classifiers.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(root, "classifiers.lock.json"), "utf8"));
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

test("classifiers.lock.json pins every published version", () => {
  assert.deepEqual(lockProblems(registry, lock), []);
});

test("version hash ignores id order", () => {
  assert.equal(versionHash(["pii.iban", "pii.email"]), versionHash(["pii.email", "pii.iban"]));
});

const lockBreaks = {
  "id added to a published version": () => [{ ...registry, [version]: [...registry[version], "pii.zzz"].sort() }, lock],
  "id removed from a published version": () => [{ ...registry, [version]: registry[version].slice(1) }, lock],
  "id renamed in a published version": () => [
    { ...registry, [version]: registry[version].map((id, i) => (i === 0 ? "pii.renamed" : id)).sort() },
    lock,
  ],
  "published version removed": () => [{ "2099.01.1": ["pii.email"] }, { ...lock, "2099.01.1": versionHash(["pii.email"]) }],
  "new version not appended to the lock": () => [{ ...registry, "2099.01.1": ["pii.email"] }, lock],
  "malformed lock hash": () => [registry, { ...lock, [version]: "deadbeef" }],
};
for (const [name, make] of Object.entries(lockBreaks)) {
  test(`lock rejects: ${name}`, () => {
    const [r, l] = make();
    assert.notDeepEqual(lockProblems(r, l), []);
  });
}
