// Classifier registry (classifiers.json): the valid classifier ids of each `classifiers_version`.
// The console rejects findings whose version or classifier id is not in it (see openapi.yaml,
// "Console-side checks"); the console and agent generators consume it.

import { createHash } from "node:crypto";
import { REGISTRY_SCHEMA_ID } from "./contract-ajv.mjs";

/**
 * Hash pinned in classifiers.lock.json for a version: `sha256:` + hex SHA-256 of the JSON array of
 * its ids, sorted ascending, without whitespace (e.g. `["pii.email","pii.iban"]`).
 */
export function versionHash(ids) {
  return `sha256:${createHash("sha256").update(JSON.stringify([...ids].sort())).digest("hex")}`;
}

/**
 * Published versions are immutable: every version of classifiers.lock.json must still be in the
 * registry with the same hash, and every registry version must be pinned in the lock (a new
 * version is appended to the lock in the same change). A lock entry is never edited nor removed.
 */
export function lockProblems(registry, lock) {
  const problems = [];
  if (!lock || typeof lock !== "object" || Array.isArray(lock)) return ["classifiers.lock.json must be an object"];
  const HASH = /^sha256:[0-9a-f]{64}$/;
  for (const [version, hash] of Object.entries(lock)) {
    if (typeof hash !== "string" || !HASH.test(hash)) {
      problems.push(`classifiers.lock.json/${version}: malformed hash`);
    } else if (!Object.hasOwn(registry, version)) {
      problems.push(`classifiers.json: published version ${version} was removed (published versions are immutable)`);
    } else if (versionHash(registry[version]) !== hash) {
      problems.push(`classifiers.json/${version}: ids changed since publication (published versions are immutable; add a new version instead)`);
    }
  }
  for (const [version, ids] of Object.entries(registry)) {
    if (!Object.hasOwn(lock, version)) {
      problems.push(`classifiers.lock.json: new version ${version} must be appended to the lock as "${versionHash(ids)}"`);
    }
  }
  return problems;
}

/** Problems of a registry: JSON Schema (classifiers.schema.json), then ids sorted ascending. */
export function registryProblems(ajv, registry) {
  const validate = ajv.getSchema(REGISTRY_SCHEMA_ID);
  if (!validate(registry)) {
    return validate.errors.map((e) => `classifiers.json${e.instancePath}: ${e.keyword} (${e.message})`);
  }
  const problems = [];
  for (const [version, ids] of Object.entries(registry)) {
    const sorted = [...ids].sort();
    if (ids.some((id, i) => id !== sorted[i])) problems.push(`classifiers.json/${version}: ids must be sorted ascending`);
  }
  return problems;
}

/**
 * Valid fixtures must be consistent with the registry, as the console checks it: in every object
 * that carries a registered `classifiers_version` (FindingsBatch, DiscoveryScanJob), each
 * `classifier` / `classifiers` id below it belongs to that version. An unregistered version is
 * itself a problem.
 */
export function fixtureRegistryProblems(data, registry, where) {
  const problems = [];
  const ids = [];
  const collectIds = (node) => {
    if (Array.isArray(node)) return node.forEach(collectIds);
    if (!node || typeof node !== "object") return;
    for (const [k, v] of Object.entries(node)) {
      if (k === "classifier" && typeof v === "string") ids.push(v);
      else if (k === "classifiers" && Array.isArray(v)) ids.push(...v.filter((x) => typeof x === "string"));
      else collectIds(v);
    }
  };
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== "object") return;
    if (typeof node.classifiers_version === "string") {
      const known = registry[node.classifiers_version];
      if (!Object.hasOwn(registry, node.classifiers_version)) {
        problems.push(`${where}: classifiers_version "${node.classifiers_version}" is not in classifiers.json`);
        return;
      }
      ids.length = 0;
      collectIds(node);
      for (const id of ids) {
        if (!known.includes(id)) problems.push(`${where}: classifier "${id}" is not in classifiers.json for ${node.classifiers_version}`);
      }
      return;
    }
    Object.values(node).forEach(visit);
  };
  visit(data);
  return problems;
}
