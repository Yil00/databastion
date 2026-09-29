// Signal registry (signals.json): the access-event signal ids a conforming agent may emit, with
// their meaning. The `Signal` schema of openapi.yaml checks the form only (so that an older console
// accepts a signal registered later); this registry is the vocabulary. Append-only: an id is never
// removed, renamed or given another meaning (see openapi.yaml, `Signal`).

import { SIGNALS_SCHEMA_ID } from "./contract-ajv.mjs";

/** Problems of a signal registry: JSON Schema (signals.schema.json), then ids sorted ascending. */
export function signalRegistryProblems(ajv, registry) {
  const validate = ajv.getSchema(SIGNALS_SCHEMA_ID);
  if (!validate(registry)) {
    return validate.errors.map((e) => `signals.json${e.instancePath}: ${e.keyword} (${e.message})`);
  }
  const ids = Object.keys(registry);
  const sorted = [...ids].sort();
  return ids.some((id, i) => id !== sorted[i]) ? ["signals.json: ids must be sorted ascending"] : [];
}

/**
 * Valid fixtures only use registered signals: every string of every `signals` array, at any
 * depth, is a key of the registry.
 */
export function fixtureSignalProblems(data, registry, where) {
  const problems = [];
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== "object") return;
    for (const [k, v] of Object.entries(node)) {
      if (k === "signals" && Array.isArray(v)) {
        for (const s of v) {
          if (typeof s === "string" && !Object.hasOwn(registry, s)) {
            problems.push(`${where}: signal "${s}" is not in signals.json`);
          }
        }
      } else {
        visit(v);
      }
    }
  };
  visit(data);
  return problems;
}
