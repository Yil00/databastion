// Id registries: signals.json (`Signal`) and target-notes.json (`TargetNoteCode`). Each maps an id
// to {description, engines}; the contract schema of the id checks its form only (so that an older
// console accepts an id registered later), and the registry is the vocabulary a conforming agent
// uses. Append-only: an id is never removed, renamed or given another meaning (see openapi.yaml,
// "Signal registry" and "Target-note registry"; CI compares each registry with dev and main).

import { SIGNALS_SCHEMA_ID, TARGET_NOTES_SCHEMA_ID } from "./contract-ajv.mjs";

/** Ids used in a fixture, per registry: every string of `signals` arrays; every `code` of `notes` items. */
function signalIds(node, out) {
  if (Array.isArray(node)) return node.forEach((n) => signalIds(n, out));
  if (!node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    if (k === "signals" && Array.isArray(v)) out.push(...v.filter((s) => typeof s === "string"));
    else signalIds(v, out);
  }
}
function noteCodes(node, out) {
  if (Array.isArray(node)) return node.forEach((n) => noteCodes(n, out));
  if (!node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    if (k === "notes" && Array.isArray(v)) {
      for (const note of v) if (note && typeof note.code === "string") out.push(note.code);
    } else {
      noteCodes(v, out);
    }
  }
}

/** The id registries: file, JSON Schema id and how to collect their ids from a body. */
export const ID_REGISTRIES = {
  signals: { file: "signals.json", schemaId: SIGNALS_SCHEMA_ID, collect: signalIds, what: "signal" },
  targetNotes: { file: "target-notes.json", schemaId: TARGET_NOTES_SCHEMA_ID, collect: noteCodes, what: "target-note code" },
};

/** Problems of a registry: JSON Schema, then ids sorted ascending. */
export function idRegistryProblems(ajv, kind, registry) {
  const { file, schemaId } = ID_REGISTRIES[kind];
  const validate = ajv.getSchema(schemaId);
  if (!validate(registry)) {
    return validate.errors.map((e) => `${file}${e.instancePath}: ${e.keyword} (${e.message})`);
  }
  const ids = Object.keys(registry);
  const sorted = [...ids].sort();
  return ids.some((id, i) => id !== sorted[i]) ? [`${file}: ids must be sorted ascending`] : [];
}

/** Valid fixtures only use registered ids. */
export function fixtureIdProblems(data, kind, registry, where) {
  const { file, collect, what } = ID_REGISTRIES[kind];
  const ids = [];
  collect(data, ids);
  return ids.filter((id) => !Object.hasOwn(registry, id)).map((id) => `${where}: ${what} "${id}" is not in ${file}`);
}
