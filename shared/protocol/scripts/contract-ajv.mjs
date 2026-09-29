// Builds the Ajv instance used by the contract tests: the `components.schemas` of openapi.yaml
// as a JSON Schema 2020-12 document (`$defs`, refs rewritten, nothing else), plus the classifier,
// signal and target-note registry schemas (classifiers.schema.json, signals.schema.json,
// target-notes.schema.json), which refer to it.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { MAP_MARK } from "./schema-lint.mjs";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const ROOT_ID = "https://databastion.invalid/protocol/v1/schemas.json";
export const REGISTRY_SCHEMA_ID = "https://databastion.invalid/protocol/v1/classifiers.schema.json";
export const SIGNALS_SCHEMA_ID = "https://databastion.invalid/protocol/v1/signals.schema.json";
export const TARGET_NOTES_SCHEMA_ID = "https://databastion.invalid/protocol/v1/target-notes.schema.json";

const rewrite = (value) => {
  if (Array.isArray(value)) return value.map(rewrite);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = k === "$ref" && typeof v === "string" ? v.replace("#/components/schemas/", "#/$defs/") : rewrite(v);
    }
    return out;
  }
  return value;
};

/** Ajv 2020 with the contract schemas (`${ROOT_ID}#/$defs/<Name>`) and the registry schemas. */
export function buildAjv(doc) {
  // strictRequired off: `oneOf: [{required: [a]}, {required: [b]}]` (exactly one of) is intended.
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  // OpenAPI annotations, not validation keywords. `oneOf` + `const` on `type` does the validation.
  ajv.addVocabulary(["discriminator", MAP_MARK, "x-databastion-normalized-name", "x-databastion-max-bytes"]);
  ajv.addSchema({ $id: ROOT_ID, $defs: rewrite(doc.components.schemas) });
  ajv.addSchema(JSON.parse(readFileSync(join(root, "classifiers.schema.json"), "utf8")));
  ajv.addSchema(JSON.parse(readFileSync(join(root, "signals.schema.json"), "utf8")));
  ajv.addSchema(JSON.parse(readFileSync(join(root, "target-notes.schema.json"), "utf8")));
  return ajv;
}
