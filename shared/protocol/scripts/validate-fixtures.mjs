#!/usr/bin/env node
// Validates the protocol contract and its fixtures.
//
// 1. Bounds lint (scripts/schema-lint.mjs): every object schema of openapi.yaml is closed
//    (`additionalProperties: false`, invariant I2), every string / array / number is bounded, no
//    `true` / `{}` schema. The only allowed open object is a numeric map marked
//    `x-databastion-numeric-map: true`.
// 2. Every fixture in fixtures/valid/ validates against its schema; every fixture in
//    fixtures/invalid/ is rejected, with the JSON Schema keyword listed in
//    fixtures/invalid-expectations.json (so that it fails for the intended reason).
// 3. Coverage: every request / response body schema has at least one valid and one invalid fixture.
//
// Fixture file name: `<SchemaName>.<case>.json`, where SchemaName is a key of components.schemas.
// Usage: node scripts/validate-fixtures.mjs   (from shared/protocol/, or any directory)

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";
import { MAP_MARK, lintDocument } from "./schema-lint.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const doc = parse(readFileSync(join(root, "openapi.yaml"), "utf8"));
const schemas = doc.components.schemas;
const problems = [];
const fail = (msg) => problems.push(msg);

// ---------------------------------------------------------------- 1. bounds lint
for (const problem of lintDocument(doc)) fail(problem);

// ------------------------------------------------ 2. build a JSON Schema 2020-12 document
// OpenAPI 3.1 schemas are JSON Schema 2020-12: move components.schemas to $defs and rewrite refs.
const ROOT_ID = "https://databastion.invalid/protocol/v1/schemas.json";
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
const jsonSchema = { $id: ROOT_ID, $defs: rewrite(schemas) };

// strictRequired off: `oneOf: [{required: [a]}, {required: [b]}]` (exactly one of) is intended.
const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
addFormats(ajv);
// OpenAPI annotations, not validation keywords. `oneOf` + `const` on `type` does the validation.
ajv.addVocabulary(["discriminator", MAP_MARK, "x-databastion-normalized-name", "x-databastion-max-bytes"]);
ajv.addSchema(jsonSchema);

const validatorFor = (name) => {
  if (!schemas[name]) return undefined;
  return ajv.getSchema(`${ROOT_ID}#/$defs/${name}`);
};

// -------------------------------------------------------------------- 3. fixtures
const fixturesDir = join(root, "fixtures");
const expectations = JSON.parse(readFileSync(join(fixturesDir, "invalid-expectations.json"), "utf8"));
const NAME = /^([A-Z][A-Za-z0-9]*)\.([a-z0-9][a-z0-9-]*)\.json$/;
const covered = { valid: new Set(), invalid: new Set() };
let checked = 0;

for (const kind of ["valid", "invalid"]) {
  for (const file of readdirSync(join(fixturesDir, kind)).sort()) {
    const m = NAME.exec(file);
    if (!m) {
      fail(`fixtures/${kind}/${file}: name must be <SchemaName>.<case>.json`);
      continue;
    }
    const validate = validatorFor(m[1]);
    if (!validate) {
      fail(`fixtures/${kind}/${file}: unknown schema "${m[1]}"`);
      continue;
    }
    let data;
    try {
      data = JSON.parse(readFileSync(join(fixturesDir, kind, file), "utf8"));
    } catch (e) {
      fail(`fixtures/${kind}/${file}: invalid JSON (${e.message})`);
      continue;
    }
    covered[kind].add(m[1]);
    checked++;
    const maxBytes = schemas[m[1]]["x-databastion-max-bytes"];
    if (kind === "valid" && maxBytes !== undefined && Buffer.byteLength(JSON.stringify(data)) > maxBytes) {
      fail(`fixtures/valid/${file}: larger than x-databastion-max-bytes (${maxBytes})`);
    }
    const ok = validate(data);
    const errors = validate.errors ?? [];
    if (kind === "valid" && !ok) {
      fail(`fixtures/valid/${file}: rejected\n${ajv.errorsText(errors, { separator: "\n    ", dataVar: "" })}`);
    }
    if (kind === "invalid") {
      const expected = expectations[file];
      if (ok) {
        fail(`fixtures/invalid/${file}: accepted, but must be rejected`);
      } else if (expected === undefined) {
        fail(`fixtures/invalid/${file}: missing from fixtures/invalid-expectations.json`);
      } else if (!errors.some((e) => e.keyword === expected)) {
        const got = [...new Set(errors.map((e) => e.keyword))].join(", ");
        fail(`fixtures/invalid/${file}: rejected for [${got}], expected "${expected}"`);
      }
    }
  }
}
for (const file of Object.keys(expectations)) {
  if (!readdirSync(join(fixturesDir, "invalid")).includes(file)) {
    fail(`fixtures/invalid-expectations.json: "${file}" has no fixture file`);
  }
}

// ------------------------------------------------------------------- 4. coverage
const bodySchemas = new Set();
const refName = (ref) => ref?.replace("#/components/schemas/", "");
const collect = (content) => {
  for (const media of Object.values(content ?? {})) {
    if (media.schema?.$ref) bodySchemas.add(refName(media.schema.$ref));
  }
};
for (const item of Object.values(doc.paths)) {
  for (const op of Object.values(item)) {
    collect(op.requestBody?.content);
    for (const resp of Object.values(op.responses ?? {})) {
      const r = resp.$ref ? doc.components.responses[resp.$ref.split("/").pop()] : resp;
      collect(r.content);
    }
  }
}
for (const name of [...bodySchemas].sort()) {
  for (const kind of ["valid", "invalid"]) {
    if (!covered[kind].has(name)) fail(`coverage: body schema "${name}" has no ${kind} fixture`);
  }
}

// ---------------------------------------------------------------------- report
if (problems.length) {
  console.error(`FAILED: ${problems.length} problem(s)\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log(
  `OK: ${Object.keys(schemas).length} schemas bound-checked, ${checked} fixtures ` +
    `(${covered.valid.size} schemas with valid, ${covered.invalid.size} with invalid cases), ` +
    `${bodySchemas.size} body schemas covered.`,
);
