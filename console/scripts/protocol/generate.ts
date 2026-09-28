// Generates the console's protocol artifacts from shared/protocol/openapi.yaml (invariant I6):
//
// - src/generated/protocol/types.gen.ts   TypeScript types (openapi-typescript)
// - src/generated/protocol/schemas.gen.json JSON Schema 2020-12 bundle used by the runtime validator
//
// The bundle is built exactly like shared/protocol/scripts/validate-fixtures.mjs: components.schemas
// moved to $defs, `#/components/schemas/` refs rewritten to `#/$defs/`, nothing else. The runtime
// therefore never reads YAML nor any file outside the build.
//
// Usage: pnpm protocol:generate      (write the files)
// The drift test (src/lib/protocol/generated.test.ts) calls `renderArtifacts()` and compares.

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";
import { parse } from "yaml";

export const OPENAPI_URL = new URL("../../../shared/protocol/openapi.yaml", import.meta.url);
export const TYPES_URL = new URL("../../src/generated/protocol/types.gen.ts", import.meta.url);
export const SCHEMAS_URL = new URL("../../src/generated/protocol/schemas.gen.json", import.meta.url);

/** Same $id as validate-fixtures.mjs. */
export const SCHEMA_ROOT_ID = "https://databastion.invalid/protocol/v1/schemas.json";

const BANNER =
  "// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/openapi.yaml.\n" +
  "// Regenerate with `pnpm protocol:generate` (from console/).\n\n";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function rewriteRefs(value: Json): Json {
  if (Array.isArray(value)) return value.map(rewriteRefs);
  if (value !== null && typeof value === "object") {
    const out: { [key: string]: Json } = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] =
        k === "$ref" && typeof v === "string"
          ? v.replace("#/components/schemas/", "#/$defs/")
          : rewriteRefs(v);
    }
    return out;
  }
  return value;
}

/**
 * Rejects any `$ref` that is not local to the document (`#/...`): no remote or file ref may be
 * resolved at generation time, so the generator never touches the network nor other files.
 */
export function assertLocalRefs(value: unknown, path = "#"): void {
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertLocalRefs(item, `${path}/${i}`));
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (k === "$ref" && (typeof v !== "string" || !v.startsWith("#/"))) {
        throw new Error(`non-local $ref at ${path}: only "#/..." refs are allowed`);
      }
      assertLocalRefs(v, `${path}/${k}`);
    }
  }
}

export interface Artifacts {
  types: string;
  schemas: string;
}

export async function renderArtifacts(): Promise<Artifacts> {
  const yamlText = await readFile(OPENAPI_URL, "utf8");
  const parsed: unknown = parse(yamlText);
  assertLocalRefs(parsed);
  const doc = parsed as { components?: { schemas?: { [key: string]: Json } } };
  const schemas = doc.components?.schemas;
  if (!schemas || Object.keys(schemas).length === 0) {
    throw new Error("openapi.yaml has no components.schemas");
  }
  const bundle = {
    $comment:
      "GENERATED FILE, DO NOT EDIT. Source: shared/protocol/openapi.yaml. Regenerate with `pnpm protocol:generate`.",
    $id: SCHEMA_ROOT_ID,
    $defs: rewriteRefs(schemas),
  };

  const ast = await openapiTS(yamlText, { silent: true });
  return {
    types: BANNER + astToString(ast),
    schemas: `${JSON.stringify(bundle, null, 2)}\n`,
  };
}

async function main(): Promise<void> {
  const { types, schemas } = await renderArtifacts();
  await writeFile(TYPES_URL, types);
  await writeFile(SCHEMAS_URL, schemas);
  process.stdout.write(
    `wrote ${fileURLToPath(TYPES_URL)}\nwrote ${fileURLToPath(SCHEMAS_URL)}\n`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main();
}
