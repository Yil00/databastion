// Generates the console's protocol artifacts from shared/protocol/openapi.yaml (invariant I6):
//
// - src/generated/protocol/types.gen.ts   TypeScript types (openapi-typescript)
// - src/generated/protocol/schemas.gen.json JSON Schema 2020-12 bundle used by the runtime validator
// - src/generated/protocol/classifiers.gen.ts classifier registry (shared/protocol/classifiers.json)
//   as a `const`: valid classifier ids per `classifiers_version`
// - src/generated/protocol/signals.gen.ts signal registry (shared/protocol/signals.json) as a `const`
// - src/generated/protocol/target-notes.gen.ts target-note registry (shared/protocol/target-notes.json)
//   as a `const`: the phrase catalog of `TargetNote` codes
//
// The bundle is built exactly like shared/protocol/scripts/contract-ajv.mjs: components.schemas
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
export const REGISTRY_URL = new URL("../../../shared/protocol/classifiers.json", import.meta.url);
export const REGISTRY_SCHEMA_URL = new URL("../../../shared/protocol/classifiers.schema.json", import.meta.url);
export const CLASSIFIERS_URL = new URL("../../src/generated/protocol/classifiers.gen.ts", import.meta.url);
export const SIGNALS_REGISTRY_URL = new URL("../../../shared/protocol/signals.json", import.meta.url);
export const SIGNALS_SCHEMA_URL = new URL("../../../shared/protocol/signals.schema.json", import.meta.url);
export const SIGNALS_URL = new URL("../../src/generated/protocol/signals.gen.ts", import.meta.url);
export const NOTES_REGISTRY_URL = new URL("../../../shared/protocol/target-notes.json", import.meta.url);
export const NOTES_SCHEMA_URL = new URL("../../../shared/protocol/target-notes.schema.json", import.meta.url);
export const NOTES_URL = new URL("../../src/generated/protocol/target-notes.gen.ts", import.meta.url);

/** Same $id as shared/protocol/scripts/contract-ajv.mjs. */
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
  classifiers: string;
  signals: string;
  targetNotes: string;
}

/** Patterns (from openapi.yaml) and bounds (from classifiers.schema.json) of the registry. */
export interface RegistryRules {
  version: RegExp;
  id: RegExp;
  /** `maxProperties`: versions in the registry. */
  maxVersions: number;
  /** `additionalProperties.maxItems`: ids per version. */
  maxIds: number;
}

/**
 * Renders the classifier registry as a TypeScript `const`. Fails closed on anything that is not a
 * `{ "<ClassifiersVersion>": ["<ClassifierId>", ...] }` map within the schema bounds, with unique
 * ids sorted ascending (the full check, JSON Schema and immutability lock included, is `npm test`
 * in shared/protocol/).
 */
export function renderClassifierRegistry(registry: unknown, rules: RegistryRules): string {
  if (registry === null || typeof registry !== "object" || Array.isArray(registry)) {
    throw new Error("classifiers.json must be an object");
  }
  const entries = Object.entries(registry as Record<string, unknown>);
  if (entries.length === 0) throw new Error("classifiers.json has no version");
  if (entries.length > rules.maxVersions) throw new Error("classifiers.json: too many versions");
  for (const [version, ids] of entries) {
    if (!rules.version.test(version)) throw new Error("classifiers.json: invalid classifiers_version key");
    if (!Array.isArray(ids) || ids.length === 0) throw new Error(`classifiers.json/${version}: expected a non-empty array`);
    if (ids.length > rules.maxIds) throw new Error(`classifiers.json/${version}: too many classifier ids`);
    ids.forEach((id: unknown, i: number) => {
      if (typeof id !== "string" || !rules.id.test(id)) throw new Error(`classifiers.json/${version}: invalid classifier id`);
      const previous: unknown = i > 0 ? ids[i - 1] : undefined;
      if (typeof previous === "string" && !(previous < id)) {
        throw new Error(`classifiers.json/${version}: ids must be unique and sorted ascending`);
      }
    });
  }
  return (
    "// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/classifiers.json.\n" +
    "// Regenerate with `pnpm protocol:generate` (from console/).\n\n" +
    "/** Valid classifier ids per classifier set version (contract classifier registry). */\n" +
    `export const CLASSIFIER_REGISTRY = ${JSON.stringify(registry, null, 2)} as const;\n\n` +
    "/** A registered `classifiers_version`. */\n" +
    "export type KnownClassifiersVersion = keyof typeof CLASSIFIER_REGISTRY;\n"
  );
}

/** Rules of an id registry (`signals.json`, `target-notes.json`), from openapi.yaml and its schema. */
export interface IdRegistryRules {
  /** Pattern of the ids (`Signal`, `TargetNoteCode`). */
  id: RegExp;
  /** `maxProperties`: ids in the registry. */
  maxIds: number;
  /** `additionalProperties.properties.description.maxLength`. */
  maxDescription: number;
  /** `additionalProperties.properties.engines.maxItems`. */
  maxEngines: number;
  /** Contract `Engine` values. */
  engines: readonly string[];
}

/** Free text of a registry description: no control, format, private-use or line / paragraph separator. */
const DESCRIPTION_TEXT = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]+$/u;

/**
 * Renders an append-only id registry (`{ "<id>": { "description": "...", "engines": [...] } }`) as a
 * TypeScript `const` named `name`. Fails closed on anything outside the registry schema: not an
 * object, no id or too many, an id that fails the contract pattern, ids not unique and sorted
 * ascending, an unknown key, a description that is empty, too long or holds control characters,
 * engines that are not unique contract `Engine` values within the bound. The full check (JSON
 * Schema, append-only comparison) is `npm test` in shared/protocol/ and the Protocol CI job.
 */
export function renderIdRegistry(registry: unknown, rules: IdRegistryRules, name: string, source: string, doc: string): string {
  if (registry === null || typeof registry !== "object" || Array.isArray(registry)) {
    throw new Error(`${source} must be an object`);
  }
  const entries = Object.entries(registry as Record<string, unknown>);
  if (entries.length === 0) throw new Error(`${source} has no entry`);
  if (entries.length > rules.maxIds) throw new Error(`${source}: too many entries`);
  const out: Record<string, { description: string; engines: string[] }> = {};
  entries.forEach(([id, entry], i) => {
    if (!rules.id.test(id)) throw new Error(`${source}: invalid id`);
    const previous = i > 0 ? entries[i - 1]?.[0] : undefined;
    if (previous !== undefined && !(previous < id)) throw new Error(`${source}: ids must be unique and sorted ascending`);
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${source}/${id}: expected an object`);
    const { description, engines, ...rest } = entry as Record<string, unknown>;
    if (Object.keys(rest).length > 0) throw new Error(`${source}/${id}: unknown key`);
    if (typeof description !== "string" || description.length > rules.maxDescription || !DESCRIPTION_TEXT.test(description)) {
      throw new Error(`${source}/${id}: invalid description`);
    }
    if (
      !Array.isArray(engines) ||
      engines.length === 0 ||
      engines.length > rules.maxEngines ||
      new Set(engines).size !== engines.length ||
      !engines.every((e: unknown) => typeof e === "string" && rules.engines.includes(e))
    ) {
      throw new Error(`${source}/${id}: invalid engines`);
    }
    out[id] = { description, engines: engines as string[] };
  });
  return (
    `// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/${source}.\n` +
    "// Regenerate with `pnpm protocol:generate` (from console/).\n\n" +
    `/** ${doc} */\n` +
    `export const ${name} = ${JSON.stringify(out, null, 2)} as const;\n`
  );
}

async function idRegistryRules(schemaUrl: URL, id: RegExp, engines: readonly string[]): Promise<IdRegistryRules> {
  const schema = JSON.parse(await readFile(schemaUrl, "utf8")) as {
    maxProperties?: unknown;
    additionalProperties?: { properties?: { description?: { maxLength?: unknown }; engines?: { maxItems?: unknown } } };
  };
  const maxIds = schema.maxProperties;
  const maxDescription = schema.additionalProperties?.properties?.description?.maxLength;
  const maxEngines = schema.additionalProperties?.properties?.engines?.maxItems;
  if (typeof maxIds !== "number" || typeof maxDescription !== "number" || typeof maxEngines !== "number") {
    throw new Error(`${fileURLToPath(schemaUrl)}: missing maxProperties / description.maxLength / engines.maxItems`);
  }
  return { id, maxIds, maxDescription, maxEngines, engines };
}

function schemaEnum(schemas: { [key: string]: Json }, name: string): string[] {
  const schema = schemas[name];
  const values = schema !== null && typeof schema === "object" && !Array.isArray(schema) ? schema.enum : undefined;
  if (!Array.isArray(values) || !values.every((v): v is string => typeof v === "string")) {
    throw new Error(`openapi.yaml: ${name} has no string enum`);
  }
  return values;
}

function schemaPattern(schemas: { [key: string]: Json }, name: string): RegExp {
  const schema = schemas[name];
  const pattern =
    schema !== null && typeof schema === "object" && !Array.isArray(schema) ? schema.pattern : undefined;
  if (typeof pattern !== "string") throw new Error(`openapi.yaml: ${name} has no pattern`);
  return new RegExp(pattern, "u");
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

  const registry: unknown = JSON.parse(await readFile(REGISTRY_URL, "utf8"));
  const registrySchema = JSON.parse(await readFile(REGISTRY_SCHEMA_URL, "utf8")) as {
    maxProperties?: unknown;
    additionalProperties?: { maxItems?: unknown };
  };
  const maxVersions = registrySchema.maxProperties;
  const maxIds = registrySchema.additionalProperties?.maxItems;
  if (typeof maxVersions !== "number" || typeof maxIds !== "number") {
    throw new Error("classifiers.schema.json: missing maxProperties / additionalProperties.maxItems");
  }
  const classifiers = renderClassifierRegistry(registry, {
    version: schemaPattern(schemas, "ClassifiersVersion"),
    id: schemaPattern(schemas, "ClassifierId"),
    maxVersions,
    maxIds,
  });

  const engines = schemaEnum(schemas, "Engine");
  const signals = renderIdRegistry(
    JSON.parse(await readFile(SIGNALS_REGISTRY_URL, "utf8")),
    await idRegistryRules(SIGNALS_SCHEMA_URL, schemaPattern(schemas, "Signal"), engines),
    "SIGNAL_REGISTRY",
    "signals.json",
    "Registered access-event signal ids (contract signal registry), with their meaning and engines.",
  );
  const targetNotes = renderIdRegistry(
    JSON.parse(await readFile(NOTES_REGISTRY_URL, "utf8")),
    await idRegistryRules(NOTES_SCHEMA_URL, schemaPattern(schemas, "TargetNoteCode"), engines),
    "TARGET_NOTE_REGISTRY",
    "target-notes.json",
    "Registered `TargetNote` codes: the phrase catalog (`{count}` and `{labels}` placeholders) and engines.",
  );

  const ast = await openapiTS(yamlText, { silent: true });
  return {
    types: BANNER + astToString(ast),
    schemas: `${JSON.stringify(bundle, null, 2)}\n`,
    classifiers,
    signals,
    targetNotes,
  };
}

async function main(): Promise<void> {
  const artifacts = await renderArtifacts();
  const files: [URL, string][] = [
    [TYPES_URL, artifacts.types],
    [SCHEMAS_URL, artifacts.schemas],
    [CLASSIFIERS_URL, artifacts.classifiers],
    [SIGNALS_URL, artifacts.signals],
    [NOTES_URL, artifacts.targetNotes],
  ];
  for (const [url, content] of files) {
    await writeFile(url, content);
    process.stdout.write(`wrote ${fileURLToPath(url)}\n`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main();
}
