import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";

import bundle from "@/generated/protocol/schemas.gen.json";
import type { components } from "@/generated/protocol/types.gen";

/**
 * Runtime validator for agent API bodies (invariant I6, security review L2).
 *
 * The schemas come from src/generated/protocol/schemas.gen.json, generated from
 * shared/protocol/openapi.yaml by `pnpm protocol:generate`. Ajv settings are those of
 * shared/protocol/scripts/validate-fixtures.mjs, except `allErrors` (off: the first error is enough
 * to reject, and it bounds the work done on hostile input). No `removeAdditional`, no
 * `coerceTypes`, no `useDefaults`: the body is never modified, unknown fields are rejected.
 *
 * Error details never echo the submitted body: a pointer segment is kept only when it is an index
 * of an actual array or a property name declared by the contract, anything else becomes `*`.
 * Only the schema keyword is reported (no message, no params, no value).
 */

export type Schemas = components["schemas"];
export type SchemaName = keyof Schemas;

export interface ValidationDetail {
  /** JSON pointer into the body, built only from contract property names and array indices. */
  pointer: string;
  /** JSON Schema keyword that failed (e.g. `required`, `additionalProperties`, `maxLength`). */
  keyword: string;
}

/** Result of `validateSchema` / `checkSemantics`. For `validateSchema`, `ok: true` is schema-only. */
export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; details: ValidationDetail[] };

export const MAX_VALIDATION_DETAILS = 20;

const ROOT_ID = bundle.$id;
const defs: Record<string, unknown> = bundle.$defs;

// OpenAPI annotations, not validation keywords (same list as validate-fixtures.mjs).
const ANNOTATIONS = [
  "discriminator",
  "x-databastion-numeric-map",
  "x-databastion-normalized-name",
  "x-databastion-max-bytes",
];

function collectPropertyNames(node: unknown, into: Set<string>): Set<string> {
  if (Array.isArray(node)) {
    for (const item of node) collectPropertyNames(item, into);
  } else if (node !== null && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (key === "properties" && value !== null && typeof value === "object") {
        for (const name of Object.keys(value)) into.add(name);
      }
      collectPropertyNames(value, into);
    }
  }
  return into;
}

/** Every property name declared anywhere in the contract. */
const KNOWN_PROPERTIES: ReadonlySet<string> = collectPropertyNames(defs, new Set());

const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: false });
addFormats(ajv);
ajv.addVocabulary(ANNOTATIONS);
ajv.addSchema(bundle);

// Compile every schema once, at module load.
const validators = new Map<string, ValidateFunction>();
for (const name of Object.keys(defs)) {
  const fn = ajv.getSchema(`${ROOT_ID}#/$defs/${name}`);
  if (!fn) throw new Error(`protocol schema ${name} failed to compile`);
  validators.set(name, fn);
}

// ErrorDetail.pointer (contract): `^(/([a-z][a-z0-9_]{0,63}|[0-9]{1,6}))*$`, maxLength 256.
const INDEX = /^(0|[1-9][0-9]{0,5})$/;
const NAME_SEGMENT = /^[a-z][a-z0-9_]{0,63}$/;
export const MAX_POINTER_LENGTH = 256;

function unescapeSegment(segment: string): string {
  return segment.replace(/~1/g, "/").replace(/~0/g, "~");
}

/**
 * Rebuilds Ajv's `instancePath` without leaking data: walks the body along the path and keeps a
 * segment only if it indexes a real array or is a contract property name of a real object. The
 * pointer is truncated at the first segment that cannot be disclosed (e.g. a key of the open
 * metrics map: `/metrics/<key>` -> `/metrics`) and at 256 characters, so it always conforms to
 * the contract's `ErrorDetail.pointer`.
 */
function safePointer(instancePath: string, body: unknown): string {
  if (instancePath === "") return "";
  let current: unknown = body;
  let pointer = "";
  for (const raw of instancePath.slice(1).split("/")) {
    const segment = unescapeSegment(raw);
    let next: unknown;
    if (Array.isArray(current) && INDEX.test(segment)) {
      next = current[Number(segment)];
    } else if (
      current !== null &&
      typeof current === "object" &&
      !Array.isArray(current) &&
      KNOWN_PROPERTIES.has(segment) &&
      NAME_SEGMENT.test(segment)
    ) {
      next = Object.hasOwn(current, segment)
        ? (current as Record<string, unknown>)[segment]
        : undefined;
    } else {
      break;
    }
    if (pointer.length + 1 + segment.length > MAX_POINTER_LENGTH) break;
    pointer += `/${segment}`;
    current = next;
  }
  return pointer;
}

// ErrorDetail.keyword (contract): `^[A-Za-z]+$`, maxLength 32. Ajv reports a `false` subschema
// as "false schema".
const KEYWORD = /^[A-Za-z]{1,32}$/;

function safeKeyword(keyword: string): string {
  if (keyword === "false schema") return "falseSchema";
  return KEYWORD.test(keyword) ? keyword : "invalid";
}

function toDetails(errors: ErrorObject[] | null | undefined, body: unknown): ValidationDetail[] {
  const details: ValidationDetail[] = [];
  for (const error of errors ?? []) {
    if (details.length >= MAX_VALIDATION_DETAILS) break;
    details.push({ pointer: safePointer(error.instancePath, body), keyword: safeKeyword(error.keyword) });
  }
  if (details.length === 0) details.push({ pointer: "", keyword: "invalid" });
  return details;
}

/**
 * Validates `body` (already JSON-parsed) against `components.schemas[name]` of the contract.
 *
 * `ok: true` means **schema-valid only**. Rules that JSON Schema cannot express are checked by
 * `checkSemantics(name, value)`, which every agent API endpoint must call on the validated value
 * before using it.
 */
export function validateSchema<K extends SchemaName>(
  name: K,
  body: unknown,
): ValidationResult<Schemas[K]> {
  const fn = validators.get(name);
  if (!fn) throw new Error(`unknown protocol schema ${String(name)}`);
  if (fn(body)) return { ok: true, value: body as Schemas[K] };
  return { ok: false, details: toDetails(fn.errors, body) };
}

function maxBytesOf(name: string): number | undefined {
  const schema = defs[name];
  if (schema === null || typeof schema !== "object") return undefined;
  const max = (schema as Record<string, unknown>)["x-databastion-max-bytes"];
  return typeof max === "number" ? max : undefined;
}

const MASK_COUNTED = /[\p{L}\p{N}*]/u;

/**
 * Console rule on `MaskedSample` (see its description in the contract): at least 50 % of the
 * letters, digits and `*` must be `*` (spaces and punctuation ignored).
 */
export function isSufficientlyMasked(sample: string): boolean {
  let counted = 0;
  let stars = 0;
  for (const ch of sample) {
    if (!MASK_COUNTED.test(ch)) continue;
    counted++;
    if (ch === "*") stars++;
  }
  return counted > 0 && stars * 2 >= counted;
}

const encoder = new TextEncoder();

/**
 * Second pass, after `validateSchema` returned `ok: true`: the contract rules that JSON Schema
 * cannot express.
 * - `x-databastion-max-bytes`: serialized size of the value (keyword `maxBytes`, pointer `""`).
 * - `MaskedSample`: at least 50 % `*` (keyword `maskRatio`). `MaskedSample` is only used in
 *   `FindingsBatch.findings[].masked_samples[]`; a test fails if the contract adds another use.
 * Reserved metric names (`HeartbeatRequest.metrics`) are not rejected: the contract says they are
 * ignored, which is the job of the `/metrics` exporter.
 */
export function checkSemantics<K extends SchemaName>(
  name: K,
  value: Schemas[K],
): ValidationResult<Schemas[K]> {
  const details: ValidationDetail[] = [];
  const maxBytes = maxBytesOf(name);
  if (maxBytes !== undefined && encoder.encode(JSON.stringify(value)).byteLength > maxBytes) {
    details.push({ pointer: "", keyword: "maxBytes" });
  }
  if (name === "FindingsBatch") {
    const batch = value as Schemas["FindingsBatch"];
    batch.findings.forEach((finding, i) => {
      (finding.masked_samples ?? []).forEach((sample, j) => {
        if (details.length < MAX_VALIDATION_DETAILS && !isSufficientlyMasked(sample)) {
          details.push({ pointer: `/findings/${i}/masked_samples/${j}`, keyword: "maskRatio" });
        }
      });
    });
  }
  return details.length === 0 ? { ok: true, value } : { ok: false, details };
}

/** Names of every schema of the contract (for tests and diagnostics). */
export const schemaNames: readonly string[] = Object.keys(defs);

// Request bodies received by the agent API (one per endpoint with a body).
export const validateEnrollRequest = (body: unknown) => validateSchema("EnrollRequest", body);
export const validateHeartbeatRequest = (body: unknown) => validateSchema("HeartbeatRequest", body);
export const validateJobStatusUpdate = (body: unknown) => validateSchema("JobStatusUpdate", body);
export const validateFindingsBatch = (body: unknown) => validateSchema("FindingsBatch", body);
export const validateEventsBatch = (body: unknown) => validateSchema("EventsBatch", body);
export const validateRotateRequest = (body: unknown) => validateSchema("RotateRequest", body);
