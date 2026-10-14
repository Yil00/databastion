// Drift test: `AccessEvent` restates `ObjectRef` inline in its `source` conditional (`then`:
// `object` as a `KeyPattern` for the redis_* sources, `else`: `object` as an `Identifier`), because
// the schema lint and Ajv's strict mode do not allow narrowing a `$ref`'d object in place. Both
// inline shapes must keep the properties, `required` and `additionalProperties` of `ObjectRef`, and
// differ only in the schema of `object`. Run with `node --test scripts/inline-objectref.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const original = parse(readFileSync(join(root, "openapi.yaml"), "utf8"));
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });

/** The inline `ObjectRef` shapes of `AccessEvent`, as [branch, schema] pairs. */
function inlineShapes(schemas) {
  const shapes = [];
  for (const cond of schemas.AccessEvent.allOf ?? []) {
    for (const branch of ["then", "else"]) {
      const items = cond[branch]?.properties?.objects?.items;
      if (items) shapes.push([branch, items]);
    }
  }
  return shapes;
}

/** Problems of the inline shapes against `ObjectRef` (empty = in step). */
export function objectRefDrift(doc) {
  const schemas = doc.components.schemas;
  const base = schemas.ObjectRef;
  const problems = [];
  const shapes = inlineShapes(schemas);
  if (shapes.length !== 2) problems.push(`expected 2 inline ObjectRef shapes, found ${shapes.length}`);
  const expectedObject = { then: ref("KeyPattern"), else: ref("Identifier") };
  for (const [branch, shape] of shapes) {
    const where = `AccessEvent ${branch}`;
    if (shape.type !== base.type) problems.push(`${where}: type ${shape.type} != ${base.type}`);
    if (shape.additionalProperties !== base.additionalProperties) {
      problems.push(`${where}: additionalProperties differs from ObjectRef`);
    }
    const req = (s) => JSON.stringify([...(s.required ?? [])].sort());
    if (req(shape) !== req(base)) problems.push(`${where}: required ${req(shape)} != ${req(base)}`);
    const keys = (s) => JSON.stringify(Object.keys(s.properties ?? {}).sort());
    if (keys(shape) !== keys(base)) problems.push(`${where}: properties ${keys(shape)} != ${keys(base)}`);
    for (const [name, sub] of Object.entries(base.properties ?? {})) {
      const want = name === "object" ? expectedObject[branch] : sub;
      if (JSON.stringify(shape.properties?.[name]) !== JSON.stringify(want)) {
        problems.push(`${where}: property ${name} differs`);
      }
    }
  }
  return problems;
}

test("the inline ObjectRef shapes of AccessEvent are in step with ObjectRef", () => {
  assert.deepEqual(objectRefDrift(original), []);
});

const mutations = {
  "ObjectRef gains a property": (s) => { s.ObjectRef.properties.extra = ref("Identifier"); },
  "ObjectRef gains a required property": (s) => { s.ObjectRef.required.push("schema"); },
  "ObjectRef opened": (s) => { s.ObjectRef.additionalProperties = true; },
  "ObjectRef.database retyped": (s) => { s.ObjectRef.properties.database = ref("KeyPattern"); },
  "inline then loses schema": (s) => {
    const items = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects).then.properties.objects.items;
    delete items.properties.schema;
  },
  "inline else object widened": (s) => {
    const items = s.AccessEvent.allOf.find((c) => c.else?.properties?.objects).else.properties.objects.items;
    items.properties.object = ref("ObjectName");
  },
};

for (const [name, fn] of Object.entries(mutations)) {
  test(`drift is caught: ${name}`, () => {
    const doc = structuredClone(original);
    fn(doc.components.schemas);
    assert.notDeepEqual(objectRefDrift(doc), []);
  });
}
