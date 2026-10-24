// Drift test: `AccessEvent` restates `ObjectRef` inline three times, because the schema lint and
// Ajv's strict mode do not allow narrowing a `$ref`'d object in place: in its `source` conditional
// (`then`: `object` as a `KeyPattern` for the redis_* sources, `else`: `object` as an `Identifier`),
// and in the `contains` item of the ADR-0053 rule that a flagged event names a `*` (`object` as
// `const: "*"`). Every inline shape must keep the properties, `required` and `additionalProperties`
// of `ObjectRef`, and differ only in the schema of `object`: a property of `ObjectRef` missing from
// the `contains` item would make a flagged event carrying it match no item (ADR-0056 decision 1
// item 2). Run with `node --test scripts/inline-objectref.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const original = parse(readFileSync(join(root, "openapi.yaml"), "utf8"));
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });

/**
 * The inline `ObjectRef` shapes of `AccessEvent`, as [kind, schema] pairs: `then` and `else` for the
 * `items` of the `source` conditional, `contains` for the `contains` item of the overflow rule.
 */
function inlineShapes(schemas) {
  const shapes = [];
  for (const cond of schemas.AccessEvent.allOf ?? []) {
    for (const branch of ["then", "else"]) {
      const objects = cond[branch]?.properties?.objects;
      if (objects?.items) shapes.push([branch, objects.items]);
      if (objects?.contains) shapes.push(["contains", objects.contains]);
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
  const kinds = JSON.stringify(shapes.map(([kind]) => kind).sort());
  if (kinds !== JSON.stringify(["contains", "else", "then"])) {
    problems.push(`expected the inline ObjectRef shapes [contains, else, then], found ${kinds}`);
  }
  const expectedObject = { then: ref("KeyPattern"), else: ref("Identifier"), contains: { const: "*" } };
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
  "inline contains loses altered (ADR-0056)": (s) => {
    const item = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.contains).then.properties.objects.contains;
    delete item.properties.altered;
  },
  "inline contains altered narrowed": (s) => {
    const item = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.contains).then.properties.objects.contains;
    item.properties.altered = { ...item.properties.altered, maxItems: 1 };
  },
  "inline contains object no longer the literal *": (s) => {
    const item = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.contains).then.properties.objects.contains;
    item.properties.object = ref("Identifier");
  },
  "inline contains opened": (s) => {
    const item = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.contains).then.properties.objects.contains;
    item.additionalProperties = true;
  },
  "inline contains removed": (s) => {
    const cond = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.contains);
    delete cond.then.properties.objects.contains;
  },
  "inline then loses altered (ADR-0056)": (s) => {
    const items = s.AccessEvent.allOf.find((c) => c.then?.properties?.objects?.items).then.properties.objects.items;
    delete items.properties.altered;
  },
  "ObjectRef.altered widened to the Location parts": (s) => {
    s.ObjectRef.properties.altered = { ...s.ObjectRef.properties.altered, items: ref("LocationPart") };
  },
};

for (const [name, fn] of Object.entries(mutations)) {
  test(`drift is caught: ${name}`, () => {
    const doc = structuredClone(original);
    fn(doc.components.schemas);
    assert.notDeepEqual(objectRefDrift(doc), []);
  });
}
