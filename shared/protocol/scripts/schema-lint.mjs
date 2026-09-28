// Bounds / closure lint of the protocol schemas (invariant I2).
//
// Rules, for every schema reachable from components.schemas and from parameters:
// - `true` and `{}` schemas are forbidden, except directly under not / if / then / else;
// - a *value* schema (property, item, top-level schema, branch of a composition without its own
//   `type`) has `type`, `$ref`, `enum`, `const` or a composition (`oneOf` / `anyOf` / `allOf`);
// - every object is closed (`additionalProperties: false`), except a numeric map explicitly marked
//   `x-databastion-numeric-map: true` (numeric values, `propertyNames.pattern`, `maxProperties`);
// - every string has `maxLength` (or `enum` / `const`), every array `maxItems`, every number
//   `minimum` and `maximum`. `type` arrays (e.g. `[string, "null"]`) are checked for each member.
//
// A *fragment* is a subschema that only adds conditions to its parent: under not / if / then / else,
// or a branch of a composition whose parent has its own `type`. Fragments are not required to be
// closed, typed or bounded, but cannot be `true` / `{}` (except under not / if / then / else) and cannot open
// the parent (no `additionalProperties` other than `false`).
// Anywhere: no `patternProperties`, no `unevaluatedProperties` other than `false`, and no
// `propertyNames` outside the numeric map.

export const MAP_MARK = "x-databastion-numeric-map";
const CONDITIONAL = new Set(["not", "if", "then", "else"]);
const COMPOSITION = ["oneOf", "anyOf", "allOf"];

function typesOf(node) {
  if (node.type === undefined) return [];
  return Array.isArray(node.type) ? node.type : [node.type];
}

function lintNode(node, path, { fragment, via }, fail) {
  const underConditional = CONDITIONAL.has(via);
  if (node === false) return;
  if (node === true) {
    if (!underConditional) fail(`${path}: boolean \`true\` schema accepts anything`);
    return;
  }
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    fail(`${path}: not a schema`);
    return;
  }
  const keys = Object.keys(node).filter((k) => !["description", "title", "default", "examples", "deprecated"].includes(k));
  if (keys.length === 0) {
    if (!underConditional) fail(`${path}: empty schema \`{}\` accepts anything`);
    return;
  }

  const types = typesOf(node);
  const hasRef = node.$ref !== undefined;
  const isEnum = node.enum !== undefined || node.const !== undefined;
  const composition = COMPOSITION.some((k) => node[k] !== undefined);
  const isObject = types.includes("object") || (!fragment && !hasRef && node.properties !== undefined);

  if (!fragment && !hasRef && !isEnum && !composition && types.length === 0) {
    fail(`${path}: value schema without type, $ref, enum or const`);
  }

  // Other ways of opening an object: pattern-keyed properties, unevaluated properties, and
  // `propertyNames` (only meaningful on an open map). Allowed only on the numeric map (and not even
  // there for patternProperties / unevaluatedProperties).
  if (node.patternProperties !== undefined) {
    fail(`${path}: patternProperties is forbidden (open keys); use closed properties or the numeric map`);
  }
  if (node.unevaluatedProperties !== undefined && node.unevaluatedProperties !== false) {
    fail(`${path}: unevaluatedProperties other than false is forbidden`);
  }
  if (node.propertyNames !== undefined && node[MAP_MARK] !== true) {
    fail(`${path}: propertyNames outside a ${MAP_MARK} object`);
  }

  if (fragment) {
    if (node.additionalProperties !== undefined && node.additionalProperties !== false) {
      fail(`${path}: a fragment cannot open its parent object`);
    }
  } else if (isObject) {
    if (node[MAP_MARK] === true) {
      const ap = node.additionalProperties;
      const apTypes = ap && typeof ap === "object" ? typesOf(ap) : [];
      const numeric = apTypes.length > 0 && apTypes.every((t) => t === "number" || t === "integer");
      if (!numeric || node.propertyNames?.pattern === undefined || node.maxProperties === undefined) {
        fail(`${path}: numeric map needs numeric additionalProperties, propertyNames.pattern and maxProperties`);
      }
    } else if (node.additionalProperties !== false) {
      fail(`${path}: object schema without "additionalProperties: false" (invariant I2)`);
    }
  }
  // Bounds are checked on value schemas; a fragment is bounded by its (typed) parent.
  if (!fragment && types.includes("string") && !isEnum && node.maxLength === undefined) {
    fail(`${path}: unbounded string (maxLength, enum or const required)`);
  }
  if (!fragment && types.includes("array") && node.maxItems === undefined) {
    fail(`${path}: unbounded array (maxItems required)`);
  }
  if (!fragment && (types.includes("integer") || types.includes("number")) && !isEnum && (node.minimum === undefined || node.maximum === undefined)) {
    fail(`${path}: unbounded number (minimum and maximum required)`);
  }

  for (const [key, value] of Object.entries(node)) {
    if (key === "properties" || key === "patternProperties" || key === "$defs") {
      for (const [name, sub] of Object.entries(value)) {
        // Inside a fragment, `properties` only constrains existing (already typed) properties.
        lintNode(sub, `${path}/${key}/${name}`, { fragment: fragment && key === "properties", via: key }, fail);
      }
    } else if (["items", "propertyNames", "contains"].includes(key)) {
      lintNode(value, `${path}/${key}`, { fragment: false, via: key }, fail);
    } else if (key === "additionalProperties" && value !== false) {
      lintNode(value, `${path}/${key}`, { fragment: false, via: key }, fail);
    } else if (CONDITIONAL.has(key)) {
      lintNode(value, `${path}/${key}`, { fragment: true, via: key }, fail);
    } else if (COMPOSITION.includes(key) || key === "prefixItems") {
      const branchFragment = key !== "prefixItems" && types.length > 0;
      value.forEach((sub, i) => lintNode(sub, `${path}/${key}/${i}`, { fragment: branchFragment, via: key }, fail));
    }
  }
}

/** Returns the list of problems found in an OpenAPI document (empty = OK). */
export function lintDocument(doc) {
  const problems = [];
  const fail = (msg) => problems.push(msg);
  const top = { fragment: false, via: "root" };
  for (const [name, schema] of Object.entries(doc.components?.schemas ?? {})) {
    lintNode(schema, `#/components/schemas/${name}`, top, fail);
  }
  for (const [name, param] of Object.entries(doc.components?.parameters ?? {})) {
    lintNode(param.schema, `#/components/parameters/${name}/schema`, top, fail);
  }
  for (const [p, item] of Object.entries(doc.paths ?? {})) {
    for (const [method, op] of Object.entries(item)) {
      (op.parameters ?? []).forEach((param, i) => {
        if (param.schema) lintNode(param.schema, `#/paths/${p}/${method}/parameters/${i}/schema`, top, fail);
      });
    }
  }
  return problems;
}
