import type { components } from "@/generated/protocol/types.gen";

import {
  exceptionGlobOptions,
  foldName,
  isPlainObject,
  trimTrailingSpaces,
  type GlobOptions,
  type NamePart,
  type PartGlobOptions,
} from "./policy-common";

/**
 * Name case semantics reported by the agent (ADR-0055, contract `TargetStatus.name_case`): how a
 * MySQL / MariaDB or SQL Server target compares names that differ only by case, and how location
 * exceptions compare them on that target (decision 6). Pure functions (worker, web, UI, tests).
 *
 * - `sensitive` and `unknown` compare with case (decision 5: `unknown` is the stricter reading);
 *   only `insensitive` compares without. Any other value read back (a hostile or corrupt stored
 *   value) is read as `unknown`.
 * - A missing `name_case` (agent built before ADR-0055, or a console that did not list the token)
 *   keeps today's rule (ADR-0054: these engines compare without case), whatever the agent's
 *   version (#301 review I-4).
 * - Applied only when the item's engine is `mysql`, `mariadb` or `sqlserver`; on any other engine
 *   the value is ignored, whatever it is (L6).
 * - A `name_case` cover is a subset of today's cover: the rule only adds `matchCase`, which is the
 *   conjunction of ADR-0054 decision 1 (a case-sensitive match is also a case-insensitive one), and
 *   never changes the trailing-space rule (N1).
 */

export type NameCase = components["schemas"]["NameCase"];
export type TargetNameCase = components["schemas"]["TargetNameCase"];

/** Engines whose targets may report `name_case` (ADR-0055 decision 1, checked by the schema). */
export const NAME_CASE_ENGINES: readonly string[] = ["mysql", "mariadb", "sqlserver"];

/** Contract bound of `except` entries (`maxItems`). */
export const MAX_EXCEPT_ENTRIES = 32;
/** Agent-side bound of the serialized `except` (contract text, ADR-0055 decision 4, L4): 8 KiB. */
export const MAX_EXCEPT_BYTES = 8192;

/** A canonical `name_case`: `except` sorted by name (UTF-8 byte order), one entry per name. */
export interface NameCaseRule {
  databases: NameCase;
  objects: NameCase;
  except?: { database: string; objects: NameCase }[];
}

const RANK: Record<NameCase, number> = { insensitive: 0, unknown: 1, sensitive: 2 };

/** The stricter of two values (`sensitive`, then `unknown`, then `insensitive`; decision 4). */
export function stricter(a: NameCase, b: NameCase): NameCase {
  return RANK[a] >= RANK[b] ? a : b;
}

/** A closed value, or `unknown` for anything else (fail closed). */
function asNameCase(v: unknown): NameCase {
  return v === "sensitive" || v === "insensitive" || v === "unknown" ? v : "unknown";
}

/** Whether `v` compares names with case (`sensitive` or `unknown`, decision 5). */
export function comparesWithCase(v: NameCase): boolean {
  return v !== "insensitive";
}

/** Code point order, which is the byte order of the UTF-8 forms (contract text of `except`). */
export function compareUtf8(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = ((x[i] as string).codePointAt(0) ?? 0) - ((y[i] as string).codePointAt(0) ?? 0);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

/**
 * The canonical form of a `name_case`, as stored and compared (#301 review L2: never the raw JSON):
 * - `null` / `undefined`: not reported (`null`, today's rule);
 * - not an object: `{databases: unknown, objects: unknown}` (fail closed);
 * - values outside the closed set: `unknown`;
 * - `except` sorted by `database` in UTF-8 byte order, one entry per name with the stricter value;
 *   an empty `except` is dropped;
 * - an `except` that is not a list of entries, with more than 32 entries, or that serializes to
 *   more than 8 KiB (#301 review L3: the console never answers `400` for it, the bound is the
 *   agent's) gives `objects: unknown` without `except`, the strict form the agent itself sends
 *   past its bounds.
 */
export function canonicalNameCase(v: unknown): NameCaseRule | null {
  if (v === null || v === undefined) return null;
  if (!isPlainObject(v)) return { databases: "unknown", objects: "unknown" };
  const databases = asNameCase(v.databases);
  const objects = asNameCase(v.objects);
  if (v.except === undefined) return { databases, objects };
  const raw = v.except;
  const entries = Array.isArray(raw) ? raw : null;
  if (
    entries === null ||
    entries.length > MAX_EXCEPT_ENTRIES ||
    !entries.every((e) => isPlainObject(e) && typeof e.database === "string") ||
    utf8Length(JSON.stringify(raw)) > MAX_EXCEPT_BYTES
  ) {
    return { databases, objects: "unknown" };
  }
  const merged = new Map<string, NameCase>();
  for (const e of entries as Record<string, unknown>[]) {
    const name = e.database as string;
    const value = asNameCase(e.objects);
    const seen = merged.get(name);
    merged.set(name, seen === undefined ? value : stricter(seen, value));
  }
  if (merged.size === 0) return { databases, objects };
  const except = [...merged]
    .sort(([a], [b]) => compareUtf8(a, b))
    .map(([database, value]) => ({ database, objects: value }));
  return { databases, objects, except };
}

/** Canonical equality of two `name_case` values (L2: sorted, merged, never raw JSON equality). */
export function sameNameCase(a: unknown, b: unknown): boolean {
  return JSON.stringify(canonicalNameCase(a)) === JSON.stringify(canonicalNameCase(b));
}

/** The literal database name of an event object whose objects span several databases. */
const STAR = "*";

/**
 * How schema, object and column names compare in `database` (decision 6, L1, L2):
 * - the database `*` (an event object over several databases, or a merged name): the strictest of
 *   `objects` and every `except` value (L1);
 * - `databases` insensitive: the stricter of the `except` entries whose name matches after the N1
 *   fold (trailing spaces dropped, Unicode lowercase), else `objects`;
 * - otherwise: the stricter of the exact entry (trailing spaces ignored, the N1 rule of these
 *   engines; `objects` without one) and every entry that matches after the fold (L2).
 */
export function databaseObjectsCase(rule: NameCaseRule, database: string | null): NameCase {
  // A rule that bypassed `canonicalNameCase` (review L3): a non-list `except` reads as a list
  // that may name any database, so object names compare with case; non-object entries likewise.
  if (rule.except !== undefined && !Array.isArray(rule.except)) return "unknown";
  const except: readonly unknown[] = rule.except ?? [];
  if (!except.every((e) => isPlainObject(e) && typeof e.database === "string")) return "unknown";
  const entries = except as { database?: unknown; objects?: unknown }[];
  if (database === null || database === STAR) return entries.reduce<NameCase>((m, e) => stricter(m, asNameCase(e.objects)), asNameCase(rule.objects));
  const exactName = trimTrailingSpaces(database);
  const foldedName = foldName(database);
  let exact: NameCase | null = null;
  let folded: NameCase | null = null;
  for (const e of entries) {
    const v = asNameCase(e.objects);
    if (typeof e.database !== "string") continue; // unreachable: checked above
    if (trimTrailingSpaces(e.database) === exactName) exact = exact === null ? v : stricter(exact, v);
    if (foldName(e.database) === foldedName) folded = folded === null ? v : stricter(folded, v);
  }
  if (!comparesWithCase(asNameCase(rule.databases))) return folded ?? asNameCase(rule.objects);
  const own = exact ?? asNameCase(rule.objects);
  return folded === null ? own : stricter(own, folded);
}

/**
 * Glob options per part of a location exception on an item of `engine` in `database` (ADR-0055
 * decision 6). Without a rule, or on an engine other than `mysql`, `mariadb` and `sqlserver`:
 * today's options (`exceptionGlobOptions`, ADR-0054 and N1) for every part. Otherwise:
 * - `database`: with case when `databases` is `sensitive` or `unknown`;
 * - `schema`, `object`: with case when the database's value ({@link databaseObjectsCase}) is;
 * - `field`: on `sqlserver` as `object`; on `mysql` / `mariadb` never with case (column names);
 * - trailing spaces ignored as today (N1: on these three engines, always).
 */
export function exceptionPartOptions(engine: string | null, rule: NameCaseRule | null | undefined, database: string | null): PartGlobOptions {
  const base = exceptionGlobOptions(engine);
  if (engine === null || !NAME_CASE_ENGINES.includes(engine) || rule === null || rule === undefined) {
    return { perPart: { database: base, schema: base, object: base, field: base } };
  }
  // Not an object (a value that bypassed `canonicalNameCase`): the strict form, never a throw.
  if (typeof rule !== "object") return exceptionPartOptions(engine, STRICT_RULE, database);
  // Cached per rule object (one per target and evaluation chunk) and (engine, database).
  let byKey = PART_CACHE.get(rule);
  if (byKey === undefined) {
    byKey = new Map();
    PART_CACHE.set(rule, byKey);
  }
  const key = `${engine}\0${database ?? "\0"}`;
  const cached = byKey.get(key);
  if (cached !== undefined) return cached;
  const withCase = (on: boolean): GlobOptions => ({ ...base, matchCase: base.matchCase === true || on });
  const objects = comparesWithCase(databaseObjectsCase(rule, database));
  const out: PartGlobOptions = {
    perPart: {
      database: withCase(comparesWithCase(asNameCase(rule.databases))),
      schema: withCase(objects),
      object: withCase(objects),
      field: withCase(engine === "sqlserver" && objects),
    },
  };
  if (byKey.size >= PART_CACHE_MAX) byKey.clear();
  byKey.set(key, out);
  return out;
}

const STRICT_RULE: NameCaseRule = { databases: "unknown", objects: "unknown" };
const PART_CACHE = new WeakMap<object, Map<string, PartGlobOptions>>();
const PART_CACHE_MAX = 1000;

/** `opts` with case compared nowhere (the inventory's "today" side, ADR-0054 decision 6). */
export function withoutCase(opts: PartGlobOptions): PartGlobOptions {
  const off = (o: GlobOptions): GlobOptions => ({ ...o, matchCase: false });
  const p = opts.perPart;
  return { perPart: { database: off(p.database), schema: off(p.schema), object: off(p.object), field: off(p.field) } };
}

/** Whether any part of `opts` compares with case. */
export function anyWithCase(opts: PartGlobOptions, parts: readonly NamePart[] = ["database", "schema", "object", "field"]): boolean {
  return parts.some((p) => opts.perPart[p].matchCase === true);
}

/** How the target page names the rule (ADR-0055 decision 7). */
export type NameCaseDisplay = "not_reported" | "with_case" | "without_case" | "per_database" | "unknown";

/**
 * The summary of a target's rule: `not_reported` without a value (today's rule), `per_database`
 * when an `except` entry or the database names compare otherwise than the object names, else the
 * one value, `unknown` (compared with case) included.
 */
export function nameCaseDisplay(rule: NameCaseRule | null): NameCaseDisplay {
  if (rule === null) return "not_reported";
  const except = Array.isArray(rule.except) ? rule.except : [];
  const values = new Set<NameCase>([rule.databases, rule.objects, ...except.map((e) => e.objects)]);
  if (values.size > 1) return "per_database";
  const [only] = [...values];
  return only === "insensitive" ? "without_case" : only === "sensitive" ? "with_case" : "unknown";
}

export const NAME_CASE_LABELS: Record<NameCaseDisplay, string> = {
  not_reported: "not reported (without case)",
  with_case: "with case",
  without_case: "without case",
  per_database: "per database",
  unknown: "unknown, treated as with case",
};

const VALUE_LABELS: Record<NameCase, string> = { sensitive: "with case", insensitive: "without case", unknown: "unknown, treated as with case" };

/** The value's label (`unknown` named as compared with case). */
export function nameCaseValueLabel(v: NameCase): string {
  return VALUE_LABELS[asNameCase(v)];
}
