/**
 * Helpers shared by the condition models of every policy source (`finding`:
 * src/lib/policy-model.ts, `access_event`: src/lib/event-model.ts). Pure functions, no dependency
 * besides the contract value lists.
 */

import { ENGINES } from "@/lib/protocol/enums";

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

export const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

export const MAX_LIST_ITEMS = 50;

/** Contract `Engine` (checked against the generated types in src/lib/protocol/enums.ts). */
export { ENGINES };
export const MAX_GLOB_LENGTH = 256;

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Free text typed by an administrator: no control / format / private-use / separator characters. */
export const TEXT = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]*$/u;

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The first key of `v` outside `allowed`, or null. */
export function onlyKeys(v: Record<string, unknown>, allowed: readonly string[]): string | null {
  return Object.keys(v).find((k) => !allowed.includes(k)) ?? null;
}

/** A non-empty list of at most `MAX_LIST_ITEMS` strings passing `check`, deduplicated. */
export function stringList(v: unknown, key: string, check: (s: string) => boolean): Parsed<string[]> {
  if (!Array.isArray(v) || v.length < 1 || v.length > MAX_LIST_ITEMS) return fail(key);
  if (!v.every((s): s is string => typeof s === "string" && check(s))) return fail(key);
  return { ok: true, value: [...new Set(v)] };
}

/** A glob on a normalized name: bounded, printable, not empty. */
export function isGlob(v: unknown): v is string {
  return typeof v === "string" && v.length >= 1 && v.length <= MAX_GLOB_LENGTH && TEXT.test(v);
}

/**
 * Lowercases each code point on its own (Unicode default mapping, no context), as the agent's
 * `char::to_lowercase` does. `String.prototype.toLowerCase` gives the same result except for the
 * context-dependent final sigma (`Σ` at the end of a word becomes `ς` there, `σ` here), so a name
 * is folded the same way wherever it stands in the string.
 */
export function foldCase(s: string): string {
  return s.includes("\u03a3") ? Array.from(s, (c) => c.toLowerCase()).join("") : s.toLowerCase();
}

/** Drops trailing spaces (U+0020 only, as the agent and SQL `rtrim` do). Linear, no regex. */
export function trimTrailingSpaces(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x20) end--;
  return end === s.length ? s : s.slice(0, end);
}

/**
 * Identity of an object name for object-scoped matching (end-of-phase-9 review N1): trailing
 * spaces dropped, then {@link foldCase}. The agent compares sensitive objects the same way
 * (`same_name` in agent/crates/core/src/job.rs): names taken from statement text keep the client's
 * spelling, and SQL Server (default collation), MySQL / MariaDB with `lower_case_table_names` other
 * than 0 and LDAP compare identifiers without case, so `CRM.CUSTOMERS` in an event is the
 * `crm.customers` that Discovery recorded.
 */
export function foldName(s: string): string {
  return foldCase(trimTrailingSpaces(s));
}

/**
 * Engines whose identifier comparisons ignore trailing spaces, so a location exception also
 * covers a name that differs from its globs by trailing spaces only (N1): SQL Server (padded
 * comparisons under every collation) and MySQL / MariaDB (identifiers cannot end with a space).
 * Elsewhere a trailing space can be part of a distinct name (a quoted PostgreSQL identifier, a
 * MongoDB collection, a Redis / Valkey key), and an exception never loosens there: looser
 * exceptions suppress more. Policy conditions and scoring ignore trailing spaces on every engine
 * (looser matching only reports more).
 */
export const TRAILING_SPACE_BLIND_ENGINES: readonly string[] = ["sqlserver", "mysql", "mariadb"];

export function exceptionGlobOptions(engine: string | null): GlobOptions {
  return { ignoreTrailingSpaces: engine !== null && TRAILING_SPACE_BLIND_ENGINES.includes(engine) };
}

export interface GlobOptions {
  /**
   * Also match once trailing spaces are dropped from the value and trailing literal spaces from
   * the pattern (N1). Strictly looser: a match without it is still a match.
   */
  ignoreTrailingSpaces?: boolean;
}

/**
 * Case-insensitive glob match (`*` any run, `?` one character, `\` escapes the next character).
 * Both sides are folded with {@link foldCase}.
 * Greedy two-pointer matcher with a single backtrack point and no regular expression: worst case
 * O(n x m) time for a name of n characters and a pattern of m tokens, O(n + m) space, with no
 * catastrophic (exponential) backtracking. Both sides are bounded (names 256 characters by the
 * contract, patterns `MAX_GLOB_LENGTH`), so a match costs at most ~65 000 steps. Tokenized
 * patterns are cached (policies reuse the same few patterns for every event or finding).
 */
export function globMatch(pattern: string, value: string, opts: GlobOptions = {}): boolean {
  const p = compiled(pattern);
  const s = [...foldCase(value)];
  if (matchTokens(p, s)) return true;
  if (!opts.ignoreTrailingSpaces) return false;
  let pe = p.length;
  while (pe > 0 && isSpace(p[pe - 1])) pe--;
  let se = s.length;
  while (se > 0 && s[se - 1] === " ") se--;
  return (pe < p.length || se < s.length) && matchTokens(pe < p.length ? p.slice(0, pe) : p, s.slice(0, se));
}

const isSpace = (t: GlobToken | undefined) => t !== undefined && t.kind === "char" && t.ch === " ";

function matchTokens(p: readonly GlobToken[], s: readonly string[]): boolean {
  let pi = 0;
  let si = 0;
  let star = -1;
  let mark = 0;
  while (si < s.length) {
    const t = p[pi];
    if (t !== undefined && t.kind !== "star" && (t.kind === "any" || t.ch === s[si])) {
      pi++;
      si++;
    } else if (t !== undefined && t.kind === "star") {
      star = pi++;
      mark = si;
    } else if (star >= 0) {
      pi = star + 1;
      si = ++mark;
    } else {
      return false;
    }
  }
  while (p[pi]?.kind === "star") pi++;
  return pi === p.length;
}

type GlobToken = { kind: "star" } | { kind: "any" } | { kind: "char"; ch: string };

const GLOB_CACHE_MAX = 1000;
const globCache = new Map<string, GlobToken[]>();

function compiled(pattern: string): GlobToken[] {
  let t = globCache.get(pattern);
  if (!t) {
    if (globCache.size >= GLOB_CACHE_MAX) globCache.clear();
    t = tokens(foldCase(pattern));
    globCache.set(pattern, t);
  }
  return t;
}

function tokens(pattern: string): GlobToken[] {
  const out: GlobToken[] = [];
  const chars = [...pattern];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i] as string;
    if (c === "\\" && i + 1 < chars.length) out.push({ kind: "char", ch: chars[++i] as string });
    else if (c === "*") {
      if (out[out.length - 1]?.kind !== "star") out.push({ kind: "star" });
    } else if (c === "?") out.push({ kind: "any" });
    else out.push({ kind: "char", ch: c });
  }
  return out;
}
