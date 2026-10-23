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
 * Unicode lowercase with the final sigma unified (security review M1): `ς` (U+03C2) becomes `σ`
 * (U+03C3), so `ΠΕΛΑΤΕΣ`, `πελατες` and `πελατεσ` fold alike whatever the position of the letter
 * (`String.prototype.toLowerCase` maps a word-final `Σ` to `ς`, a per-code-point lowercase to `σ`).
 * The agent's `same_name` applies the same mapping, and the sensitivity pre-filter in SQL too.
 */
export function foldCase(s: string): string {
  return s.toLowerCase().replaceAll(FINAL_SIGMA, SIGMA);
}

/** Final sigma and sigma (security review M1), also bound as parameters in SQL. */
export const FINAL_SIGMA = "\u03c2";
export const SIGMA = "\u03c3";

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

/**
 * Database name as hashed in the access-event incident dedup key (ADR-0021 decision 6,
 * implementation note of 2026-10-18, review M1 of PR #274): the case as sent on every engine,
 * since case can tell two databases apart (PostgreSQL quoted names, SQL Server under a
 * case-sensitive collation, MySQL / MariaDB with `lower_case_table_names=0`), and trailing spaces
 * dropped only on {@link TRAILING_SPACE_BLIND_ENGINES}, as location exceptions. A merged key would
 * link a later dump of another database to a closed incident; a null or unknown engine is never
 * loosened.
 */
export function dedupDatabaseName(name: string, engine: string | null): string {
  return engine !== null && TRAILING_SPACE_BLIND_ENGINES.includes(engine) ? trimTrailingSpaces(name) : name;
}

/**
 * Engines whose object names a location exception compares without case (ADR-0054 decision 1):
 * SQL Server (case-insensitive under the default collation) and MySQL / MariaDB (with
 * `lower_case_table_names` other than 0) while their agent reports no case semantics (ADR-0054
 * decision 3; with a `TargetStatus.name_case`, ADR-0055 decision 6 compares them per part,
 * `exceptionPartOptions` in src/lib/name-case.ts), and OpenLDAP (case-insensitive matching rules
 * of the naming attributes).
 * Every other engine compares with case, an unknown or null engine included: PostgreSQL, MongoDB,
 * Redis, Valkey and Apereo CAS by definition ({@link CASE_SENSITIVE_EXCEPTION_ENGINES}), and an
 * engine added later is never loosened before its connector ADR decides. Policy conditions,
 * per-object sensitivity and scores stay case-insensitive on every engine (looser matching only
 * reports more).
 */
export const CASE_BLIND_EXCEPTION_ENGINES: readonly string[] = ["sqlserver", "mysql", "mariadb", "openldap"];

/** The contract engines on which location exceptions compare names with case (ADR-0054). */
export const CASE_SENSITIVE_EXCEPTION_ENGINES: readonly string[] = ["postgres", "mongodb", "redis", "valkey", "cas"];

/** Whether location exceptions compare names with case on `engine` (ADR-0054 decision 1). */
export function exceptionMatchesCase(engine: string | null): boolean {
  return engine === null || !CASE_BLIND_EXCEPTION_ENGINES.includes(engine);
}

/**
 * Glob options of location exceptions on an item of `engine`: trailing spaces ignored only on
 * {@link TRAILING_SPACE_BLIND_ENGINES} (N1), case compared everywhere but on
 * {@link CASE_BLIND_EXCEPTION_ENGINES} (ADR-0054). A null (unknown) engine gets neither loosening.
 */
export function exceptionGlobOptions(engine: string | null): GlobOptions {
  return {
    ignoreTrailingSpaces: engine !== null && TRAILING_SPACE_BLIND_ENGINES.includes(engine),
    matchCase: exceptionMatchesCase(engine),
  };
}

/** The parts of a location (finding) or an event object (no `field`). */
export type NamePart = "database" | "schema" | "object" | "field";

/**
 * Glob options per location part (ADR-0055 decision 6): a target's `name_case` can compare its
 * database names and its object names differently. Built by `exceptionPartOptions`
 * (src/lib/name-case.ts).
 */
export type PartGlobOptions = { readonly perPart: Readonly<Record<NamePart, GlobOptions>> };

/**
 * ADR-0056 decision 3 item 4: whether location exception globs may cover the parts the agent
 * reported altered by its name normalization (contract `Location.altered` / `ObjectRef.altered`).
 * An altered part is covered only by a glob that is absent or exactly `*` (the glob `\*`, which
 * selects the literal name only, does not): another object of the engine may have been sent under
 * the same name. The parts not altered are left to the caller's usual match (ADR-0054 / ADR-0055
 * case rules). No list (an older agent, or a console that did not list the tokens): nothing is
 * restricted, the console never guesses an alteration from the name. A part sent as `*` that also
 * carries the marker (the contract says it never should) gets the same rule: stricter only.
 */
export function alteredPartsCoverable(
  globs: Readonly<Partial<Record<NamePart, string>>>,
  altered: readonly string[] | null | undefined,
): boolean {
  if (!altered || altered.length === 0) return true;
  return altered.every((part) => {
    const g = globs[part as NamePart];
    return g === undefined || g === "*";
  });
}

/** The options of `part`: the same for every part when `opts` is a plain {@link GlobOptions}. */
export function optionsFor(opts: GlobOptions | PartGlobOptions, part: NamePart): GlobOptions {
  return "perPart" in opts ? opts.perPart[part] : opts;
}

export interface GlobOptions {
  /**
   * Also match once trailing spaces are dropped from the value and trailing literal spaces from
   * the pattern (N1). Strictly looser: a match without it is still a match.
   */
  ignoreTrailingSpaces?: boolean;
  /**
   * Also require the match of the pattern and the value as written, without the case fold (same
   * matcher, same trailing-space handling), on top of the folded match (ADR-0054 decision 1).
   * Strictly stricter: thanks to the conjunction, a match with it is a match without it, although
   * `?` and case mappings that change a string's length (`İ`) make the folded and the exact match
   * differ in both directions.
   */
  matchCase?: boolean;
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
  if (!matchWith(compiled(pattern, true), [...foldCase(value)], opts)) return false;
  // ADR-0054: the exact match is a second pass of the same linear matcher, never a replacement.
  return !opts.matchCase || matchWith(compiled(pattern, false), [...value], opts);
}

function matchWith(p: readonly GlobToken[], s: readonly string[], opts: GlobOptions): boolean {
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
const foldedGlobCache = new Map<string, GlobToken[]>();
const exactGlobCache = new Map<string, GlobToken[]>();

/** Tokens of `pattern`, folded with {@link foldCase} or as written (`matchCase`, ADR-0054). */
function compiled(pattern: string, fold: boolean): GlobToken[] {
  const cache = fold ? foldedGlobCache : exactGlobCache;
  let t = cache.get(pattern);
  if (!t) {
    if (cache.size >= GLOB_CACHE_MAX) cache.clear();
    t = tokens(fold ? foldCase(pattern) : pattern);
    cache.set(pattern, t);
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
