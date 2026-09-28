/**
 * Helpers shared by the condition models of every policy source (`finding`:
 * src/lib/policy-model.ts, `access_event`: src/lib/event-model.ts). Pure functions, no dependency.
 */

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

export const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

export const MAX_LIST_ITEMS = 50;

/** Contract `Engine`. */
export const ENGINES = ["postgres", "mysql", "mariadb", "mongodb", "openldap"] as const;
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
 * Case-insensitive glob match (`*` any run, `?` one character, `\` escapes the next character),
 * in linear time and space (greedy two-pointer with single backtrack point: no regular expression,
 * so no catastrophic backtracking on hostile names or patterns).
 */
export function globMatch(pattern: string, value: string): boolean {
  const p = tokens(pattern.toLowerCase());
  const s = [...value.toLowerCase()];
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
