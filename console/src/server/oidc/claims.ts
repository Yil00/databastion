import * as jmespath from "jmespath";

import { USERNAME } from "@/server/auth/users";

/**
 * Claim mapping (ADR-0038 decisions 7 and 8) with JMESPath expressions, as in Grafana's Generic
 * OAuth. Library: `jmespath` (the JMESPath reference implementation for JavaScript, Apache-2.0, no
 * dependencies). Bounds: expressions at most 1 KiB (checked at configuration time), claims at most
 * 64 KiB, groups at most 256 entries of at most 256 characters. JMESPath has no loops or recursion
 * beyond the input, so evaluation is bounded by these sizes.
 *
 * Authorization (role, groups, allow-lists) must read claims that only the provider's
 * administrators set: never `email`, `preferred_username`, `name` or any user-editable attribute
 * (documented in console/README.md). Anything but exactly `admin` or `analyst` is **no role**.
 */

export type Role = "admin" | "analyst";

/** Closed list of `user.login_denied` reasons (decision 15). */
export const LOGIN_DENIED_REASONS = [
  "state",
  "nonce",
  "iss",
  "token",
  "id_token",
  "provider_error",
  "rate_limited",
  "group",
  "domain",
  "email_unverified",
  "role",
  "sign_up",
  "disabled",
  "username",
] as const;
export type LoginDeniedReason = (typeof LOGIN_DENIED_REASONS)[number];

export const MAX_CLAIMS_BYTES = 64 * 1024;
export const MAX_GROUPS = 256;
export const MAX_GROUP_LENGTH = 256;
const MAX_EMAIL_LENGTH = 320;
const MAX_NAME_LENGTH = 256;

export interface CompiledExpression {
  readonly source: string;
}

interface JmesPathModule {
  compile(expression: string): unknown;
  search(data: unknown, expression: string): unknown;
}
const jp = jmespath as unknown as JmesPathModule;

/** Parses `source` (throws on a syntax error). */
export function compileExpression(source: string): CompiledExpression {
  jp.compile(source);
  return { source };
}

/** Deep copy with null-prototype objects: claim names such as `__proto__` stay plain data. */
function plain(value: unknown, depth = 0): unknown {
  if (depth > 32) return null;
  if (Array.isArray(value)) return value.map((v) => plain(v, depth + 1));
  if (value !== null && typeof value === "object") {
    const out = Object.create(null) as Record<string, unknown>;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = plain(v, depth + 1);
    return out;
  }
  return value;
}

/** Evaluates `expr` on `claims`; an evaluation error yields `undefined`. */
export function evaluate(expr: CompiledExpression, claims: unknown): unknown {
  try {
    return jp.search(claims, expr.source);
  } catch {
    return undefined;
  }
}

export interface ClaimMappingConfig {
  loginPath: CompiledExpression;
  emailPath: CompiledExpression;
  namePath: CompiledExpression;
  groupsPath: CompiledExpression | null;
  rolePath: CompiledExpression | null;
  roleStrict: boolean;
  allowedGroups: readonly string[];
  /** Lower-cased. */
  allowedDomains: readonly string[];
}

export interface MappedIdentity {
  /** Lower-cased login claim, `null` when absent or not a valid console username. */
  login: string | null;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  groups: string[];
  /**
   * Role mapped by the role expression (`null`: no role). Without a role expression (roles managed
   * in the console) it is `null` too.
   */
  role: Role | null;
}

export type MappingResult =
  | { ok: true; identity: MappedIdentity; /** Role a new or synced user gets (never `admin` by default). */ effectiveRole: Role }
  | { ok: false; reason: LoginDeniedReason; identity: MappedIdentity | null };

function oneLine(v: string, max: number): string | null {
  const clean = v.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").trim();
  return clean === "" || clean.length > max ? null : clean;
}

/** `admin` or `analyst` exactly (case-sensitive); anything else, including errors, is no role. */
export function toRole(v: unknown): Role | null {
  return v === "admin" || v === "analyst" ? v : null;
}

/** Domain after the LAST `@`, lower-cased; `null` without one. */
export function emailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

/**
 * Maps validated claims (the `id_token`, merged with userinfo when enabled) to console attributes
 * and applies the login filters, in this order: size, groups, domains, role, login name.
 */
export function mapClaims(rawClaims: Record<string, unknown>, cfg: ClaimMappingConfig): MappingResult {
  let size: number;
  try {
    size = Buffer.byteLength(JSON.stringify(rawClaims), "utf8");
  } catch {
    return { ok: false, reason: "id_token", identity: null };
  }
  if (size > MAX_CLAIMS_BYTES) return { ok: false, reason: "id_token", identity: null };
  const claims = plain(rawClaims);

  const loginRaw = evaluate(cfg.loginPath, claims);
  const login = typeof loginRaw === "string" ? loginRaw.trim().toLowerCase() : null;
  const emailRaw = evaluate(cfg.emailPath, claims);
  const email = typeof emailRaw === "string" ? oneLine(emailRaw, MAX_EMAIL_LENGTH) : null;
  const nameRaw = evaluate(cfg.namePath, claims);
  const name = typeof nameRaw === "string" ? oneLine(nameRaw, MAX_NAME_LENGTH) : null;
  // `email_verified` is read from the standard claim only, never through an expression.
  const emailVerified = (rawClaims as { email_verified?: unknown }).email_verified === true;

  let groups: string[] = [];
  let groupsTooLarge = false;
  if (cfg.groupsPath !== null) {
    const g = evaluate(cfg.groupsPath, claims);
    if (Array.isArray(g)) {
      const strings = g.filter((x): x is string => typeof x === "string");
      if (strings.length > MAX_GROUPS || strings.some((x) => x.length > MAX_GROUP_LENGTH)) groupsTooLarge = true;
      else groups = strings;
    }
  }
  const role = cfg.rolePath === null ? null : toRole(evaluate(cfg.rolePath, claims));
  const identity: MappedIdentity = {
    login: login !== null && USERNAME.test(login) ? login : null,
    email,
    emailVerified,
    name,
    groups,
    role,
  };

  if (groupsTooLarge) return { ok: false, reason: "group", identity };
  if (cfg.allowedGroups.length > 0 && !groups.some((g) => cfg.allowedGroups.includes(g))) {
    return { ok: false, reason: "group", identity };
  }
  if (cfg.allowedDomains.length > 0) {
    if (email === null || !emailVerified) return { ok: false, reason: "email_unverified", identity };
    const domain = emailDomain(email);
    if (domain === null || !cfg.allowedDomains.includes(domain)) return { ok: false, reason: "domain", identity };
  }
  if (cfg.rolePath !== null && role === null && cfg.roleStrict) return { ok: false, reason: "role", identity };
  if (identity.login === null) return { ok: false, reason: "username", identity };
  return { ok: true, identity, effectiveRole: role ?? "analyst" };
}
