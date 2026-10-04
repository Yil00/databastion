import { readFileSync } from "node:fs";
import { isIP } from "node:net";

import { ConfigError, readEnvOrFile, type Env, type FileReader } from "@/config/env";
import { serverSubkey } from "@/server/crypto";

import { compileExpression, groupsPathIsGroups, readsTopLevelGroups, type CompiledExpression } from "./claims";

/**
 * OIDC login configuration (ADR-0038 decision 16), read from the environment only (never from a
 * request: discovery is not an SSRF vector). Error messages name variables, never values: the
 * client secret and the contents of `_FILE` variables never appear in an error or a log.
 */

export type LocalLoginMode = "enabled" | "admins" | "disabled";
export type TokenAuthMethod = "client_secret_basic" | "client_secret_post";

/** Signature algorithms an operator may list; `none` and `HS*` are always refused. */
export const SUPPORTED_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"] as const;
export type IdTokenAlg = (typeof SUPPORTED_ID_TOKEN_ALGS)[number];
export const DEFAULT_ID_TOKEN_ALGS: readonly IdTokenAlg[] = ["RS256", "PS256", "ES256"];

/** Upper bound (and default) of an OIDC session's absolute lifetime. */
export const MAX_OIDC_SESSION_MS = 12 * 3600_000;
/** Lower bound of `DATABASTION_OIDC_SESSION_MAX_AGE` (shorter than one refresh interval makes no sense). */
export const MIN_OIDC_SESSION_MS = 5 * 60_000;

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  tokenAuthMethod: TokenAuthMethod;
  scopes: string[];
  displayName: string;
  idTokenAlgs: IdTokenAlg[];
  /** Extra CA certificates (PEM) for the provider's endpoints, besides the system roots. */
  ca: string | null;
  useUserinfo: boolean;
  loginPath: CompiledExpression;
  emailPath: CompiledExpression;
  namePath: CompiledExpression;
  groupsPath: CompiledExpression | null;
  rolePath: CompiledExpression | null;
  roleStrict: boolean;
  allowedGroups: string[];
  /** Lower-cased. */
  allowedDomains: string[];
  allowSignUp: boolean;
  /** Explicit `SKIP_ROLE_SYNC=1`, or no role expression (roles managed in the console, decision 9). */
  skipRoleSync: boolean;
  autoLogin: boolean;
  useRefreshToken: boolean;
  sessionMaxAgeMs: number;
  signoutRedirectUrl: string | null;
  /** `<DATABASTION_PUBLIC_URL origin>` */
  publicOrigin: string;
  redirectUri: string;
  /** Plain-HTTP issuer allowed (loopback, outside production). */
  allowHttp: boolean;
}

const V = "DATABASTION_OIDC_";
const MAX_EXPRESSION_BYTES = 1024;
const DISPLAY_NAME = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]{1,64}$/u;
const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]{1,64}$/;
const GROUP_OR_DOMAIN_MAX = 256;

function flag(env: Env, name: string, dflt: boolean): boolean {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return dflt;
  const v = raw.trim();
  if (v === "1" || v === "true") return true;
  if (v === "0" || v === "false") return false;
  throw new ConfigError(`${name} must be 1 or 0.`);
}

/** `DATABASTION_OIDC_ENABLED=1`. Any other non-empty value than 0 / 1 is a configuration error. */
export function oidcEnabled(env: Env = process.env): boolean {
  return flag(env, `${V}ENABLED`, false);
}

/**
 * `DATABASTION_LOCAL_LOGIN`: `enabled` / `admins` / `disabled`. Default: `enabled` with OIDC off,
 * `admins` with OIDC on; `disabled` only when set explicitly (decision 11).
 */
export function localLoginMode(env: Env = process.env): LocalLoginMode {
  const raw = env.DATABASTION_LOCAL_LOGIN?.trim();
  if (raw === undefined || raw === "") return safeOidcEnabled(env) ? "admins" : "enabled";
  if (raw === "enabled" || raw === "admins" || raw === "disabled") return raw;
  throw new ConfigError("DATABASTION_LOCAL_LOGIN must be enabled, admins or disabled.");
}

function safeOidcEnabled(env: Env): boolean {
  try {
    return oidcEnabled(env);
  } catch {
    // A malformed DATABASTION_OIDC_ENABLED is fatal at startup; meanwhile the safer default applies.
    return true;
  }
}

/** `12h`, `90m`, `3600s` or `3600` (seconds). */
export function parseDuration(raw: string): number | null {
  const m = /^(\d{1,6})(h|m|s)?$/.exec(raw.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2] ?? "s";
  return n * (unit === "h" ? 3600_000 : unit === "m" ? 60_000 : 1000);
}

function list(env: Env, name: string): string[] {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return [];
  const items = raw.split(",").map((s) => s.trim()).filter((s) => s !== "");
  if (items.length > 256 || items.some((s) => s.length > GROUP_OR_DOMAIN_MAX)) {
    throw new ConfigError(`${name}: at most 256 entries of at most ${GROUP_OR_DOMAIN_MAX} characters.`);
  }
  return items;
}

function expression(env: Env, name: string, dflt: string | null): CompiledExpression | null {
  const raw = env[`${V}${name}`];
  const source = raw === undefined || raw.trim() === "" ? dflt : raw.trim();
  if (source === null) return null;
  if (Buffer.byteLength(source, "utf8") > MAX_EXPRESSION_BYTES) {
    throw new ConfigError(`${V}${name} is longer than ${MAX_EXPRESSION_BYTES} bytes.`);
  }
  try {
    return compileExpression(source);
  } catch {
    // The expression is operator-written, not a secret, but the parser message is not needed.
    throw new ConfigError(`${V}${name} is not a valid JMESPath expression.`);
  }
}

/** Whether `host` is a loopback address or `localhost`. */
export function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost") return true;
  if (isIP(h) === 4) return h.startsWith("127.");
  if (isIP(h) === 6) return h === "::1";
  return false;
}

/**
 * Checks an absolute provider URL: `https://`, or `http://` on a loopback host outside production
 * (as for the SMTP rule of ADR-0017). No credentials, no fragment.
 */
export function checkProviderUrl(raw: string, allowHttp: boolean): URL | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") return null;
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && allowHttp && isLoopbackHost(url.hostname)) return url;
  return null;
}

/**
 * The OIDC configuration, `null` when OIDC is off. Throws {@link ConfigError} (variable names only)
 * on any invalid or missing setting, or when the server key is unusable (decision 13).
 */
export function loadOidcConfig(env: Env = process.env, readFile: FileReader = (p) => readFileSync(p, "utf8")): OidcConfig | null {
  if (!oidcEnabled(env)) return null;
  const production = env.NODE_ENV === "production";
  const allowHttp = !production;

  const issuerRaw = env[`${V}ISSUER_URL`]?.trim();
  if (!issuerRaw) throw new ConfigError(`${V}ENABLED=1 requires ${V}ISSUER_URL.`);
  if (checkProviderUrl(issuerRaw, allowHttp) === null || /[?#]/.test(issuerRaw)) {
    throw new ConfigError(
      `${V}ISSUER_URL must be an https:// URL without query or fragment (http:// only on a loopback address outside production).`,
    );
  }
  const clientId = env[`${V}CLIENT_ID`]?.trim();
  if (!clientId) throw new ConfigError(`${V}ENABLED=1 requires ${V}CLIENT_ID.`);
  if (clientId.length > 255 || /[\p{Cc}]/u.test(clientId)) throw new ConfigError(`${V}CLIENT_ID is too long or has control characters.`);
  // readEnvOrFile errors name the variables only (never the secret or the file contents).
  const clientSecret = readEnvOrFile(`${V}CLIENT_SECRET`, env, readFile);
  if (clientSecret === undefined) throw new ConfigError(`${V}ENABLED=1 requires ${V}CLIENT_SECRET or ${V}CLIENT_SECRET_FILE.`);

  const publicUrl = env.DATABASTION_PUBLIC_URL?.trim();
  let publicOrigin: string;
  try {
    if (!publicUrl) throw new Error("unset");
    const u = new URL(publicUrl);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && (!production || env.DATABASTION_INSECURE_COOKIES === "1"))) throw new Error("scheme");
    publicOrigin = u.origin;
  } catch {
    throw new ConfigError(`${V}ENABLED=1 requires DATABASTION_PUBLIC_URL, an https:// URL (the redirect URI is <DATABASTION_PUBLIC_URL>/api/auth/oidc/callback).`);
  }
  if (serverSubkey("oidc-state.v1", env) === null || serverSubkey("oidc-tokens.v1", env) === null) {
    throw new ConfigError(
      `${V}ENABLED=1 requires a usable DATABASTION_ENCRYPTION_KEY(_FILE) (at least 32 characters): the OIDC state cookie and refresh tokens are encrypted with it. ` +
        "DATABASTION_ALLOW_MISSING_ENCRYPTION_KEY does not apply to OIDC.",
    );
  }

  const method = env[`${V}TOKEN_AUTH_METHOD`]?.trim() || "client_secret_basic";
  if (method !== "client_secret_basic" && method !== "client_secret_post") {
    throw new ConfigError(`${V}TOKEN_AUTH_METHOD must be client_secret_basic or client_secret_post.`);
  }

  const scopeRaw = env[`${V}SCOPES`]?.trim() || "openid profile email";
  const scopes = scopeRaw.split(/[\s,]+/).filter((s) => s !== "");
  if (scopes.length > 32 || scopes.some((s) => !SCOPE.test(s))) throw new ConfigError(`${V}SCOPES: at most 32 valid scope tokens.`);
  if (!scopes.includes("openid")) scopes.unshift("openid");

  const displayName = env[`${V}DISPLAY_NAME`]?.trim() || "Single sign-on";
  if (!DISPLAY_NAME.test(displayName)) throw new ConfigError(`${V}DISPLAY_NAME: 1 to 64 printable characters.`);

  const algRaw = env[`${V}ID_TOKEN_ALGS`]?.trim();
  const algs = algRaw ? algRaw.split(",").map((a) => a.trim()).filter((a) => a !== "") : [...DEFAULT_ID_TOKEN_ALGS];
  for (const a of algs) {
    if (!(SUPPORTED_ID_TOKEN_ALGS as readonly string[]).includes(a)) {
      throw new ConfigError(`${V}ID_TOKEN_ALGS: only ${SUPPORTED_ID_TOKEN_ALGS.join(", ")} are allowed (never none or HS*).`);
    }
  }
  if (algs.length === 0) throw new ConfigError(`${V}ID_TOKEN_ALGS is empty.`);

  let ca: string | null = null;
  const caFile = env[`${V}CA_FILE`]?.trim();
  if (caFile) {
    try {
      ca = readFile(caFile);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code ?? "unknown error";
      throw new ConfigError(`Cannot read the file referenced by ${V}CA_FILE (${code}).`);
    }
    if (!/-----BEGIN CERTIFICATE-----/.test(ca)) throw new ConfigError(`${V}CA_FILE holds no PEM certificate.`);
  }

  const rolePath = expression(env, "ROLE_ATTRIBUTE_PATH", null);
  const groupsPath = expression(env, "GROUPS_ATTRIBUTE_PATH", null);
  const roleStrict = flag(env, `${V}ROLE_ATTRIBUTE_STRICT`, true);
  const allowedGroups = list(env, `${V}ALLOWED_GROUPS`);
  const allowedDomains = list(env, `${V}ALLOWED_DOMAINS`).map((d) => d.toLowerCase());
  for (const d of allowedDomains) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) {
      throw new ConfigError(`${V}ALLOWED_DOMAINS: each entry must be a domain name (exact match, e.g. example.com).`);
    }
  }
  if (allowedGroups.length > 0 && groupsPath === null) {
    throw new ConfigError(`${V}ALLOWED_GROUPS requires ${V}GROUPS_ATTRIBUTE_PATH.`);
  }
  const allowSignUp = flag(env, `${V}ALLOW_SIGN_UP`, false);
  // Decision 16: sign-up only with a group filter, or a strict role expression.
  if (allowSignUp && allowedGroups.length === 0 && !(rolePath !== null && roleStrict)) {
    throw new ConfigError(
      `${V}ALLOW_SIGN_UP=1 requires ${V}ALLOWED_GROUPS, or ${V}ROLE_ATTRIBUTE_PATH with ${V}ROLE_ATTRIBUTE_STRICT=1.`,
    );
  }

  const maxAgeRaw = env[`${V}SESSION_MAX_AGE`]?.trim();
  let sessionMaxAgeMs = MAX_OIDC_SESSION_MS;
  if (maxAgeRaw) {
    const ms = parseDuration(maxAgeRaw);
    if (ms === null || ms > MAX_OIDC_SESSION_MS || ms < MIN_OIDC_SESSION_MS) {
      throw new ConfigError(`${V}SESSION_MAX_AGE must be a duration from 5m to 12h (e.g. 8h, 90m).`);
    }
    sessionMaxAgeMs = ms;
  }

  let signoutRedirectUrl: string | null = null;
  const signout = env[`${V}SIGNOUT_REDIRECT_URL`]?.trim();
  if (signout) {
    const u = checkProviderUrl(signout, allowHttp);
    if (u === null) throw new ConfigError(`${V}SIGNOUT_REDIRECT_URL must be an https:// URL.`);
    signoutRedirectUrl = u.toString();
  }

  return {
    issuer: issuerRaw,
    clientId,
    clientSecret,
    tokenAuthMethod: method,
    scopes,
    displayName,
    idTokenAlgs: algs as IdTokenAlg[],
    ca,
    useUserinfo: flag(env, `${V}USE_USERINFO`, false),
    loginPath: expression(env, "LOGIN_ATTRIBUTE_PATH", "preferred_username") as CompiledExpression,
    emailPath: expression(env, "EMAIL_ATTRIBUTE_PATH", "email") as CompiledExpression,
    namePath: expression(env, "NAME_ATTRIBUTE_PATH", "name") as CompiledExpression,
    groupsPath,
    rolePath,
    roleStrict,
    allowedGroups,
    allowedDomains,
    allowSignUp,
    skipRoleSync: flag(env, `${V}SKIP_ROLE_SYNC`, false) || rolePath === null,
    autoLogin: flag(env, `${V}AUTO_LOGIN`, false),
    useRefreshToken: flag(env, `${V}USE_REFRESH_TOKEN`, false),
    sessionMaxAgeMs,
    signoutRedirectUrl,
    publicOrigin,
    redirectUri: `${publicOrigin}/api/auth/oidc/callback`,
    allowHttp,
  };
}

/**
 * OIDC configuration warnings logged at startup (end-of-phase-8 review of #147), or none when OIDC
 * is off or misconfigured (then {@link oidcStartupFatal} reports it). Never contains a value.
 */
export function oidcConfigWarnings(env: Env = process.env): string[] {
  let cfg: OidcConfig | null;
  try {
    cfg = loadOidcConfig(env);
  } catch {
    return [];
  }
  if (cfg === null) return [];
  const warnings: string[] = [];
  if (cfg.rolePath !== null && cfg.groupsPath !== null && !groupsPathIsGroups(cfg.groupsPath) && readsTopLevelGroups(cfg.rolePath)) {
    warnings.push(
      `${V}ROLE_ATTRIBUTE_PATH reads \`groups\` while ${V}GROUPS_ATTRIBUTE_PATH is another path: in the role expression, \`groups\` is the list mapped by ${V}GROUPS_ATTRIBUTE_PATH, not the raw \`groups\` claim (console/README.md, "Role expression and groups").`,
    );
  }
  if (cfg.useRefreshToken && !cfg.skipRoleSync && !cfg.useUserinfo) {
    warnings.push(
      `${V}USE_REFRESH_TOKEN=1 with role sync on but without ${V}USE_USERINFO=1: a refresh that returns no id_token does not re-check groups or role, so role changes at the provider apply only at the next id_token or login.`,
    );
  }
  return warnings;
}

/**
 * Fatal OIDC / local-login configuration error (web and worker, every environment: OIDC is an
 * explicit opt-in), or `null`. Never contains a configuration value.
 */
export function oidcStartupFatal(env: Env = process.env): string | null {
  try {
    localLoginMode(env);
    loadOidcConfig(env);
    return null;
  } catch (err) {
    if (err instanceof ConfigError) return `OIDC login configuration error: ${err.message} Refusing to start.`;
    return "OIDC login configuration error: refusing to start.";
  }
}
