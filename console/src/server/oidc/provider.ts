import { logger } from "@/lib/logger";

import { checkProviderUrl, type IdTokenAlg, type OidcConfig } from "./config";
import { MAX_DISCOVERY_BYTES, MAX_JWKS_BYTES, providerRequest, ProviderHttpError, type ProviderTransport } from "./http";

/**
 * OIDC provider metadata (discovery from the issuer, ADR-0038 decision 2) and its JWKS cache
 * (decision 4). The configuration comes from the environment only.
 */

export interface ProviderMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userinfoEndpoint: string | null;
  endSessionEndpoint: string | null;
  revocationEndpoint: string | null;
  /** Configured algorithms that the provider supports (never empty). */
  idTokenAlgs: IdTokenAlg[];
  /** RFC 9207: the authorization response carries `iss`. */
  issParameterSupported: boolean;
  tokenAuthMethods: string[];
}

export class DiscoveryError extends Error {
  override name = "DiscoveryError";
}

function endpoint(doc: Record<string, unknown>, key: string, cfg: OidcConfig, required: boolean): string | null {
  const v = doc[key];
  if (v === undefined || v === null) {
    if (required) throw new DiscoveryError(`discovery document has no ${key}`);
    return null;
  }
  if (typeof v !== "string" || v.length > 2048 || checkProviderUrl(v, cfg.allowHttp) === null) {
    throw new DiscoveryError(`discovery ${key} is not an https:// URL`);
  }
  return v;
}

function strings(v: unknown): string[] | null {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null;
}

/** Validates a discovery document against the configuration. */
export function parseDiscovery(json: unknown, cfg: OidcConfig): ProviderMetadata {
  if (json === null || typeof json !== "object" || Array.isArray(json)) throw new DiscoveryError("discovery document is not an object");
  const doc = json as Record<string, unknown>;
  // Exact match, character for character (no trailing-slash or case normalization).
  if (doc.issuer !== cfg.issuer) throw new DiscoveryError("discovery issuer differs from DATABASTION_OIDC_ISSUER_URL");
  const responseTypes = strings(doc.response_types_supported);
  if (responseTypes !== null && !responseTypes.includes("code")) throw new DiscoveryError("provider does not support response_type=code");
  const pkce = strings(doc.code_challenge_methods_supported);
  // Absent: assumed supported (many providers omit it); listed without S256: refused.
  if (pkce !== null && !pkce.includes("S256")) throw new DiscoveryError("provider does not support PKCE S256");
  const responseModes = strings(doc.response_modes_supported);
  if (responseModes !== null && !responseModes.includes("query")) throw new DiscoveryError("provider does not support the query response mode");
  const providerAlgs = strings(doc.id_token_signing_alg_values_supported);
  if (providerAlgs === null) throw new DiscoveryError("discovery document has no id_token_signing_alg_values_supported");
  const idTokenAlgs = cfg.idTokenAlgs.filter((a) => providerAlgs.includes(a));
  if (idTokenAlgs.length === 0) throw new DiscoveryError("no id_token signing algorithm in common with DATABASTION_OIDC_ID_TOKEN_ALGS");
  // Default per OpenID Connect Discovery: client_secret_basic.
  const tokenAuthMethods = strings(doc.token_endpoint_auth_methods_supported) ?? ["client_secret_basic"];
  if (!tokenAuthMethods.includes(cfg.tokenAuthMethod)) throw new DiscoveryError(`provider does not support ${cfg.tokenAuthMethod}`);
  return {
    issuer: cfg.issuer,
    authorizationEndpoint: endpoint(doc, "authorization_endpoint", cfg, true) as string,
    tokenEndpoint: endpoint(doc, "token_endpoint", cfg, true) as string,
    jwksUri: endpoint(doc, "jwks_uri", cfg, true) as string,
    userinfoEndpoint: endpoint(doc, "userinfo_endpoint", cfg, cfg.useUserinfo),
    endSessionEndpoint: endpoint(doc, "end_session_endpoint", cfg, false),
    revocationEndpoint: endpoint(doc, "revocation_endpoint", cfg, false),
    idTokenAlgs,
    issParameterSupported: doc.authorization_response_iss_parameter_supported === true,
    tokenAuthMethods,
  };
}

export function discoveryUrl(issuer: string): string {
  return `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
}

// ------------------------------------------------------------------------------------- JWKS

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  crv?: string;
  [k: string]: unknown;
}

/** Freshness: refetched at least every hour; usable at most `Cache-Control: max-age` (capped 24 h). */
export const JWKS_REFRESH_MS = 3600_000;
export const JWKS_MAX_AGE_CAP_MS = 24 * 3600_000;
/** An unknown `kid` refetches the JWKS at most once per minute; also the minimum lifetime. */
export const JWKS_MIN_REFETCH_MS = 60_000;

interface JwksEntry {
  keys: Jwk[];
  fetchedAt: number;
  /** After this the keys are no longer used (Cache-Control max-age, capped at 24 h, at least 1 min). */
  expiresAt: number;
}

function maxAgeMs(cacheControl: string | string[] | undefined): number | null {
  const v = Array.isArray(cacheControl) ? cacheControl.join(",") : (cacheControl ?? "");
  if (/(^|,)\s*(no-store|no-cache)\s*(,|$)/i.test(v)) return 0;
  const m = /(?:^|,)\s*max-age\s*=\s*"?(\d{1,10})"?/i.exec(v);
  return m ? Number(m[1]) * 1000 : null;
}

export function parseJwks(json: unknown): Jwk[] {
  if (json === null || typeof json !== "object" || !Array.isArray((json as { keys?: unknown }).keys)) throw new DiscoveryError("JWKS has no keys array");
  const keys = (json as { keys: unknown[] }).keys;
  if (keys.length > 100) throw new DiscoveryError("JWKS has too many keys");
  return keys.filter((k): k is Jwk => k !== null && typeof k === "object" && typeof (k as Jwk).kty === "string");
}

// --------------------------------------------------------------------------------- provider

export type Fetcher = typeof providerRequest;

/**
 * One configured provider: metadata (fetched lazily, retried with backoff while the provider is
 * unreachable; the console keeps running and the local login keeps working, decision 11) and the
 * JWKS cache.
 */
export class OidcProvider {
  private metadata: ProviderMetadata | null = null;
  private inflight: Promise<ProviderMetadata> | null = null;
  private nextAttemptAt = 0;
  private failures = 0;
  private jwks: JwksEntry | null = null;
  private jwksInflight: Promise<JwksEntry> | null = null;
  private loggedHosts = false;

  constructor(
    readonly config: OidcConfig,
    readonly fetcher: Fetcher = providerRequest,
    private readonly now: () => number = Date.now,
  ) {}

  get transport(): ProviderTransport {
    return { ca: this.config.ca, allowHttp: this.config.allowHttp };
  }

  /** The provider metadata; throws {@link DiscoveryError} / {@link ProviderHttpError} while unavailable. */
  async getMetadata(): Promise<ProviderMetadata> {
    if (this.metadata) return this.metadata;
    if (this.inflight) return this.inflight;
    if (this.now() < this.nextAttemptAt) throw new DiscoveryError("provider discovery is backing off");
    this.inflight = (async () => {
      try {
        const res = await this.fetcher(discoveryUrl(this.config.issuer), { maxBytes: MAX_DISCOVERY_BYTES }, this.transport);
        const md = parseDiscovery(res.json, this.config);
        this.metadata = md;
        this.failures = 0;
        if (!this.loggedHosts) {
          this.loggedHosts = true;
          const hosts = [...new Set([md.authorizationEndpoint, md.tokenEndpoint, md.jwksUri, md.userinfoEndpoint, md.endSessionEndpoint, md.revocationEndpoint]
            .filter((u): u is string => u !== null)
            .map((u) => new URL(u).host))];
          logger.info({ component: "oidc", issuer_host: new URL(md.issuer).host, hosts, id_token_algs: md.idTokenAlgs }, "OIDC provider discovered");
        }
        return md;
      } catch (err) {
        this.failures++;
        // Backoff: 2 s, doubling, at most 5 min.
        this.nextAttemptAt = this.now() + Math.min(300_000, 2000 * 2 ** Math.min(this.failures - 1, 10));
        logger.warn(
          { component: "oidc", error: err instanceof ProviderHttpError || err instanceof DiscoveryError ? err.message : "error", failures: this.failures },
          "OIDC provider discovery failed: single sign-on unavailable, retrying with backoff",
        );
        throw err;
      } finally {
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  private async fetchJwks(): Promise<JwksEntry> {
    if (this.jwksInflight) return this.jwksInflight;
    this.jwksInflight = (async () => {
      try {
        const md = await this.getMetadata();
        const res = await this.fetcher(md.jwksUri, { maxBytes: MAX_JWKS_BYTES }, this.transport);
        const keys = parseJwks(res.json);
        const at = this.now();
        const declared = maxAgeMs(res.headers["cache-control"]);
        const life = Math.max(JWKS_MIN_REFETCH_MS, Math.min(JWKS_MAX_AGE_CAP_MS, declared ?? JWKS_REFRESH_MS));
        const entry = { keys, fetchedAt: at, expiresAt: at + life };
        this.jwks = entry;
        return entry;
      } finally {
        this.jwksInflight = null;
      }
    })();
    return this.jwksInflight;
  }

  /**
   * Candidate keys for `kid`. Uses the cache while fresh (younger than 1 h and within its
   * Cache-Control lifetime); refetches when stale (a failed refetch keeps the unexpired cache), and
   * on an unknown `kid` at most once per minute.
   */
  async keysFor(kid: string | undefined): Promise<Jwk[]> {
    const now = this.now();
    let entry = this.jwks;
    if (!entry || now >= entry.expiresAt || now - entry.fetchedAt >= JWKS_REFRESH_MS) {
      try {
        entry = await this.fetchJwks();
      } catch (err) {
        if (!entry || this.now() >= entry.expiresAt) throw err;
      }
    }
    const match = (e: JwksEntry) => (kid === undefined ? e.keys : e.keys.filter((k) => k.kid === kid));
    let found = match(entry);
    if (found.length === 0 && kid !== undefined && this.now() - entry.fetchedAt >= JWKS_MIN_REFETCH_MS) {
      entry = await this.fetchJwks();
      found = match(entry);
    }
    return found;
  }
}
