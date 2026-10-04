import { MAX_TOKEN_BYTES, ProviderHttpError } from "./http";
import { IdTokenError, validateIdToken, type IdTokenClaims } from "./id-token";
import type { OidcProvider, ProviderMetadata } from "./provider";
import { pkceChallenge, type FlowState } from "./state-cookie";

/**
 * OpenID Connect Authorization Code flow with PKCE (S256), confidential client, `query` response
 * mode only (ADR-0038 decision 1). Errors carry closed codes; tokens, codes, the state and the
 * nonce are never logged.
 */

export class OidcFlowError extends Error {
  override name = "OidcFlowError";
  constructor(readonly reason: "token" | "id_token" | "nonce" | "iss" | "provider_error") {
    super(`OIDC flow failed: ${reason}`);
  }
}

export function authorizationUrl(md: ProviderMetadata, p: OidcProvider, s: FlowState): string {
  const u = new URL(md.authorizationEndpoint);
  const q = u.searchParams;
  q.set("response_type", "code");
  q.set("response_mode", "query");
  q.set("client_id", p.config.clientId);
  q.set("redirect_uri", p.config.redirectUri);
  q.set("scope", p.config.scopes.join(" "));
  q.set("state", s.state);
  q.set("nonce", s.nonce);
  q.set("code_challenge", pkceChallenge(s.verifier));
  q.set("code_challenge_method", "S256");
  if (s.purpose === "link") {
    // Security review L1: linking binds an identity to an account, so it needs a fresh
    // authentication at the provider, not a reused provider session (`auth_time` checked).
    q.set("prompt", "login");
    q.set("max_age", "0");
  }
  return u.toString();
}

/** RFC 6749 2.3.1: client id and secret are form-encoded before the Basic encoding. */
function basicAuth(id: string, secret: string): string {
  const enc = (v: string) => encodeURIComponent(v).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${enc(id)}:${enc(secret)}`, "utf8").toString("base64")}`;
}

function clientAuth(p: OidcProvider, form: URLSearchParams): Record<string, string> {
  if (p.config.tokenAuthMethod === "client_secret_post") {
    form.set("client_id", p.config.clientId);
    form.set("client_secret", p.config.clientSecret);
    return {};
  }
  return { Authorization: basicAuth(p.config.clientId, p.config.clientSecret) };
}

export interface TokenSet {
  idToken: string | null;
  accessToken: string | null;
  refreshToken: string | null;
}

async function tokenRequest(p: OidcProvider, md: ProviderMetadata, form: URLSearchParams): Promise<TokenSet> {
  const headers = clientAuth(p, form);
  let json: unknown;
  try {
    ({ json } = await p.fetcher(md.tokenEndpoint, { method: "POST", form, headers, maxBytes: MAX_TOKEN_BYTES }, p.transport));
  } catch (err) {
    if (err instanceof ProviderHttpError) throw new OidcFlowError("token");
    throw err;
  }
  if (json === null || typeof json !== "object") throw new OidcFlowError("token");
  const t = json as Record<string, unknown>;
  if (typeof t.token_type !== "string" || t.token_type.toLowerCase() !== "bearer") throw new OidcFlowError("token");
  const str = (v: unknown) => (typeof v === "string" && v.length > 0 ? v : null);
  return { idToken: str(t.id_token), accessToken: str(t.access_token), refreshToken: str(t.refresh_token) };
}

/** Code exchange, then `id_token` validation (an `id_token` is required). */
export async function exchangeCode(p: OidcProvider, md: ProviderMetadata, code: string, s: FlowState): Promise<{ tokens: TokenSet; claims: IdTokenClaims }> {
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: p.config.redirectUri, code_verifier: s.verifier });
  const tokens = await tokenRequest(p, md, form);
  if (tokens.idToken === null) throw new OidcFlowError("id_token");
  const claims = await checkIdToken(p, md, tokens.idToken, s.nonce);
  return { tokens, claims };
}

export async function checkIdToken(p: OidcProvider, md: ProviderMetadata, idToken: string, nonce: string | null): Promise<IdTokenClaims> {
  try {
    return await validateIdToken(idToken, {
      issuer: md.issuer,
      clientId: p.config.clientId,
      nonce,
      algorithms: md.idTokenAlgs,
      keysFor: (kid) => p.keysFor(kid),
    });
  } catch (err) {
    if (err instanceof IdTokenError) {
      if (err.failure === "nonce") throw new OidcFlowError("nonce");
      if (err.failure === "iss") throw new OidcFlowError("iss");
      throw new OidcFlowError("id_token");
    }
    // JWKS unavailable (transport): not an id_token refusal, not charged to the global budget.
    throw new OidcFlowError("provider_error");
  }
}

/**
 * Userinfo claims merged UNDER those of the `id_token` (`DATABASTION_OIDC_USE_USERINFO=1`): its
 * `sub` must equal the `id_token`'s.
 */
export async function withUserinfo(p: OidcProvider, md: ProviderMetadata, claims: IdTokenClaims, accessToken: string | null): Promise<Record<string, unknown>> {
  if (!p.config.useUserinfo) return claims;
  const info = await fetchUserinfo(p, md, accessToken);
  if (info.sub !== claims.sub) throw new OidcFlowError("id_token");
  return { ...info, ...claims };
}

/**
 * Userinfo claims (same fetcher as every provider call: no redirect, 5 s, 64 KiB cap, TLS rules).
 * The caller binds them to a subject: their `sub` is not checked here.
 */
export async function fetchUserinfo(p: OidcProvider, md: ProviderMetadata, accessToken: string | null): Promise<Record<string, unknown>> {
  if (md.userinfoEndpoint === null || accessToken === null) throw new OidcFlowError("token");
  let json: unknown;
  try {
    ({ json } = await p.fetcher(md.userinfoEndpoint, { headers: { Authorization: `Bearer ${accessToken}` }, maxBytes: MAX_TOKEN_BYTES }, p.transport));
  } catch {
    throw new OidcFlowError("token");
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) throw new OidcFlowError("token");
  return json as Record<string, unknown>;
}

/** Refresh grant. A refreshed `id_token`, when returned, is validated (no nonce, same `sub`). */
export async function refreshTokens(p: OidcProvider, md: ProviderMetadata, refreshToken: string, sub: string): Promise<{ tokens: TokenSet; claims: IdTokenClaims | null }> {
  const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken });
  const tokens = await tokenRequest(p, md, form);
  if (tokens.idToken === null) return { tokens, claims: null };
  const claims = await checkIdToken(p, md, tokens.idToken, null);
  if (claims.sub !== sub) throw new OidcFlowError("id_token");
  return { tokens, claims };
}

/** RFC 7009 revocation of a refresh token, best effort (`false` when it failed). */
export async function revokeRefreshToken(p: OidcProvider, md: ProviderMetadata, refreshToken: string): Promise<boolean> {
  if (md.revocationEndpoint === null) return false;
  const form = new URLSearchParams({ token: refreshToken, token_type_hint: "refresh_token" });
  const headers = clientAuth(p, form);
  try {
    await p.fetcher(md.revocationEndpoint, { method: "POST", form, headers, maxBytes: MAX_TOKEN_BYTES, noBody: true }, p.transport);
    return true;
  } catch {
    return false;
  }
}

/** RP-initiated logout URL (decision 14), or `null` when the provider advertises none. */
export function endSessionUrl(p: OidcProvider, md: ProviderMetadata | null, logoutHint: string | null): string | null {
  if (p.config.signoutRedirectUrl !== null) return p.config.signoutRedirectUrl;
  if (md === null || md.endSessionEndpoint === null) return null;
  const u = new URL(md.endSessionEndpoint);
  u.searchParams.set("client_id", p.config.clientId);
  if (logoutHint !== null) u.searchParams.set("logout_hint", logoutHint);
  u.searchParams.set("post_logout_redirect_uri", `${p.config.publicOrigin}/login`);
  return u.toString();
}
