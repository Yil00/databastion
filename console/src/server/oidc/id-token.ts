import { compactVerify, decodeProtectedHeader, importJWK } from "jose";

import type { Jwk } from "./provider";

/**
 * `id_token` validation (ADR-0038 decision 4). Library: `jose` (MIT, no dependencies) for the JWS
 * signature check only; every header and claim rule is checked here:
 * - algorithm in the allowed set (configured ∩ provider's); `none` and `HS*` never;
 * - the JWK selected by `kid` has a `kty` (and `crv`) matching the algorithm, an `alg` equal to it
 *   when present, and `use` absent or `sig`; without a `kid`, only a JWKS with exactly one
 *   matching key is accepted;
 * - `iss` equal to the issuer, `aud` containing the client id (and `azp` equal to it when `aud`
 *   has several values, or whenever `azp` is present), `exp` in the future, `nbf` (when present)
 *   in the past, `iat` not in the future and at most 10 minutes old, 60 s clock skew, `nonce` equal
 *   to the one sent (when expected), `sub` a non-empty string.
 */

export const CLOCK_SKEW_S = 60;
export const MAX_IAT_AGE_S = 600;
const MAX_ID_TOKEN_LENGTH = 32 * 1024;

export type IdTokenFailure = "format" | "alg" | "key" | "signature" | "iss" | "aud" | "azp" | "exp" | "nbf" | "iat" | "nonce" | "sub";

export class IdTokenError extends Error {
  override name = "IdTokenError";
  constructor(readonly failure: IdTokenFailure) {
    super(`id_token rejected: ${failure}`);
  }
}

export interface IdTokenExpectations {
  issuer: string;
  clientId: string;
  /** `null`: no nonce expected (a refreshed `id_token`, OIDC Core 12.2). */
  nonce: string | null;
  algorithms: readonly string[];
  keysFor(kid: string | undefined): Promise<Jwk[]>;
  /** Seconds since the epoch. */
  nowS?: number;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  sid?: string;
  [claim: string]: unknown;
}

const KTY: Record<string, { kty: string; crv?: string }> = {
  RS256: { kty: "RSA" },
  RS384: { kty: "RSA" },
  RS512: { kty: "RSA" },
  PS256: { kty: "RSA" },
  PS384: { kty: "RSA" },
  PS512: { kty: "RSA" },
  ES256: { kty: "EC", crv: "P-256" },
  ES384: { kty: "EC", crv: "P-384" },
  ES512: { kty: "EC", crv: "P-521" },
  EdDSA: { kty: "OKP", crv: "Ed25519" },
};

function keyMatches(k: Jwk, alg: string): boolean {
  const want = KTY[alg];
  if (!want || k.kty !== want.kty) return false;
  if (want.crv !== undefined && k.crv !== want.crv) return false;
  if (k.alg !== undefined && k.alg !== alg) return false;
  if (k.use !== undefined && k.use !== "sig") return false;
  if (k.d !== undefined) return false; // never a private key
  return true;
}

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

export async function validateIdToken(token: string, x: IdTokenExpectations): Promise<IdTokenClaims> {
  if (typeof token !== "string" || token.length > MAX_ID_TOKEN_LENGTH || token.split(".").length !== 3) throw new IdTokenError("format");
  let header: { alg?: unknown; kid?: unknown; crit?: unknown };
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new IdTokenError("format");
  }
  const alg = header.alg;
  if (typeof alg !== "string" || alg === "none" || /^HS/i.test(alg) || !x.algorithms.includes(alg) || !(alg in KTY)) {
    throw new IdTokenError("alg");
  }
  if (header.crit !== undefined) throw new IdTokenError("format");
  if (header.kid !== undefined && (typeof header.kid !== "string" || header.kid.length > 256)) throw new IdTokenError("key");
  const kid = header.kid as string | undefined;
  const candidates = (await x.keysFor(kid)).filter((k) => keyMatches(k, alg));
  // Without a `kid`, a single matching key only (no trial of several keys).
  if (candidates.length !== 1) throw new IdTokenError("key");
  let payloadBytes: Uint8Array;
  try {
    const key = await importJWK(candidates[0] as Parameters<typeof importJWK>[0], alg);
    ({ payload: payloadBytes } = await compactVerify(token, key, { algorithms: [alg] }));
  } catch {
    throw new IdTokenError("signature");
  }
  let claims: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    claims = parsed as Record<string, unknown>;
  } catch {
    throw new IdTokenError("format");
  }
  const now = x.nowS ?? Math.floor(Date.now() / 1000);
  if (claims.iss !== x.issuer) throw new IdTokenError("iss");
  const aud = claims.aud;
  const audList = typeof aud === "string" ? [aud] : Array.isArray(aud) && aud.every((a) => typeof a === "string") ? (aud as string[]) : null;
  if (audList === null || !audList.includes(x.clientId)) throw new IdTokenError("aud");
  if ((audList.length > 1 || claims.azp !== undefined) && claims.azp !== x.clientId) throw new IdTokenError("azp");
  if (!isNum(claims.exp) || claims.exp <= now - CLOCK_SKEW_S) throw new IdTokenError("exp");
  if (claims.nbf !== undefined && (!isNum(claims.nbf) || claims.nbf > now + CLOCK_SKEW_S)) throw new IdTokenError("nbf");
  if (!isNum(claims.iat) || claims.iat > now + CLOCK_SKEW_S || claims.iat < now - MAX_IAT_AGE_S - CLOCK_SKEW_S) throw new IdTokenError("iat");
  if (x.nonce !== null && claims.nonce !== x.nonce) throw new IdTokenError("nonce");
  if (typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 255) throw new IdTokenError("sub");
  if (claims.sid !== undefined && (typeof claims.sid !== "string" || claims.sid.length < 1 || claims.sid.length > 255)) delete claims.sid;
  return claims as IdTokenClaims;
}
