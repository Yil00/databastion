import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import type { Env } from "@/config/env";
import { serverSubkey } from "@/server/crypto";

/**
 * Refresh tokens at rest (ADR-0038 decision 13, `DATABASTION_OIDC_USE_REFRESH_TOKEN=1` only):
 * AES-256-GCM under the HKDF subkey `oidc-tokens.v1`, random 96-bit nonce, AAD = label || format ||
 * session token hash, so a ciphertext copied onto another session row does not decrypt. Access
 * tokens and ID tokens are never stored. Nothing here logs its input or output.
 */
export const TOKENS_DOMAIN = "oidc-tokens.v1";
const FORMAT = 0x01;
const LABEL = Buffer.from("databastion.oidc-tokens.v1", "utf8");
const MAX_REFRESH_TOKEN_LENGTH = 16 * 1024;

const aad = (sessionHash: string) => Buffer.concat([LABEL, Buffer.from([FORMAT]), Buffer.from(sessionHash, "utf8")]);

/** `null` when the key is unavailable or the token is unreasonably long (then no refresh). */
export function encryptRefreshToken(token: string, sessionHash: string, env: Env = process.env): Buffer | null {
  const key = serverSubkey(TOKENS_DOMAIN, env);
  if (key === null || token.length === 0 || token.length > MAX_REFRESH_TOKEN_LENGTH) return null;
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  c.setAAD(aad(sessionHash));
  const body = Buffer.concat([c.update(token, "utf8"), c.final()]);
  return Buffer.concat([Buffer.from([FORMAT]), nonce, body, c.getAuthTag()]);
}

/** The token, or `null` (never throws) on a wrong key, another session's blob or tampering. */
export function decryptRefreshToken(blob: Buffer, sessionHash: string, env: Env = process.env): string | null {
  const key = serverSubkey(TOKENS_DOMAIN, env);
  if (key === null || blob.length < 1 + 12 + 16 || blob[0] !== FORMAT) return null;
  try {
    const d = createDecipheriv("aes-256-gcm", key, blob.subarray(1, 13), { authTagLength: 16 });
    d.setAAD(aad(sessionHash));
    d.setAuthTag(blob.subarray(blob.length - 16));
    return Buffer.concat([d.update(blob.subarray(13, blob.length - 16)), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}
