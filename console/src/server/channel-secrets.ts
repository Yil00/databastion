import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import type { Env } from "@/config/env";

import { serverSubkey } from "./crypto";

/**
 * Encryption at rest of the notification channel secrets (P3-C): the SMTP password of an e-mail
 * channel, the signing secret of a webhook channel.
 *
 * - Key: 256-bit HKDF-SHA256 subkey of `DATABASTION_ENCRYPTION_KEY(_FILE)`, domain
 *   `notification-channels.v1` (independent from the other subkeys).
 * - AES-256-GCM, random 96-bit nonce per encryption, 128-bit tag.
 * - AAD: `"databastion.notification-channels.v1" || 0x01 || channel id || 0x00 || type`: a
 *   ciphertext copied onto another channel row (or onto a channel of the other type) does not
 *   decrypt.
 * - Layout: `0x01 || nonce (12) || ciphertext || tag (16)`.
 *
 * Without a usable server key, no secret can be stored (the API answers `409
 * encryption_key_unavailable`) and stored ones cannot be used (the delivery fails with
 * `secret_unavailable`). Nothing here logs its input or output.
 */
export const CHANNEL_SECRETS_DOMAIN = "notification-channels.v1";
const FORMAT_VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const AAD_LABEL = Buffer.from(`databastion.${CHANNEL_SECRETS_DOMAIN}`, "utf8");

export function channelSecretsKey(env: Env = process.env): Buffer | null {
  return serverSubkey(CHANNEL_SECRETS_DOMAIN, env);
}

function aad(channelId: string, type: string): Buffer {
  return Buffer.concat([
    AAD_LABEL,
    Buffer.from([FORMAT_VERSION]),
    Buffer.from(channelId, "utf8"),
    Buffer.from([0]),
    Buffer.from(type, "utf8"),
  ]);
}

export function encryptChannelSecret(key: Buffer, channelId: string, type: string, secret: string): Buffer {
  if (key.length !== 32) throw new Error("channel secrets key must be 256 bits");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad(channelId, type));
  const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from([FORMAT_VERSION]), nonce, body, cipher.getAuthTag()]);
}

/** The secret, or `null` (never throws) on a wrong key, another row's blob or a tampered blob. */
export function decryptChannelSecret(key: Buffer, channelId: string, type: string, blob: Buffer): string | null {
  if (key.length !== 32 || blob.length < 1 + NONCE_BYTES + TAG_BYTES || blob[0] !== FORMAT_VERSION) return null;
  try {
    const nonce = blob.subarray(1, 1 + NONCE_BYTES);
    const tag = blob.subarray(blob.length - TAG_BYTES);
    const body = blob.subarray(1 + NONCE_BYTES, blob.length - TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad(channelId, type));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

export const WEBHOOK_SECRET_PREFIX = "whsec_";

/** A new webhook signing secret: `whsec_` + 43 base64url characters (256 bits from the CSPRNG). */
export function newWebhookSecret(): string {
  return WEBHOOK_SECRET_PREFIX + randomBytes(32).toString("base64url");
}
