import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import type { Env } from "@/config/env";

import { serverSubkey } from "./crypto";

/**
 * Encryption at rest of masked samples (docs/05-security.md, "At rest"; P2-D).
 *
 * - Key: 256-bit HKDF-SHA256 subkey of `DATABASTION_ENCRYPTION_KEY(_FILE)`, domain
 *   `masked-samples.v1` (independent from the other subkeys of the server key).
 * - AES-256-GCM, random 96-bit nonce per encryption, 128-bit tag.
 * - AAD: `"databastion.masked-samples.v1" || 0x01 (format version) || finding id`, so a ciphertext
 *   copied onto another finding row, or relabelled with another format version, does not decrypt
 *   (a tampered or swapped row is detected, not shown).
 * - Stored layout: `0x01 || nonce (12) || ciphertext || tag (16)`; the plaintext is the JSON array
 *   of the masked samples of the latest scan.
 *
 * Without a usable server key nothing is encrypted and the caller stores no samples at all (fail
 * closed). Nothing here logs its input or output.
 */

export const MASKED_SAMPLES_DOMAIN = "masked-samples.v1";
const FORMAT_VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** Contract bounds (`Finding.masked_samples`: at most 5 items of at most 128 characters). */
const MAX_SAMPLES = 5;
const MAX_SAMPLE_LENGTH = 128;

/** The masked-samples subkey, or `null` when the server key is unavailable (fail closed). */
export function maskedSamplesKey(env: Env = process.env): Buffer | null {
  return serverSubkey(MASKED_SAMPLES_DOMAIN, env);
}

const AAD_LABEL = Buffer.from(`databastion.${MASKED_SAMPLES_DOMAIN}`, "utf8");

/** `label || format version || finding id`: binds the ciphertext to its row and its format. */
function aad(findingId: string): Buffer {
  return Buffer.concat([AAD_LABEL, Buffer.from([FORMAT_VERSION]), Buffer.from(findingId, "utf8")]);
}

export function encryptMaskedSamples(key: Buffer, findingId: string, samples: readonly string[]): Buffer {
  if (key.length !== 32) throw new Error("masked samples key must be 256 bits");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad(findingId));
  const body = Buffer.concat([cipher.update(JSON.stringify(samples), "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from([FORMAT_VERSION]), nonce, body, cipher.getAuthTag()]);
}

/**
 * Decrypts the samples of `findingId`. Returns `null` (never throws) on a wrong key, another
 * finding's ciphertext, a tampered or malformed blob, or a plaintext outside the contract bounds.
 */
export function decryptMaskedSamples(key: Buffer, findingId: string, blob: Buffer): string[] | null {
  if (key.length !== 32 || blob.length < 1 + NONCE_BYTES + TAG_BYTES || blob[0] !== FORMAT_VERSION) {
    return null;
  }
  try {
    const nonce = blob.subarray(1, 1 + NONCE_BYTES);
    const tag = blob.subarray(blob.length - TAG_BYTES);
    const body = blob.subarray(1 + NONCE_BYTES, blob.length - TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad(findingId));
    decipher.setAuthTag(tag);
    const text = Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
    const parsed: unknown = JSON.parse(text);
    if (
      !Array.isArray(parsed) ||
      parsed.length > MAX_SAMPLES ||
      !parsed.every((s): s is string => typeof s === "string" && s.length <= MAX_SAMPLE_LENGTH)
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}
