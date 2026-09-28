import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { hash, verify, type Algorithm } from "@node-rs/argon2";

/**
 * Secret primitives. Nothing here logs its input.
 *
 * argon2id library: `@node-rs/argon2` (pinned in package.json). It ships prebuilt N-API binaries as
 * per-platform optional dependencies, so it needs no install script (pnpm 10 blocks them by
 * default) and no build toolchain in the Docker image; hashing runs off the event loop.
 */

/** OWASP 2024 minimum for argon2id: m = 19 MiB, t = 2, p = 1. */
const ARGON2_OPTIONS = {
  // `Algorithm.Argon2id` (an ambient const enum, not importable under isolatedModules).
  algorithm: 2 as Algorithm,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

export function argon2Hash(secret: string): Promise<string> {
  return hash(secret, ARGON2_OPTIONS);
}

/** Never throws on a malformed stored hash: returns false. */
export async function argon2Verify(storedHash: string, secret: string): Promise<boolean> {
  try {
    return await verify(storedHash, secret);
  } catch {
    return false;
  }
}

let dummyHash: Promise<string> | undefined;

/** Burns one verification when no hash exists (unknown user), to flatten timing differences. */
export async function argon2VerifyDummy(secret: string): Promise<void> {
  dummyHash ??= argon2Hash(randomToken(""));
  await argon2Verify(await dummyHash, secret);
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** `prefix` + 43 base64url characters (256 bits from the CSPRNG). */
export function randomToken(prefix: string): string {
  return prefix + randomBytes(32).toString("base64url");
}

export const ENROLLMENT_TOKEN_PREFIX = "dbe_";
export const AGENT_SECRET_PREFIX = "dbs_";

export const newEnrollmentToken = () => randomToken(ENROLLMENT_TOKEN_PREFIX);
export const newAgentSecret = () => randomToken(AGENT_SECRET_PREFIX);

export const AGENT_SECRET_FORMAT = /^dbs_[A-Za-z0-9_-]{43}$/;
export const ENROLLMENT_TOKEN_FORMAT = /^dbe_[A-Za-z0-9_-]{43}$/;

/**
 * Contract `AgentSecret`: obviously low-entropy values (fewer than 16 distinct characters in the
 * 43-character body) are rejected. A CSPRNG body has ~ 31 distinct characters on average; fewer
 * than 16 happens with negligible probability.
 */
export const MIN_DISTINCT_SECRET_CHARS = 16;

export function isLowEntropySecret(secret: string): boolean {
  const body = secret.slice(AGENT_SECRET_PREFIX.length);
  return new Set(body).size < MIN_DISTINCT_SECRET_CHARS;
}

/** Constant-time comparison of two hex digests / strings of equal meaning. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
