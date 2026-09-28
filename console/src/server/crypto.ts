import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

import { hash, verify, type Algorithm } from "@node-rs/argon2";

import { readEnvOrFile, type Env } from "@/config/env";

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

/** Counters for tests and metrics: argon2 operations started, running, and peak concurrency. */
export const argon2Stats = { started: 0, active: 0, maxActive: 0 };

const recentDurations: number[] = [];
const DEFAULT_ARGON2_MS = 50;

/** Median duration of the last 32 argon2id operations (clamped), for timing-equivalent delays. */
export function argon2MedianMs(): number {
  if (recentDurations.length === 0) return DEFAULT_ARGON2_MS;
  const sorted = [...recentDurations].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)] ?? DEFAULT_ARGON2_MS;
  return Math.min(1000, Math.max(10, Math.round(median)));
}

async function tracked<T>(op: () => Promise<T>): Promise<T> {
  argon2Stats.started++;
  argon2Stats.active++;
  argon2Stats.maxActive = Math.max(argon2Stats.maxActive, argon2Stats.active);
  const start = performance.now();
  try {
    return await op();
  } finally {
    argon2Stats.active--;
    recentDurations.push(performance.now() - start);
    if (recentDurations.length > 32) recentDurations.shift();
  }
}

export function argon2Hash(secret: string): Promise<string> {
  return tracked(() => hash(secret, ARGON2_OPTIONS));
}

/** Never throws on a malformed stored hash: returns false. */
export async function argon2Verify(storedHash: string, secret: string): Promise<boolean> {
  try {
    return await tracked(() => verify(storedHash, secret));
  } catch {
    return false;
  }
}

/**
 * Process-wide cap on argon2id operations run on unauthenticated input (login, agent auth).
 * Non-blocking: when every slot is taken the caller answers 503 with `Retry-After` instead of
 * queueing, so the hash cost cannot be turned into a CPU / memory denial of service.
 */
export class Semaphore {
  private active = 0;
  constructor(readonly max: number) {}

  /** Synchronous: returns a release function, or null when saturated. */
  tryAcquire(): (() => void) | null {
    if (this.active >= this.max) return null;
    this.active++;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.active--;
      }
    };
  }

  get inUse(): number {
    return this.active;
  }
}

/**
 * Separate pools, so that one path can never starve another (security re-review N1):
 * - `loginArgon2Gate`: user logins;
 * - `agentArgon2Gate`: agent authentications with an unrecognized secret;
 * - `agentKnownGoodGate`: reserved for agent secrets matching the last verified fingerprint
 *   (the legitimate agent after its 25 s cache expired). Full argon2id still runs.
 */
export const MAX_CONCURRENT_UNAUTHENTICATED_ARGON2 = 8;
export const MAX_CONCURRENT_LOGIN_ARGON2 = 4;
export const MAX_CONCURRENT_KNOWN_GOOD_ARGON2 = 4;
export const loginArgon2Gate = new Semaphore(MAX_CONCURRENT_LOGIN_ARGON2);
export const agentArgon2Gate = new Semaphore(MAX_CONCURRENT_UNAUTHENTICATED_ARGON2);
export const agentKnownGoodGate = new Semaphore(MAX_CONCURRENT_KNOWN_GOOD_ARGON2);
/**
 * `/rotate` (authenticated agents only): hashing the new secret and comparing it with the pending /
 * just-promoted one. Its own small pool, so rotations can neither starve nor be starved by
 * authentication or logins.
 */
export const MAX_CONCURRENT_ROTATE_ARGON2 = 2;
export const rotateArgon2Gate = new Semaphore(MAX_CONCURRENT_ROTATE_ARGON2);
/**
 * `/enroll` (P1-D L4): hashing the new agent secret, after the (cheap) enrollment token lookup. Its
 * own small pool: a burst of enrollments with valid tokens neither runs unbounded argon2id work nor
 * competes with authentication or logins (`503` + `Retry-After` when full, token not consumed).
 */
export const MAX_CONCURRENT_ENROLL_ARGON2 = 2;
export const enrollArgon2Gate = new Semaphore(MAX_CONCURRENT_ENROLL_ARGON2);

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

// ------------------------------------------------------------------------ server key

/** Minimum length of `DATABASTION_ENCRYPTION_KEY` (e.g. `openssl rand -base64 32`: 44 characters). */
export const MIN_SERVER_KEY_LENGTH = 32;

const subkeyCache = new Map<string, { source: string; key: Buffer | null }>();
let warnedServerKey = false;

/**
 * 256-bit subkey derived (HKDF-SHA256) from the console server key `DATABASTION_ENCRYPTION_KEY(_FILE)`
 * for one `domain` (e.g. `agent-known-good.v1`); distinct domains give independent keys. Returns
 * `null` when the key is unset, too short or unreadable: callers must then fail closed. Memoized per
 * configuration (a file is read once). The key is never logged.
 */
export function serverSubkey(domain: string, env: Env = process.env): Buffer | null {
  const source = `${env.DATABASTION_ENCRYPTION_KEY ?? ""}\0${env.DATABASTION_ENCRYPTION_KEY_FILE ?? ""}`;
  const cached = subkeyCache.get(domain);
  if (cached && cached.source === source) return cached.key;
  let key: Buffer | null = null;
  try {
    const ikm = readEnvOrFile("DATABASTION_ENCRYPTION_KEY", env);
    if (ikm !== undefined && ikm.length >= MIN_SERVER_KEY_LENGTH) {
      key = Buffer.from(hkdfSync("sha256", Buffer.from(ikm, "utf8"), "databastion.console.v1", domain, 32));
    }
  } catch {
    key = null;
  }
  if (key === null && !warnedServerKey) {
    warnedServerKey = true;
    // Imported lazily: crypto.ts stays free of the logger for the Edge-safe callers.
    void import("@/lib/logger").then(({ logger }) =>
      logger.warn(
        `DATABASTION_ENCRYPTION_KEY(_FILE) unset, shorter than ${MIN_SERVER_KEY_LENGTH} characters or unreadable: features keyed by it are disabled (fail closed)`,
      ),
    );
  }
  subkeyCache.set(domain, { source, key });
  return key;
}

/** Hex HMAC-SHA256 of `value` under `key`. */
export function hmacSha256Hex(key: Buffer, value: string): string {
  return createHmac("sha256", key).update(value, "utf8").digest("hex");
}
