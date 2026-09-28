import { eq } from "drizzle-orm";

import { getDb } from "@/db/client";
import { agents } from "@/db/schema";
import {
  AGENT_SECRET_FORMAT,
  argon2Gate,
  argon2Verify,
  isLowEntropySecret,
  safeEqual,
  sha256Hex,
} from "@/server/crypto";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp } from "@/server/request";

import { rateLimited, unauthorized, unavailable } from "./errors";

/**
 * Agent authentication (contract `agentSecret` security scheme).
 * - Failed authentications are rate limited per agent id and per source IP BEFORE any argon2id
 *   verification. Each attempt is counted (reserved) synchronously before the verification and
 *   refunded on success, so concurrent requests cannot overrun the limit.
 * - The per-agent limit is keyed by (agent id, source IP) when the IP is known, so an attacker
 *   elsewhere cannot lock a legitimate agent out. The per-IP limit only applies when the IP is known
 *   (no shared global bucket).
 * - argon2id verifications run under a process-wide concurrency cap (`argon2Gate`, 503 beyond).
 * - Verified secrets are cached for less than 30 s. A cache entry is bound to the stored hash it
 *   was verified against, and the agent row is read on every request, so a revocation, a lock or a
 *   rotation (from any console process) makes the secret unusable immediately; the cache is also
 *   purged explicitly on revocation.
 * - A longer-lived "last verified secret" fingerprint (SHA-256, bound to the stored hash) is used
 *   ONLY to exempt the legitimate secret from the per-agent failure limit, never to authenticate:
 *   the secret still goes through the cache or a full argon2id verification.
 */

export type AgentRow = typeof agents.$inferSelect;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BEARER = /^Bearer ([^\s]+)$/;

export const CACHE_TTL_MS = 25_000;
export const KNOWN_GOOD_TTL_MS = 24 * 60 * 60 * 1000;
export const failuresPerAgent = new RateLimiter(10, 5 * 60_000);
export const failuresPerIp = new RateLimiter(50, 5 * 60_000);

interface CacheEntry {
  secretSha256: string;
  storedHash: string;
  expiresAt: number;
}
const MAX_CACHE_ENTRIES = 50_000;

class BoundCache {
  private readonly entries = new Map<string, CacheEntry>();
  constructor(private readonly ttlMs: number) {}

  matches(agentId: string, secret: string, storedHash: string): boolean {
    const entry = this.entries.get(agentId);
    if (!entry) return false;
    if (entry.expiresAt <= Date.now() || entry.storedHash !== storedHash) {
      this.entries.delete(agentId);
      return false;
    }
    return safeEqual(entry.secretSha256, sha256Hex(secret));
  }

  remember(agentId: string, secret: string, storedHash: string): void {
    if (this.entries.size >= MAX_CACHE_ENTRIES && !this.entries.has(agentId)) {
      const oldest = this.entries.keys().next();
      if (!oldest.done) this.entries.delete(oldest.value);
    }
    this.entries.set(agentId, {
      secretSha256: sha256Hex(secret),
      storedHash,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  delete(agentId?: string): void {
    if (agentId === undefined) this.entries.clear();
    else this.entries.delete(agentId);
  }
}

/** Authenticates (< 30 s). */
const verified = new BoundCache(CACHE_TTL_MS);
/** Never authenticates: only exempts the legitimate secret from the per-agent failure limit. */
const knownGood = new BoundCache(KNOWN_GOOD_TTL_MS);

/** Test hook: simulates the expiry of the short verified-secret cache (the known-good set stays). */
export function expireVerifiedCacheForTests(): void {
  verified.delete();
}

export function purgeSecretCache(agentId?: string): void {
  verified.delete(agentId);
  knownGood.delete(agentId);
}

export type AuthResult = { ok: true; agent: AgentRow } | { ok: false; response: Response };

const agentKey = (agentId: string, ip: string | null) => (ip ? `${agentId}|${ip}` : agentId);

export async function authenticateAgent(req: Request): Promise<AuthResult> {
  const ip = clientIp(req);
  const headerId = req.headers.get("x-databastion-agent-id");
  const agentId = headerId !== null && UUID.test(headerId) ? headerId : null;
  const secret = BEARER.exec(req.headers.get("authorization") ?? "")?.[1];

  const denied = (): AuthResult => ({ ok: false, response: unauthorized() });
  const limitedResponse = (keys: { agent?: string }): AuthResult | null => {
    const byIp = ip ? failuresPerIp.check(ip) : undefined;
    const byAgent = keys.agent ? failuresPerAgent.check(keys.agent) : undefined;
    if (byIp?.limited || byAgent?.limited) {
      const retry = Math.max(byIp?.retryAfterS ?? 1, byAgent?.retryAfterS ?? 1);
      return { ok: false, response: rateLimited(retry) };
    }
    return null;
  };
  /** Cheap failure (no argon2): counted after the fact. */
  const cheapFailure = (key?: string): AuthResult => {
    const blocked = limitedResponse({ agent: key });
    if (blocked) return blocked;
    if (key) failuresPerAgent.hit(key);
    if (ip) failuresPerIp.hit(ip);
    return denied();
  };

  if (agentId === null || secret === undefined) return cheapFailure();
  const key = agentKey(agentId, ip);
  if (!AGENT_SECRET_FORMAT.test(secret) || isLowEntropySecret(secret)) return cheapFailure(key);

  const [agent] = await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1);
  const storedHash = agent?.currentSecretHash;
  if (!agent || !storedHash || agent.revokedAt !== null || agent.lockedAt !== null) {
    return cheapFailure(key);
  }
  if (verified.matches(agentId, secret, storedHash)) return { ok: true, agent };

  // Expensive path. Everything up to argon2Verify is synchronous: reservations cannot race.
  const exempt = knownGood.matches(agentId, secret, storedHash);
  const refundIp = ip ? failuresPerIp.reserve(ip) : () => undefined;
  const refundAgent = exempt ? () => undefined : failuresPerAgent.reserve(key);
  if (!refundIp || !refundAgent) {
    refundIp?.();
    refundAgent?.();
    return limitedResponse({ agent: exempt ? undefined : key }) ?? { ok: false, response: rateLimited(1) };
  }
  const release = argon2Gate.tryAcquire();
  if (!release) {
    // Not a failed attempt: give the reservations back.
    refundIp();
    refundAgent();
    return { ok: false, response: unavailable() };
  }
  let ok: boolean;
  try {
    ok = await argon2Verify(storedHash, secret);
  } finally {
    release();
  }
  if (!ok) return denied();

  // Re-read: a revocation may have landed during the (slow) verification.
  const [fresh] = await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1);
  if (!fresh || fresh.currentSecretHash !== storedHash || fresh.revokedAt || fresh.lockedAt) {
    return denied();
  }
  refundIp();
  refundAgent();
  verified.remember(agentId, secret, storedHash);
  knownGood.remember(agentId, secret, storedHash);
  return { ok: true, agent: fresh };
}
