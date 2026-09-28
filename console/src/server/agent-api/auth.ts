import { and, eq, isNull, sql } from "drizzle-orm";

import { getDb } from "@/db/client";
import { agents } from "@/db/schema";
import {
  AGENT_SECRET_FORMAT,
  agentArgon2Gate,
  agentKnownGoodGate,
  argon2Verify,
  isLowEntropySecret,
  safeEqual,
  sha256Hex,
} from "@/server/crypto";
import { writeAudit } from "@/server/audit";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp, ipBucket } from "@/server/request";

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

/** Agent ids with an unrecognized-secret verification in flight (bounded by the pool size). */
const unrecognizedInFlight = new Set<string>();

/**
 * Rotation (ADR-0008, ADR-0010): after promotion, the previous secret `S0` is answered `401` without
 * incident during this window (requests in flight during the switch); `/rotate` retries with `S0`
 * and the same `S1` inside it are duplicates. Any use of `S0` after it is a `rotation_conflict`.
 */
export const TOLERANCE_WINDOW_MS = 60_000;

/**
 * Which stored secret the presented one matched:
 * - `current`: the current secret (which is `S0` while a rotation is pending);
 * - `pending`: the pending `S1`, promoted by this very request (first successful use);
 * - `previous`: `S0` within the tolerance window after promotion. Only returned to `/rotate`
 *   (`allowPrevious`); every other endpoint answers `401`.
 * `matchedHash` is the stored hash the secret was verified against, so a handler can re-check the
 * slot against a fresh row (a promotion may land between authentication and the handler).
 */
export type SecretSlot = "current" | "pending" | "previous";

export type AuthResult =
  | { ok: true; agent: AgentRow; via: SecretSlot; matchedHash: string }
  | { ok: false; response: Response; staleSecret?: undefined }
  /** `S0` used after the tolerance window: the caller locks the agent (`rotation_conflict`). */
  | { ok: false; staleSecret: true; agentId: string; response?: undefined };

export interface AuthOptions {
  /** `/rotate` only: accept `S0` inside the tolerance window (the handler decides duplicate / conflict). */
  allowPrevious?: boolean;
}

const agentKey = (agentId: string, ip: string | null) => (ip ? `${agentId}|${ip}` : agentId);

const loadAgent = async (agentId: string) =>
  (await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1))[0];

const active = (a: AgentRow | undefined): a is AgentRow & { currentSecretHash: string } =>
  !!a && !!a.currentSecretHash && a.revokedAt === null && a.lockedAt === null;

/**
 * Promotes the pending secret (conditional on the row still holding `pendingHash` and
 * `currentHash`, so concurrent promotions are idempotent). `S0` becomes the previous secret: it
 * never authenticates again, it is only kept to tell a retry inside the window from a conflict,
 * and to detect a later use of `S0` (replaced at the next promotion).
 */
export async function promotePending(
  agentId: string,
  currentHash: string,
  pendingHash: string,
  promotedAt: Date | "now",
  trigger: "first_use" | "grace_expired",
): Promise<void> {
  await getDb().transaction(async (tx) => {
    const rows = await tx
      .update(agents)
      .set({
        currentSecretHash: pendingHash,
        previousSecretHash: currentHash,
        pendingSecretHash: null,
        promotedAt: promotedAt === "now" ? sql`now()` : promotedAt,
      })
      .where(
        and(
          eq(agents.id, agentId),
          eq(agents.currentSecretHash, currentHash),
          eq(agents.pendingSecretHash, pendingHash),
          isNull(agents.revokedAt),
          isNull(agents.lockedAt),
        ),
      )
      .returning({ id: agents.id });
    if (rows.length === 0) return;
    await writeAudit(tx, {
      actorType: trigger === "first_use" ? "agent" : "system",
      actorId: trigger === "first_use" ? agentId : null,
      action: "agent.secret_promote",
      targetType: "agent",
      targetId: agentId,
      details: { trigger },
    });
  });
  // The cache entries are bound to the old current hash: they are dead already; purge anyway.
  purgeSecretCache(agentId);
}

export async function authenticateAgent(req: Request, opts: AuthOptions = {}): Promise<AuthResult> {
  const ip = clientIp(req);
  const ipKey = ip ? ipBucket(ip) : null;
  const headerId = req.headers.get("x-databastion-agent-id");
  const agentId = headerId !== null && UUID.test(headerId) ? headerId : null;
  const secret = BEARER.exec(req.headers.get("authorization") ?? "")?.[1];

  const denied = (): AuthResult => ({ ok: false, response: unauthorized() });
  const limitedResponse = (keys: { agent?: string }): AuthResult | null => {
    const byIp = ipKey ? failuresPerIp.check(ipKey) : undefined;
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
    if (ipKey) failuresPerIp.hit(ipKey);
    return denied();
  };

  if (agentId === null || secret === undefined) return cheapFailure();
  const key = agentKey(agentId, ipKey);
  if (!AGENT_SECRET_FORMAT.test(secret) || isLowEntropySecret(secret)) return cheapFailure(key);

  let agent = await loadAgent(agentId);
  if (!active(agent)) return cheapFailure(key);
  // Grace deadline reached without any use of S1: promotion at the deadline (ADR-0008).
  if (agent.pendingSecretHash && agent.graceExpiresAt && agent.graceExpiresAt.getTime() <= Date.now()) {
    await promotePending(agentId, agent.currentSecretHash, agent.pendingSecretHash, agent.graceExpiresAt, "grace_expired");
    agent = await loadAgent(agentId);
    if (!active(agent)) return cheapFailure(key);
  }
  const storedHash = agent.currentSecretHash;
  if (verified.matches(agentId, secret, storedHash)) {
    return { ok: true, agent, via: "current", matchedHash: storedHash };
  }

  // Expensive path. Everything up to argon2Verify is synchronous: reservations cannot race.
  const exempt = knownGood.matches(agentId, secret, storedHash);
  const refundIp = ipKey ? failuresPerIp.reserve(ipKey) : () => undefined;
  const refundAgent = exempt ? () => undefined : failuresPerAgent.reserve(key);
  if (!refundIp || !refundAgent) {
    refundIp?.();
    refundAgent?.();
    return limitedResponse({ agent: exempt ? undefined : key }) ?? { ok: false, response: rateLimited(1) };
  }
  // N1: the legitimate secret uses a reserved pool that floods of wrong secrets cannot fill.
  // L1: in the shared pool, at most one verification in flight per agent id (fair allocation).
  const fair = exempt ? true : !unrecognizedInFlight.has(agentId);
  const gate = fair ? (exempt ? agentKnownGoodGate : agentArgon2Gate).tryAcquire() : null;
  if (!exempt && gate) unrecognizedInFlight.add(agentId);
  const release = gate
    ? () => {
        gate();
        if (!exempt) unrecognizedInFlight.delete(agentId);
      }
    : null;
  if (!release) {
    // Not a failed attempt: give the reservations back.
    refundIp();
    refundAgent();
    return { ok: false, response: unavailable() };
  }
  // Candidates, in order, under the same pool slot (one attempt for the rate limits). A known-good
  // secret is the current one by construction: nothing else to try.
  const candidates: [SecretSlot, string][] = [["current", storedHash]];
  if (!exempt && agent.pendingSecretHash) candidates.push(["pending", agent.pendingSecretHash]);
  if (!exempt && agent.previousSecretHash) candidates.push(["previous", agent.previousSecretHash]);
  let match: [SecretSlot, string] | undefined;
  try {
    for (const candidate of candidates) {
      if (await argon2Verify(candidate[1], secret)) {
        match = candidate;
        break;
      }
    }
  } finally {
    release();
  }
  if (!match) return denied();
  const [slot, matchedHash] = match;

  if (slot === "previous") {
    // Not a guessing attempt: the secret is genuine (old). Never counted against the limits.
    refundIp();
    refundAgent();
    const promotedAt = agent.promotedAt?.getTime() ?? 0;
    if (Date.now() - promotedAt >= TOLERANCE_WINDOW_MS) return { ok: false, staleSecret: true, agentId };
    if (!opts.allowPrevious) return denied();
    return { ok: true, agent, via: "previous", matchedHash };
  }
  if (slot === "pending") {
    await promotePending(agentId, storedHash, matchedHash, "now", "first_use");
  }

  // Re-read: a revocation may have landed during the (slow) verification.
  const fresh = await loadAgent(agentId);
  if (!active(fresh) || fresh.currentSecretHash !== matchedHash) return denied();
  refundIp();
  refundAgent();
  verified.remember(agentId, secret, matchedHash);
  knownGood.remember(agentId, secret, matchedHash);
  return { ok: true, agent: fresh, via: slot, matchedHash };
}
