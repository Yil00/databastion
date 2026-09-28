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
import { errorSummary, logger } from "@/lib/logger";
import { writeAudit } from "@/server/audit";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp, ipBucket } from "@/server/request";

import { rateLimited, unauthorized, unavailable } from "./errors";
import { jobHub, REVOKED_CHANNEL } from "./job-hub";

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
 *   the secret still goes through the cache or a full argon2id verification. It is persisted in the
 *   agent row (P1-D), so a console restart does not expose the agent to a lock-out flood.
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

/** Test hook: simulates the expiry of the short verified-secret cache (known-good fingerprints stay). */
export function expireVerifiedCacheForTests(): void {
  verified.delete();
}

export function purgeSecretCache(agentId?: string): void {
  verified.delete(agentId);
}

/**
 * "Known good" fingerprint (persisted in `agents.known_good_fingerprint`, P1-D). Never
 * authenticates: it only exempts the last verified secret from the per-agent failure limit (and
 * routes it to the reserved argon2id pool). Stored at rest, so it is:
 * - domain-separated (no other console value is a SHA-256 over this input);
 * - bound to the stored argon2id hash (a promotion, a lock or a revocation invalidates it);
 * - computed over a 256-bit CSPRNG secret (`AgentSecret`, low-entropy values rejected): no
 *   practical preimage, so it reveals nothing usable about the secret.
 */
export function knownGoodFingerprint(secret: string, storedHash: string): string {
  return sha256Hex(`databastion.agent-known-good.v1\0${storedHash}\0${secret}`);
}

/** Refresh the persisted confirmation time at most this often (one write per agent per hour). */
export const KNOWN_GOOD_REFRESH_MS = 60 * 60 * 1000;

export function isKnownGood(
  row: Pick<AgentRow, "knownGoodFingerprint" | "knownGoodAt">,
  secret: string,
  storedHash: string,
  now = Date.now(),
): boolean {
  if (row.knownGoodFingerprint === null || row.knownGoodAt === null) return false;
  if (now - row.knownGoodAt.getTime() >= KNOWN_GOOD_TTL_MS) return false;
  return safeEqual(row.knownGoodFingerprint, knownGoodFingerprint(secret, storedHash));
}

/** Persists the fingerprint after a full verification (conditional on the hash still current). */
async function rememberKnownGood(row: AgentRow, secret: string, matchedHash: string): Promise<void> {
  const fingerprint = knownGoodFingerprint(secret, matchedHash);
  const fresh =
    row.knownGoodFingerprint !== null &&
    row.knownGoodAt !== null &&
    Date.now() - row.knownGoodAt.getTime() < KNOWN_GOOD_REFRESH_MS &&
    safeEqual(row.knownGoodFingerprint, fingerprint);
  if (fresh) return;
  try {
    await getDb()
      .update(agents)
      .set({ knownGoodFingerprint: fingerprint, knownGoodAt: new Date() })
      .where(
        and(
          eq(agents.id, row.id),
          eq(agents.currentSecretHash, matchedHash),
          isNull(agents.revokedAt),
          isNull(agents.lockedAt),
        ),
      );
  } catch (err) {
    // Best effort: the request is authenticated; only the lock-out exemption is not refreshed.
    logger.warn({ error: errorSummary(err), agentId: row.id }, "known-good fingerprint not persisted");
  }
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
 * `stale`: `S0` presented after the tolerance window (`/rotate` only, see `allowPrevious`).
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
  | {
      ok: true;
      agent: AgentRow;
      via: SecretSlot;
      matchedHash: string;
      stale?: boolean;
      /**
       * `S0` after the window on `/rotate` only: whether `staleCandidate` verified against the current
       * hash (`agent.currentSecretHash`), computed under the same pool slot as `S0` itself.
       * `undefined` when no well-formed candidate was given.
       */
      staleDuplicate?: boolean;
      /**
       * `via: "previous"` only: the failed-attempt reservations taken for this request are kept
       * (a use of `S0` is counted like a failed attempt); `/rotate` gives them back on a duplicate.
       */
      refundAttempt?: () => void;
    }
  | { ok: false; response: Response; staleSecret?: undefined }
  /** `S0` used after the tolerance window: the caller locks the agent (`rotation_conflict`). */
  | { ok: false; staleSecret: true; agentId: string; response?: undefined };

export interface AuthOptions {
  /** `/rotate` only: accept `S0` inside the tolerance window (the handler decides duplicate / conflict). */
  allowPrevious?: boolean;
  /**
   * `/rotate` only (with `allowPrevious`): the `new_secret` of the request body, read before
   * authentication. When the presented secret is a stale `S0`, it is verified against the current
   * hash under the SAME argon2id pool slot and the same counted attempt as `S0` (P1-D): the late
   * retry check costs no verification outside the bounded pools.
   */
  staleCandidate?: string;
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
  const promoted = await getDb().transaction(async (tx) => {
    const rows = await tx
      .update(agents)
      .set({
        currentSecretHash: pendingHash,
        previousSecretHash: currentHash,
        pendingSecretHash: null,
        knownGoodFingerprint: null,
        knownGoodAt: null,
        // L1: every rotation instant uses the console (Node) clock, like the window checks.
        promotedAt: promotedAt === "now" ? new Date() : promotedAt,
        // L4: the deadline of this rotation, answered to late S0 + S1 retries (ADR-0011).
        promotedGraceExpiresAt: sql`${agents.graceExpiresAt}`,
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
    if (rows.length === 0) return false;
    await writeAudit(tx, {
      actorType: trigger === "first_use" ? "agent" : "system",
      actorId: trigger === "first_use" ? agentId : null,
      action: "agent.secret_promote",
      targetType: "agent",
      targetId: agentId,
      details: { trigger },
    });
    return true;
  });
  // The cache entries are bound to the old current hash: they are dead already; purge anyway.
  purgeSecretCache(agentId);
  // Only the request that actually promoted wakes the polls (a lost race changes nothing).
  if (!promoted) return;
  // L2: wake held long-polls here and in every console process; each one re-checks that the secret
  // it was opened with is still the current one (polls opened with S0 are closed).
  jobHub.closeAgent(agentId);
  await getDb().execute(sql`select pg_notify(${REVOKED_CHANNEL}, ${agentId})`);
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
  const exempt = isKnownGood(agent, secret, storedHash);
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
  let stale = false;
  let staleDuplicate: boolean | undefined;
  try {
    for (const candidate of candidates) {
      if (await argon2Verify(candidate[1], secret)) {
        match = candidate;
        break;
      }
    }
    if (match?.[0] === "previous") {
      stale = Date.now() - (agent.promotedAt?.getTime() ?? 0) >= TOLERANCE_WINDOW_MS;
      // P1-D: the late-retry check of a stale S0 on `/rotate` (ADR-0011) runs here, under the slot
      // already held: at most one more verification, never outside the bounded pools, never a 503.
      if (stale && opts.allowPrevious && opts.staleCandidate !== undefined) {
        staleDuplicate = await argon2Verify(storedHash, opts.staleCandidate);
      }
    }
  } finally {
    release();
  }
  if (!match) return denied();
  const [slot, matchedHash] = match;

  if (slot === "previous") {
    // P1-D: the secret is genuine (old) but never authenticates. The attempt stays counted against
    // the per-agent / per-IP limits, so repeated uses of S0 (each one up to three argon2id
    // verifications) are bounded like wrong secrets; `/rotate` refunds it on a duplicate only.
    const refundAttempt = () => {
      refundIp();
      refundAgent();
    };
    // `/rotate` decides itself (ADR-0011): S0 + the promoted S1 is a harmless retry at any time.
    if (opts.allowPrevious) {
      return { ok: true, agent, via: "previous", matchedHash, stale, staleDuplicate, refundAttempt };
    }
    if (stale) return { ok: false, staleSecret: true, agentId };
    return denied();
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
  await rememberKnownGood(fresh, secret, matchedHash);
  return { ok: true, agent: fresh, via: slot, matchedHash };
}
