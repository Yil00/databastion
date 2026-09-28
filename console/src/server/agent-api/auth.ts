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
  hmacSha256Hex,
  serverSubkey,
  sha256Hex,
} from "@/server/crypto";
import { errorSummary, logger } from "@/lib/logger";
import { writeAudit } from "@/server/audit";
import { RateLimiter, type RateLimitDecision } from "@/server/rate-limit";
import { clientIp, ipBucket } from "@/server/request";

import { rateLimited, unauthorized, unavailable } from "./errors";
import { jobHub, REVOKED_CHANNEL } from "./job-hub";

/**
 * Agent authentication (contract `agentSecret` security scheme).
 * - Failed authentications are rate limited per agent id and per source IP BEFORE any argon2id
 *   verification. Each attempt is counted (reserved) synchronously before the verification and
 *   refunded on success, so concurrent requests cannot overrun the limit.
 * - The per-agent limit is keyed by (agent id, source IP) when the IP is known, so an attacker
 *   elsewhere cannot lock a legitimate agent out. The per-IP limits only apply when the IP is known
 *   (no shared global bucket).
 * - Per IP (P1-D M1): only argon2id-backed failures count toward `failuresPerIp`; cheap failures
 *   (bad headers or secret format, unknown or inactive agent, trickled `/rotate` body) count toward
 *   the higher `cheapFailuresPerIp`, which only gates reaching the argon2id path. Neither limit
 *   holds a secret that is in the verified cache or known good (current or pending): agents behind
 *   a shared (NAT / proxy) IP cannot be blocked by junk requests from that IP.
 * - argon2id verifications run under a process-wide concurrency cap (`argon2Gate`, 503 beyond).
 * - Verified secrets are cached for less than 30 s. A cache entry is bound to the stored hash it
 *   was verified against, and the agent row is read on every request, so a revocation, a lock or a
 *   rotation (from any console process) makes the secret unusable immediately; the cache is also
 *   purged explicitly on revocation.
 * - A longer-lived "last verified secret" fingerprint (bound to the stored hash) is used ONLY to
 *   exempt the legitimate secret from the failure limits (per agent and, M1, per IP), never to
 *   authenticate:
 *   the secret still goes through the cache or a full argon2id verification. It is persisted in the
 *   agent row (P1-D), so a console restart does not expose the agent to a lock-out flood.
 */

export type AgentRow = typeof agents.$inferSelect;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BEARER = /^Bearer ([^\s]+)$/;

export const CACHE_TTL_MS = 25_000;
export const KNOWN_GOOD_TTL_MS = 24 * 60 * 60 * 1000;
export const failuresPerAgent = new RateLimiter(10, 5 * 60_000);
/** argon2id-backed failed authentications per source IP (P1-D M1: nothing else counts here). */
export const failuresPerIp = new RateLimiter(50, 5 * 60_000);
/**
 * Cheap failures per source IP (no argon2id: bad headers or format, unknown or inactive agent,
 * trickled `/rotate` body). Higher, and only gates reaching the argon2id path (P1-D M1).
 */
export const cheapFailuresPerIp = new RateLimiter(500, 5 * 60_000);

interface CacheEntry {
  secretSha256: string;
  storedHash: string;
  expiresAt: number;
}
const MAX_CACHE_ENTRIES = 50_000;

class BoundCache {
  private readonly entries = new Map<string, CacheEntry>();
  constructor(private readonly ttlMs: number) {}

  /**
   * Whether `secret` was verified for `agentId` less than the TTL ago, whatever the stored hash
   * (P1-D M1). Never authenticates: only used by `authPrecheck` to skip the failure limits before
   * the agent row is read; `matches` (hash-bound) still runs afterwards.
   */
  holds(agentId: string, secret: string): boolean {
    const entry = this.entries.get(agentId);
    if (!entry || entry.expiresAt <= Date.now()) return false;
    return safeEqual(entry.secretSha256, sha256Hex(secret));
  }

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
  if (agentId === undefined) knownGoodHints.clear();
  else knownGoodHints.delete(agentId);
}

/**
 * "Known good" fingerprint (persisted in `agents.known_good_fingerprint`, P1-D). Never
 * authenticates: it only exempts the last verified secret from the failure limits (and
 * routes it to the reserved argon2id pool). Stored at rest, so it is:
 * - an HMAC-SHA256 keyed by a subkey of the console server key (`DATABASTION_ENCRYPTION_KEY`,
 *   HKDF domain `agent-known-good.v1`): a database dump alone cannot be used to test secrets;
 * - bound to the stored argon2id hash (a promotion, a lock or a revocation invalidates it);
 * - computed over a 256-bit CSPRNG secret (`AgentSecret`, low-entropy values rejected).
 * `null` when the server key is unavailable: nothing is stored and nothing matches (fail closed;
 * the agent then only loses the lock-out exemption). A changed key, or a fingerprint written by an
 * earlier version (plain SHA-256), never matches either.
 */
export const KNOWN_GOOD_DOMAIN = "agent-known-good.v1";

export function knownGoodFingerprint(secret: string, storedHash: string): string | null {
  const key = serverSubkey(KNOWN_GOOD_DOMAIN);
  return key ? hmacSha256Hex(key, `${storedHash}\0${secret}`) : null;
}

function fingerprintMatches(stored: string | null, secret: string, storedHash: string): boolean {
  if (stored === null) return false;
  const expected = knownGoodFingerprint(secret, storedHash);
  return expected !== null && safeEqual(stored, expected);
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
  return fingerprintMatches(row.knownGoodFingerprint, secret, storedHash);
}

/** The pending secret `S1`, registered by the agent authenticated with its current secret (L2). */
export function isKnownGoodPending(
  row: Pick<AgentRow, "knownGoodPendingFingerprint" | "pendingSecretHash">,
  secret: string,
): boolean {
  if (row.pendingSecretHash === null) return false;
  return fingerprintMatches(row.knownGoodPendingFingerprint, secret, row.pendingSecretHash);
}

/** Persists the fingerprint after a full verification (conditional on the hash still current). */
async function rememberKnownGood(row: AgentRow, secret: string, matchedHash: string): Promise<void> {
  const fingerprint = knownGoodFingerprint(secret, matchedHash);
  if (fingerprint === null) return;
  const fresh =
    row.knownGoodFingerprint !== null &&
    row.knownGoodAt !== null &&
    Date.now() - row.knownGoodAt.getTime() < KNOWN_GOOD_REFRESH_MS &&
    safeEqual(row.knownGoodFingerprint, fingerprint);
  if (fresh) return;
  try {
    const knownGoodAt = new Date();
    const updated = await getDb()
      .update(agents)
      .set({ knownGoodFingerprint: fingerprint, knownGoodAt })
      .where(
        and(
          eq(agents.id, row.id),
          eq(agents.currentSecretHash, matchedHash),
          isNull(agents.revokedAt),
          isNull(agents.lockedAt),
        ),
      )
      .returning({ id: agents.id });
    // N4: the in-memory hint follows the row at once (the next request may be a flood's victim).
    if (updated.length > 0) rememberHint({ ...row, knownGoodFingerprint: fingerprint, knownGoodAt }, row.id);
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

/**
 * In-memory copy of the known-good fields of recently read agent rows (P1-D N4). Only a HINT used by
 * `authPrecheck` to exempt a known-good secret from the failure limits without a database read (the
 * row is read on every request anyway, so it stays fresh); it never authenticates, and
 * `authenticateAgent` re-checks everything on the fresh row. Bounded like the verified cache.
 */
type KnownGoodHint = Pick<
  AgentRow,
  "knownGoodFingerprint" | "knownGoodAt" | "knownGoodPendingFingerprint" | "pendingSecretHash"
> & { currentSecretHash: string };
const knownGoodHints = new Map<string, KnownGoodHint>();

function rememberHint(agent: AgentRow | undefined, agentId: string): void {
  knownGoodHints.delete(agentId);
  if (!active(agent) || (agent.knownGoodFingerprint === null && agent.knownGoodPendingFingerprint === null)) return;
  if (knownGoodHints.size >= MAX_CACHE_ENTRIES) {
    const oldest = knownGoodHints.keys().next();
    if (!oldest.done) knownGoodHints.delete(oldest.value);
  }
  knownGoodHints.set(agentId, {
    knownGoodFingerprint: agent.knownGoodFingerprint,
    knownGoodAt: agent.knownGoodAt,
    knownGoodPendingFingerprint: agent.knownGoodPendingFingerprint,
    pendingSecretHash: agent.pendingSecretHash,
    currentSecretHash: agent.currentSecretHash,
  });
}

/** Test hook: simulates a restarted process (no known-good hints in memory). */
export function clearKnownGoodHintsForTests(): void {
  knownGoodHints.clear();
}

/** Database reads made only to decide a failure-limit exemption (test / metrics counter, N4). */
export const exemptionLookupStats = { lookups: 0 };

const loadAgent = async (agentId: string) => {
  const agent = (await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1))[0];
  rememberHint(agent, agentId);
  return agent;
};

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
        // L2: S1's fingerprint (bound to the pending hash, now the current one) carries over.
        knownGoodFingerprint: sql`${agents.knownGoodPendingFingerprint}`,
        knownGoodAt: sql`case when ${agents.knownGoodPendingFingerprint} is null then null else ${new Date().toISOString()}::timestamptz end`,
        knownGoodPendingFingerprint: null,
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

interface Limits {
  ipKey: string | null;
}

const retryAfter = (...decisions: (RateLimitDecision | undefined)[]) =>
  Math.max(1, ...decisions.map((d) => (d?.limited ? d.retryAfterS : 1)));

/**
 * The limits that gate the argon2id path for a non-exempt secret: argon2id-backed failures per IP,
 * cheap failures per IP (M1), argon2id-backed failures per (agent, IP). `null` when none is reached.
 */
function argon2PathLimited(ipKey: string | null, key: string | null): Response | null {
  const byIp = ipKey ? failuresPerIp.check(ipKey) : undefined;
  const cheapByIp = ipKey ? cheapFailuresPerIp.check(ipKey) : undefined;
  const byAgent = key ? failuresPerAgent.check(key) : undefined;
  if (byIp?.limited || cheapByIp?.limited || byAgent?.limited) {
    return rateLimited(retryAfter(byIp, cheapByIp, byAgent));
  }
  return null;
}

/**
 * Cheap failure (no argon2id): counted after the fact against the cheap per-IP counter only (M1):
 * neither `failuresPerIp` nor the per-(agent, IP) limit, so junk requests that need no secret cannot
 * block an agent (not even one not yet known good) behind the same source IP.
 */
function cheapFailure({ ipKey }: Limits): { ok: false; response: Response } {
  if (ipKey) {
    const cheapByIp = cheapFailuresPerIp.check(ipKey);
    if (cheapByIp.limited) return { ok: false, response: rateLimited(cheapByIp.retryAfterS) };
    cheapFailuresPerIp.hit(ipKey);
  }
  return { ok: false, response: unauthorized() };
}

export type Precheck =
  | { ok: true; agentId: string; secret: string; ipKey: string | null; key: string }
  | { ok: false; response: Response };

/**
 * Counts a `/rotate` body that missed its read deadline against the cheap per-IP counter only (never
 * per agent: a trickled body proves nothing about the agent, and must not eat its budget; and no
 * argon2id ran, so not `failuresPerIp` either, M1).
 */
export function countTimedOutBody(ipKey: string | null): void {
  if (ipKey) cheapFailuresPerIp.hit(ipKey);
}

const knownGoodFor = (row: KnownGoodHint, secret: string) =>
  isKnownGood(row, secret, row.currentSecretHash) || isKnownGoodPending(row, secret);

/**
 * Whether the presented secret is exempt from the failure limits (M1, L2), checked in this order:
 * verified less than 25 s ago (cache), known good per the in-memory hint (no database read), then
 * known good per the agent row. N4: that database read is skipped when the source IP is over the
 * cheap per-IP limit, and a read that does not end in an exemption is charged to it, so it cannot
 * be used for uncounted database reads. Never authenticates: `authenticateAgent` still runs the
 * hash-bound cache or a full verification.
 */
async function exemptFromLimits(agentId: string, secret: string, ipKey: string | null): Promise<boolean> {
  if (verified.holds(agentId, secret)) return true;
  const hint = knownGoodHints.get(agentId);
  if (hint && knownGoodFor(hint, secret)) return true;
  if (ipKey && cheapFailuresPerIp.check(ipKey).limited) return false;
  exemptionLookupStats.lookups++;
  const agent = await loadAgent(agentId);
  const exempt = active(agent) && knownGoodFor(agent, secret);
  if (!exempt && ipKey) cheapFailuresPerIp.hit(ipKey);
  return exempt;
}

/**
 * The cheap part of agent authentication (P1-D L1), run before anything expensive (argon2id, and
 * for `/rotate` reading the body): header parsing, secret format, and the per-IP / per-agent failure
 * limits. A secret that is in the verified cache or known good (current or pending, L2) is held by
 * none of them (M1): the agent row is only read in that case (a limit reached), to check the
 * fingerprint.
 */
export async function authPrecheck(req: Request): Promise<Precheck> {
  const ip = clientIp(req);
  const limits: Limits = { ipKey: ip ? ipBucket(ip) : null };
  const headerId = req.headers.get("x-databastion-agent-id");
  const agentId = headerId !== null && UUID.test(headerId) ? headerId : null;
  const secret = BEARER.exec(req.headers.get("authorization") ?? "")?.[1];
  if (agentId === null || secret === undefined) return cheapFailure(limits);
  const key = agentKey(agentId, limits.ipKey);
  if (!AGENT_SECRET_FORMAT.test(secret) || isLowEntropySecret(secret)) return cheapFailure(limits);
  const limited = argon2PathLimited(limits.ipKey, key);
  if (limited && !(await exemptFromLimits(agentId, secret, limits.ipKey))) return { ok: false, response: limited };
  return { ok: true, agentId, secret, ipKey: limits.ipKey, key };
}

export async function authenticateAgent(req: Request, opts: AuthOptions = {}): Promise<AuthResult> {
  const pre = await authPrecheck(req);
  if (!pre.ok) return pre;
  const { agentId, secret, ipKey, key } = pre;
  const limits: Limits = { ipKey };
  const denied = (): AuthResult => ({ ok: false, response: unauthorized() });

  let agent = await loadAgent(agentId);
  if (!active(agent)) return cheapFailure(limits);
  // Grace deadline reached without any use of S1: promotion at the deadline (ADR-0008).
  if (agent.pendingSecretHash && agent.graceExpiresAt && agent.graceExpiresAt.getTime() <= Date.now()) {
    await promotePending(agentId, agent.currentSecretHash, agent.pendingSecretHash, agent.graceExpiresAt, "grace_expired");
    agent = await loadAgent(agentId);
    if (!active(agent)) return cheapFailure(limits);
  }
  const storedHash = agent.currentSecretHash;
  if (verified.matches(agentId, secret, storedHash)) {
    return { ok: true, agent, via: "current", matchedHash: storedHash };
  }

  // Expensive path. Everything up to argon2Verify is synchronous: reservations cannot race.
  // L2: the current secret, or the pending S1 registered by this agent, can be known good.
  const exemptSlot: [SecretSlot, string] | null = isKnownGood(agent, secret, storedHash)
    ? ["current", storedHash]
    : agent.pendingSecretHash && isKnownGoodPending(agent, secret)
      ? ["pending", agent.pendingSecretHash]
      : null;
  const exempt = exemptSlot !== null;
  // M1: a known-good secret is held by no failure limit (it only uses the reserved pool). Any other
  // secret reaches argon2id only below the cheap per-IP limit, and its attempt is reserved against
  // the argon2id-backed per-IP and per-(agent, IP) limits.
  if (!exempt && ipKey && cheapFailuresPerIp.check(ipKey).limited) {
    return { ok: false, response: argon2PathLimited(ipKey, key) ?? rateLimited(1) };
  }
  const refundIp = exempt || !ipKey ? () => undefined : failuresPerIp.reserve(ipKey);
  const refundAgent = exempt ? () => undefined : failuresPerAgent.reserve(key);
  if (!refundIp || !refundAgent) {
    refundIp?.();
    refundAgent?.();
    return { ok: false, response: argon2PathLimited(ipKey, key) ?? rateLimited(1) };
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
  // secret is only tried against the slot its fingerprint is bound to.
  const candidates: [SecretSlot, string][] = exemptSlot ? [exemptSlot] : [["current", storedHash]];
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
