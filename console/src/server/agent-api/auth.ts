import { eq } from "drizzle-orm";

import { getDb } from "@/db/client";
import { agents } from "@/db/schema";
import {
  AGENT_SECRET_FORMAT,
  argon2Verify,
  isLowEntropySecret,
  safeEqual,
  sha256Hex,
} from "@/server/crypto";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp } from "@/server/request";

import { rateLimited, unauthorized } from "./errors";

/**
 * Agent authentication (contract `agentSecret` security scheme).
 * - Failed authentications are rate limited per agent id and per source IP, and the limit is
 *   checked BEFORE any argon2id verification.
 * - Verified secrets are cached for less than 30 s. A cache entry is bound to the stored hash it
 *   was verified against, and the agent row is read on every request, so a revocation, a lock or a
 *   rotation (from any console process) makes the secret unusable immediately; the cache is also
 *   purged explicitly on revocation.
 */

export type AgentRow = typeof agents.$inferSelect;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BEARER = /^Bearer ([^\s]+)$/;

export const CACHE_TTL_MS = 25_000;
export const failuresPerAgent = new RateLimiter(10, 5 * 60_000);
export const failuresPerIp = new RateLimiter(50, 5 * 60_000);

interface CacheEntry {
  secretSha256: string;
  storedHash: string;
  expiresAt: number;
}
const verified = new Map<string, CacheEntry>();
const MAX_CACHE_ENTRIES = 50_000;

export function purgeSecretCache(agentId?: string): void {
  if (agentId === undefined) verified.clear();
  else verified.delete(agentId);
}

function cacheHit(agentId: string, secret: string, storedHash: string): boolean {
  const entry = verified.get(agentId);
  if (!entry) return false;
  if (entry.expiresAt <= Date.now() || entry.storedHash !== storedHash) {
    verified.delete(agentId);
    return false;
  }
  return safeEqual(entry.secretSha256, sha256Hex(secret));
}

function remember(agentId: string, secret: string, storedHash: string): void {
  if (verified.size >= MAX_CACHE_ENTRIES) {
    const oldest = verified.keys().next();
    if (!oldest.done) verified.delete(oldest.value);
  }
  verified.set(agentId, {
    secretSha256: sha256Hex(secret),
    storedHash,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
}

export type AuthResult = { ok: true; agent: AgentRow } | { ok: false; response: Response };

function fail(agentKey: string | null, ipKey: string): AuthResult {
  if (agentKey) failuresPerAgent.hit(agentKey);
  failuresPerIp.hit(ipKey);
  return { ok: false, response: unauthorized() };
}

export async function authenticateAgent(req: Request): Promise<AuthResult> {
  const ip = clientIp(req);
  const agentId = req.headers.get("x-databastion-agent-id");
  const secret = BEARER.exec(req.headers.get("authorization") ?? "")?.[1];

  const limited = (): AuthResult | null => {
    const byIp = failuresPerIp.check(ip);
    const byAgent = agentId && UUID.test(agentId) ? failuresPerAgent.check(agentId) : undefined;
    if (byIp.limited || byAgent?.limited) {
      return {
        ok: false,
        response: rateLimited(Math.max(byIp.retryAfterS, byAgent?.retryAfterS ?? 1)),
      };
    }
    return null;
  };

  if (agentId === null || !UUID.test(agentId) || secret === undefined) {
    return limited() ?? fail(null, ip);
  }
  if (!AGENT_SECRET_FORMAT.test(secret) || isLowEntropySecret(secret)) {
    return limited() ?? fail(agentId, ip);
  }

  const [agent] = await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1);
  const storedHash = agent?.currentSecretHash;
  if (!agent || !storedHash || agent.revokedAt !== null || agent.lockedAt !== null) {
    return limited() ?? fail(agentId, ip);
  }
  if (cacheHit(agentId, secret, storedHash)) return { ok: true, agent };

  const blocked = limited();
  if (blocked) return blocked;
  if (!(await argon2Verify(storedHash, secret))) return fail(agentId, ip);

  // Re-read: a revocation may have landed during the (slow) verification.
  const [fresh] = await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1);
  if (!fresh || fresh.currentSecretHash !== storedHash || fresh.revokedAt || fresh.lockedAt) {
    return fail(agentId, ip);
  }
  remember(agentId, secret, storedHash);
  return { ok: true, agent: fresh };
}
