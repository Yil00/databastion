import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditLog, jobs, securityEvents } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import {
  agentArgon2Gate,
  argon2Stats,
  loginArgon2Gate,
  MAX_CONCURRENT_ROTATE_ARGON2,
  newAgentSecret,
  rotateArgon2Gate,
} from "@/server/crypto";
import { claimJobs } from "@/server/jobs";
import {
  requestSecretRotation,
  rotatePerAgent,
  rotateStats,
  rotationBlocked,
  staleRetriesPerAgent,
  staleRotateRetry,
} from "@/server/rotation";
import { revokeAgent } from "@/server/agents";
import { agentHeaders, BASE } from "@/test/helpers";
import { ipBucket } from "@/server/request";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, expectConformingError } from "@/test/helpers";

import {
  expireVerifiedCacheForTests,
  failuresPerAgent,
  failuresPerIp,
  cheapFailuresPerIp,
  isKnownGood,
  knownGoodFingerprint,
  TOLERANCE_WINDOW_MS,
} from "./auth";
import { handleHeartbeat, handlePollJobs, handleRotate, pollClock, rotateBodyDeadline } from "./handlers";
import { jobHub } from "./job-hub";

type Creds = { agentId: string; secret: string };

const HEARTBEAT = () => ({
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 1,
  connectors: ["postgres"],
  targets: [],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
});

const rotate = (auth: Creds, body: Record<string, unknown>) =>
  handleRotate(agentRequest("POST", "/rotate", { auth, body }));
const heartbeat = (auth: Creds) => handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT() }));

const row = async (agentId: string) =>
  (await getDb().select().from(agents).where(eq(agents.id, agentId)).limit(1))[0];

async function shiftPromotion(agentId: string, msAgo: number): Promise<void> {
  await getDb()
    .update(agents)
    .set({ promotedAt: new Date(Date.now() - msAgo) })
    .where(eq(agents.id, agentId));
}

async function expectLocked(agentId: string): Promise<void> {
  const a = await row(agentId);
  expect(a?.status).toBe("locked");
  expect(a?.lockedAt).not.toBeNull();
  expect(a?.currentSecretHash).toBeNull();
  expect(a?.pendingSecretHash).toBeNull();
  expect(a?.previousSecretHash).toBeNull();
  expect(a?.knownGoodFingerprint).toBeNull();
  expect(a?.knownGoodAt).toBeNull();
  const events = await getDb().select().from(securityEvents).where(eq(securityEvents.agentId, agentId));
  expect(events).toHaveLength(1);
  expect(events[0]?.kind).toBe("agent.rotation_conflict");
  const audit = await getDb()
    .select()
    .from(auditLog)
    .where(and(eq(auditLog.targetId, agentId), eq(auditLog.action, "agent.rotation_conflict")));
  expect(audit).toHaveLength(1);
}

async function expectNotLocked(agentId: string): Promise<void> {
  const a = await row(agentId);
  expect(a?.lockedAt).toBeNull();
  const events = await getDb().select().from(securityEvents).where(eq(securityEvents.agentId, agentId));
  expect(events).toHaveLength(0);
}

/** Registers S1 and promotes it by a first use; returns S0 / S1 credentials. */
async function rotated(): Promise<{ s0: Creds; s1: Creds }> {
  const s0 = await enroll();
  const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
  expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
  expect((await heartbeat(s1)).status).toBe(200);
  return { s0, s1 };
}

describe.skipIf(!hasDb)("POST /rotate (ADR-0008, ADR-0010)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => {
    pollClock.msPerSecond = 1000;
    await teardown?.();
  });
  beforeEach(() => {
    failuresPerAgent.clear();
    failuresPerIp.clear();
    cheapFailuresPerIp.clear();
    rotatePerAgent.clear();
    staleRetriesPerAgent.clear();
  });

  it("registers the new secret as a pending argon2id hash, 300 s grace, no-store, audited", async () => {
    const s0 = await enroll();
    const s1 = newAgentSecret();
    const before = Date.now();
    const res = await rotate(s0, { new_secret: s1 });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const text = await res.text();
    expect(text).not.toContain(s1);
    const body = JSON.parse(text) as { grace_expires_at: string; duplicate: boolean };
    expect(validateSchema("RotateResponse", body).ok).toBe(true);
    expect(body.duplicate).toBe(false);
    const grace = Date.parse(body.grace_expires_at);
    expect(grace).toBeGreaterThanOrEqual(before + 299_000);
    expect(grace).toBeLessThanOrEqual(Date.now() + 301_000);
    const a = await row(s0.agentId);
    expect(a?.pendingSecretHash).toMatch(/^\$argon2id\$/);
    expect(JSON.stringify(a)).not.toContain(s1);
    const audit = await getDb()
      .select()
      .from(auditLog)
      .where(and(eq(auditLog.targetId, s0.agentId), eq(auditLog.action, "agent.rotate")));
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit)).not.toContain(s1);
    // S0 is still the current secret while S1 is pending.
    expect((await heartbeat(s0)).status).toBe(200);
  });

  it("answers an idempotent retry (same S1 with S0) with duplicate and the unchanged deadline", async () => {
    const s0 = await enroll();
    const s1 = newAgentSecret();
    const first = (await (await rotate(s0, { new_secret: s1 })).json()) as { grace_expires_at: string };
    await new Promise((r) => setTimeout(r, 20));
    const retry = await rotate(s0, { new_secret: s1 });
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ grace_expires_at: first.grace_expires_at, duplicate: true });
    await expectNotLocked(s0.agentId);
  });

  it("rejects a malformed, low-entropy or current new secret with invalid_secret (no lock)", async () => {
    const s0 = await enroll();
    for (const bad of ["dbs_short", `dbs_${"A".repeat(43)}`, `dbs_${"AbCdEfGh".repeat(5)}abc`, s0.secret]) {
      const res = await rotate(s0, { new_secret: bad });
      expect(res.status).toBe(400);
      const body = await expectConformingError(res, { new_secret: bad });
      expect(body.code).toBe("invalid_secret");
    }
    // Unknown field: plain invalid_request (schema), never stored.
    const extra = await rotate(s0, { new_secret: newAgentSecret(), other: 1 });
    expect(extra.status).toBe(400);
    expect(((await extra.json()) as { code: string }).code).toBe("invalid_request");
    expect((await row(s0.agentId))?.pendingSecretHash).toBeNull();
    await expectNotLocked(s0.agentId);
  });

  it("answers 404 for a job_id that is not a rotate job of this agent", async () => {
    const s0 = await enroll();
    const res = await rotate(s0, { new_secret: newAgentSecret(), job_id: "01890a5d-ac96-774b-bcce-b302099a8057" });
    expect(res.status).toBe(404);
  });

  it("promotes S1 on its first successful use; S0 inside the window gets 401 without incident", async () => {
    const { s0, s1 } = await rotated();
    const a = await row(s0.agentId);
    expect(a?.pendingSecretHash).toBeNull();
    expect(a?.previousSecretHash).toMatch(/^\$argon2id\$/);
    expect(a?.promotedAt).not.toBeNull();
    expireVerifiedCacheForTests();
    const late = await heartbeat(s0);
    expect(late.status).toBe(401);
    expect(((await late.json()) as { code: string }).code).toBe("unauthorized");
    await expectNotLocked(s0.agentId);
    expect((await heartbeat(s1)).status).toBe(200);
  });

  it("answers a /rotate with S0 and the same S1 inside the window as a duplicate", async () => {
    const { s0, s1 } = await rotated();
    const res = await rotate(s0, { new_secret: s1.secret });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { duplicate: boolean }).duplicate).toBe(true);
    await expectNotLocked(s0.agentId);
  });

  it("locks on a /rotate with S0 and a different secret while S1 is pending", async () => {
    const s0 = await enroll();
    expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(200);
    const res = await rotate(s0, { new_secret: newAgentSecret() });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { code: string }).code).toBe("rotation_conflict");
    await expectLocked(s0.agentId);
    expect((await heartbeat(s0)).status).toBe(401);
  });

  it("locks on a /rotate with S0 and a different secret inside the window; S1 is revoked too", async () => {
    const { s0, s1 } = await rotated();
    const res = await rotate(s0, { new_secret: newAgentSecret() });
    expect(res.status).toBe(409);
    await expectLocked(s0.agentId);
    expect((await heartbeat(s1)).status).toBe(401);
  });

  it("never treats a /rotate authenticated with the current secret as a conflict (new rotation)", async () => {
    const { s0, s1 } = await rotated();
    const s2 = newAgentSecret();
    const res = await rotate(s1, { new_secret: s2 });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { duplicate: boolean }).duplicate).toBe(false);
    await expectNotLocked(s0.agentId);
    expect((await row(s0.agentId))?.pendingSecretHash).toMatch(/^\$argon2id\$/);
  });

  it("treats any use of S0 after the 60 s window as rotation_conflict", async () => {
    const { s0, s1 } = await rotated();
    await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
    expireVerifiedCacheForTests();
    const res = await heartbeat(s0);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { code: string }).code).toBe("rotation_conflict");
    await expectLocked(s0.agentId);
    expect((await heartbeat(s1)).status).toBe(401);
  });

  it("ADR-0011: S0 + the promoted S1 after the window is a duplicate; S0 + another secret locks", async () => {
    const { s0, s1 } = await rotated();
    await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
    const late = await rotate(s0, { new_secret: s1.secret });
    expect(late.status).toBe(200);
    expect(((await late.json()) as { duplicate: boolean }).duplicate).toBe(true);
    await expectNotLocked(s0.agentId);
    expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(409);
    await expectLocked(s0.agentId);
  });

  it("ADR-0011: response lost, agent offline beyond grace + 60 s, then S0 + same S1 is a duplicate", async () => {
    const s0 = await enroll();
    const s1 = newAgentSecret();
    const first = (await (await rotate(s0, { new_secret: s1 })).json()) as { grace_expires_at: string };
    // Deadline passed long ago: lazy promotion at the deadline, S0 is now far outside the window.
    const deadline = new Date(Date.now() - TOLERANCE_WINDOW_MS - 120_000);
    await getDb().update(agents).set({ graceExpiresAt: deadline }).where(eq(agents.id, s0.agentId));
    expireVerifiedCacheForTests();
    const retry = await rotate(s0, { new_secret: s1 });
    expect(retry.status).toBe(200);
    const body = (await retry.json()) as { grace_expires_at: string; duplicate: boolean };
    expect(body.duplicate).toBe(true);
    expect(body.grace_expires_at).toBe(deadline.toISOString());
    expect(first.grace_expires_at).not.toBe(body.grace_expires_at); // test moved the deadline
    await expectNotLocked(s0.agentId);
    expect((await heartbeat({ agentId: s0.agentId, secret: s1 })).status).toBe(200);
  });

  describe("N1: stale S0 on /rotate is a duplicate or a lock, never anything else", () => {
    const staleCases: [string, (s1: string) => { body?: unknown; raw?: string }][] = [
      ["empty body", () => ({ body: {} })],
      ["extra field", (s1) => ({ body: { new_secret: s1, other: 1 } })],
      ["invalid JSON", () => ({ raw: "{" })],
      ["malformed secret", () => ({ body: { new_secret: "dbs_short" } })],
      ["low-entropy secret", () => ({ body: { new_secret: `dbs_${"A".repeat(43)}` } })],
      ["unknown job_id", (s1) => ({ body: { new_secret: s1, job_id: "01890a5d-ac96-774b-bcce-b302099a8057" } })],
      ["another secret", () => ({ body: { new_secret: newAgentSecret() } })],
    ];
    it.each(staleCases)("%s -> 409 + lock + security event", async (_name, make) => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      const res = await handleRotate(agentRequest("POST", "/rotate", { auth: s0, ...make(s1.secret) }));
      expect(res.status).toBe(409);
      expect(((await res.json()) as { code: string }).code).toBe("rotation_conflict");
      await expectLocked(s0.agentId);
    });

    it("11 stale requests in a row: the first locks, the rotate bucket is untouched", async () => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      const statuses: number[] = [];
      for (let i = 0; i < 11; i++) statuses.push((await rotate(s0, {})).status);
      expect(statuses[0]).toBe(409);
      // Once locked, S0 is an unknown secret: 401, then the ordinary auth failure limit (429).
      expect(statuses.slice(1).every((st) => st === 401 || st === 429)).toBe(true);
      expect(rotatePerAgent.check(s0.agentId).limited).toBe(false);
      await expectLocked(s0.agentId);
      expect([401, 429]).toContain((await heartbeat(s1)).status);
    });

    it("a stale S0 is not blocked by a saturated rotate pool: legit retry duplicate, bad one locks", async () => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      const held = Array.from({ length: MAX_CONCURRENT_ROTATE_ARGON2 }, () => rotateArgon2Gate.tryAcquire());
      try {
        const ok = await rotate(s0, { new_secret: s1.secret });
        expect(ok.status).toBe(200);
        expect(((await ok.json()) as { duplicate: boolean }).duplicate).toBe(true);
        await expectNotLocked(s0.agentId);
        expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(409);
        await expectLocked(s0.agentId);
      } finally {
        held.forEach((r) => r?.());
      }
    });

    it("more than 10 late duplicates in 5 min lock the agent", async () => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      for (let i = 0; i < 10; i++) expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      await expectNotLocked(s0.agentId);
      expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(409);
      await expectLocked(s0.agentId);
    });
  });

  it("L4: a late S0 + S1 duplicate keeps S1's deadline even after S1 -> S2 started", async () => {
    const s0 = await enroll();
    const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
    const first = (await (await rotate(s0, { new_secret: s1.secret })).json()) as { grace_expires_at: string };
    expect((await heartbeat(s1)).status).toBe(200); // promotion
    await new Promise((r) => setTimeout(r, 20));
    const second = (await (await rotate(s1, { new_secret: newAgentSecret() })).json()) as { grace_expires_at: string };
    expect(second.grace_expires_at).not.toBe(first.grace_expires_at);
    const late = (await (await rotate(s0, { new_secret: s1.secret })).json()) as { grace_expires_at: string; duplicate: boolean };
    expect(late).toEqual({ grace_expires_at: first.grace_expires_at, duplicate: true });
    await expectNotLocked(s0.agentId);
  });

  it("L1: promotion time and deadline use the console clock", async () => {
    const s0 = await enroll();
    const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
    const before = Date.now();
    expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
    expect((await heartbeat(s1)).status).toBe(200);
    const after = Date.now();
    const a = await row(s0.agentId);
    expect(a?.promotedAt?.getTime()).toBeGreaterThanOrEqual(before);
    expect(a?.promotedAt?.getTime()).toBeLessThanOrEqual(after);
    expect(a?.promotedGraceExpiresAt?.getTime()).toBe(a?.graceExpiresAt?.getTime());
  });

  it("L2: a long-poll opened with S0 is closed when S1 is promoted", async () => {
    const s0 = await enroll();
    const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
    await jobHub.ready();
    expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
    const poll = handlePollJobs(agentRequest("GET", "/jobs?wait=25", { auth: s0 }));
    await new Promise((r) => setTimeout(r, 200));
    expect(jobHub.heldPolls(s0.agentId)).toBe(1);
    const started = Date.now();
    expect((await heartbeat(s1)).status).toBe(200); // promotion
    expect((await poll).status).toBe(401);
    expect(Date.now() - started).toBeLessThan(5000);
    // A poll opened with the current secret is not affected by a wake-up.
    const p1 = handlePollJobs(agentRequest("GET", "/jobs?wait=1", { auth: s1 }));
    await new Promise((r) => setTimeout(r, 100));
    jobHub.closeAgent(s0.agentId);
    expect((await p1).status).toBe(204);
  });

  it("promotes S1 at the grace deadline; S0 then follows the same window rules", async () => {
    const s0 = await enroll();
    const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
    expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
    await getDb()
      .update(agents)
      .set({ graceExpiresAt: new Date(Date.now() - 10_000) })
      .where(eq(agents.id, s0.agentId));
    expireVerifiedCacheForTests();
    expect((await heartbeat(s0)).status).toBe(401); // promoted 10 s ago: inside the window
    const a = await row(s0.agentId);
    expect(a?.pendingSecretHash).toBeNull();
    expect(a?.promotedAt?.getTime()).toBe(a?.graceExpiresAt?.getTime());
    expect((await heartbeat(s1)).status).toBe(200);
    await expectNotLocked(s0.agentId);

    const other = await enroll();
    expect((await rotate(other, { new_secret: newAgentSecret() })).status).toBe(200);
    await getDb()
      .update(agents)
      .set({ graceExpiresAt: new Date(Date.now() - TOLERANCE_WINDOW_MS - 5000) })
      .where(eq(agents.id, other.agentId));
    expireVerifiedCacheForTests();
    expect((await heartbeat(other)).status).toBe(409);
    await expectLocked(other.agentId);
  });

  it("closes held long-polls on a conflict", async () => {
    const s0 = await enroll();
    await jobHub.ready();
    const poll = handlePollJobs(agentRequest("GET", "/jobs?wait=25", { auth: s0 }));
    await new Promise((r) => setTimeout(r, 200));
    expect(jobHub.heldPolls(s0.agentId)).toBe(1);
    expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(200);
    expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(409);
    expect((await poll).status).toBe(401);
  });

  describe("concurrency", () => {
    // Authentication allows one unrecognized-secret verification per agent at a time (503 beyond):
    // the verified cache is warmed first so that the race happens inside /rotate itself.
    it("two concurrent /rotate with S0 and different secrets: one registers, the other locks", async () => {
      const s0 = await enroll();
      expect((await heartbeat(s0)).status).toBe(200);
      const results = await Promise.all([
        rotate(s0, { new_secret: newAgentSecret() }),
        rotate(s0, { new_secret: newAgentSecret() }),
      ]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
      await expectLocked(s0.agentId);
    });

    it("two concurrent /rotate with the same S1: one registration, one duplicate, no lock", async () => {
      const s0 = await enroll();
      expect((await heartbeat(s0)).status).toBe(200);
      const s1 = newAgentSecret();
      const results = await Promise.all([rotate(s0, { new_secret: s1 }), rotate(s0, { new_secret: s1 })]);
      expect(results.map((r) => r.status)).toEqual([200, 200]);
      const bodies = (await Promise.all(results.map((r) => r.json()))) as { duplicate: boolean; grace_expires_at: string }[];
      expect(bodies.map((b) => b.duplicate).sort()).toEqual([false, true]);
      expect(bodies[0]?.grace_expires_at).toBe(bodies[1]?.grace_expires_at);
      await expectNotLocked(s0.agentId);
    });
  });

  describe("argon2 pools", () => {
    it("runs its argon2 work in the dedicated rotate pool: 503 when saturated, other pools untouched", async () => {
      const s0 = await enroll();
      await heartbeat(s0); // warm the verified cache: authentication needs no pool
      const held = Array.from({ length: MAX_CONCURRENT_ROTATE_ARGON2 }, () => rotateArgon2Gate.tryAcquire());
      try {
        const res = await rotate(s0, { new_secret: newAgentSecret() });
        expect(res.status).toBe(503);
        expect(res.headers.get("retry-after")).toBe("5");
      } finally {
        held.forEach((r) => r?.());
      }
      expect(rotateArgon2Gate.inUse).toBe(0);
      const ops = rotateStats.argon2Ops;
      expect((await rotate(s0, { new_secret: newAgentSecret() })).status).toBe(200);
      expect(rotateStats.argon2Ops).toBe(ops + 1); // one argon2id hash of the new secret
      expect(rotateArgon2Gate.inUse).toBe(0);
      expect(agentArgon2Gate.inUse).toBe(0);
      expect(loginArgon2Gate.inUse).toBe(0);
    });

    it("rate limits /rotate per agent", async () => {
      const s0 = await enroll();
      const s1 = newAgentSecret();
      let last = 0;
      for (let i = 0; i < 11; i++) last = (await rotate(s0, { new_secret: s1 })).status;
      expect(last).toBe(429);
    });
  });

  describe("P1-D: bounded argon2id cost of previous-secret (S0) checks", () => {
    it("a stale S0 late retry runs its argon2id work only under the authentication pool slot", async () => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      expireVerifiedCacheForTests();
      // Shared agent pool saturated: nothing runs (no verification, no lock). Same answer as for any
      // unrecognized secret, so it does not confirm S0.
      const held = Array.from({ length: agentArgon2Gate.max }, () => agentArgon2Gate.tryAcquire());
      try {
        const started = argon2Stats.started;
        const busy = await rotate(s0, { new_secret: s1.secret });
        expect(busy.status).toBe(503);
        expect(argon2Stats.started).toBe(started);
        await expectNotLocked(s0.agentId);
      } finally {
        held.forEach((r) => r?.());
      }
      const started = argon2Stats.started;
      const rotateOps = rotateStats.argon2Ops;
      argon2Stats.maxActive = 0;
      const ok = await rotate(s0, { new_secret: s1.secret });
      expect(ok.status).toBe(200);
      expect(((await ok.json()) as { duplicate: boolean }).duplicate).toBe(true);
      // current (miss) + previous (S0) + the late-retry check, all in authenticateAgent's slot.
      expect(argon2Stats.started - started).toBe(3);
      expect(argon2Stats.maxActive).toBe(1);
      expect(rotateStats.argon2Ops).toBe(rotateOps); // nothing outside the pool of authentication
      expect(agentArgon2Gate.inUse).toBe(0);
      await expectNotLocked(s0.agentId);
    });

    it("S0 inside the window counts as a failed attempt: bounded argon2id work, then 429", async () => {
      const { s0, s1 } = await rotated();
      expireVerifiedCacheForTests();
      const started = argon2Stats.started;
      const statuses: number[] = [];
      for (let i = 0; i < 12; i++) statuses.push((await heartbeat(s0)).status);
      expect(statuses.slice(0, failuresPerAgent.limit)).toEqual(Array(failuresPerAgent.limit).fill(401));
      expect(statuses.slice(failuresPerAgent.limit)).toEqual([429, 429]);
      // At most three verifications (current, pending, previous) per counted attempt.
      expect(argon2Stats.started - started).toBeLessThanOrEqual(3 * failuresPerAgent.limit);
      await expectNotLocked(s0.agentId);
      // The current secret was verified before: known good, exempt from the per-agent limit.
      expect((await heartbeat(s1)).status).toBe(200);
    });

    it("the persisted known-good fingerprint follows the promotion (S0's one is dropped)", async () => {
      const s0 = await enroll();
      expect((await heartbeat(s0)).status).toBe(200);
      const before = (await row(s0.agentId))?.knownGoodFingerprint;
      expect(before).toMatch(/^[0-9a-f]{64}$/);
      const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
      expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      expect((await heartbeat(s1)).status).toBe(200); // promotion by first use
      const after = await row(s0.agentId);
      expect(after?.knownGoodFingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(after?.knownGoodFingerprint).not.toBe(before);
    });

    it("a /rotate duplicate with S0 gives its attempt back (inside and after the window)", async () => {
      const { s0, s1 } = await rotated();
      for (let i = 0; i < 5; i++) {
        expireVerifiedCacheForTests();
        expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      }
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      for (let i = 0; i < 5; i++) expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      // Ten counted attempts would have reached the per-agent limit.
      expect(failuresPerAgent.check(s0.agentId).limited).toBe(false);
      await expectNotLocked(s0.agentId);
    });
  });

  describe("P1-D follow-up review", () => {
    /** A `/rotate` whose body never completes; reports whether the handler started reading it. */
    const hangingRotate = (auth: Creds, extraHeaders: Record<string, string> = {}) => {
      const state = { pulled: false };
      const body = new ReadableStream<Uint8Array>({
        pull() {
          state.pulled = true;
          return new Promise(() => undefined);
        },
      }, { highWaterMark: 0 });
      const req = new Request(`${BASE}/rotate`, {
        method: "POST",
        headers: { ...agentHeaders(auth), ...extraHeaders },
        body,
        duplex: "half",
      } as RequestInit);
      return { req, state };
    };
    const flood = async (agentId: string) => {
      const wrong = newAgentSecret();
      for (let i = 0; i < failuresPerAgent.limit + 2; i++) await heartbeat({ agentId, secret: wrong });
      expect((await heartbeat({ agentId, secret: wrong })).status).toBe(429);
    };

    it("L1: cheap rejections happen before the body is read", async () => {
      const s0 = await enroll();
      const malformed = hangingRotate({ agentId: s0.agentId, secret: "dbs_short" });
      expect((await handleRotate(malformed.req)).status).toBe(401);
      expect(malformed.state.pulled).toBe(false);
      await flood(s0.agentId);
      const limited = hangingRotate({ agentId: s0.agentId, secret: newAgentSecret() });
      expect((await handleRotate(limited.req)).status).toBe(429);
      expect(limited.state.pulled).toBe(false);
    });

    it("L1: a body past the read deadline is a 400 before any argon2id work, never a lock", async () => {
      const { s0 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000); // stale S0: any bad body would lock
      expireVerifiedCacheForTests();
      rotateBodyDeadline.ms = 50;
      try {
        const started = argon2Stats.started;
        const slow = hangingRotate(s0);
        const res = await handleRotate(slow.req);
        expect(res.status).toBe(400);
        expect(slow.state.pulled).toBe(true);
        expect(argon2Stats.started).toBe(started);
        await expectNotLocked(s0.agentId);
      } finally {
        rotateBodyDeadline.ms = 10_000;
      }
    });

    it("L-a: timed-out bodies count against the cheap per-IP limit (M1), not the agent's", async () => {
      process.env.DATABASTION_TRUST_PROXY = "1";
      rotateBodyDeadline.ms = 5;
      try {
        const s0 = await enroll();
        const xff = { "X-Forwarded-For": "198.51.100.40" };
        // Earlier cheap failures from this IP (the limit is high: fill it directly), then real ones.
        for (let i = 0; i < cheapFailuresPerIp.limit - 5; i++) cheapFailuresPerIp.hit(ipBucket("198.51.100.40"));
        for (let i = 0; i < 5; i++) {
          expect((await handleRotate(hangingRotate(s0, xff).req)).status).toBe(400);
        }
        // No argon2id ran: the argon2id-backed per-IP counter is untouched.
        expect(failuresPerIp.check(ipBucket("198.51.100.40")).limited).toBe(false);
        // The IP is now limited; another IP, and the agent itself, are not.
        expect((await handleRotate(hangingRotate(s0, xff).req)).status).toBe(429);
        expect((await heartbeat(s0)).status).toBe(200);
        await expectNotLocked(s0.agentId);
      } finally {
        rotateBodyDeadline.ms = 10_000;
        delete process.env.DATABASTION_TRUST_PROXY;
      }
    });

    it("L2: a pending S1 is exempt from a failure flood, before and after its promotion", async () => {
      const s0 = await enroll();
      const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
      expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      const pending = await row(s0.agentId);
      expect(pending?.knownGoodPendingFingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(pending?.knownGoodPendingFingerprint).toBe(knownGoodFingerprint(s1.secret, pending?.pendingSecretHash ?? ""));
      await flood(s0.agentId);
      expect((await heartbeat(s1)).status).toBe(200); // first use: promotion despite the flood
      const promoted = await row(s0.agentId);
      expect(promoted?.pendingSecretHash).toBeNull();
      expect(promoted?.knownGoodPendingFingerprint).toBeNull();
      expect(promoted?.knownGoodFingerprint).toBe(pending?.knownGoodPendingFingerprint);
      expect(promoted?.knownGoodAt).not.toBeNull();
      await flood(s0.agentId);
      expireVerifiedCacheForTests();
      expect((await heartbeat(s1)).status).toBe(200);
      // S0 is not exempt (its fingerprint was replaced).
      expect((await heartbeat(s0)).status).toBe(429);
    });

    it("L2: the pending fingerprint carries over on a promotion at the deadline", async () => {
      const s0 = await enroll();
      const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
      expect((await rotate(s0, { new_secret: s1.secret })).status).toBe(200);
      const fp = (await row(s0.agentId))?.knownGoodPendingFingerprint;
      await getDb().update(agents).set({ graceExpiresAt: new Date(Date.now() - 1000) }).where(eq(agents.id, s0.agentId));
      await flood(s0.agentId); // the lazy promotion runs on one of these requests
      const a = await row(s0.agentId);
      expect(a?.pendingSecretHash).toBeNull();
      expect(a?.knownGoodFingerprint).toBe(fp);
      expireVerifiedCacheForTests();
      expect((await heartbeat(s1)).status).toBe(200);
    });

    it("L2: the pending fingerprint is cleared on lock and on revocation", async () => {
      const locked = await enroll();
      expect((await rotate(locked, { new_secret: newAgentSecret() })).status).toBe(200);
      expect((await rotate(locked, { new_secret: newAgentSecret() })).status).toBe(409);
      expect((await row(locked.agentId))?.knownGoodPendingFingerprint).toBeNull();
      const revoked = await enroll();
      expect((await rotate(revoked, { new_secret: newAgentSecret() })).status).toBe(200);
      expect((await row(revoked.agentId))?.knownGoodPendingFingerprint).not.toBeNull();
      await revokeAgent(getDb(), revoked.agentId, { userId: await adminUser(), ip: null });
      const r = await row(revoked.agentId);
      expect(r?.knownGoodPendingFingerprint).toBeNull();
      expect(r?.knownGoodFingerprint).toBeNull();
    });

    it("I1: a stale S0 without a late-retry check locks when the row is unchanged", async () => {
      const { s0, s1 } = await rotated();
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      const a = await row(s0.agentId);
      const base = { agentId: s0.agentId, matchedHash: a?.previousSecretHash ?? "" };
      // Row changed since authentication (another current hash): no decision.
      const changed = await staleRotateRetry(
        getDb(),
        { ...base, verifiedCurrentHash: "$argon2id$other", staleDuplicate: true },
        { new_secret: s1.secret },
        null,
      );
      expect(changed.kind).toBe("unauthorized");
      await expectNotLocked(s0.agentId);
      const unchecked = await staleRotateRetry(
        getDb(),
        { ...base, verifiedCurrentHash: a?.currentSecretHash ?? null, staleDuplicate: undefined },
        { new_secret: s1.secret },
        null,
      );
      expect(unchecked.kind).toBe("conflict");
      await expectLocked(s0.agentId);
    });

    it("I2: fingerprints are keyed by the server key; without it, or with another key, nothing matches", async () => {
      const s0 = await enroll();
      expect((await heartbeat(s0)).status).toBe(200);
      const a = await row(s0.agentId);
      const hash = a?.currentSecretHash ?? "";
      expect(a?.knownGoodFingerprint).toBe(knownGoodFingerprint(s0.secret, hash));
      expect(isKnownGood(a!, s0.secret, hash)).toBe(true);
      // Legacy (plain SHA-256) fingerprint written by an earlier version: never matches.
      const { sha256Hex } = await import("@/server/crypto");
      const legacy = sha256Hex(`databastion.agent-known-good.v1\0${hash}\0${s0.secret}`);
      expect(isKnownGood({ knownGoodFingerprint: legacy, knownGoodAt: new Date() }, s0.secret, hash)).toBe(false);
      const key = process.env.DATABASTION_ENCRYPTION_KEY;
      try {
        process.env.DATABASTION_ENCRYPTION_KEY = `${key}-rotated`;
        expect(isKnownGood(a!, s0.secret, hash)).toBe(false);
        delete process.env.DATABASTION_ENCRYPTION_KEY;
        expect(knownGoodFingerprint(s0.secret, hash)).toBeNull();
        expect(isKnownGood(a!, s0.secret, hash)).toBe(false);
        // No key: the lock-out exemption is gone (fail closed), authentication still works.
        await flood(s0.agentId);
        expireVerifiedCacheForTests();
        expect((await heartbeat(s0)).status).toBe(429);
        failuresPerAgent.clear();
        const other = await enroll();
        expect((await heartbeat(other)).status).toBe(200);
        expect((await row(other.agentId))?.knownGoodFingerprint).toBeNull();
      } finally {
        process.env.DATABASTION_ENCRYPTION_KEY = key;
      }
    });
  });

  describe("console-issued rotate jobs", () => {
    it("queues a job carrying no secret, refused while pending, within 60 s of promotion or while open", async () => {
      const userId = await adminUser();
      const actor = { userId, ip: null };
      const s0 = await enroll();
      const first = await requestSecretRotation(getDb(), s0.agentId, actor);
      expect(first.outcome).toBe("queued");
      expect((await requestSecretRotation(getDb(), s0.agentId, actor)).outcome).toBe("busy"); // open job
      const claimed = await claimJobs(getDb(), s0.agentId);
      expect(claimed).toHaveLength(1);
      expect(claimed[0]).toMatchObject({ type: "agent.rotate_secret", params: { reason: "manual" } });
      expect(JSON.stringify(claimed)).not.toMatch(/dbs_/);

      const s1 = { agentId: s0.agentId, secret: newAgentSecret() };
      expect((await rotate(s0, { new_secret: s1.secret, job_id: first.jobId })).status).toBe(200);
      await getDb().update(jobs).set({ status: "succeeded" }).where(eq(jobs.id, first.jobId as string));
      expect((await requestSecretRotation(getDb(), s0.agentId, actor)).outcome).toBe("busy"); // pending
      expect((await heartbeat(s1)).status).toBe(200); // promotion
      expect((await requestSecretRotation(getDb(), s0.agentId, actor)).outcome).toBe("busy"); // < 60 s
      await shiftPromotion(s0.agentId, TOLERANCE_WINDOW_MS + 1000);
      expect((await requestSecretRotation(getDb(), s0.agentId, actor)).outcome).toBe("queued");
      const audit = await getDb()
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.targetId, s0.agentId), eq(auditLog.action, "agent.rotate_request")));
      expect(audit.map((a) => a.outcome).sort()).toEqual(["failure", "failure", "failure", "success", "success"]);
    });

    it("computes the ADR-0010 blocking window", () => {
      const now = Date.now();
      const none = { pendingSecretHash: null, graceExpiresAt: null, promotedAt: null };
      expect(rotationBlocked(none, now)).toBe(false);
      expect(rotationBlocked({ ...none, promotedAt: new Date(now - 59_000) }, now)).toBe(true);
      expect(rotationBlocked({ ...none, promotedAt: new Date(now - 61_000) }, now)).toBe(false);
      expect(rotationBlocked({ ...none, pendingSecretHash: "h", graceExpiresAt: new Date(now + 1000) }, now)).toBe(true);
      expect(rotationBlocked({ ...none, pendingSecretHash: "h", graceExpiresAt: new Date(now - 30_000) }, now)).toBe(true);
      expect(rotationBlocked({ ...none, pendingSecretHash: "h", graceExpiresAt: new Date(now - 61_000) }, now)).toBe(false);
    });
  });
});
