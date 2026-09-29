import { randomUUID } from "node:crypto";

import { and, eq, sql } from "drizzle-orm";
import { Client } from "pg";
import { PgBoss } from "pg-boss";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb, getPool } from "@/db/client";
import { agents, agentTargets, auditLog, enrollmentTokens, jobs } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import schemasBundle from "@/generated/protocol/schemas.gen.json";
import { MAX_TARGET_NOTES_BYTES } from "@/lib/target-notes";
import { enrollFailureAuditBudget, getAgentDetail, listAgents, revokeAgent } from "@/server/agents";
import {
  agentArgon2Gate,
  argon2Stats,
  enrollArgon2Gate,
  MAX_CONCURRENT_ENROLL_ARGON2,
  loginArgon2Gate,
  MAX_CONCURRENT_UNAUTHENTICATED_ARGON2,
  sha256Hex,
} from "@/server/crypto";
import { handleLogin, loginFailuresUnknownUser } from "@/server/user-api";
import { enqueueJob, MAX_JOB_ATTEMPTS } from "@/server/jobs";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";
import { runtimeRoleWarnings } from "@/server/db-role-check";
import { pgBossOptions } from "@/worker/queues";
import {
  adminUser,
  agentRequest,
  enroll,
  expectConformingError,
  fixtures,
  newToken,
} from "@/test/helpers";

import { ipBucket } from "@/server/request";
import { CONSOLE_ACCEPTS } from "@/server/agent-api/capabilities";

import {
  cheapFailuresPerIp,
  clearKnownGoodHintsForTests,
  exemptionLookupStats,
  expireVerifiedCacheForTests,
  failuresPerAgent,
  failuresPerIp,
  holdUnrecognizedVerificationForTests,
} from "./auth";
import {
  enrollPerIp,
  handleEnroll,
  handleHeartbeat,
  handleJobStatus,
  handlePollJobs,
  pollClock,
} from "./handlers";
import { jobHub } from "./job-hub";

const MINIMAL_HEARTBEAT = {
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 12,
  connectors: ["postgres"],
  targets: [{ target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "limited" }],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

const SCAN_PARAMS = { sample_rows: 200, max_duration_s: 900 };

describe.skipIf(!hasDb)("agent API v1 (PostgreSQL)", () => {
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
    loginFailuresUnknownUser.clear();
    enrollFailureAuditBudget.clear();
    failuresPerAgent.clear();
    failuresPerIp.clear();
    cheapFailuresPerIp.clear();
    enrollPerIp.clear();
    pollClock.msPerSecond = 1000;
  });

  describe("POST /enroll", () => {
    it("exchanges a token for an identity, stores only hashes, audits, no-store", async () => {
      const token = await newToken();
      const res = await handleEnroll(
        agentRequest("POST", "/enroll", {
          body: { token, hostname: "db-host-1", agent_version: "0.1.0", connectors: ["postgres"] },
        }),
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const body = (await res.json()) as Record<string, unknown>;
      expect(validateSchema("EnrollResponse", body).ok).toBe(true);
      expect(body.heartbeat_interval_s).toBe(30);
      const [agent] = await getDb().select().from(agents).where(eq(agents.id, String(body.agent_id)));
      expect(agent?.currentSecretHash).toMatch(/^\$argon2id\$/);
      expect(agent?.currentSecretHash).not.toContain(String(body.agent_secret));
      const [tok] = await getDb()
        .select()
        .from(enrollmentTokens)
        .where(eq(enrollmentTokens.tokenHash, sha256Hex(token)));
      expect(tok?.consumedAt).not.toBeNull();
      expect(tok?.consumedByAgentId).toBe(body.agent_id);
      const audit = await getDb().select().from(auditLog).where(eq(auditLog.action, "agent.enroll"));
      expect(audit.some((a) => a.targetId === body.agent_id)).toBe(true);
      // Neither the token nor the secret is stored anywhere in clear.
      const dump = await getDb().execute(sql`
        select coalesce(string_agg(t::text, ' '), '') as s from (
          select row_to_json(a)::text as t from agents a
          union all select row_to_json(e)::text from enrollment_tokens e
          union all select row_to_json(l)::text from audit_log l) x`);
      const all = String(dump.rows[0]?.s);
      expect(all).not.toContain(token);
      expect(all).not.toContain(String(body.agent_secret));
    });

    it("rejects a reused, expired or revoked token with 401", async () => {
      const token = await newToken();
      const body = { token, hostname: "h1", agent_version: "0.1.0", connectors: [] };
      expect((await handleEnroll(agentRequest("POST", "/enroll", { body }))).status).toBe(200);
      const reuse = await handleEnroll(agentRequest("POST", "/enroll", { body }));
      expect(reuse.status).toBe(401);
      await expectConformingError(reuse, body);

      const expired = await newToken();
      await getDb()
        .update(enrollmentTokens)
        .set({ expiresAt: new Date(Date.now() - 1000) })
        .where(eq(enrollmentTokens.tokenHash, sha256Hex(expired)));
      const res = await handleEnroll(agentRequest("POST", "/enroll", { body: { ...body, token: expired } }));
      expect(res.status).toBe(401);

      const revoked = await newToken();
      await getDb()
        .update(enrollmentTokens)
        .set({ revokedAt: new Date() })
        .where(eq(enrollmentTokens.tokenHash, sha256Hex(revoked)));
      expect(
        (await handleEnroll(agentRequest("POST", "/enroll", { body: { ...body, token: revoked } }))).status,
      ).toBe(401);
    });

    it("consumes a token atomically under concurrency", async () => {
      const token = await newToken();
      const body = { token, hostname: "h2", agent_version: "0.1.0", connectors: [] };
      const results = await Promise.all(
        Array.from({ length: 5 }, () => handleEnroll(agentRequest("POST", "/enroll", { body }))),
      );
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      // The others lost the race (401) or found the bounded enroll pool full (503, L4).
      expect(results.every((r) => [200, 401, 503].includes(r.status))).toBe(true);
      const created = await getDb().select().from(agents).where(eq(agents.hostname, "h2"));
      expect(created).toHaveLength(1);
      // Retried after the pool freed up: the token is consumed.
      expect((await handleEnroll(agentRequest("POST", "/enroll", { body }))).status).toBe(401);
    });

    it.each(fixtures("valid", "EnrollRequest"))("valid fixture %s passes validation", async (_f, body) => {
      // Fixture tokens are well-formed but unknown: validation passes, the token lookup fails.
      const res = await handleEnroll(agentRequest("POST", "/enroll", { body }));
      expect(res.status).toBe(401);
    });

    it.each(fixtures("invalid", "EnrollRequest"))("invalid fixture %s -> 400", async (_f, body) => {
      const res = await handleEnroll(agentRequest("POST", "/enroll", { body }));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.code).toBe("invalid_request");
      expect(Array.isArray(err.details)).toBe(true);
    });

    it("rate limits per source IP when the IP is known (trusted proxy)", async () => {
      process.env.DATABASTION_TRUST_PROXY = "1";
      try {
        const body = { token: `dbe_${"A".repeat(43)}`, hostname: "h", agent_version: "0.1.0", connectors: [] };
        const headers = { "X-Forwarded-For": "198.51.100.20" };
        let last = 0;
        for (let i = 0; i < 21; i++) {
          last = (await handleEnroll(agentRequest("POST", "/enroll", { body, headers }))).status;
        }
        expect(last).toBe(429);
        // Another client IP is not affected.
        const other = await handleEnroll(
          agentRequest("POST", "/enroll", { body, headers: { "X-Forwarded-For": "198.51.100.21" } }),
        );
        expect(other.status).toBe(401);
      } finally {
        delete process.env.DATABASTION_TRUST_PROXY;
      }
    });

    it("runs no argon2id for an unusable token and audits the failure without token material (M4, L3)", async () => {
      const token = `dbe_${"B".repeat(43)}`;
      const before = argon2Stats.started;
      const res = await handleEnroll(
        agentRequest("POST", "/enroll", { body: { token, hostname: "h", agent_version: "0.1.0", connectors: [] } }),
      );
      expect(res.status).toBe(401);
      expect(argon2Stats.started).toBe(before);
      const rows = await getDb().select().from(auditLog).where(eq(auditLog.action, "agent.enroll"));
      const failures = rows.filter((r) => r.outcome === "failure");
      expect(failures.length).toBeGreaterThan(0);
      expect(JSON.stringify(failures)).not.toContain(token);
      expect(JSON.stringify(failures)).not.toContain(sha256Hex(token));
    });
  });

  describe("POST /enroll argon2id pool (P1-D L4)", () => {
    it("answers 503 + Retry-After when the enroll pool is full, without consuming the token", async () => {
      const token = await newToken();
      const body = { token, hostname: "l4", agent_version: "0.1.0", connectors: [] };
      const held = Array.from({ length: MAX_CONCURRENT_ENROLL_ARGON2 }, () => enrollArgon2Gate.tryAcquire());
      expect(held.every((r) => r !== null)).toBe(true);
      const before = argon2Stats.started;
      try {
        const busy = await handleEnroll(agentRequest("POST", "/enroll", { body }));
        expect(busy.status).toBe(503);
        expect(Number(busy.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
        await expectConformingError(busy, body);
        expect(argon2Stats.started).toBe(before);
        const [tok] = await getDb()
          .select()
          .from(enrollmentTokens)
          .where(eq(enrollmentTokens.tokenHash, sha256Hex(token)));
        expect(tok?.consumedAt).toBeNull();
      } finally {
        for (const release of held) release?.();
      }
      // Once a slot is free, the same token enrolls.
      expect((await handleEnroll(agentRequest("POST", "/enroll", { body }))).status).toBe(200);
      expect(enrollArgon2Gate.inUse).toBe(0);
    });

    it("never runs more than the pool size of enroll hashes at once", async () => {
      const tokens = await Promise.all(Array.from({ length: 6 }, () => newToken()));
      argon2Stats.maxActive = 0;
      const results = await Promise.all(
        tokens.map((token, i) =>
          handleEnroll(
            agentRequest("POST", "/enroll", { body: { token, hostname: `l4-${i}`, agent_version: "0.1.0", connectors: [] } }),
          ),
        ),
      );
      expect(results.every((r) => [200, 503].includes(r.status))).toBe(true);
      expect(results.filter((r) => r.status === 200).length).toBeGreaterThanOrEqual(1);
      expect(argon2Stats.maxActive).toBeLessThanOrEqual(MAX_CONCURRENT_ENROLL_ARGON2);
    });
  });

  describe("common request checks", () => {
    it("requires the protocol and user-agent headers; 426 below the minimum", async () => {
      const auth = await enroll();
      const noProto = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT, headers: { "X-DataBastion-Protocol": "" } }),
      );
      expect(noProto.status).toBe(400);
      const old = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT, headers: { "X-DataBastion-Protocol": "0" } }),
      );
      expect(old.status).toBe(426);
      const err = await expectConformingError(old, {});
      expect(err.code).toBe("protocol_unsupported");
      expect(err.min_protocol).toBe(1);
      const ua = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT, headers: { "User-Agent": "curl/8" } }),
      );
      expect(ua.status).toBe(400);
    });

    it("rejects bodies over 4 MiB with 413", async () => {
      const auth = await enroll();
      const raw = JSON.stringify({ ...MINIMAL_HEARTBEAT, pad: "x".repeat(4 * 1024 * 1024) });
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, raw }));
      expect(res.status).toBe(413);
      expect(((await res.json()) as { code: string }).code).toBe("payload_too_large");
    });

    it("rejects unknown fields at any depth without echoing them", async () => {
      const auth = await enroll();
      const body = {
        ...MINIMAL_HEARTBEAT,
        targets: [{ ...MINIMAL_HEARTBEAT.targets[0], password_leak: "jane.doe@example.com" }],
      };
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.details).toEqual([{ pointer: "/targets/0", keyword: "additionalProperties" }]);
    });

    it("rejects malformed JSON and wrong content type", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, raw: "{" }))).status).toBe(400);
      const res = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT, headers: { "Content-Type": "text/plain" } }),
      );
      expect(res.status).toBe(400);
    });
  });

  describe("authentication", () => {
    it("rejects missing, malformed and wrong secrets with 401", async () => {
      const auth = await enroll();
      const none = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { body: MINIMAL_HEARTBEAT }),
      );
      expect(none.status).toBe(401);
      const wrong = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", {
          auth: { agentId: auth.agentId, secret: (await enroll("other")).secret },
          body: MINIMAL_HEARTBEAT,
        }),
      );
      expect(wrong.status).toBe(401);
      const lowEntropy = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", {
          auth: { agentId: auth.agentId, secret: `dbs_${"EXAMPLE".repeat(6)}1` },
          body: MINIMAL_HEARTBEAT,
        }),
      );
      expect(lowEntropy.status).toBe(401);
      const unknown = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", {
          auth: { agentId: "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a", secret: auth.secret },
          body: MINIMAL_HEARTBEAT,
        }),
      );
      expect(unknown.status).toBe(401);
      await expectConformingError(unknown, {});
    });

    it("rate limits failed authentications per agent id before verifying (429 + Retry-After)", async () => {
      const auth = await enroll();
      const other = (await enroll("other2")).secret;
      const statuses: number[] = [];
      for (let i = 0; i < 11; i++) {
        const res = await handleHeartbeat(
          agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: other }, body: MINIMAL_HEARTBEAT }),
        );
        statuses.push(res.status);
        if (res.status === 429) {
          expect(Number(res.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
          expect(((await res.json()) as { code: string }).code).toBe("rate_limited");
        }
      }
      expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
      expect(statuses[10]).toBe(429);
    });
  });

  describe("brute-force protections (security review H1, M1)", () => {
    it("40 concurrent wrong secrets: at most the per-agent limit reaches argon2id", async () => {
      const auth = await enroll();
      const wrong = (await enroll("other-bf")).secret;
      const before = argon2Stats.started;
      const results = await Promise.all(
        Array.from({ length: 40 }, () =>
          handleHeartbeat(
            agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
          ),
        ),
      );
      expect(argon2Stats.started - before).toBeLessThanOrEqual(failuresPerAgent.limit);
      expect(results.every((r) => [401, 429, 503].includes(r.status))).toBe(true);
      expect(results.filter((r) => r.status === 401).length).toBeLessThanOrEqual(failuresPerAgent.limit);
    });

    it("caps concurrent argon2id verifications process-wide", async () => {
      const ids = await Promise.all(Array.from({ length: 12 }, (_, i) => enroll(`conc-${i}`)));
      const wrong = (await enroll("conc-wrong")).secret;
      argon2Stats.maxActive = 0;
      const results = await Promise.all(
        ids.flatMap((a) =>
          Array.from({ length: 3 }, () =>
            handleHeartbeat(
              agentRequest("POST", "/heartbeat", { auth: { agentId: a.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
            ),
          ),
        ),
      );
      expect(argon2Stats.maxActive).toBeLessThanOrEqual(MAX_CONCURRENT_UNAUTHENTICATED_ARGON2);
      const busy = results.filter((r) => r.status === 503);
      for (const r of busy) expect(Number(r.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    });

    it("an attacker from another IP cannot lock a legitimate agent out", async () => {
      process.env.DATABASTION_TRUST_PROXY = "1";
      try {
        const auth = await enroll();
        const wrong = (await enroll("other-m1")).secret;
        for (let i = 0; i < 12; i++) {
          await handleHeartbeat(
            agentRequest("POST", "/heartbeat", {
              auth: { agentId: auth.agentId, secret: wrong },
              body: MINIMAL_HEARTBEAT,
              headers: { "X-Forwarded-For": "203.0.113.66" },
            }),
          );
        }
        const legit = await handleHeartbeat(
          agentRequest("POST", "/heartbeat", {
            auth,
            body: MINIMAL_HEARTBEAT,
            headers: { "X-Forwarded-For": "192.0.2.10" },
          }),
        );
        expect(legit.status).toBe(200);
      } finally {
        delete process.env.DATABASTION_TRUST_PROXY;
      }
    });

    it("with an unknown IP, a known-good secret is exempt from the per-agent limit (never authenticates)", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      const wrong = (await enroll("other-m1b")).secret;
      for (let i = 0; i < 12; i++) {
        await handleHeartbeat(
          agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
        );
      }
      const blocked = await handleHeartbeat(
        agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
      );
      expect(blocked.status).toBe(429);
      expireVerifiedCacheForTests();
      const before = argon2Stats.started;
      const legit = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
      expect(legit.status).toBe(200);
      // Exempt from the limit, but still fully verified.
      expect(argon2Stats.started).toBe(before + 1);
    });
  });

  describe("P1-D M1: agents behind a shared source IP", () => {
    const IP = "198.51.100.77";
    const XFF = { "X-Forwarded-For": IP };
    const hb = (auth?: { agentId: string; secret: string }, headers: Record<string, string> = XFF) =>
      handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT, headers }));
    beforeEach(() => {
      process.env.DATABASTION_TRUST_PROXY = "1";
    });
    afterEach(() => {
      delete process.env.DATABASTION_TRUST_PROXY;
    });

    it("50 cheap failures from an IP (no secret needed) block no agent behind it", async () => {
      const known = await enroll("m1-known");
      expect((await hb(known)).status).toBe(200);
      const fresh = await enroll("m1-fresh");
      const before = argon2Stats.started;
      for (let i = 0; i < 50; i++) {
        const junk =
          i % 3 === 0
            ? hb() // no agent id / secret headers
            : i % 3 === 1
              ? hb({ agentId: known.agentId, secret: "dbs_short" }) // malformed secret
              : hb({ agentId: randomUUID(), secret: fresh.secret }); // unknown agent
        expect((await junk).status).toBe(401);
      }
      expect(argon2Stats.started).toBe(before);
      expect(failuresPerIp.check(ipBucket(IP)).limited).toBe(false);
      expireVerifiedCacheForTests();
      expect((await hb(known)).status).toBe(200);
      // A never-verified agent still reaches argon2id: cheap failures only gate at a much higher count.
      expect((await hb(fresh)).status).toBe(200);
    });

    it("with both per-IP limits reached, known-good and cached secrets get 200, others 429", async () => {
      const known = await enroll("m1-kg");
      expect((await hb(known)).status).toBe(200);
      const cached = await enroll("m1-cached");
      expect((await hb(cached)).status).toBe(200);
      // Only the short verified cache exempts this one.
      await getDb()
        .update(agents)
        .set({ knownGoodFingerprint: null, knownGoodAt: null })
        .where(eq(agents.id, cached.agentId));
      const stranger = await enroll("m1-stranger");
      const key = ipBucket(IP);
      for (let i = 0; i < failuresPerIp.limit; i++) failuresPerIp.hit(key);
      for (let i = 0; i < cheapFailuresPerIp.limit; i++) cheapFailuresPerIp.hit(key);

      const before = argon2Stats.started;
      expect((await hb({ agentId: known.agentId, secret: stranger.secret })).status).toBe(429);
      expect((await hb(stranger)).status).toBe(429);
      expect(argon2Stats.started).toBe(before);
      // Cached: no argon2id at all.
      expect((await hb(cached)).status).toBe(200);
      expect(argon2Stats.started).toBe(before);
      // Known good (cache expired): exempt, still fully verified, in the reserved pool.
      expireVerifiedCacheForTests();
      expect((await hb(known)).status).toBe(200);
      expect(argon2Stats.started).toBe(before + 1);
      // The exemption does not change the limits of the IP.
      expect(failuresPerIp.check(key).limited).toBe(true);
    });

    it("N4: exemption lookups are counted, and skipped once the IP is over the cheap limit", async () => {
      const known = await enroll("n4-known");
      expect((await hb(known)).status).toBe(200);
      const key = ipBucket(IP);
      for (let i = 0; i < failuresPerIp.limit; i++) failuresPerIp.hit(key);
      for (let i = 0; i < cheapFailuresPerIp.limit - 1; i++) cheapFailuresPerIp.hit(key);
      const junk = { agentId: randomUUID(), secret: known.secret };
      // Limited, no cache, no hint: one row read, charged to the cheap per-IP counter.
      let lookups = exemptionLookupStats.lookups;
      expect((await hb(junk)).status).toBe(429);
      expect(exemptionLookupStats.lookups).toBe(lookups + 1);
      expect(cheapFailuresPerIp.check(key).limited).toBe(true);
      // Over the cheap limit: no row read at all.
      lookups = exemptionLookupStats.lookups;
      for (let i = 0; i < 5; i++) expect((await hb(junk)).status).toBe(429);
      expect(exemptionLookupStats.lookups).toBe(lookups);
      // The known-good agent still passes: the in-memory hint needs no row read (M1 preserved).
      expireVerifiedCacheForTests();
      expect((await hb(known)).status).toBe(200);
      expect(exemptionLookupStats.lookups).toBe(lookups);
      // Documented limit: right after a restart (no hint yet) and while the IP is over the cheap
      // limit, the known-good agent waits for the window like the others.
      expireVerifiedCacheForTests();
      clearKnownGoodHintsForTests();
      expect((await hb(known)).status).toBe(429);
      // Below the cheap limit, the row read restores the exemption.
      cheapFailuresPerIp.clear();
      expect((await hb(known)).status).toBe(200);
      expect(exemptionLookupStats.lookups).toBe(lookups + 1);
    });

    it("only argon2id-backed failures count toward the per-IP failure limit", async () => {
      const target = await enroll("m1-count");
      const wrong = (await enroll("m1-count-wrong")).secret;
      expect((await hb({ agentId: target.agentId, secret: wrong })).status).toBe(401);
      expect((await hb({ agentId: randomUUID(), secret: wrong })).status).toBe(401);
      const key = ipBucket(IP);
      // Exactly one argon2id-backed failure was counted (the unknown agent was a cheap failure):
      // limit - 2 more leave the IP below the limit, one more reaches it.
      for (let i = 0; i < failuresPerIp.limit - 2; i++) failuresPerIp.hit(key);
      expect(failuresPerIp.check(key).limited).toBe(false);
      failuresPerIp.hit(key);
      expect(failuresPerIp.check(key).limited).toBe(true);
      expect(cheapFailuresPerIp.check(key).limited).toBe(false);
    });
  });

  describe("P1-D: persisted known-good fingerprint", () => {
    const wrongHeartbeat = (h: typeof handleHeartbeat, agentId: string, wrong: string) =>
      h(agentRequest("POST", "/heartbeat", { auth: { agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }));
    const knownGoodRow = async (agentId: string) =>
      (
        await getDb()
          .select({ fp: agents.knownGoodFingerprint, at: agents.knownGoodAt })
          .from(agents)
          .where(eq(agents.id, agentId))
      )[0];

    it("stores a hash-bound fingerprint, never the secret nor its plain SHA-256", async () => {
      const auth = await enroll("kg-store");
      expect((await knownGoodRow(auth.agentId))?.fp).toBeNull();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      const [row] = await getDb().select().from(agents).where(eq(agents.id, auth.agentId));
      expect(row?.knownGoodFingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(row?.knownGoodFingerprint).not.toBe(sha256Hex(auth.secret));
      expect(row?.knownGoodAt).not.toBeNull();
      expect(JSON.stringify(row)).not.toContain(auth.secret);
      expect(JSON.stringify(row)).not.toContain(sha256Hex(auth.secret));
    });

    it("survives a console restart: fresh process state, the agent is still exempt from the lock-out", async () => {
      const auth = await enroll("kg-restart");
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      const wrong = (await enroll("kg-restart-other")).secret;
      // New module instances: empty verified cache, limiters and pools, like a restarted process.
      vi.resetModules();
      const fresh = await import("./handlers");
      const freshDb = await import("@/db/client");
      try {
        for (let i = 0; i < 12; i++) await wrongHeartbeat(fresh.handleHeartbeat, auth.agentId, wrong);
        expect((await wrongHeartbeat(fresh.handleHeartbeat, auth.agentId, wrong)).status).toBe(429);
        const legit = await fresh.handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
        expect(legit.status).toBe(200);
      } finally {
        await freshDb.closeDb();
      }
    });

    it("an expired fingerprint (24 h) or one bound to another hash exempts nothing", async () => {
      const auth = await enroll("kg-expired");
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      const wrong = (await enroll("kg-expired-other")).secret;
      await getDb()
        .update(agents)
        .set({ knownGoodAt: new Date(Date.now() - 24 * 3600_000 - 1000) })
        .where(eq(agents.id, auth.agentId));
      expireVerifiedCacheForTests();
      for (let i = 0; i < 12; i++) await wrongHeartbeat(handleHeartbeat, auth.agentId, wrong);
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(429);
      // A fingerprint of the right secret over another stored hash does not match either.
      const other = await enroll("kg-other-hash");
      const [otherRow] = await getDb().select().from(agents).where(eq(agents.id, other.agentId));
      const { knownGoodFingerprint, isKnownGood } = await import("./auth");
      const row = { knownGoodFingerprint: knownGoodFingerprint(other.secret, "$argon2id$other"), knownGoodAt: new Date() };
      expect(isKnownGood(row, other.secret, otherRow?.currentSecretHash ?? "")).toBe(false);
      expect(isKnownGood(row, other.secret, "$argon2id$other")).toBe(true);
    });

    it("is cleared on revocation", async () => {
      const auth = await enroll("kg-revoke");
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      expect((await knownGoodRow(auth.agentId))?.fp).not.toBeNull();
      const [admin] = await getDb().execute<{ id: string }>(sql`select id from users limit 1`).then((r) => r.rows);
      await revokeAgent(getDb(), auth.agentId, { userId: admin?.id ?? "", ip: null });
      expect(await knownGoodRow(auth.agentId)).toEqual({ fp: null, at: null });
    });
  });

  describe("argon2id pool isolation (security re-review N1)", () => {
    it("allows one unrecognized verification in flight per agent id (L1)", async () => {
      const auth = await enroll();
      const wrong = (await enroll("l1-other")).secret;
      const heartbeat = () =>
        handleHeartbeat(
          agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
        );
      // Deterministic: while one verification of this agent id is in flight, every other unrecognized
      // secret is turned away with 503 (the timing of 6 concurrent requests made this flaky: a fast
      // verification could finish and free the slot before the next request reached the gate).
      // Static import: the auth module instance the static handleHeartbeat uses (an earlier test
      // resets the module registry, so a dynamic import would load another instance).
      const release = holdUnrecognizedVerificationForTests(auth.agentId);
      let held: Response[];
      try {
        held = await Promise.all(Array.from({ length: 5 }, heartbeat));
      } finally {
        release();
      }
      expect(held.map((r) => r.status)).toEqual([503, 503, 503, 503, 503]);
      // Once the slot is free, the next one is verified (and fails: 401).
      expect((await heartbeat()).status).toBe(401);
    });

    it("saturated login and wrong-secret pools never block a known-good agent", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      expireVerifiedCacheForTests();
      // Deterministic saturation of both unauthenticated pools.
      const held = [
        ...Array.from({ length: loginArgon2Gate.max }, () => loginArgon2Gate.tryAcquire()),
        ...Array.from({ length: agentArgon2Gate.max }, () => agentArgon2Gate.tryAcquire()),
      ];
      try {
        expect(loginArgon2Gate.tryAcquire()).toBeNull();
        expect(agentArgon2Gate.tryAcquire()).toBeNull();
        const wrong = (await enroll("n1-other")).secret;
        const flooded = await handleHeartbeat(
          agentRequest("POST", "/heartbeat", { auth: { agentId: auth.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
        );
        expect(flooded.status).toBe(503);
        const legit = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
        expect(legit.status).toBe(200);
      } finally {
        for (const release of held) release?.();
      }
    });

    it("a concurrent login flood + wrong secrets on random agents does not produce 503 for a known-good agent", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      const victims = await Promise.all(Array.from({ length: 6 }, (_, i) => enroll(`n1-victim-${i}`)));
      const wrong = (await enroll("n1-wrong")).secret;
      expireVerifiedCacheForTests();
      const floodLogins = Array.from({ length: 30 }, (_, i) =>
        handleLogin(
          new Request("http://console.test/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: "http://console.test" },
            body: JSON.stringify({ username: `flood${i}`, password: "wrong wrong wrong" }),
          }),
        ),
      );
      const floodAgents = victims.flatMap((v) =>
        Array.from({ length: 3 }, () =>
          handleHeartbeat(
            agentRequest("POST", "/heartbeat", { auth: { agentId: v.agentId, secret: wrong }, body: MINIMAL_HEARTBEAT }),
          ),
        ),
      );
      const randomIds = Array.from({ length: 20 }, () =>
        handleHeartbeat(
          agentRequest("POST", "/heartbeat", { auth: { agentId: randomUUID(), secret: wrong }, body: MINIMAL_HEARTBEAT }),
        ),
      );
      const legit = handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
      const [legitRes] = await Promise.all([legit, ...floodLogins, ...floodAgents, ...randomIds]);
      expect(legitRes.status).toBe(200);
    });
  });

  describe("POST /heartbeat", () => {
    it.each(fixtures("valid", "HeartbeatRequest"))("valid fixture %s -> 200", async (_f, body) => {
      const auth = await enroll();
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
      expect(res.status).toBe(200);
      const out = (await res.json()) as Record<string, unknown>;
      expect(validateSchema("HeartbeatResponse", out).ok).toBe(true);
      expect(out.heartbeat_interval_s).toBe(30);
      expect(out.console_min_protocol).toBe(1);
      expect(out.accepts).toEqual([...CONSOLE_ACCEPTS]);
      const targets = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
      expect(targets).toHaveLength((body as { targets: unknown[] }).targets.length);
      const [agent] = await getDb().select().from(agents).where(eq(agents.id, auth.agentId));
      expect(agent?.status).toBe("online");
      expect(agent?.lastSeenAt).not.toBeNull();
    });

    it.each(fixtures("invalid", "HeartbeatRequest"))("invalid fixture %s -> 400", async (_f, body) => {
      const auth = await enroll();
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
      expect(res.status).toBe(400);
      await expectConformingError(res, body);
    });

    it("stores the notes of the latest heartbeat per target (contract fields only), clears them when absent", async () => {
      const auth = await enroll();
      const [body] = fixtures("valid", "HeartbeatRequest").filter(([name]) => name.includes("target-notes")).map(([, b]) => b);
      const hb = body as { targets: { target_id: string; notes?: unknown[] }[] };
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: hb }))).status).toBe(200);
      const stored = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId)).orderBy(agentTargets.targetId);
      expect(stored.map((t) => [t.targetId, t.notes])).toEqual([
        ["mysql-crm", hb.targets[1]?.notes],
        ["pg-prod-1", hb.targets[0]?.notes],
      ]);
      const detail = await getAgentDetail(getDb(), auth.agentId);
      expect(detail?.targets.find((t) => t.targetId === "pg-prod-1")?.notes).toHaveLength(6);
      const listed = (await listAgents(getDb())).find((a) => a.id === auth.agentId);
      expect(listed?.targets.find((t) => t.targetId === "mysql-crm")?.notes).toEqual([{ code: "check.stage_failed", labels: ["stage_auth"] }]);
      // The next heartbeat carries no notes: the target's notes are those of the latest heartbeat.
      const next = { ...hb, targets: hb.targets.map(({ notes: _n, ...t }) => t) };
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: next }))).status).toBe(200);
      const cleared = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
      expect(cleared.map((t) => t.notes)).toEqual([null, null]);
    });

    it("stores the largest notes the contract allows, within the size bound", async () => {
      const auth = await enroll();
      const labels = (schemasBundle.$defs.TargetNoteLabel.enum as string[])
        .slice()
        .sort((a, b) => b.length - a.length)
        .slice(0, 16);
      const word = "abcdefghijklmnop";
      const code = `privilege.${word}_${word}_${word}_abc`;
      expect(code).toHaveLength(64);
      const notes = Array.from({ length: 16 }, () => ({ code, count: Number.MAX_SAFE_INTEGER, labels }));
      const body = { ...MINIMAL_HEARTBEAT, targets: [{ ...MINIMAL_HEARTBEAT.targets[0], notes }] };
      expect(validateSchema("HeartbeatRequest", body).ok).toBe(true);
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
      const [t] = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
      expect(t?.notes).toEqual(notes);
      const size = await getDb().execute<{ n: number }>(
        sql`select octet_length(notes::text)::int as n from agent_targets where agent_id = ${auth.agentId}`,
      );
      expect(Number(size.rows[0]?.n)).toBeLessThanOrEqual(MAX_TARGET_NOTES_BYTES);
      // The database refuses anything beyond the bound (migration 0028).
      await expect(
        getDb().execute(sql`update agent_targets set notes = ${JSON.stringify([{ code: "x".repeat(20_000) }])}::jsonb where agent_id = ${auth.agentId}`),
      ).rejects.toThrow();
      await expect(
        getDb().execute(sql`update agent_targets set notes = '{"code": "audit.x"}'::jsonb where agent_id = ${auth.agentId}`),
      ).rejects.toThrow();
    });

    it("marks targets absent from the last heartbeat", async () => {
      const auth = await enroll();
      await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
      await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: { ...MINIMAL_HEARTBEAT, targets: [] } }));
      const [t] = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
      expect(t?.present).toBe(false);
    });
  });

  describe("GET /jobs (long-poll)", () => {
    it("returns 204 immediately with wait=0 and after wait seconds otherwise", async () => {
      const auth = await enroll();
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
      pollClock.msPerSecond = 50;
      const started = Date.now();
      const res = await handlePollJobs(agentRequest("GET", "/jobs?wait=2", { auth }));
      expect(res.status).toBe(204);
      expect(Date.now() - started).toBeGreaterThanOrEqual(90);
    });

    it("rejects invalid query parameters", async () => {
      const auth = await enroll();
      for (const q of ["wait=26", "wait=-1", "wait=abc", "wait=1&wait=2", "foo=1", "wait=01"]) {
        expect((await handlePollJobs(agentRequest("GET", `/jobs?${q}`, { auth }))).status).toBe(400);
      }
    });

    it("wakes a held poll when a job is queued and serves a conforming JobList", async () => {
      const auth = await enroll();
      await jobHub.ready();
      const poll = handlePollJobs(agentRequest("GET", "/jobs?wait=25", { auth }));
      await new Promise((r) => setTimeout(r, 100));
      const jobId = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "discovery.scan",
        targetId: "pg-prod-1",
        classifiersVersion: "2026.09.1",
        params: SCAN_PARAMS,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const started = Date.now();
      const res = await poll;
      expect(Date.now() - started).toBeLessThan(5000);
      expect(res.status).toBe(200);
      const list = (await res.json()) as { jobs: { job_id: string }[] };
      expect(validateSchema("JobList", list).ok).toBe(true);
      expect(list.jobs.map((j) => j.job_id)).toEqual([jobId]);
      // Leased: not delivered again before the lease expires, then redelivered.
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
      await getDb().update(jobs).set({ leaseUntil: new Date(Date.now() - 1000) }).where(eq(jobs.id, jobId));
      const again = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
      expect(again.status).toBe(200);
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, jobId));
      expect(row?.attempts).toBe(2);
    });

    it("never serves a job that does not conform to the contract", async () => {
      const auth = await enroll();
      const bad = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "agent.config.reload",
        params: { config: "targets: [...]" },
      });
      const res = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
      expect(res.status).toBe(204);
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, bad));
      expect(row?.status).toBe("failed");
    });

    it("caps held polls per agent, reserving slots before any await (M2)", async () => {
      const auth = await enroll();
      // Warm the verified-secret cache (L1 allows one unrecognized verification per agent at once).
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
      pollClock.msPerSecond = 100;
      const results = await Promise.all(
        Array.from({ length: 5 }, () => handlePollJobs(agentRequest("GET", "/jobs?wait=2", { auth }))),
      );
      const statuses = results.map((r) => r.status).sort();
      expect(statuses).toEqual([204, 204, 429, 429, 429]);
      expect(jobHub.heldPolls(auth.agentId)).toBe(0);
    });

    it("applies the held-poll slots to wait=0 too (L-a)", async () => {
      const auth = await enroll();
      const a = jobHub.reserveSlot(auth.agentId);
      const b = jobHub.reserveSlot(auth.agentId);
      try {
        expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(429);
      } finally {
        if (typeof a === "function") a();
        if (typeof b === "function") b();
      }
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
    });

    it("gives up a job delivered MAX_JOB_ATTEMPTS times without status (L7)", async () => {
      const auth = await enroll();
      const id = await enqueueJob(getDb(), { agentId: auth.agentId, type: "agent.config.reload", params: {} });
      await getDb()
        .update(jobs)
        .set({ status: "delivered", attempts: MAX_JOB_ATTEMPTS, leaseUntil: new Date(Date.now() - 1000) })
        .where(eq(jobs.id, id));
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, id));
      expect(row?.status).toBe("failed");
      expect(row?.error).toEqual({ code: "timeout" });
    });

    it("does not deliver expired jobs", async () => {
      const auth = await enroll();
      const id = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "agent.config.reload",
        params: {},
        expiresAt: new Date(Date.now() - 1000),
      });
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(204);
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, id));
      expect(row?.status).toBe("expired");
    });
  });

  describe("revocation", () => {
    it("makes the secret unusable immediately (cache purged) and closes held polls", async () => {
      const auth = await enroll();
      const userId = await adminUser();
      // Warm the verified-secret cache.
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      await jobHub.ready();
      const held = handlePollJobs(agentRequest("GET", "/jobs?wait=25", { auth }));
      await new Promise((r) => setTimeout(r, 100));
      const started = Date.now();
      expect(await revokeAgent(getDb(), auth.agentId, { userId, ip: "direct" })).toBe(true);
      const closed = await held;
      expect(closed.status).toBe(401);
      expect(Date.now() - started).toBeLessThan(2000);
      const after = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }));
      expect(after.status).toBe(401);
      const [agent] = await getDb().select().from(agents).where(eq(agents.id, auth.agentId));
      expect(agent?.currentSecretHash).toBeNull();
      expect(agent?.pendingSecretHash).toBeNull();
      expect(agent?.status).toBe("revoked");
      const audit = await getDb().select().from(auditLog).where(eq(auditLog.action, "agent.revoke"));
      expect(audit.some((a) => a.targetId === auth.agentId && a.actorId === userId)).toBe(true);
    });

    it("is effective across console processes (cache bound to the stored hash)", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(200);
      // Another process revoked the agent: this process's cache was not purged explicitly.
      await getDb()
        .update(agents)
        .set({ revokedAt: new Date(), currentSecretHash: null, status: "revoked" })
        .where(eq(agents.id, auth.agentId));
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: MINIMAL_HEARTBEAT }))).status).toBe(401);
    });
  });

  describe("audit log", () => {
    it("is append-only at the database level (M5)", async () => {
      await adminUser();
      await expect(getDb().execute(sql`update audit_log set action = 'x'`)).rejects.toThrow();
      await expect(getDb().execute(sql`delete from audit_log`)).rejects.toThrow();
      await expect(getDb().execute(sql`truncate audit_log`)).rejects.toThrow();
      const [n] = (await getDb().execute(sql`select count(*)::int as n from audit_log`)).rows;
      expect(Number(n?.n)).toBeGreaterThan(0);
    });

    it("audits a revoke of an unknown or already revoked agent (L3)", async () => {
      const userId = await adminUser();
      const auth = await enroll();
      expect(await revokeAgent(getDb(), auth.agentId, { userId, ip: null })).toBe(true);
      expect(await revokeAgent(getDb(), auth.agentId, { userId, ip: null })).toBe(false);
      const rows = await getDb()
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.targetId, auth.agentId), eq(auditLog.action, "agent.revoke")));
      expect(rows.map((r) => r.outcome).sort()).toEqual(["failure", "success"]);
    });
  });

  describe("database roles (R1, N2, L3, L4)", () => {
    it("the runtime role cannot create schemas, create in public, or touch the audit log", async () => {
      await adminUser();
      const { url } = await createRuntimeRole();
      const client = new Client({ connectionString: url });
      await client.connect();
      try {
        const [row] = (await client.query("select count(*)::int as n from users")).rows as { n: number }[];
        expect(row?.n).toBeGreaterThan(0);
        await client.query("insert into audit_log (actor_type, action) values ('system', 'user.bootstrap')");
        for (const stmt of [
          "create schema databastion",
          "create schema attacker",
          "create table public.planted (x int)",
          "create function public.format(text, name) returns text language sql as 'select 1::text'",
          "update audit_log set action = 'x'",
          "delete from audit_log",
          "truncate audit_log",
          "alter table public.audit_log disable trigger all",
          "drop trigger audit_log_no_update_delete on public.audit_log",
          "drop table public.audit_log",
        ]) {
          await expect(client.query(stmt), stmt).rejects.toThrow();
        }
        expect(await runtimeRoleWarnings(client)).toEqual([]);
      } finally {
        await client.end();
      }
    });

    it("databastion_app has no UPDATE, DELETE or TRUNCATE on audit_log and no CREATE on the database (L4)", async () => {
      const { rows } = await getDb().execute(sql`
        select has_table_privilege('databastion_app', 'public.audit_log', 'UPDATE') as upd,
               has_table_privilege('databastion_app', 'public.audit_log', 'DELETE') as del,
               has_table_privilege('databastion_app', 'public.audit_log', 'TRUNCATE') as trunc,
               has_table_privilege('databastion_app', 'public.audit_log', 'INSERT') as ins,
               has_database_privilege('databastion_app', current_database(), 'CREATE') as db_create,
               has_schema_privilege('databastion_app', 'public', 'CREATE') as public_create,
               has_schema_privilege('databastion_app', 'pgboss', 'CREATE') as pgboss_create`);
      expect(rows[0]).toEqual({
        upd: false,
        del: false,
        trunc: false,
        ins: true,
        db_create: false,
        public_create: false,
        pgboss_create: true,
      });
    });

    it("warns when the console connects as the owner of audit_log (L3)", async () => {
      const warnings = await runtimeRoleWarnings(getPool());
      expect(warnings.some((w) => w.includes("owner of audit_log"))).toBe(true);
    });

    it("pg-boss installs and works as the runtime role in the pgboss schema", async () => {
      const { url } = await createRuntimeRole();
      const boss = new PgBoss(pgBossOptions(url));
      boss.on("error", () => undefined);
      await boss.start();
      try {
        await boss.createQueue("test.queue");
        const id = await boss.send("test.queue", { n: 1 });
        expect(id).toBeTruthy();
        const jobsFetched = await boss.fetch("test.queue");
        expect(jobsFetched.map((j) => j.id)).toEqual([id]);
      } finally {
        await boss.stop({ graceful: false });
      }
      const { rows } = await getDb().execute(
        sql`select count(*)::int as n from pg_catalog.pg_tables where schemaname = 'pgboss'`,
      );
      expect(Number(rows[0]?.n)).toBeGreaterThan(0);
    });
  });

  describe("POST /jobs/{job_id}/status", () => {
    async function deliveredJob(agentId: string) {
      const id = await enqueueJob(getDb(), {
        agentId,
        type: "discovery.scan",
        targetId: "pg-prod-1",
        classifiersVersion: "2026.09.1",
        params: SCAN_PARAMS,
      });
      return id;
    }

    it.each(fixtures("valid", "JobStatusUpdate"))("valid fixture %s -> 204", async (_f, body) => {
      const auth = await enroll();
      const id = await deliveredJob(auth.agentId);
      const update: Record<string, unknown> = { ...(body as Record<string, unknown>), ts: new Date().toISOString() };
      const res = await handleJobStatus(agentRequest("POST", `/jobs/${id}/status`, { auth, body: update }), id);
      expect(res.status).toBe(204);
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, id));
      expect(row?.status).toBe(update.status);
    });

    it.each(fixtures("invalid", "JobStatusUpdate"))("invalid fixture %s -> 400", async (_f, body) => {
      const auth = await enroll();
      const id = await deliveredJob(auth.agentId);
      const res = await handleJobStatus(agentRequest("POST", `/jobs/${id}/status`, { auth, body }), id);
      expect(res.status).toBe(400);
      await expectConformingError(res, body);
    });

    it("404 for unknown or foreign jobs, 409 after a terminal status, ignores older updates", async () => {
      const auth = await enroll();
      const other = await enroll("other-host");
      const foreign = await deliveredJob(other.agentId);
      const ts = new Date().toISOString();
      const running = { status: "running", ts };
      expect(
        (await handleJobStatus(agentRequest("POST", `/jobs/${foreign}/status`, { auth, body: running }), foreign)).status,
      ).toBe(404);
      const unknown = "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a";
      expect(
        (await handleJobStatus(agentRequest("POST", `/jobs/${unknown}/status`, { auth, body: running }), unknown)).status,
      ).toBe(404);
      expect(
        (await handleJobStatus(agentRequest("POST", "/jobs/NOT-A-UUID/status", { auth, body: running }), "NOT-A-UUID")).status,
      ).toBe(400);

      const id = await deliveredJob(auth.agentId);
      const post = (body: unknown) =>
        handleJobStatus(agentRequest("POST", `/jobs/${id}/status`, { auth, body }), id);
      expect((await post({ status: "running", ts, progress: { ratio: 0.5 } })).status).toBe(204);
      const older = new Date(Date.parse(ts) - 60_000).toISOString();
      expect((await post({ status: "running", ts: older, progress: { ratio: 0.1 } })).status).toBe(204);
      const [mid] = await getDb().select().from(jobs).where(eq(jobs.id, id));
      expect(mid?.progress).toEqual({ ratio: 0.5 });
      const future = new Date(Date.now() + 10 * 60_000).toISOString();
      expect((await post({ status: "running", ts: future })).status).toBe(400);
      expect((await post({ status: "succeeded", ts: new Date().toISOString() })).status).toBe(204);
      const conflict = await post({ status: "running", ts: new Date().toISOString() });
      expect(conflict.status).toBe(409);
      expect(((await conflict.json()) as { code: string }).code).toBe("conflict");
    });
  });
});
