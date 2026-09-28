import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agents, agentTargets, auditLog, enrollmentTokens, jobs } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { revokeAgent } from "@/server/agents";
import { sha256Hex } from "@/server/crypto";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import {
  adminUser,
  agentRequest,
  enroll,
  expectConformingError,
  fixtures,
  newToken,
} from "@/test/helpers";

import { failuresPerAgent, failuresPerIp } from "./auth";
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
    failuresPerAgent.clear();
    failuresPerIp.clear();
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
      expect(results.filter((r) => r.status === 401)).toHaveLength(4);
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

    it("rate limits per source IP", async () => {
      const body = { token: `dbe_${"A".repeat(43)}`, hostname: "h", agent_version: "0.1.0", connectors: [] };
      let last = 0;
      for (let i = 0; i < 21; i++) {
        last = (await handleEnroll(agentRequest("POST", "/enroll", { body }))).status;
      }
      expect(last).toBe(429);
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

  describe("POST /heartbeat", () => {
    it.each(fixtures("valid", "HeartbeatRequest"))("valid fixture %s -> 200", async (_f, body) => {
      const auth = await enroll();
      const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
      expect(res.status).toBe(200);
      const out = (await res.json()) as Record<string, unknown>;
      expect(validateSchema("HeartbeatResponse", out).ok).toBe(true);
      expect(out.heartbeat_interval_s).toBe(30);
      expect(out.console_min_protocol).toBe(1);
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
