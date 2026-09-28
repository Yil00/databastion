import { and, eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Client, Pool } from "pg";
import { PgBoss } from "pg-boss";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import * as schema from "@/db/schema";
import { runtimeRoleWarnings } from "@/server/db-role-check";
import { auditLog, findings, incidents, jobs, policies, policyExceptions, users } from "@/db/schema";
import { logger } from "@/lib/logger";
import { findingsPerAgent, findingsRequestsPerAgent, handleFindings, handleHeartbeat, handlePollJobs } from "@/server/agent-api/handlers";
import { failuresPerAgent } from "@/server/agent-api/auth";
import { argon2Hash } from "@/server/crypto";
import { enqueueJob } from "@/server/jobs";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, uuidv7 } from "@/test/helpers";
import { pgBossOptions, registerPolicyQueue } from "@/worker/queues";

import { dedupKey, drainPolicyWork, getIncident, listIncidents, reopensResolved, transitionIncident } from "./incidents";
import { POLICY_QUEUE, setPolicyJobSender } from "./policy-queue";
import {
  handleCreateException,
  handleCreatePolicy,
  handleDeleteException,
  handleDeletePolicy,
  handleFalsePositive,
  handleIncidentTransition,
  handleLogin,
  handleUpdatePolicy,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresPerUserGlobal,
  loginFailuresUnknownUser,
} from "./user-api";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";
type Who = { cookie: string; csrf: string };
type Auth = { agentId: string; secret: string };

function userReq(method: string, p: string, opts: { body?: unknown; who?: Who; origin?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: opts.origin ?? ORIGIN };
  if (opts.who?.cookie) headers.Cookie = opts.who.cookie;
  if (opts.who?.csrf) headers["X-CSRF-Token"] = opts.who.csrf;
  return new Request(`${ORIGIN}${p}`, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function login(username: string): Promise<Who> {
  const res = await handleLogin(userReq("POST", "/api/auth/login", { body: { username, password: PASSWORD } }));
  expect(res.status).toBe(200);
  const cookie = (res.headers.getSetCookie().find((c) => c.startsWith("databastion_session=")) ?? "").split(";")[0] ?? "";
  const { csrf_token: csrf } = (await res.json()) as { csrf_token: string };
  return { cookie, csrf };
}

const HEARTBEAT = {
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 12,
  classifiers_version: "2026.09.1",
  connectors: ["postgres"],
  targets: [
    { target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "limited" },
    { target_id: "pg-test", engine: "postgres", reachable: true, audit_level: "limited" },
  ],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

/** Masked samples: must never appear outside the encrypted `findings.masked_samples` column (I2). */
const SAMPLES = ["j*******@e******.com", "m****@e******.org"];

const finding = (over: Record<string, unknown> = {}) => ({
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "email" },
  classifier: "pii.email",
  confidence: 0.97,
  sampled: 200,
  matched: 150,
  masked_samples: SAMPLES,
  ...over,
});

const PHONE = {
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "phone" },
  classifier: "pii.phone",
  confidence: 0.8,
  sampled: 200,
  matched: 40,
};

async function agentWithTargets(): Promise<Auth> {
  const auth = await enroll();
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
  return auth;
}

/** A scan job of `targetId`, delivered to (claimed by) the agent. */
async function claimedScan(auth: Auth, targetId = "pg-prod-1"): Promise<string> {
  const jobId = await enqueueJob(getDb(), {
    agentId: auth.agentId,
    type: "discovery.scan",
    targetId,
    classifiersVersion: "2026.09.1",
    params: { sample_rows: 200, max_duration_s: 900 },
  });
  expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
  return jobId;
}

/** A batch of `items` for the claimed job `jobId`, accepted. */
async function sendBatch(auth: Auth, jobId: string, items: Record<string, unknown>[]): Promise<void> {
  const body = { batch_id: uuidv7(), job_id: jobId, classifiers_version: "2026.09.1", findings: items };
  const res = await handleFindings(agentRequest("POST", "/findings", { auth, body }));
  expect(res.status).toBe(202);
}

/** One delivered scan of `targetId` and a batch of `items`, accepted. */
async function scanWith(auth: Auth, items: Record<string, unknown>[], targetId = "pg-prod-1"): Promise<void> {
  await sendBatch(auth, await claimedScan(auth, targetId), items);
}

async function findingId(agentId: string, classifier = "pii.email", field = "email"): Promise<string> {
  const [row] = await getDb()
    .select({ id: findings.id })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), eq(findings.classifier, classifier), eq(findings.fieldName, field)));
  if (!row) throw new Error("no finding");
  return row.id;
}

async function incidentsOf(agentId: string) {
  return getDb().select().from(incidents).where(eq(incidents.agentId, agentId)).orderBy(incidents.createdAt);
}

async function audits(action: string, targetId?: string) {
  return getDb()
    .select()
    .from(auditLog)
    .where(targetId ? and(eq(auditLog.action, action), eq(auditLog.targetId, targetId)) : eq(auditLog.action, action));
}

describe.skipIf(!hasDb)("policies and incidents (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let admin: Who;
  let analyst: Who;
  let analystId: string;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
    const [a] = await getDb()
      .insert(users)
      .values({ username: "analyst", passwordHash: await argon2Hash(PASSWORD), role: "analyst" })
      .returning({ id: users.id });
    analystId = String(a?.id);
    admin = await login("admin");
    analyst = await login("analyst");
  });
  afterAll(async () => teardown?.());
  beforeEach(async () => {
    loginFailuresPerIp.clear();
    loginFailuresPerUser.clear();
    loginFailuresPerUserGlobal.clear();
    loginFailuresUnknownUser.clear();
    failuresPerAgent.clear();
    findingsPerAgent.clear();
    findingsRequestsPerAgent.clear();
    // Every test starts without policies (their incidents are kept, keyed by agent).
    await getDb().delete(policies);
    await drainPolicyWork(getDb());
  });
  afterEach(() => setPolicyJobSender(null));

  const create = (body: unknown, who: Who = admin) => handleCreatePolicy(userReq("POST", "/api/policies", { body, who }));
  const update = (id: string, body: unknown, who: Who = admin) =>
    handleUpdatePolicy(userReq("PATCH", `/api/policies/${id}`, { body, who }), id);
  const remove = (id: string, who: Who = admin) => handleDeletePolicy(userReq("DELETE", `/api/policies/${id}`, { who }), id);
  const transition = (id: string, status: string, who: Who = admin) =>
    handleIncidentTransition(userReq("POST", `/api/incidents/${id}/transition`, { body: { status }, who }), id);
  const except = (body: unknown, who: Who = admin) =>
    handleCreateException(userReq("POST", "/api/policy-exceptions", { body, who }));
  const unexcept = (id: string, who: Who = admin) =>
    handleDeleteException(userReq("DELETE", `/api/policy-exceptions/${id}`, { who }), id);

  const EMAIL_POLICY = {
    name: "Emails in production",
    description: "Any e-mail column",
    conditions: { classifiers: ["pii.email"], target_ids: ["pg-prod-1"], min_confidence: 0.9 },
    actions: [
      { type: "create_incident", severity: "high" },
      { type: "notify", channel: "secops-mail" },
    ],
  };

  async function newPolicy(body: Record<string, unknown> = EMAIL_POLICY): Promise<string> {
    const res = await create(body);
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  }

  describe("policy API: admin only, CSRF, strict validation, audited", () => {
    it("creates, updates and deletes (admin), with identifier-only audit details", async () => {
      const id = await newPolicy();
      const [row] = await getDb().select().from(policies).where(eq(policies.id, id));
      expect(row?.revision).toBe(1);
      expect(row?.conditions).toEqual(EMAIL_POLICY.conditions);
      const [created] = await audits("policy.create", id);
      expect(created?.outcome).toBe("success");
      expect(created?.details).toMatchObject({ severity: "high", classifiers: "pii.email", notify_channels: "secops-mail" });
      // No free text in the audit log.
      expect(JSON.stringify(created?.details)).not.toContain("Emails in production");
      expect(JSON.stringify(created?.details)).not.toContain("Any e-mail");

      expect((await update(id, { enabled: false, name: "Renamed" })).status).toBe(204);
      const [updated] = await getDb().select().from(policies).where(eq(policies.id, id));
      expect(updated?.revision).toBe(2);
      expect(updated?.enabled).toBe(false);
      expect((await audits("policy.update", id))[0]?.details).toMatchObject({ changed: "enabled,name", revision: 2 });

      expect((await remove(id)).status).toBe(204);
      expect((await remove(id)).status).toBe(404);
      expect((await audits("policy.delete", id)).map((a) => a.outcome).sort()).toEqual(["failure", "success"]);
    });

    it("refuses analysts (403, audited), missing CSRF, cross-origin and anonymous requests", async () => {
      const deniedBefore = (await audits("user.access_denied")).length;
      expect((await create(EMAIL_POLICY, analyst)).status).toBe(403);
      expect((await create(EMAIL_POLICY, { cookie: admin.cookie, csrf: "" })).status).toBe(403);
      expect((await handleCreatePolicy(userReq("POST", "/api/policies", { body: EMAIL_POLICY, who: admin, origin: "http://evil.test" }))).status).toBe(403);
      expect((await create(EMAIL_POLICY, { cookie: "", csrf: "" })).status).toBe(401);
      const id = await newPolicy();
      expect((await update(id, { enabled: false }, analyst)).status).toBe(403);
      expect((await remove(id, analyst)).status).toBe(403);
      expect((await except({ target_id: "pg-prod-1", reason: "test" }, analyst)).status).toBe(403);
      const denied = await audits("user.access_denied");
      // Analyst x4, missing CSRF, cross-origin (the anonymous request has no user to audit).
      expect(denied.length - deniedBefore).toBe(6);
      expect((await getDb().select().from(policies)).length).toBe(1);
    });

    it.each([
      ["unknown key", { ...EMAIL_POLICY, owner: "x" }, "unknown_key"],
      ["unregistered classifier", { ...EMAIL_POLICY, conditions: { classifiers: ["pii.nope"] } }, "classifiers"],
      ["unknown condition key", { ...EMAIL_POLICY, conditions: { sql: "select 1" } }, "conditions"],
      ["no incident action", { ...EMAIL_POLICY, actions: [{ type: "notify", channel: "x" }] }, "actions.create_incident"],
      ["address as channel", { ...EMAIL_POLICY, actions: [{ type: "create_incident", severity: "low" }, { type: "notify", channel: "a@b.c" }] }, "actions.channel"],
      ["control characters in the name", { ...EMAIL_POLICY, name: "a‮b" }, "name"],
      ["missing name", { conditions: {}, actions: EMAIL_POLICY.actions }, "name"],
      ["unknown source", { ...EMAIL_POLICY, source: "access_event" }, "source"],
    ])("rejects %s (400 invalid_policy + field)", async (_name, body, field) => {
      const res = await create(body);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_policy", field });
    });

    it("rejects a duplicate name (case-insensitive) with 409", async () => {
      await newPolicy();
      expect((await create({ ...EMAIL_POLICY, name: "EMAILS IN PRODUCTION" })).status).toBe(409);
    });
  });

  describe("execution in the worker", () => {
    it("creates one incident per matching (policy, finding); re-evaluations never duplicate it", async () => {
      const auth = await agentWithTargets();
      const policyId = await newPolicy();
      await scanWith(auth, [finding(), PHONE]);
      const stats = await drainPolicyWork(getDb());
      expect(stats.created).toBe(1);
      let rows = await incidentsOf(auth.agentId);
      expect(rows).toHaveLength(1);
      const email = await findingId(auth.agentId);
      expect(rows[0]).toMatchObject({
        status: "open",
        severity: "high",
        policyId,
        policyName: "Emails in production",
        policyRevision: 1,
        findingId: email,
        targetId: "pg-prod-1",
        classifier: "pii.email",
        dedupKey: dedupKey(policyId, email),
        notifyChannels: ["secops-mail"],
        matchCount: 1,
      });
      const [created] = await audits("incident.create", rows[0]?.id);
      expect(created?.actorType).toBe("system");

      // Same revision again (retry, duplicate job, concurrent workers): nothing changes.
      await Promise.all([drainPolicyWork(getDb()), drainPolicyWork(getDb())]);
      // A full pass of the policy over the same finding revision: nothing either.
      await getDb().update(policies).set({ changedAt: sql`now()` }).where(eq(policies.id, policyId));
      await drainPolicyWork(getDb());
      rows = await incidentsOf(auth.agentId);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.matchCount).toBe(1);

      // A rescan (new finding revision) re-matches the open incident once.
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      await drainPolicyWork(getDb());
      rows = await incidentsOf(auth.agentId);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.matchCount).toBe(2);
      expect((await audits("incident.create", rows[0]?.id)).length).toBe(1);
    });

    it("the unique index forbids a second active incident for a dedup key", async () => {
      const auth = await agentWithTargets();
      await newPolicy();
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      const [row] = await incidentsOf(auth.agentId);
      const { id: _id, createdAt: _c, ...copy } = row as NonNullable<typeof row>;
      await expect(getDb().insert(incidents).values(copy)).rejects.toThrow();
    });

    it("applies a new, changed or re-enabled policy to the existing findings (full pass)", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding(), PHONE]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(0);

      const id = await newPolicy({ ...EMAIL_POLICY, enabled: false });
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(0);

      expect((await update(id, { enabled: true })).status).toBe(204);
      const stats = await drainPolicyWork(getDb());
      expect(stats.policyPasses).toBe(1);
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      const [p] = await getDb().select().from(policies).where(eq(policies.id, id));
      expect(p?.evaluatedAt).not.toBeNull();

      expect((await update(id, { conditions: { classifiers: ["pii.*"], location: { object: "cli*" } } })).status).toBe(204);
      await drainPolicyWork(getDb());
      const rows = await incidentsOf(auth.agentId);
      expect(rows.map((r) => r.classifier).sort()).toEqual(["pii.email", "pii.phone"]);
      expect(rows.find((r) => r.classifier === "pii.phone")?.policyRevision).toBe(3);
    });

    it("matches thresholds and target conditions", async () => {
      const auth = await agentWithTargets();
      await newPolicy({ ...EMAIL_POLICY, conditions: { classifiers: ["pii.email"], min_matched: 100, min_match_ratio: 0.5 } });
      await scanWith(auth, [finding({ matched: 99 })]);
      await scanWith(auth, [finding({ target_id: "pg-test", matched: 150 })], "pg-test");
      await drainPolicyWork(getDb());
      const rows = await incidentsOf(auth.agentId);
      expect(rows.map((r) => r.targetId)).toEqual(["pg-test"]);
    });

    it("wakes the worker after an accepted batch, not on a duplicate", async () => {
      const send = vi.fn(async () => undefined);
      setPolicyJobSender(send);
      const auth = await agentWithTargets();
      const jobId = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "discovery.scan",
        targetId: "pg-prod-1",
        classifiersVersion: "2026.09.1",
        params: { sample_rows: 200, max_duration_s: 900 },
      });
      await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
      const body = { batch_id: uuidv7(), job_id: jobId, classifiers_version: "2026.09.1", findings: [finding()] };
      expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
      expect(send).toHaveBeenCalledTimes(1);
      expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
      expect(send).toHaveBeenCalledTimes(1);
      // A failing sender never fails the request (the worker's schedule catches up).
      setPolicyJobSender(async () => {
        throw new Error("queue down");
      });
      const again = { ...body, batch_id: uuidv7() };
      expect((await handleFindings(agentRequest("POST", "/findings", { auth, body: again }))).status).toBe(202);
    });

    it("drains through a real pg-boss queue run by the runtime role", async () => {
      const { url } = await createRuntimeRole();
      const boss = new PgBoss(pgBossOptions(url));
      boss.on("error", () => undefined);
      await boss.start();
      try {
        await registerPolicyQueue(boss, getDb, logger, { pollingIntervalSeconds: 0.5 });
        const auth = await agentWithTargets();
        await newPolicy();
        await scanWith(auth, [finding()]);
        await boss.send(POLICY_QUEUE, {});
        for (let i = 0; i < 100 && (await incidentsOf(auth.agentId)).length === 0; i++) {
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      } finally {
        await boss.stop({ graceful: false, timeout: 2000 });
      }
    });
  });

  describe("drain", () => {
    it("evaluates every pending finding once, beyond one chunk, and leaves none pending (timestamp precision)", async () => {
      const auth = await agentWithTargets();
      await newPolicy();
      const items = Array.from({ length: 250 }, (_, i) => finding({ location: { engine: "postgres", database: "crm", schema: "public", object: `t${i}`, field: "email" } }));
      const jobId = await claimedScan(auth);
      await sendBatch(auth, jobId, items.slice(0, 200));
      await sendBatch(auth, jobId, items.slice(200));
      const stats = await drainPolicyWork(getDb());
      expect(stats.findings).toBe(250);
      expect(stats.more).toBe(false);
      expect(await incidentsOf(auth.agentId)).toHaveLength(250);
      const [pending] = (
        await getDb().execute<{ n: number }>(sql`select count(*)::int as n from findings where policy_evaluated_at is distinct from last_seen_at`)
      ).rows;
      expect(pending?.n).toBe(0);
      expect((await drainPolicyWork(getDb())).findings).toBe(0);
    });
  });

  describe("exceptions", () => {
    it("suppresses matching findings; expiry and deletion let the policy apply again", async () => {
      const auth = await agentWithTargets();
      const policyId = await newPolicy();
      const res = await except({ policy_id: policyId, target_id: "pg-prod-1", location: { object: "clients" }, reason: "Known test data" });
      expect(res.status).toBe(201);
      const { id } = (await res.json()) as { id: string };
      const [audit] = await audits("policy_exception.create", id);
      expect(audit?.details).toMatchObject({ policy_id: policyId, target_id: "pg-prod-1", location: true, expires_at: null });
      expect(JSON.stringify(audit?.details)).not.toContain("Known test data");

      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(0);

      // Expiry: the policy is due for a full pass once an exception of it has expired.
      await getDb()
        .update(policyExceptions)
        .set({ expiresAt: new Date(Date.now() - 1000) })
        .where(eq(policyExceptions.id, id));
      await getDb().update(policies).set({ evaluatedAt: new Date(Date.now() - 5000) }).where(eq(policies.id, policyId));
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      expect((await unexcept(id)).status).toBe(204);
      expect((await unexcept(id)).status).toBe(404);
    });

    it("a global exception covers every policy; deleting it re-evaluates", async () => {
      const auth = await agentWithTargets();
      await newPolicy();
      await newPolicy({ ...EMAIL_POLICY, name: "Any PII", conditions: { classifiers: ["pii.*"] } });
      const res = await except({ agent_id: auth.agentId, classifier: "pii.*", reason: "Staging copy" });
      const { id } = (await res.json()) as { id: string };
      await scanWith(auth, [finding(), PHONE]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(0);
      expect((await unexcept(id)).status).toBe(204);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(3);
    });

    it.each([
      ["no scope", { reason: "x" }, "scope"],
      ["no reason", { target_id: "pg-prod-1" }, "reason"],
      ["past expiry", { target_id: "pg-prod-1", reason: "x", expires_at: "2020-01-01T00:00:00Z" }, "expires_at"],
      ["bad classifier", { classifier: "pii.nope", reason: "x" }, "classifier"],
      ["unknown key", { target_id: "pg-prod-1", reason: "x", note: "y" }, "unknown_key"],
    ])("rejects %s", async (_name, body, field) => {
      const res = await except(body);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_exception", field });
    });

    it("404 for an unknown policy", async () => {
      const res = await except({ policy_id: "01890a5d-ac96-774b-bcce-b302099a8057", target_id: "pg-prod-1", reason: "x" });
      expect(res.status).toBe(404);
    });
  });

  describe("incident lifecycle", () => {
    async function openIncident() {
      const auth = await agentWithTargets();
      const policyId = await newPolicy();
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      const [row] = await incidentsOf(auth.agentId);
      if (!row) throw new Error("no incident");
      return { auth, policyId, id: row.id };
    }

    it("open -> acknowledged -> resolved by an analyst, with actor, timestamp and audit", async () => {
      const { id } = await openIncident();
      expect((await transition(id, "acknowledged", analyst)).status).toBe(204);
      expect((await transition(id, "resolved", analyst)).status).toBe(204);
      const [row] = await getDb().select().from(incidents).where(eq(incidents.id, id));
      expect(row?.status).toBe("resolved");
      expect(row?.acknowledgedBy).toBe(analystId);
      expect(row?.acknowledgedAt).not.toBeNull();
      expect(row?.resolvedBy).toBe(analystId);
      const trail = await audits("incident.transition", id);
      expect(trail.map((a) => a.details)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ from: "open", to: "acknowledged" }),
          expect.objectContaining({ from: "acknowledged", to: "resolved" }),
        ]),
      );
      expect(trail.every((a) => a.actorId === analystId)).toBe(true);
      const view = await getIncident(getDb(), id);
      expect(view?.resolvedBy).toBe("analyst");
      expect(view?.location).toEqual({ databaseName: "crm", schemaName: "public", objectName: "clients", fieldName: "email" });
    });

    it("refuses transitions outside the lifecycle (409, audited as failures) and bad bodies", async () => {
      const { id } = await openIncident();
      expect((await transition(id, "resolved")).status).toBe(204);
      const res = await transition(id, "acknowledged");
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "invalid_transition", from: "resolved" });
      expect((await transition(id, "open")).status).toBe(400);
      expect((await transition(id, "closed")).status).toBe(400);
      expect((await transition("01890a5d-ac96-774b-bcce-b302099a8057", "resolved")).status).toBe(404);
      expect((await transition(id, "resolved", { cookie: admin.cookie, csrf: "" })).status).toBe(403);
      const failures = (await audits("incident.transition", id)).filter((a) => a.outcome === "failure");
      expect(failures[0]?.details).toMatchObject({ from: "resolved", to: "acknowledged", reason: "invalid_transition" });
    });

    it("M1: resolved = remediated; a later scan that still sees the finding opens a new incident", async () => {
      const { auth, id } = await openIncident();
      expect((await transition(id, "resolved", analyst)).status).toBe(204);
      // No rescan: re-evaluations (retries, a full pass after a policy edit) open nothing.
      await drainPolicyWork(getDb());
      await getDb().update(policies).set({ changedAt: sql`now()` });
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      // A rescan with identical data still sees the finding: a new incident.
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      await drainPolicyWork(getDb());
      const rows = await incidentsOf(auth.agentId);
      expect(rows.map((r) => r.status)).toEqual(["resolved", "open"]);
      expect(rows[1]?.matchCount).toBe(1);
    });

    it("N1: a scan in flight during the resolution does not reopen; the next scan does", async () => {
      const { auth, id } = await openIncident();
      // The scan is claimed by the agent (it may already be reading) before the resolution.
      const inFlight = await claimedScan(auth);
      const [claimed] = await getDb().select({ first: jobs.firstDeliveredAt }).from(jobs).where(eq(jobs.id, inFlight));
      expect(claimed?.first).not.toBeNull();
      expect((await transition(id, "resolved", analyst)).status).toBe(204);
      // Its batch arrives after the resolution (ingestion time later than resolved_at): data read
      // before the resolution, so nothing reopens.
      await sendBatch(auth, inFlight, [finding()]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).map((r) => r.status)).toEqual(["resolved"]);
      // A later redelivery (lease expiry) does not move the first claim time.
      await getDb().execute(sql`update jobs set delivered_at = now() + interval '1 hour' where id = ${inFlight}`);
      await getDb().update(policies).set({ changedAt: sql`now()` });
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      // A scan claimed after the resolution still sees the finding: a new incident.
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).map((r) => r.status)).toEqual(["resolved", "open"]);
    });

    it("M1: an admin false positive stays silent across identical rescans", async () => {
      const { auth, id } = await openIncident();
      expect((await transition(id, "false_positive")).status).toBe(204);
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).map((r) => r.status)).toEqual(["false_positive"]);
    });

    it("M1: reopensResolved keeps the growth / reclassification triggers", () => {
      const t = new Date("2026-09-28T12:00:00Z");
      const inc = { resolvedAt: t, findingMatched: 150, findingClassifiersVersion: "2026.09.1" };
      const f = { lastSeenAt: new Date(t.getTime() - 1000), matched: 150, classifiersVersion: "2026.09.1" };
      expect(reopensResolved(inc, f)).toBe(false);
      expect(reopensResolved(inc, { ...f, lastSeenAt: new Date(t.getTime() + 1) })).toBe(true);
      expect(reopensResolved(inc, { ...f, matched: 151 })).toBe(true);
      expect(reopensResolved(inc, { ...f, classifiersVersion: "2099.01.1" })).toBe(true);
      // N1: the scan claim time decides, not the ingestion time.
      const late = new Date(t.getTime() + 60_000);
      expect(reopensResolved(inc, { ...f, lastSeenAt: late, scanClaimedAt: new Date(t.getTime() - 1) })).toBe(false);
      expect(reopensResolved(inc, { ...f, lastSeenAt: late, scanClaimedAt: new Date(t.getTime() + 1) })).toBe(true);
      expect(reopensResolved(inc, { ...f, lastSeenAt: late, scanClaimedAt: null })).toBe(true);
    });

    it("L3: an incident resolved while the engine re-matches it falls through to the resolved rules", async () => {
      const { auth, id } = await openIncident();
      await scanWith(auth, [finding()]);
      const c = new Client({ connectionString: process.env.DATABASE_URL });
      await c.connect();
      try {
        await c.query("begin");
        // Resolved before the rescan (so the rescan reopens it), row lock held until commit.
        await c.query(
          "update incidents set status = 'resolved', resolved_at = now() - interval '1 hour' where id = $1",
          [id],
        );
        const drain = drainPolicyWork(getDb());
        await new Promise((r) => setTimeout(r, 300));
        await c.query("commit");
        await drain;
      } finally {
        await c.end();
      }
      const rows = await incidentsOf(auth.agentId);
      expect(rows.map((r) => r.status)).toEqual(["resolved", "open"]);
    });

    it("L1: a false-positive transition and the engine on the same finding do not deadlock", async () => {
      for (let i = 0; i < 3; i++) {
        await getDb().delete(policies);
        const { auth, id } = await openIncident();
        await scanWith(auth, [finding()]);
        const [t] = await Promise.all([transition(id, "false_positive"), drainPolicyWork(getDb())]);
        expect(t.status).toBe(204);
        await drainPolicyWork(getDb());
        expect((await incidentsOf(auth.agentId)).map((r) => r.status)).toEqual(["false_positive"]);
      }
    });

    it("L4: an incomplete full pass does not hold back the pending findings", async () => {
      const auth = await agentWithTargets();
      const emailPolicy = await newPolicy();
      await newPolicy({ ...EMAIL_POLICY, name: "Phones", conditions: { classifiers: ["pii.phone"], min_matched: 45 } });
      await scanWith(auth, [finding(), PHONE]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).map((r) => r.classifier)).toEqual(["pii.email"]);
      // The phone finding becomes pending and matching; the e-mail policy needs a full pass.
      await scanWith(auth, [{ ...PHONE, matched: 50 }]);
      await getDb().update(policies).set({ changedAt: sql`now()` }).where(eq(policies.id, emailPolicy));
      const email = await findingId(auth.agentId);
      const c = new Client({ connectionString: process.env.DATABASE_URL });
      await c.connect();
      try {
        await c.query("begin");
        await c.query("select 1 from findings where id = $1 for update", [email]);
        const stats = await drainPolicyWork(getDb());
        expect(stats.more).toBe(true);
        await c.query("commit");
      } finally {
        await c.end();
      }
      expect((await incidentsOf(auth.agentId)).map((r) => r.classifier).sort()).toEqual(["pii.email", "pii.phone"]);
      const [p] = await getDb().select().from(policies).where(eq(policies.id, emailPolicy));
      expect(p !== undefined && (p.evaluatedAt === null || p.evaluatedAt < p.changedAt)).toBe(true);
    });

    it("false positive: admin only; marks the finding and closes its incidents; unmarking re-evaluates", async () => {
      const { auth, id } = await openIncident();
      await newPolicy({ ...EMAIL_POLICY, name: "All PII", conditions: { classifiers: ["pii.*"] } });
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(2);

      expect((await transition(id, "false_positive", analyst)).status).toBe(403);
      const [denied] = (await audits("user.access_denied")).filter((a) => a.actorId === analystId).slice(-1);
      expect(denied?.details).toEqual({ route: "incident.transition", reason: "role" });

      expect((await transition(id, "false_positive")).status).toBe(204);
      const email = await findingId(auth.agentId);
      const [f] = await getDb().select().from(findings).where(eq(findings.id, email));
      expect(f?.falsePositiveAt).not.toBeNull();
      let rows = await incidentsOf(auth.agentId);
      expect(rows.map((r) => r.status)).toEqual(["false_positive", "false_positive"]);
      const [mark] = await audits("finding.false_positive", email);
      expect(mark?.details).toMatchObject({ false_positive: true, incident_id: id });

      // A false-positive finding raises nothing, rescanned or not.
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(2);

      // Unmarked on the findings page: the policies apply again.
      const unmark = await handleFalsePositive(
        userReq("POST", `/api/findings/${email}/false-positive`, { body: { false_positive: false }, who: admin }),
        email,
      );
      expect(unmark.status).toBe(204);
      await drainPolicyWork(getDb());
      rows = await incidentsOf(auth.agentId);
      expect(rows.filter((r) => r.status === "open")).toHaveLength(2);
    });

    it("marking the finding a false positive on the findings page closes its incidents", async () => {
      const { auth, id } = await openIncident();
      const email = await findingId(auth.agentId);
      const res = await handleFalsePositive(
        userReq("POST", `/api/findings/${email}/false-positive`, { body: { false_positive: true }, who: admin }),
        email,
      );
      expect(res.status).toBe(204);
      const [row] = await getDb().select().from(incidents).where(eq(incidents.id, id));
      expect(row?.status).toBe("false_positive");
      const [audit] = await audits("incident.transition", id);
      expect(audit?.details).toMatchObject({ from: "open", to: "false_positive", via: "finding" });
    });

    it("lists with filters on status, severity and target", async () => {
      const { auth, id } = await openIncident();
      const open = await listIncidents(getDb(), { statuses: ["open"], severity: "high", agentId: auth.agentId, targetId: "pg-prod-1" });
      expect(open.map((i) => i.id)).toEqual([id]);
      expect(await listIncidents(getDb(), { severity: "low", agentId: auth.agentId })).toHaveLength(0);
      expect(await listIncidents(getDb(), { targetId: "pg-test", agentId: auth.agentId })).toHaveLength(0);
      expect(await listIncidents(getDb(), { statuses: ["resolved"], agentId: auth.agentId })).toHaveLength(0);
    });
  });

  describe("storage", () => {
    it("I2: no masked sample in clear in incidents, policies, exceptions or the audit log", async () => {
      const auth = await agentWithTargets();
      await newPolicy();
      await except({ target_id: "pg-test", reason: "Only test data" });
      await scanWith(auth, [finding()]);
      await drainPolicyWork(getDb());
      const [incident] = await incidentsOf(auth.agentId);
      await transition(String(incident?.id), "acknowledged");
      const res = await getDb().execute(sql`
        select coalesce(string_agg(t, ' '), '') as s from (
          select row_to_json(i)::text as t from incidents i
          union all select row_to_json(p)::text from policies p
          union all select row_to_json(e)::text from policy_exceptions e
          union all select row_to_json(l)::text from audit_log l) x`);
      const dump = String(res.rows[0]?.s);
      expect(dump).toContain(auth.agentId);
      for (const s of SAMPLES) expect(dump).not.toContain(s);
      expect(dump).not.toContain("e******");
    });

    it("the runtime role cannot delete incidents nor rewrite their snapshot (migrations 0015, 0016)", async () => {
      const res = await getDb().execute(sql`
        select has_table_privilege('databastion_app', 'public.incidents', 'DELETE') as del,
               has_table_privilege('databastion_app', 'public.incidents', 'TRUNCATE') as trunc,
               has_table_privilege('databastion_app', 'public.incidents', 'UPDATE') as upd,
               has_column_privilege('databastion_app', 'public.incidents', 'status', 'UPDATE') as status_upd,
               has_column_privilege('databastion_app', 'public.incidents', 'match_count', 'UPDATE') as count_upd,
               has_column_privilege('databastion_app', 'public.incidents', 'severity', 'UPDATE') as sev_upd,
               has_column_privilege('databastion_app', 'public.incidents', 'dedup_key', 'UPDATE') as key_upd,
               has_column_privilege('databastion_app', 'public.incidents', 'policy_name', 'UPDATE') as name_upd,
               has_table_privilege('databastion_app', 'public.policies', 'DELETE') as pdel`);
      expect(res.rows[0]).toEqual({
        del: false,
        trunc: false,
        upd: false,
        status_upd: true,
        count_upd: true,
        sev_upd: false,
        key_upd: false,
        name_upd: false,
        pdel: true,
      });
    });

    it("the whole lifecycle and the engine work as the runtime role; the role check stays quiet", async () => {
      const { url } = await createRuntimeRole();
      const auth = await agentWithTargets();
      await newPolicy();
      await scanWith(auth, [finding()]);
      const pool = new Pool({ connectionString: url, max: 2 });
      try {
        const db = drizzle(pool, { schema });
        await drainPolicyWork(db);
        const [row] = await incidentsOf(auth.agentId);
        const actor = { userId: analystId, ip: null };
        expect(await transitionIncident(db, String(row?.id), "acknowledged", actor)).toEqual({ outcome: "ok", from: "open" });
        await scanWith(auth, [finding()]);
        await drainPolicyWork(db);
        expect((await incidentsOf(auth.agentId))[0]?.matchCount).toBe(2);
        expect(await transitionIncident(db, String(row?.id), "false_positive", actor)).toEqual({
          outcome: "ok",
          from: "acknowledged",
        });
        await expect(pool.query("update incidents set severity = 'low'")).rejects.toThrow(/permission denied/);
        await expect(pool.query("delete from incidents")).rejects.toThrow(/permission denied/);
        expect(await runtimeRoleWarnings(pool)).toEqual([]);
      } finally {
        await pool.end();
      }
    });
  });
});
