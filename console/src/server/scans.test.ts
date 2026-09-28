import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { auditLog, findings, jobs, users } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { handleFindings, handleHeartbeat, handleJobStatus, handlePollJobs } from "@/server/agent-api/handlers";
import { failuresPerAgent } from "@/server/agent-api/auth";
import { argon2Hash } from "@/server/crypto";
import { listFindings, summarizeFindings } from "@/server/findings";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, fixtures, uuidv7 } from "@/test/helpers";

import { buildScanParams, SCAN_DEFAULTS, SCAN_GRACE_MS } from "./scans";
import {
  handleFalsePositive,
  handleLogin,
  handleRequestScan,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresPerUserGlobal,
  loginFailuresUnknownUser,
} from "./user-api";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";

function userReq(p: string, opts: { body?: unknown; cookie?: string; csrf?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: ORIGIN };
  if (opts.cookie) headers.Cookie = opts.cookie;
  if (opts.csrf) headers["X-CSRF-Token"] = opts.csrf;
  return new Request(`${ORIGIN}${p}`, {
    method: "POST",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function login(username: string) {
  const res = await handleLogin(userReq("/api/auth/login", { body: { username, password: PASSWORD } }));
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
  targets: [{ target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "limited" }],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

async function agentWithTarget(heartbeat: Record<string, unknown> = HEARTBEAT) {
  const auth = await enroll();
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: heartbeat }))).status).toBe(200);
  return auth;
}

describe("buildScanParams", () => {
  it("applies the contract defaults and keeps valid filters", () => {
    expect(buildScanParams({})).toEqual({ ok: true, params: { ...SCAN_DEFAULTS } });
    expect(buildScanParams(undefined)).toEqual({ ok: true, params: { ...SCAN_DEFAULTS } });
    const r = buildScanParams({ sample_rows: 50, databases: ["crm"], exclude_objects: [], classifiers: ["pii.email"] });
    expect(r).toEqual({
      ok: true,
      params: { ...SCAN_DEFAULTS, sample_rows: 50, databases: ["crm"], exclude_objects: [], classifiers: ["pii.email"] },
    });
  });

  it.each([
    ["sample_rows 0", { sample_rows: 0 }],
    ["sample_rows above 10000", { sample_rows: 10_001 }],
    ["fractional sample_rows", { sample_rows: 1.5 }],
    ["max_duration_s below 10", { max_duration_s: 9 }],
    ["statement_timeout_ms 0 (never unlimited)", { statement_timeout_ms: 0 }],
    ["statement_timeout_ms above 600000", { statement_timeout_ms: 600_001 }],
    ["empty databases", { databases: [] }],
    ["empty schemas", { schemas: [] }],
    ["empty include_objects", { include_objects: [] }],
    ["empty classifiers", { classifiers: [] }],
    ["duplicate classifiers", { classifiers: ["pii.email", "pii.email"] }],
    ["malformed classifier", { classifiers: ["Email"] }],
    ["quote in a name filter", { databases: ["crm'; drop table x"] }],
    ["unknown key", { target: "db.example.com" }],
    ["credential-looking key", { password: "x" }],
    ["array body", []],
    ["string body", "scan"],
  ])("rejects %s", (_name, input) => {
    expect(buildScanParams(input).ok).toBe(false);
  });
});

describe.skipIf(!hasDb)("scan launching and false positives (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let admin: { cookie: string; csrf: string };
  let analyst: { cookie: string; csrf: string };

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
    await getDb()
      .insert(users)
      .values({ username: "analyst", passwordHash: await argon2Hash(PASSWORD), role: "analyst" });
    admin = await login("admin");
    analyst = await login("analyst");
  });
  afterAll(async () => teardown?.());
  beforeEach(() => {
    loginFailuresPerIp.clear();
    loginFailuresPerUser.clear();
    loginFailuresPerUserGlobal.clear();
    loginFailuresUnknownUser.clear();
    failuresPerAgent.clear();
  });

  const scan = (agentId: string, body: unknown, who = admin, target = "pg-prod-1") =>
    handleRequestScan(
      userReq(`/api/agents/${agentId}/targets/${target}/scan`, { body, cookie: who.cookie, csrf: who.csrf }),
      agentId,
      target,
    );

  it("queues a conforming discovery.scan job with defaults, audited, served in a valid JobList", async () => {
    const auth = await agentWithTarget();
    const res = await scan(auth.agentId, { classifiers: ["pii.email"] });
    expect(res.status).toBe(202);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const { job_id: jobId } = (await res.json()) as { job_id: string };
    const [job] = await getDb().select().from(jobs).where(eq(jobs.id, jobId));
    expect(job?.type).toBe("discovery.scan");
    expect(job?.targetId).toBe("pg-prod-1");
    expect(job?.classifiersVersion).toBe("2026.09.1");
    expect(job?.params).toEqual({ ...SCAN_DEFAULTS, classifiers: ["pii.email"] });
    expect(job?.expiresAt).not.toBeNull();
    const [audit] = await getDb()
      .select()
      .from(auditLog)
      .where(and(eq(auditLog.action, "discovery.scan_request"), eq(auditLog.targetId, jobId)));
    expect(audit?.outcome).toBe("success");
    expect(audit?.details).toMatchObject({ agent_id: auth.agentId, target_id: "pg-prod-1", sample_rows: 200 });

    const poll = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    expect(poll.status).toBe(200);
    const list = (await poll.json()) as { jobs: Record<string, unknown>[] };
    expect(validateSchema("JobList", list).ok).toBe(true);
    expect(list.jobs[0]).toMatchObject({
      job_id: jobId,
      type: "discovery.scan",
      target_id: "pg-prod-1",
      classifiers_version: "2026.09.1",
      params: { ...SCAN_DEFAULTS, classifiers: ["pii.email"] },
    });

    // Status transitions through the agent API: running -> succeeded; then a new scan is allowed.
    const ts = () => new Date().toISOString();
    const status = (body: Record<string, unknown>) =>
      handleJobStatus(agentRequest("POST", `/jobs/${jobId}/status`, { auth, body }), jobId);
    expect((await status({ status: "running", ts: ts(), progress: { ratio: 0.5 } })).status).toBe(204);
    expect((await scan(auth.agentId, {})).status).toBe(409);
    expect((await status({ status: "succeeded", ts: ts(), progress: { ratio: 1, batches: 1 } })).status).toBe(204);
    expect((await status({ status: "running", ts: ts() })).status).toBe(409);
    const [done] = await getDb().select().from(jobs).where(eq(jobs.id, jobId));
    expect(done?.status).toBe("succeeded");
    expect((await scan(auth.agentId, {})).status).toBe(202);
  });

  it("one open scan per target (409 scan_in_progress); a dead scan is swept, audited, then replaced (L2)", async () => {
    const auth = await agentWithTarget();
    const first = await scan(auth.agentId, {});
    expect(first.status).toBe(202);
    const { job_id: jobId } = (await first.json()) as { job_id: string };
    const busy = await scan(auth.agentId, {});
    expect(busy.status).toBe(409);
    expect(await busy.json()).toEqual({ error: "scan_in_progress" });
    // Delivered, then running within its budget: still busy.
    expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
    await getDb().update(jobs).set({ status: "running" }).where(eq(jobs.id, jobId));
    expect((await scan(auth.agentId, {})).status).toBe(409);
    // Past delivered_at + max_duration_s + grace: dead.
    const past = new Date(Date.now() - SCAN_DEFAULTS.max_duration_s * 1000 - SCAN_GRACE_MS - 60_000);
    await getDb().update(jobs).set({ deliveredAt: past }).where(eq(jobs.id, jobId));
    const replaced = await scan(auth.agentId, {});
    expect(replaced.status).toBe(202);
    const [dead] = await getDb().select().from(jobs).where(eq(jobs.id, jobId));
    expect(dead?.status).toBe("failed");
    expect(dead?.error).toEqual({ code: "timeout" });
    const [audit] = await getDb()
      .select()
      .from(auditLog)
      .where(and(eq(auditLog.action, "job.timeout"), eq(auditLog.targetId, jobId)));
    expect(audit?.actorType).toBe("system");
    // A pending scan past expires_at is expired by the sweep, not busy.
    const { job_id: pendingId } = (await replaced.json()) as { job_id: string };
    await getDb().update(jobs).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(jobs.id, pendingId));
    expect((await scan(auth.agentId, {})).status).toBe(202);
    const [expired] = await getDb().select().from(jobs).where(eq(jobs.id, pendingId));
    expect(expired?.status).toBe("expired");
  });

  it("rejects out-of-range or unknown parameters with 400 and queues nothing", async () => {
    const auth = await agentWithTarget();
    for (const body of [{ sample_rows: 0 }, { databases: [] }, { statement_timeout_ms: 0 }, { foo: 1 }, []]) {
      const res = await scan(auth.agentId, body);
      expect(res.status).toBe(400);
    }
    expect(await getDb().select().from(jobs).where(eq(jobs.agentId, auth.agentId))).toHaveLength(0);
  });

  it("requires an admin, CSRF and a same-origin request", async () => {
    const auth = await agentWithTarget();
    expect((await scan(auth.agentId, {}, analyst)).status).toBe(403);
    expect((await scan(auth.agentId, {}, { cookie: admin.cookie, csrf: "" })).status).toBe(403);
    expect((await scan(auth.agentId, {}, { cookie: "", csrf: "" })).status).toBe(401);
    const denied = await getDb()
      .select()
      .from(auditLog)
      .where(and(eq(auditLog.action, "user.access_denied"), eq(auditLog.outcome, "failure")));
    expect(denied.some((d) => (d.details as Record<string, unknown>).route === "discovery.scan_request")).toBe(true);
  });

  it("404 for unknown agents or targets, revoked agents and removed targets; 409 while not ready", async () => {
    const auth = await agentWithTarget();
    expect((await scan(uuidv7(), {})).status).toBe(404);
    expect((await scan(auth.agentId, {}, admin, "unknown-target")).status).toBe(404);
    expect((await scan(auth.agentId, {}, admin, "Not A Slug")).status).toBe(404);
    await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: { ...HEARTBEAT, targets: [] } }));
    expect((await scan(auth.agentId, {})).status).toBe(404);
    const noVersion = { ...HEARTBEAT } as Record<string, unknown>;
    delete noVersion.classifiers_version;
    const young = await agentWithTarget(noVersion);
    expect((await scan(young.agentId, {})).status).toBe(409);
    const failures = await getDb()
      .select()
      .from(auditLog)
      .where(and(eq(auditLog.action, "discovery.scan_request"), eq(auditLog.outcome, "failure")));
    expect(failures.length).toBeGreaterThanOrEqual(4);
  });

  it("the JobList gate never serves a scan job whose params break the contract", async () => {
    const auth = await agentWithTarget();
    const bad = [
      { sample_rows: 0, max_duration_s: 900 },
      { sample_rows: 200, max_duration_s: 900, databases: [] },
      { sample_rows: 200, max_duration_s: 900, statement_timeout_ms: 0 },
      { sample_rows: 200, max_duration_s: 900, connection_string: "postgres://u:p@db/crm" },
    ];
    const ids: string[] = [];
    for (const params of bad) {
      ids.push(
        await enqueueJob(getDb(), {
          agentId: auth.agentId,
          type: "discovery.scan",
          targetId: "pg-prod-1",
          classifiersVersion: "2026.09.1",
          params,
        }),
      );
    }
    const res = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    expect(res.status).toBe(204);
    for (const id of ids) {
      const [row] = await getDb().select().from(jobs).where(eq(jobs.id, id));
      expect(row?.status).toBe("failed");
    }
  });

  it.each(fixtures("valid", "JobList").filter(([f]) => f.includes("discovery-scan")))(
    "fixture %s params are accepted by buildScanParams",
    (_f, list) => {
      for (const job of (list as { jobs: { params: Record<string, unknown> }[] }).jobs) {
        expect(buildScanParams(job.params).ok).toBe(true);
      }
    },
  );

  describe("false positives", () => {
    async function withFinding() {
      const auth = await agentWithTarget();
      const jobId = (await ((await scan(auth.agentId, {})).json())) as { job_id: string };
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
      const body = {
        batch_id: uuidv7(),
        job_id: jobId.job_id,
        classifiers_version: "2026.09.1",
        findings: [
          {
            target_id: "pg-prod-1",
            location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "email" },
            classifier: "pii.email",
            confidence: 0.9,
            sampled: 10,
            matched: 9,
          },
          {
            target_id: "pg-prod-1",
            location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "note" },
            classifier: "pii.phone",
            confidence: 0.4,
            sampled: 10,
            matched: 1,
          },
        ],
      };
      expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
      const rows = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      const phone = rows.find((r) => r.classifier === "pii.phone");
      return { auth, id: String(phone?.id) };
    }

    const mark = (id: string, value: unknown, who = admin) =>
      handleFalsePositive(
        userReq(`/api/findings/${id}/false-positive`, { body: { false_positive: value }, cookie: who.cookie, csrf: who.csrf }),
        id,
      );

    it("marks and unmarks (admin only, audited with agent, target, classifier); hidden by default", async () => {
      const { auth, id } = await withFinding();
      expect((await mark(id, true, analyst)).status).toBe(403);
      expect((await mark(id, true)).status).toBe(204);
      const [row] = await getDb().select().from(findings).where(eq(findings.id, id));
      expect(row?.falsePositiveAt).not.toBeNull();
      expect(row?.falsePositiveBy).not.toBeNull();
      const audits = await getDb()
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.action, "finding.false_positive"), eq(auditLog.targetId, id)));
      expect(audits).toHaveLength(1);
      expect(audits[0]?.details).toEqual({
        false_positive: true,
        agent_id: auth.agentId,
        target_id: "pg-prod-1",
        classifier: "pii.phone",
      });
      expect(row?.falsePositiveMatched).toBe(1);
      expect(row?.falsePositiveClassifiersVersion).toBe("2026.09.1");

      const hidden = await listFindings(getDb(), { agentId: auth.agentId });
      expect(hidden.map((f) => f.classifier)).toEqual(["pii.email"]);
      const summary = await summarizeFindings(getDb(), { agentId: auth.agentId });
      expect(summary.map((s) => s.classifier)).toEqual(["pii.email"]);
      const all = await listFindings(getDb(), { agentId: auth.agentId, includeFalsePositives: true });
      expect(all.map((f) => f.classifier).sort()).toEqual(["pii.email", "pii.phone"]);
      expect(all.find((f) => f.id === id)?.falsePositiveAt).not.toBeNull();

      expect((await mark(id, false)).status).toBe(204);
      const [cleared] = await getDb().select().from(findings).where(eq(findings.id, id));
      expect(cleared?.falsePositiveMatched).toBeNull();
      expect((await listFindings(getDb(), { agentId: auth.agentId })).length).toBe(2);
    });

    it("validates the request: CSRF, body shape, unknown finding (audited)", async () => {
      const { id } = await withFinding();
      expect((await mark(id, true, { cookie: admin.cookie, csrf: "" })).status).toBe(403);
      expect((await mark(id, "yes")).status).toBe(400);
      expect(
        (
          await handleFalsePositive(
            userReq(`/api/findings/${id}/false-positive`, {
              body: { false_positive: true, note: "x" },
              cookie: admin.cookie,
              csrf: admin.csrf,
            }),
            id,
          )
        ).status,
      ).toBe(400);
      expect((await mark("not-a-uuid", true)).status).toBe(404);
      const unknown = uuidv7();
      expect((await mark(unknown, true)).status).toBe(404);
      const [audit] = await getDb()
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.action, "finding.false_positive"), eq(auditLog.targetId, unknown)));
      expect(audit?.outcome).toBe("failure");
    });
  });
});
