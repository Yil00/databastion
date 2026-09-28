import { and, desc, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { auditConfigs, auditLog, jobs, users } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { failuresPerAgent } from "@/server/agent-api/auth";
import { findingsPerAgent, findingsRequestsPerAgent, handleFindings, handleHeartbeat, handlePollJobs } from "@/server/agent-api/handlers";
import { revokeAgent } from "@/server/agents";
import { argon2Hash } from "@/server/crypto";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, uuidv7 } from "@/test/helpers";

import {
  assessAuditChange,
  auditSummaries,
  getAuditConfig,
  MAX_SENSITIVE_OBJECTS,
  mergeSensitiveObjects,
  parseAuditConfigInput,
  SHRINK_MIN_REMOVED,
  type SensitiveObject,
} from "./audit-config";
import {
  handleConfigureAudit,
  handleLogin,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresPerUserGlobal,
  loginFailuresUnknownUser,
} from "./user-api";

const obj = (object: string, classifiers = ["pii.email"], schema: string | null = "public"): SensitiveObject =>
  schema === null ? { database: "crm", object, classifiers } : { database: "crm", schema, object, classifiers };
const objs = (n: number, prefix = "t") => Array.from({ length: n }, (_, i) => obj(`${prefix}${i}`));

describe("audit settings model", () => {
  it("parses a request with the contract defaults made explicit", () => {
    expect(parseAuditConfigInput({ enabled: true })).toEqual({
      ok: true,
      value: {
        enabled: true,
        aggregationWindowS: 60,
        pollIntervalS: 10,
        minRows: null,
        deriveFromFindings: true,
        manualObjects: [],
        confirm: null,
      },
    });
  });

  it.each([
    ["an unknown key", { enabled: true, sensitive_objects: [] }, "unknown_key"],
    ["no enabled flag", {}, "enabled"],
    ["a window out of range", { enabled: true, aggregation_window_s: 301 }, "aggregation_window_s"],
    ["a poll interval of 0", { enabled: true, poll_interval_s: 0 }, "poll_interval_s"],
    ["negative min_rows", { enabled: true, min_rows: -1 }, "min_rows"],
    ["a value as an object name", { enabled: true, manual_objects: [{ database: "crm", object: "jane@example.com", classifiers: ["pii.email"] }] }, "manual_objects"],
    ["an SQL fragment as an object name", { enabled: true, manual_objects: [{ database: "crm", object: "t; drop table x", classifiers: ["pii.email"] }] }, "manual_objects"],
    ["an object without classifier", { enabled: true, manual_objects: [{ database: "crm", object: "t", classifiers: [] }] }, "manual_objects"],
    ["an unknown field in an object", { enabled: true, manual_objects: [{ ...obj("t"), note: "x" }] }, "manual_objects"],
    ["too many objects", { enabled: true, manual_objects: objs(MAX_SENSITIVE_OBJECTS + 1) }, "manual_objects"],
    ["a malformed confirmation", { enabled: true, confirm: "yes" }, "confirm"],
  ])("rejects %s", (_name, body, field) => {
    expect(parseAuditConfigInput(body)).toEqual({ ok: false, error: field });
  });

  it("merges manual and derived objects: classifiers united, manual first, then most sensitive, bounded", () => {
    const derived = [
      { ...obj("low", ["pii.person_name"]), sensitivity: 2 },
      { ...obj("high", ["pii.iban"]), sensitivity: 7 },
      { ...obj("both", ["pii.phone"]), sensitivity: 3 },
    ];
    const { objects, truncated } = mergeSensitiveObjects(derived, [obj("both", ["pii.email"]), obj("hand", ["secret.aws_key"], null)]);
    expect(objects.map((o) => o.object)).toEqual(["both", "hand", "high", "low"]);
    expect(objects[0]?.classifiers).toEqual(["pii.email", "pii.phone"]);
    expect(objects[1]).toEqual({ database: "crm", object: "hand", classifiers: ["secret.aws_key"] });
    expect(truncated).toBe(0);
    const many = mergeSensitiveObjects(
      objs(MAX_SENSITIVE_OBJECTS + 5).map((o, i) => ({ ...o, sensitivity: i })),
      [],
    );
    expect(many.objects).toHaveLength(MAX_SENSITIVE_OBJECTS);
    expect(many.truncated).toBe(5);
    expect(many.objects[0]?.object).toBe(`t${MAX_SENSITIVE_OBJECTS + 4}`);
  });

  it("flags a change that disables Audit, empties the list or removes many objects", () => {
    const on = (objects: SensitiveObject[]) => ({ enabled: true, objects });
    // First configuration: never a warning.
    expect(assessAuditChange(null, on([])).warning).toBeNull();
    expect(assessAuditChange(on(objs(3)), { enabled: false, objects: objs(3) }).warning).toBe("disabled");
    expect(assessAuditChange(on(objs(1)), on([]))).toMatchObject({ warning: "emptied", removed: 1, previousCount: 1, nextCount: 0 });
    // At least 50 % removed.
    expect(assessAuditChange(on(objs(10)), on(objs(5))).warning).toBe("shrunk");
    expect(assessAuditChange(on(objs(10)), on(objs(6))).warning).toBeNull();
    // At least 20 removed, whatever the ratio.
    expect(assessAuditChange(on(objs(100)), on(objs(100 - SHRINK_MIN_REMOVED))).warning).toBe("shrunk");
    expect(assessAuditChange(on(objs(100)), on(objs(100 - SHRINK_MIN_REMOVED + 1))).warning).toBeNull();
    // Replacing objects counts as removals.
    expect(assessAuditChange(on(objs(4)), on(objs(4, "u")))).toMatchObject({ warning: "shrunk", added: 4, removed: 4 });
    // Growing or keeping the list, or enabling Audit, never warns.
    expect(assessAuditChange({ enabled: false, objects: [] }, on(objs(2))).warning).toBeNull();
    expect(assessAuditChange(on([]), on([])).warning).toBeNull();
    // Classifiers of a kept object do not count.
    expect(assessAuditChange(on([obj("t0", ["pii.email"])]), on([obj("t0", ["pii.iban"])])).removed).toBe(0);
  });
});

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";
type Who = { cookie: string; csrf: string };
type Auth = { agentId: string; secret: string };

function userReq(method: string, p: string, opts: { body?: unknown; who?: Who; origin?: string; csrf?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: opts.origin ?? ORIGIN };
  if (opts.who?.cookie) headers.Cookie = opts.who.cookie;
  const csrf = opts.csrf ?? opts.who?.csrf;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  return new Request(`${ORIGIN}${p}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
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
  targets: [{ target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "full", audit_source: "pgaudit" }],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

const finding = (object: string, classifier = "pii.email", confidence = 0.9) => ({
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object, field: "c" },
  classifier,
  confidence,
  sampled: 100,
  matched: 50,
});

async function agentWithFindings(objects: string[]): Promise<Auth> {
  const auth = await enroll();
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
  if (objects.length > 0) {
    await enqueueJob(getDb(), {
      agentId: auth.agentId,
      type: "discovery.scan",
      targetId: "pg-prod-1",
      classifiersVersion: "2026.09.1",
      params: { sample_rows: 200, max_duration_s: 900 },
    });
    const { jobs: list } = (await (await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).json()) as { jobs: { job_id: string }[] };
    const body = { batch_id: uuidv7(), job_id: list[0]?.job_id, classifiers_version: "2026.09.1", findings: objects.map((o) => finding(o)) };
    expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
  }
  return auth;
}

describe.skipIf(!hasDb)("audit.configure (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let admin: Who;
  let analyst: Who;
  let adminId: string;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    adminId = await adminUser();
    await getDb().insert(users).values({ username: "analyst", passwordHash: await argon2Hash(PASSWORD), role: "analyst" });
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
    findingsPerAgent.clear();
    findingsRequestsPerAgent.clear();
  });

  const configure = (auth: Auth, body: unknown, opts: { who?: Who; origin?: string; csrf?: string; target?: string } = {}) =>
    handleConfigureAudit(
      userReq("POST", `/api/agents/${auth.agentId}/targets/${opts.target ?? "pg-prod-1"}/audit`, { body, who: opts.who ?? admin, origin: opts.origin, csrf: opts.csrf }),
      auth.agentId,
      opts.target ?? "pg-prod-1",
    );

  async function auditJobs(agentId: string) {
    return getDb()
      .select()
      .from(jobs)
      .where(and(eq(jobs.agentId, agentId), eq(jobs.type, "audit.configure")))
      .orderBy(desc(jobs.createdAt));
  }

  async function audits(agentId: string) {
    const rows = await getDb().select().from(auditLog).where(eq(auditLog.action, "audit.configure")).orderBy(desc(auditLog.at));
    return rows.filter((r) => r.targetId === agentId || (r.details as Record<string, unknown> | null)?.agent_id === agentId);
  }

  it("queues a contract audit.configure job with the objects derived from the findings, audited", async () => {
    const auth = await agentWithFindings(["clients", "orders"]);
    const res = await configure(auth, { enabled: true, min_rows: 10_000 });
    expect(res.status).toBe(202);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ warning: null, previous_objects: 0, next_objects: 2, added_objects: 2, removed_objects: 0 });
    const [job] = await auditJobs(auth.agentId);
    expect(job).toMatchObject({ id: body.job_id, status: "pending", targetId: "pg-prod-1", createdBy: adminId });
    expect(job?.params).toEqual({
      enabled: true,
      aggregation_window_s: 60,
      poll_interval_s: 10,
      min_rows: 10_000,
      sensitive_objects: [
        { database: "crm", schema: "public", object: "clients", classifiers: ["pii.email"] },
        { database: "crm", schema: "public", object: "orders", classifiers: ["pii.email"] },
      ],
    });
    // The agent receives it through the long-poll, as a contract JobList.
    const poll = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    const list = (await poll.json()) as unknown;
    expect(validateSchema("JobList", list).ok).toBe(true);
    expect(list).toMatchObject({ jobs: [{ job_id: body.job_id, type: "audit.configure", target_id: "pg-prod-1" }] });
    const [audit] = await audits(auth.agentId);
    expect(audit).toMatchObject({ actorId: adminId, outcome: "success", targetType: "job", targetId: body.job_id });
    expect(audit?.details).toMatchObject({ enabled: true, derived_objects: 2, next_objects: 2, removed_objects: 0, warning: null, confirmed: false });
    const view = await getAuditConfig(getDb(), auth.agentId, "pg-prod-1");
    expect(view).toMatchObject({ configured: true, enabled: true, minRows: 10_000, warning: null, lastJob: { id: body.job_id, status: "delivered" } });
    expect(view?.sentObjects).toHaveLength(2);
  });

  it("an emptying change needs a confirmation of the exact settings; then it is queued with a warning on the target", async () => {
    const auth = await agentWithFindings(["clients"]);
    expect((await configure(auth, { enabled: true })).status).toBe(202);
    const res = await configure(auth, { enabled: true, derive_from_findings: false });
    expect(res.status).toBe(409);
    const refused = (await res.json()) as Record<string, unknown>;
    expect(refused).toMatchObject({ error: "confirmation_required", warning: "emptied", previous_objects: 1, next_objects: 0, removed_objects: 1 });
    expect(refused.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(await auditJobs(auth.agentId)).toHaveLength(1);
    const [failure] = await audits(auth.agentId);
    expect(failure).toMatchObject({ outcome: "failure", targetId: auth.agentId });
    expect(failure?.details).toMatchObject({ reason: "confirmation_required", warning: "emptied", removed_objects: 1 });
    // A confirmation of other settings is not a confirmation of these.
    expect((await configure(auth, { enabled: true, derive_from_findings: false, confirm: "0".repeat(64) })).status).toBe(409);
    const ok = await configure(auth, { enabled: true, derive_from_findings: false, confirm: refused.digest });
    expect(ok.status).toBe(202);
    const [job] = await auditJobs(auth.agentId);
    expect(job?.params).toMatchObject({ enabled: true, sensitive_objects: [] });
    const [success] = await audits(auth.agentId);
    expect(success?.details).toMatchObject({ warning: "emptied", confirmed: true, removed_objects: 1, next_objects: 0 });
    expect((await auditSummaries(getDb(), auth.agentId)).get("pg-prod-1")).toEqual({ enabled: true, objects: 0, warning: "emptied", warningRemoved: 1 });
    // A later change that does not narrow clears the warning.
    expect((await configure(auth, { enabled: true })).status).toBe(202);
    expect((await auditSummaries(getDb(), auth.agentId)).get("pg-prod-1")).toMatchObject({ objects: 1, warning: null });
  });

  it("disabling Audit and removing many objects also need a confirmation", async () => {
    const auth = await agentWithFindings([]);
    const manual = objs(30);
    expect((await configure(auth, { enabled: true, manual_objects: manual })).status).toBe(202);
    const shrink = await configure(auth, { enabled: true, manual_objects: manual.slice(0, 10) });
    expect(shrink.status).toBe(409);
    const s = (await shrink.json()) as { warning: string; removed_objects: number; digest: string };
    expect(s).toMatchObject({ warning: "shrunk", removed_objects: 20 });
    expect((await configure(auth, { enabled: true, manual_objects: manual.slice(0, 10), confirm: s.digest })).status).toBe(202);
    const off = await configure(auth, { enabled: false, manual_objects: manual.slice(0, 10) });
    expect(off.status).toBe(409);
    const d = (await off.json()) as { warning: string; digest: string };
    expect(d.warning).toBe("disabled");
    expect((await configure(auth, { enabled: false, manual_objects: manual.slice(0, 10), confirm: d.digest })).status).toBe(202);
    const [row] = await getDb().select().from(auditConfigs).where(eq(auditConfigs.agentId, auth.agentId));
    expect(row).toMatchObject({ enabled: false, warning: "disabled" });
  });

  it("supersedes the settings jobs not delivered yet", async () => {
    const auth = await agentWithFindings(["clients"]);
    expect((await configure(auth, { enabled: true })).status).toBe(202);
    expect((await configure(auth, { enabled: true, poll_interval_s: 30 })).status).toBe(202);
    const list = await auditJobs(auth.agentId);
    expect(list.map((j) => j.status)).toEqual(["pending", "cancelled"]);
  });

  it("admin only, same origin and CSRF; unknown, removed or revoked targets are 404", async () => {
    const auth = await agentWithFindings(["clients"]);
    expect((await configure(auth, { enabled: true }, { who: analyst })).status).toBe(403);
    expect((await configure(auth, { enabled: true }, { csrf: "nope" })).status).toBe(403);
    expect((await configure(auth, { enabled: true }, { origin: "http://evil.test" })).status).toBe(403);
    expect((await configure(auth, { enabled: true }, { who: { cookie: "", csrf: "" } })).status).toBe(401);
    expect((await configure(auth, { enabled: true }, { target: "pg-nope" })).status).toBe(404);
    expect((await configure(auth, { enabled: true }, { target: "Not a slug" })).status).toBe(404);
    expect((await configure(auth, { enabled: "yes" })).status).toBe(400);
    expect(await auditJobs(auth.agentId)).toHaveLength(0);
    const denied = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.access_denied")));
    expect(denied.some((d) => (d.details as Record<string, unknown>).route === "audit.configure")).toBe(true);
    await revokeAgent(getDb(), auth.agentId, { userId: adminId, ip: null });
    expect((await configure(auth, { enabled: true })).status).toBe(404);
  });
});
