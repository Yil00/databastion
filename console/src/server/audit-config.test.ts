import { and, desc, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditConfigs, auditLog, jobs, securityEvents, users } from "@/db/schema";
import { minRowsWarning } from "@/lib/audit-warning";
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
  auditRequeueBudget,
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
  it("#235 review N2: warns on min_rows only on a key-pattern engine, 0 included", () => {
    expect(minRowsWarning(true, 0)).toBe("no_row_counts");
    expect(minRowsWarning(true, 1000)).toBe("no_row_counts");
    expect(minRowsWarning(true, null)).toBeNull();
    expect(minRowsWarning(false, 1000)).toBeNull();
  });

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

  it("keeps every spelling of an object as Discovery or the administrator wrote it (N1: the agent matches without case)", () => {
    const derived = [
      { ...obj("Customers", ["pii.email"]), sensitivity: 3 },
      { ...obj("customers", ["pii.iban"]), sensitivity: 7 },
    ];
    const { objects } = mergeSensitiveObjects(derived, [obj("customers", ["pii.phone"]), obj("CUSTOMERS", ["pii.phone"])]);
    expect(objects.map((o) => o.object)).toEqual(["CUSTOMERS", "customers", "Customers"]);
    expect(objects[1]?.classifiers).toEqual(["pii.iban", "pii.phone"]);
    expect(objects[2]?.classifiers).toEqual(["pii.email"]);
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
    expect(body).toMatchObject({ warning: null, previous_objects: 0, next_objects: 2, added_objects: 2, removed_objects: 0, min_rows_warning: null });
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

  /** An agent with a Redis target and two findings there: a key pattern and a plain name. */
  async function redisAgentWithFindings(accepts?: string[]): Promise<Auth> {
    const auth = await enroll();
    const hb = {
      ...HEARTBEAT,
      connectors: ["postgres", "redis"],
      targets: [{ target_id: "cache-redis", engine: "redis", reachable: true, audit_level: "limited", audit_source: "redis_slowlog" }],
      ...(accepts ? { accepts } : {}),
    };
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: hb }))).status).toBe(200);
    await enqueueJob(getDb(), {
      agentId: auth.agentId,
      type: "discovery.scan",
      targetId: "cache-redis",
      classifiersVersion: "2026.09.1",
      params: { sample_rows: 200, max_duration_s: 900 },
    });
    const { jobs: list } = (await (await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).json()) as { jobs: { job_id: string }[] };
    const redisFinding = (object: string) => ({
      target_id: "cache-redis",
      location: { engine: "redis", database: "db0", schema: "hash", object, field: "email" },
      classifier: "pii.email",
      confidence: 0.9,
      sampled: 100,
      matched: 50,
    });
    const body = { batch_id: uuidv7(), job_id: list[0]?.job_id, classifiers_version: "2026.09.1", findings: [redisFinding("user:*:profile"), redisFinding("profiles")] };
    expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
    return auth;
  }

  it("P9-E review M3: on a Redis target of an agent without sensitive_object.key_pattern, key patterns are left out, never failing the save; turning Audit off works", async () => {
    const auth = await redisAgentWithFindings();
    const on = await configure(auth, { enabled: true }, { target: "cache-redis" });
    expect(on.status).toBe(202);
    expect(await on.json()).toMatchObject({ next_objects: 1, skipped_key_patterns: 1 });
    const [job] = await auditJobs(auth.agentId);
    expect(job?.params).toMatchObject({ enabled: true, sensitive_objects: [{ database: "db0", schema: "hash", object: "profiles", classifiers: ["pii.email"] }] });
    const [audit] = await audits(auth.agentId);
    expect(audit?.details).toMatchObject({ derived_objects: 1, skipped_key_patterns: 1 });
    expect((await getAuditConfig(getDb(), auth.agentId, "cache-redis"))?.agentAcceptsKeyPatterns).toBe(false);
    // Turning Audit off: confirmation, then queued.
    const off = await configure(auth, { enabled: false }, { target: "cache-redis" });
    expect(off.status).toBe(409);
    const d = (await off.json()) as { digest: string };
    expect((await configure(auth, { enabled: false, confirm: d.digest }, { target: "cache-redis" })).status).toBe(202);
    const [row] = await getDb().select().from(auditConfigs).where(eq(auditConfigs.agentId, auth.agentId));
    expect(row).toMatchObject({ enabled: false });
    // A key pattern typed by hand is kept in the settings but left out of the job, and counted
    // (here the change empties the objects sent: a confirmation first).
    const settings = {
      enabled: true,
      derive_from_findings: false,
      manual_objects: [{ database: "db0", object: "user:*:email", classifiers: ["pii.email"] }],
    };
    const emptied = await configure(auth, settings, { target: "cache-redis" });
    expect(emptied.status).toBe(409);
    const e = (await emptied.json()) as { digest: string; skipped_key_patterns: number; warning: string };
    expect(e).toMatchObject({ warning: "emptied", skipped_key_patterns: 1 });
    const manual = await configure(auth, { ...settings, confirm: e.digest }, { target: "cache-redis" });
    expect(manual.status).toBe(202);
    expect(await manual.json()).toMatchObject({ next_objects: 0, skipped_key_patterns: 1 });
    const [latest] = await auditJobs(auth.agentId);
    expect(latest?.params).toMatchObject({ enabled: true, sensitive_objects: [] });
    expect((await getAuditConfig(getDb(), auth.agentId, "cache-redis"))?.manualObjects).toEqual([{ database: "db0", object: "user:*:email", classifiers: ["pii.email"] }]);
  });

  it("phase 9 follow-ups: an agent that lists sensitive_object.key_pattern receives the key patterns, from findings and typed by hand", async () => {
    const auth = await redisAgentWithFindings(["future.feature", "sensitive_object.key_pattern"]);
    const [stored] = await getDb().select({ accepts: agents.accepts }).from(agents).where(eq(agents.id, auth.agentId));
    // Only the tokens this console knows are stored.
    expect(stored?.accepts).toEqual(["sensitive_object.key_pattern"]);
    expect((await getAuditConfig(getDb(), auth.agentId, "cache-redis"))?.agentAcceptsKeyPatterns).toBe(true);
    const on = await configure(
      auth,
      { enabled: true, manual_objects: [{ database: "db1", object: "session:*:token", classifiers: ["pii.phone"] }] },
      { target: "cache-redis" },
    );
    expect(on.status).toBe(202);
    expect(await on.json()).toMatchObject({ next_objects: 3, skipped_key_patterns: 0 });
    const [job] = await auditJobs(auth.agentId);
    const sent = (job?.params as { sensitive_objects: SensitiveObject[] }).sensitive_objects.map((o) => o.object).sort();
    expect(sent).toEqual(["profiles", "session:*:token", "user:*:profile"]);
    // Delivered as such, and a conforming JobList.
    const polled = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    const { jobs: list } = (await polled.json()) as { jobs: { type: string; params: { sensitive_objects: SensitiveObject[] } }[] };
    const delivered = list.find((j) => j.type === "audit.configure");
    expect(delivered?.params.sensitive_objects.map((o) => o.object).sort()).toEqual(sent);
    expect(validateSchema("JobList", { jobs: list }).ok).toBe(true);
  });

  const REDIS_HB = {
    ...HEARTBEAT,
    connectors: ["postgres", "redis"],
    targets: [{ target_id: "cache-redis", engine: "redis", reachable: true, audit_level: "limited", audit_source: "redis_slowlog" }],
  };

  it("#280 review M2: a downgraded agent's settings are queued again without key patterns, with a warning, by the system", async () => {
    const auth = await redisAgentWithFindings(["sensitive_object.key_pattern"]);
    expect((await configure(auth, { enabled: true }, { target: "cache-redis" })).status).toBe(202);
    // A rolled-back agent: its next heartbeat lists nothing.
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: REDIS_HB }))).status).toBe(200);
    const [latest, first] = await auditJobs(auth.agentId);
    expect(first?.status).toBe("cancelled");
    expect((latest?.params as { sensitive_objects: SensitiveObject[] }).sensitive_objects.map((o) => o.object)).toEqual(["profiles"]);
    expect(latest?.createdBy).toBeNull();
    const [row] = await getDb().select().from(auditConfigs).where(eq(auditConfigs.agentId, auth.agentId));
    expect(row).toMatchObject({ warning: "shrunk", warningRemoved: 1 });
    const [audit] = await audits(auth.agentId);
    expect(audit).toMatchObject({ actorType: "system", actorId: null });
    expect(audit?.details).toMatchObject({ reason: "agent_accepts_changed", key_patterns: 0, removed_objects: 1, warning: "shrunk" });
    // The same heartbeat again changes nothing: no new job.
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: REDIS_HB }))).status).toBe(200);
    expect(await auditJobs(auth.agentId)).toHaveLength(2);
  });

  it("#280 review M2 and re-review N2: an upgraded agent gets the key patterns left out before; plain names and the stored warning are kept", async () => {
    const auth = await redisAgentWithFindings();
    const on = await configure(auth, { enabled: true }, { target: "cache-redis" });
    expect(await on.json()).toMatchObject({ next_objects: 1, skipped_key_patterns: 1 });
    expect((await auditJobs(auth.agentId))[0]?.params).toMatchObject({ sensitive_objects: [{ object: "profiles" }] });
    // What was sent last is the base, never today's findings: a plain name sent before stays, one
    // that was not sent is not added (here, `profiles` taken out of the record of what was sent),
    // and an earlier warning on the target stays.
    await getDb()
      .update(auditConfigs)
      .set({ sentObjects: [{ database: "db0", object: "kept_plain", classifiers: ["pii.email"] }], warning: "shrunk", warningRemoved: 7 })
      .where(eq(auditConfigs.agentId, auth.agentId));
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: { ...REDIS_HB, accepts: ["sensitive_object.key_pattern"] } }))).status).toBe(200);
    const [latest] = await auditJobs(auth.agentId);
    expect((latest?.params as { sensitive_objects: SensitiveObject[] }).sensitive_objects.map((o) => o.object)).toEqual(["kept_plain", "user:*:profile"]);
    const [row] = await getDb().select().from(auditConfigs).where(eq(auditConfigs.agentId, auth.agentId));
    expect(row).toMatchObject({ warning: "shrunk", warningRemoved: 7 });
    const [audit] = await audits(auth.agentId);
    expect(audit?.details).toMatchObject({ reason: "agent_accepts_changed", added_objects: 1, removed_objects: 0, key_patterns: 1, warning: null });
  });

  it("#280 re-review N1: an agent flipping its tokens gets at most 4 requeues an hour, then one accepts_flapping integrity event", async () => {
    const auth = await redisAgentWithFindings();
    expect((await configure(auth, { enabled: true }, { target: "cache-redis" })).status).toBe(202);
    for (let i = 0; i < 8; i++) {
      const body = i % 2 === 0 ? { ...REDIS_HB, accepts: ["sensitive_object.key_pattern"] } : REDIS_HB;
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
    }
    // 8 changes: the first 4 are requeued (each one changes the key patterns sent), then none.
    expect(await auditJobs(auth.agentId)).toHaveLength(1 + 4);
    const events = await getDb().select().from(securityEvents).where(eq(securityEvents.agentId, auth.agentId));
    expect(events.filter((e) => e.kind === "agent.accepts_flapping")).toHaveLength(1);
  });

  it("#280 re-review L-a: a change past the requeue budget is deferred, audited once, and acted on from a later heartbeat", async () => {
    const auth = await redisAgentWithFindings();
    expect((await configure(auth, { enabled: true }, { target: "cache-redis" })).status).toBe(202);
    const withToken = { ...REDIS_HB, accepts: ["sensitive_object.key_pattern"] };
    const hb = async (body: unknown) => expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
    const sentObjects = async () => ((await auditJobs(auth.agentId))[0]?.params as { sensitive_objects: SensitiveObject[] }).sensitive_objects.map((o) => o.object).sort();
    const mark = async () => (await getDb().select({ dueAt: agents.auditRequeueDueAt }).from(agents).where(eq(agents.id, auth.agentId)))[0]?.dueAt;
    const deferrals = async () =>
      (await getDb().select().from(auditLog).where(and(eq(auditLog.action, "audit.requeue_deferred"), eq(auditLog.targetId, auth.agentId))));
    // Four changes spend the budget (each one requeued), ending without the token.
    for (let i = 0; i < 4; i++) await hb(i % 2 === 0 ? withToken : REDIS_HB);
    expect(await auditJobs(auth.agentId)).toHaveLength(1 + 4);
    expect(await mark()).toBeNull();
    // The fifth change (an upgrade) is stored but not requeued: the agent is marked, audited once.
    await hb(withToken);
    expect((await getDb().select({ accepts: agents.accepts }).from(agents).where(eq(agents.id, auth.agentId)))[0]?.accepts).toEqual(["sensitive_object.key_pattern"]);
    expect(await auditJobs(auth.agentId)).toHaveLength(5);
    expect(await sentObjects()).toEqual(["profiles"]);
    expect(await mark()).toBeInstanceOf(Date);
    const [deferred] = await deferrals();
    expect(deferred).toMatchObject({ actorType: "system", outcome: "failure", targetType: "agent" });
    expect(deferred?.details).toEqual({ agent_id: auth.agentId, reason: "budget_spent" });
    // Later heartbeats in the same window: nothing queued, no second audit entry or integrity event.
    await hb(withToken);
    await hb(withToken);
    expect(await auditJobs(auth.agentId)).toHaveLength(5);
    expect(await deferrals()).toHaveLength(1);
    const flapping = async () => (await getDb().select().from(securityEvents).where(eq(securityEvents.agentId, auth.agentId))).filter((e) => e.kind === "agent.accepts_flapping");
    expect(await flapping()).toHaveLength(1);
    // The window is over: the next heartbeat, with no change, queues the settings from the latest
    // tokens and clears the mark.
    auditRequeueBudget.clear();
    await hb(withToken);
    expect(await auditJobs(auth.agentId)).toHaveLength(6);
    expect(await sentObjects()).toEqual(["profiles", "user:*:profile"]);
    const [audit] = await audits(auth.agentId);
    expect(audit?.details).toMatchObject({ reason: "agent_accepts_changed", added_objects: 1, deferred: true });
    expect(await mark()).toBeNull();
    await hb(withToken);
    expect(await auditJobs(auth.agentId)).toHaveLength(6);
    expect(await flapping()).toHaveLength(1);
  });

  it("#280 re-review L-a: an agent without Redis / Valkey Audit settings is not marked past the budget", async () => {
    const auth = await enroll();
    for (let i = 0; i < 6; i++) {
      const body = i % 2 === 0 ? { ...REDIS_HB, accepts: ["sensitive_object.key_pattern"] } : REDIS_HB;
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
    }
    const [row] = await getDb().select({ dueAt: agents.auditRequeueDueAt }).from(agents).where(eq(agents.id, auth.agentId));
    expect(row?.dueAt).toBeNull();
    expect((await getDb().select().from(auditLog).where(and(eq(auditLog.action, "audit.requeue_deferred"), eq(auditLog.targetId, auth.agentId))))).toHaveLength(0);
  });

  it("#280 review M2 and L4: a job carrying key patterns is delivered without them to an agent that never listed the token, recorded on the job", async () => {
    const auth = await redisAgentWithFindings();
    const params = {
      enabled: true,
      sensitive_objects: [
        { database: "db0", object: "user:*:email", classifiers: ["pii.email"] },
        { database: "db0", object: "profiles", classifiers: ["pii.email"] },
      ],
    };
    const id = await enqueueJob(getDb(), { agentId: auth.agentId, type: "audit.configure", targetId: "cache-redis", params });
    const polled = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    const { jobs: list } = (await polled.json()) as { jobs: { job_id: string; params: { sensitive_objects: SensitiveObject[] } }[] };
    const delivered = list.find((j) => j.job_id === id);
    expect(delivered?.params.sensitive_objects.map((o) => o.object)).toEqual(["profiles"]);
    const [job] = await getDb().select().from(jobs).where(eq(jobs.id, id));
    expect(job?.deliveredWithoutKeyPatterns).toBe(1);
    expect((job?.params as typeof params).sensitive_objects).toHaveLength(2);
    expect((await getAuditConfig(getDb(), auth.agentId, "cache-redis"))?.lastJob?.deliveredWithoutKeyPatterns).toBe(1);
  });

  it("phase 9 follow-ups: a key pattern typed by hand for a target of another engine is refused", async () => {
    const auth = await agentWithFindings([]);
    const r = await configure(auth, { enabled: true, manual_objects: [{ database: "crm", object: "user:*:email", classifiers: ["pii.email"] }] });
    expect(r.status).toBe(400);
    expect(await auditJobs(auth.agentId)).toHaveLength(0);
  });

  it("#235 review N2: min_rows on a Redis / Valkey target is saved with a warning, in the answer and the audit entry", async () => {
    const auth = await enroll();
    const hb = {
      ...HEARTBEAT,
      connectors: ["postgres", "redis"],
      targets: [
        ...HEARTBEAT.targets,
        { target_id: "cache-valkey", engine: "valkey", reachable: true, audit_level: "limited", audit_source: "redis_commandlog" },
      ],
    };
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: hb }))).status).toBe(200);
    const withRows = await configure(auth, { enabled: true, min_rows: 100 }, { target: "cache-valkey" });
    expect(withRows.status).toBe(202);
    expect(await withRows.json()).toMatchObject({ min_rows_warning: "no_row_counts" });
    const [job] = await auditJobs(auth.agentId);
    expect(job?.params).toMatchObject({ enabled: true, min_rows: 100 });
    const [audit] = await audits(auth.agentId);
    expect(audit?.details).toMatchObject({ target_id: "cache-valkey", min_rows: 100, min_rows_warning: "no_row_counts" });
    // Without min_rows: no warning; on a SQL target, min_rows carries none either.
    const without = await configure(auth, { enabled: true }, { target: "cache-valkey" });
    expect(await without.json()).toMatchObject({ min_rows_warning: null });
    const sql = await configure(auth, { enabled: true, min_rows: 100 });
    expect(sql.status).toBe(202);
    expect(await sql.json()).toMatchObject({ min_rows_warning: null });
    // The warning rides along with a confirmation request too.
    const off = await configure(auth, { enabled: false, min_rows: 5 }, { target: "cache-valkey" });
    expect(off.status).toBe(409);
    expect(await off.json()).toMatchObject({ error: "confirmation_required", min_rows_warning: "no_row_counts" });
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
