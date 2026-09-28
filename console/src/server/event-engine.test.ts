import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, auditLog, incidentEvents, incidents, notificationDeliveries, policies, principalBaselines } from "@/db/schema";
import { BASELINE_WARMUP, eventScore, objectSensitivity } from "@/lib/event-model";
import { failuresPerAgent } from "@/server/agent-api/auth";
import {
  eventsPerAgent,
  eventsRequestsPerAgent,
  findingsPerAgent,
  findingsRequestsPerAgent,
  handleEvents,
  handleFindings,
  handleHeartbeat,
  handlePollJobs,
} from "@/server/agent-api/handlers";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, uuidv7 } from "@/test/helpers";

import { EVENT_CHUNK } from "./event-engine";
import { getPrincipal, incidentEventCount, incidentEventViews, listEvents, listPrincipals, principalIncidents, principalKey } from "./events";
import { setFalsePositive } from "./findings";
import { drainPolicyWork, getIncident, transitionIncident } from "./incidents";
import { createException, createPolicy, type PolicyInput } from "./policies";

type Auth = { agentId: string; secret: string };

const HEARTBEAT = {
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 12,
  classifiers_version: "2026.09.1",
  connectors: ["postgres", "mysql"],
  targets: [
    { target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "full", audit_source: "pgaudit" },
    { target_id: "mysql-crm", engine: "mysql", reachable: true, audit_level: "partial" },
  ],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

/** Masked samples and fingerprints of the findings: never copied out of `findings` (I2). */
const SAMPLES = ["j*******@e******.com", "m****@e******.org"];
const FINGERPRINT = "hmac-sha256:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f";

const finding = (field: string, classifier: string, confidence: number, object = "clients", extra: Record<string, unknown> = {}) => ({
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object, field },
  classifier,
  confidence,
  sampled: 200,
  matched: 150,
  ...extra,
});

const HOUR = 3600_000;
/** A fixed hour in the past, so tests do not depend on where the clock is within the hour. */
const T0 = Date.parse("2026-09-27T10:05:00Z");
const at = (offsetMs: number) => new Date(T0 + offsetMs).toISOString();

const dumpEvent = (over: Record<string, unknown> = {}) => ({
  target_id: "pg-prod-1",
  ts: at(0),
  principal: { db_user: "backup", client_addr: "192.0.2.14", application: "pg_dump" },
  action: "read",
  objects: [{ database: "crm", schema: "public", object: "clients" }],
  rows: 1_250_000,
  signals: ["signature.pg_dump", "shape.full_table_copy"],
  source: "pgaudit",
  aggregated_count: 1,
  ...over,
});

async function agentWithTargets(): Promise<Auth> {
  const auth = await enroll();
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
  return auth;
}

async function scanWith(auth: Auth, items: Record<string, unknown>[]): Promise<void> {
  await enqueueJob(getDb(), {
    agentId: auth.agentId,
    type: "discovery.scan",
    targetId: "pg-prod-1",
    classifiersVersion: "2026.09.1",
    params: { sample_rows: 200, max_duration_s: 900 },
  });
  const poll = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
  const { jobs } = (await poll.json()) as { jobs: { job_id: string }[] };
  const body = { batch_id: uuidv7(), job_id: jobs[0]?.job_id, classifiers_version: "2026.09.1", findings: items };
  expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
}

async function send(auth: Auth, events: Record<string, unknown>[]): Promise<void> {
  const res = await handleEvents(agentRequest("POST", "/events", { auth, body: { batch_id: uuidv7(), events } }));
  expect(res.status).toBe(202);
}

let adminId: string;
const actor = () => ({ userId: adminId, ip: null });

async function policy(conditions: Record<string, unknown>, over: Partial<PolicyInput> = {}): Promise<string> {
  const r = await createPolicy(
    getDb(),
    {
      name: `p-${uuidv7()}`,
      description: null,
      enabled: true,
      source: "access_event",
      conditions: conditions as PolicyInput["conditions"],
      actions: [
        { type: "create_incident", severity: "high" },
        { type: "notify", channel: "secops" },
      ],
      ...over,
    },
    actor(),
  );
  if (r.outcome !== "ok") throw new Error("policy not created");
  return r.id;
}

/** Incidents of an agent, oldest first (incidents of one transaction share `created_at`). */
async function incidentsOf(agentId: string) {
  return getDb().select().from(incidents).where(eq(incidents.agentId, agentId)).orderBy(incidents.createdAt, incidents.lastEventAt);
}

async function eventsOf(agentId: string) {
  return getDb().select().from(accessEvents).where(eq(accessEvents.agentId, agentId)).orderBy(accessEvents.ts, accessEvents.itemIndex);
}

describe.skipIf(!hasDb)("access event correlation (PostgreSQL)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    adminId = await adminUser();
  });
  afterAll(async () => teardown?.());
  beforeEach(async () => {
    failuresPerAgent.clear();
    findingsPerAgent.clear();
    findingsRequestsPerAgent.clear();
    eventsPerAgent.clear();
    eventsRequestsPerAgent.clear();
    await getDb().delete(policies);
    await drainPolicyWork(getDb());
  });

  describe("scoring", () => {
    it("scores each event by the sensitivity of its objects (findings, false positives excluded) and its volume", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [
        finding("email", "pii.email", 0.97, "clients", { masked_samples: SAMPLES, fingerprints: [FINGERPRINT] }),
        finding("iban", "pii.iban", 0.9),
        finding("note", "pii.phone", 0.5, "orders"),
      ]);
      await send(auth, [
        dumpEvent(),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "orders" }], rows: 999 }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "orders" }, { database: "crm", schema: "public", object: "clients" }], rows: 10 }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "audit" }] }),
        dumpEvent({ objects: [{ database: "crm", schema: "private", object: "clients" }] }),
        dumpEvent({ rows: undefined }),
      ]);
      const stats = await drainPolicyWork(getDb());
      expect(stats.events).toBeGreaterThanOrEqual(6);
      const rows = await eventsOf(auth.agentId);
      const clients = objectSensitivity([
        { classifier: "pii.email", confidence: 0.97 },
        { classifier: "pii.iban", confidence: 0.9 },
      ]);
      expect(rows.map((r) => r.sensitivity)).toEqual([clients, 1.5, clients, 0, 0, clients]);
      expect(rows.map((r) => r.score)).toEqual([
        eventScore(clients, 1_250_000),
        eventScore(1.5, 999),
        eventScore(clients, 10),
        0,
        0,
        0,
      ]);
      expect(rows.every((r) => r.evaluatedAt !== null)).toBe(true);

      // A false positive no longer counts.
      const [iban] = await getDb().execute<{ id: string }>(sql`select id from findings where agent_id = ${auth.agentId} and classifier = 'pii.iban'`).then((r) => r.rows);
      await setFalsePositive(getDb(), String(iban?.id), true, actor());
      await send(auth, [dumpEvent({ ts: at(60_000) })]);
      await drainPolicyWork(getDb());
      const last = (await eventsOf(auth.agentId)).at(-1);
      expect(last?.sensitivity).toBe(objectSensitivity([{ classifier: "pii.email", confidence: 0.97 }]));
    });

    it("an event without schema matches the findings of any schema (MySQL-like sources)", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding("email", "pii.email", 1)]);
      await send(auth, [dumpEvent({ objects: [{ database: "crm", object: "clients" }], rows: 99 })]);
      await drainPolicyWork(getDb());
      expect((await eventsOf(auth.agentId))[0]?.score).toBe(6);
    });
  });

  describe("policies over access events", () => {
    it("pg_dump -> incident: linked event, principal, database, score, audit entry and outbox row", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding("email", "pii.email", 0.97, "clients", { masked_samples: SAMPLES, fingerprints: [FINGERPRINT] })]);
      const pid = await policy({ signals: ["signature.*"], target_ids: ["pg-prod-1"] });
      await send(auth, [dumpEvent()]);
      const stats = await drainPolicyWork(getDb());
      expect(stats.created).toBe(1);
      const [inc] = await incidentsOf(auth.agentId);
      const [ev] = await eventsOf(auth.agentId);
      expect(inc).toMatchObject({
        source: "access_event",
        policyId: pid,
        severity: "high",
        status: "open",
        targetId: "pg-prod-1",
        principal: "backup",
        eventDatabase: "crm",
        accessEventId: ev?.id,
        eventScore: ev?.score,
        eventRows: 1_250_000,
        eventSignals: ["shape.full_table_copy", "signature.pg_dump"],
        matchCount: 1,
        findingId: null,
        classifier: null,
      });
      expect(inc?.eventBucket?.toISOString()).toBe("2026-09-27T10:00:00.000Z");
      expect(inc?.dedupKey).toContain(`principal:${principalKey({ db_user: "backup" })}`);
      expect(inc?.dedupKey).not.toContain("backup");
      const links = await getDb().select().from(incidentEvents).where(eq(incidentEvents.incidentId, String(inc?.id)));
      expect(links.map((l) => l.eventId)).toEqual([ev?.id]);
      const [audit] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "incident.create"), eq(auditLog.targetId, String(inc?.id))));
      expect(audit?.details).toMatchObject({ source: "access_event", policy_id: pid, access_event_id: ev?.id });
      const [delivery] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(inc?.id)));
      expect(delivery).toMatchObject({ event: "incident.opened", channelSlug: "secops", status: "skipped", lastError: "unknown_channel" });
      expect(delivery?.payload).toMatchObject({
        source: "access_event",
        principal: "backup",
        database: "crm",
        access: { action: "read", rows: 1_250_000, signals: ["signature.pg_dump", "shape.full_table_copy"] },
      });
      const view = await getIncident(getDb(), String(inc?.id));
      expect(view?.access).toMatchObject({ principal: "backup", database: "crm", rows: 1_250_000 });
      expect(await incidentEventCount(getDb(), String(inc?.id))).toBe(1);
      expect((await incidentEventViews(getDb(), String(inc?.id)))[0]?.incidentIds).toEqual([inc?.id]);
    });

    it("dedup: one incident per policy, principal, database and hour; resolved suppresses the rest of the hour", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.pg_dump"] });
      // A pg_dump of two tables of `crm`, then of another database, in the same hour.
      await send(auth, [
        dumpEvent(),
        dumpEvent({ ts: at(1000), objects: [{ database: "crm", schema: "public", object: "orders" }], rows: 10, signals: ["signature.pg_dump", "shape.copy_to"] }),
        dumpEvent({ ts: at(2000), objects: [{ database: "billing", schema: "public", object: "invoices" }] }),
      ]);
      await drainPolicyWork(getDb());
      let list = await incidentsOf(auth.agentId);
      expect(list.map((i) => [i.eventDatabase, i.matchCount, i.eventRows])).toEqual([
        ["crm", 2, 1_250_010],
        ["billing", 1, 1_250_000],
      ]);
      expect(list[0]?.eventSignals).toEqual(["shape.copy_to", "shape.full_table_copy", "signature.pg_dump"]);
      expect(list[0]?.lastEventAt?.toISOString()).toBe(at(1000));
      // Another principal: another incident.
      await send(auth, [dumpEvent({ principal: { db_user: "report" } })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(3);
      // Resolved: the rest of the hour opens nothing (and links nothing); the next hour does.
      const crm = list[0];
      expect((await transitionIncident(getDb(), String(crm?.id), "resolved", actor())).outcome).toBe("ok");
      await send(auth, [dumpEvent({ ts: at(30 * 60_000) })]);
      await drainPolicyWork(getDb());
      list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(3);
      expect(await incidentEventCount(getDb(), String(crm?.id))).toBe(2);
      await send(auth, [dumpEvent({ ts: at(HOUR) })]);
      await drainPolicyWork(getDb());
      list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(4);
      expect(list[3]?.eventBucket?.toISOString()).toBe("2026-09-27T11:00:00.000Z");
    });

    it("every enabled access_event policy applies; exclusions, exceptions and finding policies do not", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.*"], exclude_principals: ["back*"] });
      const disabled = await policy({ signals: ["signature.*"] }, { enabled: false });
      const excepted = await policy({ signals: ["signature.*"] });
      await createException(getDb(), { policyId: excepted, agentId: null, targetId: "pg-prod-1", classifier: null, location: null, reason: "backups", expiresAt: null }, actor());
      // A classifier-scoped exception never covers events.
      const kept = await policy({ event_actions: ["read"], min_rows: 1000 });
      await createException(getDb(), { policyId: kept, agentId: null, targetId: null, classifier: "pii.*", location: null, reason: "x", expiresAt: null }, actor());
      // A finding policy matches no event.
      await createPolicy(
        getDb(),
        { name: "findings", description: null, enabled: true, source: "finding", conditions: {}, actions: [{ type: "create_incident", severity: "low" }] },
        actor(),
      );
      await send(auth, [dumpEvent()]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list.map((i) => i.policyId)).toEqual([kept]);
      expect(list.every((i) => i.policyId !== disabled)).toBe(true);
    });

    it("a policy change applies to the events evaluated after it, never to past ones", async () => {
      const auth = await agentWithTargets();
      await send(auth, [dumpEvent()]);
      await drainPolicyWork(getDb());
      await policy({ signals: ["signature.*"] });
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(0);
      const [p] = await getDb().select({ evaluatedAt: policies.evaluatedAt }).from(policies);
      expect(p?.evaluatedAt).toBeNull();
    });

    it("drains more than one chunk in a run, in arrival order", async () => {
      const auth = await agentWithTargets();
      const events = Array.from({ length: EVENT_CHUNK + 20 }, (_, i) => dumpEvent({ ts: at(i * 1000), rows: i + 1 }));
      await send(auth, events.slice(0, 500));
      const stats = await drainPolicyWork(getDb());
      expect(stats.events).toBe(EVENT_CHUNK + 20);
      expect(stats.more).toBe(false);
      const [b] = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
      expect(b?.events).toBe(EVENT_CHUNK + 20);
    });
  });

  describe("per-principal baselines", () => {
    it("warms up, then flags a volume far above the principal's usual one; anomaly policies fire", async () => {
      const auth = await agentWithTargets();
      const pid = await policy({ anomaly: true });
      const report = (rows: number, i: number) =>
        dumpEvent({
          target_id: "mysql-crm",
          ts: at(i * 60_000),
          principal: { db_user: "report" },
          objects: [{ database: "shop", object: "customers" }],
          rows,
          signals: [],
          source: "performance_schema",
        });
      await send(auth, Array.from({ length: BASELINE_WARMUP }, (_, i) => report(2000 + (i % 3) * 100, i)));
      await drainPolicyWork(getDb());
      expect((await eventsOf(auth.agentId)).every((e) => e.anomaly === false)).toBe(true);
      expect((await eventsOf(auth.agentId)).at(-1)?.baselineRows).toBeNull();
      await send(auth, [report(2100, 100), report(500_000, 101)]);
      await drainPolicyWork(getDb());
      const evs = await eventsOf(auth.agentId);
      expect(evs.map((e) => e.anomaly).slice(-2)).toEqual([false, true]);
      expect(evs.at(-1)?.baselineRows).toBeGreaterThan(1500);
      expect(evs.at(-1)?.baselineRows).toBeLessThan(3000);
      const list = await incidentsOf(auth.agentId);
      expect(list.map((i) => [i.policyId, i.principal, i.accessEventId])).toEqual([[pid, "report", evs.at(-1)?.id]]);
      const key = principalKey({ db_user: "report" });
      const view = await getPrincipal(getDb(), auth.agentId, "mysql-crm", key);
      expect(view).toMatchObject({ principal: "report", events: BASELINE_WARMUP + 2, warm: true, anomalies: 1, rowsTotal: evs.reduce((s, e) => s + (e.rows ?? 0), 0) });
      expect(view?.baselineRows).toBeLessThan(3000);
      expect((await principalIncidents(getDb(), auth.agentId, "mysql-crm", key)).map((i) => i.policyName)).toHaveLength(1);
      expect((await listPrincipals(getDb(), { agentId: auth.agentId })).map((p) => p.principal)).toEqual(["report"]);
      // Stored aggregates only: no object name, no event in the baseline row.
      const [row] = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
      expect(JSON.stringify(row)).not.toMatch(/customers|shop/);
    });

    it("keeps one baseline per principal kind: a name and a fingerprint never share one", async () => {
      const auth = await agentWithTargets();
      const fp = "hmac-sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
      await send(auth, [
        dumpEvent({ principal: { db_user: fp } }),
        dumpEvent({ principal: { db_user_fingerprint: fp }, action: "auth_failure", objects: [], rows: undefined, signals: [] }),
      ]);
      await drainPolicyWork(getDb());
      const rows = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
      expect(rows).toHaveLength(2);
      expect(new Set(rows.map((r) => r.principalKey)).size).toBe(2);
    });
  });

  describe("views", () => {
    it("filters events by target, principal, signal (id or family), time and anomaly", async () => {
      const auth = await agentWithTargets();
      await send(auth, [
        dumpEvent(),
        dumpEvent({ ts: at(HOUR), principal: { db_user: "report" }, signals: ["shape.full_table_copy"] }),
        dumpEvent({ ts: at(2 * HOUR), target_id: "mysql-crm", objects: [{ database: "shop", object: "customers" }], signals: [], source: "performance_schema" }),
      ]);
      await drainPolicyWork(getDb());
      const ids = async (f: Parameters<typeof listEvents>[1]) => (await listEvents(getDb(), { agentId: auth.agentId, ...f })).map((e) => e.ts.toISOString());
      expect(await ids({})).toEqual([at(2 * HOUR), at(HOUR), at(0)]);
      expect(await ids({ targetId: "mysql-crm" })).toEqual([at(2 * HOUR)]);
      expect(await ids({ principalKey: principalKey({ db_user: "report" }) })).toEqual([at(HOUR)]);
      expect(await ids({ signal: "signature.pg_dump" })).toEqual([at(0)]);
      expect(await ids({ signal: "shape.*" })).toEqual([at(HOUR), at(0)]);
      expect(await ids({ from: new Date(at(30 * 60_000)), to: new Date(at(90 * 60_000)) })).toEqual([at(HOUR)]);
      expect(await ids({ anomalyOnly: true })).toEqual([]);
      const [first] = await listEvents(getDb(), { agentId: auth.agentId, targetId: "pg-prod-1", principalKey: principalKey({ db_user: "backup" }) });
      expect(first).toMatchObject({ principal: "backup", fingerprinted: false, application: "pg_dump", evaluated: true, incidentIds: [] });
    });
  });

  it("I2: nothing copied from the findings' samples or fingerprints into events, incidents, baselines, links or notifications", async () => {
    const auth = await agentWithTargets();
    await scanWith(auth, [finding("email", "pii.email", 0.97, "clients", { masked_samples: SAMPLES, fingerprints: [FINGERPRINT] })]);
    await policy({ signals: ["signature.*"] });
    await send(auth, [dumpEvent()]);
    await drainPolicyWork(getDb());
    const res = await getDb().execute(sql`
      select coalesce(string_agg(t, ' '), '') as s from (
        select row_to_json(e)::text as t from access_events e
        union all select row_to_json(b)::text from events_batches b
        union all select row_to_json(i)::text from incidents i
        union all select row_to_json(l)::text from incident_events l
        union all select row_to_json(p)::text from principal_baselines p
        union all select row_to_json(d)::text from notification_deliveries d
        union all select row_to_json(a)::text from audit_log a) x`);
    const dump = String(res.rows[0]?.s);
    expect(dump).toContain("backup");
    for (const s of [...SAMPLES, FINGERPRINT, "e******"]) expect(dump).not.toContain(s);
  });
});
