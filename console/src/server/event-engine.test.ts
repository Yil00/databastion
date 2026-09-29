import { and, eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { PgBoss } from "pg-boss";
import { randomBytes } from "node:crypto";

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import * as schema from "@/db/schema";
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
import { logger } from "@/lib/logger";
import { runtimeRoleWarnings } from "@/server/db-role-check";
import { pgBossOptions, registerPolicyQueue } from "@/worker/queues";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, uuidv7 } from "@/test/helpers";

import { configureAudit } from "./audit-config";
import * as engine from "./event-engine";
import { EVENT_CHUNK, EVENT_CHUNK_PER_AGENT, evaluateChunk } from "./event-engine";
import { BASELINES_CAP_VAR, EVENT_INCIDENTS_CAP_VAR, getPrincipal, ingestEvents, incidentEventCount, incidentEventViews, listEvents, listPrincipals, principalIncidents, principalKey } from "./events";
import { setFalsePositive } from "./findings";
import { drainPolicyWork, getIncident, transitionIncident } from "./incidents";
import { createException, createPolicy, type PolicyInput } from "./policies";
import { POLICY_QUEUE, setPolicyJobSender } from "./policy-queue";

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
    process.env.DATABASTION_EVENTS_RETENTION_DAYS = "3650";
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
        dumpEvent({ ts: at(1000), objects: [{ database: "crm", schema: "public", object: "orders" }], rows: 10, signals: ["signature.pg_dump", "shape.full_table_read"] }),
        dumpEvent({ ts: at(2000), objects: [{ database: "billing", schema: "public", object: "invoices" }] }),
      ]);
      await drainPolicyWork(getDb());
      let list = await incidentsOf(auth.agentId);
      expect(list.map((i) => [i.eventDatabase, i.matchCount, i.eventRows])).toEqual([
        ["crm", 2, 1_250_010],
        ["billing", 1, 1_250_000],
      ]);
      expect(list[0]?.eventSignals).toEqual(["shape.full_table_copy", "shape.full_table_read", "signature.pg_dump"]);
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
      // M1: not worse than the resolved incident: linked to it, visible there.
      expect(await incidentEventCount(getDb(), String(crm?.id))).toBe(3);
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

  describe("security review", () => {
    const randomFp = () => `hmac-sha256:${randomBytes(32).toString("hex")}`;
    const ip = (i: number) => `198.51.${Math.floor(i / 250)}.${(i % 250) + 1}`;

    it("H1: random account names create no baseline and one auth_failure incident per client and hour", async () => {
      const auth = await agentWithTargets();
      const pid = await policy({ event_actions: ["auth_failure"] });
      const n = 450;
      const failures = Array.from({ length: n }, (_, i) =>
        dumpEvent({ ts: at(i * 1000), principal: { db_user_fingerprint: randomFp(), client_addr: "203.0.113.9" }, action: "auth_failure", objects: [], rows: undefined, signals: [] }),
      );
      // Also failures reported under random (conforming) names, from the same client.
      failures.push(...Array.from({ length: 40 }, (_, i) => dumpEvent({ ts: at(i * 1000), principal: { db_user: `u${i}x${randomBytes(4).toString("hex")}`, client_addr: "203.0.113.9" }, action: "auth_failure", objects: [], rows: undefined, signals: [] })));
      await send(auth, failures.slice(0, 250));
      await send(auth, failures.slice(250));
      await drainPolicyWork(getDb());
      const baselines = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
      expect(baselines).toHaveLength(0);
      const list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({ policyId: pid, matchCount: n + 40 });
      expect(list[0]?.dedupKey).toContain(`principal:unknown:`);
    });

    it("H1: a flood of distinct principals and clients is capped: incidents per policy and hour, baselines per target", async () => {
      process.env[EVENT_INCIDENTS_CAP_VAR] = "5";
      process.env[BASELINES_CAP_VAR] = "20";
      try {
        const auth = await agentWithTargets();
        const pid = await policy({ signals: ["shape.*"] });
        const n = 400;
        // Not severe (no signature, no baseline, no sensitivity): subject to the cap.
        const flood = Array.from({ length: n }, (_, i) =>
          dumpEvent({ ts: at(i * 1000), principal: { db_user: `user${i}`, client_addr: ip(i) }, rows: 10 + i, signals: ["shape.full_table_read"] }),
        );
        await send(auth, flood.slice(0, 200));
        await send(auth, flood.slice(200));
        await drainPolicyWork(getDb());
        const list = (await incidentsOf(auth.agentId)).filter((i) => !i.eventOverflow);
        const overflow = await getDb().select().from(incidents).where(and(eq(incidents.policyId, pid), eq(incidents.eventOverflow, true)));
        expect(list).toHaveLength(5);
        expect(overflow).toHaveLength(1);
        expect(overflow[0]).toMatchObject({ agentId: auth.agentId, targetId: "pg-prod-1" });
        expect(overflow[0]?.matchCount).toBe(n - 5);
        expect(await incidentEventCount(getDb(), String(overflow[0]?.id))).toBe(n - 5);
        const baselines = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
        expect(baselines.length).toBeLessThanOrEqual(20);
        // The least recently updated baselines were evicted: those kept come from the last chunk.
        expect(baselines.every((b) => Number(b.dbUser?.slice(4)) >= n - EVENT_CHUNK_PER_AGENT)).toBe(true);
        // One more ordinary event the same hour opens nothing new.
        await send(auth, [dumpEvent({ ts: at(n * 1000), principal: { db_user: "late", client_addr: "192.0.2.200" }, rows: 10, signals: ["shape.full_table_read"] })]);
        await drainPolicyWork(getDb());
        expect(await incidentsOf(auth.agentId)).toHaveLength(6);
        // N1 (c): a signature event bypasses the full cap.
        await send(auth, [dumpEvent({ ts: at(n * 1000 + 1), principal: { db_user: "dumper" }, signals: ["signature.pg_dump", "shape.full_table_copy"] })]);
        await drainPolicyWork(getDb());
        const after = await incidentsOf(auth.agentId);
        expect(after).toHaveLength(7);
        expect(after.filter((i) => i.principal === "dumper")).toHaveLength(1);
      } finally {
        delete process.env[EVENT_INCIDENTS_CAP_VAR];
        delete process.env[BASELINES_CAP_VAR];
      }
    });

    it("N1: the cap is per target; a resolved overflow does not silence worse or severe events", async () => {
      process.env[EVENT_INCIDENTS_CAP_VAR] = "2";
      try {
        const auth = await agentWithTargets();
        await policy({ signals: ["shape.*"] });
        const read = (i: number, target_id = "pg-prod-1", over: Record<string, unknown> = {}) =>
          dumpEvent({
            target_id,
            ts: at(i * 1000),
            principal: { db_user: `noise${i}` },
            objects: target_id === "pg-prod-1" ? [{ database: "crm", schema: "public", object: "clients" }] : [{ database: "shop", object: "customers" }],
            rows: 5,
            signals: ["shape.full_table_read"],
            source: target_id === "pg-prod-1" ? "pgaudit" : "performance_schema",
            ...over,
          });
        // Noise on target A (pg-prod-1) fills its cap and overflows.
        await send(auth, Array.from({ length: 30 }, (_, i) => read(i)));
        await drainPolicyWork(getDb());
        const onTarget = async (t: string) => (await incidentsOf(auth.agentId)).filter((x) => x.targetId === t);
        expect((await onTarget("pg-prod-1")).map((x) => x.eventOverflow).sort()).toEqual([false, false, true]);
        // Target B is not affected.
        await send(auth, [read(100, "mysql-crm"), read(101, "mysql-crm")]);
        await drainPolicyWork(getDb());
        expect((await onTarget("mysql-crm")).map((x) => x.eventOverflow)).toEqual([false, false]);
        // Resolve A's overflow: a similar event is linked; a worse one (new signal) opens a new overflow.
        const [ov] = (await onTarget("pg-prod-1")).filter((x) => x.eventOverflow);
        await transitionIncident(getDb(), String(ov?.id), "resolved", actor());
        const links = await incidentEventCount(getDb(), String(ov?.id));
        await send(auth, [read(40)]);
        await drainPolicyWork(getDb());
        expect(await incidentEventCount(getDb(), String(ov?.id))).toBe(links + 1);
        await send(auth, [read(41, "pg-prod-1", { signals: ["shape.full_table_copy"] })]);
        await drainPolicyWork(getDb());
        const overflows = (await onTarget("pg-prod-1")).filter((x) => x.eventOverflow);
        expect(overflows).toHaveLength(2);
        const [d] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(overflows[1]?.id)));
        expect(d?.payload).toMatchObject({ overflow: { limit_per_hour: 2 }, incident: { reopened_from: ov?.id } });
        // A pg_dump after the resolved overflow opens its own incident.
        await transitionIncident(getDb(), String(overflows[1]?.id), "resolved", actor());
        await send(auth, [read(42, "pg-prod-1", { principal: { db_user: "backup" }, signals: ["signature.pg_dump", "shape.full_table_copy"] })]);
        await drainPolicyWork(getDb());
        expect((await onTarget("pg-prod-1")).filter((x) => x.principal === "backup" && !x.eventOverflow)).toHaveLength(1);
      } finally {
        delete process.env[EVENT_INCIDENTS_CAP_VAR];
      }
    });

    it("N2: failed logins are grouped per client network (IPv4 /24, IPv6 /64, IPv4-mapped as IPv4, local)", async () => {
      const auth = await agentWithTargets();
      await policy({ event_actions: ["auth_failure"] });
      const fail = (i: number, client_addr: string) =>
        dumpEvent({ ts: at(i * 1000), principal: { db_user_fingerprint: randomFp(), client_addr }, action: "auth_failure", objects: [], rows: undefined, signals: [] });
      await send(auth, [
        fail(0, "203.0.113.9"),
        fail(1, "203.0.113.77"),
        fail(2, "::ffff:203.0.113.5"),
        fail(3, "2001:db8:1:2::1"),
        fail(4, "2001:0DB8:0001:0002:ffff::9"),
        fail(5, "local"),
        fail(6, "local"),
        fail(7, "203.0.114.1"),
      ]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).map((i) => i.matchCount).sort()).toEqual([1, 2, 2, 3]);
    });

    it("M1: after a resolution, a worse event of the same hour opens a new incident; a similar one is only linked", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding("email", "pii.email", 1)]);
      await policy({ signals: ["signature.*"] });
      await send(auth, [dumpEvent({ rows: 1000 })]);
      await drainPolicyWork(getDb());
      const [first] = await incidentsOf(auth.agentId);
      await transitionIncident(getDb(), String(first?.id), "resolved", actor());
      // Same signals, lower score: linked to the resolved incident.
      await send(auth, [dumpEvent({ ts: at(60_000), rows: 10 })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      expect(await incidentEventCount(getDb(), String(first?.id))).toBe(2);
      // A new signal: a new incident, reopened from the resolved one.
      await send(auth, [dumpEvent({ ts: at(120_000), rows: 10, signals: ["signature.copy_to_program"] })]);
      await drainPolicyWork(getDb());
      let list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(2);
      const [delivery] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(list[1]?.id)));
      expect(delivery?.payload).toMatchObject({ incident: { reopened_from: first?.id } });
      // A higher score after resolving that one: another incident.
      await transitionIncident(getDb(), String(list[1]?.id), "resolved", actor());
      await send(auth, [dumpEvent({ ts: at(180_000), rows: 10_000_000, signals: ["signature.copy_to_program"] })]);
      await drainPolicyWork(getDb());
      list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(3);
      // A false positive is never reopened within the hour.
      await transitionIncident(getDb(), String(list[2]?.id), "false_positive", actor());
      await send(auth, [dumpEvent({ ts: at(240_000), rows: 99_000_000, signals: ["signature.copy_to_file"] })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(3);
      expect(await incidentEventCount(getDb(), String(list[2]?.id))).toBe(2);
    });

    it("M2: one chunk takes at most a fair share of each agent's events", async () => {
      await drainPolicyWork(getDb());
      const busy = await agentWithTargets();
      const quiet = await agentWithTargets();
      await send(busy, Array.from({ length: 300 }, (_, i) => dumpEvent({ ts: at(i * 1000) })));
      await send(quiet, Array.from({ length: 5 }, (_, i) => dumpEvent({ ts: at(i * 1000) })));
      const stats = { events: 0, created: 0, anomalies: 0, more: false };
      expect(await evaluateChunk(getDb(), stats)).toBe(EVENT_CHUNK_PER_AGENT + 5);
      const done = async (agentId: string) => (await eventsOf(agentId)).filter((e) => e.evaluatedAt !== null).length;
      expect(await done(quiet.agentId)).toBe(5);
      expect(await done(busy.agentId)).toBe(EVENT_CHUNK_PER_AGENT);
      // Each agent's events are taken in arrival order.
      const busyEvents = await eventsOf(busy.agentId);
      expect(busyEvents.slice(0, EVENT_CHUNK_PER_AGENT).every((e) => e.evaluatedAt !== null)).toBe(true);
      await drainPolicyWork(getDb());
    });

    it("M2: the findings are evaluated even when the events use their whole share of the budget", async () => {
      const auth = await agentWithTargets();
      await createPolicy(
        getDb(),
        { name: `f-${uuidv7()}`, description: null, enabled: true, source: "finding", conditions: {}, actions: [{ type: "create_incident", severity: "low" }] },
        actor(),
      );
      await drainPolicyWork(getDb());
      await scanWith(auth, [finding("email", "pii.email", 1)]);
      const spy = vi.spyOn(engine, "drainEventWork").mockResolvedValue({ events: 0, created: 0, anomalies: 0, more: true });
      try {
        const stats = await drainPolicyWork(getDb());
        expect(stats.more).toBe(true);
        expect(stats.findings).toBeGreaterThanOrEqual(1);
        expect((await incidentsOf(auth.agentId)).map((i) => i.source)).toEqual(["finding"]);
      } finally {
        spy.mockRestore();
      }
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
        dumpEvent({ principal: { db_user_fingerprint: fp } }),
        // Never a baseline for a failed authentication (security review H1).
        dumpEvent({ principal: { db_user: "nobody" }, action: "auth_failure", objects: [], rows: 5, signals: [] }),
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

  it("exit criterion path: an accepted pg_dump batch wakes a real pg-boss worker, which opens the incident within seconds", async () => {
    const { url } = await createRuntimeRole();
    const boss = new PgBoss(pgBossOptions(url));
    boss.on("error", () => undefined);
    await boss.start();
    try {
      await registerPolicyQueue(boss, getDb, logger, { pollingIntervalSeconds: 0.5 });
      setPolicyJobSender(async () => {
        await boss.send(POLICY_QUEUE, {});
      });
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.pg_dump", "signature.copy_to_file"] });
      const started = Date.now();
      await send(auth, [dumpEvent({ ts: new Date().toISOString() })]);
      for (let i = 0; i < 100 && (await incidentsOf(auth.agentId)).length === 0; i++) {
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(await incidentsOf(auth.agentId)).toHaveLength(1);
      expect(Date.now() - started).toBeLessThan(10_000);
    } finally {
      setPolicyJobSender(null);
      await boss.stop({ graceful: false, timeout: 2000 });
    }
  });

  it("ingestion, correlation, incidents, purge and Audit settings work as the runtime role; the role check stays quiet", async () => {
    const auth = await agentWithTargets();
    await scanWith(auth, [finding("email", "pii.email", 1)]);
    await policy({ signals: ["signature.*"] });
    const { url } = await createRuntimeRole();
    const pool = new Pool({ connectionString: url, max: 2 });
    try {
      const db = drizzle(pool, { schema });
      const body = { batch_id: uuidv7(), events: [dumpEvent(), dumpEvent({ ts: at(1000) })] };
      expect(await ingestEvents(db, auth.agentId, body as never)).toMatchObject({ kind: "accepted", duplicate: false });
      expect(await ingestEvents(db, auth.agentId, body as never)).toMatchObject({ kind: "accepted", duplicate: true });
      const stats = await drainPolicyWork(db);
      expect(stats.events).toBeGreaterThanOrEqual(2);
      const [inc] = await incidentsOf(auth.agentId);
      expect(inc?.matchCount).toBe(2);
      expect(await transitionIncident(db, String(inc?.id), "resolved", actor())).toMatchObject({ outcome: "ok" });
      const r = await configureAudit(db, auth.agentId, "pg-prod-1", { enabled: true, aggregationWindowS: 60, pollIntervalS: 10, minRows: null, deriveFromFindings: true, manualObjects: [], confirm: null }, actor());
      expect(r.outcome).toBe("queued");
      expect((await configureAudit(db, auth.agentId, "pg-prod-1", { enabled: true, aggregationWindowS: 30, pollIntervalS: 10, minRows: 5, deriveFromFindings: true, manualObjects: [], confirm: null }, actor())).outcome).toBe("queued");
      await pool.query("select public.databastion_purge_access_events(7, 10)");
      await expect(pool.query("update access_events set rows = 0")).rejects.toThrow(/permission denied/);
      await expect(pool.query("delete from incident_events")).rejects.toThrow(/permission denied/);
      await expect(pool.query("delete from principal_baselines")).rejects.toThrow(/permission denied/);
      await expect(pool.query("update incidents set principal = 'x'")).rejects.toThrow(/permission denied/);
      expect(await runtimeRoleWarnings(pool)).toEqual([]);
    } finally {
      await pool.end();
    }
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
