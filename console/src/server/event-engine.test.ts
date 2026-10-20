import { and, eq, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { PgBoss } from "pg-boss";
import { randomBytes, randomUUID } from "node:crypto";

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import * as schema from "@/db/schema";
import { accessEvents, agentTargets, auditLog, incidentEvents, incidents, notificationDeliveries, policies, principalBaselines } from "@/db/schema";
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
import { sha256Hex } from "./crypto";
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

    it("matches the findings of an object without case or trailing spaces, on database, schema and object (N1)", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding("email", "pii.email", 1), finding("name", "pii.person_name", 1, "clientèle"), finding("phone", "pii.phone", 1, "πελατες")]);
      await send(auth, [
        dumpEvent({ objects: [{ database: "CRM ", schema: "PUBLIC", object: "CLIENTS  " }], rows: 99 }),
        dumpEvent({ objects: [{ database: "Crm", object: "Clients" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "crm", schema: "Public", object: "CLIENTÈLE" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "CRM", schema: "PUBLIC", object: "CLIENT" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "CRM", schema: "PRIVATE", object: "CLIENTS" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "SHOP", schema: "PUBLIC", object: "CLIENTS" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: " clients" }], rows: 99 }),
        // Review M1: final sigma.
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "ΠΕΛΑΤΕΣ" }], rows: 99 }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "ΠΕΛΑΤΗΣ" }], rows: 99 }),
      ]);
      await drainPolicyWork(getDb());
      const rows = await eventsOf(auth.agentId);
      expect(rows.map((r) => r.sensitivity)).toEqual([3, 3, 2, 0, 0, 0, 0, 3, 0]);
      expect(rows.map((r) => r.score)).toEqual([6, 6, 4, 0, 0, 0, 0, 6, 0]);
      // The event keeps the names as the agent sent them.
      expect(rows[0]?.objects).toEqual([{ database: "CRM ", schema: "PUBLIC", object: "CLIENTS  " }]);
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
        eventSignals: ["signature.pg_dump", "shape.full_table_copy"],
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
        access: { action: "read", rows: 1_250_000, signals: ["signature.pg_dump", "shape.full_table_copy"], unregistered_signals: [] },
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
      expect(list[0]?.eventSignals).toEqual(["signature.pg_dump", "shape.full_table_copy", "shape.full_table_read"]);
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

    it("PR #274 review M1: a false positive on `CRM` does not swallow a later dump of `crm` on PostgreSQL; a new incident opens", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.pg_dump"] });
      const db = (database: string, ms: number) => dumpEvent({ ts: at(ms), objects: [{ database, schema: "public", object: "clients" }] });
      await send(auth, [db("CRM", 0)]);
      await drainPolicyWork(getDb());
      const [first] = await incidentsOf(auth.agentId);
      expect(first?.dedupKey).toContain(`|database:${sha256Hex("CRM")}|`);
      expect((await transitionIncident(getDb(), String(first?.id), "false_positive", actor())).outcome).toBe("ok");
      await send(auth, [db("crm", 1000)]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list.map((i) => [i.eventDatabase, i.status])).toEqual([
        ["CRM", "false_positive"],
        ["crm", "open"],
      ]);
      expect(await incidentEventCount(getDb(), String(first?.id))).toBe(1);
    });

    it("ADR-0021 decision 6 note of 2026-10-18: `crm ` and `crm` share a key on MySQL, not on PostgreSQL; case is kept on both", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.pg_dump"] });
      const ev = (target: string, database: string, ms: number) =>
        dumpEvent({
          ts: at(ms),
          target_id: target,
          objects: target === "mysql-crm" ? [{ database, object: "clients" }] : [{ database, schema: "public", object: "clients" }],
          ...(target === "mysql-crm" ? { source: "performance_schema" } : {}),
        });
      await send(auth, [ev("mysql-crm", "crm ", 0), ev("mysql-crm", "crm", 1000), ev("mysql-crm", "CRM", 2000), ev("pg-prod-1", "crm ", 3000), ev("pg-prod-1", "crm", 4000)]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      const of = (t: string) => list.filter((i) => i.targetId === t).map((i) => [i.eventDatabase, i.matchCount]);
      expect(of("mysql-crm")).toEqual([
        ["crm ", 2],
        ["CRM", 1],
      ]);
      expect(list.find((i) => i.eventDatabase === "crm " && i.targetId === "mysql-crm")?.dedupKey).toContain(`|database:${sha256Hex("crm")}|`);
      expect(of("pg-prod-1")).toEqual([
        ["crm ", 1],
        ["crm", 1],
      ]);
    });

    it("ADR-0021 note of 2026-10-18: on MySQL, an incident opened under the name as sent (`crm `) keeps its events; an active one comes before a closed one of the new key", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["signature.pg_dump"] });
      const ev = (database: string, ms: number) => dumpEvent({ ts: at(ms), target_id: "mysql-crm", objects: [{ database, object: "clients" }], source: "performance_schema" });
      // A: the new key of `crm`, then resolved. B: another database, turned into a legacy-key
      // incident of `crm ` (as an earlier console would have keyed it), still open.
      await send(auth, [ev("crm", 0), ev("billing", 1000)]);
      await drainPolicyWork(getDb());
      const [a, b] = await incidentsOf(auth.agentId);
      expect(a?.eventDatabase).toBe("crm");
      expect((await transitionIncident(getDb(), String(a?.id), "resolved", actor())).outcome).toBe("ok");
      const legacy = String(a?.dedupKey).replace(`|database:${sha256Hex("crm")}|`, `|database:${sha256Hex("crm ")}|`);
      expect(legacy).not.toBe(a?.dedupKey);
      await getDb().update(incidents).set({ dedupKey: legacy, eventDatabase: "crm " }).where(eq(incidents.id, String(b?.id)));
      // `crm ` after the upgrade: added to the active legacy incident, not linked to the resolved one.
      await send(auth, [ev("crm ", 2000)]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(2);
      expect(list.find((i) => i.id === b?.id)?.matchCount).toBe(2);
      expect(await incidentEventCount(getDb(), String(a?.id))).toBe(1);
      // Plain `crm` has no other key: it goes to the resolved new-key incident (M1 rule: linked).
      await send(auth, [ev("crm", 3000)]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(2);
      expect(await incidentEventCount(getDb(), String(a?.id))).toBe(2);
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

    it("`objects` conditions ignore case and trailing spaces; exceptions compare with case on PostgreSQL (ADR-0054) and ignore trailing spaces on MySQL only (N1)", async () => {
      const auth = await agentWithTargets();
      const pid = await policy({ objects: { database: "crm", object: "clients" } });
      // Exception of a second policy, scoped to the location only: with case on PostgreSQL,
      // without case on MySQL (ADR-0054), blind to trailing spaces on SQL Server and MySQL /
      // MariaDB only (N1).
      const xp = await policy({ objects: { object: "clients" } });
      await createException(
        getDb(),
        { policyId: xp, agentId: null, targetId: null, classifier: null, location: { database: "crm", object: "clients" }, reason: "x", expiresAt: null },
        actor(),
      );
      const mysql = (object: string, ts: string) =>
        dumpEvent({ ts, target_id: "mysql-crm", objects: [{ database: "CRM", object }], signals: [], source: "performance_schema" });
      await send(auth, [
        dumpEvent({ objects: [{ database: "CRM", schema: "public", object: "CLIENTS " }], principal: { db_user: "a" } }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "Clients" }], principal: { db_user: "b" } }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "clients " }], principal: { db_user: "c" } }),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "client" }], principal: { db_user: "d" } }),
        mysql("Clients ", at(1000)),
        mysql("CLIENT", at(2000)),
        dumpEvent({ objects: [{ database: "crm", schema: "public", object: "clients" }], principal: { db_user: "e" }, ts: at(3000) }),
      ]);
      // The target's engine changes after ingest: the events keep the engine their source tells
      // (pgaudit: PostgreSQL), not the target's current one (ADR-0054 review L1).
      await getDb()
        .update(agentTargets)
        .set({ engine: "mysql" })
        .where(and(eq(agentTargets.agentId, auth.agentId), eq(agentTargets.targetId, "pg-prod-1")));
      await drainPolicyWork(getDb());
      const evs = await eventsOf(auth.agentId);
      const linked = async (policyId: string) => {
        const incs = (await incidentsOf(auth.agentId)).filter((i) => i.policyId === policyId).map((i) => i.id);
        const links = incs.length === 0 ? [] : await getDb().select().from(incidentEvents).where(inArray(incidentEvents.incidentId, incs));
        return evs.flatMap((e, i) => (links.some((l) => l.eventId === e.id) ? [i] : []));
      };
      // Policy: every spelling of crm.clients, never `client`.
      expect(await linked(pid)).toEqual([0, 1, 2, 4, 6]);
      // Exception: on PostgreSQL only the exact `crm.clients` is excepted; `Clients`, `CLIENTS `
      // and `clients ` are distinct (quoted) names there. `Clients ` is excepted on MySQL.
      expect(await linked(xp)).toEqual([0, 1, 2]);
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
      // After a false positive (end-of-phase-6 M1): a similar event, even with a new non-signature
      // signal, is only linked.
      await transitionIncident(getDb(), String(list[2]?.id), "false_positive", actor());
      await send(auth, [dumpEvent({ ts: at(240_000), rows: 10, signals: ["signature.copy_to_program", "shape.full_table_read"] })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(3);
      expect(await incidentEventCount(getDb(), String(list[2]?.id))).toBe(2);
      // A clearly worse one (a signature signal the false positive did not have) opens a new one.
      await send(auth, [dumpEvent({ ts: at(300_000), rows: 10, signals: ["signature.copy_to_file"] })]);
      await drainPolicyWork(getDb());
      list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(4);
      const [again] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(list[3]?.id)));
      expect(again?.payload).toMatchObject({ incident: { reopened_from: list[2]?.id } });
      // And so does a strictly higher score after that one is a false positive too.
      await transitionIncident(getDb(), String(list[3]?.id), "false_positive", actor());
      await send(auth, [dumpEvent({ ts: at(360_000), rows: 10, signals: ["signature.copy_to_file"] })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(4);
      await send(auth, [dumpEvent({ ts: at(420_000), rows: 99_000_000, signals: ["signature.copy_to_file"] })]);
      await drainPolicyWork(getDb());
      expect(await incidentsOf(auth.agentId)).toHaveLength(5);
    });

    it("ADR-0031: after a false positive, reads split below the judged score open an incident once their rows exceed it", async () => {
      try {
        const auth = await agentWithTargets();
        await policy({ signals: ["shape.*"] });
        // No finding: every score is 0, only the rows rule can tell a worse event.
        const read = (i: number, user: string, rows: number) =>
          dumpEvent({ ts: at(i * 1000), principal: { db_user: user }, rows, signals: ["shape.full_table_read"] });
        await send(auth, [read(0, "splitter", 1000)]);
        await drainPolicyWork(getDb());
        const [judged] = await incidentsOf(auth.agentId);
        expect(judged?.eventRows).toBe(1000);
        await transitionIncident(getDb(), String(judged?.id), "false_positive", actor());
        // 400 + 400 = 800 <= 1000: linked; the third read makes 1200 > 1000: a new incident.
        await send(auth, [read(10, "splitter", 400), read(11, "splitter", 400)]);
        await drainPolicyWork(getDb());
        expect(await incidentsOf(auth.agentId)).toHaveLength(1);
        expect(await incidentEventCount(getDb(), String(judged?.id))).toBe(3);
        await send(auth, [read(12, "splitter", 400)]);
        await drainPolicyWork(getDb());
        const list = await incidentsOf(auth.agentId);
        expect(list).toHaveLength(2);
        const [d] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(list[1]?.id)));
        expect(d?.payload).toMatchObject({ incident: { reopened_from: judged?.id } });

        // The same on a false-positive overflow incident (cap 1: other principals overflow).
        process.env[EVENT_INCIDENTS_CAP_VAR] = "1";
        await send(auth, [read(20, "other", 1000)]);
        await drainPolicyWork(getDb());
        const [ov] = (await incidentsOf(auth.agentId)).filter((x) => x.eventOverflow);
        expect(ov?.eventRows).toBe(1000);
        await transitionIncident(getDb(), String(ov?.id), "false_positive", actor());
        await send(auth, [read(21, "third", 600)]);
        await drainPolicyWork(getDb());
        expect((await incidentsOf(auth.agentId)).filter((x) => x.eventOverflow)).toHaveLength(1);
        await send(auth, [read(22, "fourth", 600)]);
        await drainPolicyWork(getDb());
        const overflows = (await incidentsOf(auth.agentId)).filter((x) => x.eventOverflow);
        expect(overflows).toHaveLength(2);
        const [od] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(overflows[1]?.id)));
        expect(od?.payload).toMatchObject({ overflow: { limit_per_hour: 1 }, incident: { reopened_from: ov?.id } });
      } finally {
        delete process.env[EVENT_INCIDENTS_CAP_VAR];
      }
    });

    it("PR #81 L1: links carry the wall clock of their insert, not the transaction start", async () => {
      const auth = await agentWithTargets();
      await policy({ signals: ["shape.*"] });
      await send(auth, Array.from({ length: 4 }, (_, i) => dumpEvent({ ts: at(i * 1000), principal: { db_user: "clocked" }, rows: 10, signals: ["shape.full_table_read"] })));
      await drainPolicyWork(getDb());
      const [inc] = await incidentsOf(auth.agentId);
      expect(inc?.matchCount).toBe(4);
      // One chunk, one transaction: with now() the four links would share one instant (compared in
      // microseconds, in the database).
      const [row] = (
        await getDb().execute<{ n: number; distinct_at: number }>(
          sql`select count(*)::int as n, count(distinct created_at)::int as distinct_at from incident_events where incident_id = ${String(inc?.id)}`,
        )
      ).rows;
      expect(row).toEqual({ n: 4, distinct_at: 4 });
    });

    it("end-of-phase-6 M1: fingerprinted principals are keyed per fingerprint, never merged with each other", async () => {
      const auth = await agentWithTargets();
      await scanWith(auth, [finding("email", "pii.email", 1)]);
      await policy({ signals: ["shape.*"] });
      const alice = randomFp();
      const bob = randomFp();
      // As on OpenLDAP: fingerprinted principals, no client address.
      const read = (i: number, fp: string, over: Record<string, unknown> = {}) =>
        dumpEvent({ ts: at(i * 1000), principal: { db_user_fingerprint: fp }, rows: 20_000, signals: ["shape.full_table_read"], ...over });
      await send(auth, [read(0, alice), read(1, bob), read(2, alice)]);
      await drainPolicyWork(getDb());
      let list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(2);
      const of = (fp: string) => list.find((x) => x.principal === fp);
      expect(of(alice)?.matchCount).toBe(2);
      expect(of(bob)?.matchCount).toBe(1);
      expect(of(alice)?.dedupKey).not.toContain("principal:unknown:");
      expect(of(alice)?.dedupKey).not.toContain(alice);
      // A false positive on one principal does not suppress another's incident of the hour.
      await transitionIncident(getDb(), String(of(alice)?.id), "false_positive", actor());
      await transitionIncident(getDb(), String(of(bob)?.id), "resolved", actor());
      const carol = randomFp();
      await send(auth, [read(10, alice), read(11, carol)]);
      await drainPolicyWork(getDb());
      list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(3);
      expect(list.filter((x) => x.principal === carol)).toHaveLength(1);
      // One fingerprint (e.g. every unidentified account of the agent) is one principal, whatever
      // the client network (the coarse per-network key is for failed logins only).
      const unidentified = randomFp();
      await send(auth, [
        read(20, unidentified, { principal: { db_user_fingerprint: unidentified, client_addr: "192.0.2.10" } }),
        read(21, unidentified, { principal: { db_user_fingerprint: unidentified, client_addr: "198.51.100.7" } }),
      ]);
      await drainPolicyWork(getDb());
      expect((await incidentsOf(auth.agentId)).filter((x) => x.principal === unidentified).map((x) => x.matchCount)).toEqual([2]);
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

  describe("P9-E: events without a recorded account (Redis / Valkey, ADR-0052 decision 8)", () => {
    const REDIS_HEARTBEAT = {
      ...HEARTBEAT,
      connectors: [...HEARTBEAT.connectors, "redis"],
      targets: [
        ...HEARTBEAT.targets,
        { target_id: "cache-redis", engine: "redis", reachable: true, audit_level: "limited", audit_source: "redis_slowlog" },
      ],
    };
    const slowRead = (i: number, principal: Record<string, unknown>, over: Record<string, unknown> = {}) => ({
      target_id: "cache-redis",
      ts: at(i * 1000),
      principal,
      action: "read",
      objects: [{ database: "db0", object: "user:*:profile" }],
      rows: 50_000,
      source: "redis_slowlog",
      aggregated_count: 1,
      ...over,
    });

    it("dedup principal unrecorded:<network> / unrecorded:local / unrecorded:none, no baseline, principal shown as not recorded", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: REDIS_HEARTBEAT }))).status).toBe(200);
      await policy({ event_actions: ["read"], sources: ["redis_slowlog", "redis_sync"] });
      const none = { account_not_recorded: true };
      await send(auth, [
        slowRead(0, { account_not_recorded: true, client_addr: "198.51.100.31" }),
        slowRead(1, { account_not_recorded: true, client_addr: "198.51.100.77", application: "redis-cli" }),
        slowRead(2, { account_not_recorded: true, client_addr: "203.0.113.40" }),
        slowRead(3, { account_not_recorded: true, client_addr: "local" }),
        slowRead(4, none, { source: "redis_sync", objects: [{ database: "*", object: "*" }], signals: ["signature.full_sync"] }),
        slowRead(5, none, { source: "redis_sync", objects: [{ database: "*", object: "*" }], signals: ["signature.full_sync"] }),
        // A named account of the same network is never merged with the unrecorded ones.
        slowRead(6, { db_user: "app", client_addr: "198.51.100.31" }),
      ]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      const principalPart = (k: string) => /\|principal:([^|]+)\|/.exec(k)?.[1];
      const byPrincipal = new Map(list.map((i) => [principalPart(i.dedupKey), i]));
      const net = (n: string) => `unrecorded:${sha256Hex(n)}`;
      expect([...byPrincipal.keys()].sort()).toEqual(
        [net("198.51.100.0/24"), net("203.0.113.0/24"), "unrecorded:local", "unrecorded:none", principalKey({ db_user: "app" })].sort(),
      );
      expect(byPrincipal.get(net("198.51.100.0/24"))?.matchCount).toBe(2);
      expect(byPrincipal.get("unrecorded:none")?.matchCount).toBe(2);
      expect(byPrincipal.get("unrecorded:local")?.matchCount).toBe(1);
      // Never the hash of an empty fingerprint, never agent text in a key.
      for (const i of list) {
        expect(i.dedupKey).not.toContain(principalKey({ db_user_fingerprint: "" } as never));
        expect(i.dedupKey).not.toContain("198.51.100");
      }
      const unrecorded = list.filter((i) => i.principal === "");
      expect(unrecorded).toHaveLength(4);
      expect(byPrincipal.get(principalKey({ db_user: "app" }))?.principal).toBe("app");
      // No per-principal baseline for the unrecorded events: only `app` has one.
      const baselines = await getDb().select().from(principalBaselines).where(eq(principalBaselines.agentId, auth.agentId));
      expect(baselines.map((b) => b.dbUser)).toEqual(["app"]);
      const events = await eventsOf(auth.agentId);
      expect(events.filter((e) => e.accountNotRecorded).every((e) => e.anomaly === false && e.baselineRows === null)).toBe(true);
      // Notifications: no principal, flagged as not recorded, never fingerprinted.
      const [delivery] = await getDb()
        .select()
        .from(notificationDeliveries)
        .where(eq(notificationDeliveries.incidentId, String(byPrincipal.get("unrecorded:none")?.id)));
      expect(delivery?.payload).toMatchObject({ principal: "", principal_fingerprinted: false, principal_not_recorded: true });
      const [named] = await getDb()
        .select()
        .from(notificationDeliveries)
        .where(eq(notificationDeliveries.incidentId, String(byPrincipal.get(principalKey({ db_user: "app" }))?.id)));
      expect(named?.payload).toMatchObject({ principal: "app", principal_fingerprinted: false, principal_not_recorded: false });
      // Views: the events carry the flag; filtering on the network key lists that network only.
      const views = await listEvents(getDb(), { agentId: auth.agentId, targetId: "cache-redis" });
      expect(views.filter((v) => v.accountNotRecorded).every((v) => v.principal === "" && !v.fingerprinted)).toBe(true);
      const key = principalKey({ account_not_recorded: true, client_addr: "198.51.100.31" });
      expect(await listEvents(getDb(), { agentId: auth.agentId, principalKey: key })).toHaveLength(2);
    });

    it("review M1: a failed login and an unrecorded event of the same /24 never share an incident", async () => {
      const auth = await enroll();
      expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: REDIS_HEARTBEAT }))).status).toBe(200);
      await policy({ event_actions: ["read", "auth_failure"] });
      await send(auth, [
        // The attacker fails an AUTH on purpose first (ACL LOG, fingerprinted name tried)...
        slowRead(0, { db_user_fingerprint: `hmac-sha256:${randomBytes(32).toString("hex")}`, client_addr: "198.51.100.9" }, {
          action: "auth_failure",
          source: "redis_acl_log",
          objects: [],
          rows: undefined,
        }),
        // ...then a full synchronization from the same network.
        slowRead(1, { account_not_recorded: true, client_addr: "198.51.100.10" }, {
          source: "redis_sync",
          objects: [{ database: "*", object: "*" }],
          rows: undefined,
          signals: ["signature.full_sync"],
        }),
      ]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(2);
      const keys = list.map((i) => /\|principal:([^|]+)\|/.exec(i.dedupKey)?.[1]).sort();
      expect(keys).toEqual([`unknown:${sha256Hex("198.51.100.0/24")}`, `unrecorded:${sha256Hex("198.51.100.0/24")}`].sort());
      expect(list.every((i) => i.matchCount === 1)).toBe(true);
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

  describe("objects left out under a bound (ADR-0053 decision 3)", () => {
    /** A finding row of any target, written directly (the scan path serves one target per job). */
    const findingRow = (agentId: string, targetId: string, database: string, object: string, classifier: string) => ({
      id: randomUUID(),
      agentId,
      targetId,
      locationKey: sha256Hex(`${targetId}/${database}/public/${object}/${classifier}`),
      engine: "postgres",
      databaseName: database,
      schemaName: "public",
      objectName: object,
      fieldName: classifier.replace(/\W/g, "_"),
      classifier,
      classifiersVersion: "2026.09.1",
      confidence: 1,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
    });
    const quiet = (over: Record<string, unknown> = {}) => dumpEvent({ principal: { db_user: "app" }, rows: 99, signals: [], ...over });
    const named = { database: "crm", schema: "public", object: "audit_log" };
    const clients = { database: "crm", schema: "public", object: "clients" };
    const crmStar = { database: "crm", object: "*" };
    /** crm.clients 10 (email + IBAN), crm.orders 3, hr.staff 15 (card + NIR); others out of reach. */
    async function seed(auth: Auth): Promise<void> {
      await scanWith(auth, [finding("email", "pii.email", 1), finding("iban", "pii.iban", 1), finding("phone", "pii.phone", 1, "orders")]);
      await getDb()
        .insert(schema.findings)
        .values([
          findingRow(auth.agentId, "pg-prod-1", "hr", "staff", "pii.card_number"),
          findingRow(auth.agentId, "pg-prod-1", "hr", "staff", "pii.nir"),
          // Another target of the same agent: never read for pg-prod-1.
          findingRow(auth.agentId, "mysql-crm", "crm", "vault", "secret.aws_key"),
          findingRow(auth.agentId, "mysql-crm", "crm", "vault", "secret.password_hash"),
          // A false positive: excluded.
          findingRow(auth.agentId, "pg-prod-1", "crm", "tokens", "secret.aws_key"),
          findingRow(auth.agentId, "pg-prod-1", "crm", "tokens", "secret.password_hash"),
        ]);
      await getDb().execute(sql`update findings set false_positive_at = now() where agent_id = ${auth.agentId} and object_name = 'tokens'`);
    }

    it("stores the flag as sent and both scores; an event without it (a 0.8.0 agent) is scored exactly as before", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      await send(auth, [
        quiet({ objects: [named, crmStar], objects_overflowed: true }),
        quiet({ objects: [{ database: "CRM ", object: "*" }], objects_overflowed: true }),
        quiet({ objects: [{ database: "*", object: "*" }], objects_overflowed: true }),
        quiet({ objects: [named, crmStar] }),
        quiet({ objects: [clients, crmStar], objects_overflowed: true }),
        quiet({ objects: [{ database: "shop", object: "*" }], objects_overflowed: true }),
        quiet({ objects: [{ database: "crm", schema: "billing", object: "*" }], objects_overflowed: true }),
      ]);
      await drainPolicyWork(getDb());
      const rows = await eventsOf(auth.agentId);
      expect(rows.map((r) => r.objectsOverflowed)).toEqual([true, true, true, null, true, true, true]);
      expect(rows.map((r) => r.sensitivity)).toEqual([0, 0, 0, 0, 10, 0, 0]);
      expect(rows.map((r) => r.score)).toEqual([0, 0, 0, 0, 20, 0, 0]);
      expect(rows.map((r) => r.boundSensitivity)).toEqual([10, 10, 15, 0, 10, 0, 10]);
      expect(rows.map((r) => r.boundScore)).toEqual([20, 20, 30, 0, 20, 0, 20]);
    });

    it("objects, min_sensitivity and min_score policies see a flagged event through its bound; the incident keeps the named score", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      const byObject = await policy({ objects: { database: "crm", object: "clients" } });
      const bySensitivity = await policy({ min_sensitivity: 5 });
      const byScore = await policy({ min_score: 15 });
      await send(auth, [quiet({ objects: [named, crmStar], objects_overflowed: true }), quiet({ ts: at(1000), principal: { db_user: "old" }, objects: [named, crmStar] })]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list.map((i) => i.policyId).sort()).toEqual([byObject, bySensitivity, byScore].sort());
      const [first] = await eventsOf(auth.agentId);
      for (const inc of list) {
        expect(inc).toMatchObject({ principal: "app", eventDatabase: "crm", accessEventId: first?.id, eventScore: 0, eventBoundScore: 20, eventObjectsOverflowed: true });
        const [d] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, inc.id));
        expect(d?.payload).toMatchObject({ access: { score: 0, sensitivity: 0, objects_overflowed: true } });
      }
      const view = await getIncident(getDb(), String(list[0]?.id));
      expect(view?.access).toMatchObject({ score: 0, boundScore: 20, objectsOverflowed: true });
      const [ev] = await incidentEventViews(getDb(), String(list[0]?.id));
      expect(ev).toMatchObject({ objectsOverflowed: true, score: 0, boundScore: 20, boundSensitivity: 10 });
    });

    it("an unflagged event opens incidents exactly as before (no flag, bound = named, payload key false)", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      await policy({ objects: { database: "crm", object: "*" } });
      await policy({ objects: { database: "crm", object: "clients" } });
      await send(auth, [quiet({ objects: [named, crmStar] })]);
      await drainPolicyWork(getDb());
      const list = await incidentsOf(auth.agentId);
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({ eventScore: 0, eventBoundScore: 0, eventObjectsOverflowed: null, eventDatabase: "crm" });
      const [d] = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, String(list[0]?.id)));
      expect(d?.payload).toMatchObject({ access: { objects_overflowed: false } });
      expect((await getIncident(getDb(), String(list[0]?.id)))?.access).toMatchObject({ objectsOverflowed: false, boundScore: 0 });
    });

    it("the dedup object is the overflow `*` when its bound is the highest: the database `*`", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      await policy({ min_sensitivity: 1 });
      await send(auth, [quiet({ objects: [clients, { database: "*", object: "*" }], objects_overflowed: true })]);
      await drainPolicyWork(getDb());
      const [inc] = await incidentsOf(auth.agentId);
      expect(inc).toMatchObject({ eventDatabase: "*", eventScore: 20, eventBoundScore: 30 });
    });

    it("a location exception covers an overflow `*` only when it covers the whole database", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      const narrow = await policy({ objects: { database: "crm" } });
      const whole = await policy({ objects: { database: "crm" } });
      const literal = await policy({ objects: { database: "crm" } });
      const exception = (policyId: string, location: Record<string, string>) =>
        createException(getDb(), { policyId, agentId: null, targetId: null, classifier: null, location, reason: "job", expiresAt: null }, actor());
      await exception(narrow, { database: "crm", object: "clients" });
      await exception(whole, { database: "crm", schema: "*", object: "*" });
      await exception(literal, { database: "crm", object: "\\*" });
      const inHour = async (h: number) =>
        (await incidentsOf(auth.agentId)).filter((i) => i.eventBucket?.getTime() === T0 - (T0 % HOUR) + h * HOUR).map((i) => i.policyId);
      await send(auth, [quiet({ objects: [crmStar], objects_overflowed: true })]);
      await drainPolicyWork(getDb());
      expect((await inHour(0)).sort()).toEqual([narrow, literal].sort());
      // The same event without the flag (next hour): `\*` covers its literal `*`, the narrow one does not.
      await send(auth, [quiet({ ts: at(HOUR), objects: [crmStar] })]);
      await drainPolicyWork(getDb());
      expect(await inHour(1)).toEqual([narrow]);
      // With a named object too, the whole-database exception covers both.
      await send(auth, [quiet({ ts: at(2 * HOUR), objects: [clients, crmStar], objects_overflowed: true })]);
      await drainPolicyWork(getDb());
      expect((await inHour(2)).sort()).toEqual([narrow, literal].sort());
    });

    it("test obligation 1: a resolved or false-positive incident opened by a flagged event does not hide a later event naming the sensitive object", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      await policy({ objects: { database: "crm", object: "clients" } });
      for (const [i, close] of [[0, "resolved"], [1, "false_positive"]] as const) {
        const principal = { db_user: `etl${i}` };
        const base = i * 10_000;
        // The flagged event: named score 0, bound 60 (1 M rows).
        await send(auth, [quiet({ ts: at(base), principal, objects: [named, crmStar], rows: 1_000_000, objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        const [opened] = (await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user);
        expect(opened).toMatchObject({ eventScore: 0, eventBoundScore: 60 });
        if (close === "resolved") await transitionIncident(getDb(), String(opened?.id), "resolved", actor());
        else await transitionIncident(getDb(), String(opened?.id), "false_positive", actor());
        // A later flagged event like it is only linked.
        await send(auth, [quiet({ ts: at(base + 1000), principal, objects: [named, crmStar], rows: 10, objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        expect((await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user)).toHaveLength(1);
        // An event naming crm.clients (named score 20 < the bound 60, > the incident's 0) opens a new incident.
        await send(auth, [quiet({ ts: at(base + 2000), principal, objects: [clients], rows: 99 })]);
        await drainPolicyWork(getDb());
        const mine = (await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user);
        expect(mine).toHaveLength(2);
        expect(mine[1]).toMatchObject({ status: "open", eventScore: 20, eventObjectsOverflowed: null });
      }
    });

    it("test obligation 2: after a flagged event joins the overflow incident, a later event above its named score still bypasses the cap", async () => {
      process.env[EVENT_INCIDENTS_CAP_VAR] = "1";
      try {
        const auth = await agentWithTargets();
        await seed(auth);
        await policy({ objects: { database: "crm" } });
        await send(auth, [quiet({ principal: { db_user: "p0" }, objects: [clients], rows: 99 })]);
        await drainPolicyWork(getDb());
        // Cap reached: the flagged event (named 0, bound 60) opens the overflow incident.
        await send(auth, [quiet({ ts: at(1000), principal: { db_user: "p1" }, objects: [named, crmStar], rows: 1_000_000, objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        const [overflow] = (await incidentsOf(auth.agentId)).filter((x) => x.eventOverflow);
        expect(overflow).toMatchObject({ eventScore: 0, eventBoundScore: 60, eventObjectsOverflowed: true });
        // A second flagged event joins it: still the named scores only.
        await send(auth, [quiet({ ts: at(2000), principal: { db_user: "p2" }, objects: [named, crmStar], rows: 1_000_000, objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        const [joined] = (await incidentsOf(auth.agentId)).filter((x) => x.eventOverflow);
        expect(joined).toMatchObject({ id: overflow?.id, matchCount: 2, eventScore: 0, eventBoundScore: 60 });
        // Named score 10 (crm.clients, 9 rows): above the overflow's 0, below the bound 60: severe.
        await send(auth, [quiet({ ts: at(3000), principal: { db_user: "p3" }, objects: [clients], rows: 9 })]);
        await drainPolicyWork(getDb());
        const own = (await incidentsOf(auth.agentId)).filter((x) => x.principal === "p3");
        expect(own).toHaveLength(1);
        expect(own[0]).toMatchObject({ eventOverflow: false, eventScore: 10 });
      } finally {
        delete process.env[EVENT_INCIDENTS_CAP_VAR];
      }
    });

    it("security review M1: a closed incident of the bound's database does not absorb a flagged event that the named objects' scope would open", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      await policy({ min_sensitivity: 1 });
      const staff = { database: "hr", schema: "public", object: "staff" };
      const hrStar = { database: "hr", object: "*" };
      for (const [i, close] of [[0, "false_positive"], [1, "resolved"]] as const) {
        const principal = { db_user: `m1-${i}` };
        const base = i * 10_000;
        // An incident on hr (score 90), then closed.
        await send(auth, [quiet({ ts: at(base), principal, objects: [staff], rows: 1_000_000 })]);
        await drainPolicyWork(getDb());
        const [onHr] = (await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user);
        expect(onHr).toMatchObject({ eventDatabase: "hr", eventScore: 90 });
        await transitionIncident(getDb(), String(onHr?.id), close, actor());
        // Flagged: the bound picks hr (15 > 10), the named objects crm (named score 20 < 90).
        await send(auth, [quiet({ ts: at(base + 1000), principal, objects: [clients, hrStar], objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        const mine = (await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user);
        expect(mine.map((x) => x.eventDatabase)).toEqual(["hr", "crm"]);
        expect(mine[1]).toMatchObject({ status: "open", eventScore: 20, eventBoundScore: 30, eventObjectsOverflowed: true });
        // A second one joins the open crm incident, not the closed hr one.
        await send(auth, [quiet({ ts: at(base + 2000), principal, objects: [clients, hrStar], objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        const after = (await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user);
        expect(after).toHaveLength(2);
        expect(after[1]?.matchCount).toBe(2);
        // Once the crm incident is closed too and the event is no worse, it is linked to hr's, as before.
        await transitionIncident(getDb(), String(after[1]?.id), "resolved", actor());
        const links = await incidentEventCount(getDb(), String(onHr?.id));
        await send(auth, [quiet({ ts: at(base + 3000), principal, objects: [clients, hrStar], objects_overflowed: true })]);
        await drainPolicyWork(getDb());
        expect((await incidentsOf(auth.agentId)).filter((x) => x.principal === principal.db_user)).toHaveLength(2);
        expect(await incidentEventCount(getDb(), String(onHr?.id))).toBe(links + 1);
      }
    });

    it("security review L1: whole-target bounds are cached per process and read again when the target's findings change", async () => {
      const auth = await agentWithTargets();
      await seed(auth);
      const inner = engine.boundedWholeTargetCache();
      const set = vi.fn(inner.set);
      const cache = { get: inner.get, set };
      const events = [{ agentId: auth.agentId, targetId: "pg-prod-1", objects: [{ database: "*", object: "*" }], objectsOverflowed: true }];
      const read = () => getDb().transaction((tx) => engine.loadDatabaseBounds(tx, events, undefined, cache));
      const uncached = () => getDb().transaction((tx) => engine.loadDatabaseBounds(tx, events));
      const both = async () => {
        const [a, b] = [await read(), await uncached()];
        for (const db of ["*", "crm", "hr"]) expect(a.get(auth.agentId, "pg-prod-1", db), db).toBe(b.get(auth.agentId, "pg-prod-1", db));
        return a.get(auth.agentId, "pg-prod-1", "*");
      };
      expect(await both()).toBe(15);
      expect(set).toHaveBeenCalledTimes(1);
      expect(await both()).toBe(15);
      expect(set).toHaveBeenCalledTimes(1);
      // A new finding: read again.
      await getDb().insert(schema.findings).values([findingRow(auth.agentId, "pg-prod-1", "hr", "staff", "secret.aws_key")]);
      expect(await both()).toBe(25);
      expect(set).toHaveBeenCalledTimes(2);
      // A confidence change (a rescan), then a false-positive mark: read again each time.
      await getDb().execute(sql`update findings set confidence = 0.5 where agent_id = ${auth.agentId} and classifier = 'secret.aws_key' and object_name = 'staff'`);
      expect(await both()).toBe(20);
      await getDb().execute(sql`update findings set false_positive_at = now() where agent_id = ${auth.agentId} and object_name = 'staff'`);
      expect(await both()).toBe(10);
      // And back (the mark reset).
      await getDb().execute(sql`update findings set false_positive_at = null where agent_id = ${auth.agentId} and object_name = 'staff'`);
      expect(await both()).toBe(20);
      expect(set).toHaveBeenCalledTimes(5);
      // A per-database request of a cached target is served from it too.
      const perDb = await getDb().transaction((tx) => engine.loadDatabaseBounds(tx, [...events, { ...events[0]!, objects: [{ database: "crm", object: "*" }] }], undefined, cache));
      expect(perDb.get(auth.agentId, "pg-prod-1", "crm")).toBe(10);
      expect(set).toHaveBeenCalledTimes(5);
    });

    it("test obligation 3: the per-database lookup folds names, reads only the event's target, and gives the same result through the ASCII fallback", async () => {
      // `undefined`: probed (this database's `lower`); `false`: the `C`-ctype fallback forced
      // (event-engine-c-locale.test.ts runs the same rows on a `C` database).
      const auth = await agentWithTargets();
      await getDb()
        .insert(schema.findings)
        .values([
          findingRow(auth.agentId, "pg-prod-1", "Crm", "a", "pii.email"),
          findingRow(auth.agentId, "pg-prod-1", "ΒΆΣΗ", "b", "pii.iban"),
          findingRow(auth.agentId, "pg-prod-1", "Krm", "c", "pii.phone"),
          findingRow(auth.agentId, "mysql-crm", "crm", "z", "secret.aws_key"),
          findingRow(auth.agentId, "mysql-crm", "βάση", "z", "secret.aws_key"),
        ]);
      const star = (database: string) => ({ agentId: auth.agentId, targetId: "pg-prod-1", objects: [{ database, object: "*" }], objectsOverflowed: true });
      for (const unicodeLower of [undefined, false]) {
        const bounds = await getDb().transaction((tx) => engine.loadDatabaseBounds(tx, [star("CRM "), star("βάση"), star("krm"), star("none"), star("*")], unicodeLower));
        expect(bounds.get(auth.agentId, "pg-prod-1", "crm  ")).toBe(3);
        expect(bounds.get(auth.agentId, "pg-prod-1", "Βάση")).toBe(7);
        expect(bounds.get(auth.agentId, "pg-prod-1", "KRM")).toBe(3);
        expect(bounds.get(auth.agentId, "pg-prod-1", "none")).toBe(0);
        expect(bounds.get(auth.agentId, "pg-prod-1", "*")).toBe(7);
        expect(bounds.get(auth.agentId, "mysql-crm", "crm")).toBe(0);
      }
      // Without the database `*` (which reads the whole target), the per-database pre-filter alone.
      for (const unicodeLower of [undefined, false]) {
        const only = await getDb().transaction((tx) => engine.loadDatabaseBounds(tx, [star("CRM "), star("βάση"), star("krm"), star("none")], unicodeLower));
        expect([only.get(auth.agentId, "pg-prod-1", "crm"), only.get(auth.agentId, "pg-prod-1", "ΒΆΣΗ"), only.get(auth.agentId, "pg-prod-1", "krm")]).toEqual([3, 7, 3]);
        expect(only.get(auth.agentId, "pg-prod-1", "*")).toBe(0);
      }
      // Unflagged events read nothing.
      const none = await getDb().transaction((tx) => engine.loadDatabaseBounds(tx, [{ ...star("crm"), objectsOverflowed: null }]));
      expect(none.get(auth.agentId, "pg-prod-1", "crm")).toBe(0);
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
      // ADR-0053: the second event is flagged, so the bound columns and the incident flag are written too.
      const flagged = dumpEvent({ ts: at(1000), objects: [{ database: "crm", schema: "public", object: "clients" }, { database: "crm", object: "*" }], objects_overflowed: true });
      const body = { batch_id: uuidv7(), events: [dumpEvent(), flagged] };
      expect(await ingestEvents(db, auth.agentId, body as never)).toMatchObject({ kind: "accepted", duplicate: false });
      expect(await ingestEvents(db, auth.agentId, body as never)).toMatchObject({ kind: "accepted", duplicate: true });
      const stats = await drainPolicyWork(db);
      expect(stats.events).toBeGreaterThanOrEqual(2);
      const [inc] = await incidentsOf(auth.agentId);
      expect(inc?.matchCount).toBe(2);
      expect(inc).toMatchObject({ eventObjectsOverflowed: true });
      expect((await eventsOf(auth.agentId)).map((e) => [e.objectsOverflowed, e.boundScore !== null])).toEqual([[null, true], [true, true]]);
      await expect(pool.query("update access_events set objects_overflowed = true")).rejects.toThrow(/permission denied/);
      // Security review L2: the column grants of migration 0043, and nothing more.
      const { rows: privs } = await pool.query<{ flag: boolean; bound: boolean; inc_flag: boolean; inc_bound: boolean }>(`
        select has_column_privilege(current_user, 'public.access_events', 'objects_overflowed', 'UPDATE') as flag,
               has_column_privilege(current_user, 'public.access_events', 'bound_score', 'UPDATE')
                 and has_column_privilege(current_user, 'public.access_events', 'bound_sensitivity', 'UPDATE') as bound,
               has_column_privilege(current_user, 'public.incidents', 'event_objects_overflowed', 'UPDATE') as inc_flag,
               has_column_privilege(current_user, 'public.incidents', 'event_bound_score', 'UPDATE') as inc_bound`);
      expect(privs[0]).toEqual({ flag: false, bound: true, inc_flag: true, inc_bound: true });
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
