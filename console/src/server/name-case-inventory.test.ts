import { randomBytes, randomUUID } from "node:crypto";

import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agentTargets, auditLog, findings, incidents, policyExceptions } from "@/db/schema";
import type { Logger } from "@/lib/logger";
import { CONSOLE_ACCEPTS } from "@/server/agent-api/capabilities";
import { handleEvents, handleHeartbeat } from "@/server/agent-api/handlers";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, fixtures, uuidv7 } from "@/test/helpers";
import { createNameCaseInventoryHandler } from "@/worker/queues";

import { getAgentDetail } from "./agents";
import { drainPolicyWork } from "./incidents";
import { NAME_CASE_INVENTORY_ACTION, latestNameCaseInventories, runDueNameCaseInventories, storeNameCase } from "./name-case-inventory";
import { createException, createPolicy, type PolicyInput } from "./policies";

/** ADR-0055 decision 7 (L8, M2) and the console rule end to end, against the console database. */

type Auth = { agentId: string; secret: string };

const sqlserverTarget = (nameCase?: unknown) => ({
  target_id: "mssql-1",
  engine: "sqlserver",
  reachable: true,
  audit_level: "partial",
  audit_source: "sqlserver_audit",
  ...(nameCase === undefined ? {} : { name_case: nameCase }),
});

const heartbeat = (targets: Record<string, unknown>[]) => ({
  ts: new Date().toISOString(),
  agent_version: "0.9.0",
  uptime_s: 60,
  classifiers_version: "2026.09.1",
  connectors: ["sqlserver", "mysql"],
  targets,
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
});

async function beat(auth: Auth, targets: Record<string, unknown>[]): Promise<Response> {
  return handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: heartbeat(targets) }));
}

async function targetRow(agentId: string, targetId = "mssql-1") {
  const [row] = await getDb()
    .select()
    .from(agentTargets)
    .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)));
  return row;
}

function captureLog(): { log: Logger; lines: string[] } {
  const lines: string[] = [];
  const write = (o: unknown, m?: string) => lines.push(`${JSON.stringify(o)} ${m ?? ""}`);
  return { log: { info: write, warn: write, error: write, debug: write } as unknown as Logger, lines };
}

const SENSITIVE = { databases: "sensitive", objects: "sensitive" };
const INSENSITIVE = { databases: "insensitive", objects: "insensitive" };

describe.skipIf(!hasDb)("name_case storage, inventory and correlation (ADR-0055)", () => {
  let teardown: () => Promise<void>;
  let adminId: string;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
    adminId = await adminUser();
  });
  afterAll(async () => teardown?.());

  it("lists the token and stores each fixture's name_case canonically; absent elsewhere", async () => {
    const auth = await enroll();
    const [, body] = fixtures("valid", "HeartbeatRequest").find(([f]) => f === "HeartbeatRequest.name-case-sqlserver.json") ?? [];
    const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { accepts: string[] }).accepts).toContain("target_status.name_case");
    expect(CONSOLE_ACCEPTS).toContain("target_status.name_case");
    const sent = (body as { targets: { target_id: string; name_case: unknown }[] }).targets;
    for (const t of sent) expect((await targetRow(auth.agentId, t.target_id))?.nameCase).toEqual(t.name_case);
    const detail = await getAgentDetail(getDb(), auth.agentId);
    expect(detail?.targets.find((t) => t.targetId === "mssql-many")?.nameCase).toEqual({ databases: "insensitive", objects: "unknown" });
  });

  it("compares canonically (L2): another order or a duplicate entry is no change; a missing field clears it (I-4)", async () => {
    const auth = await enroll();
    const v = { databases: "insensitive", objects: "insensitive", except: [{ database: "a_cs", objects: "sensitive" }, { database: "b_cs", objects: "unknown" }] };
    expect((await beat(auth, [sqlserverTarget(v)])).status).toBe(200);
    const first = await targetRow(auth.agentId);
    expect(first?.nameCase).toEqual(v);
    expect(first?.nameCaseInventoryDueAt).not.toBeNull();
    const reordered = { ...v, except: [{ database: "b_cs", objects: "unknown" }, { database: "a_cs", objects: "insensitive" }, { database: "a_cs", objects: "sensitive" }] };
    expect((await beat(auth, [sqlserverTarget(reordered)])).status).toBe(200);
    expect((await targetRow(auth.agentId))?.nameCaseChangedAt?.getTime()).toBe(first?.nameCaseChangedAt?.getTime());
    // An older agent (or a rolled-back one): no field, today's rule, and a change.
    expect((await beat(auth, [sqlserverTarget()])).status).toBe(200);
    const cleared = await targetRow(auth.agentId);
    expect(cleared?.nameCase).toBeNull();
    expect(cleared?.nameCaseChangedAt?.getTime()).toBeGreaterThanOrEqual(first?.nameCaseChangedAt?.getTime() ?? 0);
  });

  it("never answers 400 for an except past 8 KiB: stores objects unknown without except (L3)", async () => {
    const auth = await enroll();
    const except = Array.from({ length: 32 }, (_, i) => ({ database: `${String(i).padStart(2, "0")}${"d".repeat(250)}`, objects: "insensitive" }));
    const res = await beat(auth, [sqlserverTarget({ databases: "insensitive", objects: "insensitive", except })]);
    expect(res.status).toBe(200);
    expect((await targetRow(auth.agentId))?.nameCase).toEqual({ databases: "insensitive", objects: "unknown" });
  });

  it("compare-and-set: of two concurrent transactions storing one change, exactly one sees it (L8)", async () => {
    const auth = await enroll();
    expect((await beat(auth, [sqlserverTarget()])).status).toBe(200);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const first = getDb().transaction(async (tx) => {
      const changed = await storeNameCase(tx, auth.agentId, "mssql-1", "sqlserver", SENSITIVE);
      await gate;
      return changed;
    });
    await new Promise((r) => setTimeout(r, 100));
    const second = getDb().transaction((tx) => storeNameCase(tx, auth.agentId, "mssql-1", "sqlserver", { objects: "sensitive", databases: "sensitive" }));
    await new Promise((r) => setTimeout(r, 200));
    release();
    expect((await Promise.all([first, second])).sort()).toEqual([false, true]);
    // A value on another engine is stored as none.
    expect(await getDb().transaction((tx) => storeNameCase(tx, auth.agentId, "mssql-1", "postgres", SENSITIVE))).toBe(true);
    expect((await targetRow(auth.agentId))?.nameCase).toBeNull();
  });

  it("runs one inventory per change, at most once per target and hour, coalesced; ids and counts only (M2)", async () => {
    const db = getDb();
    const auth = await enroll();
    expect((await beat(auth, [sqlserverTarget()])).status).toBe(200);
    await db.insert(findings).values({
      id: randomUUID(),
      agentId: auth.agentId,
      targetId: "mssql-1",
      locationKey: randomBytes(32).toString("hex"),
      engine: "sqlserver",
      databaseName: "crm",
      schemaName: "dbo",
      objectName: "CustomersSecretNc",
      fieldName: "email",
      classifier: "pii.email",
      classifiersVersion: "2026.09.1",
      confidence: 0.9,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
    });
    const [x] = await db
      .insert(policyExceptions)
      .values({ agentId: auth.agentId, targetId: "mssql-1", location: { object: "customerssecretnc" }, reason: "lowercase" })
      .returning({ id: policyExceptions.id });
    const { log, lines } = captureLog();
    // The targets of the earlier tests (same database) are run first.
    await runDueNameCaseInventories(db, captureLog().log, { limit: 1000 });
    // No name_case yet: nothing due.
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(0);

    expect((await beat(auth, [sqlserverTarget(SENSITIVE)])).status).toBe(200);
    const handler = createNameCaseInventoryHandler(() => db, log);
    await handler([{ id: randomUUID(), name: "targets.name_case_inventory", data: {} }] as never);
    const audits = () =>
      db
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.action, NAME_CASE_INVENTORY_ACTION), sql`${auditLog.details}->>'agent_id' = ${auth.agentId}::text`));
    const [entry] = await audits();
    expect(entry).toMatchObject({ actorType: "system", outcome: "success", targetType: "agent_target", targetId: auth.agentId });
    expect(entry?.details).toMatchObject({ trigger: "name_case", target_id: "mssql-1", name_case: "with_case", exceptions: `${x?.id}:1:0`, exceptions_listed: 1 });
    const written = [JSON.stringify(entry?.details), ...lines].join("\n").toLowerCase();
    for (const s of ["customerssecretnc", "crm", "dbo"]) expect(written).not.toContain(s);
    expect((await targetRow(auth.agentId))?.nameCaseInventoryDueAt).toBeNull();

    // Two more changes within the hour: no run, one due mark (the earliest) kept.
    expect((await beat(auth, [sqlserverTarget(INSENSITIVE)])).status).toBe(200);
    const due = (await targetRow(auth.agentId))?.nameCaseInventoryDueAt;
    expect(due).not.toBeNull();
    expect((await beat(auth, [sqlserverTarget({ databases: "insensitive", objects: "unknown" })])).status).toBe(200);
    expect((await targetRow(auth.agentId))?.nameCaseInventoryDueAt?.getTime()).toBe(due?.getTime());
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(0);
    expect(await audits()).toHaveLength(1);

    // An hour later: one run for both changes, with the value stored then.
    await db
      .update(agentTargets)
      .set({ nameCaseInventoryAt: new Date(Date.now() - 3_700_000) })
      .where(eq(agentTargets.agentId, auth.agentId));
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(1);
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(0);
    const all = await audits();
    expect(all).toHaveLength(2);
    expect(all.map((a) => a.details?.name_case).sort()).toEqual(["per_database", "with_case"]);
    const latest = await latestNameCaseInventories(db, auth.agentId);
    expect(latest.get("mssql-1")).toMatchObject({ ok: true });

    // Another run holds the advisory lock: the target is put back, not lost.
    await db.update(agentTargets).set({ nameCaseInventoryAt: null }).where(eq(agentTargets.agentId, auth.agentId));
    expect((await beat(auth, [sqlserverTarget(SENSITIVE)])).status).toBe(200);
    await db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended('policy_exception.case_inventory', 0))`);
      expect((await runDueNameCaseInventories(db, log)).busy).toBe(1);
    });
    const back = await targetRow(auth.agentId);
    expect(back?.nameCaseInventoryDueAt).not.toBeNull();
    expect(back?.nameCaseInventoryAt).toBeNull();
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(1);
  });

  it("claims never-run targets first and at most 8 per agent and job, so one agent cannot starve the others (review L1)", async () => {
    const db = getDb();
    const { log } = captureLog();
    await runDueNameCaseInventories(db, log, { limit: 1000 });
    const flapping = await enroll();
    const quiet = await enroll();
    const targets = Array.from({ length: 12 }, (_, i) => ({ ...sqlserverTarget(SENSITIVE), target_id: `mssql-f${i}` }));
    expect((await beat(flapping, targets)).status).toBe(200);
    // The flapping agent's targets ran before (an hour ago); the quiet one never ran.
    await db
      .update(agentTargets)
      .set({ nameCaseInventoryAt: new Date(Date.now() - 2 * 3_600_000), nameCaseInventoryDueAt: new Date(Date.now() - 3_600_000) })
      .where(eq(agentTargets.agentId, flapping.agentId));
    expect((await beat(quiet, [sqlserverTarget(SENSITIVE)])).status).toBe(200);
    const stats = await runDueNameCaseInventories(db, log, { limit: 9 });
    expect(stats.ran).toBe(9);
    const ran = await db
      .select({ agentId: agentTargets.agentId, at: agentTargets.nameCaseInventoryAt })
      .from(agentTargets)
      .where(sql`${agentTargets.agentId} in (${flapping.agentId}::uuid, ${quiet.agentId}::uuid) and ${agentTargets.nameCaseInventoryDueAt} is null`);
    expect(ran.filter((r) => r.agentId === quiet.agentId)).toHaveLength(1);
    expect(ran.filter((r) => r.agentId === flapping.agentId)).toHaveLength(8);
    // The rest of the flapping agent's targets are taken by the next job.
    expect((await runDueNameCaseInventories(db, log)).ran).toBe(4);
  });

  async function policy(source: "access_event" | "finding", conditions: Record<string, unknown>): Promise<string> {
    const r = await createPolicy(
      getDb(),
      {
        name: `p-${uuidv7()}`,
        description: null,
        enabled: true,
        source,
        conditions: conditions as PolicyInput["conditions"],
        actions: [{ type: "create_incident", severity: "high" }],
      },
      { userId: adminId, ip: null },
    );
    if (r.outcome !== "ok") throw new Error("policy not created");
    return r.id;
  }

  it("correlation: an exception written in another case stops covering events and findings once the target reports name_case", async () => {
    const db = getDb();
    const auth = await enroll();
    expect((await beat(auth, [sqlserverTarget()])).status).toBe(200);
    const scope = { agent_ids: [auth.agentId], target_ids: ["mssql-1"] };
    const eventPolicy = await policy("access_event", { event_actions: ["read"], ...scope });
    const findingPolicy = await policy("finding", { classifiers: ["pii.email"], ...scope });
    for (const policyId of [eventPolicy, findingPolicy]) {
      const r = await createException(
        db,
        { policyId, agentId: auth.agentId, targetId: "mssql-1", classifier: null, location: { database: "crm", object: "customers" }, reason: "lowercase", expiresAt: null },
        { userId: adminId, ip: null },
      );
      expect(r.outcome).toBe("ok");
    }
    const sendRead = async (object: string, database = "crm") => {
      const event = {
        target_id: "mssql-1",
        ts: new Date().toISOString(),
        principal: { db_user: "etl" },
        action: "read",
        objects: [{ database, schema: "dbo", object }],
        rows: 10,
        signals: [],
        source: "sqlserver_audit",
        aggregated_count: 1,
      };
      const res = await handleEvents(agentRequest("POST", "/events", { auth, body: { batch_id: uuidv7(), events: [event] } }));
      expect(res.status).toBe(202);
    };
    const addFinding = (objectName: string, fieldName = "email") =>
      db.insert(findings).values({
        id: randomUUID(),
        agentId: auth.agentId,
        targetId: "mssql-1",
        locationKey: randomBytes(32).toString("hex"),
        engine: "sqlserver",
        databaseName: "crm",
        schemaName: "dbo",
        objectName,
        fieldName,
        classifier: "pii.email",
        classifiersVersion: "2026.09.1",
        confidence: 0.9,
        sampled: 10,
        matched: 5,
        lastBatchId: randomUUID(),
      });
    const count = async (policyId: string) => (await db.select().from(incidents).where(eq(incidents.policyId, policyId))).length;

    // No name_case (an older agent): today's rule, case-insensitive, both excepted.
    await sendRead("Customers");
    await addFinding("Customers");
    await drainPolicyWork(db);
    expect(await count(eventPolicy)).toBe(0);
    expect(await count(findingPolicy)).toBe(0);

    // The target reports a case-sensitive collation: `Customers` is no longer `customers`.
    expect((await beat(auth, [sqlserverTarget(SENSITIVE)])).status).toBe(200);
    await sendRead("Customers");
    await sendRead("customers");
    await addFinding("Customers", "phone");
    await addFinding("customers", "phone");
    await drainPolicyWork(db);
    expect(await count(eventPolicy)).toBe(1);
    // The new findings: `Customers` raises, `customers` stays excepted.
    expect(await count(findingPolicy)).toBe(1);

    // Per database: `crm` back to without case, another database with case.
    expect((await beat(auth, [sqlserverTarget({ databases: "insensitive", objects: "insensitive", except: [{ database: "crm_cs", objects: "sensitive" }] })])).status).toBe(200);
    const before = await count(eventPolicy);
    await sendRead("CUSTOMERS");
    await drainPolicyWork(db);
    expect(await count(eventPolicy)).toBe(before);
  });
});
