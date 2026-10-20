import { randomBytes, randomUUID } from "node:crypto";

import { and, eq, sql } from "drizzle-orm";
import type { Job } from "pg-boss";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb, type Database } from "@/db/client";
import { accessEvents, agentTargets, auditLog, findings, policyExceptions } from "@/db/schema";
import type { Logger } from "@/lib/logger";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, enroll } from "@/test/helpers";
import { createCaseInventoryHandler } from "@/worker/queues";

import { CASE_INVENTORY_QUEUE, setCaseInventoryJobSender } from "./case-inventory-queue";

import {
  compareNames,
  computeCaseInventory,
  eventCaseChange,
  findingCaseChange,
  inventoryDetails,
  caseInventoryStatus,
  parseInventoryDetails,
  runCaseInventory,
  runStartupCaseInventory,
  type EventNameGroup,
  type FindingNameGroup,
  type InventoryException,
} from "./exception-case-inventory";
import { handleCaseInventory, handleLogin } from "./user-api";

const NOW = new Date("2026-10-20T12:00:00Z");
const X = (over: Partial<InventoryException> = {}): InventoryException => ({
  id: randomUUID(),
  agentId: null,
  targetId: null,
  classifier: null,
  location: { database: "crm", object: "customers" },
  expiresAt: null,
  ...over,
});
const F = (over: Partial<FindingNameGroup> = {}): FindingNameGroup => ({
  agentId: "a",
  targetId: "t",
  engine: "postgres",
  databaseName: "crm",
  schemaName: "public",
  objectName: "Customers",
  fieldName: "email",
  classifier: "pii.email",
  n: 3,
  ...over,
});
const E = (over: Partial<EventNameGroup> = {}): EventNameGroup => ({
  agentId: "a",
  targetId: "t",
  engine: "mongodb",
  database: "crm",
  schema: null,
  object: "Customers",
  ...over,
});

describe("case inventory comparison (ADR-0054 decision 6, pure)", () => {
  it("flags a name covered without case but not with case, on case-sensitive engines only", () => {
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas"]) {
      expect(findingCaseChange(X(), F({ engine }))).toBe(true);
      expect(eventCaseChange(X(), E({ engine }))).toBe(true);
      // Covered both ways, or neither: no change.
      expect(findingCaseChange(X(), F({ engine, objectName: "customers" }))).toBe(false);
      expect(findingCaseChange(X(), F({ engine, objectName: "orders" }))).toBe(false);
      expect(eventCaseChange(X({ location: { object: "*" } }), E({ engine }))).toBe(false);
    }
    for (const engine of ["sqlserver", "mysql", "mariadb", "openldap"]) {
      expect(findingCaseChange(X(), F({ engine }))).toBe(false);
      expect(eventCaseChange(X(), E({ engine }))).toBe(false);
    }
    // Unknown event engine: compared with case.
    expect(eventCaseChange(X(), E({ engine: null }))).toBe(true);
  });

  it("keeps the other scopes of the exception", () => {
    expect(findingCaseChange(X({ agentId: "b" }), F())).toBe(false);
    expect(findingCaseChange(X({ targetId: "u" }), F())).toBe(false);
    expect(findingCaseChange(X({ classifier: "pii.phone" }), F())).toBe(false);
    expect(findingCaseChange(X({ classifier: "pii.*" }), F())).toBe(true);
    // A classifier or a field glob other than `*` never covers an event.
    expect(eventCaseChange(X({ classifier: "pii.*" }), E())).toBe(false);
    expect(eventCaseChange(X({ location: { object: "customers", field: "email" } }), E())).toBe(false);
    expect(eventCaseChange(X({ location: { object: "customers", field: "*" } }), E())).toBe(true);
    // Field case on findings.
    expect(findingCaseChange(X({ location: { field: "email" } }), F({ objectName: "x", fieldName: "Email" }))).toBe(true);
  });

  it("counts findings per exception and lists event names; expired or location-less exceptions are left out", async () => {
    const a = X();
    const expired = X({ expiresAt: NOW });
    const noLocation = X({ location: null, targetId: "t" });
    const r = await compareNames([a, expired, noLocation], [F(), F({ fieldName: "phone", n: 2 }), F({ objectName: "customers" })], [E(), E({ object: "customers" })], NOW);
    expect(r.budgetReached).toBe(false);
    expect(r.findings.get(a.id)).toBe(5);
    expect(r.eventNames.get(a.id)).toEqual([E()]);
    expect(r.findings.has(expired.id)).toBe(false);
    expect(r.findings.has(noLocation.id)).toBe(false);
  });

  it("stops at the comparison budget and says so", async () => {
    const xs = [X(), X(), X()];
    // 2 names per exception: a budget of 5 evaluations compares two exceptions only.
    const r = await compareNames(xs, [F()], [E()], NOW, 5);
    expect(r.budgetReached).toBe(true);
    expect([...r.findings.keys()]).toEqual([xs[0]?.id, xs[1]?.id]);
    expect((await compareNames(xs, [F()], [E()], NOW, 6)).budgetReached).toBe(false);
  });

  it("audit / log details hold ids and counts only, and read back", () => {
    const id = randomUUID();
    const d = inventoryDetails({ entries: [{ exceptionId: id, findings: 4, events: 7 }], findingNamesCompared: 10, eventNamesCompared: 3, boundReached: true }, "startup");
    expect(d).toMatchObject({ exceptions: `${id}:4:7`, exceptions_listed: 1, bound_reached: true, trigger: "startup" });
    const back = parseInventoryDetails(NOW, d);
    expect(back.entries).toEqual([{ exceptionId: id, findings: 4, events: 7 }]);
    expect(back.boundReached).toBe(true);
    // Anything else in the string is dropped.
    expect(parseInventoryDetails(NOW, { exceptions: "crm.customers:1:1 <b>:2:2" }).entries).toEqual([]);
  });
});

function captureLog(): { log: Logger; lines: string[] } {
  const lines: string[] = [];
  const push = (obj: unknown, msg?: string) => lines.push(JSON.stringify(obj) + (msg ?? ""));
  return { log: { warn: push, info: push, error: push } as unknown as Logger, lines };
}

describe.skipIf(!hasDb)("case inventory against the console database (ADR-0054 decision 6)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
  });
  afterAll(async () => teardown?.());

  it("lists the exceptions that no longer cover stored findings or events, with ids and counts only; once at startup", async () => {
    const db = getDb();
    const { agentId } = await enroll();
    await db.insert(agentTargets).values([
      { agentId, targetId: "pg-1", engine: "postgres", reachable: true, auditLevel: "full" },
      { agentId, targetId: "my-1", engine: "mysql", reachable: true, auditLevel: "partial" },
      { agentId, targetId: "mongo-1", engine: "mongodb", reachable: true, auditLevel: "partial" },
    ]);
    const finding = (targetId: string, engine: string, objectName: string, fp = false) => ({
      id: randomUUID(),
      agentId,
      targetId,
      locationKey: randomBytes(32).toString("hex"),
      engine,
      databaseName: "crm",
      schemaName: "public",
      objectName,
      fieldName: "email",
      classifier: "pii.email",
      classifiersVersion: "2026.09.1",
      confidence: 0.9,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
      falsePositiveAt: fp ? new Date() : null,
    });
    await db.insert(findings).values([
      finding("pg-1", "postgres", "CustomersSecret"),
      finding("pg-1", "postgres", "CustomersSecret2", true),
      finding("pg-1", "postgres", "customerssecret"),
      finding("my-1", "mysql", "CustomersSecret"),
    ]);
    const event = (
      targetId: string,
      objects: { database: string; schema?: string; object: string }[],
      ts = new Date(),
      source = "mongodb_audit_log",
    ) => ({
      agentId,
      targetId,
      batchId: randomUUID(),
      itemIndex: 0,
      ts,
      principalKey: "a".repeat(64),
      dbUser: "app",
      action: "read",
      objects,
      source,
      aggregatedCount: 1,
    });
    await db.insert(accessEvents).values([
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }, { database: "crm", object: "USERACCOUNTS" }]),
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }]),
      event("mongo-1", [{ database: "crm", object: "useraccounts" }]),
      // Outside the retention: not counted.
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }], new Date(Date.now() - 400 * 86_400_000)),
      // A source that tells a case-blind engine: not counted, whatever the target's engine (L1).
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }], new Date(), "sqlserver_audit"),
    ]);
    // The target's engine changed after ingest: the events keep the engine their source tells (L1).
    await db.update(agentTargets).set({ engine: "mysql" }).where(eq(agentTargets.targetId, "mongo-1"));
    const [pgX, mongoX, okX] = await db
      .insert(policyExceptions)
      .values([
        { location: { object: "customerssecret*" }, reason: "pg glob in lowercase" },
        { targetId: "mongo-1", location: { database: "crm", object: "useraccounts" }, reason: "mongo glob in lowercase" },
        { location: { object: "orders" }, reason: "unaffected" },
      ])
      .returning({ id: policyExceptions.id });

    const { log, lines } = captureLog();
    const first = await runStartupCaseInventory(db, log);
    expect(first?.entries).toEqual(
      expect.arrayContaining([
        { exceptionId: pgX?.id, findings: 2, events: 0 },
        { exceptionId: mongoX?.id, findings: 0, events: 2 },
      ]),
    );
    expect(first?.entries.some((e) => e.exceptionId === okX?.id)).toBe(false);
    expect(first?.boundReached).toBe(false);

    // Startup runs once: the audit log already holds an inventory.
    expect(await runStartupCaseInventory(db, log)).toBeNull();
    const audits = await db.select().from(auditLog).where(eq(auditLog.action, "policy_exception.case_inventory"));
    expect(audits).toHaveLength(1);
    expect(audits[0]?.actorType).toBe("system");

    // Never a glob or a name in the audit entry or the log.
    const written = [JSON.stringify(audits[0]?.details), ...lines].join("\n");
    for (const s of ["customerssecret", "CustomersSecret", "useraccounts", "UserAccounts", "crm", "orders"]) {
      expect(written.toLowerCase()).not.toContain(s.toLowerCase());
    }
    expect(written).toContain(String(pgX?.id));

    const status = await caseInventoryStatus(db);
    expect(status.latest?.entries).toHaveLength(2);
    expect(status.failure).toBeNull();

    // A failed startup run: a failure entry with the error code only, shown while more recent than
    // the latest success, and not counted as done (L3).
    const failing = Object.assign(Object.create(db) as Database, {
      transaction: () => Promise.reject(Object.assign(new Error("canceling statement due to statement timeout on crm.useraccounts"), { code: "57014" })),
    });
    expect(await runStartupCaseInventory(failing, log)).toBeNull();
    const [failed] = await db.select().from(auditLog).where(and(eq(auditLog.action, "policy_exception.case_inventory"), eq(auditLog.outcome, "failure")));
    expect(failed?.details).toEqual({ trigger: "startup", error_code: "57014" });
    expect((await caseInventoryStatus(db)).failure).toMatchObject({ trigger: "startup", errorCode: "57014" });
    expect(lines.join("\n")).not.toContain("useraccounts");

    // On demand (worker job): audited as the user's action; a later success hides the failure.
    const userId = await adminUser();
    const handler = createCaseInventoryHandler(() => db, log);
    const job = (data: Record<string, unknown>) => ({ id: randomUUID(), name: CASE_INVENTORY_QUEUE, data }) as unknown as Job<Record<string, unknown>>;
    await handler([job({ userId: "not-a-uuid", ip: null })]);
    await handler([job({ userId, ip: "192.0.2.1" })]);
    const rows = await db.select().from(auditLog).where(and(eq(auditLog.action, "policy_exception.case_inventory"), eq(auditLog.outcome, "success")));
    expect(rows.filter((r) => r.actorType === "user")).toHaveLength(1);
    expect(rows.find((r) => r.actorType === "user")).toMatchObject({ actorId: userId, sourceIp: "192.0.2.1" });
    const after = await caseInventoryStatus(db);
    expect(after.failure).toBeNull();
    expect(after.latest?.trigger).toBe("user");
    expect(after.latest?.entries).toHaveLength(2);

    // Another run holds the lock: the on-demand run does not wait, and is audited as a failure.
    await db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended('policy_exception.case_inventory', 0))`);
      expect(await runCaseInventory(db, log, { userId, ip: null })).toBeNull();
    });
    expect((await caseInventoryStatus(db)).failure).toMatchObject({ trigger: "user", errorCode: "inventory_running" });
  });

  it("the route queues the run for the worker (202), coalesces, is rate limited per user and audited (M1)", async () => {
    await adminUser();
    const origin = "http://console.test";
    const loginRes = await handleLogin(
      new Request(`${origin}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: origin },
        body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
      }),
    );
    expect(loginRes.status).toBe(200);
    const cookie = (loginRes.headers.getSetCookie().find((c) => c.startsWith("databastion_session=")) ?? "").split(";")[0] ?? "";
    const { csrf_token: csrf } = (await loginRes.json()) as { csrf_token: string };
    const post = () =>
      handleCaseInventory(
        new Request(`${origin}/api/policy-exceptions/case-inventory`, { method: "POST", headers: { Origin: origin, Cookie: cookie, "X-CSRF-Token": csrf } }),
      );
    const requests = () =>
      getDb().select().from(auditLog).where(eq(auditLog.action, "policy_exception.case_inventory_request"));

    // No sender (the web process could not queue it): 503, audited, not counted.
    setCaseInventoryJobSender(null);
    expect((await post()).status).toBe(503);
    expect(await requests()).toEqual([expect.objectContaining({ outcome: "failure", details: { reason: "queue_unavailable" } })]);

    const sent: unknown[] = [];
    setCaseInventoryJobSender(async (job) => {
      sent.push(job);
      return sent.length === 1 ? "job-1" : null;
    });
    try {
      const first = await post();
      expect(first.status).toBe(202);
      expect(await first.json()).toEqual({ queued: true, coalesced: false });
      const second = await post();
      expect(await second.json()).toEqual({ queued: true, coalesced: true });
      expect(sent).toHaveLength(2);
      expect((sent[0] as { userId: string }).userId).toMatch(/^[0-9a-f-]{36}$/);
      expect((await post()).status).toBe(202);
      // Past 3 requests per 10 minutes: refused before queuing.
      const limited = await post();
      expect(limited.status).toBe(429);
      expect(limited.headers.get("Retry-After")).not.toBeNull();
      expect(sent).toHaveLength(3);
      const audited = await requests();
      expect(audited.filter((r) => r.outcome === "success")).toHaveLength(3);
      expect(audited.filter((r) => r.outcome === "failure").map((r) => r.details)).toEqual(
        expect.arrayContaining([{ reason: "queue_unavailable" }, { reason: "rate_limited" }]),
      );
      // The web process ran nothing: no inventory entry was written by these requests.
    } finally {
      setCaseInventoryJobSender(null);
    }
  });

  it("says when the bound is reached", async () => {
    const r = await getDb().transaction((tx) => computeCaseInventory(tx, { bound: 1 }));
    expect(r.boundReached).toBe(true);
    expect(r.findingNamesCompared).toBe(1);
    expect(r.eventNamesCompared).toBe(1);
    // The comparison budget too.
    expect((await getDb().transaction((tx) => computeCaseInventory(tx, { comparisonBudget: 1 }))).boundReached).toBe(true);
  });
});
