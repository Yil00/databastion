import { randomBytes, randomUUID } from "node:crypto";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, agentTargets, auditLog, findings, policyExceptions } from "@/db/schema";
import type { Logger } from "@/lib/logger";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, enroll } from "@/test/helpers";

import {
  compareNames,
  computeCaseInventory,
  eventCaseChange,
  findingCaseChange,
  inventoryDetails,
  latestCaseInventory,
  parseInventoryDetails,
  runCaseInventory,
  runStartupCaseInventory,
  type EventNameGroup,
  type FindingNameGroup,
  type InventoryException,
} from "./exception-case-inventory";

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

  it("counts findings per exception and lists event names; expired or location-less exceptions are left out", () => {
    const a = X();
    const expired = X({ expiresAt: NOW });
    const noLocation = X({ location: null, targetId: "t" });
    const r = compareNames([a, expired, noLocation], [F(), F({ fieldName: "phone", n: 2 }), F({ objectName: "customers" })], [E(), E({ object: "customers" })], NOW);
    expect(r.findings.get(a.id)).toBe(5);
    expect(r.eventNames.get(a.id)).toEqual([E()]);
    expect(r.findings.has(expired.id)).toBe(false);
    expect(r.findings.has(noLocation.id)).toBe(false);
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
    const event = (targetId: string, objects: { database: string; schema?: string; object: string }[], ts = new Date()) => ({
      agentId,
      targetId,
      batchId: randomUUID(),
      itemIndex: 0,
      ts,
      principalKey: "a".repeat(64),
      dbUser: "app",
      action: "read",
      objects,
      source: "auditlog",
      aggregatedCount: 1,
    });
    await db.insert(accessEvents).values([
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }, { database: "crm", object: "USERACCOUNTS" }]),
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }]),
      event("mongo-1", [{ database: "crm", object: "useraccounts" }]),
      // Outside the retention: not counted.
      event("mongo-1", [{ database: "crm", object: "UserAccounts" }], new Date(Date.now() - 400 * 86_400_000)),
    ]);
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

    const latest = await latestCaseInventory(db);
    expect(latest?.entries).toHaveLength(2);

    // On demand: audited as the user's action.
    const userId = await adminUser();
    const again = await runCaseInventory(db, log, { userId, ip: "192.0.2.1" });
    expect(again.entries).toHaveLength(2);
    const rows = await db.select().from(auditLog).where(eq(auditLog.action, "policy_exception.case_inventory"));
    expect(rows.some((r) => r.actorType === "user" && r.actorId === userId)).toBe(true);
  });

  it("says when the bound is reached", async () => {
    const r = await getDb().transaction((tx) => computeCaseInventory(tx, { bound: 1 }));
    expect(r.boundReached).toBe(true);
    expect(r.findingNamesCompared).toBe(1);
    expect(r.eventNamesCompared).toBe(1);
  });
});
