import { randomBytes, randomUUID } from "node:crypto";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agentTargets, auditLog, findings } from "@/db/schema";
import type { Logger } from "@/lib/logger";
import { hasDb, setupTestDatabase } from "@/test/db";
import { enroll } from "@/test/helpers";

import { drainPolicyWork } from "./incidents";
import { REEVALUATION_ACTION, runStartupSqliteReevaluation } from "./sqlite-reach-reevaluation";

/** P10-E, security review L1 of 342a257: SQLite findings re-evaluated once at the first worker start. */

function captureLog(): { log: Logger; lines: string[] } {
  const lines: string[] = [];
  const push = (obj: unknown, msg?: string) => lines.push(JSON.stringify(obj) + (msg ?? ""));
  return { log: { warn: push, info: push, error: push } as unknown as Logger, lines };
}

describe.skipIf(!hasDb)("SQLite findings re-evaluation at the first worker start (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
  });
  afterAll(async () => teardown?.());

  it("marks only the sqlite findings pending, once, audited with the count only; concurrent starts run it once", async () => {
    const db = getDb();
    const { agentId } = await enroll();
    await db.insert(agentTargets).values([
      { agentId, targetId: "crm-app", engine: "sqlite", reachable: true, auditLevel: "none" },
      { agentId, targetId: "pg-1", engine: "postgres", reachable: true, auditLevel: "full" },
    ]);
    const row = (targetId: string, engine: string, objectName: string) => ({
      id: randomUUID(),
      agentId,
      targetId,
      locationKey: randomBytes(32).toString("hex"),
      engine,
      databaseName: engine === "sqlite" ? "main" : "crm",
      schemaName: engine === "sqlite" ? null : "public",
      objectName,
      fieldName: "email",
      classifier: "pii.email",
      classifiersVersion: "2026.09.1",
      confidence: 0.9,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
    });
    await db.insert(findings).values([row("crm-app", "sqlite", "customers"), row("crm-app", "sqlite", "orders"), row("pg-1", "postgres", "clients")]);
    // As an older worker left them: evaluated.
    await drainPolicyWork(db);
    const pending = async () =>
      (await db.select({ engine: findings.engine, at: findings.policyEvaluatedAt }).from(findings).where(eq(findings.agentId, agentId)))
        .filter((r) => r.at === null)
        .map((r) => r.engine)
        .sort();
    expect(await pending()).toEqual([]);

    const { log, lines } = captureLog();
    // Two workers starting together: one runs it, the other skips (lock or recorded entry).
    const results = await Promise.all([runStartupSqliteReevaluation(db, log), runStartupSqliteReevaluation(db, log)]);
    expect(results.filter((r) => r !== null)).toEqual([2]);
    expect(await pending()).toEqual(["sqlite", "sqlite"]);
    const entries = await db.select().from(auditLog).where(eq(auditLog.action, REEVALUATION_ACTION));
    expect(entries).toHaveLength(1);
    expect(entries[0]?.actorType).toBe("system");
    expect(entries[0]?.details).toEqual({ engines: "sqlite", findings: 2 });
    // Names never logged.
    expect(lines.join("\n")).not.toContain("customers");

    // The policy engine evaluates them again; a later start does nothing.
    await drainPolicyWork(db);
    expect(await pending()).toEqual([]);
    expect(await runStartupSqliteReevaluation(db, log)).toBeNull();
    expect(await pending()).toEqual([]);
    expect(await db.select().from(auditLog).where(eq(auditLog.action, REEVALUATION_ACTION))).toHaveLength(1);
  });
});
