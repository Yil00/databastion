import { randomBytes, randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agentTargets, findings, policyExceptions } from "@/db/schema";
import { hasDb, setupTestDatabase } from "@/test/db";
import { enroll } from "@/test/helpers";

import { computeCaseInventory } from "./exception-case-inventory";

/**
 * ADR-0054 decision 6 under a `C` / `POSIX` ctype, where PostgreSQL `lower` folds ASCII only: the
 * inventory compares names in JavaScript (SQL only groups them by exact text), so its result is
 * the one of a UTF-8 console database.
 */
describe.skipIf(!hasDb)("case inventory on a console database with the C character type (N1 fallback)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase({ ctype: "C" });
  });
  afterAll(async () => teardown?.());

  it("compares non-ASCII names in JavaScript: the same result as on a UTF-8 database", async () => {
    const db = getDb();
    const { agentId } = await enroll();
    await db.insert(agentTargets).values({ agentId, targetId: "pg-1", engine: "postgres", reachable: true, auditLevel: "full" });
    await db.insert(findings).values(
      ["ΠΕΛΑΤΕΣ", "πελατεσ", "ÉCOLE"].map((objectName) => ({
        id: randomUUID(),
        agentId,
        targetId: "pg-1",
        locationKey: randomBytes(32).toString("hex"),
        engine: "postgres",
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
      })),
    );
    const [greek, french] = await db
      .insert(policyExceptions)
      .values([
        { location: { object: "πελατεσ" }, reason: "greek" },
        { location: { object: "école" }, reason: "french" },
      ])
      .returning({ id: policyExceptions.id });
    const r = await db.transaction((tx) => computeCaseInventory(tx));
    expect(r.entries).toEqual(
      expect.arrayContaining([
        { exceptionId: greek?.id, findings: 1, events: 0 },
        { exceptionId: french?.id, findings: 1, events: 0 },
      ]),
    );
    expect(r.entries).toHaveLength(2);
  });

  it("compares a name_case target's names in JavaScript too (ADR-0055): per part, as on a UTF-8 database", async () => {
    const db = getDb();
    const { agentId } = await enroll();
    await db.insert(agentTargets).values([
      { agentId, targetId: "mssql-c", engine: "sqlserver", reachable: true, auditLevel: "partial", nameCase: { databases: "insensitive", objects: "insensitive", except: [{ database: "ΒΆΣΗ", objects: "sensitive" }] } },
      { agentId, targetId: "my-c", engine: "mysql", reachable: true, auditLevel: "partial", nameCase: { databases: "sensitive", objects: "sensitive" } },
    ]);
    const row = (targetId: string, engine: string, databaseName: string, schemaName: string | null, objectName: string, fieldName: string) => ({
      id: randomUUID(),
      agentId,
      targetId,
      locationKey: randomBytes(32).toString("hex"),
      engine,
      databaseName,
      schemaName,
      objectName,
      fieldName,
      classifier: "pii.email",
      classifiersVersion: "2026.09.1",
      confidence: 0.9,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
    });
    await db.insert(findings).values([
      // The database `βάση` is listed (folded lookup, final sigma): object names with case.
      row("mssql-c", "sqlserver", "βάση", "dbo", "ΠΕΛΑΤΕΣ", "email"),
      // Another database: without case.
      row("mssql-c", "sqlserver", "crm", "dbo", "ÉCOLE", "email"),
      // MySQL: object names with case, column names never.
      row("my-c", "mysql", "crm", null, "ÉCOLE", "ÉMAIL"),
    ]);
    const [greek, french, column] = await db
      .insert(policyExceptions)
      .values([
        { agentId, location: { object: "πελατεσ" }, reason: "greek" },
        { agentId, location: { object: "école" }, reason: "french" },
        { agentId, targetId: "my-c", location: { field: "émail" }, reason: "column" },
      ])
      .returning({ id: policyExceptions.id });
    const run = (scope?: { agentId: string; targetId: string }) => db.transaction((tx) => computeCaseInventory(tx, { scope }));
    const all = await run();
    expect(all.entries.filter((e) => [greek?.id, french?.id, column?.id].includes(e.exceptionId))).toEqual(
      expect.arrayContaining([
        { exceptionId: greek?.id, findings: 1, events: 0 },
        { exceptionId: french?.id, findings: 1, events: 0 },
      ]),
    );
    expect(all.entries.some((e) => e.exceptionId === column?.id)).toBe(false);
    // One target's run: only that target's names (the earlier test's global exceptions filtered out).
    const ours = (r: Awaited<ReturnType<typeof run>>) => r.entries.filter((e) => [greek?.id, french?.id, column?.id].includes(e.exceptionId));
    expect(ours(await run({ agentId, targetId: "mssql-c" }))).toEqual([{ exceptionId: greek?.id, findings: 1, events: 0 }]);
    expect(ours(await run({ agentId, targetId: "my-c" }))).toEqual([{ exceptionId: french?.id, findings: 1, events: 0 }]);
  });
});
