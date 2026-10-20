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
});
