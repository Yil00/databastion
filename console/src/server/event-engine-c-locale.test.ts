import { createHash, randomUUID } from "node:crypto";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, findings as findingsTable } from "@/db/schema";
import { handleEvents, handleFindings, handleHeartbeat, handlePollJobs } from "@/server/agent-api/handlers";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import { agentRequest, enroll, uuidv7 } from "@/test/helpers";

import { loadObjectHits, prefilterNames } from "./event-engine";
import { drainPolicyWork } from "./incidents";

/**
 * Security review L1 of the N1 change: under a `C` / `POSIX` character type, PostgreSQL `lower`
 * folds ASCII only, so the sensitivity lookup drops its name pre-filter when a name holds another
 * character and lets `objectKey` (JavaScript `foldName`) decide.
 */
describe("sensitivity name pre-filter (pure)", () => {
  it("keeps every name and its fold; the ASCII form under an ASCII-only `lower`", () => {
    expect(prefilterNames(["CLIENTS ", "orders"], true)).toEqual({ kind: "fold", names: ["CLIENTS ", "clients", "orders"] });
    // PR #274 review L2: under an ASCII-only `lower`, the ASCII form for every chunk.
    expect(prefilterNames(["CLIENTS ", "orders"], false)).toEqual({ kind: "ascii", folded: ["clients", "orders"] });
    expect(prefilterNames(["ΠΕΛΑΤΕΣ"], true)).toEqual({ kind: "fold", names: ["ΠΕΛΑΤΕΣ", "πελατεσ"] });
    // Phase 9 follow-up after N1: the JavaScript folds, compared with the SQL fold of ASCII names.
    expect(prefilterNames(["clients", "CLIENTÈLE", "Clients "], false)).toEqual({ kind: "ascii", folded: ["clients", "clientèle"] });
  });
});

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

describe.skipIf(!hasDb)("sensitivity on a console database with the C character type (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase({ ctype: "C" });
  });
  afterAll(async () => teardown?.());

  it("matches non-ASCII names without case all the same; never a different name", async () => {
    const auth = await enroll();
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
    await enqueueJob(getDb(), {
      agentId: auth.agentId,
      type: "discovery.scan",
      targetId: "pg-prod-1",
      classifiersVersion: "2026.09.1",
      params: { sample_rows: 200, max_duration_s: 900 },
    });
    const poll = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
    const { jobs } = (await poll.json()) as { jobs: { job_id: string }[] };
    const item = (object: string, field: string, classifier: string) => ({
      target_id: "pg-prod-1",
      location: { engine: "postgres", database: "crm", schema: "public", object, field },
      classifier,
      confidence: 1,
      sampled: 200,
      matched: 150,
    });
    const findings = [item("CLIENTÈLE", "email", "pii.email"), item("ΠΕΛΑΤΕΣ", "phone", "pii.phone"), item("clients", "name", "pii.person_name")];
    const body = { batch_id: uuidv7(), job_id: jobs[0]?.job_id, classifiers_version: "2026.09.1", findings };
    expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);

    const event = (object: string, i: number) => ({
      target_id: "pg-prod-1",
      ts: new Date(Date.parse("2026-09-27T10:05:00Z") + i * 1000).toISOString(),
      principal: { db_user: "backup" },
      action: "read",
      objects: [{ database: "crm", schema: "public", object }],
      rows: 99,
      signals: [],
      source: "pgaudit",
      aggregated_count: 1,
    });
    const events = ["clientèle", "πελατες", "CLIENTS ", "clientele", "πελατης"].map(event);
    expect((await handleEvents(agentRequest("POST", "/events", { auth, body: { batch_id: uuidv7(), events } }))).status).toBe(202);
    await drainPolicyWork(getDb());
    const rows = await getDb().select().from(accessEvents).where(eq(accessEvents.agentId, auth.agentId)).orderBy(accessEvents.ts);
    expect(rows.map((r) => r.sensitivity)).toEqual([3, 3, 2, 0, 0]);
  });
  it("phase 9 follow-up after N1: the fallback reads the chunk's targets only, and of their ASCII names the matching ones", async () => {
    const auth = await enroll();
    const hb = {
      ...HEARTBEAT,
      targets: [...HEARTBEAT.targets, { target_id: "pg-prod-2", engine: "postgres", reachable: true, audit_level: "full", audit_source: "pgaudit" }],
    };
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: hb }))).status).toBe(200);
    const row = (targetId: string, object: string) => ({
      id: randomUUID(),
      agentId: auth.agentId,
      targetId,
      locationKey: createHash("sha256").update(`${targetId}/crm/public/${object}/c`).digest("hex"),
      engine: "postgres",
      databaseName: "crm",
      schemaName: "public",
      objectName: object,
      fieldName: "c",
      classifier: "pii.email",
      classifiersVersion: "2026.09.1",
      confidence: 1,
      sampled: 10,
      matched: 5,
      lastBatchId: randomUUID(),
    });
    await getDb()
      .insert(findingsTable)
      .values([row("pg-prod-1", "CLIENTÈLE"), row("pg-prod-1", "CLIENTS"), row("pg-prod-1", "invoices"), row("pg-prod-2", "CLIENTÈLE"), row("pg-prod-2", "clients")]);
    const hits = await getDb().transaction((tx) =>
      loadObjectHits(tx, [
        { agentId: auth.agentId, targetId: "pg-prod-1", objects: [{ database: "crm", schema: "public", object: "clientèle" }] },
        { agentId: auth.agentId, targetId: "pg-prod-1", objects: [{ database: "crm", schema: "public", object: "clients " }] },
      ]),
    );
    const read = [...hits.keys()].filter((k) => k.includes("\u0000=public\u0000")).map((k) => k.split("\u0000").filter((_p, i) => i === 1 || i === 4).join("/"));
    // Non-ASCII names of the chunk's targets are all read (JavaScript decides); ASCII ones only
    // when they fold to an event name; nothing of the other target of the same agent.
    expect(read.sort()).toEqual(["pg-prod-1/clients", "pg-prod-1/clientèle"]);
  });
  it("PR #274 review L2: an ASCII event name gets the sensitivity of a finding spelled with the Kelvin sign", async () => {
    const auth = await enroll();
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
    await enqueueJob(getDb(), {
      agentId: auth.agentId,
      type: "discovery.scan",
      targetId: "pg-prod-1",
      classifiersVersion: "2026.09.1",
      params: { sample_rows: 200, max_duration_s: 900 },
    });
    const { jobs } = (await (await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).json()) as { jobs: { job_id: string }[] };
    // `\u212a` is the Kelvin sign: JavaScript lowercases it to an ASCII `k`, `C`-ctype `lower` does not.
    const kunden = {
      target_id: "pg-prod-1",
      location: { engine: "postgres", database: "crm", schema: "public", object: "\u212aunden", field: "email" },
      classifier: "pii.email",
      confidence: 1,
      sampled: 200,
      matched: 150,
    };
    const body = { batch_id: uuidv7(), job_id: jobs[0]?.job_id, classifiers_version: "2026.09.1", findings: [kunden] };
    expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
    const event = {
      target_id: "pg-prod-1",
      ts: "2026-09-27T11:05:00.000Z",
      principal: { db_user: "backup" },
      action: "read",
      objects: [{ database: "crm", schema: "public", object: "kunden" }],
      rows: 99,
      signals: [],
      source: "pgaudit",
      aggregated_count: 1,
    };
    expect((await handleEvents(agentRequest("POST", "/events", { auth, body: { batch_id: uuidv7(), events: [event] } }))).status).toBe(202);
    await drainPolicyWork(getDb());
    const [row] = await getDb().select().from(accessEvents).where(eq(accessEvents.agentId, auth.agentId));
    expect(row?.sensitivity).toBe(3);
  });
});
