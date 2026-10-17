import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents } from "@/db/schema";
import { handleEvents, handleFindings, handleHeartbeat, handlePollJobs } from "@/server/agent-api/handlers";
import { enqueueJob } from "@/server/jobs";
import { hasDb, setupTestDatabase } from "@/test/db";
import { agentRequest, enroll, uuidv7 } from "@/test/helpers";

import { prefilterNames } from "./event-engine";
import { drainPolicyWork } from "./incidents";

/**
 * Security review L1 of the N1 change: under a `C` / `POSIX` character type, PostgreSQL `lower`
 * folds ASCII only, so the sensitivity lookup drops its name pre-filter when a name holds another
 * character and lets `objectKey` (JavaScript `foldName`) decide.
 */
describe("sensitivity name pre-filter (pure)", () => {
  it("keeps every name and its fold; none under an ASCII-only `lower` with a non-ASCII name", () => {
    expect(prefilterNames(["CLIENTS ", "orders"], true)).toEqual(["CLIENTS ", "clients", "orders"]);
    expect(prefilterNames(["CLIENTS ", "orders"], false)).toEqual(["CLIENTS ", "clients", "orders"]);
    expect(prefilterNames(["ΠΕΛΑΤΕΣ"], true)).toEqual(["ΠΕΛΑΤΕΣ", "πελατεσ"]);
    expect(prefilterNames(["clients", "CLIENTÈLE"], false)).toBeNull();
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
});
