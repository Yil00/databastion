import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { auditLog, findings, findingsBatches, jobs, securityEvents } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import {
  canonicalJson,
  findingLocationKey,
  LATE_BATCH_RETENTION_MS,
  listFindings,
  MAX_FINDINGS_PER_JOB,
  MAX_LISTED_FINDINGS,
  MAX_SUMMARY_GROUPS,
  setFalsePositive,
  summarizeFindings,
} from "@/server/findings";
import { SCAN_GRACE_MS } from "@/server/scans";
import { integrityStats, integrityWriteBudget } from "@/server/integrity";
import { enqueueJob } from "@/server/jobs";
import { decryptMaskedSamples, encryptMaskedSamples, maskedSamplesKey } from "@/server/samples";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, expectConformingError, fixtures, uuidv7 } from "@/test/helpers";

import { failuresPerAgent } from "./auth";
import { findingsPerAgent, findingsRequestsPerAgent, handleFindings, handleHeartbeat, handlePollJobs } from "./handlers";

// The real registry plus a second, test-only classifier set sharing `pii.email` with 2026.09.1.
vi.mock("@/generated/protocol/classifiers.gen", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/generated/protocol/classifiers.gen")>();
  return { CLASSIFIER_REGISTRY: { ...real.CLASSIFIER_REGISTRY, "2099.01.1": ["pii.email", "pii.test_only"] } };
});
const TEST_VERSION = "2099.01.1";

type Auth = { agentId: string; secret: string };
type Body = Record<string, unknown> & { findings: Record<string, unknown>[] };

const HEARTBEAT = {
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 12,
  classifiers_version: "2026.09.1",
  connectors: ["postgres", "mysql", "mongodb", "openldap"],
  targets: [
    { target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "limited" },
    { target_id: "pg-other", engine: "postgres", reachable: true, audit_level: "limited" },
    { target_id: "mysql-crm", engine: "mysql", reachable: true, audit_level: "partial" },
    { target_id: "mongo-app", engine: "mongodb", reachable: true, audit_level: "limited" },
    { target_id: "ldap-main", engine: "openldap", reachable: true, audit_level: "full" },
  ],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

const PG_FINDING = {
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "email" },
  classifier: "pii.email",
  confidence: 0.97,
  sampled: 200,
  matched: 194,
  estimated_rows: 1250000,
  masked_samples: ["j*******@e******.com", "m****@e******.org"],
  fingerprints: ["hmac-sha256:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"],
};

/** Enrolled agent with its targets reported (heartbeat). */
async function agentWithTargets(): Promise<Auth> {
  const auth = await enroll();
  const res = await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }));
  expect(res.status).toBe(200);
  return auth;
}

/** A `discovery.scan` job for `targetId`, delivered to the agent through `GET /jobs`. */
async function deliveredScan(
  auth: Auth,
  targetId = "pg-prod-1",
  params: Record<string, unknown> = {},
  classifiersVersion = "2026.09.1",
): Promise<string> {
  const id = await enqueueJob(getDb(), {
    agentId: auth.agentId,
    type: "discovery.scan",
    targetId,
    classifiersVersion,
    params: { sample_rows: 200, max_duration_s: 900, ...params },
  });
  const res = await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }));
  expect(res.status).toBe(200);
  return id;
}

const batch = (jobId: string, items: Record<string, unknown>[] = [PG_FINDING]): Body => ({
  batch_id: uuidv7(),
  job_id: jobId,
  classifiers_version: "2026.09.1",
  findings: items,
});

const post = (auth: Auth, body: unknown) => handleFindings(agentRequest("POST", "/findings", { auth, body }));

async function integrityRows(agentId: string, kind: string) {
  const events = await getDb()
    .select()
    .from(securityEvents)
    .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, kind)));
  const audits = await getDb()
    .select()
    .from(auditLog)
    .where(and(eq(auditLog.actorId, agentId), eq(auditLog.action, kind)));
  return { events, audits };
}

async function databaseDump(): Promise<string> {
  const res = await getDb().execute(sql`
    select coalesce(string_agg(t, ' '), '') as s from (
      select row_to_json(f)::text as t from findings f
      union all select encode(masked_samples, 'escape') from findings where masked_samples is not null
      union all select row_to_json(b)::text from findings_batches b
      union all select row_to_json(l)::text from audit_log l
      union all select row_to_json(e)::text from security_events e
      union all select row_to_json(j)::text from jobs j) x`);
  return String(res.rows[0]?.s);
}

describe.skipIf(!hasDb)("POST /findings (PostgreSQL)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => teardown?.());
  beforeEach(() => {
    failuresPerAgent.clear();
    integrityWriteBudget.clear();
    findingsPerAgent.clear();
    findingsRequestsPerAgent.clear();
  });

  describe("contract fixtures", () => {
    it.each(fixtures("valid", "FindingsBatch"))("valid fixture %s -> 202 and stored", async (_f, fixture) => {
      const auth = await agentWithTargets();
      const body = structuredClone(fixture) as Body;
      const target = String(body.findings[0]?.target_id);
      body.job_id = await deliveredScan(auth, target);
      body.batch_id = uuidv7();
      const res = await post(auth, body);
      expect(res.status).toBe(202);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const ack = (await res.json()) as Record<string, unknown>;
      expect(validateSchema("BatchAck", ack).ok).toBe(true);
      expect(ack).toEqual({ batch_id: body.batch_id, duplicate: false });
      const rows = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(rows).toHaveLength(body.findings.length);
      for (const row of rows) expect(row.firstJobId).toBe(body.job_id);
    });

    it.each(fixtures("invalid", "FindingsBatch"))(
      "invalid fixture %s -> 400, nothing stored, integrity event recorded",
      async (_f, fixture) => {
        const auth = await agentWithTargets();
        const jobId = await deliveredScan(auth);
        const body = structuredClone(fixture) as Record<string, unknown>;
        if ("job_id" in body) body.job_id = jobId;
        const res = await post(auth, body);
        expect(res.status).toBe(400);
        const err = await expectConformingError(res, body);
        expect(err.code).toBe("invalid_request");
        expect(Array.isArray(err.details)).toBe(true);
        expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
        const { events, audits } = await integrityRows(auth.agentId, "agent.batch_rejected");
        expect(events).toHaveLength(1);
        expect(events[0]?.severity).toBe("high");
        expect(audits).toHaveLength(1);
        expect(audits[0]?.outcome).toBe("failure");
        // Integrity rows never carry submitted values.
        expect(JSON.stringify([events, audits])).not.toMatch(/\*\*\*|hmac-sha256|@/);
      },
    );

    it("rejects the 50 % mask rule (checkSemantics after validateSchema)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      // Schema-valid (no run > 4) but only 4 of 12 counted characters are `*`.
      const res = await post(auth, batch(jobId, [{ ...PG_FINDING, masked_samples: ["ab*c.de*f.gh**"] }]));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, {});
      expect(err.details).toEqual([{ pointer: "/findings/0/masked_samples/0", keyword: "maskRatio" }]);
    });

    it("rejects bodies over 4 MiB with 413, without an integrity event", async () => {
      const auth = await agentWithTargets();
      const res = await handleFindings(
        agentRequest("POST", "/findings", { auth, raw: `{"x":"${"a".repeat(4 * 1024 * 1024)}"}` }),
      );
      expect(res.status).toBe(413);
      expect((await expectConformingError(res, {})).code).toBe("payload_too_large");
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(0);
    });

    it("rejects a batch over the 1 MiB contract size (maxBytes) with 400", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const fp = (i: number) => `hmac-sha256:${i.toString(16).padStart(64, "0")}`;
      const items = Array.from({ length: 200 }, (_, i) => ({
        ...PG_FINDING,
        location: {
          ...PG_FINDING.location,
          database: "d".repeat(250),
          schema: "s".repeat(250),
          object: "o".repeat(250),
          field: `f${i}`.padEnd(250, "x"),
        },
        fingerprints: Array.from({ length: 50 }, (_, j) => fp(i * 100 + j)),
        masked_samples: Array.from({ length: 5 }, () => "*".repeat(120)),
      }));
      const body = batch(jobId, items);
      expect(JSON.stringify(body).length).toBeGreaterThan(1024 * 1024);
      const res = await post(auth, body);
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "", keyword: "maxBytes" }]);
    });

    it("requires authentication", async () => {
      const res = await handleFindings(agentRequest("POST", "/findings", { body: batch(uuidv7()) }));
      expect(res.status).toBe(401);
    });
  });

  describe("idempotency on (agent_id, batch_id)", () => {
    it("acknowledges a same-content replay as a duplicate without processing it again", async () => {
      const auth = await agentWithTargets();
      const body = batch(await deliveredScan(auth));
      expect((await post(auth, body)).status).toBe(202);
      const [before] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      await new Promise((r) => setTimeout(r, 20));
      // Re-serialized with other whitespace: same content.
      const res = await handleFindings(
        agentRequest("POST", "/findings", { auth, raw: JSON.stringify(body, null, 2) }),
      );
      expect(res.status).toBe(202);
      expect(await res.json()).toEqual({ batch_id: body.batch_id, duplicate: true });
      const [after] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(after?.lastSeenAt.getTime()).toBe(before?.lastSeenAt.getTime());
      expect(after?.maskedSamples?.equals(before?.maskedSamples ?? Buffer.alloc(0))).toBe(true);
      const batches = await getDb().select().from(findingsBatches).where(eq(findingsBatches.agentId, auth.agentId));
      expect(batches).toHaveLength(1);
      expect(batches[0]?.bodySha256).toMatch(/^[0-9a-f]{64}$/);
    });

    it("answers 409 batch_conflict for other content under the same batch_id, with an integrity event", async () => {
      const auth = await agentWithTargets();
      const body = batch(await deliveredScan(auth));
      expect((await post(auth, body)).status).toBe(202);
      const changed = { ...body, findings: [{ ...PG_FINDING, matched: 10 }] };
      const res = await post(auth, changed);
      expect(res.status).toBe(409);
      expect((await expectConformingError(res, changed)).code).toBe("batch_conflict");
      const [row] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(row?.matched).toBe(194);
      const { events, audits } = await integrityRows(auth.agentId, "agent.batch_conflict");
      expect(events).toHaveLength(1);
      expect(audits).toHaveLength(1);
    });

    it("hashes canonical JSON: a replay with other key order is a duplicate (L6)", async () => {
      const auth = await agentWithTargets();
      const body = batch(await deliveredScan(auth));
      expect((await post(auth, body)).status).toBe(202);
      const reordered = {
        findings: body.findings.map((f) => Object.fromEntries(Object.entries(f).reverse())),
        classifiers_version: body.classifiers_version,
        job_id: body.job_id,
        batch_id: body.batch_id,
      };
      const res = await post(auth, reordered);
      expect(res.status).toBe(202);
      expect(((await res.json()) as { duplicate: boolean }).duplicate).toBe(true);
      expect(canonicalJson({ b: [{ d: 1, c: 2 }], a: null })).toBe('{"a":null,"b":[{"c":2,"d":1}]}');
    });

    it("scopes batch ids per agent", async () => {
      const a = await agentWithTargets();
      const b = await agentWithTargets();
      const body = batch(await deliveredScan(a));
      expect((await post(a, body)).status).toBe(202);
      const other = { ...body, job_id: await deliveredScan(b) };
      const res = await post(b, other);
      expect(res.status).toBe(202);
      expect(((await res.json()) as { duplicate: boolean }).duplicate).toBe(false);
    });

    it("serializes concurrent submissions of the same batch: one stored, the other a duplicate", async () => {
      const auth = await agentWithTargets();
      const body = batch(await deliveredScan(auth));
      const results = await Promise.all([post(auth, body), post(auth, body), post(auth, body)]);
      expect(results.map((r) => r.status)).toEqual([202, 202, 202]);
      const acks = (await Promise.all(results.map((r) => r.json()))) as { duplicate: boolean }[];
      expect(acks.filter((a) => !a.duplicate)).toHaveLength(1);
    });
  });

  describe("cross-field checks", () => {
    it("404 /job_id: unknown job, another agent's job, not a scan, never delivered; no integrity event", async () => {
      const auth = await agentWithTargets();
      const other = await agentWithTargets();
      const foreignJob = await deliveredScan(other);
      const reload = await enqueueJob(getDb(), { agentId: auth.agentId, type: "agent.config.reload", params: {} });
      const pending = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "discovery.scan",
        targetId: "pg-other",
        classifiersVersion: "2026.09.1",
        params: { sample_rows: 200, max_duration_s: 900 },
      });
      for (const jobId of [uuidv7(), foreignJob, reload, pending]) {
        const res = await post(auth, batch(jobId));
        expect(res.status).toBe(404);
        const err = await expectConformingError(res, {});
        expect(err.code).toBe("not_found");
        expect(err.details).toEqual([{ pointer: "/job_id", keyword: "notFound" }]);
      }
      const cancelled = await deliveredScan(auth);
      await getDb().update(jobs).set({ status: "cancelled" }).where(eq(jobs.id, cancelled));
      expect((await post(auth, batch(cancelled))).status).toBe(404);
      expect((await integrityRows(auth.agentId, "agent.foreign_target")).events).toHaveLength(0);
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(0);
    });

    it("accepts findings of a running or finished scan (spooled batches may arrive late)", async () => {
      const auth = await agentWithTargets();
      for (const status of ["running", "succeeded", "failed"] as const) {
        const jobId = await deliveredScan(auth);
        // Terminal statuses always carry finished_at (recordJobStatus).
        const finishedAt = status === "running" ? null : new Date();
        await getDb().update(jobs).set({ status, finishedAt }).where(eq(jobs.id, jobId));
        expect((await post(auth, batch(jobId))).status).toBe(202);
      }
    });

    it("404 with item pointers for a target the agent never reported, recorded as an integrity event", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const res = await post(auth, batch(jobId, [PG_FINDING, { ...PG_FINDING, target_id: "someone-elses-db" }]));
      expect(res.status).toBe(404);
      const err = await expectConformingError(res, {});
      expect(err.details).toEqual([{ pointer: "/findings/1/target_id", keyword: "notFound" }]);
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
      const { events, audits } = await integrityRows(auth.agentId, "agent.foreign_target");
      expect(events).toHaveLength(1);
      expect(events[0]?.details).toMatchObject({ endpoint: "findings", status: 404, pointer: "/findings/1/target_id" });
      expect(audits).toHaveLength(1);
    });

    it("rejects findings sent through a scan job of another target of the same agent (L7)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth, "pg-other");
      const res = await post(auth, batch(jobId, [PG_FINDING]));
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "/findings/0/target_id", keyword: "const" }]);
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
    });

    it("rejects a batch whose registered classifiers_version differs from the job's (L1: const)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const res = await post(auth, { ...batch(jobId), classifiers_version: TEST_VERSION });
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "/classifiers_version", keyword: "const" }]);
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(1);
    });

    it("rejects a batch whose classifiers_version is not in the registry (enum, before const)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const res = await post(auth, { ...batch(jobId), classifiers_version: "2026.10.1" });
      expect(res.status).toBe(400);
      // No item pointer: the whole batch is dropped, whatever its classifier ids.
      expect((await expectConformingError(res, {})).details).toEqual([
        { pointer: "/classifiers_version", keyword: "enum" },
        { pointer: "/classifiers_version", keyword: "const" },
      ]);
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(1);
    });

    it("rejects, item by item, classifier ids not registered for the batch's version (enum)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const items = [
        { ...PG_FINDING, classifier: "pii.unknown" },
        // Valid in another registered version, not in 2026.09.1.
        { ...PG_FINDING, classifier: "pii.test_only" },
        // Prototype-like ids (schema-valid): never "registered" through a prototype lookup.
        { ...PG_FINDING, classifier: "x.__proto__" },
        { ...PG_FINDING, classifier: "x.constructor" },
        { ...PG_FINDING, classifier: "pii.phone" },
        { ...PG_FINDING, classifier: "secret.password_hash" },
      ];
      const res = await post(auth, batch(jobId, items));
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([
        { pointer: "/findings/0/classifier", keyword: "enum" },
        { pointer: "/findings/1/classifier", keyword: "enum" },
        { pointer: "/findings/2/classifier", keyword: "enum" },
        { pointer: "/findings/3/classifier", keyword: "enum" },
      ]);
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
      // The agent drops the pointed items and resends the rest.
      expect((await post(auth, batch(jobId, items.slice(4)))).status).toBe(202);
    });

    it("checks the ids against the batch's own version: a 2026.09.1 id is refused in a test-version job", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth, "pg-prod-1", {}, TEST_VERSION);
      const items = [
        { ...PG_FINDING, classifier: "pii.phone" },
        { ...PG_FINDING, classifier: "pii.test_only" },
        { ...PG_FINDING, classifier: "pii.email", location: { ...PG_FINDING.location, field: "mail2" } },
      ];
      const res = await post(auth, { ...batch(jobId, items), classifiers_version: TEST_VERSION });
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "/findings/0/classifier", keyword: "enum" }]);
      const retry = await post(auth, { ...batch(jobId, items.slice(1)), classifiers_version: TEST_VERSION });
      expect(retry.status).toBe(202);
    });

    it("a target of another agent is foreign too", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const other = await enroll();
      await handleHeartbeat(
        agentRequest("POST", "/heartbeat", {
          auth: other,
          body: { ...HEARTBEAT, targets: [{ target_id: "only-theirs", engine: "postgres", reachable: true, audit_level: "none" }] },
        }),
      );
      const res = await post(auth, batch(jobId, [{ ...PG_FINDING, target_id: "only-theirs" }]));
      expect(res.status).toBe(404);
    });

    it("400 with item pointers: counts, sample_rows, engine, job target, job classifiers", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth, "pg-prod-1", { sample_rows: 100, classifiers: ["pii.email"] });
      const items = [
        { ...PG_FINDING, sampled: 100, matched: 101 },
        { ...PG_FINDING, sampled: 150, matched: 1 },
        { ...PG_FINDING, sampled: 100, matched: 1, location: { ...PG_FINDING.location, engine: "mysql" } },
        { ...PG_FINDING, sampled: 100, matched: 1, target_id: "pg-other" },
        { ...PG_FINDING, sampled: 100, matched: 1, classifier: "pii.iban" },
        { ...PG_FINDING, sampled: 100, matched: 100 },
      ];
      const res = await post(auth, batch(jobId, items));
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, {});
      expect(err.details).toEqual([
        { pointer: "/findings/0/matched", keyword: "maximum" },
        { pointer: "/findings/1/sampled", keyword: "maximum" },
        { pointer: "/findings/2/location/engine", keyword: "const" },
        { pointer: "/findings/3/target_id", keyword: "const" },
        { pointer: "/findings/4/classifier", keyword: "enum" },
      ]);
      expect(await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId))).toHaveLength(0);
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(1);
      // The agent drops the pointed items and resends the rest under a new batch_id.
      const retry = await post(auth, batch(jobId, [items[5] as Record<string, unknown>]));
      expect(retry.status).toBe(202);
    });

    it("bounds integrity writes per agent; beyond the budget events are only counted", async () => {
      const auth = await agentWithTargets();
      const before = integrityStats.suppressed;
      for (let i = 0; i < integrityWriteBudget.limit + 5; i++) {
        expect((await post(auth, { batch_id: "nope" })).status).toBe(400);
      }
      const { events } = await integrityRows(auth.agentId, "agent.batch_rejected");
      expect(events).toHaveLength(integrityWriteBudget.limit);
      expect(integrityStats.suppressed - before).toBe(5);
      // L5: the next recorded event carries the number suppressed in between.
      integrityWriteBudget.clear();
      expect((await post(auth, { batch_id: "nope" })).status).toBe(400);
      const after = await integrityRows(auth.agentId, "agent.batch_rejected");
      const latest = after.events.sort((a, b) => b.at.getTime() - a.at.getTime())[0];
      expect(latest?.details).toMatchObject({ suppressed_before: 5 });
    });
  });

  describe("M1: time box, per-job cap, rate limit", () => {
    const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000);

    it("refuses late batches of finished scans after the spool-retention bound (404 /job_id)", async () => {
      const auth = await agentWithTargets();
      expect(LATE_BATCH_RETENTION_MS).toBe(24 * 3600_000);
      const recent = await deliveredScan(auth);
      await getDb().update(jobs).set({ status: "succeeded", finishedAt: hoursAgo(23) }).where(eq(jobs.id, recent));
      expect((await post(auth, batch(recent))).status).toBe(202);
      const old = await deliveredScan(auth);
      await getDb().update(jobs).set({ status: "failed", finishedAt: hoursAgo(25) }).where(eq(jobs.id, old));
      const res = await post(auth, batch(old));
      expect(res.status).toBe(404);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "/job_id", keyword: "notFound" }]);
    });

    it("finished scans: a null finished_at closes the window, and the scan's deadline bounds it", async () => {
      const auth = await agentWithTargets();
      // Fail closed on a missing finished_at.
      const noFinish = await deliveredScan(auth);
      await getDb().update(jobs).set({ status: "succeeded", finishedAt: null }).where(eq(jobs.id, noFinish));
      expect((await post(auth, batch(noFinish))).status).toBe(404);
      // A final status sent long after the deadline does not reopen the window: delivered 30 h ago
      // (deadline 30 h - 15 min - 1 h ago), "finished" 1 h ago.
      const stale = await deliveredScan(auth);
      await getDb()
        .update(jobs)
        .set({ status: "succeeded", deliveredAt: hoursAgo(30), firstDeliveredAt: hoursAgo(30), finishedAt: hoursAgo(1) })
        .where(eq(jobs.id, stale));
      expect((await post(auth, batch(stale))).status).toBe(404);
      await getDb().update(jobs).set({ status: "failed" }).where(eq(jobs.id, stale));
      expect((await post(auth, batch(stale))).status).toBe(404);
      // Deadline within the last 24 h: accepted.
      const recent = await deliveredScan(auth);
      await getDb()
        .update(jobs)
        .set({ status: "failed", deliveredAt: hoursAgo(20), firstDeliveredAt: hoursAgo(20), finishedAt: hoursAgo(1) })
        .where(eq(jobs.id, recent));
      expect((await post(auth, batch(recent))).status).toBe(202);
      // A finished job that was never delivered (no delivered_at): closed.
      const undelivered = await deliveredScan(auth);
      await getDb()
        .update(jobs)
        .set({ status: "failed", deliveredAt: null, firstDeliveredAt: null, finishedAt: hoursAgo(1) })
        .where(eq(jobs.id, undelivered));
      expect((await post(auth, batch(undelivered))).status).toBe(404);
    });

    it("refuses batches of a running scan past first_delivered_at + max_duration_s + grace", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth, "pg-prod-1", { max_duration_s: 600 });
      await getDb().update(jobs).set({ status: "running" }).where(eq(jobs.id, jobId));
      const past = new Date(Date.now() - 600_000 - SCAN_GRACE_MS - 60_000);
      const inTime = new Date(past.getTime() + 120_000);
      await getDb().update(jobs).set({ deliveredAt: inTime, firstDeliveredAt: inTime }).where(eq(jobs.id, jobId));
      expect((await post(auth, batch(jobId))).status).toBe(202);
      await getDb().update(jobs).set({ deliveredAt: past, firstDeliveredAt: past }).where(eq(jobs.id, jobId));
      expect((await post(auth, batch(jobId))).status).toBe(404);
    });

    it("anchors the window on the first delivery: a redelivery and a late running ack do not extend it (M1)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth, "pg-prod-1", { max_duration_s: 600 });
      const past = new Date(Date.now() - 600_000 - SCAN_GRACE_MS - 60_000);
      // First delivered past the window, redelivered a minute ago, acknowledged `running` late.
      await getDb()
        .update(jobs)
        .set({ status: "running", firstDeliveredAt: past, deliveredAt: new Date(Date.now() - 60_000), leaseUntil: null })
        .where(eq(jobs.id, jobId));
      expect((await post(auth, batch(jobId))).status).toBe(404);
      // Same redelivery, first delivered within the window: accepted.
      await getDb()
        .update(jobs)
        .set({ firstDeliveredAt: new Date(past.getTime() + 120_000) })
        .where(eq(jobs.id, jobId));
      expect((await post(auth, batch(jobId))).status).toBe(202);
    });

    it("caps the findings of one job: 400 /findings + integrity event beyond the cap", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      await getDb().insert(findingsBatches).values({
        agentId: auth.agentId,
        batchId: uuidv7(),
        bodySha256: "0".repeat(64),
        jobId,
        findingsCount: MAX_FINDINGS_PER_JOB - 1,
      });
      const second = { ...PG_FINDING, location: { ...PG_FINDING.location, field: "phone" } };
      const res = await post(auth, batch(jobId, [PG_FINDING, second]));
      expect(res.status).toBe(400);
      expect((await expectConformingError(res, {})).details).toEqual([{ pointer: "/findings", keyword: "maxItems" }]);
      expect((await integrityRows(auth.agentId, "agent.batch_rejected")).events).toHaveLength(1);
      expect((await post(auth, batch(jobId, [PG_FINDING]))).status).toBe(202);
      expect((await post(auth, batch(jobId, [second]))).status).toBe(400);
    });

    it("rate limits stored batches per agent (429 + Retry-After); duplicates and rejections are free", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const first = batch(jobId);
      expect((await post(auth, first)).status).toBe(202);
      for (let i = 0; i < 5; i++) expect((await post(auth, first)).status).toBe(202);
      expect((await post(auth, batch(jobId, [{ ...PG_FINDING, matched: 999 }]))).status).toBe(400);
      expect(findingsPerAgent.check(auth.agentId).limited).toBe(false);
      for (let i = 1; i < findingsPerAgent.limit; i++) findingsPerAgent.hit(auth.agentId);
      const res = await post(auth, batch(jobId));
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
      expect((await expectConformingError(res, {})).code).toBe("rate_limited");
      // Other agents are not affected.
      const other = await agentWithTargets();
      expect((await post(other, batch(await deliveredScan(other)))).status).toBe(202);
    });

    it("limits every authenticated /findings request per agent (429), rejected and not-found included", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      // Schema-invalid, cross-field-invalid and unknown-job batches all count.
      expect((await post(auth, { ...batch(jobId), extra: 1 })).status).toBe(400);
      expect((await post(auth, batch(jobId, [{ ...PG_FINDING, matched: 999 }]))).status).toBe(400);
      expect((await post(auth, batch(uuidv7()))).status).toBe(404);
      expect(findingsRequestsPerAgent.check(auth.agentId).limited).toBe(false);
      for (let i = 3; i < findingsRequestsPerAgent.limit; i++) findingsRequestsPerAgent.hit(auth.agentId);
      expect(findingsRequestsPerAgent.limit).toBe(300);
      // The stored-batch limiter is untouched, yet the request is refused.
      expect(findingsPerAgent.check(auth.agentId).limited).toBe(false);
      for (const body of [batch(jobId), batch(uuidv7()), { ...batch(jobId), extra: 1 }]) {
        const res = await post(auth, body);
        expect(res.status).toBe(429);
        expect(Number(res.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
        expect((await expectConformingError(res, {})).code).toBe("rate_limited");
      }
      expect(await getDb().select().from(findingsBatches).where(eq(findingsBatches.agentId, auth.agentId))).toHaveLength(0);
      // Unauthenticated requests do not consume an agent's budget; other agents are not affected.
      const other = await agentWithTargets();
      expect((await post(other, batch(await deliveredScan(other)))).status).toBe(202);
    });

    it("summarizes fairly: a noisy agent cannot fill every summary group", async () => {
      const noisy = await agentWithTargets();
      const quiet = await agentWithTargets();
      // MAX_SUMMARY_GROUPS + 20 groups for the noisy agent (distinct classifiers on one target).
      await getDb().execute(sql`
        insert into findings (id, agent_id, target_id, location_key, engine, database_name, object_name,
          field_name, classifier, classifiers_version, confidence, sampled, matched, last_batch_id, last_seen_at)
        select gen_random_uuid(), ${noisy.agentId}, 'pg-prod-1', md5(g::text) || md5(g::text), 'postgres', 'a',
          'o', 'f', 'custom.c' || g, '2026.09.1', 0.5, 10, 5, gen_random_uuid(), now()
        from generate_series(1, ${MAX_SUMMARY_GROUPS + 20}) g`);
      expect((await post(quiet, batch(await deliveredScan(quiet)))).status).toBe(202);
      const other = { ...PG_FINDING, target_id: "pg-other" };
      expect((await post(quiet, batch(await deliveredScan(quiet, "pg-other"), [other]))).status).toBe(202);
      await getDb().execute(sql`update findings set last_seen_at = now() - interval '1 day' where agent_id = ${quiet.agentId}`);
      const summary = await summarizeFindings(getDb());
      expect(summary).toHaveLength(MAX_SUMMARY_GROUPS);
      const quietGroups = summary.filter((g) => g.agentId === quiet.agentId);
      expect(quietGroups.map((g) => g.targetId).sort()).toEqual(["pg-other", "pg-prod-1"]);
      expect(quietGroups.every((g) => g.findings === 1 && g.classifier === "pii.email")).toBe(true);
      // Stable reading order.
      const keys = summary.map((g) => `${g.agentName}\0${g.agentId}\0${g.targetId}\0${g.classifier}`);
      expect(keys).toEqual([...keys].sort());
    });

    it("lists findings fairly: a noisy target cannot hide the others", async () => {
      const noisy = await agentWithTargets();
      const quiet = await agentWithTargets();
      await getDb().execute(sql`
        insert into findings (id, agent_id, target_id, location_key, engine, database_name, object_name,
          field_name, classifier, classifiers_version, confidence, sampled, matched, last_batch_id, last_seen_at)
        select gen_random_uuid(), ${noisy.agentId}, 'pg-prod-1', md5(g::text) || md5(g::text), 'postgres', 'a',
          'o', 'f' || g, 'pii.email', '2026.09.1', 0.5, 10, 5, gen_random_uuid(), now()
        from generate_series(1, ${MAX_LISTED_FINDINGS + 20}) g`);
      expect((await post(quiet, batch(await deliveredScan(quiet)))).status).toBe(202);
      await getDb().execute(sql`update findings set last_seen_at = now() - interval '1 day' where agent_id = ${quiet.agentId}`);
      const view = await listFindings(getDb());
      expect(view).toHaveLength(MAX_LISTED_FINDINGS);
      expect(view.some((f) => f.agentId === quiet.agentId)).toBe(true);
    });
  });

  describe("M2: false-positive reset on rescan", () => {
    async function markedFinding() {
      const auth = await agentWithTargets();
      const first = await deliveredScan(auth);
      expect((await post(auth, batch(first, [{ ...PG_FINDING, matched: 100 }]))).status).toBe(202);
      await getDb().update(jobs).set({ status: "succeeded" }).where(eq(jobs.id, first));
      const [row] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      const userId = await adminUser();
      expect(await setFalsePositive(getDb(), String(row?.id), true, { userId, ip: null })).toBe(true);
      const [marked] = await getDb().select().from(findings).where(eq(findings.id, String(row?.id)));
      expect(marked?.falsePositiveMatched).toBe(100);
      expect(marked?.falsePositiveClassifiersVersion).toBe("2026.09.1");
      return { auth, id: String(row?.id) };
    }
    const resets = (id: string) =>
      getDb()
        .select()
        .from(auditLog)
        .where(and(eq(auditLog.action, "finding.false_positive_reset"), eq(auditLog.targetId, id)));

    it("keeps the mark while matched does not rise, resets (audited) when it does", async () => {
      const { auth, id } = await markedFinding();
      const again = await deliveredScan(auth);
      expect((await post(auth, batch(again, [{ ...PG_FINDING, matched: 90 }]))).status).toBe(202);
      let [row] = await getDb().select().from(findings).where(eq(findings.id, id));
      expect(row?.falsePositiveAt).not.toBeNull();
      expect(await resets(id)).toHaveLength(0);
      expect((await post(auth, batch(again, [{ ...PG_FINDING, matched: 101 }]))).status).toBe(202);
      [row] = await getDb().select().from(findings).where(eq(findings.id, id));
      expect(row?.falsePositiveAt).toBeNull();
      expect(row?.falsePositiveBy).toBeNull();
      expect(row?.falsePositiveMatched).toBeNull();
      const audit = await resets(id);
      expect(audit).toHaveLength(1);
      expect(audit[0]?.actorType).toBe("system");
      expect(audit[0]?.details).toMatchObject({ agent_id: auth.agentId, target_id: "pg-prod-1", classifier: "pii.email", reason: "matched_increased" });
    });

    it("resets when the classifier set changes", async () => {
      const { auth, id } = await markedFinding();
      const next = await deliveredScan(auth, "pg-prod-1", {}, TEST_VERSION);
      const res = await post(auth, { ...batch(next, [{ ...PG_FINDING, matched: 50 }]), classifiers_version: TEST_VERSION });
      expect(res.status).toBe(202);
      const [row] = await getDb().select().from(findings).where(eq(findings.id, id));
      expect(row?.falsePositiveAt).toBeNull();
      expect((await resets(id))[0]?.details).toMatchObject({ reason: "classifiers_version" });
    });
  });

  describe("storage", () => {
    it("upserts by location + classifier, keeps the id, first-seen data and false-positive decision", async () => {
      const auth = await agentWithTargets();
      const first = await deliveredScan(auth);
      expect((await post(auth, batch(first))).status).toBe(202);
      const [a] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      await getDb().update(findings).set({ falsePositiveAt: new Date() }).where(eq(findings.id, String(a?.id)));
      await getDb().update(jobs).set({ status: "succeeded" }).where(eq(jobs.id, first));
      const second = await deliveredScan(auth);
      const res = await post(auth, batch(second, [{ ...PG_FINDING, matched: 150, masked_samples: ["x****@e******.com"] }]));
      expect(res.status).toBe(202);
      const rows = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(rows).toHaveLength(1);
      const b = rows[0];
      expect(b?.id).toBe(a?.id);
      expect(b?.matched).toBe(150);
      expect(b?.firstJobId).toBe(first);
      expect(b?.lastJobId).toBe(second);
      expect(b?.firstSeenAt.getTime()).toBe(a?.firstSeenAt.getTime());
      expect(b?.falsePositiveAt).not.toBeNull();
      expect(b?.locationKey).toBe(findingLocationKey(PG_FINDING as Parameters<typeof findingLocationKey>[0]));
      const key = maskedSamplesKey();
      expect(decryptMaskedSamples(key as Buffer, String(b?.id), b?.maskedSamples as Buffer)).toEqual(["x****@e******.com"]);
    });

    it("keeps one row per location when a batch repeats it (last item wins)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      expect((await post(auth, batch(jobId, [PG_FINDING, { ...PG_FINDING, matched: 3 }]))).status).toBe(202);
      const rows = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(rows.map((r) => r.matched)).toEqual([3]);
    });
  });

  describe("masked samples at rest (AES-256-GCM)", () => {
    it("stores no plaintext sample; the right key decrypts, a wrong key or another finding id does not", async () => {
      const auth = await agentWithTargets();
      const samples = ["q******@z******.io", "w*****@y*****.fr"];
      const jobId = await deliveredScan(auth);
      expect((await post(auth, batch(jobId, [{ ...PG_FINDING, masked_samples: samples }]))).status).toBe(202);
      const [row] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      const blob = row?.maskedSamples as Buffer;
      expect(blob[0]).toBe(1);
      // 1 version byte + 12 nonce + ciphertext + 16 tag.
      expect(blob.length).toBeGreaterThan(29);
      const dump = await databaseDump();
      for (const s of samples) expect(dump).not.toContain(s);
      // The raw bytes do not contain the plaintext either.
      for (const s of samples) expect(blob.includes(Buffer.from(s))).toBe(false);
      // Fingerprints are stored as given (keyed by the agent-local key).
      expect(row?.fingerprints).toEqual(PG_FINDING.fingerprints);

      const key = maskedSamplesKey() as Buffer;
      expect(decryptMaskedSamples(key, String(row?.id), blob)).toEqual(samples);
      const wrong = maskedSamplesKey({ DATABASTION_ENCRYPTION_KEY: "another-server-key-0123456789abcdefghijkl" }) as Buffer;
      expect(wrong.equals(key)).toBe(false);
      expect(decryptMaskedSamples(wrong, String(row?.id), blob)).toBeNull();
      expect(decryptMaskedSamples(key, uuidv7(), blob)).toBeNull();
      const tampered = Buffer.from(blob);
      tampered[20] = (tampered[20] ?? 0) ^ 1;
      expect(decryptMaskedSamples(key, String(row?.id), tampered)).toBeNull();

      const view = await listFindings(getDb(), { agentId: auth.agentId });
      expect(view[0]?.samples).toEqual({ state: "ok", values: samples });
    });

    it("uses a fresh nonce for every encryption", () => {
      const key = maskedSamplesKey() as Buffer;
      const a = encryptMaskedSamples(key, "id", ["a***"]);
      const b = encryptMaskedSamples(key, "id", ["a***"]);
      expect(a.subarray(1, 13).equals(b.subarray(1, 13))).toBe(false);
    });

    it("the view shows samples as unavailable when the key changed", async () => {
      const auth = await agentWithTargets();
      expect((await post(auth, batch(await deliveredScan(auth)))).status).toBe(202);
      const saved = process.env.DATABASTION_ENCRYPTION_KEY;
      process.env.DATABASTION_ENCRYPTION_KEY = "rotated-server-key-0123456789abcdefghijklmn";
      try {
        const view = await listFindings(getDb(), { agentId: auth.agentId });
        expect(view[0]?.samples).toEqual({ state: "unavailable" });
      } finally {
        process.env.DATABASTION_ENCRYPTION_KEY = saved;
      }
    });

    it("without the server key: the finding is stored, its samples are not (fail closed)", async () => {
      const auth = await agentWithTargets();
      const jobId = await deliveredScan(auth);
      const saved = process.env.DATABASTION_ENCRYPTION_KEY;
      delete process.env.DATABASTION_ENCRYPTION_KEY;
      try {
        expect(maskedSamplesKey()).toBeNull();
        expect((await post(auth, batch(jobId))).status).toBe(202);
      } finally {
        process.env.DATABASTION_ENCRYPTION_KEY = saved;
      }
      const [row] = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
      expect(row).toBeDefined();
      expect(row?.maskedSamples).toBeNull();
      expect(row?.matched).toBe(194);
      const view = await listFindings(getDb(), { agentId: auth.agentId });
      expect(view[0]?.samples).toEqual({ state: "none" });
    });
  });
});
