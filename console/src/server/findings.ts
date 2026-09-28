import { randomUUID } from "node:crypto";

import { and, asc, eq, inArray, isNull, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, findings, findingsBatches, jobs } from "@/db/schema";
import { MAX_VALIDATION_DETAILS, type Schemas, type ValidationDetail } from "@/lib/protocol/validate";

import type { FindingFilter } from "@/lib/findings-filter";

import { writeAudit } from "./audit";
import { sha256Hex } from "./crypto";
import { decryptMaskedSamples, encryptMaskedSamples, maskedSamplesKey } from "./samples";

/**
 * Discovery findings (P2-D): ingestion of `POST /findings` batches, the findings view and
 * false-positive marking. Never logs a masked sample or a fingerprint.
 */

type FindingsBatch = Schemas["FindingsBatch"];
type Finding = Schemas["Finding"];

/**
 * Job statuses under which findings of a `discovery.scan` job are accepted: the job was delivered
 * to the agent. `delivered` because the first batch may overtake the `running` status update, and
 * the terminal ones because spooled batches may arrive after the final status (both requests are
 * retried independently by the agent). `pending` (never delivered), `expired` (never started) and
 * `cancelled` (revocation / lock) are refused (`404`, like an unknown job).
 */
export const FINDINGS_JOB_STATUSES = ["delivered", "running", "succeeded", "failed"] as const;

/** SHA-256 of the validated batch serialized as JSON (idempotency on `(agent_id, batch_id)`). */
export function batchSha256(batch: FindingsBatch): string {
  return sha256Hex(JSON.stringify(batch));
}

/** Identity of a finding within an agent: target, location (engine excluded) and classifier. */
export function findingLocationKey(f: Pick<Finding, "target_id" | "location" | "classifier">): string {
  const l = f.location;
  return sha256Hex(JSON.stringify([f.target_id, l.database, l.schema ?? null, l.object, l.field, f.classifier]));
}

export type IngestOutcome =
  | { kind: "accepted"; duplicate: boolean }
  | { kind: "batch_conflict" }
  /** Unknown job, job of another agent, not a delivered `discovery.scan` job: pointer `/job_id`. */
  | { kind: "job_not_found"; details: ValidationDetail[] }
  /** `target_id` not reported by this agent: pointers `/findings/<i>/target_id`. */
  | { kind: "foreign_target"; details: ValidationDetail[] }
  /** Console-side cross-field checks (contract "Console-side checks not expressible..."). */
  | { kind: "invalid"; details: ValidationDetail[] };

interface JobRow {
  id: string;
  type: string;
  status: string;
  targetId: string | null;
  params: Record<string, unknown>;
}

function jobSampleRows(params: Record<string, unknown>): number {
  const v = params.sample_rows;
  return typeof v === "number" && Number.isInteger(v) ? v : 0;
}

function jobClassifiers(params: Record<string, unknown>): Set<string> | null {
  const v = params.classifiers;
  return Array.isArray(v) ? new Set(v.filter((c): c is string => typeof c === "string")) : null;
}

/**
 * Cross-field checks of a schema- and semantics-valid batch against the job and the targets
 * reported by the agent. Pointers designate items (`/findings/<i>/...`) so that the agent can drop
 * them and resend the rest under a new `batch_id`.
 */
function crossFieldDetails(
  batch: FindingsBatch,
  job: JobRow,
  engines: ReadonlyMap<string, string>,
): ValidationDetail[] {
  const details: ValidationDetail[] = [];
  const push = (d: ValidationDetail) => {
    if (details.length < MAX_VALIDATION_DETAILS) details.push(d);
  };
  const sampleRows = jobSampleRows(job.params);
  const allowed = jobClassifiers(job.params);
  batch.findings.forEach((f, i) => {
    // A scan job covers one target: its findings are about that target only.
    if (f.target_id !== job.targetId) push({ pointer: `/findings/${i}/target_id`, keyword: "const" });
    if (engines.get(f.target_id) !== f.location.engine) {
      push({ pointer: `/findings/${i}/location/engine`, keyword: "const" });
    }
    if (f.matched > f.sampled) push({ pointer: `/findings/${i}/matched`, keyword: "maximum" });
    if (f.sampled > sampleRows) push({ pointer: `/findings/${i}/sampled`, keyword: "maximum" });
    if (allowed && !allowed.has(f.classifier)) push({ pointer: `/findings/${i}/classifier`, keyword: "enum" });
  });
  return details;
}

/**
 * Ingests a validated findings batch of `agentId`, atomically:
 * 1. idempotency on `(agent_id, batch_id)`: same content -> duplicate, other content -> conflict;
 * 2. `job_id` is a delivered `discovery.scan` job of the agent (`404` `/job_id` otherwise);
 * 3. every `target_id` was reported by the agent (`404`, item pointers);
 * 4. cross-field checks (`400`, item pointers);
 * 5. upsert of the findings (masked samples encrypted, see `samples.ts`) + the batch record.
 * Batches of one agent are serialized (transaction-scoped advisory lock), so the finding id bound
 * into the samples' AAD is always the id of the stored row.
 */
export async function ingestFindings(db: Database, agentId: string, batch: FindingsBatch): Promise<IngestOutcome> {
  const bodySha256 = batchSha256(batch);
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`findings:${agentId}`}, 0))`);
    const [previous] = await tx
      .select({ bodySha256: findingsBatches.bodySha256 })
      .from(findingsBatches)
      .where(and(eq(findingsBatches.agentId, agentId), eq(findingsBatches.batchId, batch.batch_id)))
      .limit(1);
    if (previous) {
      return previous.bodySha256 === bodySha256
        ? { kind: "accepted" as const, duplicate: true }
        : { kind: "batch_conflict" as const };
    }

    const [job] = await tx
      .select({ id: jobs.id, type: jobs.type, status: jobs.status, targetId: jobs.targetId, params: jobs.params })
      .from(jobs)
      .where(and(eq(jobs.id, batch.job_id), eq(jobs.agentId, agentId)))
      .limit(1);
    if (
      !job ||
      job.type !== "discovery.scan" ||
      !(FINDINGS_JOB_STATUSES as readonly string[]).includes(job.status)
    ) {
      return { kind: "job_not_found" as const, details: [{ pointer: "/job_id", keyword: "notFound" }] };
    }

    const targetIds = [...new Set(batch.findings.map((f) => f.target_id))];
    const targets = await tx
      .select({ targetId: agentTargets.targetId, engine: agentTargets.engine })
      .from(agentTargets)
      .where(and(eq(agentTargets.agentId, agentId), inArray(agentTargets.targetId, targetIds)));
    const engines = new Map(targets.map((t) => [t.targetId, t.engine]));
    const foreign: ValidationDetail[] = [];
    batch.findings.forEach((f, i) => {
      if (!engines.has(f.target_id) && foreign.length < MAX_VALIDATION_DETAILS) {
        foreign.push({ pointer: `/findings/${i}/target_id`, keyword: "notFound" });
      }
    });
    if (foreign.length > 0) return { kind: "foreign_target" as const, details: foreign };

    const invalid = crossFieldDetails(batch, job, engines);
    if (invalid.length > 0) return { kind: "invalid" as const, details: invalid };

    await upsertFindings(tx, agentId, batch);
    await tx.insert(findingsBatches).values({
      agentId,
      batchId: batch.batch_id,
      bodySha256,
      jobId: job.id,
      findingsCount: batch.findings.length,
    });
    return { kind: "accepted" as const, duplicate: false };
  });
}

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

const excluded = (column: string) => sql.raw(`excluded.${column}`);

async function upsertFindings(tx: Tx, agentId: string, batch: FindingsBatch): Promise<void> {
  // One row per location + classifier: within a batch, the last item wins.
  const byKey = new Map<string, Finding>();
  for (const f of batch.findings) byKey.set(findingLocationKey(f), f);
  const keys = [...byKey.keys()];
  const existing = await tx
    .select({ id: findings.id, locationKey: findings.locationKey })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), inArray(findings.locationKey, keys)));
  const ids = new Map(existing.map((r) => [r.locationKey, r.id]));
  // Fail closed: without the server key, no sample is stored (the finding still is).
  const key = maskedSamplesKey();
  const rows = keys.map((locationKey) => {
    const f = byKey.get(locationKey) as Finding;
    const id = ids.get(locationKey) ?? randomUUID();
    const samples = f.masked_samples ?? [];
    return {
      id,
      agentId,
      targetId: f.target_id,
      locationKey,
      engine: f.location.engine,
      databaseName: f.location.database,
      schemaName: f.location.schema ?? null,
      objectName: f.location.object,
      fieldName: f.location.field,
      classifier: f.classifier,
      classifiersVersion: batch.classifiers_version,
      confidence: f.confidence,
      sampled: f.sampled,
      matched: f.matched,
      estimatedRows: f.estimated_rows ?? null,
      maskedSamples: key && samples.length > 0 ? encryptMaskedSamples(key, id, samples) : null,
      fingerprints: f.fingerprints ?? [],
      firstJobId: batch.job_id,
      lastJobId: batch.job_id,
      lastBatchId: batch.batch_id,
    };
  });
  await tx
    .insert(findings)
    .values(rows)
    .onConflictDoUpdate({
      target: [findings.agentId, findings.locationKey],
      // The id, first_* and the false-positive decision are kept across scans.
      set: {
        engine: excluded("engine"),
        classifiersVersion: excluded("classifiers_version"),
        confidence: excluded("confidence"),
        sampled: excluded("sampled"),
        matched: excluded("matched"),
        estimatedRows: excluded("estimated_rows"),
        maskedSamples: excluded("masked_samples"),
        fingerprints: excluded("fingerprints"),
        lastJobId: excluded("last_job_id"),
        lastBatchId: excluded("last_batch_id"),
        lastSeenAt: sql`now()`,
      },
    });
}

// ----------------------------------------------------------------------------- view

export const MAX_LISTED_FINDINGS = 500;

export interface FindingView {
  id: string;
  agentId: string;
  agentName: string;
  targetId: string;
  engine: string;
  databaseName: string;
  schemaName: string | null;
  objectName: string;
  fieldName: string;
  classifier: string;
  confidence: number;
  sampled: number;
  matched: number;
  estimatedRows: number | null;
  fingerprintCount: number;
  /** Decrypted server side; `unavailable` when the key is missing or the blob does not decrypt. */
  samples: { state: "none" } | { state: "ok"; values: string[] } | { state: "unavailable" };
  firstSeenAt: Date;
  lastSeenAt: Date;
  falsePositiveAt: Date | null;
}

function filterWhere(filter: FindingFilter): SQL | undefined {
  const conds: SQL[] = [];
  if (filter.agentId) conds.push(eq(findings.agentId, filter.agentId));
  if (filter.targetId) conds.push(eq(findings.targetId, filter.targetId));
  if (filter.classifier) conds.push(eq(findings.classifier, filter.classifier));
  if (!filter.includeFalsePositives) conds.push(isNull(findings.falsePositiveAt));
  return conds.length > 0 ? and(...conds) : undefined;
}

/**
 * Findings for the view (server side only: the decrypted samples go into the rendered page of an
 * authenticated user, never into a cacheable response). False positives are excluded by default.
 */
export async function listFindings(db: Database, filter: FindingFilter = {}): Promise<FindingView[]> {
  const rows = await db
    .select({
      id: findings.id,
      agentId: findings.agentId,
      agentName: agents.name,
      targetId: findings.targetId,
      engine: findings.engine,
      databaseName: findings.databaseName,
      schemaName: findings.schemaName,
      objectName: findings.objectName,
      fieldName: findings.fieldName,
      classifier: findings.classifier,
      confidence: findings.confidence,
      sampled: findings.sampled,
      matched: findings.matched,
      estimatedRows: findings.estimatedRows,
      fingerprintCount: sql<number>`jsonb_array_length(${findings.fingerprints})::int`,
      maskedSamples: findings.maskedSamples,
      firstSeenAt: findings.firstSeenAt,
      lastSeenAt: findings.lastSeenAt,
      falsePositiveAt: findings.falsePositiveAt,
    })
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(filterWhere(filter))
    .orderBy(
      asc(agents.name),
      asc(findings.targetId),
      asc(findings.classifier),
      asc(findings.databaseName),
      asc(findings.schemaName),
      asc(findings.objectName),
      asc(findings.fieldName),
    )
    .limit(MAX_LISTED_FINDINGS);
  const key = maskedSamplesKey();
  return rows.map(({ maskedSamples, ...r }) => {
    let samples: FindingView["samples"] = { state: "none" };
    if (maskedSamples) {
      const values = key ? decryptMaskedSamples(key, r.id, maskedSamples) : null;
      samples = values ? { state: "ok", values } : { state: "unavailable" };
    }
    return { ...r, samples };
  });
}

export interface FindingSummaryRow {
  agentId: string;
  agentName: string;
  targetId: string;
  classifier: string;
  findings: number;
  maxConfidence: number;
}

/** Counts per target and classifier (false positives excluded unless asked). */
export async function summarizeFindings(db: Database, filter: FindingFilter = {}): Promise<FindingSummaryRow[]> {
  return db
    .select({
      agentId: findings.agentId,
      agentName: agents.name,
      targetId: findings.targetId,
      classifier: findings.classifier,
      findings: sql<number>`count(*)::int`,
      maxConfidence: sql<number>`max(${findings.confidence})`,
    })
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(filterWhere(filter))
    .groupBy(findings.agentId, agents.name, findings.targetId, findings.classifier)
    .orderBy(asc(agents.name), asc(findings.targetId), asc(findings.classifier))
    .limit(1000);
}

// -------------------------------------------------------------------- false positives

/**
 * Marks (or unmarks) a finding as a false positive. Kept across rescans of the same location and
 * classifier. Audited, including when the finding does not exist.
 */
export async function setFalsePositive(
  db: Database,
  findingId: string,
  falsePositive: boolean,
  actor: { userId: string; ip: string | null },
): Promise<boolean> {
  return db.transaction(async (tx) => {
    const rows = await tx
      .update(findings)
      .set(
        falsePositive
          ? { falsePositiveAt: sql`coalesce(${findings.falsePositiveAt}, now())`, falsePositiveBy: sql`coalesce(${findings.falsePositiveBy}, ${actor.userId}::uuid)` }
          : { falsePositiveAt: null, falsePositiveBy: null },
      )
      .where(eq(findings.id, findingId))
      .returning({ id: findings.id });
    const found = rows.length > 0;
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "finding.false_positive",
      outcome: found ? "success" : "failure",
      targetType: "finding",
      targetId: findingId,
      sourceIp: actor.ip,
      details: found ? { false_positive: falsePositive } : { false_positive: falsePositive, reason: "not_found" },
    });
    return found;
  });
}
