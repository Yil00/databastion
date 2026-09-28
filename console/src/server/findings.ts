import { randomUUID } from "node:crypto";

import { and, asc, eq, inArray, isNull, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, findings, findingsBatches, incidents, jobs } from "@/db/schema";
import { MAX_VALIDATION_DETAILS, type Schemas, type ValidationDetail } from "@/lib/protocol/validate";

import type { FindingFilter } from "@/lib/findings-filter";
import { registeredClassifiers } from "@/lib/protocol/classifiers";

import { writeAudit } from "./audit";
import { sha256Hex } from "./crypto";
import { decryptMaskedSamples, encryptMaskedSamples, maskedSamplesKey } from "./samples";
import { scanDeadlineSql } from "./scans";

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

/**
 * Late batches (M1). A finished (`succeeded` / `failed`) scan accepts findings for this long after
 * `least(finished_at, delivered_at + max_duration_s + SCAN_GRACE_MS)`: the bound on how long an
 * agent's spool may hold a batch of a finished scan (e.g. console outage, network partition). The
 * scan's own deadline caps it, so a final status sent long after the deadline does not reopen the
 * window; a null `finished_at` or `delivered_at` closes it (fail closed). A `delivered` / `running` scan accepts them until
 * `delivered_at + max_duration_s + SCAN_GRACE_MS` (see `scans.ts`). Later batches get `404` on
 * `/job_id` (the agent drops them), so an agent cannot write into old jobs forever.
 */
export const LATE_BATCH_RETENTION_MS = 24 * 3600_000;
/** Findings accepted per scan job, over all its batches (M1); beyond, `400` + integrity event. */
export const MAX_FINDINGS_PER_JOB = 50_000;

/** JSON with object keys sorted recursively (arrays keep their order). */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * SHA-256 of the validated batch in canonical JSON (idempotency on `(agent_id, batch_id)`): neither
 * whitespace nor key order changes it, any value change does.
 */
export function batchSha256(batch: FindingsBatch): string {
  return sha256Hex(canonicalJson(batch));
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
  | { kind: "invalid"; details: ValidationDetail[] }
  /** The job already received `MAX_FINDINGS_PER_JOB` findings: pointer `/findings`. */
  | { kind: "job_full"; details: ValidationDetail[] };

interface JobRow {
  id: string;
  type: string;
  status: string;
  targetId: string | null;
  classifiersVersion: string | null;
  params: Record<string, unknown>;
  /** The job still accepts findings (not past its time box). */
  open: boolean;
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
  // The batch's classifier set is registered (contract registry `classifiers.json`), and is the
  // one the scan asked for (L1). Both drop the whole batch.
  const registered = registeredClassifiers(batch.classifiers_version);
  if (!registered) push({ pointer: "/classifiers_version", keyword: "enum" });
  if (batch.classifiers_version !== job.classifiersVersion) {
    push({ pointer: "/classifiers_version", keyword: "const" });
  }
  batch.findings.forEach((f, i) => {
    // A scan job covers one target: its findings are about that target only.
    if (f.target_id !== job.targetId) push({ pointer: `/findings/${i}/target_id`, keyword: "const" });
    if (engines.get(f.target_id) !== f.location.engine) {
      push({ pointer: `/findings/${i}/location/engine`, keyword: "const" });
    }
    if (f.matched > f.sampled) push({ pointer: `/findings/${i}/matched`, keyword: "maximum" });
    if (f.sampled > sampleRows) push({ pointer: `/findings/${i}/sampled`, keyword: "maximum" });
    // An id of the batch's version and of the job's `params.classifiers` when present; both skipped
    // when the version itself is unknown (the whole batch is already rejected). Set lookups only.
    if (registered && (!registered.has(f.classifier) || (allowed && !allowed.has(f.classifier)))) {
      push({ pointer: `/findings/${i}/classifier`, keyword: "enum" });
    }
  });
  return details;
}

/**
 * Ingests a validated findings batch of `agentId`, atomically:
 * 1. idempotency on `(agent_id, batch_id)`: same content -> duplicate, other content -> conflict;
 * 2. `job_id` is a delivered `discovery.scan` job of the agent (`404` `/job_id` otherwise);
 * 3. every `target_id` was reported by the agent (`404`, item pointers);
 * 4. cross-field checks (`400`, all together): `classifiers_version` registered (`enum`) and equal
 *    to the job's (`const`), then item pointers (job target, engine, counts, classifier id of the
 *    batch's registered version and of the job's `params.classifiers`);
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
      .select({
        id: jobs.id,
        type: jobs.type,
        status: jobs.status,
        targetId: jobs.targetId,
        classifiersVersion: jobs.classifiersVersion,
        params: jobs.params,
        open: sql<boolean>`case
          when ${jobs.status} in ('succeeded', 'failed')
            then least(
                coalesce(${jobs.finishedAt}, '-infinity'::timestamptz),
                coalesce(${scanDeadlineSql}, '-infinity'::timestamptz)
              ) >= now() - make_interval(secs => ${LATE_BATCH_RETENTION_MS / 1000})
          when ${jobs.status} in ('delivered', 'running')
            then ${jobs.deliveredAt} is not null and ${scanDeadlineSql} >= now()
          else false end`,
      })
      .from(jobs)
      .where(and(eq(jobs.id, batch.job_id), eq(jobs.agentId, agentId)))
      .limit(1);
    if (
      !job ||
      job.type !== "discovery.scan" ||
      !(FINDINGS_JOB_STATUSES as readonly string[]).includes(job.status) ||
      !job.open
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

    const [received] = await tx
      .select({ n: sql<number>`coalesce(sum(${findingsBatches.findingsCount}), 0)::int` })
      .from(findingsBatches)
      .where(and(eq(findingsBatches.agentId, agentId), eq(findingsBatches.jobId, job.id)));
    if ((received?.n ?? 0) + batch.findings.length > MAX_FINDINGS_PER_JOB) {
      return { kind: "job_full" as const, details: [{ pointer: "/findings", keyword: "maxItems" }] };
    }

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

export type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

const excluded = (column: string) => sql.raw(`excluded.${column}`);

async function upsertFindings(tx: Tx, agentId: string, batch: FindingsBatch): Promise<void> {
  // One row per location + classifier: within a batch, the last item wins.
  const byKey = new Map<string, Finding>();
  for (const f of batch.findings) byKey.set(findingLocationKey(f), f);
  const keys = [...byKey.keys()];
  // Locked: a concurrent false-positive marking waits, so the reset decision below is exact.
  const existing = await tx
    .select({
      id: findings.id,
      locationKey: findings.locationKey,
      falsePositiveAt: findings.falsePositiveAt,
      falsePositiveMatched: findings.falsePositiveMatched,
      falsePositiveClassifiersVersion: findings.falsePositiveClassifiersVersion,
    })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), inArray(findings.locationKey, keys)))
    .for("update");
  const ids = new Map(existing.map((r) => [r.locationKey, r.id]));
  const resets = existing.filter((r) => {
    const f = byKey.get(r.locationKey);
    return f !== undefined && r.falsePositiveAt !== null && fpResetNeeded(r, f.matched, batch.classifiers_version);
  });
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
        // M2: same predicate as `fpResetNeeded`, evaluated on the locked row.
        falsePositiveAt: sql`case when ${FP_RESET_SQL} then null else ${findings.falsePositiveAt} end`,
        falsePositiveBy: sql`case when ${FP_RESET_SQL} then null else ${findings.falsePositiveBy} end`,
        falsePositiveMatched: sql`case when ${FP_RESET_SQL} then null else ${findings.falsePositiveMatched} end`,
        falsePositiveClassifiersVersion: sql`case when ${FP_RESET_SQL} then null else ${findings.falsePositiveClassifiersVersion} end`,
      },
    });
  for (const r of resets) {
    const f = byKey.get(r.locationKey) as Finding;
    await writeAudit(tx, {
      actorType: "system",
      action: "finding.false_positive_reset",
      targetType: "finding",
      targetId: r.id,
      details: {
        agent_id: agentId,
        target_id: f.target_id,
        classifier: f.classifier,
        job_id: batch.job_id,
        reason:
          r.falsePositiveClassifiersVersion !== batch.classifiers_version ? "classifiers_version" : "matched_increased",
      },
    });
  }
}

/**
 * M2: a false positive is reset when a later scan matches more values than when it was marked, or
 * ran another classifier set (a mark without a snapshot is kept).
 */
export function fpResetNeeded(
  row: { falsePositiveMatched: number | null; falsePositiveClassifiersVersion: string | null },
  matched: number,
  classifiersVersion: string,
): boolean {
  if (row.falsePositiveMatched !== null && matched > row.falsePositiveMatched) return true;
  return row.falsePositiveClassifiersVersion !== null && row.falsePositiveClassifiersVersion !== classifiersVersion;
}

const FP_RESET_SQL = sql`(${findings.falsePositiveAt} is not null and (
  (${findings.falsePositiveMatched} is not null and excluded.matched > ${findings.falsePositiveMatched})
  or (${findings.falsePositiveClassifiersVersion} is not null
      and excluded.classifiers_version <> ${findings.falsePositiveClassifiersVersion})))`;

// ----------------------------------------------------------------------------- view

export const MAX_LISTED_FINDINGS = 500;

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

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
    .select(FINDING_VIEW_COLUMNS)
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(filterWhere(filter))
    // M1: round-robin over targets (most recently seen first within each), so that one noisy agent
    // or target cannot push every other finding out of the first MAX_LISTED_FINDINGS rows.
    .orderBy(
      sql`row_number() over (partition by ${findings.agentId}, ${findings.targetId} order by ${findings.lastSeenAt} desc, ${findings.id})`,
      asc(agents.name),
      asc(findings.targetId),
      asc(findings.classifier),
      asc(findings.databaseName),
      asc(findings.schemaName),
      asc(findings.objectName),
      asc(findings.fieldName),
    )
    .limit(MAX_LISTED_FINDINGS);
  // Fetched fairly (see above), displayed in a stable reading order.
  rows.sort(
    (a, b) =>
      cmp(a.agentName, b.agentName) ||
      cmp(a.targetId, b.targetId) ||
      cmp(a.classifier, b.classifier) ||
      cmp(a.databaseName, b.databaseName) ||
      cmp(a.schemaName ?? "", b.schemaName ?? "") ||
      cmp(a.objectName, b.objectName) ||
      cmp(a.fieldName, b.fieldName),
  );
  const key = maskedSamplesKey();
  return rows.map((r) => toFindingView(r, key));
}

const FINDING_VIEW_COLUMNS = {
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
};

type FindingViewRow = Omit<FindingView, "samples"> & { maskedSamples: Buffer | null };

/** The single decryption path of masked samples for display (`unavailable` on any failure). */
function toFindingView({ maskedSamples, ...r }: FindingViewRow, key: Buffer | null): FindingView {
  let samples: FindingView["samples"] = { state: "none" };
  if (maskedSamples) {
    const values = key ? decryptMaskedSamples(key, r.id, maskedSamples) : null;
    samples = values ? { state: "ok", values } : { state: "unavailable" };
  }
  return { ...r, samples };
}

/** One finding for a server-rendered page (e.g. an incident's linked finding), or null. */
export async function getFindingView(db: Database, findingId: string): Promise<FindingView | null> {
  const [row] = await db
    .select(FINDING_VIEW_COLUMNS)
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(eq(findings.id, findingId))
    .limit(1);
  return row ? toFindingView(row, maskedSamplesKey()) : null;
}

export interface FindingSummaryRow {
  agentId: string;
  agentName: string;
  targetId: string;
  classifier: string;
  findings: number;
  maxConfidence: number;
}

export const MAX_SUMMARY_GROUPS = 1000;

/**
 * Counts per target and classifier (false positives excluded unless asked). At most
 * `MAX_SUMMARY_GROUPS` groups, fetched round-robin like {@link listFindings}: over agents, then over
 * the targets of each agent (most recently seen first within each target), so one noisy agent or
 * target cannot push the others out. Returned in a stable reading order.
 */
export async function summarizeFindings(db: Database, filter: FindingFilter = {}): Promise<FindingSummaryRow[]> {
  const grouped = db
    .select({
      agentId: sql<string>`${findings.agentId}`.as("agent_id"),
      agentName: sql<string>`${agents.name}`.as("agent_name"),
      targetId: sql<string>`${findings.targetId}`.as("target_id"),
      classifier: sql<string>`${findings.classifier}`.as("classifier"),
      findings: sql<number>`count(*)::int`.as("findings"),
      maxConfidence: sql<number>`max(${findings.confidence})`.as("max_confidence"),
      // Rank of the group within its (agent, target).
      targetRank: sql<number>`row_number() over (partition by ${findings.agentId}, ${findings.targetId}
        order by max(${findings.lastSeenAt}) desc, ${findings.classifier})`.as("target_rank"),
    })
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(filterWhere(filter))
    .groupBy(findings.agentId, agents.name, findings.targetId, findings.classifier)
    .as("grouped");
  const rows = await db
    .select({
      agentId: grouped.agentId,
      agentName: grouped.agentName,
      targetId: grouped.targetId,
      classifier: grouped.classifier,
      findings: grouped.findings,
      maxConfidence: grouped.maxConfidence,
    })
    .from(grouped)
    .orderBy(
      sql`row_number() over (partition by ${grouped.agentId} order by ${grouped.targetRank}, ${grouped.targetId})`,
      asc(grouped.agentName),
      asc(grouped.agentId),
      asc(grouped.targetId),
      asc(grouped.classifier),
    )
    .limit(MAX_SUMMARY_GROUPS);
  rows.sort(
    (a, b) => cmp(a.agentName, b.agentName) || cmp(a.agentId, b.agentId) || cmp(a.targetId, b.targetId) || cmp(a.classifier, b.classifier),
  );
  return rows;
}

// -------------------------------------------------------------------- false positives

/**
 * Marks (or unmarks) a finding as a false positive (admin decision, M2). The mark records `matched`
 * and `classifiers_version` at marking time; a later scan matching more values or using another
 * classifier set resets it (see `fpResetNeeded`). Kept across other rescans. Audited, including
 * when the finding does not exist. See {@link applyFalsePositive} for the incidents side.
 */
export async function setFalsePositive(
  db: Database,
  findingId: string,
  falsePositive: boolean,
  actor: { userId: string; ip: string | null },
): Promise<boolean> {
  return db.transaction(async (tx) => (await applyFalsePositive(tx, findingId, falsePositive, actor)) !== null);
}

/**
 * The false-positive decision lives on the finding (location + classifier), for findings and
 * incidents alike (P3-B): in the caller's transaction,
 * - marking closes every open / acknowledged incident of the finding as `false_positive` (same
 *   actor, audited `incident.transition`), and the policy engine skips false-positive findings;
 * - unmarking sets the finding pending for the policy engine (`policy_evaluated_at = null`), so
 *   the policies are applied to it again.
 * Returns the finding's identifiers, or `null` when it does not exist (audited as a failure).
 */
export async function applyFalsePositive(
  tx: Tx,
  findingId: string,
  falsePositive: boolean,
  actor: { userId: string; ip: string | null },
  via?: { incidentId: string },
): Promise<{ agentId: string; targetId: string; classifier: string } | null> {
  const rows = await tx
    .update(findings)
    .set(
      falsePositive
        ? {
            falsePositiveAt: sql`coalesce(${findings.falsePositiveAt}, now())`,
            falsePositiveBy: sql`coalesce(${findings.falsePositiveBy}, ${actor.userId}::uuid)`,
            falsePositiveMatched: sql`case when ${findings.falsePositiveAt} is null then ${findings.matched} else ${findings.falsePositiveMatched} end`,
            falsePositiveClassifiersVersion: sql`case when ${findings.falsePositiveAt} is null then ${findings.classifiersVersion} else ${findings.falsePositiveClassifiersVersion} end`,
          }
        : {
            falsePositiveAt: null,
            falsePositiveBy: null,
            falsePositiveMatched: null,
            falsePositiveClassifiersVersion: null,
            policyEvaluatedAt: null,
          },
    )
    .where(eq(findings.id, findingId))
    .returning({ agentId: findings.agentId, targetId: findings.targetId, classifier: findings.classifier });
  const row = rows[0];
  await writeAudit(tx, {
    actorType: "user",
    actorId: actor.userId,
    action: "finding.false_positive",
    outcome: row ? "success" : "failure",
    targetType: "finding",
    targetId: findingId,
    sourceIp: actor.ip,
    details: row
      ? {
          false_positive: falsePositive,
          agent_id: row.agentId,
          target_id: row.targetId,
          classifier: row.classifier,
          ...(via ? { incident_id: via.incidentId } : {}),
        }
      : { false_positive: falsePositive, reason: "not_found" },
  });
  if (row && falsePositive) {
    const active = await tx
      .select({ id: incidents.id, status: incidents.status })
      .from(incidents)
      .where(and(eq(incidents.findingId, findingId), inArray(incidents.status, ["open", "acknowledged"])))
      .for("update");
    for (const incident of active) {
      await tx
        .update(incidents)
        .set({ status: "false_positive", falsePositiveAt: sql`now()`, falsePositiveBy: actor.userId, updatedAt: sql`now()` })
        .where(eq(incidents.id, incident.id));
      await writeAudit(tx, {
        actorType: "user",
        actorId: actor.userId,
        action: "incident.transition",
        targetType: "incident",
        targetId: incident.id,
        sourceIp: actor.ip,
        details: { from: incident.status, to: "false_positive", finding_id: findingId, via: via ? "incident" : "finding" },
      });
    }
  }
  return row ?? null;
}
