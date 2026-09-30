import { and, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { jobs } from "@/db/schema";
import { logger } from "@/lib/logger";
import { checkSemantics, validateSchema, type Schemas } from "@/lib/protocol/validate";

import { JOBS_CHANNEL } from "./agent-api/job-hub";
import { HEARTBEAT_INTERVAL_S } from "./agent-api/pipeline";

/** A delivered job with no status is delivered again after this lease (contract: 120 s). */
export const JOB_LEASE_S = 120;
export const MAX_JOBS_PER_POLL = 16;
/**
 * Deliveries without any status before a job is given up (`failed`, `timeout`), except a queued
 * `discovery.scan` of an online agent within its budget (see `QUEUED_SCAN_MARGIN_S`).
 */
export const MAX_JOB_ATTEMPTS = 5;
/** An agent whose last heartbeat is more recent than this is online (3 missed heartbeats: offline). */
export const AGENT_ONLINE_WINDOW_S = 3 * HEARTBEAT_INTERVAL_S;
/**
 * Queued scans (Discovery pacing, PR #93). The agent runs scans one at a time and acknowledges a
 * scan (`running`) only when it starts it, so a scan queued behind a long paced scan stays
 * delivered without a status for minutes. Its `max_duration_s` window counts from the agent's
 * reception of the job, queue time included (docs/09, "Scan worker"): past it, the agent itself
 * ends the scan `failed` / `timeout` without touching the target. So while the agent is online
 * (heartbeat within `AGENT_ONLINE_WINDOW_S`), such a scan is not given up after `MAX_JOB_ATTEMPTS`
 * deliveries before `first_delivered_at + max_duration_s + QUEUED_SCAN_MARGIN_S`. It is still
 * delivered again every lease (the agent ignores a job it has queued, and queues it again after a
 * restart that lost its queue). The margin is the tolerance of any unacknowledged job (5 leases):
 * lost deliveries, and the agent's own `timeout` status.
 */
export const QUEUED_SCAN_MARGIN_S = MAX_JOB_ATTEMPTS * JOB_LEASE_S;

/**
 * SQL: a delivered, unacknowledged job of the table `jobs` that is a queued `discovery.scan` of an
 * online agent, still within its budget (not given up after `MAX_JOB_ATTEMPTS` deliveries).
 */
const queuedScanSql = sql`(${jobs.type} = 'discovery.scan'
  and exists (select 1 from agents a where a.id = ${jobs.agentId}
    and a.last_seen_at > now() - make_interval(secs => ${AGENT_ONLINE_WINDOW_S}))
  and coalesce(${jobs.firstDeliveredAt}, ${jobs.deliveredAt})
    + make_interval(secs => case when ${jobs.type} = 'discovery.scan'
        then coalesce((${jobs.params}->>'max_duration_s')::int, 86400) else 0 end)
    + make_interval(secs => ${QUEUED_SCAN_MARGIN_S}) > now())`;

export type JobType = Schemas["Job"]["type"];

export interface NewJob {
  agentId: string;
  type: JobType;
  targetId?: string;
  classifiersVersion?: string;
  params: Record<string, unknown>;
  expiresAt?: Date;
  createdBy?: string;
}

/** Queues a job and wakes the agent's held long-poll (NOTIFY is delivered on commit). */
export async function enqueueJob(db: Database, job: NewJob): Promise<string> {
  return db.transaction(async (tx) => {
    const [row] = await tx
      .insert(jobs)
      .values({
        agentId: job.agentId,
        type: job.type,
        targetId: job.targetId ?? null,
        classifiersVersion: job.classifiersVersion ?? null,
        params: job.params,
        expiresAt: job.expiresAt ?? null,
        createdBy: job.createdBy ?? null,
      })
      .returning({ id: jobs.id });
    if (!row) throw new Error("job insert returned no row");
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${job.agentId})`);
    return row.id;
  });
}

interface ClaimedRow extends Record<string, unknown> {
  id: string;
  type: string;
  target_id: string | null;
  classifiers_version: string | null;
  params: Record<string, unknown>;
  created_at: Date | string;
  expires_at: Date | string | null;
}

const iso = (v: Date | string) => (v instanceof Date ? v : new Date(v)).toISOString();

function toContractJob(r: ClaimedRow): Record<string, unknown> {
  const job: Record<string, unknown> = {
    job_id: r.id,
    type: r.type,
    created_at: iso(r.created_at),
    params: r.params,
  };
  if (r.expires_at !== null) job.expires_at = iso(r.expires_at);
  if (r.target_id !== null) job.target_id = r.target_id;
  if (r.classifiers_version !== null) job.classifiers_version = r.classifiers_version;
  return job;
}

/**
 * Leases up to 16 deliverable jobs of the agent (pending, or delivered with an expired lease),
 * oldest first, in one short statement (`FOR UPDATE SKIP LOCKED`: concurrent polls never get the
 * same job twice within a lease). Expired jobs are marked `expired` first. Each job is validated
 * against the contract (schema + `checkSemantics`: a `discovery.scan` job carries a registered
 * `classifiers_version` and registered `params.classifiers` ids); a job that does not conform is
 * marked `failed` (`internal`) and never sent.
 */
export async function claimJobs(db: Database, agentId: string): Promise<Schemas["Job"][]> {
  await db.execute(sql`
    update jobs set status = 'expired', finished_at = now()
    where agent_id = ${agentId} and status in ('pending', 'delivered')
      and expires_at is not null and expires_at <= now()`);
  // L7: a job delivered MAX_JOB_ATTEMPTS times without any status is not redelivered forever,
  // unless it is a scan queued behind others on an online agent, within its budget.
  const givenUp = await db.execute<{ id: string; type: string; target_id: string | null }>(sql`
    update jobs set status = 'failed', error = '{"code":"timeout"}'::jsonb, finished_at = now(),
      lease_until = null
    where agent_id = ${agentId} and status = 'delivered' and lease_until < now()
      and attempts >= ${MAX_JOB_ATTEMPTS} and not ${queuedScanSql}
    returning id, type, target_id`);
  for (const job of givenUp.rows) {
    logger.warn({ jobId: job.id, type: job.type, targetId: job.target_id }, "job given up: no status after its deliveries");
  }
  const result = await db.execute<ClaimedRow>(sql`
    update jobs set
      status = 'delivered',
      lease_until = now() + make_interval(secs => ${JOB_LEASE_S}),
      attempts = attempts + 1,
      delivered_at = now(),
      first_delivered_at = coalesce(first_delivered_at, now())
    where id in (
      select id from jobs
      where agent_id = ${agentId}
        and (status = 'pending' or (status = 'delivered' and lease_until < now()))
        and (expires_at is null or expires_at > now())
      order by created_at, id
      limit ${MAX_JOBS_PER_POLL}
      for update skip locked)
    returning id, type, target_id, classifiers_version, params, created_at, expires_at`);
  const out: Schemas["Job"][] = [];
  for (const row of [...result.rows].sort((a, b) => iso(a.created_at).localeCompare(iso(b.created_at)))) {
    // Schema, then the semantic checks (a scan job's classifier set and ids are registered).
    const schema = validateSchema("Job", toContractJob(row));
    const checked = schema.ok ? checkSemantics("Job", schema.value) : schema;
    if (checked.ok) {
      out.push(checked.value);
      continue;
    }
    logger.error({ jobId: row.id, details: checked.details }, "job does not conform to the contract");
    await db
      .update(jobs)
      .set({ status: "failed", error: { code: "internal" }, finishedAt: sql`now()` })
      .where(eq(jobs.id, row.id));
  }
  return out;
}

export type StatusOutcome = "recorded" | "ignored" | "not_found" | "conflict";

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

/**
 * Applies a (validated) status update of the calling agent's job.
 * - unknown job or job of another agent: `not_found` (not distinguished);
 * - job already terminal: `conflict`;
 * - update older than the last one received (`ts`): `ignored`.
 * An `expired` job may still be reported `failed` by the agent (it rejects expired jobs).
 */
export async function applyJobStatus(
  db: Database,
  agentId: string,
  jobId: string,
  update: Schemas["JobStatusUpdate"],
): Promise<StatusOutcome> {
  return db.transaction(async (tx) => {
    const [job] = await tx
      .select({ status: jobs.status, lastStatusAt: jobs.lastStatusAt })
      .from(jobs)
      .where(and(eq(jobs.id, jobId), eq(jobs.agentId, agentId)))
      .for("update")
      .limit(1);
    if (!job) return "not_found";
    if (TERMINAL.has(job.status)) return "conflict";
    if (job.status === "expired" && update.status !== "failed") return "conflict";
    const ts = new Date(update.ts);
    if (job.lastStatusAt && ts.getTime() < job.lastStatusAt.getTime()) return "ignored";
    const terminal = update.status !== "running";
    await tx
      .update(jobs)
      .set({
        status: update.status,
        lastStatusAt: ts,
        progress: update.progress ? { ...update.progress } : undefined,
        error: update.status === "failed" && update.error ? { ...update.error } : undefined,
        finishedAt: terminal ? sql`now()` : undefined,
        leaseUntil: null,
      })
      .where(eq(jobs.id, jobId));
    return "recorded";
  });
}
