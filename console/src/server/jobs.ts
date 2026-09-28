import { and, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { jobs } from "@/db/schema";
import { logger } from "@/lib/logger";
import { validateSchema, type Schemas } from "@/lib/protocol/validate";

import { JOBS_CHANNEL } from "./agent-api/job-hub";

/** A delivered job with no status is delivered again after this lease (contract: 120 s). */
export const JOB_LEASE_S = 120;
export const MAX_JOBS_PER_POLL = 16;
/** Deliveries without any status before a job is given up (`failed`, `timeout`). */
export const MAX_JOB_ATTEMPTS = 5;

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
 * against the contract; a job that does not conform is marked `failed` (`internal`) and never sent.
 */
export async function claimJobs(db: Database, agentId: string): Promise<Schemas["Job"][]> {
  await db.execute(sql`
    update jobs set status = 'expired', finished_at = now()
    where agent_id = ${agentId} and status in ('pending', 'delivered')
      and expires_at is not null and expires_at <= now()`);
  // L7: a job delivered MAX_JOB_ATTEMPTS times without any status is not redelivered forever.
  await db.execute(sql`
    update jobs set status = 'failed', error = '{"code":"timeout"}'::jsonb, finished_at = now(),
      lease_until = null
    where agent_id = ${agentId} and status = 'delivered' and lease_until < now()
      and attempts >= ${MAX_JOB_ATTEMPTS}`);
  const result = await db.execute<ClaimedRow>(sql`
    update jobs set
      status = 'delivered',
      lease_until = now() + make_interval(secs => ${JOB_LEASE_S}),
      attempts = attempts + 1,
      delivered_at = now()
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
    const checked = validateSchema("Job", toContractJob(row));
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
