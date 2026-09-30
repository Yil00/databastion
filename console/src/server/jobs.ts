import { and, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { jobs } from "@/db/schema";
import { logger } from "@/lib/logger";
import { checkSemantics, validateSchema, type Schemas } from "@/lib/protocol/validate";

import { JOBS_CHANNEL } from "./agent-api/job-hub";
import { lockAgentJobs } from "./job-lock";
import { AGENT_ONLINE_WINDOW_S, heldScanExpirySql, scanAnchorSql, scanBudgetSql, scanInFlightSql, sweepDeadScans } from "./scans";

export { AGENT_ONLINE_WINDOW_S };

/** A delivered job with no status is delivered again after this lease (contract: 120 s). */
export const JOB_LEASE_S = 120;
export const MAX_JOBS_PER_POLL = 16;
/**
 * Deliveries without any status before a job is given up (`failed`, `timeout`), except a queued
 * `discovery.scan` of an online agent within its budget (see `QUEUED_SCAN_MARGIN_S`).
 */
export const MAX_JOB_ATTEMPTS = 5;
/**
 * Queued scans (Discovery pacing, PR #93). The agent runs scans one at a time and acknowledges a
 * scan (`running`) only when it starts it. Its `max_duration_s` window counts from the agent's
 * reception of the job, queue time included (docs/09, "Scan worker"). Since the M1 fix, the
 * console delivers at most one `discovery.scan` per agent at a time (see `claimJobs`), so a scan is
 * normally delivered only when the agent's scan worker is free and its window starts when it can
 * run. A delivered scan may still wait in the agent's queue (a scan the agent still runs after a
 * console-side timeout, scans delivered by an older console before an upgrade): while the agent
 * is online (heartbeat within `AGENT_ONLINE_WINDOW_S`), such a scan is not given up after
 * `MAX_JOB_ATTEMPTS` deliveries before `first_delivered_at + max_duration_s +
 * QUEUED_SCAN_MARGIN_S` (#94). It is still delivered again every lease (the agent ignores a job it
 * has queued, and queues it again after a restart that lost its queue). The margin is the
 * tolerance of any unacknowledged job (5 leases): lost deliveries, and the agent's own `timeout`
 * status.
 */
export const QUEUED_SCAN_MARGIN_S = MAX_JOB_ATTEMPTS * JOB_LEASE_S;

/**
 * SQL: a delivered, unacknowledged job of the table `jobs` that is a queued `discovery.scan` of an
 * online agent, still within its budget (not given up after `MAX_JOB_ATTEMPTS` deliveries).
 */
const queuedScanSql = sql`(${jobs.type} = 'discovery.scan'
  and exists (select 1 from agents a where a.id = ${jobs.agentId}
    and a.last_seen_at > now() - make_interval(secs => ${AGENT_ONLINE_WINDOW_S}))
  and ${scanAnchorSql} + make_interval(secs => ${scanBudgetSql})
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
  attempts: number | string;
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
 * oldest first (`FOR UPDATE SKIP LOCKED`: concurrent polls never get the same job twice within a
 * lease). Dead scans are swept and expired jobs are marked `expired` first. Each job is validated
 * against the contract (schema + `checkSemantics`: a `discovery.scan` job carries a registered
 * `classifiers_version` and registered `params.classifiers` ids); a job that does not conform is
 * marked `failed` (`internal`) and never sent.
 *
 * One scan at a time (security review M1): a pending `discovery.scan` is delivered only when the
 * agent has no other `discovery.scan` `delivered` or `running` and no older pending one, so the
 * next scan is delivered after the previous one ends (`succeeded`, `failed`, `cancelled`, or
 * given up / timed out by the console) and its window starts when the agent can run it. A
 * delivered scan keeps its lease, redelivery and give-up rules. Other job types are not held.
 * The claims of one agent are serialized by a transaction-scoped advisory lock, so two concurrent
 * polls cannot each deliver a different scan (each statement of the second claim sees the first
 * one's deliveries). A scan that fails the contract check does not hold the next one back: the
 * claim is repeated (bounded), so the next pending scan goes out in the same response.
 */
export async function claimJobs(db: Database, agentId: string): Promise<Schemas["Job"][]> {
  const out: Schemas["Job"][] = [];
  for (let round = 0; round < MAX_JOBS_PER_POLL && out.length < MAX_JOBS_PER_POLL; round++) {
    const { jobs: claimed, rejectedScan } = await claimOnce(db, agentId, MAX_JOBS_PER_POLL - out.length);
    out.push(...claimed);
    if (!rejectedScan) break;
  }
  return out;
}

async function claimOnce(
  db: Database,
  agentId: string,
  limit: number,
): Promise<{ jobs: Schemas["Job"][]; rejectedScan: boolean }> {
  const { givenUp, claimed } = await db.transaction(async (tx) => {
    await lockAgentJobs(tx, agentId);
    // Scans that died silently (past their deadline) are failed first: they must not hold the
    // agent's next scan back. Held scans of an online agent do not expire while held. Nothing to
    // sweep or hold without a scan in flight (pending scans expire below).
    const inFlight = await tx.execute(sql`select 1 from jobs where agent_id = ${agentId}
      and type = 'discovery.scan' and status in ('delivered', 'running') limit 1`);
    if (inFlight.rows.length > 0) await sweepDeadScans(tx, agentId);
    await tx.execute(sql`
      update jobs set status = 'expired', finished_at = now()
      where agent_id = ${agentId} and status in ('pending', 'delivered')
        and expires_at is not null and expires_at <= now()`);
    // L7: a job delivered MAX_JOB_ATTEMPTS times without any status is not redelivered forever,
    // unless it is a scan queued behind others on an online agent, within its budget.
    const givenUp = await tx.execute<{ id: string; type: string; target_id: string | null }>(sql`
      update jobs set status = 'failed', error = '{"code":"timeout"}'::jsonb, finished_at = now(),
        lease_until = null
      where agent_id = ${agentId} and status = 'delivered' and lease_until < now()
        and attempts >= ${MAX_JOB_ATTEMPTS} and not ${queuedScanSql}
      returning id, type, target_id`);
    const claimed = await tx.execute<ClaimedRow>(sql`
      update jobs set
        status = 'delivered',
        lease_until = now() + make_interval(secs => ${JOB_LEASE_S}),
        attempts = attempts + 1,
        delivered_at = now(),
        first_delivered_at = coalesce(first_delivered_at, now()),
        expires_at = case when type = 'discovery.scan' and status = 'pending' and expires_at is not null
          then greatest(expires_at, ${heldScanExpirySql}) else expires_at end
      where id in (
        select id from jobs
        where agent_id = ${agentId}
          and (status = 'pending' or (status = 'delivered' and lease_until < now()))
          and (expires_at is null or expires_at > now())
          and not (type = 'discovery.scan' and status = 'pending' and (${scanInFlightSql}
            or exists (select 1 from jobs p where p.agent_id = ${jobs.agentId} and p.type = 'discovery.scan'
              and p.status = 'pending' and (p.created_at, p.id) < (${jobs.createdAt}, ${jobs.id}))))
        order by created_at, id
        limit ${limit}
        for update skip locked)
      returning id, type, target_id, classifiers_version, params, created_at, expires_at, attempts`);
    return { givenUp: givenUp.rows, claimed: claimed.rows };
  });
  for (const job of givenUp) {
    logger.warn({ jobId: job.id, type: job.type, targetId: job.target_id }, "job given up: no status after its deliveries");
  }
  for (const row of claimed) {
    // Only a queued scan of an online agent is delivered past MAX_JOB_ATTEMPTS: said once per job.
    if (row.type === "discovery.scan" && Number(row.attempts) === MAX_JOB_ATTEMPTS + 1) {
      logger.info(
        { jobId: row.id, agentId, attempts: Number(row.attempts) },
        "queued scan kept past its delivery limit: agent online, within the scan budget",
      );
    }
  }
  const out: Schemas["Job"][] = [];
  let rejectedScan = false;
  for (const row of [...claimed].sort((a, b) => iso(a.created_at).localeCompare(iso(b.created_at)))) {
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
      // Only while still delivered: never over a concurrent `cancelled` (revocation).
      .where(and(eq(jobs.id, row.id), eq(jobs.status, "delivered")));
    if (row.type === "discovery.scan") rejectedScan = true;
  }
  return { jobs: out, rejectedScan };
}

export type StatusOutcome = "recorded" | "ignored" | "not_found" | "conflict";

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

/**
 * Applies a (validated) status update of the calling agent's job.
 * - unknown job or job of another agent: `not_found` (not distinguished);
 * - job already terminal: `conflict`;
 * - update older than the last one received (`ts`): `ignored`.
 * An `expired` job may still be reported `failed` by the agent (it rejects expired jobs).
 * A `discovery.scan` that ends wakes the agent's held long-poll (NOTIFY on commit): its next
 * pending scan, held back while this one was in flight (M1), is delivered without waiting for the
 * next poll.
 */
export async function applyJobStatus(
  db: Database,
  agentId: string,
  jobId: string,
  update: Schemas["JobStatusUpdate"],
): Promise<StatusOutcome> {
  return db.transaction(async (tx) => {
    const [job] = await tx
      .select({ status: jobs.status, type: jobs.type, lastStatusAt: jobs.lastStatusAt })
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
    if (terminal && job.type === "discovery.scan") {
      await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    }
    return "recorded";
  });
}
