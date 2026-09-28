import { and, desc, eq, inArray, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, jobs } from "@/db/schema";
import { checkSemantics, validateSchema, type Schemas } from "@/lib/protocol/validate";

import { JOBS_CHANNEL } from "./agent-api/job-hub";
import { writeAudit } from "./audit";

/**
 * Launching Discovery scans (P2-D): a `discovery.scan` job for one target of one agent, with
 * contract `DiscoveryScanParams`. Parameters are validated against the contract when the job is
 * created (unknown keys, ranges, non-empty filter lists), and every outgoing `JobList` is
 * validated again when the job is served (`claimJobs`, `conformingJson`).
 */

export type DiscoveryScanParams = Schemas["DiscoveryScanParams"];

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

/** Contract defaults (`DiscoveryScanParams`), made explicit in every job. */
export const SCAN_DEFAULTS = { sample_rows: 200, max_duration_s: 900, statement_timeout_ms: 30_000 } as const;
/** The agent must not start a scan after this delay (contract `expires_at`). */
export const SCAN_JOB_TTL_MS = 6 * 3600_000;
/**
 * Slack added to a scan's `max_duration_s` after delivery: past `delivered_at + max_duration_s +
 * SCAN_GRACE_MS`, a `delivered` / `running` scan is dead (the agent's own budget is over). It gets no
 * more findings, and the next scan request of the agent marks it `failed` (`timeout`).
 */
export const SCAN_GRACE_MS = 3600_000;

/** SQL: the instant after which a delivered / running scan job is dead. */
export const scanDeadlineSql = sql`${jobs.deliveredAt} + make_interval(secs => coalesce((${jobs.params}->>'max_duration_s')::int, 86400)) + make_interval(secs => ${SCAN_GRACE_MS / 1000})`;

/**
 * Expiry sweep of the agent's scan jobs, run before the "one open scan per target" check (L2):
 * pending scans past `expires_at` become `expired`; delivered / running scans past their deadline
 * become `failed` (`timeout`), each audited as a system action. Returns the timed-out job ids.
 */
export async function sweepDeadScans(tx: Tx, agentId: string): Promise<string[]> {
  await tx.execute(sql`
    update jobs set status = 'expired', finished_at = now()
    where agent_id = ${agentId} and type = 'discovery.scan' and status = 'pending'
      and expires_at is not null and expires_at <= now()`);
  const dead = await tx
    .update(jobs)
    .set({ status: "failed", error: { code: "timeout" }, finishedAt: sql`now()`, leaseUntil: null })
    .where(
      and(
        eq(jobs.agentId, agentId),
        eq(jobs.type, "discovery.scan"),
        inArray(jobs.status, ["delivered", "running"]),
        sql`${jobs.deliveredAt} is not null and ${scanDeadlineSql} < now()`,
      ),
    )
    .returning({ id: jobs.id, targetId: jobs.targetId });
  for (const job of dead) {
    await writeAudit(tx, {
      actorType: "system",
      action: "job.timeout",
      outcome: "failure",
      targetType: "job",
      targetId: job.id,
      details: { agent_id: agentId, target_id: job.targetId, type: "discovery.scan" },
    });
  }
  return dead.map((j) => j.id);
}

const PARAM_KEYS = new Set([
  "sample_rows",
  "max_duration_s",
  "statement_timeout_ms",
  "databases",
  "schemas",
  "include_objects",
  "exclude_objects",
  "classifiers",
]);

/**
 * Builds the job parameters from a user request body: defaults for the three bounds, then the
 * contract schema (unknown keys and out-of-range values rejected, empty include filters rejected:
 * an empty list never means "everything") and `checkSemantics`.
 */
export function buildScanParams(input: unknown): { ok: true; params: DiscoveryScanParams } | { ok: false } {
  if (input === undefined || input === null) input = {};
  if (typeof input !== "object" || Array.isArray(input)) return { ok: false };
  const record = input as Record<string, unknown>;
  if (!Object.keys(record).every((k) => PARAM_KEYS.has(k))) return { ok: false };
  const params = { ...SCAN_DEFAULTS, ...record };
  const schema = validateSchema("DiscoveryScanParams", params);
  if (!schema.ok || !checkSemantics("DiscoveryScanParams", schema.value).ok) return { ok: false };
  return { ok: true, params: schema.value };
}

export type ScanRequestOutcome =
  | { outcome: "queued"; jobId: string }
  /** Unknown agent or target, agent revoked / locked, target no longer reported. */
  | { outcome: "not_found" }
  /** The agent has not reported its classifiers version yet (required by the job). */
  | { outcome: "not_ready" }
  /** A scan of this target is already pending, delivered or running. */
  | { outcome: "busy" };

const OPEN_STATUSES = ["pending", "delivered", "running"] as const;

export async function requestScan(
  db: Database,
  agentId: string,
  targetId: string,
  params: DiscoveryScanParams,
  actor: { userId: string; ip: string | null },
): Promise<ScanRequestOutcome> {
  const result = await db.transaction(async (tx): Promise<ScanRequestOutcome> => {
    // Serializes scan requests of the agent (one open scan per target).
    const [agent] = await tx
      .select({
        id: agents.id,
        revokedAt: agents.revokedAt,
        lockedAt: agents.lockedAt,
        classifiersVersion: agents.classifiersVersion,
      })
      .from(agents)
      .where(eq(agents.id, agentId))
      .for("update")
      .limit(1);
    if (!agent || agent.revokedAt || agent.lockedAt) return { outcome: "not_found" };
    const [target] = await tx
      .select({ present: agentTargets.present })
      .from(agentTargets)
      .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)))
      .limit(1);
    if (!target?.present) return { outcome: "not_found" };
    const version = agent.classifiersVersion;
    if (!version || !validateSchema("ClassifiersVersion", version).ok) return { outcome: "not_ready" };
    await sweepDeadScans(tx, agentId);
    const [open] = await tx
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.agentId, agentId),
          eq(jobs.type, "discovery.scan"),
          eq(jobs.targetId, targetId),
          inArray(jobs.status, [...OPEN_STATUSES]),
        ),
      )
      .limit(1);
    if (open) return { outcome: "busy" };
    const [job] = await tx
      .insert(jobs)
      .values({
        agentId,
        type: "discovery.scan",
        targetId,
        classifiersVersion: version,
        params: { ...params },
        expiresAt: new Date(Date.now() + SCAN_JOB_TTL_MS),
        createdBy: actor.userId,
      })
      .returning({ id: jobs.id });
    if (!job) throw new Error("job insert returned no row");
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "discovery.scan_request",
      targetType: "job",
      targetId: job.id,
      sourceIp: actor.ip,
      details: {
        agent_id: agentId,
        target_id: targetId,
        sample_rows: params.sample_rows,
        max_duration_s: params.max_duration_s,
        statement_timeout_ms: params.statement_timeout_ms ?? null,
        filtered: ["databases", "schemas", "include_objects", "exclude_objects", "classifiers"].some(
          (k) => k in params,
        ),
      },
    });
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    return { outcome: "queued", jobId: job.id };
  });
  if (result.outcome !== "queued") {
    await writeAudit(db, {
      actorType: "user",
      actorId: actor.userId,
      action: "discovery.scan_request",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
      details: { target_id: targetId, reason: result.outcome },
    });
  }
  return result;
}

export interface ScanJobView {
  id: string;
  status: string;
  createdAt: Date;
  finishedAt: Date | null;
  progress: Record<string, number> | null;
  errorCode: string | null;
}

/** Latest scan job of each target of an agent (agent detail page). */
export async function latestScans(db: Database, agentId: string): Promise<Map<string, ScanJobView>> {
  const rows = await db
    .selectDistinctOn([jobs.targetId], {
      targetId: jobs.targetId,
      id: jobs.id,
      status: jobs.status,
      createdAt: jobs.createdAt,
      finishedAt: jobs.finishedAt,
      progress: jobs.progress,
      error: jobs.error,
    })
    .from(jobs)
    .where(and(eq(jobs.agentId, agentId), eq(jobs.type, "discovery.scan")))
    .orderBy(jobs.targetId, desc(jobs.createdAt));
  const out = new Map<string, ScanJobView>();
  for (const r of rows) {
    if (r.targetId === null) continue;
    out.set(r.targetId, {
      id: r.id,
      status: r.status,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
      progress: r.progress ?? null,
      errorCode: r.error?.code ?? null,
    });
  }
  return out;
}
