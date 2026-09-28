import { and, asc, desc, eq, gt, inArray, or, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, findings, incidents, jobs, policies, policyExceptions, users } from "@/db/schema";
import { errorSummary, logger } from "@/lib/logger";
import {
  ACTIVE_STATUSES,
  canTransition,
  exceptionCovers,
  findingMatches,
  incidentSeverityOf,
  notifyChannelsOf,
  parsePolicyActions,
  parsePolicyConditions,
  type ExceptionScope,
  type FindingConditions,
  type FindingFacts,
  type IncidentStatus,
  type LocationPattern,
  type Severity,
} from "@/lib/policy-model";

import { writeAudit } from "./audit";
import { applyFalsePositive, fpResetNeeded, type Tx } from "./findings";

/**
 * Policy engine (P3-A, worker) and incidents (P3-B).
 *
 * Evaluation is driven by durable markers, so it is idempotent and survives lost queue jobs:
 * - a finding is pending while `policy_evaluated_at` differs from `last_seen_at` (every rescan
 *   changes `last_seen_at`; unmarking a false positive clears the marker);
 * - a policy needs a full pass over the existing findings while `evaluated_at` is null, older than
 *   `changed_at` (edit, enablement, exception deleted) or older than the expiry of one of its
 *   exceptions.
 * Each chunk of findings is processed in one transaction holding the findings' row locks, so an
 * ingestion or a false-positive marking of the same finding is serialized with its evaluation.
 *
 * Dedup: `dedup_key = policy:<id>|finding:<id>`; a partial unique index allows one open or
 * acknowledged incident per key. A re-match of an active incident only bumps `match_count` (once
 * per finding revision). After `resolved`, a new incident opens when a scan claimed after the
 * resolution still sees the finding, or when the finding changed the way that also resets a false
 * positive (more values matched, or another classifier set); see `reopensResolved`. A
 * false-positive finding never raises an incident.
 *
 * Nothing here reads or stores a sampled value: masked samples stay encrypted on the finding row.
 */

export const EVALUATION_CHUNK = 200;

interface LoadedPolicy {
  id: string;
  name: string;
  revision: number;
  conditions: FindingConditions;
  severity: Severity;
  notifyChannels: string[];
}

const log = logger.child({ component: "policy-engine" });

async function loadEnabledPolicies(db: Database | Tx, ids?: string[]): Promise<LoadedPolicy[]> {
  const rows = await db
    .select({
      id: policies.id,
      name: policies.name,
      revision: policies.revision,
      source: policies.source,
      conditions: policies.conditions,
      actions: policies.actions,
    })
    .from(policies)
    .where(and(eq(policies.enabled, true), ids ? inArray(policies.id, ids) : undefined));
  const out: LoadedPolicy[] = [];
  for (const r of rows) {
    // Documents are validated on write; a document that no longer validates (e.g. a classifier
    // removed from the registry) is skipped, never half-applied.
    const conditions = parsePolicyConditions(r.source, r.conditions);
    const actions = parsePolicyActions(r.actions);
    if (!conditions.ok || !actions.ok) {
      log.error({ policyId: r.id }, "policy document does not validate: skipped");
      continue;
    }
    out.push({
      id: r.id,
      name: r.name,
      revision: r.revision,
      conditions: conditions.value,
      severity: incidentSeverityOf(actions.value),
      notifyChannels: notifyChannelsOf(actions.value),
    });
  }
  return out;
}

async function loadExceptions(db: Database | Tx): Promise<ExceptionScope[]> {
  const rows = await db
    .select({
      policyId: policyExceptions.policyId,
      agentId: policyExceptions.agentId,
      targetId: policyExceptions.targetId,
      classifier: policyExceptions.classifier,
      location: policyExceptions.location,
      expiresAt: policyExceptions.expiresAt,
    })
    .from(policyExceptions);
  return rows.map((r) => ({ ...r, location: (r.location as LocationPattern | null) ?? null }));
}

const FACT_COLUMNS = {
  id: findings.id,
  agentId: findings.agentId,
  targetId: findings.targetId,
  engine: findings.engine,
  databaseName: findings.databaseName,
  schemaName: findings.schemaName,
  objectName: findings.objectName,
  fieldName: findings.fieldName,
  classifier: findings.classifier,
  classifiersVersion: findings.classifiersVersion,
  confidence: findings.confidence,
  sampled: findings.sampled,
  matched: findings.matched,
  lastSeenAt: findings.lastSeenAt,
  falsePositiveAt: findings.falsePositiveAt,
  /**
   * N1: first delivery (console clock) of the scan job that produced the latest revision; no
   * value of that revision was read before it. Null for a job that is gone (then `last_seen_at`).
   * A scalar subquery, so the `FOR UPDATE` of the callers only locks the findings rows.
   */
  scanClaimedAt: sql<Date | null>`(select coalesce(${jobs.firstDeliveredAt}, ${jobs.deliveredAt}) from ${jobs} where ${jobs.id} = ${findings.lastJobId})`.mapWith(
    jobs.deliveredAt,
  ),
};

type FindingRow = FindingFacts & {
  id: string;
  classifiersVersion: string;
  lastSeenAt: Date;
  scanClaimedAt: Date | null;
  falsePositiveAt: Date | null;
};

/**
 * M1: `resolved` means remediated. A resolved incident is followed by a new one when a scan that
 * read the data after the resolution still sees the finding, or when the finding matches more
 * values or is classified by another classifier set (the false-positive reset rule). Durable
 * suppression is an administrator decision: a false positive or an exception.
 *
 * N1: "read after the resolution" is decided on the console-side claim time of the scan job that
 * produced the latest revision (`jobs.first_delivered_at`, database clock, like `resolved_at`): the
 * agent cannot read anything for a job before fetching it. The ingestion time (`last_seen_at`) is
 * not used, as a scan in flight during the resolution would otherwise reopen at once with data read
 * before it. Without a job (deleted), `last_seen_at` is the fallback.
 */
export function reopensResolved(
  incident: { resolvedAt: Date | null; findingMatched: number | null; findingClassifiersVersion: string | null },
  f: { lastSeenAt: Date; scanClaimedAt?: Date | null; matched: number; classifiersVersion: string },
): boolean {
  const readFrom = f.scanClaimedAt ?? f.lastSeenAt;
  if (incident.resolvedAt === null || readFrom.getTime() > incident.resolvedAt.getTime()) return true;
  return fpResetNeeded(
    { falsePositiveMatched: incident.findingMatched, falsePositiveClassifiersVersion: incident.findingClassifiersVersion },
    f.matched,
    f.classifiersVersion,
  );
}

export const dedupKey = (policyId: string, findingId: string) => `policy:${policyId}|finding:${findingId}`;

type ApplyResult = "created" | "rematched" | "unchanged" | "suppressed" | "excepted" | "no_match";

/** Applies one policy to one locked, non-false-positive finding. */
async function applyPolicy(
  tx: Tx,
  policy: LoadedPolicy,
  f: FindingRow,
  exceptions: readonly ExceptionScope[],
  now: Date,
): Promise<ApplyResult> {
  if (!findingMatches(policy.conditions, f)) return "no_match";
  if (exceptions.some((e) => exceptionCovers(e, policy.id, f, now))) return "excepted";
  const key = dedupKey(policy.id, f.id);
  const readLatest = async () =>
    (
      await tx
        .select({
          id: incidents.id,
          status: incidents.status,
          findingMatched: incidents.findingMatched,
          findingClassifiersVersion: incidents.findingClassifiersVersion,
          resolvedAt: incidents.resolvedAt,
        })
        .from(incidents)
        .where(eq(incidents.dedupKey, key))
        .orderBy(desc(incidents.createdAt), desc(incidents.id))
        .limit(1)
    )[0];
  let latest = await readLatest();
  if (latest && (ACTIVE_STATUSES as readonly string[]).includes(latest.status)) {
    // One bump per finding revision: re-evaluating the same revision changes nothing.
    const updated = await tx
      .update(incidents)
      .set({
        matchCount: sql`${incidents.matchCount} + 1`,
        lastFindingSeenAt: f.lastSeenAt,
        findingMatched: f.matched,
        findingClassifiersVersion: f.classifiersVersion,
        updatedAt: sql`now()`,
      })
      .where(
        and(
          eq(incidents.id, latest.id),
          inArray(incidents.status, ["open", "acknowledged"]),
          or(sql`${incidents.lastFindingSeenAt} is null`, sql`${incidents.lastFindingSeenAt} < ${f.lastSeenAt}`),
        ),
      )
      .returning({ id: incidents.id });
    if (updated.length > 0) return "rematched";
    // L3: nothing updated. Either this revision was already counted, or the incident was closed
    // concurrently (e.g. resolved): re-read, and apply the closed-incident rules in that case.
    latest = await readLatest();
    if (latest && (ACTIVE_STATUSES as readonly string[]).includes(latest.status)) return "unchanged";
  }
  if (latest?.status === "resolved" && !reopensResolved(latest, f)) return "suppressed";
  const inserted = await tx
    .insert(incidents)
    .values({
      dedupKey: key,
      source: "finding",
      policyId: policy.id,
      policyName: policy.name,
      policyRevision: policy.revision,
      severity: policy.severity,
      notifyChannels: policy.notifyChannels,
      findingId: f.id,
      agentId: f.agentId,
      targetId: f.targetId,
      classifier: f.classifier,
      findingMatched: f.matched,
      findingClassifiersVersion: f.classifiersVersion,
      lastFindingSeenAt: f.lastSeenAt,
    })
    .onConflictDoNothing({
      target: incidents.dedupKey,
      where: sql`${incidents.status} in ('open', 'acknowledged')`,
    })
    .returning({ id: incidents.id });
  const row = inserted[0];
  if (!row) return "unchanged";
  await writeAudit(tx, {
    actorType: "system",
    action: "incident.create",
    targetType: "incident",
    targetId: row.id,
    details: {
      policy_id: policy.id,
      policy_revision: policy.revision,
      finding_id: f.id,
      agent_id: f.agentId,
      target_id: f.targetId,
      classifier: f.classifier,
      severity: policy.severity,
    },
  });
  return "created";
}

export interface DrainStats {
  findings: number;
  policyPasses: number;
  created: number;
  /** Work remains (time budget reached, or findings locked by a concurrent writer). */
  more: boolean;
}

/**
 * Drains the pending policy work within `budgetMs`: full passes of changed policies first, then the
 * pending findings. Safe to run concurrently and repeatedly (row locks, skip-locked, dedup index).
 */
export async function drainPolicyWork(db: Database, opts: { budgetMs?: number } = {}): Promise<DrainStats> {
  const deadline = Date.now() + (opts.budgetMs ?? 50_000);
  const stats: DrainStats = { findings: 0, policyPasses: 0, created: 0, more: false };
  const count = (results: ApplyResult[]) => {
    stats.created += results.filter((r) => r === "created").length;
  };

  // 1. Full passes: policies changed since their last pass, or with an exception expired since.
  const stale = await db
    .select({ id: policies.id })
    .from(policies)
    .where(
      and(
        eq(policies.enabled, true),
        sql`(${policies.evaluatedAt} is null or ${policies.evaluatedAt} < ${policies.changedAt} or exists (
          select 1 from ${policyExceptions} e
          where (e.policy_id = ${policies.id} or e.policy_id is null)
            and e.expires_at > ${policies.evaluatedAt} and e.expires_at <= now()))`,
      ),
    )
    .orderBy(asc(policies.changedAt));
  for (const { id } of stale) {
    if (Date.now() > deadline) {
      stats.more = true;
      return stats;
    }
    const done = await fullPass(db, id, deadline, count);
    stats.policyPasses += 1;
    // L4: an incomplete pass (rows locked by a writer, time budget) leaves the policy pending, but
    // never holds back the pending findings below.
    if (!done) stats.more = true;
  }

  // 2. Pending findings, against every enabled policy.
  for (;;) {
    if (Date.now() > deadline) {
      stats.more = true;
      return stats;
    }
    const processed = await db.transaction(async (tx) => {
      const rows = await tx
        .select(FACT_COLUMNS)
        .from(findings)
        .where(sql`${findings.policyEvaluatedAt} is distinct from ${findings.lastSeenAt}`)
        .orderBy(asc(findings.id))
        .limit(EVALUATION_CHUNK)
        .for("update", { skipLocked: true });
      if (rows.length === 0) return 0;
      const [{ now } = { now: new Date() }] = (await tx.execute(sql`select now() as now`)).rows as { now: Date }[];
      const active = await loadEnabledPolicies(tx);
      const exceptions = await loadExceptions(tx);
      for (const f of rows) {
        if (f.falsePositiveAt === null) {
          const results: ApplyResult[] = [];
          for (const p of active) results.push(await applyPolicy(tx, p, f, exceptions, new Date(now)));
          count(results);
        }
        await tx.update(findings).set({ policyEvaluatedAt: f.lastSeenAt }).where(eq(findings.id, f.id));
      }
      return rows.length;
    });
    stats.findings += processed;
    if (processed < EVALUATION_CHUNK) {
      // Rows locked by a concurrent writer were skipped: they are still pending.
      const [left] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(findings)
        .where(sql`${findings.policyEvaluatedAt} is distinct from ${findings.lastSeenAt}`);
      stats.more = stats.more || (left?.n ?? 0) > 0;
      return stats;
    }
  }
}

/**
 * Applies one policy to every existing finding (id order, chunked). Records `evaluated_at` = the
 * pass start (database clock) only when the pass saw every finding: a change during the pass, or a
 * finding locked by a concurrent writer, leaves the policy pending.
 */
async function fullPass(
  db: Database,
  policyId: string,
  deadline: number,
  count: (r: ApplyResult[]) => void,
): Promise<boolean> {
  const startRes = await db.execute(sql`select now() as now`);
  const startedAt = new Date((startRes.rows[0] as { now: Date | string }).now);
  let cursor: string | null = null;
  let complete = true;
  for (;;) {
    if (Date.now() > deadline) return false;
    const result: { rows: number; last: string | null; skipped: boolean } = await db.transaction(async (tx) => {
      const [policy] = await loadEnabledPolicies(tx, [policyId]);
      if (!policy) return { rows: 0, last: null, skipped: false };
      const exceptions = await loadExceptions(tx);
      const ids = await tx
        .select({ id: findings.id })
        .from(findings)
        .where(cursor ? gt(findings.id, cursor) : undefined)
        .orderBy(asc(findings.id))
        .limit(EVALUATION_CHUNK);
      if (ids.length === 0) return { rows: 0, last: null, skipped: false };
      const idList = ids.map((r) => r.id);
      const locked = await tx
        .select(FACT_COLUMNS)
        .from(findings)
        .where(inArray(findings.id, idList))
        .orderBy(asc(findings.id))
        .for("update", { skipLocked: true });
      const results: ApplyResult[] = [];
      for (const f of locked) {
        if (f.falsePositiveAt === null) results.push(await applyPolicy(tx, policy, f, exceptions, startedAt));
      }
      count(results);
      return { rows: ids.length, last: idList[idList.length - 1] ?? null, skipped: locked.length < ids.length };
    });
    if (result.skipped) complete = false;
    if (result.rows < EVALUATION_CHUNK) break;
    cursor = result.last;
  }
  if (!complete) return false;
  await db
    .update(policies)
    .set({ evaluatedAt: startedAt })
    .where(and(eq(policies.id, policyId), sql`${policies.changedAt} <= ${startedAt}`));
  return true;
}

// ------------------------------------------------------------------------ lifecycle

export type TransitionOutcome =
  | { outcome: "ok"; from: IncidentStatus }
  | { outcome: "not_found" }
  | { outcome: "invalid_transition"; from: IncidentStatus };

/**
 * Moves an incident to `to` (P3-B), validated server side against the lifecycle, with actor and
 * timestamp, audited (`incident.transition`, refused transitions as failures). `false_positive`
 * (admin, checked by the caller) is the finding's false-positive decision: it marks the linked
 * finding and closes every active incident of it (see `applyFalsePositive`).
 */
export async function transitionIncident(
  db: Database,
  incidentId: string,
  to: IncidentStatus,
  actor: { userId: string; ip: string | null },
): Promise<TransitionOutcome> {
  return db.transaction(async (tx) => {
    // L1: same lock order as the policy engine and the findings writers: the finding first, then
    // the incident. `finding_id` only ever changes to null (finding deleted), which is re-checked.
    const [link] = await tx.select({ findingId: incidents.findingId }).from(incidents).where(eq(incidents.id, incidentId));
    if (link?.findingId) {
      await tx.select({ id: findings.id }).from(findings).where(eq(findings.id, link.findingId)).for("update");
    }
    const [current] = await tx
      .select({ status: incidents.status, findingId: incidents.findingId })
      .from(incidents)
      .where(eq(incidents.id, incidentId))
      .for("update");
    const audit = (outcome: "success" | "failure", details: Record<string, string | null>) =>
      writeAudit(tx, {
        actorType: "user",
        actorId: actor.userId,
        action: "incident.transition",
        outcome,
        targetType: "incident",
        targetId: incidentId,
        sourceIp: actor.ip,
        details,
      });
    if (!current) {
      await audit("failure", { to, reason: "not_found" });
      return { outcome: "not_found" as const };
    }
    if (!canTransition(current.status, to)) {
      await audit("failure", { from: current.status, to, reason: "invalid_transition" });
      return { outcome: "invalid_transition" as const, from: current.status };
    }
    if (to === "false_positive" && current.findingId !== null) {
      // Audits the finding mark and the transition of every active incident of the finding.
      const marked = await applyFalsePositive(tx, current.findingId, true, actor, { incidentId });
      if (marked) return { outcome: "ok" as const, from: current.status };
    }
    const stamp =
      to === "acknowledged"
        ? { acknowledgedAt: sql`now()`, acknowledgedBy: actor.userId }
        : to === "resolved"
          ? { resolvedAt: sql`now()`, resolvedBy: actor.userId }
          : to === "false_positive"
            ? { falsePositiveAt: sql`now()`, falsePositiveBy: actor.userId }
            : {};
    await tx
      .update(incidents)
      .set({ status: to, updatedAt: sql`now()`, ...stamp })
      .where(eq(incidents.id, incidentId));
    await audit("success", { from: current.status, to, finding_id: current.findingId });
    return { outcome: "ok" as const, from: current.status };
  });
}

// ----------------------------------------------------------------------------- views

export const MAX_LISTED_INCIDENTS = 500;

export interface IncidentFilter {
  statuses?: IncidentStatus[];
  severity?: Severity;
  agentId?: string;
  targetId?: string;
}

export interface IncidentView {
  id: string;
  status: IncidentStatus;
  severity: Severity;
  policyId: string | null;
  policyName: string;
  policyRevision: number;
  source: string;
  findingId: string | null;
  agentId: string | null;
  agentName: string | null;
  targetId: string | null;
  classifier: string | null;
  location: { databaseName: string; schemaName: string | null; objectName: string; fieldName: string } | null;
  findingMatched: number | null;
  matchCount: number;
  notifyChannels: string[];
  createdAt: Date;
  updatedAt: Date;
  acknowledgedAt: Date | null;
  acknowledgedBy: string | null;
  resolvedAt: Date | null;
  resolvedBy: string | null;
  falsePositiveAt: Date | null;
  falsePositiveBy: string | null;
}

const SEVERITY_RANK = sql`case ${incidents.severity} when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end`;

function incidentWhere(filter: IncidentFilter): SQL | undefined {
  const conds: SQL[] = [];
  if (filter.statuses && filter.statuses.length > 0) conds.push(inArray(incidents.status, filter.statuses));
  if (filter.severity) conds.push(eq(incidents.severity, filter.severity));
  if (filter.agentId) conds.push(eq(incidents.agentId, filter.agentId));
  if (filter.targetId) conds.push(eq(incidents.targetId, filter.targetId));
  return conds.length > 0 ? and(...conds) : undefined;
}

async function selectIncidents(db: Database, where: SQL | undefined, limit: number): Promise<IncidentView[]> {
  const rows = await db
    .select({
      id: incidents.id,
      status: incidents.status,
      severity: incidents.severity,
      policyId: incidents.policyId,
      policyName: incidents.policyName,
      policyRevision: incidents.policyRevision,
      source: incidents.source,
      findingId: incidents.findingId,
      agentId: incidents.agentId,
      agentName: agents.name,
      targetId: incidents.targetId,
      classifier: incidents.classifier,
      databaseName: findings.databaseName,
      schemaName: findings.schemaName,
      objectName: findings.objectName,
      fieldName: findings.fieldName,
      findingMatched: incidents.findingMatched,
      matchCount: incidents.matchCount,
      notifyChannels: incidents.notifyChannels,
      createdAt: incidents.createdAt,
      updatedAt: incidents.updatedAt,
      acknowledgedAt: incidents.acknowledgedAt,
      acknowledgedBy: sql<string | null>`(select ${users.username} from ${users} where ${users.id} = ${incidents.acknowledgedBy})`,
      resolvedAt: incidents.resolvedAt,
      resolvedBy: sql<string | null>`(select ${users.username} from ${users} where ${users.id} = ${incidents.resolvedBy})`,
      falsePositiveAt: incidents.falsePositiveAt,
      falsePositiveBy: sql<string | null>`(select ${users.username} from ${users} where ${users.id} = ${incidents.falsePositiveBy})`,
    })
    .from(incidents)
    .leftJoin(agents, eq(agents.id, incidents.agentId))
    .leftJoin(findings, eq(findings.id, incidents.findingId))
    .where(where)
    .orderBy(SEVERITY_RANK, desc(incidents.createdAt), asc(incidents.id))
    .limit(limit);
  return rows.map(({ databaseName, schemaName, objectName, fieldName, ...r }) => ({
    ...r,
    location:
      databaseName !== null && objectName !== null && fieldName !== null
        ? { databaseName, schemaName, objectName, fieldName }
        : null,
  }));
}

export function listIncidents(db: Database, filter: IncidentFilter = {}): Promise<IncidentView[]> {
  return selectIncidents(db, incidentWhere(filter), MAX_LISTED_INCIDENTS);
}

export async function getIncident(db: Database, id: string): Promise<IncidentView | null> {
  const [row] = await selectIncidents(db, eq(incidents.id, id), 1);
  return row ?? null;
}

/** Counts of active incidents per severity (navigation badge, list header). */
export async function activeIncidentCounts(db: Database): Promise<Record<Severity, number>> {
  const rows = await db
    .select({ severity: incidents.severity, n: sql<number>`count(*)::int` })
    .from(incidents)
    .where(inArray(incidents.status, ["open", "acknowledged"]))
    .groupBy(incidents.severity);
  const out: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const r of rows) out[r.severity] = r.n;
  return out;
}

/** Worker entry point: drains, logs a summary (counts only), and reports whether work remains. */
export async function runPolicyEvaluation(db: Database, budgetMs?: number): Promise<boolean> {
  try {
    const stats = await drainPolicyWork(db, { budgetMs });
    if (stats.findings > 0 || stats.policyPasses > 0) log.info({ ...stats }, "policy evaluation");
    return stats.more;
  } catch (err) {
    log.error({ error: errorSummary(err) }, "policy evaluation failed");
    throw err;
  }
}
