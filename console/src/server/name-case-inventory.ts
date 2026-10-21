import { and, desc, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { auditLog } from "@/db/schema";
import { errorSummary, type Logger } from "@/lib/logger";
import { canonicalNameCase, NAME_CASE_ENGINES, nameCaseDisplay, type NameCaseRule } from "@/lib/name-case";

import { writeAudit } from "./audit";
import { computeCaseInventory, errorCode, inventoryDetails, parseInventoryDetails, runLocked, type InventoryResult, type LatestInventory } from "./exception-case-inventory";

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

/**
 * ADR-0055 decision 7: the stored `name_case` of each target, and the ADR-0054 decision 6
 * inventory of a target when its effective rule changes.
 *
 * - **Compare-and-set** (L8): the heartbeat's transaction writes the canonical value only when it
 *   differs from the stored one (`is distinct from` on `jsonb`, whose equality ignores key order;
 *   `except` is canonically sorted and merged, #301 review L2), and in the same statement marks the
 *   target's inventory due. Concurrent heartbeats of one target (several console replicas) update
 *   the same row: the second waits for the first's row lock, re-reads the row and no longer
 *   differs, so exactly one transaction sees each change.
 * - **Debounce** (M2): the worker runs a due target's inventory at most once per target and hour
 *   (`name_case_inventory_at`); changes within the hour keep the target due (the earliest due time is
 *   kept) and are coalesced into the next run, which reads the value stored at that time. The run is
 *   claimed by a compare-and-set too (`for update skip locked`), so two workers never run one target.
 * - The run is the ADR-0054 inventory restricted to the target (same bounds, JavaScript comparison,
 *   ids and counts only) under the same advisory lock, recorded in one audit entry
 *   (`policy_exception.name_case_inventory`, actor `system`) with the target's ids, the counts and
 *   the closed display value of its rule; a failed run in a failure entry with an error code only.
 */

/** Audit action of a per-target run (apart from the startup / on-demand `policy_exception.case_inventory`). */
export const NAME_CASE_INVENTORY_ACTION = "policy_exception.name_case_inventory";
/** At most one inventory per target in this interval (M2). */
export const NAME_CASE_DEBOUNCE_MS = 3_600_000;
/** Targets taken per worker job; the rest wait for the next one. */
export const NAME_CASE_TARGETS_PER_RUN = 20;

/**
 * Stores the canonical `name_case` of one target of a heartbeat (already upserted in `tx`), with a
 * compare-and-set; `true` when this transaction changed it (its first value, a change of any
 * value, or its loss) and marked the inventory due. A value on an engine other than `mysql`,
 * `mariadb` and `sqlserver` (the schema refuses it) is stored as none.
 */
export async function storeNameCase(tx: Tx, agentId: string, targetId: string, engine: string, value: unknown): Promise<boolean> {
  const rule = NAME_CASE_ENGINES.includes(engine) ? canonicalNameCase(value) : null;
  const json = rule === null ? null : JSON.stringify(rule);
  const res = await tx.execute<{ target_id: string }>(sql`
    update agent_targets
    set name_case = ${json}::jsonb,
      name_case_changed_at = now(),
      name_case_inventory_due_at = coalesce(name_case_inventory_due_at, now())
    where agent_id = ${agentId}::uuid and target_id = ${targetId}::text and name_case is distinct from ${json}::jsonb
    returning target_id`);
  return res.rows.length > 0;
}

interface Claimed {
  agentId: string;
  targetId: string;
  previousAt: Date | null;
  dueAt: Date;
}

/** Takes the due targets whose last run is an hour old or more: due cleared, run time set. */
async function claimDue(db: Database, limit: number): Promise<Claimed[]> {
  const res = await db.execute<{ agent_id: string; target_id: string; prev: Date | string | null; due: Date | string }>(sql`
    with due as (
      select agent_id, target_id, name_case_inventory_at as prev, name_case_inventory_due_at as due
      from agent_targets
      where name_case_inventory_due_at is not null
        and (name_case_inventory_at is null or name_case_inventory_at <= now() - make_interval(secs => ${NAME_CASE_DEBOUNCE_MS / 1000}::int))
      order by name_case_inventory_due_at, agent_id, target_id
      limit ${limit}
      for update skip locked
    )
    update agent_targets t
    set name_case_inventory_due_at = null, name_case_inventory_at = now()
    from due
    where t.agent_id = due.agent_id and t.target_id = due.target_id
    returning t.agent_id, t.target_id, due.prev, due.due`);
  return res.rows.map((r) => ({
    agentId: r.agent_id,
    targetId: r.target_id,
    previousAt: r.prev === null ? null : new Date(r.prev),
    dueAt: new Date(r.due),
  }));
}

/**
 * Puts a claimed target back: due again (the earliest due time kept). After a busy lock its
 * previous run time is restored (taken by the next job); after a failure the run time stays, so
 * the target is retried an hour later, never in a loop.
 */
async function unclaim(db: Database, c: Claimed, restoreRunTime: boolean): Promise<void> {
  const due = sql`least(coalesce(name_case_inventory_due_at, ${c.dueAt}::timestamptz), ${c.dueAt}::timestamptz)`;
  await db.execute(
    restoreRunTime
      ? sql`update agent_targets set name_case_inventory_due_at = ${due}, name_case_inventory_at = ${c.previousAt}::timestamptz
          where agent_id = ${c.agentId}::uuid and target_id = ${c.targetId}::text`
      : sql`update agent_targets set name_case_inventory_due_at = ${due}
          where agent_id = ${c.agentId}::uuid and target_id = ${c.targetId}::text`,
  );
}

export interface NameCaseRunStats {
  ran: number;
  failed: number;
  busy: number;
}

/**
 * Runs the inventory of every due target (at most `limit`), once per target and hour. Never throws:
 * a failed run is audited (error code only) and the target waits for the next hour; a run that
 * finds the advisory lock held puts the target back for the next job.
 */
export async function runDueNameCaseInventories(
  db: Database,
  log: Logger,
  opts: { limit?: number; bound?: number; comparisonBudget?: number } = {},
): Promise<NameCaseRunStats> {
  const stats: NameCaseRunStats = { ran: 0, failed: 0, busy: 0 };
  let claimed: Claimed[];
  try {
    claimed = await claimDue(db, opts.limit ?? NAME_CASE_TARGETS_PER_RUN);
  } catch (err) {
    log.warn({ error_code: errorCode(err) }, "name case inventory: due targets not read");
    return stats;
  }
  for (const c of claimed) {
    try {
      const r = await runLocked(db, async (tx) => {
        const rule = await storedRule(tx, c);
        const res = await computeCaseInventory(tx, { scope: c, bound: opts.bound, comparisonBudget: opts.comparisonBudget });
        await writeAudit(tx, {
          actorType: "system",
          action: NAME_CASE_INVENTORY_ACTION,
          targetType: "agent_target",
          targetId: c.agentId,
          details: { ...inventoryDetails(res, "name_case"), agent_id: c.agentId, target_id: c.targetId, name_case: nameCaseDisplay(rule) },
        });
        return res;
      });
      if (r === "busy" || r === null) {
        stats.busy += 1;
        await unclaim(db, c, true);
        continue;
      }
      stats.ran += 1;
      logRun(log, c, r);
    } catch (err) {
      stats.failed += 1;
      await recordFailure(db, log, c, errorCode(err));
      await unclaim(db, c, false).catch((e: unknown) => log.warn({ error_code: errorCode(e) }, "name case inventory: target not put back"));
    }
  }
  return stats;
}

async function storedRule(tx: Tx, c: Claimed): Promise<NameCaseRule | null> {
  const res = await tx.execute<{ name_case: unknown }>(
    sql`select name_case from agent_targets where agent_id = ${c.agentId}::uuid and target_id = ${c.targetId}::text`,
  );
  return canonicalNameCase(res.rows[0]?.name_case ?? null);
}

async function recordFailure(db: Database, log: Logger, c: Claimed, code: string): Promise<void> {
  log.warn({ trigger: "name_case", agent_id: c.agentId, target_id: c.targetId, error_code: code }, "name case inventory failed");
  try {
    await writeAudit(db, {
      actorType: "system",
      action: NAME_CASE_INVENTORY_ACTION,
      outcome: "failure",
      targetType: "agent_target",
      targetId: c.agentId,
      details: { trigger: "name_case", agent_id: c.agentId, target_id: c.targetId, error_code: code },
    });
  } catch (err) {
    log.warn({ error: errorSummary(err) }, "name case inventory failure not audited");
  }
}

function logRun(log: Logger, c: Claimed, r: InventoryResult): void {
  const details = { ...inventoryDetails(r, "name_case"), agent_id: c.agentId, target_id: c.targetId };
  if (r.entries.length > 0 || r.boundReached) {
    log.warn(details, "location exceptions that no longer cover names of this target differing by case only (ADR-0055): review them on the policies page");
  } else {
    log.info(details, "name case inventory: no exception affected (ADR-0055)");
  }
}

/** The latest per-target inventory (success or failure) of each target of `agentId`, by target id. */
export async function latestNameCaseInventories(db: Database, agentId: string): Promise<Map<string, LatestNameCaseInventory>> {
  const rows = await db
    .selectDistinctOn([sql`${auditLog.details}->>'target_id'`], { at: auditLog.at, outcome: auditLog.outcome, details: auditLog.details })
    .from(auditLog)
    .where(and(eq(auditLog.action, NAME_CASE_INVENTORY_ACTION), eq(auditLog.targetId, agentId), sql`${auditLog.details}->>'agent_id' = ${agentId}::text`))
    .orderBy(sql`${auditLog.details}->>'target_id'`, desc(auditLog.at), desc(auditLog.id));
  const out = new Map<string, LatestNameCaseInventory>();
  for (const r of rows) {
    const d = r.details ?? {};
    if (typeof d.target_id !== "string") continue;
    out.set(d.target_id, r.outcome === "success" ? { ok: true, inventory: parseInventoryDetails(r.at, d) } : { ok: false, at: r.at });
  }
  return out;
}

export type LatestNameCaseInventory = { ok: true; inventory: LatestInventory } | { ok: false; at: Date };
