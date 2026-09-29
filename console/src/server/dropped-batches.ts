import { and, gt, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, securityEvents } from "@/db/schema";
import { logger } from "@/lib/logger";

import { consoleUrl } from "./alerting-config";
import { writeAudit } from "./audit";
import type { Tx } from "./findings";
import { enqueueSystemAlert } from "./notifications";

/**
 * "Dropped batches" alert (P7, end-of-phase-4 review M2). The agent reports in each heartbeat
 * `spool.dropped_batches`: batches dropped since it started (spool full, or rejected with a
 * non-retryable 4xx). A rise means findings or access events that never reached the console, for
 * instance the signature batches of a dump evicted by a failed-login flood.
 *
 * - Each heartbeat adds the rise of the counter (`droppedBatchesDelta`) to
 *   `agents.dropped_batches_unalerted` (and sets `dropped_batches_since` on the first one).
 * - `raiseDroppedBatchesAlert` turns the unalerted count into ONE `security_events` row
 *   (`agent.batches_dropped`, medium), an audit entry (system) and the notifications of the
 *   `system_alerts` channels, at most once per agent and `DROPPED_BATCHES_ALERT_INTERVAL_S`
 *   (conditional update on `dropped_batches_alerted_at`: concurrent heartbeats and workers alert
 *   once). Drops seen within the interval are counted in the next alert: raised by the next
 *   heartbeat after the interval or, if the agent stops dropping, by the worker
 *   (`flushDroppedBatchAlerts`, every minute).
 *
 * Only numbers leave the heartbeat: the delta, console timestamps and ids. Nothing the agent wrote
 * as text (hostname, name) is copied into the event, the audit entry or the notification.
 */

export const DROPPED_BATCHES_ALERT_INTERVAL_S = 3600;
const INT_MAX = 2_147_483_647;

const log = logger.child({ component: "dropped-batches" });

function count(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

/**
 * Batches dropped between two heartbeats. `dropped_batches` counts since agent start: a counter
 * lower than the previous one, or a lower uptime, means a restart, and the whole current value is
 * new. No previous counter (first heartbeat, or an agent build that did not report it): the
 * current value counts since that agent's start, so it is new too. Absent now: 0.
 */
export function droppedBatchesDelta(
  previous: { spool: Record<string, unknown> | null; uptimeS: number | null },
  current: { spool: Record<string, unknown>; uptimeS: number },
): number {
  const now = count(current.spool.dropped_batches);
  if (now === null || now === 0) return 0;
  const before = count(previous.spool?.dropped_batches);
  const restarted = previous.uptimeS !== null && current.uptimeS < previous.uptimeS;
  if (before === null || restarted || now < before) return Math.min(now, INT_MAX);
  return Math.min(now - before, INT_MAX);
}

/**
 * Adds `delta` to the unalerted count of `agentId` (in the heartbeat transaction, after the row
 * was locked by its update). Saturates at the `integer` bound.
 */
export async function addDroppedBatches(tx: Tx, agentId: string, delta: number): Promise<void> {
  if (delta <= 0) return;
  await tx
    .update(agents)
    .set({
      droppedBatchesUnalerted: sql`least(${agents.droppedBatchesUnalerted}::bigint + ${delta}, ${INT_MAX})::int`,
      droppedBatchesSince: sql`coalesce(${agents.droppedBatchesSince}, now())`,
    })
    .where(sql`${agents.id} = ${agentId}`);
}

export interface DroppedBatchesAlert {
  securityEventId: string;
  droppedBatches: number;
  since: string;
}

/**
 * Raises the alert for `agentId` when it has unalerted drops, is neither revoked nor locked and
 * was not alerted within the interval. Returns what was raised, or null. `now`: tests.
 */
export async function raiseDroppedBatchesAlert(tx: Tx, agentId: string, opts: { now?: Date } = {}): Promise<DroppedBatchesAlert | null> {
  const now = opts.now ? sql`${opts.now.toISOString()}::timestamptz` : sql`now()`;
  const res = await tx.execute<{ dropped: number; since: Date | string }>(sql`
    update agents a
       set dropped_batches_unalerted = 0, dropped_batches_since = null, dropped_batches_alerted_at = ${now}
      from (select id, dropped_batches_unalerted as dropped, dropped_batches_since as since
              from agents where id = ${agentId} for update) o
     where a.id = o.id and a.dropped_batches_unalerted > 0
       and a.revoked_at is null and a.locked_at is null
       and (a.dropped_batches_alerted_at is null
            or a.dropped_batches_alerted_at <= ${now} - make_interval(secs => ${DROPPED_BATCHES_ALERT_INTERVAL_S}))
    returning o.dropped, coalesce(o.since, ${now}) as since`);
  const row = res.rows[0];
  if (!row) return null;
  const dropped = Number(row.dropped);
  const since = new Date(row.since).toISOString();
  const details = { dropped_batches: dropped, since, min_interval_s: DROPPED_BATCHES_ALERT_INTERVAL_S };
  const [event] = await tx
    .insert(securityEvents)
    .values({ kind: "agent.batches_dropped", severity: "medium", agentId, details })
    .returning({ id: securityEvents.id, at: securityEvents.at });
  if (!event) throw new Error("security event insert returned no row");
  await writeAudit(tx, {
    actorType: "system",
    action: "agent.batches_dropped",
    targetType: "agent",
    targetId: agentId,
    details: { ...details, security_event_id: event.id },
  });
  await enqueueSystemAlert(tx, {
    // One alert per security event: the conditional update above is the rate limit.
    subjectKey: `agent:${agentId}|batches_dropped:${event.id}`,
    agentId,
    securityEventId: event.id,
    payload: {
      event: "agent.batches_dropped",
      occurred_at: event.at.toISOString(),
      url: consoleUrl(`/agents/${agentId}`),
      agent_id: agentId,
      dropped_batches: dropped,
      since,
      min_interval_s: DROPPED_BATCHES_ALERT_INTERVAL_S,
      security_event_id: event.id,
    },
  });
  log.warn({ agentId, droppedBatches: dropped }, "agent reported dropped batches");
  return { securityEventId: event.id, droppedBatches: dropped, since };
}

/**
 * Worker, every minute: the alerts of drops counted within the interval of a previous alert, once
 * the interval is over (the agent may send no further rise). Returns the number raised.
 */
export async function flushDroppedBatchAlerts(db: Database, opts: { now?: Date; maxAgents?: number } = {}): Promise<number> {
  const now = opts.now ? sql`${opts.now.toISOString()}::timestamptz` : sql`now()`;
  const due = await db
    .select({ id: agents.id })
    .from(agents)
    .where(
      and(
        gt(agents.droppedBatchesUnalerted, 0),
        isNull(agents.revokedAt),
        isNull(agents.lockedAt),
        sql`(${agents.droppedBatchesAlertedAt} is null
             or ${agents.droppedBatchesAlertedAt} <= ${now} - make_interval(secs => ${DROPPED_BATCHES_ALERT_INTERVAL_S}))`,
      ),
    )
    .limit(opts.maxAgents ?? 500);
  let raised = 0;
  for (const { id } of due) {
    if (await db.transaction((tx) => raiseDroppedBatchesAlert(tx, id, opts))) raised++;
  }
  return raised;
}
