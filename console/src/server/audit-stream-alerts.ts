import { and, gt, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, securityEvents } from "@/db/schema";
import { logger } from "@/lib/logger";
import type { StoredTargetNote } from "@/lib/target-notes";

import { consoleUrl } from "./alerting-config";
import { writeAudit } from "./audit";
import type { Tx } from "./findings";
import { enqueueSystemAlert } from "./notifications";

/**
 * "Audit stream stopped" alert (P7, ADR-0031 decision 3, end-of-phase-6 review M2). The agent runs
 * every connector call through a panic guard; an Audit stream that panics 3 times in a row is
 * stopped until Audit is reconfigured or the agent restarts, and its target reports level None
 * with the note `audit.stream_stopped`. Audit of that target has stopped: operators must know.
 *
 * - Each heartbeat counts the targets whose status carries the note, and records it in
 *   `agents.audit_stream_stops_unalerted` (the highest count since the last alert) in the heartbeat
 *   transaction, after the agent row lock. Every heartbeat of a stopped stream counts, not only the
 *   first: the alert is repeated every hour while the stream stays stopped (ADR-0031 review).
 * - `raiseAuditStreamStoppedAlert` turns the unalerted count into ONE `security_events` row
 *   (`agent.audit_stream_stopped`, medium: monitoring of one or more targets is lost, as for a
 *   silent agent or dropped batches, but it is not by itself evidence of an attack), an audit entry
 *   (system) and the notifications of the `system_alerts` channels (within their hourly budget),
 *   at most once per agent and `AUDIT_STREAM_ALERT_INTERVAL_S` (conditional update on
 *   `audit_stream_stops_alerted_at`: concurrent heartbeats and workers alert once). Stops seen
 *   within the interval are reported by the next alert: raised by the next heartbeat after the
 *   interval or, when the agent sends none, by the worker (`flushAuditStreamStoppedAlerts`, every
 *   minute).
 *
 * Only console-computed numbers, timestamps and ids leave the heartbeat: no target id, host name
 * or other text the agent wrote is copied into the event, the audit entry or the notification (the
 * agent page shows which targets carry the note).
 */

export const AUDIT_STREAM_STOPPED_NOTE = "audit.stream_stopped";
export const AUDIT_STREAM_ALERT_INTERVAL_S = 3600;
const INT_MAX = 2_147_483_647;

const log = logger.child({ component: "audit-stream-alerts" });

export function streamStopped(notes: readonly Pick<StoredTargetNote, "code">[] | null | undefined): boolean {
  return (notes ?? []).some((n) => n.code === AUDIT_STREAM_STOPPED_NOTE);
}

/** Targets of a heartbeat reported with a stopped Audit stream (each target id once). */
export function stoppedStreams(targets: readonly { target_id: string; notes?: readonly { code: string }[] }[]): number {
  return new Set(targets.filter((t) => streamStopped(t.notes)).map((t) => t.target_id)).size;
}

/**
 * Records that `n` targets report a stopped stream (heartbeat transaction): the unalerted count
 * becomes the highest seen since the last alert.
 */
export async function recordAuditStreamStops(tx: Tx, agentId: string, n: number): Promise<void> {
  if (n <= 0) return;
  await tx
    .update(agents)
    .set({
      auditStreamStopsUnalerted: sql`greatest(${agents.auditStreamStopsUnalerted}, ${Math.min(n, INT_MAX)}::int)`,
      auditStreamStopsSince: sql`coalesce(${agents.auditStreamStopsSince}, now())`,
    })
    .where(sql`${agents.id} = ${agentId}`);
}

export interface AuditStreamStoppedAlert {
  securityEventId: string;
  stoppedStreams: number;
  since: string;
}

/**
 * Raises the alert for `agentId` when it has unalerted stops, is neither revoked nor locked and was
 * not alerted within the interval. Returns what was raised, or null. `now`: tests.
 */
export async function raiseAuditStreamStoppedAlert(tx: Tx, agentId: string, opts: { now?: Date } = {}): Promise<AuditStreamStoppedAlert | null> {
  const now = opts.now ? sql`${opts.now.toISOString()}::timestamptz` : sql`now()`;
  const res = await tx.execute<{ stopped: number; since: Date | string }>(sql`
    update agents a
       set audit_stream_stops_unalerted = 0, audit_stream_stops_since = null, audit_stream_stops_alerted_at = ${now}
      from (select id, audit_stream_stops_unalerted as stopped, audit_stream_stops_since as since
              from agents where id = ${agentId} for update) o
     where a.id = o.id and a.audit_stream_stops_unalerted > 0
       and a.revoked_at is null and a.locked_at is null
       and (a.audit_stream_stops_alerted_at is null
            or a.audit_stream_stops_alerted_at <= ${now} - make_interval(secs => ${AUDIT_STREAM_ALERT_INTERVAL_S}))
    returning o.stopped, coalesce(o.since, ${now}) as since`);
  const row = res.rows[0];
  if (!row) return null;
  const stopped = Number(row.stopped);
  const since = new Date(row.since).toISOString();
  const details = { stopped_streams: stopped, since, min_interval_s: AUDIT_STREAM_ALERT_INTERVAL_S };
  const [event] = await tx
    .insert(securityEvents)
    .values({ kind: "agent.audit_stream_stopped", severity: "medium", agentId, details })
    .returning({ id: securityEvents.id, at: securityEvents.at });
  if (!event) throw new Error("security event insert returned no row");
  await writeAudit(tx, {
    actorType: "system",
    action: "agent.audit_stream_stopped",
    targetType: "agent",
    targetId: agentId,
    details: { ...details, security_event_id: event.id },
  });
  await enqueueSystemAlert(tx, {
    // One alert per security event: the conditional update above is the rate limit.
    subjectKey: `agent:${agentId}|audit_stream_stopped:${event.id}`,
    agentId,
    securityEventId: event.id,
    payload: {
      event: "agent.audit_stream_stopped",
      occurred_at: event.at.toISOString(),
      url: consoleUrl(`/agents/${agentId}`),
      agent_id: agentId,
      stopped_streams: stopped,
      since,
      min_interval_s: AUDIT_STREAM_ALERT_INTERVAL_S,
      security_event_id: event.id,
    },
  });
  log.warn({ agentId, stoppedStreams: stopped }, "agent reported stopped Audit streams");
  return { securityEventId: event.id, stoppedStreams: stopped, since };
}

/**
 * Worker, every minute: the alerts of stops counted within the interval of a previous alert, once
 * the interval is over. Returns the number raised.
 */
export async function flushAuditStreamStoppedAlerts(db: Database, opts: { now?: Date; maxAgents?: number } = {}): Promise<number> {
  const now = opts.now ? sql`${opts.now.toISOString()}::timestamptz` : sql`now()`;
  const due = await db
    .select({ id: agents.id })
    .from(agents)
    .where(
      and(
        gt(agents.auditStreamStopsUnalerted, 0),
        isNull(agents.revokedAt),
        isNull(agents.lockedAt),
        sql`(${agents.auditStreamStopsAlertedAt} is null
             or ${agents.auditStreamStopsAlertedAt} <= ${now} - make_interval(secs => ${AUDIT_STREAM_ALERT_INTERVAL_S}))`,
      ),
    )
    .limit(opts.maxAgents ?? 500);
  let raised = 0;
  for (const { id } of due) {
    if (await db.transaction((tx) => raiseAuditStreamStoppedAlert(tx, id, opts))) raised++;
  }
  return raised;
}
