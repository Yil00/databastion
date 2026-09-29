import { and, eq, isNotNull, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, securityEvents } from "@/db/schema";
import { logger } from "@/lib/logger";

import { consoleUrl, silentAgentThresholdS } from "./alerting-config";
import { writeAudit } from "./audit";
import type { Tx } from "./findings";
import { enqueueSystemAlert } from "./notifications";

/**
 * Console alerts that no policy raises (P3-C): silent agents and agent-integrity events. Both go
 * to the channels flagged `system_alerts` and are recorded in `security_events` (insert-only for
 * the runtime role: a compromised console cannot erase them), not in `incidents`, which only hold
 * what policies raise (ADR-0014: policy snapshot, dedup key, column grants).
 *
 * P7 (#75 review L4): besides the per-agent bounds below, every system alert is charged to a global
 * budget per channel and hour (`enqueueSystemAlert`, `DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR`); the
 * overflow is summed up in one digest per channel and hour.
 */

const log = logger.child({ component: "system-alerts" });

/**
 * Notification of an agent-integrity event (`security_events` row written by the caller in `tx`):
 * at most one per (agent, kind, hour) and channel, so a misbehaving agent cannot flood the
 * channels (the security events themselves are all recorded, within their own write budget).
 */
export async function notifyIntegrityEvent(
  tx: Tx,
  e: { securityEventId: string; agentId: string; kind: string; severity: string; details: Record<string, string | number | boolean | null>; at: Date },
): Promise<void> {
  const hour = e.at.toISOString().slice(0, 13);
  await enqueueSystemAlert(tx, {
    subjectKey: `agent:${e.agentId}|integrity:${e.kind}|hour:${hour}`,
    agentId: e.agentId,
    securityEventId: e.securityEventId,
    payload: {
      event: "agent.integrity",
      occurred_at: e.at.toISOString(),
      url: consoleUrl(`/agents/${e.agentId}`),
      kind: e.kind,
      severity: e.severity,
      agent_id: e.agentId,
      security_event_id: e.securityEventId,
      details: e.details,
    },
  });
}

export interface SilenceCheckOptions {
  /** Current time (tests: fake time). Default: the database clock. */
  now?: Date;
  thresholdS?: number;
  /**
   * No new silence alert before this instant: the worker passes its start time + the threshold,
   * so a console outage (no heartbeat could be received) does not turn into one alert per agent.
   */
  notBefore?: Date;
  maxAgents?: number;
}

export interface SilenceCheckStats {
  silent: number;
  recovered: number;
}

/**
 * "Silent agent" check (worker, every minute). An agent that was online (it sent at least one
 * heartbeat), is neither revoked nor locked, and has sent no heartbeat for the threshold
 * (`DATABASTION_SILENT_AGENT_INTERVALS` x the 30 s heartbeat interval, 5 min by default) raises ONE
 * alert per silence episode: `agents.silence_alerted_for` records the `last_seen_at` of the
 * alerted episode (conditional update: concurrent workers alert once). In the same transaction:
 * a `security_events` row `agent.silent` (medium), an audit entry (system) and the deliveries.
 * When a later heartbeat ends the episode, the marker is cleared, `agent.recovered` is audited and
 * a recovery notice goes to the same channels; the next silence is a new episode.
 */
export async function checkSilentAgents(db: Database, opts: SilenceCheckOptions = {}): Promise<SilenceCheckStats> {
  const thresholdS = opts.thresholdS ?? silentAgentThresholdS();
  const now = opts.now ? sql`${opts.now.toISOString()}::timestamptz` : sql`now()`;
  const stats: SilenceCheckStats = { silent: 0, recovered: 0 };

  // Recoveries first: an agent back online never gets a stale silence alert.
  const back = await db
    .select({ id: agents.id })
    .from(agents)
    .where(and(isNotNull(agents.silenceAlertedFor), sql`${agents.lastSeenAt} > ${agents.silenceAlertedFor}`))
    .limit(opts.maxAgents ?? 500);
  for (const { id } of back) {
    const done = await db.transaction(async (tx) => {
      const res = await tx.execute<{ silent_since: Date | string; last_seen_at: Date | string; name: string; hostname: string; revoked: boolean }>(sql`
        update agents a set silence_alerted_for = null
        from (select id, silence_alerted_for as old from agents where id = ${id} for update) o
        where a.id = o.id and a.silence_alerted_for is not null and a.last_seen_at > a.silence_alerted_for
        returning o.old as silent_since, a.last_seen_at, a.name, a.hostname,
          (a.revoked_at is not null or a.locked_at is not null) as revoked`);
      const row = res.rows[0];
      if (!row) return false;
      const silentSince = new Date(row.silent_since).toISOString();
      const lastSeenAt = new Date(row.last_seen_at).toISOString();
      await writeAudit(tx, {
        actorType: "system",
        action: "agent.recovered",
        targetType: "agent",
        targetId: id,
        details: { silent_since: silentSince, last_seen_at: lastSeenAt },
      });
      if (!row.revoked) {
        await enqueueSystemAlert(tx, {
          subjectKey: `agent:${id}|silence:${silentSince}`,
          agentId: id,
          securityEventId: null,
          payload: {
            event: "agent.recovered",
            occurred_at: lastSeenAt,
            url: consoleUrl(`/agents/${id}`),
            agent: { id, name: row.name, hostname: row.hostname },
            silent_since: silentSince,
            last_seen_at: lastSeenAt,
          },
        });
      }
      return true;
    });
    if (done) stats.recovered++;
  }

  if (opts.notBefore) {
    const [{ due } = { due: false }] = (await db.execute<{ due: boolean }>(sql`select ${now} >= ${opts.notBefore.toISOString()}::timestamptz as due`)).rows;
    if (!due) return stats;
  }

  const cutoff = sql`${now} - make_interval(secs => ${thresholdS})`;
  const candidates = await db
    .select({ id: agents.id })
    .from(agents)
    .where(
      and(
        eq(agents.status, "online"),
        isNull(agents.revokedAt),
        isNull(agents.lockedAt),
        isNull(agents.silenceAlertedFor),
        isNotNull(agents.lastSeenAt),
        sql`${agents.lastSeenAt} < ${cutoff}`,
      ),
    )
    .limit(opts.maxAgents ?? 500);
  for (const { id } of candidates) {
    const done = await db.transaction(async (tx) => {
      // Conditional: a heartbeat, a revocation or another worker in between wins.
      const res = await tx.execute<{ last_seen_at: Date | string; name: string; hostname: string }>(sql`
        update agents set silence_alerted_for = last_seen_at
        where id = ${id} and status = 'online' and revoked_at is null and locked_at is null
          and silence_alerted_for is null and last_seen_at < ${cutoff}
        returning last_seen_at, name, hostname`);
      const row = res.rows[0];
      if (!row) return false;
      const lastSeenAt = new Date(row.last_seen_at).toISOString();
      const [event] = await tx
        .insert(securityEvents)
        .values({ kind: "agent.silent", severity: "medium", agentId: id, details: { last_seen_at: lastSeenAt, threshold_s: thresholdS } })
        .returning({ id: securityEvents.id, at: securityEvents.at });
      if (!event) throw new Error("security event insert returned no row");
      await writeAudit(tx, {
        actorType: "system",
        action: "agent.silent",
        targetType: "agent",
        targetId: id,
        details: { last_seen_at: lastSeenAt, threshold_s: thresholdS, security_event_id: event.id },
      });
      await enqueueSystemAlert(tx, {
        subjectKey: `agent:${id}|silence:${lastSeenAt}`,
        agentId: id,
        securityEventId: event.id,
        payload: {
          event: "agent.silent",
          occurred_at: (opts.now ?? event.at).toISOString(),
          url: consoleUrl(`/agents/${id}`),
          agent: { id, name: row.name, hostname: row.hostname },
          last_seen_at: lastSeenAt,
          threshold_s: thresholdS,
          security_event_id: event.id,
        },
      });
      return true;
    });
    if (done) stats.silent++;
  }
  if (stats.silent > 0 || stats.recovered > 0) log.info({ ...stats, thresholdS }, "silent-agent check");
  return stats;
}
