import { randomUUID } from "node:crypto";

import { and, desc, eq, inArray, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { notificationChannels, notificationDeliveries } from "@/db/schema";
import { errorSummary, logger } from "@/lib/logger";
import { SYSTEM_ALERT_EVENTS, type DeliveryStatus, type SystemAlertEvent } from "@/lib/notification-model";
import { renderEmail, webhookBody, type NotificationPayload } from "@/lib/notification-render";

import { consoleUrl, insecureDevAllowed, notifyMaxPerHour, systemAlertsMaxPerHour } from "./alerting-config";
import { writeAudit } from "./audit";
import { loadChannelForDelivery } from "./channels";
import type { Tx } from "./findings";
import { sendMail } from "./senders/smtp";
import type { SendResult } from "./senders/types";
import { sendWebhook } from "./senders/webhook";

/**
 * Notification outbox and delivery (P3-C).
 *
 * Enqueueing happens in the transaction of the event (transactional outbox): the incident insert
 * of the policy engine, the silent-agent check, an agent-integrity event. One row per (subject,
 * event, channel), keyed by a unique `idempotency_key`, so a retried or concurrent evaluation
 * never notifies twice. A referenced slug with no channel, or a disabled channel, gives a row in
 * status `skipped` (`unknown_channel` / `channel_disabled`), visible on the incident page: the
 * incident itself is always created.
 *
 * Delivery runs in the worker only (pg-boss queue `notifications.deliver`, see
 * `notification-queue.ts`): due rows are claimed with `FOR UPDATE SKIP LOCKED` and a lease
 * (a crashed worker's rows are claimed again after it), sent outside any transaction, and the
 * outcome recorded: `delivered`; `pending` again with an exponential backoff (1 min, doubling,
 * capped at 1 h) for a retryable failure; `failed` after 8 attempts or on a permanent failure.
 * Delivery is at least once: receivers deduplicate on the delivery id (webhook header, e-mail
 * `Message-ID`).
 */

export const MAX_DELIVERY_ATTEMPTS = 8;
export const DELIVERY_LEASE_S = 120;
export const DELIVERY_BATCH = 10;

const log = logger.child({ component: "notifications" });

/** Seconds before the next attempt after `attempts` failed ones: 60, 120, 240, ... capped at 3600. */
export function backoffSeconds(attempts: number): number {
  return Math.min(3600, 60 * 2 ** Math.max(0, Math.min(attempts - 1, 12)));
}

type Exec = Database | Tx;

/**
 * Time source of the hourly budget (L6): the enqueue time of a delivery (`created_at`), the hour
 * whose budget it uses, and the closed hours the digests cover. `null` (production): the database
 * clock. Tests pin it, so a run never depends on where the wall clock is within the hour.
 */
export const notificationClock: { now: (() => Date) | null } = { now: null };

function clockSql() {
  const pinned = notificationClock.now?.();
  return pinned ? sql`${pinned.toISOString()}::timestamptz` : sql`now()`;
}

interface NewDelivery {
  key: string;
  event: NotificationPayload["event"];
  channelId: string | null;
  channelSlug: string;
  incidentId?: string | null;
  agentId?: string | null;
  securityEventId?: string | null;
  payload: NotificationPayload;
  status: "pending" | "skipped";
  lastError?: string | null;
}

async function insertDeliveries(db: Exec, rows: NewDelivery[]): Promise<number> {
  const inserted = await insertDeliveryRows(db, rows);
  return inserted.filter((r) => r.status === "pending").length;
}

/** The rows actually inserted (a repeated idempotency key inserts nothing). */
async function insertDeliveryRows(db: Exec, rows: NewDelivery[]): Promise<{ id: string; channelId: string | null; status: DeliveryStatus }[]> {
  if (rows.length === 0) return [];
  return db
    .insert(notificationDeliveries)
    .values(
      rows.map((r) => ({
        idempotencyKey: r.key,
        event: r.event,
        channelId: r.channelId,
        channelSlug: r.channelSlug,
        incidentId: r.incidentId ?? null,
        agentId: r.agentId ?? null,
        securityEventId: r.securityEventId ?? null,
        payload: r.payload as unknown as Record<string, unknown>,
        status: r.status,
        lastError: r.lastError ?? null,
        createdAt: clockSql(),
      })),
    )
    .onConflictDoNothing({ target: notificationDeliveries.idempotencyKey })
    .returning({ id: notificationDeliveries.id, channelId: notificationDeliveries.channelId, status: notificationDeliveries.status });
}

/**
 * Deliveries of a new incident, one per channel slug of its policy's `notify` actions. Unknown
 * slugs and disabled channels are recorded as `skipped`. Returns the number of pending rows.
 */
export async function enqueueIncidentNotifications(
  tx: Exec,
  incidentId: string,
  slugs: readonly string[],
  payload: NotificationPayload,
): Promise<number> {
  if (slugs.length === 0) return 0;
  const channels = await tx
    .select({ id: notificationChannels.id, slug: notificationChannels.slug, enabled: notificationChannels.enabled })
    .from(notificationChannels)
    .where(inArray(notificationChannels.slug, [...slugs]));
  const bySlug = new Map(channels.map((c) => [c.slug, c]));
  // L6: hourly budget per channel (soft: concurrent evaluations may overshoot by a few).
  const now = clockSql();
  const enabledIds = channels.filter((c) => c.enabled).map((c) => c.id);
  const used = new Map<string, number>();
  if (enabledIds.length > 0) {
    const counts = await tx
      .select({ channelId: notificationDeliveries.channelId, n: sql<number>`count(*)::int` })
      .from(notificationDeliveries)
      .where(
        and(
          inArray(notificationDeliveries.channelId, enabledIds),
          eq(notificationDeliveries.event, "incident.opened"),
          sql`${notificationDeliveries.status} <> 'skipped'`,
          sql`${notificationDeliveries.createdAt} >= date_trunc('hour', ${now})`,
          sql`${notificationDeliveries.createdAt} < date_trunc('hour', ${now}) + interval '1 hour'`,
        ),
      )
      .groupBy(notificationDeliveries.channelId);
    for (const c of counts) if (c.channelId) used.set(c.channelId, c.n);
  }
  const limit = notifyMaxPerHour();
  return insertDeliveries(
    tx,
    [...new Set(slugs)].map((slug) => {
      const ch = bySlug.get(slug);
      const overBudget = ch?.enabled === true && (used.get(ch.id) ?? 0) >= limit;
      return {
        key: `incident:${incidentId}|${payload.event}|channel:${slug}`,
        event: payload.event,
        channelId: ch?.id ?? null,
        channelSlug: slug,
        incidentId,
        payload,
        status: ch?.enabled && !overBudget ? "pending" : "skipped",
        lastError: !ch ? "unknown_channel" : !ch.enabled ? "channel_disabled" : overBudget ? "rate_limited" : null,
      };
    }),
  );
}

/** Start of the UTC clock hour of the budget clock (`notificationClock`, else the database clock). */
function hourSql() {
  return sql`date_trunc('hour', ${clockSql()}, 'UTC')`;
}

/**
 * P7 (#75 review L4): charges one system alert to the hourly budget of each channel, in the
 * caller's transaction. One conditional upsert per channel on `system_alert_budgets`: the row of
 * (channel, hour) is created at 1, or incremented only while below the limit. The row lock is held
 * until the transaction ends, so concurrent transactions of any process are serialized on it and
 * never exceed the limit; an aborted transaction gives its charge back. Channels are charged in
 * sorted order, so two transactions charging the same channels cannot deadlock. Callers take the
 * budget rows last (after their agent row), never the other way round. Returns the channels whose
 * budget of the hour is spent.
 */
async function chargeSystemAlertBudget(tx: Exec, channelIds: readonly string[]): Promise<Set<string>> {
  const limit = systemAlertsMaxPerHour();
  const refused = new Set<string>();
  for (const id of [...new Set(channelIds)].sort()) {
    const res = await tx.execute<{ sent: number }>(sql`
      insert into system_alert_budgets as b (channel_id, window_start, sent)
      values (${id}, ${hourSql()}, 1)
      on conflict (channel_id, window_start) do update set sent = b.sent + 1 where b.sent < ${limit}
      returning b.sent`);
    if (res.rows.length === 0) refused.add(id);
  }
  return refused;
}

/**
 * A console alert (silent agent and recovery, agent-integrity event, dropped batches) to every
 * enabled channel flagged `system_alerts`. `subjectKey` identifies the alert (e.g. the silence
 * episode); with no such channel nothing is queued (the security event row remains). Returns the
 * number of rows queued as pending.
 *
 * P7 (#75 review L4): besides the per-agent bounds of each alert, a global budget of
 * `DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR` system alerts per channel and UTC clock hour holds for
 * all agents together (N misbehaving agents no longer send N alerts per hour to each channel).
 * Over it, the delivery is recorded as `skipped` (`rate_limited`) and counted in the hour's
 * `system_alerts.suppressed` digest (`enqueueSystemAlertDigests`). Only new deliveries are
 * charged: a repeated alert (same idempotency key) costs nothing.
 */
export async function enqueueSystemAlert(
  tx: Exec,
  alert: { subjectKey: string; agentId: string | null; securityEventId: string | null; payload: NotificationPayload & { event: SystemAlertEvent } },
): Promise<number> {
  const channels = await tx
    .select({ id: notificationChannels.id, slug: notificationChannels.slug })
    .from(notificationChannels)
    .where(and(eq(notificationChannels.systemAlerts, true), eq(notificationChannels.enabled, true)))
    // One order for every writer: concurrent inserts of the same keys cannot deadlock.
    .orderBy(notificationChannels.id);
  const inserted = await insertDeliveryRows(
    tx,
    channels.map((ch) => ({
      key: `${alert.subjectKey}|${alert.payload.event}|channel:${ch.id}`,
      event: alert.payload.event,
      channelId: ch.id,
      channelSlug: ch.slug,
      agentId: alert.agentId,
      securityEventId: alert.securityEventId,
      payload: alert.payload,
      status: "pending",
    })),
  );
  const fresh = inserted.filter((r): r is typeof r & { channelId: string } => r.status === "pending" && r.channelId !== null);
  if (fresh.length === 0) return 0;
  const refused = await chargeSystemAlertBudget(
    tx,
    fresh.map((r) => r.channelId),
  );
  const over = fresh.filter((r) => refused.has(r.channelId)).map((r) => r.id);
  if (over.length > 0) {
    await tx
      .update(notificationDeliveries)
      .set({ status: "skipped", lastError: "rate_limited" })
      .where(inArray(notificationDeliveries.id, over));
    log.debug({ event: alert.payload.event, channels: over.length }, "system alert over the channel's hourly budget: counted in the digest");
  }
  return fresh.length - over.length;
}

/**
 * L6: one digest per channel and closed clock hour in which incident notifications were suppressed
 * by the hourly budget (last 2 days; idempotent). Counts only. Returns the number queued.
 */
export async function enqueueSuppressionDigests(db: Database): Promise<number> {
  const now = clockSql();
  const res = await db.execute<{ channel_id: string; channel_slug: string; window_start: Date | string; n: number }>(sql`
    select channel_id, max(channel_slug) as channel_slug, date_trunc('hour', created_at) as window_start, count(*)::int as n
    from notification_deliveries
    where last_error = 'rate_limited' and event = 'incident.opened' and channel_id is not null
      and created_at >= ${now} - interval '2 days' and created_at < date_trunc('hour', ${now})
    group by channel_id, date_trunc('hour', created_at)`);
  const limit = notifyMaxPerHour();
  let queued = 0;
  for (const r of res.rows) {
    const start = new Date(r.window_start);
    const end = new Date(start.getTime() + 3600_000);
    queued += await insertDeliveries(db, [
      {
        key: `digest:${r.channel_id}|${start.toISOString()}|notifications.suppressed|channel:${r.channel_id}`,
        event: "notifications.suppressed",
        channelId: r.channel_id,
        channelSlug: r.channel_slug,
        payload: {
          event: "notifications.suppressed",
          occurred_at: end.toISOString(),
          url: consoleUrl("/incidents"),
          channel: r.channel_slug,
          window_start: start.toISOString(),
          window_end: end.toISOString(),
          suppressed: r.n,
          limit_per_hour: limit,
        },
        status: "pending",
      },
    ]);
  }
  return queued;
}

/** Past hours of `system_alert_budgets` kept before pruning (only the current hour is charged). */
const SYSTEM_ALERT_BUDGET_KEEP_HOURS = 2;

/**
 * P7 (#75 review L4): one `system_alerts.suppressed` digest per channel and closed UTC clock hour
 * in which system alerts were suppressed by the global hourly budget (last 2 days; idempotent, so
 * every worker run may call it). Counts only: per event, and the number of distinct agents; never
 * an agent id or any agent-provided text. Digests are not charged to the budget. Also prunes the
 * budget rows of past hours. Returns the number of digests queued.
 */
export async function enqueueSystemAlertDigests(db: Database): Promise<number> {
  const now = clockSql();
  const events = sql.join(
    SYSTEM_ALERT_EVENTS.map((e) => sql`${e}`),
    sql`, `,
  );
  const res = await db.execute<{ channel_id: string; channel_slug: string; window_start: Date | string; n: number; agents: number; by_event: Record<string, number> }>(sql`
    with s as (
      select channel_id, channel_slug, date_trunc('hour', created_at, 'UTC') as window_start, event, agent_id
      from notification_deliveries
      where last_error = 'rate_limited' and event in (${events}) and channel_id is not null
        and created_at >= ${now} - interval '2 days' and created_at < date_trunc('hour', ${now}, 'UTC')
    )
    select channel_id, max(channel_slug) as channel_slug, window_start, count(*)::int as n,
      count(distinct agent_id)::int as agents,
      (select jsonb_object_agg(e.event, e.n) from (
         select s2.event, count(*)::int as n from s s2
         where s2.channel_id = s.channel_id and s2.window_start = s.window_start group by s2.event) e) as by_event
    from s
    group by channel_id, window_start`);
  const limit = systemAlertsMaxPerHour();
  let queued = 0;
  for (const r of res.rows) {
    const start = new Date(r.window_start);
    const end = new Date(start.getTime() + 3600_000);
    const byEvent: Partial<Record<SystemAlertEvent, number>> = {};
    for (const e of SYSTEM_ALERT_EVENTS) {
      const n = Number(r.by_event?.[e] ?? 0);
      if (n > 0) byEvent[e] = n;
    }
    queued += await insertDeliveries(db, [
      {
        key: `system-digest:${r.channel_id}|${start.toISOString()}|system_alerts.suppressed|channel:${r.channel_id}`,
        event: "system_alerts.suppressed",
        channelId: r.channel_id,
        channelSlug: r.channel_slug,
        payload: {
          event: "system_alerts.suppressed",
          occurred_at: end.toISOString(),
          url: consoleUrl("/agents"),
          channel: r.channel_slug,
          window_start: start.toISOString(),
          window_end: end.toISOString(),
          suppressed: r.n,
          by_event: byEvent,
          agents: r.agents,
          limit_per_hour: limit,
        },
        status: "pending",
      },
    ]);
  }
  await db.execute(
    sql`delete from system_alert_budgets where window_start < date_trunc('hour', ${now}, 'UTC') - make_interval(hours => ${SYSTEM_ALERT_BUDGET_KEEP_HOURS})`,
  );
  return queued;
}

/** A test notification to one channel (admin, audited); sent even when the channel is disabled. */
export async function enqueueTestNotification(
  db: Database,
  channelId: string,
  actor: { userId: string; ip: string | null },
): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [ch] = await tx
      .select({ id: notificationChannels.id, slug: notificationChannels.slug, type: notificationChannels.type })
      .from(notificationChannels)
      .where(eq(notificationChannels.id, channelId));
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "notification_channel.test",
      outcome: ch ? "success" : "failure",
      targetType: "notification_channel",
      targetId: channelId,
      sourceIp: actor.ip,
      details: ch ? { slug: ch.slug, type: ch.type } : { reason: "not_found" },
    });
    if (!ch) return false;
    const payload: NotificationPayload = {
      event: "channel.test",
      occurred_at: new Date().toISOString(),
      url: consoleUrl("/notifications"),
      channel: ch.slug,
    };
    await insertDeliveries(tx, [
      {
        key: `test:${randomUUID()}|channel:${ch.id}`,
        event: "channel.test",
        channelId: ch.id,
        channelSlug: ch.slug,
        payload,
        status: "pending",
      },
    ]);
    return true;
  });
}

// ------------------------------------------------------------------------------ delivery

export interface Senders {
  email: typeof sendMail;
  webhook: typeof sendWebhook;
}

const defaultSenders: Senders = { email: sendMail, webhook: sendWebhook };

export interface DeliveryOptions {
  budgetMs?: number;
  senders?: Senders;
  /** Sender options for the tests (resolver, CA). */
  senderOptions?: { resolver?: Parameters<typeof sendWebhook>[3]["resolver"]; ca?: string | Buffer };
}

interface ClaimedRow extends Record<string, unknown> {
  id: string;
  event: string;
  channel_id: string | null;
  channel_slug: string;
  payload: NotificationPayload;
  attempts: number;
}

async function claim(db: Database): Promise<ClaimedRow[]> {
  const res = await db.execute<ClaimedRow>(sql`
    update notification_deliveries set
      status = 'sending',
      attempts = attempts + 1,
      last_attempt_at = now(),
      lease_until = now() + make_interval(secs => ${DELIVERY_LEASE_S})
    where id in (
      select id from notification_deliveries
      where (status = 'pending' and next_attempt_at <= now())
         or (status = 'sending' and lease_until < now())
      order by next_attempt_at, id
      limit ${DELIVERY_BATCH}
      for update skip locked)
    returning id, event, channel_id, channel_slug, payload, attempts`);
  return res.rows;
}

/**
 * L3: a test send reaches a destination chosen by an administrator; "refused" and "filtered" are
 * reported alike, so tests cannot map which ports of a host answer.
 */
const CONNECT_CODES = new Set(["connect_failed", "connect_timeout"]);

async function record(db: Database, row: ClaimedRow, raw: SendResult): Promise<"delivered" | "retry" | "failed" | "skipped"> {
  const result: SendResult =
    !raw.ok && row.event === "channel.test" && CONNECT_CODES.has(raw.code) ? { ...raw, code: "connect_failed" } : raw;
  let status: DeliveryStatus;
  let outcome: "delivered" | "retry" | "failed" | "skipped";
  if (result.ok) {
    status = "delivered";
    outcome = "delivered";
  } else if (result.code === "channel_disabled") {
    status = "skipped";
    outcome = "skipped";
  } else if (result.retryable && row.attempts < MAX_DELIVERY_ATTEMPTS) {
    status = "pending";
    outcome = "retry";
  } else {
    status = "failed";
    outcome = "failed";
  }
  await db
    .update(notificationDeliveries)
    .set({
      status,
      leaseUntil: null,
      lastError: result.ok ? null : result.code,
      deliveredAt: result.ok ? sql`now()` : undefined,
      nextAttemptAt: outcome === "retry" ? sql`now() + make_interval(secs => ${backoffSeconds(row.attempts)})` : undefined,
    })
    // Only the holder of this attempt records it (a lease taken over meanwhile wins).
    .where(and(eq(notificationDeliveries.id, row.id), eq(notificationDeliveries.status, "sending"), eq(notificationDeliveries.attempts, row.attempts)));
  if (!result.ok) {
    log.warn({ deliveryId: row.id, event: row.event, channel: row.channel_slug, code: result.code, attempt: row.attempts, outcome }, "notification not delivered");
  }
  return outcome;
}

async function attempt(db: Database, row: ClaimedRow, opts: DeliveryOptions): Promise<SendResult> {
  if (row.attempts > MAX_DELIVERY_ATTEMPTS) return { ok: false, code: "timeout", retryable: false };
  if (row.channel_id === null) return { ok: false, code: "channel_deleted", retryable: false };
  const ch = await loadChannelForDelivery(db, row.channel_id);
  if (!ch) return { ok: false, code: "channel_deleted", retryable: false };
  if (!ch.enabled && row.event !== "channel.test") return { ok: false, code: "channel_disabled", retryable: false };
  if (!ch.secretOk) return { ok: false, code: "secret_unavailable", retryable: true };
  const senders = opts.senders ?? defaultSenders;
  const insecure = insecureDevAllowed();
  if (ch.type === "webhook") {
    return senders.webhook(
      ch.url as string,
      ch.signingSecret as string,
      { deliveryId: row.id, event: row.event, body: webhookBody(row.id, row.payload) },
      { allowInternal: insecure, allowHttp: insecure, resolver: opts.senderOptions?.resolver, ca: opts.senderOptions?.ca },
    );
  }
  const { subject, text } = renderEmail(row.payload);
  return senders.email(ch.config, ch.password, { deliveryId: row.id, event: row.event, subject, text }, {
    allowInsecure: insecure,
    resolver: opts.senderOptions?.resolver,
    ca: opts.senderOptions?.ca,
  });
}

export interface DeliveryStats {
  attempted: number;
  delivered: number;
  retried: number;
  failed: number;
  /** Due rows remain (time budget reached). */
  more: boolean;
}

/** Sends the due deliveries within `budgetMs` (worker). Safe to run concurrently. */
export async function drainDeliveries(db: Database, opts: DeliveryOptions = {}): Promise<DeliveryStats> {
  const deadline = Date.now() + (opts.budgetMs ?? 50_000);
  const stats: DeliveryStats = { attempted: 0, delivered: 0, retried: 0, failed: 0, more: false };
  for (;;) {
    if (Date.now() > deadline) {
      stats.more = true;
      break;
    }
    const rows = await claim(db);
    if (rows.length === 0) break;
    const outcomes = await Promise.all(
      rows.map(async (row) => {
        let result: SendResult;
        try {
          result = await attempt(db, row, opts);
        } catch (err) {
          log.error({ deliveryId: row.id, error: errorSummary(err) }, "notification attempt failed");
          result = { ok: false, code: "internal", retryable: true };
        }
        return record(db, row, result);
      }),
    );
    stats.attempted += rows.length;
    stats.delivered += outcomes.filter((o) => o === "delivered").length;
    stats.retried += outcomes.filter((o) => o === "retry").length;
    stats.failed += outcomes.filter((o) => o === "failed").length;
  }
  return stats;
}

// --------------------------------------------------------------------------------- views

export interface DeliveryView {
  id: string;
  event: string;
  channelSlug: string;
  status: DeliveryStatus;
  attempts: number;
  lastAttemptAt: Date | null;
  nextAttemptAt: Date;
  deliveredAt: Date | null;
  lastError: string | null;
  createdAt: Date;
  incidentId: string | null;
  agentId: string | null;
}

export async function listDeliveries(db: Database, filter: { incidentId?: string } = {}, limit = 100): Promise<DeliveryView[]> {
  return db
    .select({
      id: notificationDeliveries.id,
      event: notificationDeliveries.event,
      channelSlug: notificationDeliveries.channelSlug,
      status: notificationDeliveries.status,
      attempts: notificationDeliveries.attempts,
      lastAttemptAt: notificationDeliveries.lastAttemptAt,
      nextAttemptAt: notificationDeliveries.nextAttemptAt,
      deliveredAt: notificationDeliveries.deliveredAt,
      lastError: notificationDeliveries.lastError,
      createdAt: notificationDeliveries.createdAt,
      incidentId: notificationDeliveries.incidentId,
      agentId: notificationDeliveries.agentId,
    })
    .from(notificationDeliveries)
    .where(filter.incidentId ? eq(notificationDeliveries.incidentId, filter.incidentId) : undefined)
    .orderBy(desc(notificationDeliveries.createdAt), notificationDeliveries.channelSlug)
    .limit(limit);
}
