import type { Job, PgBoss } from "pg-boss";

import type { Database } from "@/db/client";
import { errorSummary, type Logger } from "@/lib/logger";
import { silentAgentThresholdS } from "@/server/alerting-config";
import { runPolicyEvaluation } from "@/server/incidents";
import { NOTIFICATION_QUEUE } from "@/server/notification-queue";
import { eventsRetentionDays, purgeAccessEvents } from "@/server/events";
import { pruneRateLimitCounters } from "@/server/rate-limit";
import { drainDeliveries, enqueueSuppressionDigests } from "@/server/notifications";
import { POLICY_QUEUE } from "@/server/policy-queue";
import { checkSilentAgents } from "@/server/system-alerts";

/**
 * Queues handled by the worker: `console.noop` (wiring check), `policies.evaluate` (P3-A, see
 * src/server/policy-queue.ts) and `notifications.deliver` (P3-C, see
 * src/server/notification-queue.ts), `events.purge` (P4-C: retention of access events) and
 * `rate_limits.prune` (P4-D: expired shared rate-limit windows). The correlation of access events
 * runs in `policies.evaluate` (src/server/event-engine.ts).
 */
export const NOOP_QUEUE = "console.noop";
/** Catch-up schedule of the policy engine (lost wake-ups, restarts, exception expiries). */
export const POLICY_SCHEDULE_CRON = "* * * * *";
/** Time budget of one `policies.evaluate` job; remaining work is re-queued. */
export const POLICY_JOB_BUDGET_MS = 50_000;

/**
 * pg-boss runs in the `pgboss` schema, created by the owner in migration 0004. The runtime role
 * has `USAGE, CREATE` on that schema only and no `CREATE` on the database, so pg-boss must not
 * try to create its schema (security re-review N2).
 */
export const PGBOSS_SCHEMA = "pgboss";

export function pgBossOptions(connectionString: string) {
  return {
    connectionString,
    application_name: "databastion-worker",
    schema: PGBOSS_SCHEMA,
    createSchema: false,
  };
}

export type NoopPayload = Record<string, never>;

/** Acknowledges jobs without doing anything; proves the worker loop is wired. */
export function createNoopHandler(log: Logger) {
  return async (jobs: Job<NoopPayload>[]): Promise<void> => {
    for (const job of jobs) {
      log.debug({ queue: NOOP_QUEUE, jobId: job.id }, "noop job processed");
    }
  };
}

/**
 * `policies.evaluate`: drains the pending policy work (payload ignored). When work remains (time
 * budget, rows locked by a concurrent writer) another wake-up is queued. A failure is retried by
 * pg-boss; the work itself stays pending in the console tables.
 */
export function createPolicyHandler(
  db: () => Database,
  log: Logger,
  requeue: () => Promise<unknown>,
  budgetMs = POLICY_JOB_BUDGET_MS,
  notify: () => Promise<unknown> = async () => undefined,
) {
  return async (jobs: Job<Record<string, unknown>>[]): Promise<void> => {
    if (jobs.length === 0) return;
    const stats = await runPolicyEvaluation(db(), budgetMs);
    if (stats.created > 0) {
      // New incidents may have queued notifications (the schedule catches up if this is lost).
      await notify().catch((err: unknown) =>
        log.warn({ queue: NOTIFICATION_QUEUE, error: errorSummary(err) }, "notification wake-up failed"),
      );
    }
    if (stats.more) {
      await requeue().catch((err: unknown) =>
        log.warn({ queue: POLICY_QUEUE, error: errorSummary(err) }, "policy evaluation re-queue failed"),
      );
    }
  };
}

/** Creates the policy queue (stately: bursts coalesce), its worker and its catch-up schedule. */
export async function registerPolicyQueue(boss: PgBoss, db: () => Database, log: Logger, opts: { pollingIntervalSeconds?: number; budgetMs?: number } = {}): Promise<void> {
  await boss.createQueue(POLICY_QUEUE, { policy: "stately" });
  await boss.work(
    POLICY_QUEUE,
    { pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 },
    createPolicyHandler(db, log, () => boss.send(POLICY_QUEUE, {}), opts.budgetMs, () => boss.send(NOTIFICATION_QUEUE, {})),
  );
}

export async function schedulePolicyQueue(boss: PgBoss): Promise<void> {
  await boss.schedule(POLICY_QUEUE, POLICY_SCHEDULE_CRON, {});
  // Work left pending while the worker was down.
  await boss.send(POLICY_QUEUE, {});
}

/** Catch-up schedule of the notifications: retries with backoff and the silent-agent check. */
export const NOTIFICATION_SCHEDULE_CRON = "* * * * *";
export const NOTIFICATION_JOB_BUDGET_MS = 50_000;

/**
 * `notifications.deliver`: the silent-agent check (no new silence alert during the first threshold
 * after the worker started, see `checkSilentAgents`), then the due deliveries. Re-queued when due
 * deliveries remain; a failure is retried by pg-boss, the outbox keeps the work.
 */
export function createNotificationHandler(
  db: () => Database,
  log: Logger,
  requeue: () => Promise<unknown>,
  opts: { startedAt?: Date; budgetMs?: number } = {},
) {
  const startedAt = opts.startedAt ?? new Date();
  return async (jobs: Job<Record<string, unknown>>[]): Promise<void> => {
    if (jobs.length === 0) return;
    const thresholdS = silentAgentThresholdS();
    await checkSilentAgents(db(), { thresholdS, notBefore: new Date(startedAt.getTime() + thresholdS * 1000) });
    await enqueueSuppressionDigests(db());
    const stats = await drainDeliveries(db(), { budgetMs: opts.budgetMs ?? NOTIFICATION_JOB_BUDGET_MS });
    if (stats.attempted > 0) log.info({ ...stats }, "notifications");
    if (stats.more) {
      await requeue().catch((err: unknown) =>
        log.warn({ queue: NOTIFICATION_QUEUE, error: errorSummary(err) }, "notification re-queue failed"),
      );
    }
  };
}

/** Creates the notification queue (stately), its worker, its schedule, and sends a first wake-up. */
export async function registerNotificationQueue(
  boss: PgBoss,
  db: () => Database,
  log: Logger,
  opts: { pollingIntervalSeconds?: number; budgetMs?: number } = {},
): Promise<void> {
  await boss.createQueue(NOTIFICATION_QUEUE, { policy: "stately" });
  await boss.work(
    NOTIFICATION_QUEUE,
    { pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 },
    createNotificationHandler(db, log, () => boss.send(NOTIFICATION_QUEUE, {}), { budgetMs: opts.budgetMs }),
  );
}

export async function scheduleNotificationQueue(boss: PgBoss): Promise<void> {
  await boss.schedule(NOTIFICATION_QUEUE, NOTIFICATION_SCHEDULE_CRON, {});
  await boss.send(NOTIFICATION_QUEUE, {});
}

/** Retention of access events (P4-C): hourly, and once at worker start. */
export const EVENTS_PURGE_QUEUE = "events.purge";
export const EVENTS_PURGE_CRON = "17 * * * *";
export const EVENTS_PURGE_BUDGET_MS = 50_000;

/**
 * `events.purge`: deletes the access events older than `DATABASTION_EVENTS_RETENTION_DAYS` (default
 * 90) through the owner-defined purge function (the runtime role cannot delete events otherwise),
 * in chunks; re-queued when rows remain after the time budget.
 */
export function createEventsPurgeHandler(
  db: () => Database,
  log: Logger,
  requeue: () => Promise<unknown>,
  opts: { budgetMs?: number; retentionDays?: () => number } = {},
) {
  return async (jobs: Job<Record<string, unknown>>[]): Promise<void> => {
    if (jobs.length === 0) return;
    const retentionDays = (opts.retentionDays ?? eventsRetentionDays)();
    const stats = await purgeAccessEvents(db(), { retentionDays, budgetMs: opts.budgetMs ?? EVENTS_PURGE_BUDGET_MS });
    if (stats.deleted > 0) log.info({ queue: EVENTS_PURGE_QUEUE, deleted: stats.deleted, retentionDays }, "access events purged");
    if (stats.more) {
      await requeue().catch((err: unknown) =>
        log.warn({ queue: EVENTS_PURGE_QUEUE, error: errorSummary(err) }, "events purge re-queue failed"),
      );
    }
  };
}

export async function registerEventsPurgeQueue(boss: PgBoss, db: () => Database, log: Logger): Promise<void> {
  await boss.createQueue(EVENTS_PURGE_QUEUE, { policy: "stately" });
  await boss.work(EVENTS_PURGE_QUEUE, { pollingIntervalSeconds: 30 }, createEventsPurgeHandler(db, log, () => boss.send(EVENTS_PURGE_QUEUE, {})));
}

export async function scheduleEventsPurgeQueue(boss: PgBoss): Promise<void> {
  await boss.schedule(EVENTS_PURGE_QUEUE, EVENTS_PURGE_CRON, {});
  await boss.send(EVENTS_PURGE_QUEUE, {});
}

/** Expired shared rate-limit windows (P4-D, src/server/rate-limit.ts): every 5 minutes. */
export const RATE_LIMITS_PRUNE_QUEUE = "rate_limits.prune";
export const RATE_LIMITS_PRUNE_CRON = "*/5 * * * *";
export const RATE_LIMITS_PRUNE_BUDGET_MS = 20_000;

/**
 * `rate_limits.prune`: deletes the expired windows of `rate_limit_counters` in chunks. Pruning
 * changes no rate-limit decision (an expired window is reset by the next hit of its key); it only
 * bounds the table. Re-queued when expired rows remain after the time budget.
 */
export function createRateLimitsPruneHandler(
  db: () => Database,
  log: Logger,
  requeue: () => Promise<unknown>,
  opts: { budgetMs?: number } = {},
) {
  return async (jobs: Job<Record<string, unknown>>[]): Promise<void> => {
    if (jobs.length === 0) return;
    const stats = await pruneRateLimitCounters(db(), { budgetMs: opts.budgetMs ?? RATE_LIMITS_PRUNE_BUDGET_MS });
    if (stats.deleted > 0) log.debug({ queue: RATE_LIMITS_PRUNE_QUEUE, deleted: stats.deleted }, "rate-limit windows pruned");
    if (stats.more) {
      await requeue().catch((err: unknown) =>
        log.warn({ queue: RATE_LIMITS_PRUNE_QUEUE, error: errorSummary(err) }, "rate-limit prune re-queue failed"),
      );
    }
  };
}

export async function registerRateLimitsPruneQueue(boss: PgBoss, db: () => Database, log: Logger): Promise<void> {
  await boss.createQueue(RATE_LIMITS_PRUNE_QUEUE, { policy: "stately" });
  await boss.work(
    RATE_LIMITS_PRUNE_QUEUE,
    { pollingIntervalSeconds: 30 },
    createRateLimitsPruneHandler(db, log, () => boss.send(RATE_LIMITS_PRUNE_QUEUE, {})),
  );
}

export async function scheduleRateLimitsPruneQueue(boss: PgBoss): Promise<void> {
  await boss.schedule(RATE_LIMITS_PRUNE_QUEUE, RATE_LIMITS_PRUNE_CRON, {});
  await boss.send(RATE_LIMITS_PRUNE_QUEUE, {});
}
