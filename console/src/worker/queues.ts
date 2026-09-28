import type { Job, PgBoss } from "pg-boss";

import type { Database } from "@/db/client";
import { errorSummary, type Logger } from "@/lib/logger";
import { silentAgentThresholdS } from "@/server/alerting-config";
import { runPolicyEvaluation } from "@/server/incidents";
import { NOTIFICATION_QUEUE } from "@/server/notification-queue";
import { drainDeliveries, enqueueSuppressionDigests } from "@/server/notifications";
import { POLICY_QUEUE } from "@/server/policy-queue";
import { checkSilentAgents } from "@/server/system-alerts";

/**
 * Queues handled by the worker: `console.noop` (wiring check), `policies.evaluate` (P3-A, see
 * src/server/policy-queue.ts) and `notifications.deliver` (P3-C, see
 * src/server/notification-queue.ts). Correlation arrives with its ROADMAP task.
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
