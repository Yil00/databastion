/**
 * Worker process entrypoint (`pnpm worker`). Same codebase and image as the
 * web process, different command. Runs background jobs through pg-boss on the
 * console's internal PostgreSQL (no Redis).
 */
import { Pool } from "pg";
import { PgBoss } from "pg-boss";

import { getDatabaseUrl } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";
import { runtimeRoleWarnings } from "@/server/db-role-check";
import { startupErrors, startupFatal } from "@/server/startup-checks";

import { getDb } from "@/db/client";
import { alertingWarnings } from "@/server/alerting-config";
import { NOTIFICATION_QUEUE } from "@/server/notification-queue";
import { POLICY_QUEUE } from "@/server/policy-queue";

import {
  createNoopHandler,
  NOOP_QUEUE,
  pgBossOptions,
  registerNotificationQueue,
  registerPolicyQueue,
  scheduleNotificationQueue,
  schedulePolicyQueue,
  type NoopPayload,
} from "./queues";

const SHUTDOWN_TIMEOUT_MS = 30_000;

const log = logger.child({ process: "worker" });

async function main(): Promise<void> {
  const fatal = startupFatal();
  if (fatal !== null) throw new Error(fatal);
  for (const message of startupErrors()) log.error(message);
  for (const warning of alertingWarnings()) log.warn(warning);

  const boss = new PgBoss(pgBossOptions(getDatabaseUrl()));

  boss.on("error", (err: unknown) => {
    log.error({ error: errorSummary(err) }, "pg-boss error");
  });

  let stopping = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (stopping) return;
    stopping = true;
    log.info({ signal }, "worker shutting down");
    boss
      .stop({ graceful: true, timeout: SHUTDOWN_TIMEOUT_MS })
      .then(() => {
        log.info("worker stopped");
        process.exit(0);
      })
      .catch((err: unknown) => {
        log.error({ error: errorSummary(err) }, "worker shutdown failed");
        process.exit(1);
      });
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);

  try {
    const pool = new Pool({ connectionString: getDatabaseUrl(), max: 1 });
    for (const warning of await runtimeRoleWarnings(pool)) log.warn(warning);
    await pool.end();
  } catch (err) {
    log.warn({ error: errorSummary(err) }, "database role check skipped");
  }

  await boss.start();
  await boss.createQueue(NOOP_QUEUE);
  await boss.work<NoopPayload>(NOOP_QUEUE, createNoopHandler(log));
  await registerPolicyQueue(boss, getDb, log);
  await schedulePolicyQueue(boss);
  // P3-C: notification delivery (outbound webhooks / SMTP happen in the worker only).
  await registerNotificationQueue(boss, getDb, log);
  await scheduleNotificationQueue(boss);

  log.info({ queues: [NOOP_QUEUE, POLICY_QUEUE, NOTIFICATION_QUEUE] }, "worker started");
}

main().catch((err: unknown) => {
  log.fatal({ error: errorSummary(err) }, "worker failed to start");
  process.exit(1);
});
