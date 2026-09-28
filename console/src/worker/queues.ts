import type { Job } from "pg-boss";

import type { Logger } from "@/lib/logger";

/**
 * Queues handled by the worker. Placeholder only: the real queues
 * (policies, correlation, alerting) arrive with their ROADMAP tasks.
 */
export const NOOP_QUEUE = "console.noop";

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
