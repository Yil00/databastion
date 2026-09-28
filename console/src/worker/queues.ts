import type { Job } from "pg-boss";

import type { Logger } from "@/lib/logger";

/**
 * Queues handled by the worker. Placeholder only: the real queues
 * (policies, correlation, alerting) arrive with their ROADMAP tasks.
 */
export const NOOP_QUEUE = "console.noop";

export type NoopPayload = Record<string, never>;

/** Acknowledges jobs without doing anything; proves the worker loop is wired. */
export function createNoopHandler(log: Logger) {
  return async (jobs: Job<NoopPayload>[]): Promise<void> => {
    for (const job of jobs) {
      log.debug({ queue: NOOP_QUEUE, jobId: job.id }, "noop job processed");
    }
  };
}
