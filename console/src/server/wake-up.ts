import { errorSummary, logger } from "@/lib/logger";

import { processGlobal, processSlot } from "./process-global";

/**
 * Best-effort wake-up of a worker queue (`policies.evaluate`, `notifications.deliver`): the sender
 * is installed once per process (web: the send-only pg-boss instance of `policy-queue-boss.ts`,
 * installed by the startup hook; tests: their own) and kept on `globalThis` (see
 * `process-global.ts`), so the route handlers see it although they run another bundled copy of
 * this module than the startup hook.
 */
export type JobSender = () => Promise<void>;

/** Minimum interval between two "no sender" warnings, per queue and process. */
export const NO_SENDER_WARNING_INTERVAL_MS = 10 * 60_000;

export interface WakeUp {
  setSender(s: JobSender | null): void;
  /** Sends the wake-up. Never throws: a lost wake-up is caught up by the worker's schedule. */
  request(): Promise<void>;
}

export function wakeUp(queue: string, slotName: string, failureMessage: string): WakeUp {
  const slot = processSlot<JobSender>(slotName);
  const warnedAt = processGlobal("wakeUpNoSenderWarnedAt", () => new Map<string, number>());
  return {
    setSender: (s) => slot.set(s),
    async request() {
      const send = slot.get();
      if (!send) {
        // Tests and CLIs run without a sender on purpose; a production web process never should.
        if (process.env.NODE_ENV !== "production") return;
        const now = Date.now();
        const last = warnedAt.get(queue);
        if (last !== undefined && now - last < NO_SENDER_WARNING_INTERVAL_MS) return;
        warnedAt.set(queue, now);
        logger.warn({ queue }, "wake-up not sent: no job sender installed (the worker's schedule catches up)");
        return;
      }
      try {
        await send();
      } catch (err) {
        logger.warn({ queue, error: errorSummary(err) }, failureMessage);
      }
    },
  };
}
