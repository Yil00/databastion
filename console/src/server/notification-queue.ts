import { errorSummary, logger } from "@/lib/logger";

/**
 * Wake-up of the notification delivery (P3-C). Like `policies.evaluate`, the pg-boss job
 * `notifications.deliver` carries no payload: the work is the outbox (`notification_deliveries`),
 * so a lost or repeated job loses or repeats nothing. It is sent after an incident is created
 * (worker), after an agent-integrity event or a test request (web, best effort), and scheduled
 * every minute by the worker (retries with backoff, the silent-agent check). `stately`: bursts
 * coalesce.
 */
export const NOTIFICATION_QUEUE = "notifications.deliver";

export type NotificationJobSender = () => Promise<void>;

let sender: NotificationJobSender | null = null;

/** Installed at startup (web: pg-boss sender; worker: its own boss); tests install their own. */
export function setNotificationJobSender(s: NotificationJobSender | null): void {
  sender = s;
}

/** Asks the worker to send the due notifications. Never throws. */
export async function requestNotificationDelivery(): Promise<void> {
  const send = sender;
  if (!send) return;
  try {
    await send();
  } catch (err) {
    // Caught up by the worker's schedule.
    logger.warn({ queue: NOTIFICATION_QUEUE, error: errorSummary(err) }, "notification wake-up not sent");
  }
}
