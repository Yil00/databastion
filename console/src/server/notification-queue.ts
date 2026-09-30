import { wakeUp, type JobSender } from "./wake-up";

/**
 * Wake-up of the notification delivery (P3-C). Like `policies.evaluate`, the pg-boss job
 * `notifications.deliver` carries no payload: the work is the outbox (`notification_deliveries`),
 * so a lost or repeated job loses or repeats nothing. It is sent after an incident is created
 * (worker, through its own pg-boss instance), after an agent-integrity event, a dropped-batches
 * alert or a test request
 * (web, best effort, through the sender below), and scheduled every minute by the worker (retries
 * with backoff, the silent-agent check). `stately`: bursts coalesce.
 */
export const NOTIFICATION_QUEUE = "notifications.deliver";

export type NotificationJobSender = JobSender;

// Process-wide (globalThis): installed by the startup hook, read by the route handlers, which run
// another bundled copy of this module (see process-global.ts).
const notificationWakeUp = wakeUp(NOTIFICATION_QUEUE, "notificationJobSender", "notification wake-up not sent");

/** Installed at startup by the web process (pg-boss sender); tests install their own. */
export function setNotificationJobSender(s: NotificationJobSender | null): void {
  notificationWakeUp.setSender(s);
}

/** Asks the worker to send the due notifications. Never throws (caught up by the worker's schedule). */
export function requestNotificationDelivery(): Promise<void> {
  return notificationWakeUp.request();
}
