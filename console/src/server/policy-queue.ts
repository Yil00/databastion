import { wakeUp, type JobSender } from "./wake-up";

/**
 * Wake-up of the policy engine (P3-A). The engine's work is recorded durably in the console
 * tables, not in the queue: a finding is pending while `policy_evaluated_at` differs from
 * `last_seen_at`, a policy while `evaluated_at` is older than `changed_at` (see incidents.ts). The
 * pg-boss job `policies.evaluate` carries no payload and only tells the worker to drain that work,
 * so a lost or duplicated job never loses or duplicates an evaluation:
 * - the web process sends it **after** the commit of a findings batch or a policy change
 *   (best effort, errors logged, never failing the request);
 * - the worker also schedules it every minute (catch-up after a lost send or a restart);
 * - the queue is `stately`: at most one job queued and one active, so bursts coalesce.
 */

export const POLICY_QUEUE = "policies.evaluate";

export type PolicyJobSender = JobSender;

// Process-wide (globalThis): installed by the startup hook, read by the route handlers, which run
// another bundled copy of this module (see process-global.ts).
const policyWakeUp = wakeUp(POLICY_QUEUE, "policyJobSender", "policy evaluation wake-up not sent");

/** Installed at startup by the web process (pg-boss sender); tests install their own. */
export function setPolicyJobSender(s: PolicyJobSender | null): void {
  policyWakeUp.setSender(s);
}

/** Asks the worker to drain the policy work. Never throws (caught up by the worker's schedule). */
export function requestPolicyEvaluation(): Promise<void> {
  return policyWakeUp.request();
}
