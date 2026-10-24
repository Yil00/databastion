import { processSlot } from "./process-global";

/**
 * On-demand case inventory (ADR-0054 decision 6): the web process only queues the job, the worker
 * runs it (`registerCaseInventoryQueue`), so a run never holds a web connection or the web event
 * loop (security review M1). The queue is `stately`: at most one job queued and one active, so
 * repeated requests coalesce.
 */
export const CASE_INVENTORY_QUEUE = "policy_exceptions.case_inventory";

export interface CaseInventoryJob {
  userId: string;
  ip: string | null;
}

/** Sends the job; resolves to the job id, or `null` when one is already queued (coalesced). */
export type CaseInventoryJobSender = (job: CaseInventoryJob) => Promise<string | null>;

// Process-wide (globalThis): installed by the startup hook, read by the route handler, which runs
// another bundled copy of this module (see process-global.ts).
const slot = processSlot<CaseInventoryJobSender>("caseInventoryJobSender");

/** Installed at startup by the web process (pg-boss sender); tests install their own. */
export function setCaseInventoryJobSender(s: CaseInventoryJobSender | null): void {
  slot.set(s);
}

/**
 * Queues an inventory run. `"queued"` / `"coalesced"` (one already queued), `"unavailable"` when no
 * sender is installed or the send failed (the caller answers `503`).
 */
export async function requestCaseInventory(job: CaseInventoryJob): Promise<"queued" | "coalesced" | "unavailable"> {
  const send = slot.get();
  if (!send) return "unavailable";
  try {
    return (await send(job)) === null ? "coalesced" : "queued";
  } catch {
    return "unavailable";
  }
}
