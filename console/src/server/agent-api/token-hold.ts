import { AGENT_TOKENS_HOLD_VAR, agentTokensHold, type Env } from "@/config/env";
import { processGlobal } from "@/server/process-global";

import { heldAccepts } from "./capabilities";

/**
 * Recurring signals of `DATABASTION_AGENT_TOKENS_HOLD` (ADR-0022 decision 8; security review of the
 * token hold, L1): while the hold is set, the ADR-0053, ADR-0055 and ADR-0056 detection rules do
 * not apply to new items (no agent sends those fields), so a hold left set after the upgrade must
 * stay visible: a startup warning, a warning at most once an hour from the heartbeat path of each
 * web process, and the `databastion_console_agent_tokens_hold` gauge (src/server/metrics.ts).
 */

/** At most one recurring hold warning per process and hour. */
export const TOKENS_HOLD_WARNING_INTERVAL_MS = 3_600_000;

/**
 * The hold warning (startup and hourly): names the release line and the held tokens (constants
 * only, never a configured value that was not validated). `null` when the hold is unset or invalid
 * (an invalid value is reported by `startupFatal`).
 */
export function agentTokensHoldWarning(env: Env = process.env): string | null {
  let hold: string | null;
  try {
    hold = agentTokensHold(env);
  } catch {
    return null;
  }
  if (hold === null) return null;
  const held = heldAccepts(env);
  return (
    `${AGENT_TOKENS_HOLD_VAR}=${hold}: heartbeat answers list the capability tokens of console ${hold}, not ${held.length === 0 ? "(none held)" : held.join(", ")}; ` +
    "every field is still accepted, but the detection rules that depend on these fields (ADR-0053, ADR-0055, ADR-0056) do not apply while agents do not send them. " +
    'Remove it from every replica once none runs an older release (deploy/README.md, "Rolling upgrade of several console replicas").'
  );
}

const lastWarning = processGlobal<{ at: number | null }>("agentTokensHold.lastWarning", () => ({ at: null }));

/**
 * The hold warning when one is due in this process (the first call while held, then at most once
 * per {@link TOKENS_HOLD_WARNING_INTERVAL_MS}); `null` otherwise. Called from the heartbeat handler,
 * so a replica that answers agents keeps reporting its hold.
 */
export function tokensHoldWarningDue(now: number = Date.now(), env: Env = process.env): string | null {
  const warning = agentTokensHoldWarning(env);
  if (warning === null) return null;
  const at = lastWarning.at;
  if (at !== null && now >= at && now - at < TOKENS_HOLD_WARNING_INTERVAL_MS) return null;
  lastWarning.at = now;
  return warning;
}

/** Test hook: forget the last recurring warning. */
export function resetTokensHoldWarning(): void {
  lastWarning.at = null;
}

/**
 * The `databastion_console_agent_tokens_hold` series of this process: `{release: "0.8"}` with value 1 while
 * held, no label and 0 when unset. An invalid value (fatal at startup) reports the fallback list's
 * release, as the listing does.
 */
export function tokensHoldMetric(env: Env = process.env): { value: 0 | 1; labels: Record<string, string> } {
  let hold: string | null;
  try {
    hold = agentTokensHold(env);
  } catch {
    hold = "invalid";
  }
  return hold === null ? { value: 0, labels: {} } : { value: 1, labels: { release: hold } };
}
