/**
 * Incident lifecycle and severities (P3-B). No dependency: imported by client components too.
 */

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const INCIDENT_STATUSES = ["open", "acknowledged", "resolved", "false_positive"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export const ACTIVE_STATUSES: readonly IncidentStatus[] = ["open", "acknowledged"];

/**
 * Allowed transitions (P3-B): open -> acknowledged -> resolved, open -> resolved, and open /
 * acknowledged -> false_positive. `resolved` and `false_positive` are final: a later change of the
 * finding opens a new incident instead (see the worker).
 */
const TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  open: ["acknowledged", "resolved", "false_positive"],
  acknowledged: ["resolved", "false_positive"],
  resolved: [],
  false_positive: [],
};

export function canTransition(from: IncidentStatus, to: IncidentStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

/** `false_positive` is an administrator decision (same rule as on findings, M2). */
export function transitionNeedsAdmin(to: IncidentStatus): boolean {
  return to === "false_positive";
}

export function isIncidentStatus(v: unknown): v is IncidentStatus {
  return typeof v === "string" && (INCIDENT_STATUSES as readonly string[]).includes(v);
}

export function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
}
