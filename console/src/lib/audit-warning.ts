/** Warning left on a target by a change that narrowed its Audit settings (P4-C, `audit_configs.warning`). */
export type AuditWarning = "disabled" | "emptied" | "shrunk";

export function auditWarningText(warning: AuditWarning, removed: number | null): string {
  switch (warning) {
    case "disabled":
      return "The last change turned Audit off for this target.";
    case "emptied":
      return `The last change emptied the sensitive objects (${removed ?? "?"} removed): only accesses with a signal or above the row threshold are reported.`;
    case "shrunk":
      return `The last change removed ${removed ?? "?"} sensitive objects: accesses to them are only reported with a signal or above the row threshold.`;
  }
}

/**
 * Warning on a `min_rows` setting that cannot work as intended on the target's engine (#235 review
 * N2), shown by the Audit settings page and returned by the API; it does not block the save.
 * `no_row_counts`: a key-pattern (Redis / Valkey) target. Its events carry no row count, so a
 * `min_rows` value makes the agent drop every read and write event of the target that carries no
 * signal, is not always reported and names no listed sensitive key pattern (none can be listed
 * for an agent that does not accept key patterns, phase 9 follow-ups).
 */
export type MinRowsWarning = "no_row_counts";

export function minRowsWarning(keyPatternEngine: boolean, minRows: number | null): MinRowsWarning | null {
  return keyPatternEngine && minRows !== null ? "no_row_counts" : null;
}

export const MIN_ROWS_WARNING_TEXT: Record<MinRowsWarning, string> = {
  no_row_counts:
    "A row threshold is set, but the events of this target carry no row count: the agent drops every read and write event of this target that carries no signal and names no listed sensitive key pattern (always-reported events, such as scripts, still pass; an agent that cannot receive key patterns gets none), and policy row conditions never match them. Leave the row threshold empty on this target, unless its sensitive objects cover every key pattern that matters.",
};
