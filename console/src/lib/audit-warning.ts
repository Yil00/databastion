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
 * `no_row_counts`: a key-pattern (Redis / Valkey) target. Its events carry no row count and its
 * key patterns cannot be listed as sensitive objects yet, so a `min_rows` value makes the agent
 * drop every read and write event of the target that carries no signal and is not always reported.
 */
export type MinRowsWarning = "no_row_counts";

export function minRowsWarning(keyPatternEngine: boolean, minRows: number | null): MinRowsWarning | null {
  return keyPatternEngine && minRows !== null ? "no_row_counts" : null;
}

export const MIN_ROWS_WARNING_TEXT: Record<MinRowsWarning, string> = {
  no_row_counts:
    "A row threshold is set, but the events of this target carry no row count and its key patterns cannot be listed as sensitive objects yet: the agent drops every read and write event of this target that carries no signal (always-reported events, such as scripts, still pass), and policy row conditions never match them. Leave the row threshold empty on this target.",
};
