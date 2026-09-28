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
