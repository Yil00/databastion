import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import bundle from "@/generated/protocol/schemas.gen.json";
import { TARGET_NOTE_REGISTRY } from "@/generated/protocol/target-notes.gen";
import { setupHint } from "@/lib/detected-targets";
import { auditSourceEngine, engineDisplayName, hasNamedLocationParts, isDiscoveryOnlyEngine, locationDatabaseShown, locationPartLabels } from "@/lib/location-labels";
import { labelDisplayName, renderTargetNote, type StoredTargetNote } from "@/lib/target-notes";
import { fixtures } from "@/test/helpers";

import { locationLabel } from "./findings-table";
import { TargetNotes } from "./target-notes";

/**
 * P10-E: Firebird targets (ADR-0060 decision 8): the eight Firebird note codes and the codes Firebird
 * joined render from the catalog, the labels of revision `target_status.note_labels.2026_10_d` get
 * their Firebird display names, `stage_tls` on a `firebird` target is the wire-encryption stage, and
 * locations show the declared database, the table and the column (no schema).
 */

const enumOf = (schema: string): string[] => ((bundle.$defs as Record<string, { enum?: string[] }>)[schema]?.enum ?? []).slice();

/** The labels of revision 2026_10_d: every `TargetNoteLabel` after `on_failure_probe` (2026_10_c). */
const REVISION_D = (() => {
  const all = enumOf("TargetNoteLabel");
  return all.slice(all.indexOf("on_failure_probe") + 1);
})();

type Hb = { targets: { target_id: string; engine: string; notes?: StoredTargetNote[] }[] };

function heartbeat(name: string): Hb {
  const found = fixtures("valid", "HeartbeatRequest").find(([f]) => f === name);
  if (!found) throw new Error(`no fixture ${name}`);
  return found[1] as Hb;
}

describe("Firebird targets: engine, detection and audit source (ADR-0060 decisions 6 and 7)", () => {
  it("is named Firebird, has Audit (not Discovery only), a setup hint, and its own audit source", () => {
    expect(engineDisplayName("firebird")).toBe("Firebird");
    expect(isDiscoveryOnlyEngine("firebird")).toBe(false);
    expect(setupHint("firebird")).toContain("never SYSDBA");
    expect(auditSourceEngine("firebird_audit_trace")).toBe("firebird");
  });
});

describe("Firebird target notes (ADR-0060 decision 8)", () => {
  const firebirdCodes = Object.entries(TARGET_NOTE_REGISTRY)
    .filter(([, n]) => (n as { engines?: readonly string[] }).engines?.includes("firebird"))
    .map(([code]) => code);

  it("the registry names the six codes of decision 8 and the two of the refinements", () => {
    for (const code of [
      "coverage.external_file_tables",
      "audit.trace_config_not_evaluated",
      "audit.trace_settings_missing",
      "audit.services_not_audited",
      "audit.log_records_ambiguous",
      "security.firebird_tunnel",
      "audit.log_readable_by_others",
      "coverage.security_database_excluded",
    ]) {
      expect(firebirdCodes, code).toContain(code);
    }
  });

  it("every firebird code renders from the catalog, with or without a count or labels, never raw", () => {
    for (const code of firebirdCodes) {
      for (const note of [{ code }, { code, count: 3 }, { code, count: 1, labels: ["other"] }]) {
        const r = renderTargetNote(note, "firebird");
        expect(r.known, code).toBe(true);
        expect(r.text, code).not.toMatch(/\{(count|labels)\}/);
        expect(r.text.length, code).toBeGreaterThan(0);
      }
    }
  });

  it("every note of the firebird heartbeat fixtures renders from the catalog", () => {
    for (const name of ["HeartbeatRequest.firebird.json", "HeartbeatRequest.firebird-labels-2026-10-d.json"]) {
      for (const t of heartbeat(name).targets) {
        for (const n of t.notes ?? []) expect(renderTargetNote(n, t.engine).known, `${name} ${n.code}`).toBe(true);
      }
    }
  });
});

describe("Firebird note labels (revision target_status.note_labels.2026_10_d)", () => {
  it("covers the revision: 27 system privileges, 4 identities, usage, 4 relations and probes, 9 reasons, 1 stall reason, 18 settings", () => {
    expect(REVISION_D).toHaveLength(64);
    expect(REVISION_D[0]).toBe("user_management");
  });

  it("system privileges in upper case with their underscores, as Firebird writes them", () => {
    expect(labelDisplayName("trace_any_attachment")).toBe("TRACE_ANY_ATTACHMENT");
    expect(labelDisplayName("select_any_object_in_database")).toBe("SELECT_ANY_OBJECT_IN_DATABASE");
    expect(labelDisplayName("use_gbak_utility")).toBe("USE_GBAK_UTILITY");
    expect(labelDisplayName("create_database")).toBe("CREATE_DATABASE");
    expect(labelDisplayName("profile_any_attachment")).toBe("PROFILE_ANY_ATTACHMENT");
  });

  it("refusal-list identities as Firebird names them, usage as a privilege", () => {
    expect(labelDisplayName("sysdba")).toBe("SYSDBA");
    expect(labelDisplayName("rdb_admin")).toBe("RDB$ADMIN");
    expect(labelDisplayName("database_owner")).toBe("database owner");
    expect(labelDisplayName("security_database_admin")).toBe("SEC$ADMIN (security database administrator)");
    expect(labelDisplayName("usage")).toBe("USAGE");
  });

  it("probes, reasons and fbtrace.conf settings as sent", () => {
    for (const label of [
      "verifier_relation_readable",
      "credential_relation_readable",
      "server_config_readable",
      "role_graph",
      "firebird_conf_unreadable",
      "trace_config_unreadable",
      "trace_config_file_mismatch",
      "config_changed_since_start",
      "server_process_not_visible",
      "similar_to_pattern",
      "databases_conf",
      "foreign_databases_logged",
      "database_path_not_unique",
      "run_confirmation_stalled",
      "enabled",
      "log_filename",
      "log_statement_finish",
      "log_blr_requests",
      "log_transactions",
      "log_initfini",
      "log_sweep",
      "log_services",
      "time_threshold",
      "print_perf",
      "include_filter",
      "exclude_filter",
      "connection_id",
    ]) {
      expect(labelDisplayName(label), label).toBe(label);
    }
  });

  it("gives every label of the revision a display name, none of them the generic spaced form", () => {
    for (const label of REVISION_D) {
      const shown = labelDisplayName(label, "firebird");
      expect(shown.length, label).toBeGreaterThan(0);
      // The generic rule (`a_b` -> `A B`) would misname Firebird privileges and settings.
      if (label.includes("_")) expect(shown, label).not.toBe(label.replace(/_/g, " ").toUpperCase());
    }
  });

  it("leaves the labels of the other revisions unchanged", () => {
    expect(labelDisplayName("binlog_admin")).toBe("BINLOG ADMIN");
    expect(labelDisplayName("control_server")).toBe("CONTROL SERVER");
    expect(labelDisplayName("bypassrls")).toBe("BYPASSRLS");
    expect(labelDisplayName("insert", "firebird")).toBe("INSERT");
    expect(labelDisplayName("on_failure_probe")).toBe("on_failure_probe");
  });

  it("renders the 2026_10_d fixture's notes with the Firebird names", () => {
    const [sysdba, crm] = heartbeat("HeartbeatRequest.firebird-labels-2026-10-d.json").targets;
    const refused = renderTargetNote((sysdba?.notes ?? [])[0] as StoredTargetNote, "firebird");
    expect(refused.text).toContain("SYSDBA, RDB$ADMIN, TRACE_ANY_ATTACHMENT, verifier_relation_readable");
    const texts = (crm?.notes ?? []).map((n) => renderTargetNote(n, "firebird").text);
    expect(texts.join("\n")).toContain("SELECT_ANY_OBJECT_IN_DATABASE, credential_relation_readable, server_config_readable");
    expect(texts.join("\n")).toContain("time_threshold, print_perf, log_blr_requests, log_transactions, log_initfini, log_sweep, exclude_filter");
    expect(texts.join("\n")).toContain("INSERT, USAGE, CREATE");
  });
});

describe("stage_tls on Firebird is the wire-encryption stage (ADR-0060 decision 1)", () => {
  const note = { code: "check.stage_failed", labels: ["stage_tls"] };

  it("is shown as wire encryption on firebird only", () => {
    expect(labelDisplayName("stage_tls", "firebird")).toBe("wire encryption (stage_tls)");
    expect(labelDisplayName("stage_tls")).toBe("stage_tls");
    for (const e of ["postgres", "sqlserver", "mysql", "redis"]) expect(labelDisplayName("stage_tls", e)).toBe("stage_tls");
    expect(renderTargetNote(note, "firebird").text).toContain("wire encryption (stage_tls)");
    expect(renderTargetNote(note, "postgres").text).not.toContain("wire encryption");
    expect(labelDisplayName("stage_auth", "firebird")).toBe("stage_auth");
  });

  it("the agent page's notes cell passes the target's engine", () => {
    expect(renderToStaticMarkup(<TargetNotes notes={[note]} engine="firebird" />)).toContain("wire encryption (stage_tls)");
    expect(renderToStaticMarkup(<TargetNotes notes={[note]} engine="sqlserver" />)).not.toContain("wire encryption");
    // The fixture's unreachable target.
    const down = heartbeat("HeartbeatRequest.firebird.json").targets.find((t) => t.target_id === "fb-down");
    expect(renderToStaticMarkup(<TargetNotes notes={down?.notes ?? []} engine={down?.engine ?? null} />)).toContain("wire encryption (stage_tls)");
  });

  it("escapes every rendered note (plain text, never HTML)", () => {
    const html = renderToStaticMarkup(<TargetNotes notes={[{ code: "privilege.refused", labels: ["rdb_admin", "<b>x</b>"] }]} engine="firebird" />);
    expect(html).toContain("RDB$ADMIN");
    expect(html).not.toContain("<b>");
  });
});

describe("Firebird locations: database, table and column, no schema (ADR-0060 decision 5)", () => {
  it("shows the declared database, the table and the column on one line", () => {
    expect(locationDatabaseShown("firebird")).toBe(true);
    expect(hasNamedLocationParts("firebird")).toBe(false);
    expect(locationPartLabels("firebird")).toMatchObject({ database: "database", object: "table", field: "column" });
    expect(locationLabel({ databaseName: "crm", schemaName: null, objectName: "CUSTOMERS", fieldName: "EMAIL" }, "firebird")).toBe("crm / CUSTOMERS / EMAIL");
  });
});
