import { describe, expect, it } from "vitest";

import { TARGET_NOTE_REGISTRY } from "@/generated/protocol/target-notes.gen";

import {
  fillTemplate,
  labelDisplayName,
  MAX_TARGET_NOTES,
  MAX_TARGET_NOTES_BYTES,
  noteTemplate,
  notesToStore,
  parseStoredNotes,
  renderTargetNote,
} from "./target-notes";

describe("target note rendering", () => {
  it("renders a registered code from the catalog, with {count} and {labels}", () => {
    expect(renderTargetNote({ code: "coverage.relations_rls_skipped", count: 5 })).toEqual({
      text: "5 relation(s) skipped because of row-level security (ADR-0012).",
      known: true,
      code: "coverage.relations_rls_skipped",
    });
    expect(renderTargetNote({ code: "privilege.role_attributes", labels: ["bypassrls", "createrole"] }).text).toBe(
      "Role attributes beyond the minimal grants: BYPASSRLS, CREATEROLE.",
    );
    expect(renderTargetNote({ code: "privilege.beyond_select", labels: ["alter_routine", "binlog_admin", "other"] }).text).toBe(
      "Privileges beyond SELECT on databases, tables or columns: ALTER ROUTINE, BINLOG ADMIN, other.",
    );
    expect(renderTargetNote({ code: "privilege.predefined_roles", labels: ["pg_write_all_data"] }).text).toBe(
      "Member of predefined roles beyond the minimal grants: pg_write_all_data.",
    );
    expect(renderTargetNote({ code: "security.tls_disabled" }).known).toBe(true);
  });

  it("shows ? for a missing count or missing labels", () => {
    expect(renderTargetNote({ code: "coverage.relations_rls_skipped" }).text).toBe(
      "? relation(s) skipped because of row-level security (ADR-0012).",
    );
    expect(renderTargetNote({ code: "privilege.role_attributes", labels: [] }).text).toBe("Role attributes beyond the minimal grants: ?.");
  });

  it("shows an unknown code raw, with its count and raw labels", () => {
    expect(renderTargetNote({ code: "coverage.shards_skipped", count: 3, labels: ["other", "<b>x</b>"] })).toEqual({
      text: "coverage.shards_skipped, count 3, labels other, <b>x</b>",
      known: false,
      code: "coverage.shards_skipped",
    });
    expect(renderTargetNote({ code: "audit.new_thing" }).text).toBe("audit.new_thing");
  });

  it("never resolves prototype names to a template", () => {
    for (const code of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
      expect(noteTemplate(code)).toBeNull();
      expect(renderTargetNote({ code }).known).toBe(false);
    }
  });

  it("substitutes in a single, non-recursive pass", () => {
    // A placeholder-like string inside a label is inserted literally, never expanded again.
    expect(fillTemplate("Roles: {labels}; {count} of them.", { count: 2, labels: ["{count}", "{labels}"] })).toBe(
      "Roles: {count}, {labels}; 2 of them.",
    );
    // `$` replacement patterns have no meaning in a value.
    expect(fillTemplate("{labels} / {count}", { labels: ["$&", "$1", "$$", "$`"] })).toBe("$&, $1, $$, $` / ?");
    // Unknown placeholders and repeated placeholders.
    expect(fillTemplate("{other} {count}{count}", { count: 7 })).toBe("{other} 77");
    // A non-integer count (stored by mistake) is shown as ?.
    expect(fillTemplate("{count}", { count: 1.5 })).toBe("?");
    expect(fillTemplate("{count}", { count: -1 })).toBe("?");
  });

  it("every catalog template only uses the {count} and {labels} placeholders", () => {
    for (const [code, entry] of Object.entries(TARGET_NOTE_REGISTRY)) {
      const placeholders = entry.description.match(/\{[^}]*\}/g) ?? [];
      for (const p of placeholders) expect(["{count}", "{labels}"], `${code}: ${p}`).toContain(p);
    }
  });

  it("labels: contract values get a display name, other values are shown raw", () => {
    expect(labelDisplayName("superuser")).toBe("SUPERUSER");
    expect(labelDisplayName("create_temporary_tables")).toBe("CREATE TEMPORARY TABLES");
    expect(labelDisplayName("stage_auth")).toBe("stage_auth");
    expect(labelDisplayName("logging_on")).toBe("logging_on");
    expect(labelDisplayName("pg_monitor")).toBe("pg_monitor");
    expect(labelDisplayName("not_a_label")).toBe("not_a_label");
  });
});

describe("target note storage", () => {
  it("keeps the contract fields only, in a fixed shape; null when there is none", () => {
    expect(notesToStore(undefined)).toBeNull();
    expect(notesToStore([])).toBeNull();
    const extra = { code: "security.tls_disabled", count: 1, labels: ["other"], extra: "x" } as { code: string; count: number; labels: string[] };
    expect(notesToStore([extra])).toEqual([{ code: "security.tls_disabled", count: 1, labels: ["other"] }]);
  });

  it("bounds the number of notes and their serialized size", () => {
    const many = Array.from({ length: 40 }, () => ({ code: "security.tls_disabled" }));
    expect(notesToStore(many)).toHaveLength(MAX_TARGET_NOTES);
    const big = Array.from({ length: 16 }, () => ({ code: "x".repeat(3000) }));
    const stored = notesToStore(big) ?? [];
    expect(stored.length).toBeLessThan(16);
    expect(JSON.stringify(stored, null, 1).length).toBeLessThanOrEqual(MAX_TARGET_NOTES_BYTES);
  });

  it("re-checks stored notes on read and drops malformed entries", () => {
    expect(parseStoredNotes(null)).toEqual([]);
    expect(parseStoredNotes({ code: "x" })).toEqual([]);
    expect(
      parseStoredNotes([
        { code: "audit.x", count: 2, labels: ["other", 3, ""] },
        { code: 5 },
        "audit.y",
        null,
        { code: "" },
        { code: "audit.z", count: "3" },
      ]),
    ).toEqual([{ code: "audit.x", count: 2, labels: ["other"] }, { code: "audit.z" }]);
    expect(parseStoredNotes(Array.from({ length: 30 }, () => ({ code: "a.b" })))).toHaveLength(MAX_TARGET_NOTES);
  });
});
