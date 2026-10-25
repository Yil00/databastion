import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { TARGET_NOTE_REGISTRY } from "@/generated/protocol/target-notes.gen";
import { setupHint } from "@/lib/detected-targets";
import {
  DISCOVERY_ONLY_ENGINES,
  engineDisplayName,
  isDiscoveryOnlyEngine,
  locationDatabaseShown,
  locationPartLabels,
} from "@/lib/location-labels";
import { renderEmail, webhookBody, type IncidentOpenedPayload } from "@/lib/notification-render";
import { renderTargetNote } from "@/lib/target-notes";
import type { FindingView } from "@/server/findings";
import type { IncidentView } from "@/server/incidents";
import type { ExceptionView } from "@/server/policies";

import { AuditLevelLabel } from "./audit-level";
import { FindingsTable, locationLabel, LocationCell } from "./findings-table";
import { incidentLocation } from "./incidents-table";
import { exceptionScopeLabels } from "./policies-table";
import { CROSS_TARGET_NOTE, EXCEPTION_MATCHING_NOTE, exceptionErrorMessage, exceptionRequestBody, exceptionSqliteScopeMessage } from "./policy-actions";
import { PolicyForm, SQLITE_LOCATION_HINT } from "./policy-form";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined, push: () => undefined }) }));

/**
 * P10-E: SQLite targets (ADR-0059): "Discovery only", the sqlite target notes, locations shown as
 * the target, the table and the column (never `main` as if it told files apart), and the
 * cross-target confirmation of location exceptions (P10-C review R2).
 */

const NOW = Date.parse("2026-10-25T12:00:00Z");
const AGENT = "01890a5d-ac96-774b-bcce-b302099a8058";

const finding = (over: Partial<FindingView> = {}): FindingView =>
  ({
    id: "01890a5d-ac96-774b-bcce-b302099a8002",
    agentId: AGENT,
    agentName: "app-host",
    targetId: "crm-app",
    engine: "sqlite",
    databaseName: "main",
    schemaName: null,
    objectName: "customers",
    fieldName: "email",
    classifier: "pii.email",
    classifiersVersion: "2026.09.1",
    confidence: 0.9,
    sampled: 64,
    matched: 61,
    estimatedRows: 100,
    samples: { state: "none" },
    fingerprintCount: 0,
    firstSeenAt: new Date(NOW - 3600_000),
    lastSeenAt: new Date(NOW - 60_000),
    falsePositiveAt: null,
    altered: null,
    ...over,
  }) as unknown as FindingView;

describe("SQLite targets: Discovery only (ADR-0059 decision 7)", () => {
  it("sqlite is the only Discovery-only engine, named SQLite", () => {
    expect(DISCOVERY_ONLY_ENGINES).toEqual(["sqlite"]);
    expect(isDiscoveryOnlyEngine("sqlite")).toBe(true);
    for (const e of ["postgres", "sqlserver", "redis", "cas", null, undefined]) expect(isDiscoveryOnlyEngine(e)).toBe(false);
    expect(engineDisplayName("sqlite")).toBe("SQLite");
    expect(setupHint("sqlite")).toContain("never detected");
  });

  it("the agent page's audit level says Discovery only for SQLite, the level alone elsewhere", () => {
    const html = renderToStaticMarkup(<AuditLevelLabel engine="sqlite" level="none" />);
    expect(html).toContain("none");
    expect(html).toContain("Discovery only");
    expect(html).toContain("data-discovery-only");
    expect(renderToStaticMarkup(<AuditLevelLabel engine="postgres" level="none" />)).toBe("none");
  });
});

describe("SQLite target notes (ADR-0059 decision 8)", () => {
  /** Every code whose engines name sqlite in the registry: the new ones and those sqlite joined. */
  const sqliteCodes = Object.entries(TARGET_NOTE_REGISTRY)
    .filter(([, n]) => (n as { engines?: readonly string[] }).engines?.includes("sqlite"))
    .map(([code]) => code);

  it("the registry names the 12 new sqlite codes and the 5 sqlite joined", () => {
    for (const code of [
      "coverage.unrecognized_file_format",
      "coverage.wal_files_not_readable",
      "coverage.hot_journal_pending",
      "coverage.network_filesystem_refused",
      "coverage.filesystem_not_read_only",
      "coverage.file_path_refused",
      "coverage.rollback_mode_not_read",
      "coverage.reader_sandbox_unavailable",
      "coverage.reader_process_failed",
      "coverage.virtual_tables_not_sampled",
      "privilege.database_file_writable",
      "security.file_world_readable",
      "check.stage_failed",
      "check.timed_out",
      "coverage.views_not_sampled",
      "coverage.computed_columns_not_sampled",
      "coverage.cas_guard_tripped",
    ]) {
      expect(sqliteCodes, code).toContain(code);
    }
  });

  it("every sqlite code renders from the catalog, with or without a count, never raw", () => {
    for (const code of sqliteCodes) {
      for (const note of [{ code }, { code, count: 3 }]) {
        const r = renderTargetNote(note);
        expect(r.known, code).toBe(true);
        expect(r.text, code).not.toMatch(/\{(count|labels)\}/);
        expect(r.text.length, code).toBeGreaterThan(0);
      }
    }
  });
});

describe("SQLite locations: target, table and column (ADR-0059 decision 6)", () => {
  it("labels and line: never main", () => {
    expect(locationDatabaseShown("sqlite")).toBe(false);
    expect(locationDatabaseShown("postgres")).toBe(true);
    expect(locationPartLabels("sqlite")).toMatchObject({ object: "table", field: "column" });
    const parts = { databaseName: "main", schemaName: null, objectName: "customers", fieldName: "email" };
    expect(locationLabel(parts, "sqlite")).toBe("table customers / column email");
    // Other engines: unchanged.
    expect(locationLabel({ ...parts, schemaName: "public", databaseName: "crm" }, "postgres")).toBe("crm / public / customers / email");
  });

  it("the findings table shows the target, the table and the column, and SQLite", () => {
    const html = renderToStaticMarkup(<FindingsTable findings={[finding()]} csrfToken="t" now={NOW} canMark={false} />);
    expect(html).toContain("crm-app");
    expect(html).toContain("customers");
    expect(html).toContain("email");
    expect(html).toContain(">table<");
    expect(html).toContain(">column<");
    expect(html).toContain("SQLite");
    expect(html).not.toContain(">main<");
    const cell = renderToStaticMarkup(<LocationCell location={finding()} engine="sqlite" />);
    expect(cell).not.toContain("main");
    // A table named `main` is still shown: only the database part is left out.
    expect(renderToStaticMarkup(<LocationCell location={finding({ objectName: "main" })} engine="sqlite" />)).toContain(">main<");
  });

  it("a hostile table or column name is escaped text, never markup nor a link (review N4)", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const link = "javascript:alert(1)";
    for (const over of [{ objectName: hostile }, { fieldName: hostile }, { objectName: link, fieldName: link }]) {
      const html = renderToStaticMarkup(<LocationCell location={finding(over)} engine="sqlite" />);
      expect(html).not.toContain("<img");
      expect(html).not.toMatch(/<a\b|href=/);
      expect(html).toContain(over.objectName === hostile || over.fieldName === hostile ? "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" : link);
    }
    const table = renderToStaticMarkup(<FindingsTable findings={[finding({ objectName: hostile, fieldName: hostile })]} csrfToken="t" now={NOW} canMark={false} />);
    expect(table).not.toContain("<img");
    for (const h of [...table.matchAll(/href="([^"]*)"/g)].map((m) => m[1] ?? "")) expect(decodeURIComponent(h)).not.toContain("onerror");
  });

  it("incidents and e-mails: table and column; the webhook keeps the contract location as is", () => {
    const incident = {
      engine: "sqlite",
      access: null,
      location: { databaseName: "main", schemaName: null, objectName: "customers", fieldName: "email" },
    } as Pick<IncidentView, "location" | "access" | "engine">;
    expect(incidentLocation(incident)).toBe("table customers / column email");
    const payload: IncidentOpenedPayload = {
      event: "incident.opened",
      occurred_at: "2026-10-25T12:00:00.000Z",
      url: null,
      incident: { id: "01890a5d-ac96-774b-bcce-b302099a8057", severity: "high", status: "open", reopened_from: null },
      policy: { id: "01890a5d-ac96-774b-bcce-b302099a8059", name: "PII", revision: 1 },
      agent_id: AGENT,
      target_id: "crm-app",
      classifier: "pii.email",
      classifiers_version: "2026.09.1",
      location: { engine: "sqlite", database: "main", schema: null, object: "customers", field: "email" },
      counts: { sampled: 64, matched: 61, confidence: 0.9 },
    };
    const { text } = renderEmail(payload);
    expect(text).toContain("Target:     crm-app (sqlite)");
    expect(text).toContain("Location:   table customers / column email");
    expect(text).not.toContain("main.");
    const body = JSON.parse(webhookBody("d-1", payload)) as { location: { database: string } };
    expect(body.location.database).toBe("main");
  });
});

describe("SQLite location exceptions in the UI (P10-C review R2)", () => {
  const ex = (over: Partial<ExceptionView> = {}): ExceptionView => ({
    id: "01890a5d-ac96-774b-bcce-b302099a8061",
    policyId: null,
    policyName: null,
    agentId: null,
    agentName: null,
    targetId: null,
    classifier: null,
    location: { object: "customers" },
    reason: "r",
    expiresAt: null,
    createdAt: new Date(NOW - 10),
    crossTarget: false,
    ...over,
  });

  it("the form sends cross_target only when the box is ticked", () => {
    const values = { "location.object": "customers", reason: "r" };
    expect(exceptionRequestBody(values)).not.toHaveProperty("cross_target");
    expect(exceptionRequestBody({ ...values, cross_target: "on" })).toMatchObject({ cross_target: true, location: { object: "customers" } });
    expect(exceptionErrorMessage(400, { error: "invalid_exception", field: "cross_target" })).toContain("cross-target");
    expect(CROSS_TARGET_NOTE).toContain("both the agent id and the target");
    expect(EXCEPTION_MATCHING_NOTE).toContain("SQLite");
  });

  it("the creation answer tells what the exception does on SQLite", () => {
    expect(exceptionSqliteScopeMessage("excluded")).toContain("covers no SQLite target");
    expect(exceptionSqliteScopeMessage("every_target")).toContain("every SQLite target");
    expect(exceptionSqliteScopeMessage("target")).toBe("");
    expect(exceptionSqliteScopeMessage("not_location")).toBe("");
    expect(exceptionSqliteScopeMessage(undefined)).toBe("");
  });

  it("the exceptions table states the SQLite reach of a location exception that is not target-scoped", () => {
    expect(exceptionScopeLabels(ex())).toContain("no SQLite target (not target-scoped)");
    expect(exceptionScopeLabels(ex({ crossTarget: true }))).toContain("every SQLite target (cross-target, confirmed)");
    // Review N2: a confirmation scoped to an agent (or a target id) says so.
    expect(exceptionScopeLabels(ex({ crossTarget: true, agentId: AGENT, agentName: "app-host" }))).toContain(
      "every SQLite target of agent app-host (cross-target, confirmed)",
    );
    expect(exceptionScopeLabels(ex({ crossTarget: true, agentId: AGENT }))).toContain(`every SQLite target of agent ${AGENT} (cross-target, confirmed)`);
    expect(exceptionScopeLabels(ex({ crossTarget: true, targetId: "crm-app" }))).toContain(
      "every SQLite target crm-app, on any agent (cross-target, confirmed)",
    );
    const scoped = exceptionScopeLabels(ex({ agentId: AGENT, targetId: "crm-app" }));
    expect(scoped.join(";")).not.toContain("SQLite");
    expect(exceptionScopeLabels(ex({ location: null, classifier: "pii.email" })).join(";")).not.toContain("SQLite");
  });
});

describe("SQLite location conditions in the policy form (review N3)", () => {
  it("the form says a SQLite location pattern matches every SQLite file, and how to narrow it", () => {
    expect(SQLITE_LOCATION_HINT).toContain("every SQLite file");
    expect(SQLITE_LOCATION_HINT).toContain("target or agent ids");
    const html = renderToStaticMarkup(<PolicyForm csrfToken="c" />);
    expect(html).toContain("data-sqlite-location-hint");
    expect(html).toContain("every SQLite file");
  });
});
