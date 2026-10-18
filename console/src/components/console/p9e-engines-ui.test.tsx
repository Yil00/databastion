import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { parseDetectedTargets, setupHint, detectedHow } from "@/lib/detected-targets";
import { parseFindingFilter } from "@/lib/findings-filter";
import { inlineCode, isKeyPatternSource } from "@/lib/key-pattern";
import { engineDisplayName, locationPartLabels } from "@/lib/location-labels";
import { renderEmail, webhookBody, type AccessIncidentOpenedPayload, type IncidentOpenedPayload } from "@/lib/notification-render";
import { ENGINES, type Engine } from "@/lib/protocol/enums";
import { validateSchema } from "@/lib/protocol/validate";
import { labelDisplayName, renderTargetNote } from "@/lib/target-notes";
import type { EventView } from "@/server/events";
import type { FindingView } from "@/server/findings";
import type { IncidentView } from "@/server/incidents";

import { formatManualObjects, parseManualObjects } from "./audit-form";
import { EventsTable, objectsLabel, PrincipalLabel } from "./events-table";
import { findingsHref, FindingsTable, locationLabel } from "./findings-table";
import { incidentLocation, IncidentsTable } from "./incidents-table";

/**
 * P9-E: Redis / Valkey key patterns (contract `KeyPattern` rendering rule), principals without a
 * recorded account, SQL Server labels, engine names and filters, detected-target hints.
 */

/** Key patterns the schema accepts that would be dangerous if linked or auto-linked. */
const HOSTILE_PATTERNS = ["x:javascript:alert", "www.evil.example/login", "a:https:evil.example"];

const NOW = Date.parse("2026-10-14T12:00:00Z");
const AGENT = "01890a5d-ac96-774b-bcce-b302099a8058";

/** Every `href` value of the markup. */
function hrefs(html: string): string[] {
  return [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1] ?? "");
}

const event = (over: Partial<EventView> = {}): EventView => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8001",
  agentId: AGENT,
  agentName: "cache-host",
  targetId: "cache-redis",
  ts: new Date(NOW - 120_000),
  tsLast: null,
  receivedAt: new Date(NOW - 60_000),
  principalKey: "b".repeat(64),
  principal: "app",
  fingerprinted: false,
  accountNotRecorded: false,
  clientAddr: "198.51.100.30",
  application: null,
  action: "read",
  objects: HOSTILE_PATTERNS.map((object) => ({ database: "db0", object })),
  engine: "redis",
  rows: null,
  bytes: 70000,
  signals: [],
  source: "redis_slowlog",
  aggregatedCount: 1,
  unexpectedTarget: false,
  evaluated: true,
  sensitivity: null,
  score: 0,
  anomaly: false,
  baselineRows: null,
  incidentIds: [],
  ...over,
});

const finding = (object: string, engine = "redis"): FindingView =>
  ({
    id: "01890a5d-ac96-774b-bcce-b302099a8002",
    agentId: AGENT,
    agentName: "cache-host",
    targetId: "cache-redis",
    engine,
    databaseName: "db0",
    schemaName: "hash",
    objectName: object,
    fieldName: "email",
    classifier: "pii.email",
    classifiersVersion: "2026.09.1",
    confidence: 0.9,
    sampled: 10,
    matched: 9,
    estimatedRows: 100,
    samples: { state: "none" },
    fingerprintCount: 0,
    firstSeenAt: new Date(NOW - 3600_000),
    lastSeenAt: new Date(NOW - 60_000),
    falsePositiveAt: null,
  }) as unknown as FindingView;

describe("KeyPattern rendering rule (contract, ADR-0052 decision 7)", () => {
  it("the hostile test patterns are valid key patterns, so the rendering rule is what protects them", () => {
    for (const p of HOSTILE_PATTERNS) {
      const body = { engine: "redis", database: "db0", schema: "hash", object: p, field: "email" };
      expect(validateSchema("Location", body).ok, p).toBe(true);
    }
  });

  it("findings: a key pattern is escaped text in <code>, never a link nor an href", () => {
    for (const p of [...HOSTILE_PATTERNS, '<img src=x onerror="alert(1)">']) {
      const html = renderToStaticMarkup(<FindingsTable findings={[finding(p)]} csrfToken="t" now={NOW} canMark={false} />);
      expect(html).not.toMatch(/<a\b/);
      for (const h of hrefs(html)) expect(h).not.toContain(p);
      expect(html).toContain("data-key-pattern");
      expect(html).not.toContain("<img");
      expect(html).toContain("key pattern");
      expect(html).toContain("type");
    }
    expect(locationLabel({ databaseName: "db0", schemaName: "string", objectName: "user:*:email", fieldName: "value" }, "redis")).toBe(
      "database db0 / type string / key pattern user:*:email / field value",
    );
  });

  it("events: key patterns are escaped text in <code>; links (target, principal) never carry them", () => {
    const html = renderToStaticMarkup(<EventsTable events={[event()]} now={NOW} />);
    for (const p of HOSTILE_PATTERNS) {
      expect(html).toContain(`>${p}</code>`);
      for (const h of hrefs(html)) expect(decodeURIComponent(h)).not.toContain(p);
    }
    expect(html).not.toMatch(/href="(javascript|https?:|www\.)/);
    expect(objectsLabel(event().objects, 3, "valkey")).toBe(
      "key pattern x:javascript:alert in db0, key pattern www.evil.example/login in db0, key pattern a:https:evil.example in db0",
    );
  });

  it("plain-text e-mail: key patterns of Redis / Valkey sources and locations are inline code", () => {
    const access: AccessIncidentOpenedPayload = {
      event: "incident.opened",
      source: "access_event",
      occurred_at: "2026-10-14T12:00:00.000Z",
      url: null,
      incident: { id: "01890a5d-ac96-774b-bcce-b302099a8057", severity: "high", status: "open", reopened_from: null },
      policy: { id: "01890a5d-ac96-774b-bcce-b302099a8059", name: "Redis reads", revision: 1 },
      agent_id: AGENT,
      target_id: "cache-redis",
      overflow: null,
      principal: "app",
      principal_fingerprinted: false,
      principal_not_recorded: false,
      database: "db0",
      hour: "2026-10-14T11:00:00.000Z",
      access: {
        ts: "2026-10-14T11:02:00.000Z",
        action: "read",
        source: "redis_slowlog",
        rows: null,
        score: 0,
        sensitivity: 0,
        anomaly: false,
        signals: [],
        unregistered_signals: [],
        objects: HOSTILE_PATTERNS.map((object) => ({ database: "db0", schema: null, object })),
      },
    };
    const { text } = renderEmail(access);
    expect(text).toContain("Objects:    db0 / `x:javascript:alert`, db0 / `www.evil.example/login`, db0 / `a:https:evil.example`");
    // Never bare: every occurrence is inside backticks.
    for (const p of HOSTILE_PATTERNS) expect(text.split(`\`${p}\``).join("")).not.toContain(p);
    // Webhook: a JSON string, as sent.
    const body = JSON.parse(webhookBody("d-1", access)) as { access: { objects: { object: string }[] } };
    expect(body.access.objects.map((o) => o.object)).toEqual(HOSTILE_PATTERNS);
    // Other sources: unchanged (no code formatting).
    expect(renderEmail({ ...access, access: { ...access.access, source: "pgaudit", objects: [{ database: "crm", schema: "public", object: "clients" }] } }).text).toContain(
      "Objects:    crm.public.clients",
    );

    const findingIncident: IncidentOpenedPayload = {
      event: "incident.opened",
      occurred_at: "2026-10-14T12:00:00.000Z",
      url: null,
      incident: { id: "01890a5d-ac96-774b-bcce-b302099a8057", severity: "high", status: "open", reopened_from: null },
      policy: { id: "01890a5d-ac96-774b-bcce-b302099a8059", name: "Keys", revision: 1 },
      agent_id: AGENT,
      target_id: "sessions-valkey",
      classifier: "pii.email",
      classifiers_version: "2026.09.1",
      location: { engine: "valkey", database: "db0", schema: "string", object: "www.evil.example/login", field: "#key" },
      counts: { sampled: 10, matched: 9, confidence: 0.9 },
    };
    expect(renderEmail(findingIncident).text).toContain("Location:   db0 / string / `www.evil.example/login` / #key");
  });

  it("inline code: a fence longer than any backtick run inside the value", () => {
    expect(inlineCode("user:*:email")).toBe("`user:*:email`");
    expect(inlineCode("a`b")).toBe("``a`b``");
    expect(inlineCode("`a")).toBe("`` `a ``");
  });

  it("only the redis_* sources carry key patterns", () => {
    for (const s of ["redis_slowlog", "redis_commandlog", "redis_acl_log", "redis_sync"]) expect(isKeyPatternSource(s)).toBe(true);
    for (const s of ["pgaudit", "performance_schema", "sqlserver_audit", "cas_audit_log", "nope"]) expect(isKeyPatternSource(s)).toBe(false);
  });
});

describe("principal without a recorded account (ADR-0052 decision 8)", () => {
  it("events: shown as 'account not recorded', linked to the network's events, never to a principal page", () => {
    const html = renderToStaticMarkup(
      <EventsTable events={[event({ accountNotRecorded: true, principal: "", principalKey: "c".repeat(64) })]} now={NOW} />,
    );
    expect(html).toContain("account not recorded");
    expect(html).toContain("data-unrecorded-principal");
    expect(html).not.toContain("/events/principal");
    expect(hrefs(html)).toContain(`/events?agent=${AGENT}&amp;target=cache-redis&amp;principal=${"c".repeat(64)}`);
    expect(renderToStaticMarkup(<PrincipalLabel principal="" fingerprinted={false} notRecorded />)).toContain("account not recorded");
  });

  it("incidents and e-mails say the account was not recorded", () => {
    const access = { principal: "", database: "db0", overflow: false } as unknown as NonNullable<IncidentView["access"]>;
    expect(incidentLocation({ location: null, access, engine: "redis" })).toBe("account not recorded on db0");
    const payload = {
      event: "incident.opened",
      source: "access_event",
      occurred_at: "2026-10-14T12:00:00.000Z",
      url: null,
      incident: { id: "i", severity: "high", status: "open", reopened_from: null },
      policy: { id: "p", name: "Sync", revision: 1 },
      agent_id: AGENT,
      target_id: "cache-redis",
      overflow: null,
      principal: "",
      principal_fingerprinted: false,
      principal_not_recorded: true,
      database: null,
      hour: "2026-10-14T11:00:00.000Z",
      access: { ts: "2026-10-14T11:02:00.000Z", action: "read", source: "redis_sync", rows: null, score: 0, sensitivity: 0, anomaly: false, signals: ["signature.full_sync"], objects: [] },
    } satisfies AccessIncidentOpenedPayload;
    const { subject, text } = renderEmail(payload);
    expect(subject).toContain("(account not recorded)");
    expect(text).toMatch(/Principal: {2}not recorded by the source/);
  });
});

describe("engines (P9-E)", () => {
  it("every contract engine has a display name; location labels per engine", () => {
    for (const e of ENGINES) expect(engineDisplayName(e)).not.toBe(e);
    expect(engineDisplayName("sqlserver")).toBe("Microsoft SQL Server");
    expect(engineDisplayName("valkey")).toBe("Valkey");
    expect(engineDisplayName("other")).toBe("other");
    expect(locationPartLabels("sqlserver")).toEqual({ database: "database", schema: "schema", object: "table", field: "column" });
    expect(locationPartLabels("redis")).toEqual({ database: "database", schema: "type", object: "key pattern", field: "field" });
    expect(locationPartLabels("valkey")).toEqual(locationPartLabels("redis"));
    expect(locationLabel({ databaseName: "Sales", schemaName: "dbo", objectName: "Customers", fieldName: "Email" }, "sqlserver")).toBe(
      "Sales / dbo / Customers / Email",
    );
  });

  it("findings filter by engine: contract engines only", () => {
    expect(parseFindingFilter({ engine: "valkey" }).engine).toBe("valkey");
    expect(parseFindingFilter({ engine: "sqlserver" }).engine).toBe("sqlserver");
    expect(parseFindingFilter({ engine: "redis-server" }).engine).toBeUndefined();
    expect(parseFindingFilter({ engine: ["redis"] }).engine).toBeUndefined();
    expect(findingsHref({ engine: "redis", fp: true })).toBe("/findings?engine=redis&fp=1");
  });

  it("SQL Server note labels of revision 2026_10 have display names", () => {
    expect(labelDisplayName("sysadmin")).toBe("sysadmin");
    expect(labelDisplayName("db_owner")).toBe("db_owner");
    expect(labelDisplayName("db_denydatareader")).toBe("db_denydatareader");
    expect(labelDisplayName("ms_login_manager")).toBe("##MS_LoginManager##");
    expect(labelDisplayName("ms_server_state_reader")).toBe("##MS_ServerStateReader##");
    expect(labelDisplayName("control_server")).toBe("CONTROL SERVER");
    expect(labelDisplayName("alter_any_event_session")).toBe("ALTER ANY EVENT SESSION");
    expect(labelDisplayName("view_server_security_audit")).toBe("VIEW SERVER SECURITY AUDIT");
    expect(labelDisplayName("password_hash_probe")).toBe("password_hash_probe");
    // Unchanged for the earlier engines.
    expect(labelDisplayName("delete_history")).toBe("DELETE HISTORY");
    expect(labelDisplayName("pg_monitor")).toBe("pg_monitor");
  });

  it("SQL Server note labels of revision 2026_10_b have display names", () => {
    expect(labelDisplayName("alter_any_database_event_session")).toBe("ALTER ANY DATABASE EVENT SESSION");
    expect(labelDisplayName("alter_any_database_event_session_add_target")).toBe("ALTER ANY DATABASE EVENT SESSION ADD TARGET");
    expect(labelDisplayName("create_any_database_event_session")).toBe("CREATE ANY DATABASE EVENT SESSION");
    expect(labelDisplayName("view_any_column_master_key_definition")).toBe("VIEW ANY COLUMN MASTER KEY DEFINITION");
    for (const probe of ["logon_trigger_probe", "refusal_list_probe", "cas_store_guard_probe"]) expect(labelDisplayName(probe)).toBe(probe);
    const notEvaluated = renderTargetNote({ code: "privilege.not_evaluated", labels: ["password_hash_probe", "logon_trigger_probe"] });
    expect(notEvaluated.known).toBe(true);
    expect(notEvaluated.text).toContain("password_hash_probe, logon_trigger_probe");
    const refused = renderTargetNote({ code: "privilege.refused", labels: ["alter_any_database_event_session"] });
    expect(refused.text).toContain("(ALTER ANY DATABASE EVENT SESSION)");
  });

  it("the SQL Server note label of revision 2026_10_c and the source-neutral failed-logins note render (phase 9 follow-ups)", () => {
    expect(labelDisplayName("on_failure_probe")).toBe("on_failure_probe");
    const onFailure = renderTargetNote({ code: "privilege.not_evaluated", labels: ["on_failure_probe"] });
    expect(onFailure.known).toBe(true);
    expect(onFailure.text).toContain("on_failure_probe");
    const failedLogins = renderTargetNote({ code: "audit.failed_logins_not_audited" });
    expect(failedLogins.known).toBe(true);
    expect(failedLogins.text).toContain("FAILED_LOGIN_GROUP");
    expect(failedLogins.text).toContain("error_reported");
  });

  it("the new target notes render from the catalog", () => {
    for (const code of [
      "privilege.server_roles",
      "privilege.refused",
      "audit.xe_session_filtered",
      "coverage.masked_columns",
      "audit.acl_log_only",
      "security.default_user_nopass",
      "check.server_is_valkey",
      "coverage.cluster_node_only",
    ]) {
      const r = renderTargetNote({ code, count: 2, labels: ["sysadmin", "ms_login_manager"] });
      expect(r.known, code).toBe(true);
      expect(r.text, code).not.toMatch(/\{(count|labels)\}/);
    }
    expect(renderTargetNote({ code: "privilege.server_roles", labels: ["sysadmin", "ms_login_manager"] }).text).toContain("sysadmin, ##MS_LoginManager##");
  });

  it("detected local servers: re-checked on read, how they were found, and a setup hint per engine (ADR-0006)", () => {
    const stored = [
      { engine: "sqlserver", port: 1433, process: "sqlservr" },
      { engine: "redis", port: 6379 },
      { engine: "valkey", unix_socket: "/run/valkey/valkey.sock", process: "valkey-server" },
      { engine: "redis", process: "redis-sentinel" },
      { engine: "postgres" },
      "junk",
    ];
    const parsed = parseDetectedTargets(stored);
    expect(parsed.map((d) => d.engine)).toEqual(["sqlserver", "redis", "valkey"]);
    expect(parsed.map(detectedHow)).toEqual(["port 1433, process sqlservr", "port 6379", "socket /run/valkey/valkey.sock, process valkey-server"]);
    expect(parseDetectedTargets(null)).toEqual([]);
    for (const e of ENGINES) {
      const hint = setupHint(e as Engine);
      expect(hint).toContain(`engine: ${e}`);
      expect(hint).toContain("agent.yaml");
    }
    expect(setupHint("sqlserver")).toMatch(/sysadmin/);
    expect(setupHint("redis")).toMatch(/cannot tell Redis from Valkey/);
  });
});

describe("Audit manual objects on key-pattern engines (P9-E review M3)", () => {
  it("split on `;` only, never on `/` or `:`", () => {
    const text = "db0; user:*:email; pii.email, pii.phone\ndb0; cache/v2|x.y; pii.email";
    const r = parseManualObjects(text, true);
    expect(r).toEqual({
      ok: true,
      objects: [
        { database: "db0", object: "user:*:email", classifiers: ["pii.email", "pii.phone"] },
        { database: "db0", object: "cache/v2|x.y", classifiers: ["pii.email"] },
      ],
    });
    if (r.ok) expect(parseManualObjects(formatManualObjects(r.objects, true), true)).toEqual(r);
    expect(parseManualObjects("db0/user:*:email: pii.email", true)).toEqual({ ok: false, line: 1 });
    expect(parseManualObjects("db0; a; b; pii.email", true)).toEqual({ ok: false, line: 1 });
    // The other engines keep their format.
    expect(parseManualObjects("crm/public/clients: pii.email")).toMatchObject({ ok: true });
  });
});

describe("incidents table (P9-E review L3)", () => {
  it("a Redis finding incident shows its key pattern as escaped inline code, never in an href", () => {
    const incident = {
      id: "01890a5d-ac96-774b-bcce-b302099a8057",
      status: "open",
      severity: "high",
      policyId: null,
      policyName: "Keys",
      policyRevision: 1,
      source: "finding",
      findingId: "01890a5d-ac96-774b-bcce-b302099a8002",
      agentId: AGENT,
      agentName: "cache-host",
      targetId: "cache-redis",
      classifier: "pii.email",
      engine: "redis",
      location: { databaseName: "db0", schemaName: "hash", objectName: "x:javascript:alert", fieldName: "email" },
      findingMatched: 9,
      matchCount: 1,
      notifyChannels: [],
      access: null,
      createdAt: new Date(NOW - 60_000),
      updatedAt: new Date(NOW - 60_000),
      acknowledgedAt: null,
      acknowledgedBy: null,
      resolvedAt: null,
      resolvedBy: null,
      falsePositiveAt: null,
      falsePositiveBy: null,
    } as unknown as IncidentView;
    const html = renderToStaticMarkup(<IncidentsTable incidents={[incident]} now={NOW} />);
    expect(html).toContain('data-key-pattern="">x:javascript:alert</code>');
    for (const h of hrefs(html)) expect(h).not.toContain("javascript");
  });
});
