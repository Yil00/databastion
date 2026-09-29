import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { auditWarningText } from "@/lib/audit-warning";
import { eventsHref, parseEventFilter, principalHref } from "@/lib/events-filter";
import { parsePolicyActions, parsePolicyConditions } from "@/lib/policy-model";
import type { EventView, PrincipalView } from "@/server/events";
import type { IncidentView } from "@/server/incidents";
import type { PolicyView } from "@/server/policies";

import { AuditForm, confirmationText, formatManualObjects, parseManualObjects } from "./audit-form";
import { EventsTable, formatBytes, formatCount, objectsLabel, PrincipalsTable } from "./events-table";
import { IncidentsTable } from "./incidents-table";
import { conditionLines, PoliciesTable, policyFormValues } from "./policies-table";
import { PolicyForm, policyErrorMessage, policyRequestBody } from "./policy-form";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined, push: () => undefined }) }));

const NOW = Date.parse("2026-09-28T12:00:00Z");
const HOSTILE = '<img src=x onerror="alert(1)">';
const ESCAPED = "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;";
const AGENT = "01890a5d-ac96-774b-bcce-b302099a8058";
const KEY = "a".repeat(64);

const event = (over: Partial<EventView> = {}): EventView => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8001",
  agentId: AGENT,
  agentName: "db-host-1",
  targetId: "pg-prod-1",
  ts: new Date(NOW - 120_000),
  tsLast: null,
  receivedAt: new Date(NOW - 60_000),
  principalKey: KEY,
  principal: "backup",
  fingerprinted: false,
  clientAddr: "192.0.2.14",
  application: "pg_dump",
  action: "read",
  objects: [{ database: "crm", schema: "public", object: "clients" }],
  rows: 1_250_000,
  bytes: null,
  signals: ["signature.pg_dump"],
  source: "pgaudit",
  aggregatedCount: 1,
  unexpectedTarget: false,
  evaluated: true,
  sensitivity: 10.5,
  score: 64.1,
  anomaly: true,
  baselineRows: 1000,
  incidentIds: ["01890a5d-ac96-774b-bcce-b302099a8057"],
  ...over,
});

describe("access events view", () => {
  it("escapes every agent-provided string and links principal, signals and incidents", () => {
    const html = renderToStaticMarkup(
      <EventsTable
        events={[
          event({ principal: HOSTILE, application: HOSTILE, objects: [{ database: HOSTILE, object: HOSTILE }] }),
          event({ id: "b", principal: `hmac-sha256:${"5a".repeat(32)}`, fingerprinted: true, evaluated: false, score: null, anomaly: null, incidentIds: [] }),
        ]}
        now={NOW}
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain(ESCAPED);
    expect(html).toContain(`href="/events/principal?agent=${AGENT}&amp;target=pg-prod-1&amp;principal=${KEY}"`);
    expect(html).toContain('href="/events?signal=signature.pg_dump"');
    expect(html).toContain('href="/incidents/01890a5d-ac96-774b-bcce-b302099a8057"');
    expect(html).toContain("above baseline");
    expect(html).toContain("fingerprint 5a5a5a5a5a5a");
    expect(html).toContain("pending");
    expect(html).toContain("1.3 M");
  });

  it("shows AccessEvent.bytes when the source reports it", () => {
    const html = renderToStaticMarkup(<EventsTable events={[event({ bytes: 1536 }), event({ id: "c" })]} now={NOW} />);
    expect(html).toContain("1.5 KiB");
    expect(html).toContain('title="1536 bytes, as reported by the source"');
    expect(html.match(/bytes, as reported by the source/g)).toHaveLength(1);
    expect([formatBytes(null), formatBytes(0), formatBytes(1023), formatBytes(1024), formatBytes(5 * 1024 ** 3), formatBytes(Number.MAX_SAFE_INTEGER)]).toEqual([
      "",
      "0 B",
      "1023 B",
      "1.0 KiB",
      "5.0 GiB",
      "8.0 PiB",
    ]);
  });

  it("renders principals with their baseline state", () => {
    const p: PrincipalView = {
      agentId: AGENT,
      agentName: HOSTILE,
      targetId: "pg-prod-1",
      principalKey: KEY,
      principal: HOSTILE,
      fingerprinted: false,
      events: 3,
      warm: false,
      baselineRows: null,
      thresholdRows: null,
      typicalScore: null,
      rowsTotal: 30,
      maxScore: 2,
      anomalies: 0,
      firstEventAt: null,
      lastEventAt: new Date(NOW - 5000),
    };
    const html = renderToStaticMarkup(<PrincipalsTable principals={[p, { ...p, principalKey: "b".repeat(64), warm: true, baselineRows: 12_345 }]} now={NOW} />);
    expect(html).not.toContain("<img");
    expect(html).toContain("warming up");
    expect(html).toContain("12 k");
  });

  it("labels objects and counts", () => {
    expect(objectsLabel([{ database: "a", object: "b" }, { database: "a", schema: "s", object: "c" }])).toBe("a.b, a.s.c");
    expect(objectsLabel(Array.from({ length: 5 }, (_, i) => ({ database: "d", object: `o${i}` })), 2)).toBe("d.o0, d.o1 and 3 more");
    expect(formatCount(null)).toBe("");
    expect(formatCount(999)).toBe("999");
    expect(formatCount(25_400)).toBe("25 k");
  });

  it("parses the filter: formats checked, the principal is a key, never a name", () => {
    expect(
      parseEventFilter({ agent: AGENT, target: "pg-prod-1", principal: KEY, signal: "shape.*", from: "2026-09-28T10:00Z", to: "nope", anomaly: "1" }),
    ).toEqual({
      agentId: AGENT,
      targetId: "pg-prod-1",
      principalKey: KEY,
      signal: "shape.*",
      from: new Date("2026-09-28T10:00:00Z"),
      to: undefined,
      anomalyOnly: true,
    });
    expect(parseEventFilter({ principal: "backup", signal: "select *", target: "DB:5432", agent: "x" })).toEqual({
      agentId: undefined,
      targetId: undefined,
      principalKey: undefined,
      signal: undefined,
      from: undefined,
      to: undefined,
      anomalyOnly: false,
    });
    expect(eventsHref({})).toBe("/events");
    expect(eventsHref({ target: "pg-prod-1", signal: "signature.*", anomaly: true })).toBe("/events?target=pg-prod-1&signal=signature.*&anomaly=1");
    expect(principalHref(AGENT, "pg-prod-1", KEY)).toBe(`/events/principal?agent=${AGENT}&target=pg-prod-1&principal=${KEY}`);
  });
});

describe("incidents raised from access events", () => {
  it("show the principal and database instead of a finding location", () => {
    const i: IncidentView = {
      id: "01890a5d-ac96-774b-bcce-b302099a8057",
      status: "open",
      severity: "high",
      policyId: null,
      policyName: "Dumps",
      policyRevision: 1,
      source: "access_event",
      access: { eventId: null, principal: HOSTILE, database: "crm", bucket: new Date(NOW), score: 64.1, rows: 10, signals: [], lastEventAt: null, anomaly: false, overflow: false },
      findingId: null,
      agentId: AGENT,
      agentName: "db-host-1",
      targetId: "pg-prod-1",
      classifier: null,
      location: null,
      findingMatched: null,
      matchCount: 3,
      notifyChannels: [],
      createdAt: new Date(NOW),
      updatedAt: new Date(NOW),
      acknowledgedAt: null,
      acknowledgedBy: null,
      resolvedAt: null,
      resolvedBy: null,
      falsePositiveAt: null,
      falsePositiveBy: null,
    };
    const html = renderToStaticMarkup(<IncidentsTable incidents={[i]} now={NOW} />);
    expect(html).not.toContain("<img");
    expect(html).toContain(`${ESCAPED} on crm`);
    expect(html).toContain("score 64.1");
    expect(html).not.toContain("finding no longer available");
  });
});

describe("access_event policies in the UI", () => {
  const policy: PolicyView = {
    id: "01890a5d-ac96-774b-bcce-b302099a8059",
    name: "Dumps",
    description: null,
    enabled: true,
    source: "access_event",
    conditions: {
      signals: ["signature.*"],
      event_actions: ["read"],
      principals: ["*"],
      exclude_principals: ["backup"],
      objects: { database: "crm", object: HOSTILE },
      min_score: 10,
      min_rows: 1000,
      anomaly: true,
    },
    actions: [{ type: "create_incident", severity: "critical" }, { type: "notify", channel: "secops" }],
    severity: "critical",
    notifyChannels: ["secops"],
    revision: 2,
    updatedAt: new Date(NOW),
    evaluated: true,
  };

  it("describes the conditions and escapes the globs", () => {
    expect(conditionLines(policy.conditions, "access_event")).toEqual([
      "signal in signature.*",
      "action in read",
      "volume above the principal's baseline",
      "score >= 10",
      "rows >= 1000",
      "principal ~ *",
      "principal not ~ backup",
      `database ~ crm, object ~ ${HOSTILE}`,
    ]);
    const html = renderToStaticMarkup(<PoliciesTable policies={[policy]} isAdmin={false} csrfToken="c" />);
    expect(html).not.toContain("<img");
    expect(html).toContain("access events");
  });

  it("round-trips the form values into a valid condition document", () => {
    const body = policyRequestBody({ ...policyFormValues(policy), anomaly: "on" });
    expect(body).toEqual({
      name: "Dumps",
      description: null,
      enabled: true,
      source: "access_event",
      conditions: policy.conditions,
      actions: policy.actions,
    });
    expect(parsePolicyConditions("access_event", body.conditions).ok).toBe(true);
    expect(parsePolicyActions(body.actions).ok).toBe(true);
    expect(policyErrorMessage(400, { error: "invalid_policy", field: "conditions" })).toMatch(/at least a signal/);
    expect(policyErrorMessage(400, { error: "invalid_policy", field: "objects.object" })).toMatch(/globs/);
  });

  it("renders the event fields for an access_event policy, with the source fixed in edit mode", () => {
    const html = renderToStaticMarkup(<PolicyForm csrfToken="c" policyId={policy.id} initial={policyFormValues(policy)} />);
    expect(html).toContain('name="signals"');
    expect(html).toContain('name="objects.database"');
    expect(html).not.toContain('name="classifiers"');
    expect(html).toMatch(/<select[^>]*disabled[^>]*name="source"|<select[^>]*name="source"[^>]*disabled/);
    const fresh = renderToStaticMarkup(<PolicyForm csrfToken="c" />);
    expect(fresh).toContain('name="classifiers"');
    expect(fresh).toContain("Audit access events");
  });
});

describe("audit settings form", () => {
  it("parses manual objects, one per line, with or without schema", () => {
    expect(parseManualObjects("crm/public/clients: pii.email, pii.iban\n\n shop/customers : pii.phone \nou=people,dc=example,dc=com/dc=example,dc=com/x: pii.email")).toEqual({
      ok: true,
      objects: [
        { database: "crm", schema: "public", object: "clients", classifiers: ["pii.email", "pii.iban"] },
        { database: "shop", object: "customers", classifiers: ["pii.phone"] },
        { database: "ou=people,dc=example,dc=com", schema: "dc=example,dc=com", object: "x", classifiers: ["pii.email"] },
      ],
    });
    expect(parseManualObjects("crm/public/clients")).toEqual({ ok: false, line: 1 });
    expect(parseManualObjects("ok/x: pii.email\na/b/c/d: pii.email")).toEqual({ ok: false, line: 2 });
    expect(parseManualObjects("crm//clients: pii.email")).toEqual({ ok: false, line: 1 });
    expect(parseManualObjects("crm/clients: , ")).toEqual({ ok: false, line: 1 });
    const text = "crm/public/clients: pii.email, pii.iban\nshop/customers: pii.phone";
    const parsed = parseManualObjects(text);
    expect(parsed.ok && formatManualObjects(parsed.objects)).toBe(text);
  });

  it("explains what a narrowing change does", () => {
    expect(confirmationText({ warning: "disabled", previous_objects: 3, next_objects: 3, removed_objects: 0 })).toMatch(/turns Audit off/);
    expect(confirmationText({ warning: "emptied", previous_objects: 3, next_objects: 0, removed_objects: 3 })).toMatch(/empties .* \(3 today\)/);
    expect(confirmationText({ warning: "shrunk", previous_objects: 30, next_objects: 10, removed_objects: 20 })).toMatch(/removes 20 of the 30/);
    expect(auditWarningText("emptied", 4)).toMatch(/emptied .* \(4 removed\)/);
    expect(auditWarningText("shrunk", 25)).toMatch(/removed 25/);
    expect(auditWarningText("disabled", null)).toMatch(/turned Audit off/);
  });

  it("renders manual objects as text (escaped)", () => {
    const html = renderToStaticMarkup(
      <AuditForm
        agentId={AGENT}
        targetId="pg-prod-1"
        csrfToken="c"
        initial={{ enabled: true, aggregationWindowS: 60, pollIntervalS: 10, minRows: null, deriveFromFindings: true, manualObjects: [{ database: HOSTILE, object: "o", classifiers: ["pii.email"] }] }}
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain(ESCAPED);
  });
});
