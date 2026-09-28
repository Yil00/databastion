import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { incidentsHref, parseIncidentsQuery, queryStatuses } from "@/lib/incidents-filter";
import { parsePolicyActions, parsePolicyConditions } from "@/lib/policy-model";
import type { IncidentView } from "@/server/incidents";
import type { ExceptionView, PolicyView } from "@/server/policies";

import { availableTransitions } from "./incident-actions";
import { IncidentsTable } from "./incidents-table";
import { conditionLines, ExceptionsTable, PoliciesTable, policyFormValues } from "./policies-table";
import { exceptionRequestBody } from "./policy-actions";
import { policyErrorMessage, policyRequestBody } from "./policy-form";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined, push: () => undefined }) }));

const NOW = Date.parse("2026-09-28T12:00:00Z");
const HOSTILE = '<img src=x onerror="alert(1)">';
const ESCAPED = "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;";

const incident = (over: Partial<IncidentView> = {}): IncidentView => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8057",
  status: "open",
  severity: "high",
  policyId: "01890a5d-ac96-774b-bcce-b302099a8059",
  policyName: "Emails",
  policyRevision: 1,
  source: "finding",
  access: null,
  findingId: "01890a5d-ac96-774b-bcce-b302099a8050",
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  agentName: "db-host-1",
  targetId: "pg-prod-1",
  classifier: "pii.email",
  location: { databaseName: "crm", schemaName: "public", objectName: "clients", fieldName: "email" },
  findingMatched: 150,
  matchCount: 1,
  notifyChannels: [],
  createdAt: new Date(NOW - 60_000),
  updatedAt: new Date(NOW - 60_000),
  acknowledgedAt: null,
  acknowledgedBy: null,
  resolvedAt: null,
  resolvedBy: null,
  falsePositiveAt: null,
  falsePositiveBy: null,
  ...over,
});

const policy = (over: Partial<PolicyView> = {}): PolicyView => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8059",
  name: "Emails",
  description: null,
  enabled: true,
  source: "finding",
  conditions: { classifiers: ["pii.email"], location: { object: "client*" }, min_confidence: 0.9 },
  actions: [{ type: "create_incident", severity: "high" }],
  severity: "high",
  notifyChannels: [],
  revision: 1,
  updatedAt: new Date(NOW),
  evaluated: true,
  ...over,
});

describe("incidents view", () => {
  it("escapes policy names and agent-provided strings", () => {
    const html = renderToStaticMarkup(
      <IncidentsTable
        incidents={[
          incident({ policyName: HOSTILE, agentName: HOSTILE, location: { databaseName: HOSTILE, schemaName: null, objectName: "o", fieldName: "f" } }),
          incident({ id: "b", findingId: null, location: null, status: "false_positive", severity: "low" }),
        ]}
        now={NOW}
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain(ESCAPED);
    expect(html).toContain("false positive");
    expect(html).toContain("(finding no longer available)");
    expect(html).toContain('href="/incidents/01890a5d-ac96-774b-bcce-b302099a8057"');
  });

  it("parses the query: defaults to active, ignores malformed values", () => {
    const q = parseIncidentsQuery({ status: "resolved", severity: "high", target: "pg-prod-1", agent: "nope" });
    expect(q).toEqual({ status: "resolved", severity: "high", targetId: "pg-prod-1", agentId: undefined });
    expect(parseIncidentsQuery({ status: "__proto__", severity: "urgent", target: "DB.EXAMPLE:5432" })).toEqual({
      status: "active",
      severity: undefined,
      agentId: undefined,
      targetId: undefined,
    });
    expect(queryStatuses({ status: "active" })).toEqual(["open", "acknowledged"]);
    expect(queryStatuses({ status: "all" })).toBeUndefined();
    expect(incidentsHref({ status: "active" })).toBe("/incidents");
    expect(incidentsHref({ status: "all", targetId: "pg-prod-1" })).toBe("/incidents?status=all&target=pg-prod-1");
  });

  it("offers only the lifecycle transitions the user may request", () => {
    expect(availableTransitions("open", false)).toEqual(["acknowledged", "resolved"]);
    expect(availableTransitions("open", true)).toEqual(["acknowledged", "resolved", "false_positive"]);
    expect(availableTransitions("acknowledged", true)).toEqual(["resolved", "false_positive"]);
    expect(availableTransitions("resolved", true)).toEqual([]);
    expect(availableTransitions("false_positive", true)).toEqual([]);
  });
});

describe("policies view", () => {
  it("escapes names, descriptions, globs and reasons; admin actions only for admins", () => {
    const p = policy({ name: HOSTILE, description: HOSTILE, conditions: { location: { object: HOSTILE } } });
    const asAdmin = renderToStaticMarkup(<PoliciesTable policies={[p]} isAdmin csrfToken="csrf" />);
    expect(asAdmin).not.toContain("<img");
    expect(asAdmin).toContain(ESCAPED);
    expect(asAdmin).toContain("Delete");
    const asAnalyst = renderToStaticMarkup(<PoliciesTable policies={[p]} isAdmin={false} csrfToken="csrf" />);
    expect(asAnalyst).not.toContain("Delete");
    const e: ExceptionView = {
      id: "e1",
      policyId: null,
      policyName: null,
      agentId: null,
      agentName: null,
      targetId: "pg-prod-1",
      classifier: null,
      location: null,
      reason: HOSTILE,
      expiresAt: new Date(NOW - 1),
      createdAt: new Date(NOW - 10),
    };
    const ex = renderToStaticMarkup(<ExceptionsTable exceptions={[e]} isAdmin={false} csrfToken="c" now={NOW} />);
    expect(ex).not.toContain("<img");
    expect(ex).toContain("expired");
    expect(ex).toContain("all policies");
  });

  it("describes conditions in words", () => {
    expect(conditionLines({})).toEqual(["every finding"]);
    expect(conditionLines(policy().conditions)).toEqual(["classifier in pii.email", "object ~ client*", "confidence >= 0.9"]);
  });

  it("the form round-trips a policy into a body the server accepts", () => {
    const p = policy({
      conditions: {
        classifiers: ["pii.email", "secret.*"],
        target_ids: ["pg-prod-1"],
        location: { schema: "public", field: "e*" },
        min_matched: 3,
        min_match_ratio: 0.25,
      },
      actions: [
        { type: "create_incident", severity: "critical" },
        { type: "notify", channel: "secops" },
      ],
      severity: "critical",
      notifyChannels: ["secops"],
      description: "d",
    });
    const body = policyRequestBody(policyFormValues(p));
    expect(body).toEqual({
      name: "Emails",
      description: "d",
      enabled: true,
      source: "finding",
      conditions: p.conditions,
      actions: p.actions,
    });
    expect(parsePolicyConditions("finding", body.conditions).ok).toBe(true);
    expect(parsePolicyActions(body.actions).ok).toBe(true);
    // Empty inputs are no constraint; an empty description is null.
    expect(policyRequestBody({ name: " x ", description: " ", severity: "low", notify: "", enabled: "on" })).toEqual({
      name: "x",
      description: null,
      enabled: true,
      source: "finding",
      conditions: {},
      actions: [{ type: "create_incident", severity: "low" }],
    });
    expect(policyErrorMessage(400, { error: "invalid_policy", field: "classifiers" })).toMatch(/registered ids/);
    expect(policyErrorMessage(409, null)).toMatch(/already exists/);
  });

  it("builds exception bodies: empty inputs omitted, expiry as an instant", () => {
    const body = exceptionRequestBody({
      policy_id: "",
      target_id: " pg-prod-1 ",
      classifier: "",
      "location.object": "tmp_*",
      reason: " fixtures ",
      expires_at: "2030-01-01T10:00",
    });
    expect(body.target_id).toBe("pg-prod-1");
    expect(body.location).toEqual({ object: "tmp_*" });
    expect(body.reason).toBe("fixtures");
    expect(typeof body.expires_at).toBe("string");
    expect(Number.isNaN(Date.parse(String(body.expires_at)))).toBe(false);
    expect(body).not.toHaveProperty("classifier");
    expect(body).not.toHaveProperty("policy_id");
  });
});
