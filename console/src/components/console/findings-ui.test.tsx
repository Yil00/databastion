import { NextRequest } from "next/server";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { parseFindingFilter } from "@/lib/findings-filter";
import type { FindingView } from "@/server/findings";
import { proxy } from "@/proxy";

import { findingsHref, FindingsSummary, FindingsTable, locationLabel } from "./findings-table";
import { scanErrorMessage, scanRequestBody } from "./scan-dialog";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => undefined }) }));

const NOW = Date.parse("2026-09-28T12:00:00Z");
const HOSTILE = '<img src=x onerror="alert(1)">';

const finding = (over: Partial<FindingView> = {}): FindingView => ({
  id: "01890a5d-ac96-774b-bcce-b302099a8057",
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  agentName: "db-host-1",
  targetId: "pg-prod-1",
  engine: "postgres",
  databaseName: "crm",
  schemaName: "public",
  objectName: "clients",
  fieldName: "email",
  classifier: "pii.email",
  confidence: 0.97,
  sampled: 200,
  matched: 194,
  estimatedRows: 1250000,
  fingerprintCount: 2,
  samples: { state: "ok", values: ["j*******@e******.com"] },
  firstSeenAt: new Date(NOW - 60_000),
  lastSeenAt: new Date(NOW - 60_000),
  falsePositiveAt: null,
  ...over,
});

describe("FindingsTable", () => {
  it("renders agent-provided strings and samples as escaped text", () => {
    const html = renderToStaticMarkup(
      <FindingsTable
        findings={[finding({ agentName: HOSTILE, objectName: HOSTILE, fieldName: HOSTILE, samples: { state: "ok", values: [HOSTILE] } })]}
        csrfToken="csrf"
        now={NOW}
        canMark
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    // The CSRF token is only a prop of the client button, not rendered.
    expect(html).toContain("False positive");
  });

  it("shows sample states, false positives and the location without a missing schema", () => {
    const html = renderToStaticMarkup(
      <FindingsTable
        findings={[
          finding(),
          finding({ id: "b", samples: { state: "unavailable" }, falsePositiveAt: new Date(NOW) }),
          finding({ id: "c", samples: { state: "none" }, schemaName: null }),
        ]}
        csrfToken="csrf"
        now={NOW}
        canMark
      />,
    );
    expect(html).toContain("j*******@e******.com");
    expect(html).toContain("unavailable");
    expect(html).toContain("false positive");
    expect(html).toContain("Not a false positive");
    expect(html).toContain("194 / 200");
    expect(locationLabel({ databaseName: "shop", schemaName: null, objectName: "customers", fieldName: "phone" })).toBe(
      "shop / customers / phone",
    );
  });

  it("OpenLDAP locations name their parts: naming context, container, object class, attribute (ADR-0029)", () => {
    const ldap = finding({
      targetId: "ldap-1",
      engine: "openldap",
      databaseName: "dc=example,dc=org",
      schemaName: "ou=people,dc=example,dc=org",
      objectName: "inetOrgPerson",
      fieldName: "mail",
    });
    const html = renderToStaticMarkup(<FindingsTable findings={[ldap, finding({ id: "pg", schemaName: HOSTILE })]} csrfToken="csrf" now={NOW} canMark />);
    for (const label of ["naming context", "container", "object class", "attribute"]) expect(html).toContain(`>${label}</dt>`);
    expect(html).toContain(">ou=people,dc=example,dc=org</dd>");
    expect(html).toContain(">inetOrgPerson</dd>");
    // Other engines keep the plain path (and escaped names).
    expect(html).toContain("crm / &lt;img src=x onerror=&quot;alert(1)&quot;&gt; / clients / email");
    expect(html).not.toContain("<img");
    expect(locationLabel(ldap, "openldap")).toBe(
      "naming context dc=example,dc=org / container ou=people,dc=example,dc=org / object class inetOrgPerson / attribute mail",
    );
    expect(locationLabel({ ...ldap, schemaName: null }, "openldap")).toBe("naming context dc=example,dc=org / object class inetOrgPerson / attribute mail");
    expect(locationLabel(ldap)).toBe("dc=example,dc=org / ou=people,dc=example,dc=org / inetOrgPerson / mail");
  });

  it("summary links filter by target and classifier", () => {
    const html = renderToStaticMarkup(
      <FindingsSummary
        rows={[{ agentId: "a1", agentName: HOSTILE, targetId: "pg-prod-1", classifier: "pii.email", findings: 3, maxConfidence: 0.9 }]}
        showFalsePositives={false}
      />,
    );
    expect(html).not.toContain("<img");
    expect(html).toContain('href="/findings?agent=a1&amp;target=pg-prod-1&amp;classifier=pii.email"');
    expect(renderToStaticMarkup(<FindingsTable findings={[]} csrfToken="" now={NOW} canMark />)).toContain("No finding.");
  });

  it("builds and parses filters, ignoring malformed values", () => {
    expect(findingsHref({})).toBe("/findings");
    expect(findingsHref({ target: "pg-prod-1", fp: true })).toBe("/findings?target=pg-prod-1&fp=1");
    expect(
      parseFindingFilter({ agent: "01890a5d-ac96-774b-bcce-b302099a8057", target: "pg-prod-1", classifier: "pii.email", fp: "1" }),
    ).toEqual({
      agentId: "01890a5d-ac96-774b-bcce-b302099a8057",
      targetId: "pg-prod-1",
      classifier: "pii.email",
      includeFalsePositives: true,
    });
    expect(parseFindingFilter({ agent: "x", target: "a b", classifier: "<b>", fp: ["1", "1"] })).toEqual({
      agentId: undefined,
      targetId: undefined,
      classifier: undefined,
      includeFalsePositives: false,
    });
  });

  it("shows no false-positive button to non-admins (M2)", () => {
    const html = renderToStaticMarkup(<FindingsTable findings={[finding()]} csrfToken="csrf" now={NOW} canMark={false} />);
    expect(html).not.toContain("False positive");
  });
});

describe("scanRequestBody", () => {
  it("parses numbers and comma-separated lists, never sends an empty list", () => {
    expect(
      scanRequestBody({
        sample_rows: "50",
        max_duration_s: "",
        statement_timeout_ms: "1000",
        databases: " crm , shop,crm ",
        schemas: "",
        include_objects: " , ",
        exclude_objects: "audit_*",
        classifiers: "pii.email",
      }),
    ).toEqual({
      sample_rows: 50,
      statement_timeout_ms: 1000,
      databases: ["crm", "shop"],
      exclude_objects: ["audit_*"],
      classifiers: ["pii.email"],
    });
    expect(scanRequestBody({})).toEqual({});
  });
});

describe("proxy", () => {
  it("sets the nonce CSP and no-store on UI pages", () => {
    const res = proxy(new NextRequest("http://console.test/findings"));
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toContain("'nonce-");
  });
});

describe("scanErrorMessage", () => {
  it("explains the classifier registry refusals from the error code", () => {
    expect(scanErrorMessage(409, { error: "classifiers_version_unregistered" })).toMatch(/classifier set this console does not know/);
    expect(scanErrorMessage(409, { error: "agent_not_ready" })).toMatch(/not reported its classifier set/);
    expect(scanErrorMessage(422, { error: "unknown_classifiers" })).toMatch(/not part of the agent's classifier set/);
    expect(scanErrorMessage(409, { error: "scan_in_progress" })).toMatch(/already queued or running/);
  });

  it("falls back on the status for unknown or prototype-like codes and non-JSON bodies", () => {
    expect(scanErrorMessage(409, { error: "__proto__" })).toMatch(/already queued or running, or the agent is not ready/);
    expect(scanErrorMessage(409, { error: "constructor" })).toMatch(/already queued or running, or the agent is not ready/);
    expect(scanErrorMessage(422, null)).toMatch(/not part of the agent's classifier set/);
    expect(scanErrorMessage(500, [])).toBe("The scan could not be queued (500).");
  });
});
