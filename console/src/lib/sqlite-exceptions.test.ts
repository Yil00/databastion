import { describe, expect, it } from "vitest";

import { exceptionCoversEvent, type EventExceptionScope, type EventFacts } from "./event-model";
import {
  CASE_BLIND_EXCEPTION_ENGINES,
  CASE_SENSITIVE_EXCEPTION_ENGINES,
  ENGINES,
  exceptionGlobOptions,
  exceptionIsCrossTarget,
  exceptionMatchesCase,
  exceptionReachesItem,
  TARGET_SCOPED_EXCEPTION_ENGINES,
  TRAILING_SPACE_BLIND_ENGINES,
} from "./policy-common";
import { exceptionCovers, type ExceptionScope, type FindingFacts } from "./policy-model";

/**
 * P10-E, P10-C security review R2: every SQLite location is `main` with no schema (ADR-0059
 * decision 6), so a location exception reaches a SQLite item only when it is scoped to its agent
 * and target, or confirmed `cross_target`; SQLite names are compared with case (decision 6).
 */

const NOW = new Date("2026-10-25T12:00:00Z");
const AGENT = "01890a5d-ac96-774b-bcce-b302099a8058";
const OTHER_AGENT = "01890a5d-ac96-774b-bcce-b302099a8059";

const sqlite = (over: Partial<FindingFacts> = {}): FindingFacts => ({
  agentId: AGENT,
  targetId: "crm-app",
  engine: "sqlite",
  databaseName: "main",
  schemaName: null,
  objectName: "customers",
  fieldName: "email",
  classifier: "pii.email",
  confidence: 0.9,
  sampled: 64,
  matched: 61,
  ...over,
});

const LOCATION = { database: "main", object: "customers", field: "email" };

const scope = (over: Partial<ExceptionScope> = {}): ExceptionScope => ({
  policyId: null,
  agentId: null,
  targetId: null,
  classifier: null,
  location: LOCATION,
  expiresAt: null,
  crossTarget: false,
  ...over,
});

describe("SQLite engine lists (ADR-0059 decision 6)", () => {
  it("sqlite is compared with case and never ignores trailing spaces", () => {
    expect(CASE_BLIND_EXCEPTION_ENGINES).not.toContain("sqlite");
    expect(TRAILING_SPACE_BLIND_ENGINES).not.toContain("sqlite");
    expect(CASE_SENSITIVE_EXCEPTION_ENGINES).toContain("sqlite");
    expect(exceptionMatchesCase("sqlite")).toBe(true);
    expect(exceptionGlobOptions("sqlite")).toEqual({ ignoreTrailingSpaces: false, matchCase: true });
  });

  it("every contract engine is in exactly one of the case lists", () => {
    for (const e of ENGINES) {
      expect(Number(CASE_BLIND_EXCEPTION_ENGINES.includes(e)) + Number(CASE_SENSITIVE_EXCEPTION_ENGINES.includes(e)), e).toBe(1);
    }
  });

  it("only sqlite is target-scoped, and it is a contract engine", () => {
    expect(TARGET_SCOPED_EXCEPTION_ENGINES).toEqual(["sqlite"]);
    for (const e of TARGET_SCOPED_EXCEPTION_ENGINES) expect(ENGINES as readonly string[]).toContain(e);
  });

  it("an exception typed in another ASCII case, or with a trailing space, does not cover a SQLite name", () => {
    const x = scope({ agentId: AGENT, targetId: "crm-app" });
    expect(exceptionCovers(x, "p", sqlite(), NOW)).toBe(true);
    expect(exceptionCovers({ ...x, location: { object: "Customers" } }, "p", sqlite(), NOW)).toBe(false);
    expect(exceptionCovers({ ...x, location: { object: "customers" } }, "p", sqlite({ objectName: "customers " }), NOW)).toBe(false);
    // `Ärzte` and `ärzte` are two SQLite tables (SQLite folds ASCII letters only).
    expect(exceptionCovers({ ...x, location: { object: "Ärzte" } }, "p", sqlite({ objectName: "ärzte" }), NOW)).toBe(false);
  });
});

describe("exceptionReachesItem (P10-C review R2)", () => {
  it("target-scoped engines: a location exception needs the agent and the target, or the confirmation", () => {
    const reach = (over: Partial<ExceptionScope>) => exceptionReachesItem(scope(over), "sqlite");
    expect(reach({})).toBe(false);
    expect(reach({ agentId: AGENT })).toBe(false);
    expect(reach({ targetId: "crm-app" })).toBe(false);
    expect(reach({ agentId: AGENT, targetId: "crm-app" })).toBe(true);
    expect(reach({ crossTarget: true })).toBe(true);
    expect(reach({ agentId: AGENT, crossTarget: true })).toBe(true);
    expect(reach({ targetId: "crm-app", crossTarget: true })).toBe(true);
    // Not location-keyed: unchanged.
    expect(reach({ location: null, classifier: "pii.email" })).toBe(true);
    expect(reach({ location: null, agentId: AGENT })).toBe(true);
  });

  it("other engines and a null engine: unchanged", () => {
    for (const e of ENGINES.filter((e) => e !== "sqlite")) expect(exceptionReachesItem(scope(), e), e).toBe(true);
    expect(exceptionReachesItem(scope(), null)).toBe(true);
    expect(exceptionReachesItem(scope(), undefined)).toBe(true);
  });

  it("exceptionIsCrossTarget: a location without both an agent and a target", () => {
    expect(exceptionIsCrossTarget({ agentId: null, targetId: null, location: LOCATION })).toBe(true);
    expect(exceptionIsCrossTarget({ agentId: AGENT, targetId: null, location: LOCATION })).toBe(true);
    expect(exceptionIsCrossTarget({ agentId: null, targetId: "crm-app", location: LOCATION })).toBe(true);
    expect(exceptionIsCrossTarget({ agentId: AGENT, targetId: "crm-app", location: LOCATION })).toBe(false);
    expect(exceptionIsCrossTarget({ agentId: null, targetId: null, location: null })).toBe(false);
  });
});

describe("exceptionCovers on SQLite findings (P10-C review R2)", () => {
  it("a location exception without a target never merges two SQLite files", () => {
    // Two SQLite files with the same table and column: `main.customers.email` on both.
    const a = sqlite();
    const b = sqlite({ targetId: "billing-app" });
    const c = sqlite({ agentId: OTHER_AGENT });
    expect(exceptionCovers(scope(), "p", a, NOW)).toBe(false);
    expect(exceptionCovers(scope({ location: { object: "*" } }), "p", a, NOW)).toBe(false);
    // Scoped to one agent and one target: that file only.
    const one = scope({ agentId: AGENT, targetId: "crm-app" });
    expect(exceptionCovers(one, "p", a, NOW)).toBe(true);
    expect(exceptionCovers(one, "p", b, NOW)).toBe(false);
    expect(exceptionCovers(one, "p", c, NOW)).toBe(false);
    // A target id alone is an agent-local slug: not a target scope.
    expect(exceptionCovers(scope({ targetId: "crm-app" }), "p", a, NOW)).toBe(false);
    expect(exceptionCovers(scope({ agentId: AGENT }), "p", b, NOW)).toBe(false);
  });

  it("the cross_target confirmation reaches every SQLite file of the scope, still matched by the globs", () => {
    const x = scope({ crossTarget: true });
    expect(exceptionCovers(x, "p", sqlite(), NOW)).toBe(true);
    expect(exceptionCovers(x, "p", sqlite({ targetId: "billing-app" }), NOW)).toBe(true);
    expect(exceptionCovers(x, "p", sqlite({ fieldName: "phone" }), NOW)).toBe(false);
    expect(exceptionCovers(scope({ agentId: AGENT, crossTarget: true }), "p", sqlite({ agentId: OTHER_AGENT }), NOW)).toBe(false);
  });

  it("exceptions without a location keep their meaning on SQLite", () => {
    const base = { ...scope(), location: null };
    expect(exceptionCovers({ ...base, classifier: "pii.email" }, "p", sqlite(), NOW)).toBe(true);
    expect(exceptionCovers({ ...base, agentId: AGENT }, "p", sqlite({ targetId: "other" }), NOW)).toBe(true);
    expect(exceptionCovers({ ...base, targetId: "crm-app" }, "p", sqlite(), NOW)).toBe(true);
  });

  it("the same location exception still covers another engine's findings", () => {
    const pg: FindingFacts = { ...sqlite(), engine: "postgres", targetId: "pg-prod-1" };
    expect(exceptionCovers(scope(), "p", pg, NOW)).toBe(true);
  });
});

describe("exceptionCoversEvent on a SQLite event (P10-C review R2)", () => {
  const facts: EventFacts = {
    agentId: AGENT,
    targetId: "crm-app",
    engine: "sqlite",
    principal: "app",
    principalKey: "k",
    fingerprinted: false,
    action: "read",
    objects: [{ database: "main", object: "customers" }],
    rows: 10,
    signals: [],
    // SQLite has no contract `AuditSource` (Discovery only, ADR-0059 decision 7), so no real
    // SQLite event exists: this one is hypothetical, guarding the rule should one ever be stored
    // with its target's engine. `exceptionCoversEvent` does not read the source; it is left empty
    // rather than borrowing another engine's source.
    source: "",
    sensitivity: 0,
    score: 0,
    anomaly: false,
  } as unknown as EventFacts;
  const ev = (over: Partial<EventExceptionScope>): EventExceptionScope => ({ ...scope({ location: { object: "customers" } }), ...over });

  it("needs the agent and the target, or the confirmation", () => {
    expect(exceptionCoversEvent(ev({}), "p", facts, [0], NOW)).toBe(false);
    expect(exceptionCoversEvent(ev({ agentId: AGENT, targetId: "crm-app" }), "p", facts, [0], NOW)).toBe(true);
    expect(exceptionCoversEvent(ev({ crossTarget: true }), "p", facts, [0], NOW)).toBe(true);
    expect(exceptionCoversEvent(ev({}), "p", { ...facts, engine: "postgres" }, [0], NOW)).toBe(true);
  });
});
