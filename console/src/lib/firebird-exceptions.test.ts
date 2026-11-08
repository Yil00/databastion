import { describe, expect, it } from "vitest";

import {
  CASE_BLIND_EXCEPTION_ENGINES,
  CASE_SENSITIVE_EXCEPTION_ENGINES,
  dedupDatabaseName,
  exceptionGlobOptions,
  TRAILING_SPACE_BLIND_ENGINES,
} from "./policy-common";
import { exceptionCovers, type ExceptionScope, type FindingFacts } from "./policy-model";

/**
 * Firebird name rules (ADR-0060 decision 5, open question 11; P10-C security review L7): names are
 * compared with case, and trailing spaces are never significant (catalog names are space-padded
 * `CHAR`, so `"A "` and `"A"` are one table).
 */

const NOW = new Date("2026-10-25T12:00:00Z");
const AGENT = "01890a5d-ac96-774b-bcce-b302099a8058";

const firebird = (over: Partial<FindingFacts> = {}): FindingFacts => ({
  agentId: AGENT,
  targetId: "fb-crm",
  engine: "firebird",
  databaseName: "crm",
  schemaName: null,
  objectName: "CUSTOMERS",
  fieldName: "EMAIL",
  classifier: "pii.email",
  confidence: 0.9,
  sampled: 64,
  matched: 61,
  ...over,
});

const scope = (location: ExceptionScope["location"]): ExceptionScope => ({
  policyId: null,
  agentId: null,
  targetId: null,
  classifier: null,
  location,
  expiresAt: null,
  crossTarget: false,
});

describe("Firebird engine lists (ADR-0060 decision 5)", () => {
  it("firebird is compared with case and ignores trailing spaces", () => {
    expect(TRAILING_SPACE_BLIND_ENGINES).toContain("firebird");
    expect(CASE_BLIND_EXCEPTION_ENGINES).not.toContain("firebird");
    expect(CASE_SENSITIVE_EXCEPTION_ENGINES).toContain("firebird");
    expect(exceptionGlobOptions("firebird")).toEqual({ ignoreTrailingSpaces: true, matchCase: true });
    expect(dedupDatabaseName("crm  ", "firebird")).toBe("crm");
  });

  it("an exception covers a Firebird name that differs by trailing spaces only, never by case", () => {
    const x = scope({ database: "crm", object: "CUSTOMERS", field: "EMAIL" });
    expect(exceptionCovers(x, "p", firebird(), NOW)).toBe(true);
    expect(exceptionCovers(x, "p", firebird({ objectName: "CUSTOMERS  " }), NOW)).toBe(true);
    expect(exceptionCovers(scope({ database: "crm", object: "CUSTOMERS ", field: "EMAIL" }), "p", firebird(), NOW)).toBe(true);
    expect(exceptionCovers(scope({ database: "crm", object: "customers", field: "EMAIL" }), "p", firebird(), NOW)).toBe(false);
    // A leading space is part of a quoted name.
    expect(exceptionCovers(x, "p", firebird({ objectName: " CUSTOMERS" }), NOW)).toBe(false);
  });
});
