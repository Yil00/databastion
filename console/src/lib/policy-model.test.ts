import { describe, expect, it } from "vitest";

import {
  canTransition,
  classifierSelected,
  exceptionCovers,
  findingMatches,
  globMatch,
  isClassifierSelector,
  parseLocationPattern,
  parsePolicyActions,
  parsePolicyConditions,
  transitionNeedsAdmin,
  type ExceptionScope,
  type FindingFacts,
  type IncidentStatus,
} from "./policy-model";

const FACTS: FindingFacts = {
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  targetId: "pg-prod-1",
  engine: "postgres",
  databaseName: "crm",
  schemaName: "public",
  objectName: "clients",
  fieldName: "email",
  classifier: "pii.email",
  confidence: 0.97,
  sampled: 200,
  matched: 150,
};

describe("globMatch", () => {
  it.each([
    ["clients", "clients", true],
    ["CLIENTS", "clients", true],
    ["client*", "clients", true],
    ["*s", "clients", true],
    ["c*n*s", "clients", true],
    ["c?ients", "clients", true],
    ["c?ents", "clients", false],
    ["client", "clients", false],
    ["*", "", true],
    ["", "", true],
    ["a*", "", false],
    ["orders[].*", "orders[].email", true],
    ["contacts.\\*.phone", "contacts.*.phone", true],
    ["contacts.\\*.phone", "contacts.x.phone", false],
    ["**a", "bbba", true],
  ])("%s ~ %s -> %s", (pattern, value, expected) => {
    expect(globMatch(pattern, value)).toBe(expected);
  });

  it("runs in linear time on hostile inputs (no backtracking blow-up)", () => {
    const start = performance.now();
    expect(globMatch(`${"*a".repeat(100)}b`, "a".repeat(256))).toBe(false);
    expect(performance.now() - start).toBeLessThan(200);
  });
});

describe("parsePolicyConditions", () => {
  it("accepts every key, deduplicates lists", () => {
    const r = parsePolicyConditions("finding", {
      classifiers: ["pii.email", "pii.email", "secret.*"],
      agent_ids: [FACTS.agentId],
      target_ids: ["pg-prod-1"],
      engines: ["postgres"],
      location: { schema: "public", object: "client*" },
      min_confidence: 0.5,
      min_matched: 3,
      min_match_ratio: 0.1,
    });
    expect(r.ok && "classifiers" in r.value && r.value.classifiers).toEqual(["pii.email", "secret.*"]);
  });

  it("accepts an empty document (every finding)", () => {
    expect(parsePolicyConditions("finding", {})).toEqual({ ok: true, value: {} });
  });

  it.each([
    ["unknown key", { signals: ["signature.pg_dump"] }, "conditions"],
    ["unregistered classifier", { classifiers: ["pii.unknown"] }, "classifiers"],
    ["unknown family", { classifiers: ["zzz.*"] }, "classifiers"],
    ["empty list", { classifiers: [] }, "classifiers"],
    ["bad agent id", { agent_ids: ["x"] }, "agent_ids"],
    ["bad target id", { target_ids: ["DB.example.com:5432"] }, "target_ids"],
    ["unknown engine", { engines: ["oracle"] }, "engines"],
    ["unknown location key", { location: { table: "x" } }, "location"],
    ["empty location", { location: {} }, "location"],
    ["control char glob", { location: { object: "a\u0000b" } }, "location.object"],
    ["confidence above 1", { min_confidence: 1.5 }, "min_confidence"],
    ["negative matched", { min_matched: -1 }, "min_matched"],
    ["fractional matched", { min_matched: 1.5 }, "min_matched"],
    ["ratio NaN-like", { min_match_ratio: "0.5" }, "min_match_ratio"],
    ["array body", [], "conditions"],
  ])("rejects %s", (_name, doc, field) => {
    expect(parsePolicyConditions("finding", doc)).toEqual({ ok: false, error: field });
  });
});

describe("parsePolicyActions", () => {
  it("requires exactly one create_incident and distinct notify channels", () => {
    expect(parsePolicyActions([{ type: "create_incident", severity: "high" }]).ok).toBe(true);
    expect(
      parsePolicyActions([
        { type: "create_incident", severity: "low" },
        { type: "notify", channel: "secops-mail" },
      ]).ok,
    ).toBe(true);
    expect(parsePolicyActions([{ type: "notify", channel: "secops" }])).toEqual({ ok: false, error: "actions.create_incident" });
    expect(
      parsePolicyActions([
        { type: "create_incident", severity: "low" },
        { type: "create_incident", severity: "high" },
      ]).ok,
    ).toBe(false);
    expect(
      parsePolicyActions([
        { type: "create_incident", severity: "low" },
        { type: "notify", channel: "a" },
        { type: "notify", channel: "a" },
      ]),
    ).toEqual({ ok: false, error: "actions.channel" });
  });

  it.each([
    ["unknown severity", [{ type: "create_incident", severity: "urgent" }]],
    ["extra key", [{ type: "create_incident", severity: "low", note: "x" }]],
    ["address as channel", [{ type: "create_incident", severity: "low" }, { type: "notify", channel: "ops@example.com" }]],
    ["url as channel", [{ type: "create_incident", severity: "low" }, { type: "notify", channel: "https://hook" }]],
    ["unknown type", [{ type: "ignore" }]],
    ["empty list", []],
    ["object", { type: "create_incident" }],
  ])("rejects %s", (_name, doc) => {
    expect(parsePolicyActions(doc).ok).toBe(false);
  });
});

describe("findingMatches", () => {
  it("ANDs the keys and ORs the values of a list", () => {
    expect(findingMatches({}, FACTS)).toBe(true);
    expect(findingMatches({ classifiers: ["pii.phone", "pii.email"] }, FACTS)).toBe(true);
    expect(findingMatches({ classifiers: ["pii.*"] }, FACTS)).toBe(true);
    expect(findingMatches({ classifiers: ["secret.*"] }, FACTS)).toBe(false);
    expect(findingMatches({ classifiers: ["pii.email"], target_ids: ["other"] }, FACTS)).toBe(false);
    expect(findingMatches({ agent_ids: [FACTS.agentId], engines: ["postgres"] }, FACTS)).toBe(true);
    expect(findingMatches({ engines: ["mysql"] }, FACTS)).toBe(false);
  });

  it("thresholds: confidence, matched, ratio", () => {
    expect(findingMatches({ min_confidence: 0.97 }, FACTS)).toBe(true);
    expect(findingMatches({ min_confidence: 0.98 }, FACTS)).toBe(false);
    expect(findingMatches({ min_matched: 150 }, FACTS)).toBe(true);
    expect(findingMatches({ min_matched: 151 }, FACTS)).toBe(false);
    expect(findingMatches({ min_match_ratio: 0.75 }, FACTS)).toBe(true);
    expect(findingMatches({ min_match_ratio: 0.76 }, FACTS)).toBe(false);
    expect(findingMatches({ min_match_ratio: 0.1 }, { ...FACTS, sampled: 0, matched: 0 })).toBe(false);
  });

  it("location globs; a missing schema only matches `*`", () => {
    expect(findingMatches({ location: { database: "crm", object: "cli*", field: "e?ail" } }, FACTS)).toBe(true);
    expect(findingMatches({ location: { object: "orders" } }, FACTS)).toBe(false);
    const mysql = { ...FACTS, schemaName: null };
    expect(findingMatches({ location: { schema: "*" } }, mysql)).toBe(true);
    expect(findingMatches({ location: { schema: "public" } }, mysql)).toBe(false);
  });
});

describe("exceptionCovers", () => {
  const NOW = new Date("2026-09-28T12:00:00Z");
  const base: ExceptionScope = {
    policyId: null,
    agentId: null,
    targetId: "pg-prod-1",
    classifier: null,
    location: null,
    expiresAt: null,
  };
  it("matches every set scope, per policy or global, until expiry", () => {
    expect(exceptionCovers(base, "p1", FACTS, NOW)).toBe(true);
    expect(exceptionCovers({ ...base, policyId: "p1" }, "p1", FACTS, NOW)).toBe(true);
    expect(exceptionCovers({ ...base, policyId: "p2" }, "p1", FACTS, NOW)).toBe(false);
    expect(exceptionCovers({ ...base, targetId: "other" }, "p1", FACTS, NOW)).toBe(false);
    expect(exceptionCovers({ ...base, classifier: "pii.*" }, "p1", FACTS, NOW)).toBe(true);
    expect(exceptionCovers({ ...base, classifier: "pii.phone" }, "p1", FACTS, NOW)).toBe(false);
    expect(exceptionCovers({ ...base, location: { object: "clients" } }, "p1", FACTS, NOW)).toBe(true);
    expect(exceptionCovers({ ...base, location: { field: "phone" } }, "p1", FACTS, NOW)).toBe(false);
    expect(exceptionCovers({ ...base, expiresAt: new Date(NOW.getTime() + 1) }, "p1", FACTS, NOW)).toBe(true);
    expect(exceptionCovers({ ...base, expiresAt: NOW }, "p1", FACTS, NOW)).toBe(false);
  });
});

describe("classifier selectors", () => {
  it("accepts registered ids and families only", () => {
    expect(isClassifierSelector("pii.email")).toBe(true);
    expect(isClassifierSelector("pii.*")).toBe(true);
    expect(isClassifierSelector("secret.*")).toBe(true);
    expect(isClassifierSelector("__proto__")).toBe(false);
    expect(isClassifierSelector("*")).toBe(false);
    expect(isClassifierSelector("pii.e*")).toBe(false);
    expect(classifierSelected(["pii.*"], "pii.email")).toBe(true);
    expect(classifierSelected(["pii.*"], "piix.email")).toBe(false);
  });

  it("location patterns need at least one part", () => {
    expect(parseLocationPattern({ object: "x" }).ok).toBe(true);
    expect(parseLocationPattern({}).ok).toBe(false);
    expect(parseLocationPattern({ object: "x".repeat(257) }).ok).toBe(false);
  });
});

describe("incident lifecycle", () => {
  const all: IncidentStatus[] = ["open", "acknowledged", "resolved", "false_positive"];
  const allowed = new Set([
    "open>acknowledged",
    "open>resolved",
    "open>false_positive",
    "acknowledged>resolved",
    "acknowledged>false_positive",
  ]);
  it("allows exactly the lifecycle transitions; resolved and false_positive are final", () => {
    for (const from of all) {
      for (const to of all) expect(canTransition(from, to)).toBe(allowed.has(`${from}>${to}`));
    }
  });
  it("false_positive needs an administrator", () => {
    expect(transitionNeedsAdmin("false_positive")).toBe(true);
    expect(transitionNeedsAdmin("acknowledged")).toBe(false);
    expect(transitionNeedsAdmin("resolved")).toBe(false);
  });
});
