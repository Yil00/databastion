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
import { dedupDatabaseName, exceptionGlobOptions, foldName, type GlobOptions } from "./policy-common";

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

  it("runs in bounded O(n x m) time on hostile inputs (no exponential backtracking)", () => {
    const start = performance.now();
    expect(globMatch(`${"*a".repeat(100)}b`, "a".repeat(256))).toBe(false);
    expect(globMatch(`${"*a".repeat(100)}b${" ".repeat(100)}`, `${"a".repeat(156)}${" ".repeat(100)}`, { ignoreTrailingSpaces: true })).toBe(false);
    expect(performance.now() - start).toBeLessThan(200);
  });

  it("folds non-ASCII letters, with the final sigma unified (N1, review M1)", () => {
    expect(globMatch("ΚΑΤΆΛΟΓΟΣ", "κατάλογοσ")).toBe(true);
    expect(globMatch("κατάλογοσ", "ΚΑΤΆΛΟΓΟΣ")).toBe(true);
    expect(globMatch("ΠΕΛΑΤΕΣ", "πελατες")).toBe(true);
    expect(globMatch("πελατες", "ΠΕΛΑΤΕΣ")).toBe(true);
    expect(globMatch("πελατες", "πελατεσ")).toBe(true);
    expect(globMatch("ΠΕΛΑΤ*Σ", "πελατες")).toBe(true);
    expect(globMatch("ΠΕΛΑΤΕΣ", "πελατε")).toBe(false);
    expect(globMatch("CLIENTÈLE", "clientèle")).toBe(true);
    expect(globMatch("clientèle", "clientele")).toBe(false);
  });

  it("ignores trailing spaces only when asked (N1), on both sides, never inner ones", () => {
    expect(globMatch("clients", "clients  ")).toBe(false);
    expect(globMatch("clients", "clients  ", { ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("clients ", "clients", { ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("clients\\ ", "CLIENTS", { ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("cli*", "CLIENTS ", { ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("clients?", "clients ", { ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("clients", " clients", { ignoreTrailingSpaces: true })).toBe(false);
    expect(globMatch("cli ents", "clients", { ignoreTrailingSpaces: true })).toBe(false);
    expect(globMatch("orders", "clients ", { ignoreTrailingSpaces: true })).toBe(false);
  });
});

describe("globMatch with matchCase (ADR-0054)", () => {
  const CASE: GlobOptions = { matchCase: true };
  it("requires the folded match and the exact match", () => {
    expect(globMatch("clients", "clients", CASE)).toBe(true);
    expect(globMatch("clients", "Clients", CASE)).toBe(false);
    expect(globMatch("Clients", "clients", CASE)).toBe(false);
    expect(globMatch("C*", "Clients", CASE)).toBe(true);
    expect(globMatch("c*", "Clients", CASE)).toBe(false);
    expect(globMatch("?lients", "Clients", CASE)).toBe(true);
    expect(globMatch("\\*lients", "*lients", CASE)).toBe(true);
    expect(globMatch("\\Clients", "Clients", CASE)).toBe(true);
    expect(globMatch("\\Clients", "clients", CASE)).toBe(false);
    expect(globMatch("ΠΕΛΑΤΕΣ", "ΠΕΛΑΤΕΣ", CASE)).toBe(true);
    expect(globMatch("ΠΕΛΑΤΕΣ", "πελατες", CASE)).toBe(false);
    // Final sigma: the fold reads `ς` as `σ`, the exact match does not.
    expect(globMatch("πελατεσ", "πελατες")).toBe(true);
    expect(globMatch("πελατεσ", "πελατες", CASE)).toBe(false);
  });

  it("keeps the trailing-space rule of the engine", () => {
    expect(globMatch("Clients", "Clients  ", { matchCase: true, ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("Clients ", "Clients", { matchCase: true, ignoreTrailingSpaces: true })).toBe(true);
    expect(globMatch("clients", "Clients  ", { matchCase: true, ignoreTrailingSpaces: true })).toBe(false);
    expect(globMatch("Clients", "Clients  ", CASE)).toBe(false);
  });

  it("never covers what the folded match does not: length-changing case mappings", () => {
    // `İ` lowercases to `i` + U+0307: `?` matches it as written, not once folded.
    expect(globMatch("?", "İ", { matchCase: false })).toBe(false);
    expect(globMatch("?", "İ", CASE)).toBe(false);
    expect(globMatch("İ", "İ", CASE)).toBe(true);
    expect(globMatch("i\u0307", "İ")).toBe(true);
    expect(globMatch("i\u0307", "İ", CASE)).toBe(false);
    expect(globMatch("ß", "ß", CASE)).toBe(true);
    expect(globMatch("ẞ", "ß")).toBe(true);
    expect(globMatch("ẞ", "ß", CASE)).toBe(false);
  });

  it("stays linear on adversarial input", () => {
    expect(globMatch(`${"*a".repeat(100)}b`, "a".repeat(256), CASE)).toBe(false);
    expect(globMatch(`${"*A".repeat(100)}b${" ".repeat(100)}`, `${"A".repeat(156)}${" ".repeat(100)}`, { matchCase: true, ignoreTrailingSpaces: true })).toBe(false);
  });

  it("property: a matchCase cover implies today's cover, for any glob and name", () => {
    // Seeded PRNG (mulberry32), so a failure is reproducible.
    let seed = 0x5eed0054;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const NAME = ["a", "A", "b", "B", "i", "I", "İ", "ı", "\u0307", "s", "S", "ß", "ẞ", "σ", "ς", "Σ", "ǅ", "ǆ", " ", "_"];
    const GLOB = [...NAME, "*", "?", "\\", "\\*", "\\?", "\\ "];
    const pick = (xs: readonly string[], n: number) => Array.from({ length: n }, () => xs[Math.floor(rand() * xs.length)]).join("");
    let covered = 0;
    let narrowed = 0;
    for (let i = 0; i < 20_000; i++) {
      const glob = pick(GLOB, 1 + Math.floor(rand() * 6));
      // Half of the names derive from the glob, so matches are frequent.
      const name =
        rand() < 0.5
          ? pick(NAME, Math.floor(rand() * 7))
          : [...glob.replace(/\\(.)/gu, "$1").replace(/[*?]/gu, () => pick(NAME, Math.floor(rand() * 2)))]
              .map((c) => (rand() < 0.3 ? (rand() < 0.5 ? c.toUpperCase() : c.toLowerCase()) : c))
              .join("") + (rand() < 0.2 ? " " : "");
      for (const ignoreTrailingSpaces of [false, true]) {
        const strict = globMatch(glob, name, { ignoreTrailingSpaces, matchCase: true });
        const today = globMatch(glob, name, { ignoreTrailingSpaces });
        if (strict && !today) throw new Error(`matchCase loosened ${JSON.stringify(glob)} on ${JSON.stringify(name)} (trailing spaces ignored: ${ignoreTrailingSpaces})`);
        if (strict) covered++;
        if (today && !strict) narrowed++;
      }
    }
    // The generator exercises both outcomes.
    expect(covered).toBeGreaterThan(1000);
    expect(narrowed).toBeGreaterThan(1000);
  });

  it("exceptionGlobOptions: case compared everywhere but SQL Server, MySQL, MariaDB and OpenLDAP", () => {
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas", null, "", "oracle", "MYSQL"]) {
      expect(exceptionGlobOptions(engine).matchCase).toBe(true);
    }
    for (const engine of ["sqlserver", "mysql", "mariadb", "openldap"]) expect(exceptionGlobOptions(engine).matchCase).toBe(false);
  });
});

describe("dedupDatabaseName (ADR-0021 note of 2026-10-18, PR #274 review M1)", () => {
  it("keeps the case on every engine; drops trailing spaces only on SQL Server, MySQL and MariaDB", () => {
    for (const engine of ["mysql", "mariadb", "sqlserver"]) expect(dedupDatabaseName("CRM  ", engine)).toBe("CRM");
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "openldap", "unknown"]) expect(dedupDatabaseName("CRM  ", engine)).toBe("CRM  ");
    expect(dedupDatabaseName("crm ", null)).toBe("crm ");
    expect(dedupDatabaseName("crm\t", "mysql")).toBe("crm\t");
  });
});

describe("foldName (N1)", () => {
  it("drops trailing spaces only and lowercases every code point", () => {
    expect(foldName("CRM ")).toBe("crm");
    expect(foldName("  Customers  ")).toBe("  customers");
    expect(foldName("CUSTOMERS\t")).toBe("customers\t");
    expect(foldName("ΟΔΟΣ")).toBe("οδοσ");
    expect(foldName("πελατες ")).toBe("πελατεσ");
    expect(foldName("*")).toBe("*");
    expect(foldName("")).toBe("");
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

  it("location globs ignore case and trailing spaces on every engine (N1)", () => {
    const upper = { ...FACTS, databaseName: "CRM ", schemaName: "Public", objectName: "CLIENTS  " };
    expect(findingMatches({ location: { database: "crm", schema: "public", object: "clients" } }, upper)).toBe(true);
    expect(findingMatches({ location: { object: "clients " } }, FACTS)).toBe(true);
    expect(findingMatches({ location: { object: "client" } }, upper)).toBe(false);
    expect(findingMatches({ location: { database: "crm", object: "orders" } }, upper)).toBe(false);
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
    crossTarget: false,
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

  it("location: with case on PostgreSQL, MongoDB, Redis, Valkey and CAS, without case elsewhere (ADR-0054); trailing spaces ignored only on SQL Server and MySQL / MariaDB (N1)", () => {
    const x = { ...base, location: { database: "crm", schema: "public", object: "clients", field: "email" } };
    const exact = { ...FACTS, databaseName: "crm", schemaName: "public", objectName: "clients", fieldName: "email" };
    const upper = { ...FACTS, databaseName: "CRM", schemaName: "PUBLIC", objectName: "Clients", fieldName: "Email" };
    const padded = { ...upper, objectName: "Clients " };
    for (const engine of ["sqlserver", "mysql", "mariadb", "openldap"]) {
      expect(exceptionCovers(x, "p1", { ...upper, engine }, NOW)).toBe(true);
      expect(exceptionCovers(x, "p1", { ...upper, engine, objectName: "orders" }, NOW)).toBe(false);
    }
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas"]) {
      expect(exceptionCovers(x, "p1", { ...exact, engine }, NOW)).toBe(true);
      expect(exceptionCovers(x, "p1", { ...upper, engine }, NOW)).toBe(false);
      // Every location part compares with case.
      expect(exceptionCovers(x, "p1", { ...exact, engine, databaseName: "Crm" }, NOW)).toBe(false);
      expect(exceptionCovers(x, "p1", { ...exact, engine, schemaName: "Public" }, NOW)).toBe(false);
      expect(exceptionCovers(x, "p1", { ...exact, engine, objectName: "Clients" }, NOW)).toBe(false);
      expect(exceptionCovers(x, "p1", { ...exact, engine, fieldName: "EMAIL" }, NOW)).toBe(false);
      // A glob written in the name's case covers it; `?` and `*` cover either spelling.
      expect(exceptionCovers({ ...base, location: { object: "Clients" } }, "p1", { ...upper, engine }, NOW)).toBe(true);
      expect(exceptionCovers({ ...base, location: { object: "Clients" } }, "p1", { ...exact, engine }, NOW)).toBe(false);
      expect(exceptionCovers({ ...base, location: { object: "?lients" } }, "p1", { ...upper, engine }, NOW)).toBe(true);
      expect(exceptionCovers({ ...base, location: { object: "*" } }, "p1", { ...upper, engine }, NOW)).toBe(true);
    }
    for (const engine of ["sqlserver", "mysql", "mariadb"]) {
      expect(exceptionCovers(x, "p1", { ...padded, engine }, NOW)).toBe(true);
      expect(exceptionCovers({ ...x, location: { object: "clients " } }, "p1", { ...upper, engine }, NOW)).toBe(true);
      expect(exceptionCovers(x, "p1", { ...padded, engine, objectName: "client " }, NOW)).toBe(false);
    }
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "openldap", "cas"]) {
      expect(exceptionCovers({ ...base, location: { object: "Clients" } }, "p1", { ...padded, engine }, NOW)).toBe(false);
      expect(exceptionCovers({ ...x, location: { object: "Clients " } }, "p1", { ...upper, engine }, NOW)).toBe(false);
    }
  });

  it("location: an unknown or empty engine compares with case and never ignores trailing spaces (review L4, ADR-0054)", () => {
    const x = { ...base, location: { database: "crm", schema: "public", object: "clients" } };
    for (const engine of ["", "oracle", "SQLSERVER", "mysql "]) {
      expect(exceptionCovers(x, "p1", { ...FACTS, engine, objectName: "clients" }, NOW)).toBe(true);
      expect(exceptionCovers(x, "p1", { ...FACTS, engine, objectName: "Clients" }, NOW)).toBe(false);
      expect(exceptionCovers(x, "p1", { ...FACTS, engine, objectName: "clients " }, NOW)).toBe(false);
      expect(exceptionCovers({ ...x, location: { object: "clients " } }, "p1", { ...FACTS, engine }, NOW)).toBe(false);
    }
  });

  it("policy conditions stay case-insensitive on every engine (ADR-0054 decision 2)", () => {
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas", "sqlserver"]) {
      expect(findingMatches({ location: { database: "crm", object: "clients" } }, { ...FACTS, engine, databaseName: "CRM", objectName: "Clients" })).toBe(true);
    }
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

describe("exceptionCovers: names altered by normalization (ADR-0056 decision 3 item 4)", () => {
  const NOW = new Date("2026-10-23T12:00:00Z");
  const scope = (location: ExceptionScope["location"]): ExceptionScope => ({
    policyId: null,
    agentId: null,
    targetId: null,
    classifier: null,
    location,
    expiresAt: null,
    crossTarget: false,
  });
  const altered = (parts: FindingFacts["altered"], over: Partial<FindingFacts> = {}): FindingFacts => ({ ...FACTS, ...over, altered: parts });

  it("an altered part is covered only by an absent glob or exactly `*`; `\\*` does not cover it", () => {
    const f = altered(["object"]);
    expect(exceptionCovers(scope({ object: "clients" }), "p", f, NOW)).toBe(false);
    expect(exceptionCovers(scope({ object: "cli*" }), "p", f, NOW)).toBe(false);
    expect(exceptionCovers(scope({ object: "\\*" }), "p", altered(["object"], { objectName: "*" }), NOW)).toBe(false);
    expect(exceptionCovers(scope({ object: "*" }), "p", f, NOW)).toBe(true);
    // Parts not altered keep today's rule, with case on PostgreSQL (ADR-0054).
    expect(exceptionCovers(scope({ database: "crm", schema: "public" }), "p", f, NOW)).toBe(true);
    expect(exceptionCovers(scope({ database: "CRM" }), "p", f, NOW)).toBe(false);
    expect(exceptionCovers(scope({ database: "crm", object: "*", field: "email" }), "p", f, NOW)).toBe(true);
    // Without the field (an older agent), or with an empty list: today's behaviour.
    expect(exceptionCovers(scope({ object: "clients" }), "p", { ...FACTS, altered: null }, NOW)).toBe(true);
    expect(exceptionCovers(scope({ object: "clients" }), "p", { ...FACTS }, NOW)).toBe(true);
    expect(exceptionCovers(scope({ object: "clients" }), "p", altered([]), NOW)).toBe(true);
    // Exceptions without a location are not restricted.
    expect(exceptionCovers(scope(null), "p", altered(["database", "schema", "object", "field"]), NOW)).toBe(true);
    // A CAS field converted to snake_case (ADR-0056 open question 2).
    const cas = altered(["field"], { engine: "cas", databaseName: "json", schemaName: "regex", objectName: "app", fieldName: "user_name" });
    expect(exceptionCovers(scope({ field: "user_name" }), "p", cas, NOW)).toBe(false);
    expect(exceptionCovers(scope({ object: "app" }), "p", cas, NOW)).toBe(true);
  });

  it("case-blind engines keep their case rule on the parts not altered", () => {
    const f = altered(["field"], { engine: "mysql", schemaName: null, databaseName: "CRM", objectName: "Clients" });
    expect(exceptionCovers(scope({ database: "crm", object: "clients" }), "p", f, NOW)).toBe(true);
    expect(exceptionCovers(scope({ database: "crm", object: "clients", field: "email" }), "p", f, NOW)).toBe(false);
  });

  it("property: for every glob and name, a cover of an altered part implies a glob absent or exactly `*`, and is today's cover when allowed", () => {
    // Seeded PRNG (mulberry32), so a failure is reproducible.
    let seed = 0x5eed0056;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const CHARS = ["a", "A", "b", "c", "ｃ", "*", "?", "\\", " "];
    const NAMES = ["a", "A", "b", "c", "ｃ", "*", " ", "ab"];
    const pick = (xs: readonly string[], n: number) => Array.from({ length: n }, () => xs[Math.floor(rand() * xs.length)]).join("");
    const PARTS = ["database", "schema", "object", "field"] as const;
    const ENGINES_UNDER_TEST = ["postgres", "mysql", "sqlserver", "openldap", "redis", "cas", "unknown"];
    let restricted = 0;
    let coveredAltered = 0;
    for (let i = 0; i < 20_000; i++) {
      const location: Record<string, string> = {};
      for (const p of PARTS) {
        const r = rand();
        if (r < 0.3) continue;
        location[p] = r < 0.5 ? "*" : r < 0.55 ? "\\*" : pick(CHARS, 1 + Math.floor(rand() * 3));
      }
      if (Object.keys(location).length === 0) location.object = "*";
      const parts = PARTS.filter(() => rand() < 0.35);
      const f: FindingFacts = {
        ...FACTS,
        engine: ENGINES_UNDER_TEST[Math.floor(rand() * ENGINES_UNDER_TEST.length)] as string,
        databaseName: pick(NAMES, 1),
        schemaName: rand() < 0.2 ? null : pick(NAMES, 1),
        objectName: pick(NAMES, 1 + Math.floor(rand() * 2)),
        fieldName: pick(NAMES, 1),
      };
      const x = scope(location);
      const today = exceptionCovers(x, "p", f, NOW);
      const marked = exceptionCovers(x, "p", { ...f, altered: parts }, NOW);
      const allowed = parts.every((p) => location[p] === undefined || location[p] === "*");
      if (marked) {
        coveredAltered += parts.length > 0 ? 1 : 0;
        for (const p of parts) {
          if (location[p] !== undefined && location[p] !== "*") throw new Error(`altered ${p} covered by ${JSON.stringify(location)}`);
        }
      }
      // Stricter only, and unchanged when every altered part is under an absent glob or `*`.
      expect(marked).toBe(today && allowed);
      if (today && !marked) restricted++;
    }
    expect(restricted).toBeGreaterThan(100);
    expect(coveredAltered).toBeGreaterThan(100);
  });
});
