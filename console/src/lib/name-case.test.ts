import { describe, expect, it } from "vitest";

import { exceptionCoversEvent, type EventExceptionScope, type EventFacts } from "./event-model";
import {
  canonicalNameCase,
  compareUtf8,
  databaseObjectsCase,
  exceptionPartOptions,
  MAX_EXCEPT_BYTES,
  nameCaseDisplay,
  NAME_CASE_ENGINES,
  sameNameCase,
  type NameCase,
  type NameCaseRule,
} from "./name-case";
import { exceptionGlobOptions, ENGINES } from "./policy-common";
import { exceptionCovers, type ExceptionScope, type FindingFacts, type LocationPattern } from "./policy-model";

/** ADR-0055 decisions 5 and 6, #301 contract review L2, L3 and I-4. */

const NOW = new Date("2026-10-21T12:00:00Z");
const VALUES: NameCase[] = ["sensitive", "insensitive", "unknown"];

// Seeded PRNG (mulberry32), so a failure is reproducible.
function prng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const finding = (over: Partial<FindingFacts> = {}): FindingFacts => ({
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  targetId: "t1",
  engine: "sqlserver",
  databaseName: "crm",
  schemaName: "dbo",
  objectName: "Customers",
  fieldName: "Email",
  classifier: "pii.email",
  confidence: 0.9,
  sampled: 10,
  matched: 5,
  ...over,
});

const exception = (location: LocationPattern): ExceptionScope => ({ policyId: null, agentId: null, targetId: null, classifier: null, location, expiresAt: null, crossTarget: false });

const event = (over: Partial<EventFacts> = {}): EventFacts => ({
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  targetId: "t1",
  engine: "sqlserver",
  principal: "app",
  action: "read",
  source: "sqlserver_audit",
  objects: [{ database: "crm", schema: "dbo", object: "Customers" }],
  rows: 10,
  signals: [],
  sensitivity: 0,
  score: 0,
  anomaly: false,
  ...over,
});

const eventException = (location: EventExceptionScope["location"]): EventExceptionScope => ({
  policyId: null,
  agentId: null,
  targetId: null,
  classifier: null,
  location,
  expiresAt: null,
  crossTarget: false,
});

describe("canonicalNameCase (#301 review L2, L3)", () => {
  it("is null when not reported, and keeps the closed values", () => {
    expect(canonicalNameCase(undefined)).toBeNull();
    expect(canonicalNameCase(null)).toBeNull();
    for (const databases of VALUES) for (const objects of VALUES) expect(canonicalNameCase({ databases, objects })).toEqual({ databases, objects });
  });

  it("sorts except by UTF-8 byte order, one entry per name with the stricter value, an empty list dropped", () => {
    const v = {
      databases: "insensitive",
      objects: "insensitive",
      except: [
        { database: "zeta", objects: "insensitive" },
        { database: "\u{1F600}db", objects: "unknown" },
        { database: "�db", objects: "sensitive" },
        { database: "Alpha", objects: "insensitive" },
        { database: "zeta", objects: "unknown" },
        { database: "zeta", objects: "insensitive" },
      ],
    };
    // U+FFFD sorts before U+1F600 in UTF-8 (and code points), after it in UTF-16 code units.
    expect(canonicalNameCase(v)?.except).toEqual([
      { database: "Alpha", objects: "insensitive" },
      { database: "zeta", objects: "unknown" },
      { database: "�db", objects: "sensitive" },
      { database: "\u{1F600}db", objects: "unknown" },
    ]);
    expect(canonicalNameCase({ databases: "sensitive", objects: "sensitive", except: [] })).toEqual({ databases: "sensitive", objects: "sensitive" });
    expect(compareUtf8("�", "\u{1F600}")).toBeLessThan(0);
    expect("�" < "\u{1F600}").toBe(false);
  });

  it("compares canonically, never as raw JSON", () => {
    const a = { databases: "insensitive", objects: "insensitive", except: [{ database: "b", objects: "sensitive" }, { database: "a", objects: "unknown" }] };
    const b = { objects: "insensitive", except: [{ objects: "unknown", database: "a" }, { database: "b", objects: "insensitive" }, { database: "b", objects: "sensitive" }], databases: "insensitive" };
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
    expect(sameNameCase(a, b)).toBe(true);
    expect(sameNameCase(a, { ...a, objects: "unknown" })).toBe(false);
    expect(sameNameCase(undefined, null)).toBe(true);
    expect(sameNameCase(undefined, { databases: "insensitive", objects: "insensitive" })).toBe(false);
  });

  it("stores the strict form for an except past 8 KiB or 32 entries, never refusing it (L3)", () => {
    const long = (i: number) => ({ database: `${String(i).padStart(2, "0")}${"d".repeat(254)}`, objects: "insensitive" });
    const big = { databases: "insensitive", objects: "insensitive", except: Array.from({ length: 32 }, (_, i) => long(i)) };
    expect(new TextEncoder().encode(JSON.stringify(big.except)).length).toBeGreaterThan(MAX_EXCEPT_BYTES);
    expect(canonicalNameCase(big)).toEqual({ databases: "insensitive", objects: "unknown" });
    const many = { databases: "sensitive", objects: "insensitive", except: Array.from({ length: 33 }, (_, i) => ({ database: `d${i}`, objects: "insensitive" })) };
    expect(canonicalNameCase(many)).toEqual({ databases: "sensitive", objects: "unknown" });
    // Within the bound: kept.
    const small = { databases: "insensitive", objects: "insensitive", except: Array.from({ length: 32 }, (_, i) => ({ database: `d${String(i).padStart(2, "0")}`, objects: "sensitive" })) };
    expect(canonicalNameCase(small)?.except).toHaveLength(32);
  });

  it("reads hostile or corrupt values as the strict form", () => {
    expect(canonicalNameCase("sensitive")).toEqual({ databases: "unknown", objects: "unknown" });
    expect(canonicalNameCase([])).toEqual({ databases: "unknown", objects: "unknown" });
    expect(canonicalNameCase({ databases: "Latin1_General_CI_AS", objects: 0 })).toEqual({ databases: "unknown", objects: "unknown" });
    expect(canonicalNameCase({ databases: "insensitive", objects: "insensitive", except: "crm" })).toEqual({ databases: "insensitive", objects: "unknown" });
    expect(canonicalNameCase({ databases: "insensitive", objects: "insensitive", except: [{ database: 1, objects: "insensitive" }] })).toEqual({
      databases: "insensitive",
      objects: "unknown",
    });
    expect(canonicalNameCase({ databases: "insensitive", objects: "insensitive", except: [{ database: "crm", objects: "INSENSITIVE" }] })?.except).toEqual([
      { database: "crm", objects: "unknown" },
    ]);
  });
});

describe("exceptionPartOptions (ADR-0055 decision 6)", () => {
  it("keeps today's options without a rule, and on every other engine whatever the rule (L6, I-4)", () => {
    const rule: NameCaseRule = { databases: "sensitive", objects: "sensitive" };
    for (const engine of [...ENGINES, null, "", "MYSQL", "oracle"]) {
      const today = exceptionGlobOptions(engine);
      const expected = { perPart: { database: today, schema: today, object: today, field: today } };
      expect(exceptionPartOptions(engine, null, "crm")).toEqual(expected);
      expect(exceptionPartOptions(engine, undefined, "crm")).toEqual(expected);
      if (engine === null || !NAME_CASE_ENGINES.includes(engine)) expect(exceptionPartOptions(engine, rule, "crm")).toEqual(expected);
    }
  });

  it("per part, over every combination of databases, objects and an except entry", () => {
    for (const engine of NAME_CASE_ENGINES) {
      for (const databases of VALUES) {
        for (const objects of VALUES) {
          for (const entry of [undefined, ...VALUES]) {
            const rule: NameCaseRule = entry === undefined ? { databases, objects } : { databases, objects, except: [{ database: "crm", objects: entry }] };
            const o = exceptionPartOptions(engine, rule, "crm").perPart;
            const dbValue = entry ?? objects;
            expect(o.database.matchCase, `${engine} ${databases}`).toBe(databases !== "insensitive");
            expect(o.schema.matchCase).toBe(dbValue !== "insensitive");
            expect(o.object.matchCase).toBe(dbValue !== "insensitive");
            // Column names: as `object` on SQL Server, never with case on MySQL / MariaDB.
            expect(o.field.matchCase).toBe(engine === "sqlserver" ? dbValue !== "insensitive" : false);
            // The trailing-space rule is unchanged (N1: ignored on these engines).
            for (const p of [o.database, o.schema, o.object, o.field]) expect(p.ignoreTrailingSpaces).toBe(true);
            // Another database takes `objects`, unless it matches after the fold.
            expect(exceptionPartOptions(engine, rule, "billing").perPart.object.matchCase).toBe(objects !== "insensitive");
          }
        }
      }
    }
  });

  it("looks the database up folded when database names compare without case, else exact and folded (L2)", () => {
    const rule = (databases: NameCase, objects: NameCase, except: { database: string; objects: NameCase }[]): NameCaseRule => ({ databases, objects, except });
    // databases insensitive: the folded entry decides, `objects` only without one.
    expect(databaseObjectsCase(rule("insensitive", "sensitive", [{ database: "crm", objects: "insensitive" }]), "CRM")).toBe("insensitive");
    expect(databaseObjectsCase(rule("insensitive", "insensitive", [{ database: "crm", objects: "sensitive" }]), "CRM")).toBe("sensitive");
    expect(databaseObjectsCase(rule("insensitive", "insensitive", [{ database: "crm", objects: "sensitive" }]), "Crm ")).toBe("sensitive");
    // Several folded entries: the stricter.
    expect(
      databaseObjectsCase(
        rule("insensitive", "insensitive", [
          { database: "CRM", objects: "insensitive" },
          { database: "crm", objects: "unknown" },
        ]),
        "Crm",
      ),
    ).toBe("unknown");
    // databases sensitive: the exact entry (or `objects`), and every folded match, the stricter.
    expect(databaseObjectsCase(rule("sensitive", "sensitive", [{ database: "crm", objects: "insensitive" }]), "crm")).toBe("insensitive");
    expect(databaseObjectsCase(rule("sensitive", "sensitive", [{ database: "crm", objects: "insensitive" }]), "CRM")).toBe("sensitive");
    expect(
      databaseObjectsCase(
        rule("unknown", "insensitive", [
          { database: "CRM", objects: "sensitive" },
          { database: "crm", objects: "insensitive" },
        ]),
        "crm",
      ),
    ).toBe("sensitive");
    // Trailing spaces ignored in the exact lookup too (the N1 rule of these engines).
    expect(databaseObjectsCase(rule("sensitive", "sensitive", [{ database: "crm", objects: "insensitive" }]), "crm  ")).toBe("insensitive");
    // Final sigma folds as sigma.
    expect(databaseObjectsCase(rule("insensitive", "insensitive", [{ database: "ΠΕΛΑΤΕΣ", objects: "sensitive" }]), "πελατες")).toBe("sensitive");
  });

  it("a raw rule whose except is not a list of entries reads as unknown, never a throw (review L3)", () => {
    for (const except of ["crm", 3, {}, [1], [{ database: 7, objects: "insensitive" }], [null]]) {
      const rule = { databases: "insensitive", objects: "insensitive", except } as unknown as NameCaseRule;
      expect(databaseObjectsCase(rule, "crm")).toBe("unknown");
      expect(databaseObjectsCase(rule, "*")).toBe("unknown");
      for (const engine of NAME_CASE_ENGINES) expect(exceptionPartOptions(engine, rule, "crm").perPart.object.matchCase).toBe(true);
    }
    expect(nameCaseDisplay({ databases: "sensitive", objects: "sensitive", except: "x" } as unknown as NameCaseRule)).toBe("with_case");
  });

  it("the database `*` takes the strictest of objects and every except value (L1), the merged `*` entry included", () => {
    const merged: NameCaseRule = { databases: "insensitive", objects: "insensitive", except: [{ database: "*", objects: "sensitive" }] };
    expect(databaseObjectsCase(merged, "*")).toBe("sensitive");
    const r: NameCaseRule = {
      databases: "insensitive",
      objects: "insensitive",
      except: [
        { database: "a", objects: "unknown" },
        { database: "b", objects: "insensitive" },
      ],
    };
    expect(databaseObjectsCase(r, "*")).toBe("unknown");
    expect(databaseObjectsCase({ databases: "insensitive", objects: "sensitive", except: [{ database: "a", objects: "insensitive" }] }, "*")).toBe("sensitive");
    expect(databaseObjectsCase({ databases: "insensitive", objects: "insensitive" }, "*")).toBe("insensitive");
    // A database name that is not `*` does not match the `*` entry: it is a literal name.
    expect(databaseObjectsCase(merged, "crm")).toBe("insensitive");
  });
});

describe("exception covers under name_case (ADR-0055 decision 6)", () => {
  const sensitive: NameCaseRule = { databases: "sensitive", objects: "sensitive" };
  const perDb: NameCaseRule = { databases: "insensitive", objects: "insensitive", except: [{ database: "crm_cs", objects: "sensitive" }] };

  it("findings: a lowercase exception stops covering `Customers` where names compare with case", () => {
    const x = exception({ database: "crm", object: "customers" });
    expect(exceptionCovers(x, "p", finding(), NOW)).toBe(true);
    expect(exceptionCovers(x, "p", finding({ nameCase: sensitive }), NOW)).toBe(false);
    expect(exceptionCovers(x, "p", finding({ nameCase: { databases: "unknown", objects: "unknown" } }), NOW)).toBe(false);
    expect(exceptionCovers(x, "p", finding({ nameCase: { databases: "insensitive", objects: "insensitive" } }), NOW)).toBe(true);
    // Per database: only the listed database compares object names with case.
    expect(exceptionCovers(x, "p", finding({ nameCase: perDb }), NOW)).toBe(true);
    expect(exceptionCovers(exception({ database: "crm_cs", object: "customers" }), "p", finding({ databaseName: "crm_cs", nameCase: perDb }), NOW)).toBe(false);
    // Database names compare without case there: `CRM_CS` is `crm_cs`.
    expect(exceptionCovers(exception({ database: "CRM_CS", object: "Customers" }), "p", finding({ databaseName: "crm_cs", nameCase: perDb }), NOW)).toBe(true);
  });

  it("findings: column names follow `objects` on SQL Server, never with case on MySQL / MariaDB", () => {
    const x = exception({ field: "email" });
    expect(exceptionCovers(x, "p", finding({ nameCase: sensitive }), NOW)).toBe(false);
    for (const engine of ["mysql", "mariadb"]) {
      expect(exceptionCovers(x, "p", finding({ engine, schemaName: null, nameCase: sensitive }), NOW)).toBe(true);
      expect(exceptionCovers(exception({ object: "customers" }), "p", finding({ engine, schemaName: null, nameCase: sensitive }), NOW)).toBe(false);
    }
  });

  it("findings: ignored on other engines, a missing field keeps today's rule", () => {
    const x = exception({ object: "customers" });
    expect(exceptionCovers(x, "p", finding({ engine: "openldap", nameCase: sensitive }), NOW)).toBe(true);
    expect(exceptionCovers(x, "p", finding({ engine: "postgres", nameCase: { databases: "insensitive", objects: "insensitive" } }), NOW)).toBe(false);
    expect(exceptionCovers(x, "p", finding({ engine: "mysql", schemaName: null }), NOW)).toBe(true);
  });

  it("events: per object database, the database `*` strictest, the overflow `*` judged on its database part", () => {
    const x = eventException({ database: "crm", object: "customers" });
    expect(exceptionCoversEvent(x, "p", event(), [0], NOW)).toBe(true);
    expect(exceptionCoversEvent(x, "p", event({ nameCase: sensitive }), [0], NOW)).toBe(false);
    // Per database: an object of the listed database compares with case.
    const two = event({
      nameCase: perDb,
      objects: [
        { database: "crm", schema: "dbo", object: "Customers" },
        { database: "crm_cs", schema: "dbo", object: "Customers" },
      ],
    });
    expect(exceptionCoversEvent(eventException({ object: "customers" }), "p", two, [0], NOW)).toBe(true);
    expect(exceptionCoversEvent(eventException({ object: "customers" }), "p", two, [0, 1], NOW)).toBe(false);
    // The database `*`: strictest of objects and every except value (L1).
    const star = event({ nameCase: perDb, objects: [{ database: "*", schema: "dbo", object: "Customers" }] });
    expect(exceptionCoversEvent(eventException({ object: "customers" }), "p", star, [0], NOW)).toBe(false);
    expect(exceptionCoversEvent(eventException({ object: "Customers" }), "p", star, [0], NOW)).toBe(true);
    // The event's engine is the source's: a MySQL source on that target applies the rule as MySQL.
    expect(exceptionCoversEvent(x, "p", event({ engine: "mysql", nameCase: sensitive, objects: [{ database: "crm", object: "Customers" }] }), [0], NOW)).toBe(false);
    // Overflow `*`: only the database glob applies, with the database part's options.
    const overflow = event({ nameCase: sensitive, objectsOverflowed: true, objects: [{ database: "CRM", schema: "*", object: "*" }] });
    expect(exceptionCoversEvent(eventException({ database: "crm" }), "p", overflow, [0], NOW)).toBe(false);
    expect(exceptionCoversEvent(eventException({ database: "crm" }), "p", { ...overflow, nameCase: null }, [0], NOW)).toBe(true);
  });
});

describe("properties (ADR-0055 decision 10, L6)", () => {
  const rand = prng(0x5eed0055);
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;
  const NAME = ["a", "A", "b", "B", "İ", "ı", "s", "S", "ß", "σ", "ς", "Σ", " ", "_", "*"];
  const GLOB = [...NAME, "*", "?", "\\*", "\\ "];
  const str = (alphabet: readonly string[], max: number) => Array.from({ length: Math.floor(rand() * max) }, () => pick(alphabet)).join("");
  const name = () => str(NAME, 6) + (rand() < 0.2 ? " " : "");
  const glob = () => {
    const g = str(GLOB, 5);
    return g.length > 0 ? g : "*";
  };
  const value = (): unknown =>
    pick<unknown>([...VALUES, ...VALUES, "SENSITIVE", "Latin1_General_CS_AS", 0, null, undefined, {}, [], "__proto__", "constructor"]);
  /** Any `name_case`, hostile ones included: wrong types, values outside the set, odd keys. */
  const anyNameCase = (): unknown => {
    const r = rand();
    if (r < 0.05) return pick<unknown>(["sensitive", 1, [], true, "{}", { __proto__: { databases: "sensitive" } }]);
    if (r < 0.15) return undefined;
    const except =
      rand() < 0.3 ? undefined : rand() < 0.1 ? pick<unknown>(["x", 3, {}]) : Array.from({ length: Math.floor(rand() * 5) }, () => ({ database: rand() < 0.9 ? name() : 7, objects: value() }));
    return { databases: value(), objects: value(), ...(except === undefined ? {} : { except }), ...(rand() < 0.1 ? { extra: "x" } : {}) };
  };
  const location = (): LocationPattern => {
    const l: LocationPattern = {};
    for (const p of ["database", "schema", "object", "field"] as const) if (rand() < 0.6) l[p] = glob();
    return l;
  };
  /** A glob derived from `n` (case flipped, letters replaced by `?` / `*`), so matches are frequent. */
  const near = (n: string) => {
    const g = [...n]
      .map((c) => {
        const r = rand();
        if (r < 0.1) return "?";
        if (r < 0.15) return "*";
        if (c === "*" || c === "?" || c === "\\") return `\\${c}`;
        return r < 0.45 ? (rand() < 0.5 ? c.toUpperCase() : c.toLowerCase()) : c;
      })
      .join("");
    return g.length > 0 && g.length <= 256 ? g : "*";
  };
  const nearLocation = (f: FindingFacts): LocationPattern => {
    const names = { database: f.databaseName, schema: f.schemaName, object: f.objectName, field: f.fieldName };
    const l: LocationPattern = {};
    for (const p of ["database", "schema", "object", "field"] as const) {
      if (rand() < 0.5) continue;
      const v = names[p];
      l[p] = v === null || rand() < 0.15 ? glob() : near(v);
    }
    return l;
  };

  it("on any engine other than the three, the exception result is the same for any name_case", () => {
    let covered = 0;
    for (let i = 0; i < 20_000; i++) {
      const engine = pick([...ENGINES.filter((e) => !NAME_CASE_ENGINES.includes(e)), "oracle", "MySQL", ""]);
      const f = finding({ engine, databaseName: name(), schemaName: rand() < 0.3 ? null : name(), objectName: name(), fieldName: name() });
      const x = exception(rand() < 0.8 ? nearLocation(f) : location());
      const today = exceptionCovers(x, "p", f, NOW);
      const rule = canonicalNameCase(anyNameCase());
      // Also a rule that bypasses canonicalization (a hostile in-memory value).
      const raw = anyNameCase() as NameCaseRule;
      expect(exceptionCovers(x, "p", { ...f, nameCase: rule }, NOW)).toBe(today);
      expect(exceptionCovers(x, "p", { ...f, nameCase: raw }, NOW)).toBe(today);
      const e = event({ engine, objects: [{ database: f.databaseName, object: f.objectName, ...(f.schemaName === null ? {} : { schema: f.schemaName }) }] });
      const { field: _f, ...parts } = x.location ?? {};
      const ex = eventException(parts);
      expect(exceptionCoversEvent(ex, "p", { ...e, nameCase: rule }, [0], NOW)).toBe(exceptionCoversEvent(ex, "p", e, [0], NOW));
      if (today) covered++;
    }
    expect(covered).toBeGreaterThan(1000);
  });

  it("on the three engines, a cover under any name_case implies today's cover; the trailing-space rule is unchanged", () => {
    let covered = 0;
    let narrowed = 0;
    let rawRules = 0;
    for (let i = 0; i < 20_000; i++) {
      const engine = pick(NAME_CASE_ENGINES);
      const f = finding({ engine, databaseName: name(), schemaName: engine === "sqlserver" ? name() : null, objectName: name(), fieldName: name() });
      // Canonical rules, and raw ones that bypass `canonicalNameCase` (hostile in-memory values, review L3).
      const raw = rand() < 0.3;
      const rule = raw ? (anyNameCase() as NameCaseRule) : canonicalNameCase(anyNameCase());
      const x = exception(rand() < 0.8 ? nearLocation(f) : location());
      const today = exceptionCovers(x, "p", f, NOW);
      const strict = exceptionCovers(x, "p", { ...f, nameCase: rule }, NOW);
      if (strict && !today) throw new Error(`name_case loosened ${JSON.stringify(x.location)} on ${JSON.stringify(f)} with ${JSON.stringify(rule)}`);
      if (raw) rawRules++;
      if (strict) covered++;
      if (today && !strict) narrowed++;
      // Trailing spaces: the options of every part keep today's rule.
      for (const o of Object.values(exceptionPartOptions(engine, rule, f.databaseName).perPart)) {
        expect(o.ignoreTrailingSpaces).toBe(exceptionGlobOptions(engine).ignoreTrailingSpaces);
      }
      // Events too.
      const e = event({ engine, nameCase: rule, objects: [{ database: rand() < 0.1 ? "*" : f.databaseName, object: f.objectName }] });
      const { field: _f, ...parts } = x.location ?? {};
      const ex = eventException(parts);
      if (exceptionCoversEvent(ex, "p", e, [0], NOW) && !exceptionCoversEvent(ex, "p", { ...e, nameCase: null }, [0], NOW)) {
        throw new Error(`name_case loosened an event cover: ${JSON.stringify(parts)} with ${JSON.stringify(rule)}`);
      }
    }
    expect(covered).toBeGreaterThan(500);
    expect(narrowed).toBeGreaterThan(500);
    expect(rawRules).toBeGreaterThan(1000);
  });
});

describe("nameCaseDisplay (ADR-0055 decision 7)", () => {
  it("names the rule for the target page", () => {
    expect(nameCaseDisplay(null)).toBe("not_reported");
    expect(nameCaseDisplay({ databases: "sensitive", objects: "sensitive" })).toBe("with_case");
    expect(nameCaseDisplay({ databases: "insensitive", objects: "insensitive" })).toBe("without_case");
    expect(nameCaseDisplay({ databases: "unknown", objects: "unknown" })).toBe("unknown");
    expect(nameCaseDisplay({ databases: "insensitive", objects: "unknown" })).toBe("per_database");
    expect(nameCaseDisplay({ databases: "insensitive", objects: "insensitive", except: [{ database: "a", objects: "sensitive" }] })).toBe("per_database");
  });
});
