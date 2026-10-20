import { describe, expect, it } from "vitest";

import { registeredClassifiers, registeredClassifiersVersions } from "@/lib/protocol/classifiers";

import {
  ANOMALY_MIN_ROWS,
  BASELINE_WARMUP,
  CLASSIFIER_WEIGHTS,
  classifierWeight,
  dedupObject,
  dedupPrincipal,
  EMPTY_BASELINE,
  eventBucket,
  eventDedupKey,
  eventMatches,
  eventOverflowKey,
  eventScore,
  exceptionCoversEvent,
  exceptionCoversOverflowStar,
  isOverflowStar,
  mergeSignals,
  overflowStarMatches,
  objectMatches,
  objectSensitivity,
  parseEventConditions,
  SENSITIVITY_CAP,
  severeEvent,
  updateBaseline,
  worseThanClosed,
  worseThanFalsePositive,
  baselineVerdict,
  type BaselineState,
  type EventExceptionScope,
  type EventFacts,
  type EventObject,
  type ObjectPattern,
} from "./event-model";
import { exceptionGlobOptions } from "./policy-common";
import { parsePolicyConditions } from "./policy-model";

const FACTS: EventFacts = {
  agentId: "01890a5d-ac96-774b-bcce-b302099a8058",
  targetId: "pg-prod-1",
  engine: "postgres",
  principal: "backup",
  action: "read",
  source: "pgaudit",
  objects: [
    { database: "crm", schema: "public", object: "clients" },
    { database: "crm", schema: "public", object: "orders" },
  ],
  rows: 1_250_000,
  signals: ["signature.pg_dump", "shape.full_table_copy"],
  sensitivity: 10.5,
  score: 64.1,
  anomaly: false,
};

describe("scoring", () => {
  it("weights every registered classifier explicitly", () => {
    for (const version of registeredClassifiersVersions()) {
      for (const id of registeredClassifiers(version) ?? []) expect(Object.hasOwn(CLASSIFIER_WEIGHTS, id)).toBe(true);
    }
  });

  it("falls back to the family weight, then to the default", () => {
    expect(classifierWeight("secret.new_token")).toBe(8);
    expect(classifierWeight("pii.new_id")).toBe(2);
    expect(classifierWeight("other.x")).toBe(1);
    // Never a prototype lookup.
    expect(classifierWeight("constructor")).toBe(1);
    expect(classifierWeight("__proto__.x")).toBe(1);
  });

  it("object sensitivity: weight x best confidence per classifier, summed, capped", () => {
    expect(objectSensitivity([])).toBe(0);
    expect(
      objectSensitivity([
        { classifier: "pii.email", confidence: 0.9 },
        { classifier: "pii.email", confidence: 0.5 },
        { classifier: "pii.iban", confidence: 1 },
      ]),
    ).toBe(3 * 0.9 + 7);
    const many = Object.keys(CLASSIFIER_WEIGHTS).map((classifier) => ({ classifier, confidence: 1 }));
    expect(objectSensitivity(many)).toBe(SENSITIVITY_CAP);
    // Out-of-range confidences are clamped.
    expect(objectSensitivity([{ classifier: "pii.email", confidence: 7 }])).toBe(3);
    expect(objectSensitivity([{ classifier: "pii.email", confidence: Number.NaN }])).toBe(0);
  });

  it("score: sensitivity x log10(1 + rows); 0 without rows or sensitivity", () => {
    expect(eventScore(10, 999)).toBe(30);
    expect(eventScore(3, 1_000_000)).toBe(18);
    expect(eventScore(0, 1_000_000)).toBe(0);
    expect(eventScore(10, null)).toBe(0);
    expect(eventScore(10, 0)).toBe(0);
    // Monotonic in both factors.
    expect(eventScore(10, 10_000)).toBeGreaterThan(eventScore(10, 1000));
    expect(eventScore(11, 1000)).toBeGreaterThan(eventScore(10, 1000));
    // Bounded: the largest `Count` with the highest sensitivity.
    expect(eventScore(SENSITIVITY_CAP, Number.MAX_SAFE_INTEGER)).toBeLessThan(500);
  });
});

function feed(rows: number[], start: BaselineState = EMPTY_BASELINE): BaselineState {
  return rows.reduce((s, r) => updateBaseline(s, r, eventScore(5, r)), start);
}

describe("baselines", () => {
  it("is the plain mean of ln(1 + rows) during warm-up", () => {
    const s = feed([99, 9999]);
    expect(s.events).toBe(2);
    expect(s.meanLogRows).toBeCloseTo((Math.log(100) + Math.log(10000)) / 2, 10);
    // Population variance of the two values.
    expect(s.varLogRows).toBeCloseTo(((Math.log(10000) - Math.log(100)) / 2) ** 2, 10);
  });

  it("flags nothing during warm-up", () => {
    const s = feed(Array.from({ length: BASELINE_WARMUP - 1 }, () => 100));
    const v = baselineVerdict(s, 10_000_000);
    expect(v).toEqual({ warm: false, anomaly: false, baselineRows: null, thresholdRows: null });
  });

  it("after warm-up, flags a volume ten times above the typical one (and >= the floor)", () => {
    const s = feed(Array.from({ length: BASELINE_WARMUP }, () => 1000));
    const v = baselineVerdict(s, 1000);
    expect(v.warm).toBe(true);
    expect(v.anomaly).toBe(false);
    expect(v.baselineRows).toBeCloseTo(1000, 0);
    expect(v.thresholdRows).toBeGreaterThan(9_000);
    expect(baselineVerdict(s, 9_000).anomaly).toBe(false);
    expect(baselineVerdict(s, 20_000).anomaly).toBe(true);
    // Events without rows are never anomalies.
    expect(baselineVerdict(s, null).anomaly).toBe(false);
  });

  it("does not flag small volumes, whatever the baseline", () => {
    const s = feed(Array.from({ length: BASELINE_WARMUP }, () => 1));
    expect(baselineVerdict(s, ANOMALY_MIN_ROWS - 1).anomaly).toBe(false);
    expect(baselineVerdict(s, ANOMALY_MIN_ROWS * 10).anomaly).toBe(true);
  });

  it("widens the threshold with the principal's variability (3 sd)", () => {
    const noisy = feed(Array.from({ length: 200 }, (_, i) => (i % 2 === 0 ? 100 : 100_000)));
    const v = baselineVerdict(noisy, 200_000);
    expect(v.anomaly).toBe(false);
    expect(v.thresholdRows).toBeGreaterThan(1_000_000);
  });

  it("caps an anomalous event before learning it (one dump does not move the baseline much)", () => {
    const s = feed(Array.from({ length: 100 }, () => 1000));
    const after = updateBaseline(s, 50_000_000, 100);
    expect(Math.expm1(after.meanLogRows)).toBeLessThan(1000 * 1.2);
    // A lasting increase is learnt gradually.
    const shifted = feed(Array.from({ length: 200 }, () => 50_000), s);
    expect(baselineVerdict(shifted, 60_000).anomaly).toBe(false);
  });

  it("ignores events without rows", () => {
    const s = feed([100, 100]);
    expect(updateBaseline(s, null, 0)).toBe(s);
  });

  it("stays finite on extreme inputs", () => {
    const s = feed([0, Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER]);
    for (const v of Object.values(s)) expect(Number.isFinite(v)).toBe(true);
    expect(s.varLogRows).toBeGreaterThanOrEqual(0);
  });
});

describe("access_event conditions", () => {
  it("accepts every key", () => {
    const r = parseEventConditions({
      signals: ["signature.*", "shape.full_table_copy"],
      event_actions: ["read"],
      sources: ["pgaudit"],
      agent_ids: [FACTS.agentId],
      target_ids: ["pg-prod-1"],
      engines: ["postgres"],
      principals: ["backup*"],
      exclude_principals: ["svc_*"],
      objects: { database: "crm", object: "client*" },
      min_rows: 1000,
      min_score: 10,
      min_sensitivity: 1,
      anomaly: true,
    });
    expect(r.ok).toBe(true);
    expect(parsePolicyConditions("access_event", { signals: ["signature.pg_dump"] })).toEqual({
      ok: true,
      value: { signals: ["signature.pg_dump"] },
    });
  });

  it.each([
    ["an empty document (would match every access)", {}, "conditions"],
    ["only scoping keys", { target_ids: ["pg-prod-1"], sources: ["pgaudit"] }, "conditions"],
    ["a finding key", { classifiers: ["pii.email"] }, "conditions"],
    ["an unknown key", { query: "select 1" }, "conditions"],
    ["a malformed signal", { signals: ["pg_dump"] }, "signals"],
    ["another signal family", { signals: ["value.x"] }, "signals"],
    ["a digit in a signal id (contract pattern, ADR-0022)", { signals: ["signature.pg_dump2"] }, "signals"],
    ["a signal word over 16 letters", { signals: [`shape.${"a".repeat(17)}`] }, "signals"],
    ["a signal id of 7 words", { signals: ["shape.a_b_c_d_e_f_g"] }, "signals"],
    ["an unknown action", { event_actions: ["select"] }, "event_actions"],
    ["an unknown source", { signals: ["shape.*"], sources: ["syslog"] }, "sources"],
    ["an empty list", { signals: [] }, "signals"],
    ["a control character in a glob", { principals: ["a‮b"] }, "principals"],
    ["a field in objects", { objects: { field: "email" } }, "objects"],
    ["a negative threshold", { min_score: -1 }, "min_score"],
    ["a fractional row count", { min_rows: 1.5 }, "min_rows"],
    ["anomaly false", { anomaly: false }, "anomaly"],
  ])("rejects %s", (_name, doc, field) => {
    expect(parseEventConditions(doc)).toEqual({ ok: false, error: field });
  });

  it("loads a stored document written with the pre-P4-D selector, never saves one", () => {
    const doc = { signals: ["signature.tool2", "signature.pg_dump"] };
    expect(parseEventConditions(doc)).toEqual({ ok: false, error: "signals" });
    expect(parseEventConditions(doc, { stored: true })).toEqual({ ok: true, value: doc });
    expect(parseEventConditions({ signals: ["value.x"] }, { stored: true })).toEqual({ ok: false, error: "signals" });
    expect(parseEventConditions({ signals: ["shape.a_b_c_d_e_f"] }).ok).toBe(true);
  });

  it("matches with AND across keys and OR within a list", () => {
    expect(eventMatches({ signals: ["signature.*"] }, FACTS)).toEqual([0, 1]);
    expect(eventMatches({ signals: ["signature.copy_to_file"] }, FACTS)).toBeNull();
    expect(eventMatches({ signals: ["signature.copy_to_file", "shape.full_table_copy"] }, FACTS)).toEqual([0, 1]);
    expect(eventMatches({ signals: ["signature.*"], event_actions: ["write"] }, FACTS)).toBeNull();
    expect(eventMatches({ principals: ["BACK*"] }, FACTS)).toEqual([0, 1]);
    expect(eventMatches({ principals: ["*"], exclude_principals: ["backup"] }, FACTS)).toBeNull();
    // Review M1: the final sigma folds as sigma, on principals and exclusions too.
    const greek = { ...FACTS, principal: "λογαριασμος" };
    expect(eventMatches({ principals: ["ΛΟΓΑΡΙΑΣΜΟΣ"] }, greek)).toEqual([0, 1]);
    expect(eventMatches({ principals: ["λογαριασμοσ"] }, greek)).toEqual([0, 1]);
    expect(eventMatches({ principals: ["λογαριασμα"] }, greek)).toBeNull();
    expect(eventMatches({ principals: ["*"], exclude_principals: ["ΛΟΓΑΡΙΑΣΜΟΣ"] }, greek)).toBeNull();
    expect(eventMatches({ principals: ["*"], exclude_principals: ["λογαριασμοσ"] }, { ...greek, principal: "ΛΟΓΑΡΙΑΣΜΟΣ" })).toBeNull();
    expect(eventMatches({ principals: ["*"], exclude_principals: ["λογαριασμα"] }, greek)).toEqual([0, 1]);
    // P9-E review L1: an unrecorded account only matches `*`, and exclusions never hide it.
    const unrecorded = { ...FACTS, principal: "", accountNotRecorded: true };
    expect(eventMatches({ principals: ["*"] }, unrecorded)).toEqual([0, 1]);
    expect(eventMatches({ principals: ["backup*"] }, unrecorded)).toBeNull();
    expect(eventMatches({ principals: ["?*"] }, unrecorded)).toBeNull();
    expect(eventMatches({ principals: ["*"], exclude_principals: ["*"] }, unrecorded)).toEqual([0, 1]);
    expect(eventMatches({ min_rows: 2_000_000 }, FACTS)).toBeNull();
    expect(eventMatches({ min_rows: 1 }, { ...FACTS, rows: null })).toBeNull();
    expect(eventMatches({ min_score: 64.1 }, FACTS)).toEqual([0, 1]);
    expect(eventMatches({ min_sensitivity: 11 }, FACTS)).toBeNull();
    expect(eventMatches({ anomaly: true }, FACTS)).toBeNull();
    expect(eventMatches({ anomaly: true }, { ...FACTS, anomaly: true })).toEqual([0, 1]);
    expect(eventMatches({ signals: ["shape.*"], engines: ["mysql"] }, FACTS)).toBeNull();
    expect(eventMatches({ signals: ["shape.*"], engines: ["postgres"] }, { ...FACTS, engine: null })).toBeNull();
  });

  it("retains the objects matching the `objects` globs; an event without object never matches them", () => {
    expect(eventMatches({ objects: { object: "ord*" } }, FACTS)).toEqual([1]);
    expect(eventMatches({ objects: { schema: "private" } }, FACTS)).toBeNull();
    expect(eventMatches({ objects: { database: "*" } }, { ...FACTS, objects: [] })).toBeNull();
    // An object without schema only matches a schema glob of `*`.
    const mysql = { ...FACTS, objects: [{ database: "shop", object: "customers" }] };
    expect(eventMatches({ objects: { schema: "*" } }, mysql)).toEqual([0]);
    expect(eventMatches({ objects: { schema: "p*" } }, mysql)).toBeNull();
  });

  it("`objects` globs ignore case and trailing spaces on every engine (N1)", () => {
    const upper = { ...FACTS, objects: [{ database: "CRM", schema: "Public", object: "CLIENTS " }, { database: "crm", schema: "public", object: "orders" }] };
    expect(eventMatches({ objects: { database: "crm", schema: "public", object: "clients" } }, upper)).toEqual([0]);
    expect(eventMatches({ objects: { object: "clients " } }, FACTS)).toEqual([0]);
    for (const engine of ["postgres", "mongodb", "redis", "sqlserver", "mysql"]) {
      expect(eventMatches({ objects: { object: "Clients" } }, { ...upper, engine })).toEqual([0]);
    }
    expect(eventMatches({ objects: { object: "client" } }, upper)).toBeNull();
    expect(eventMatches({ objects: { schema: "private", object: "clients" } }, upper)).toBeNull();
    // A schema-less object still only matches a schema glob of `*`.
    expect(eventMatches({ objects: { schema: "public" } }, { ...FACTS, objects: [{ database: "CRM", object: "CLIENTS" }] })).toBeNull();
  });

  it("exceptions: with case on PostgreSQL, MongoDB, Redis, Valkey and CAS, without case elsewhere (ADR-0054); trailing spaces ignored only on SQL Server and MySQL / MariaDB (N1)", () => {
    const now = new Date("2026-09-28T12:00:00Z");
    const base = { policyId: null, agentId: null, targetId: null, classifier: null, expiresAt: null };
    const x = { ...base, location: { database: "crm", schema: "public", object: "clients" } };
    const exact = { ...FACTS, objects: [{ database: "crm", schema: "public", object: "clients" }] };
    const upper = { ...FACTS, objects: [{ database: "CRM", schema: "PUBLIC", object: "Clients" }] };
    const padded = { ...FACTS, objects: [{ database: "CRM ", schema: "PUBLIC", object: "Clients " }] };
    const one = (database: string, schema: string, object: string) => ({ ...FACTS, objects: [{ database, schema, object }] });
    for (const engine of ["sqlserver", "mysql", "mariadb", "openldap"]) {
      expect(exceptionCoversEvent(x, "p", { ...upper, engine }, [0], now)).toBe(true);
      expect(exceptionCoversEvent(x, "p", { ...upper, engine, objects: [{ database: "CRM", schema: "PUBLIC", object: "orders" }] }, [0], now)).toBe(false);
    }
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas"]) {
      expect(exceptionCoversEvent(x, "p", { ...exact, engine }, [0], now)).toBe(true);
      expect(exceptionCoversEvent(x, "p", { ...upper, engine }, [0], now)).toBe(false);
      expect(exceptionCoversEvent(x, "p", { ...one("Crm", "public", "clients"), engine }, [0], now)).toBe(false);
      expect(exceptionCoversEvent(x, "p", { ...one("crm", "Public", "clients"), engine }, [0], now)).toBe(false);
      expect(exceptionCoversEvent(x, "p", { ...one("crm", "public", "Clients"), engine }, [0], now)).toBe(false);
      expect(exceptionCoversEvent({ ...base, location: { database: "CRM", schema: "PUBLIC", object: "Clients" } }, "p", { ...upper, engine }, [0], now)).toBe(true);
      expect(exceptionCoversEvent({ ...base, location: { object: "?lients" } }, "p", { ...upper, engine }, [0], now)).toBe(true);
      // A field glob of `*` is the only one an event takes, whatever the case rule.
      expect(exceptionCoversEvent({ ...base, location: { object: "clients", field: "*" } }, "p", { ...exact, engine }, [0], now)).toBe(true);
      // Every retained object must be covered with case.
      const two = { ...FACTS, engine, objects: [{ database: "crm", schema: "public", object: "clients" }, { database: "crm", schema: "public", object: "Clients" }] };
      expect(exceptionCoversEvent(x, "p", two, [0], now)).toBe(true);
      expect(exceptionCoversEvent(x, "p", two, [0, 1], now)).toBe(false);
    }
    for (const engine of ["sqlserver", "mysql", "mariadb"]) {
      expect(exceptionCoversEvent(x, "p", { ...padded, engine }, [0], now)).toBe(true);
      expect(exceptionCoversEvent({ ...base, location: { object: "clients " } }, "p", { ...upper, engine }, [0], now)).toBe(true);
      expect(exceptionCoversEvent(x, "p", { ...padded, engine, objects: [{ database: "crm", schema: "public", object: "client " }] }, [0], now)).toBe(false);
    }
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "openldap", "cas"]) {
      const cased = { ...base, location: { database: "CRM", schema: "PUBLIC", object: "Clients" } };
      expect(exceptionCoversEvent(cased, "p", { ...padded, engine }, [0], now)).toBe(false);
      expect(exceptionCoversEvent({ ...base, location: { object: "Clients " } }, "p", { ...upper, engine }, [0], now)).toBe(false);
    }
    // Unknown engine (the target never reported one): never loosened, with case.
    expect(exceptionCoversEvent(x, "p", { ...exact, engine: null }, [0], now)).toBe(true);
    expect(exceptionCoversEvent(x, "p", { ...upper, engine: null }, [0], now)).toBe(false);
    expect(exceptionCoversEvent(x, "p", { ...padded, engine: null }, [0], now)).toBe(false);
  });

  it("`objects` conditions stay case-insensitive on case-sensitive engines (ADR-0054 decision 2)", () => {
    for (const engine of ["postgres", "mongodb", "redis", "valkey", "cas"]) {
      expect(eventMatches({ objects: { database: "crm", object: "clients" } }, { ...FACTS, engine, objects: [{ database: "CRM", object: "Clients" }] })).toEqual([0]);
    }
  });

  it("exceptions: agent, target and database / schema / object location only; never classifier-scoped", () => {
    const now = new Date("2026-09-28T12:00:00Z");
    const base = { policyId: null, agentId: null, targetId: null, classifier: null, location: null, expiresAt: null };
    expect(exceptionCoversEvent({ ...base, targetId: "pg-prod-1" }, "p", FACTS, [0, 1], now)).toBe(true);
    expect(exceptionCoversEvent({ ...base, targetId: "pg-prod-1", expiresAt: now }, "p", FACTS, [0, 1], now)).toBe(false);
    expect(exceptionCoversEvent({ ...base, policyId: "q", targetId: "pg-prod-1" }, "p", FACTS, [0, 1], now)).toBe(false);
    expect(exceptionCoversEvent({ ...base, classifier: "pii.*" }, "p", FACTS, [0, 1], now)).toBe(false);
    expect(exceptionCoversEvent({ ...base, location: { object: "clients" } }, "p", FACTS, [0, 1], now)).toBe(false);
    expect(exceptionCoversEvent({ ...base, location: { object: "clients" } }, "p", FACTS, [0], now)).toBe(true);
    expect(exceptionCoversEvent({ ...base, location: { object: "*", field: "email" } }, "p", FACTS, [0], now)).toBe(false);
    expect(exceptionCoversEvent({ ...base, location: { database: "crm", field: "*" } }, "p", FACTS, [0, 1], now)).toBe(true);
    expect(exceptionCoversEvent({ ...base, location: { database: "*" } }, "p", { ...FACTS, objects: [] }, [], now)).toBe(false);
  });
});

describe("severe events (N1)", () => {
  it("a signature signal, an anomaly or a score above the overflow's maximum", () => {
    const base = { signals: ["shape.full_table_read"], anomaly: false, score: 5 };
    expect(severeEvent(base, null)).toBe(false);
    expect(severeEvent(base, 5)).toBe(false);
    expect(severeEvent(base, 4.99)).toBe(true);
    expect(severeEvent({ ...base, signals: ["signature.copy_to_program"] }, 100)).toBe(true);
    expect(severeEvent({ ...base, anomaly: true }, 100)).toBe(true);
    // Fail-safe: a signature id this console does not know (registered later) is still severe.
    expect(severeEvent({ ...base, signals: ["signature.mysqldump"] }, 100)).toBe(true);
    expect(eventOverflowKey("p", "a", "t", new Date("2026-09-28T14:00:00Z"))).toBe("policy:p|agent:a|target:t|overflow|hour:2026-09-28T14:00:00.000Z");
  });
});

describe("dedup scope", () => {
  it("buckets on the UTC hour of the event", () => {
    expect(eventBucket(new Date("2026-09-28T14:59:59.999Z")).toISOString()).toBe("2026-09-28T14:00:00.000Z");
    expect(eventBucket(new Date("2026-09-28T15:00:00Z")).toISOString()).toBe("2026-09-28T15:00:00.000Z");
  });

  it("builds keys from identifiers and hashes only", () => {
    const key = eventDedupKey({
      policyId: "p1",
      agentId: FACTS.agentId,
      targetId: "pg-prod-1",
      principalKey: "a".repeat(64),
      databaseKey: "-",
      bucket: new Date("2026-09-28T14:00:00Z"),
    });
    expect(key).toBe(`policy:p1|agent:${FACTS.agentId}|target:pg-prod-1|principal:${"a".repeat(64)}|database:-|hour:2026-09-28T14:00:00.000Z`);
  });

  it("principal part: coarse for failed logins only, else the principal key (ADR-0031 decision 1)", () => {
    const net = "n".repeat(64);
    const pk = "a".repeat(64);
    expect(dedupPrincipal({ action: "auth_failure", principalKey: pk, networkHash: net })).toBe(`unknown:${net}`);
    for (const action of ["read", "write", "connect", "ddl", "dcl"]) expect(dedupPrincipal({ action, principalKey: pk, networkHash: net })).toBe(pk);
  });

  it("principal part of an unrecorded account: its own unrecorded: prefix, never the unknown: key of failed logins (P9-E review M1)", () => {
    const net = "n".repeat(64);
    const pk = "a".repeat(64);
    const u = (clientAddr: string | null) => dedupPrincipal({ action: "read", principalKey: pk, networkHash: net, accountNotRecorded: true, clientAddr });
    expect(u("198.51.100.7")).toBe(`unrecorded:${net}`);
    expect(u("local")).toBe("unrecorded:local");
    expect(u(null)).toBe("unrecorded:none");
    expect(u("198.51.100.7")).not.toBe(dedupPrincipal({ action: "auth_failure", principalKey: pk, networkHash: net }));
  });

  it("after a false positive only a new signature signal or a strictly higher score is worse (end-of-phase-6 M1)", () => {
    const fp = { eventScore: 10, eventSignals: ["signature.pg_dump", "shape.full_table_copy"] };
    const e = { score: 10, anomaly: true, signals: ["signature.pg_dump", "shape.full_table_read"] };
    // Same score, a new non-signature signal, above the baseline: still covered by the judgement.
    expect(worseThanFalsePositive(fp, e)).toBe(false);
    expect(worseThanFalsePositive(fp, { ...e, score: 10.01 })).toBe(true);
    expect(worseThanFalsePositive(fp, { ...e, signals: ["signature.copy_to_program"] })).toBe(true);
    expect(worseThanFalsePositive({ eventScore: null, eventSignals: null }, { score: 0, signals: [] })).toBe(false);
    // Anti-splitting: the rows linked since the false positive (this event's included) above the
    // rows the incident had when judged.
    const judged = { ...fp, eventRows: 1000 };
    expect(worseThanFalsePositive(judged, { score: 1, signals: [] }, 1000)).toBe(false);
    expect(worseThanFalsePositive(judged, { score: 1, signals: [] }, 1001)).toBe(true);
    expect(worseThanFalsePositive({ ...fp, eventRows: null }, { score: 1, signals: [] }, 0)).toBe(false);
    expect(worseThanClosed({ ...judged, eventAnomaly: false, status: "false_positive" }, { score: 1, anomaly: false, signals: [] }, 1500)).toBe(true);
    const closed = { ...fp, eventAnomaly: false };
    expect(worseThanClosed({ ...closed, status: "false_positive" }, e)).toBe(false);
    // A resolved incident keeps its wider rule (a new signal or the baseline verdict count).
    expect(worseThanClosed({ ...closed, status: "resolved" }, e)).toBe(true);
    expect(worseThanClosed({ ...closed, status: "open" }, { ...e, score: 1000 })).toBe(false);
  });

  it("picks the most sensitive retained object, the first on a tie", () => {
    expect(dedupObject([0, 1, 2], [1, 5, 5])).toBe(1);
    expect(dedupObject([2, 0], [1, 5, 5])).toBe(2);
    expect(dedupObject([], [])).toBeNull();
  });

  it("merges signals sorted and bounded", () => {
    expect(mergeSignals(["shape.b"], ["shape.a", "shape.b"])).toEqual(["shape.a", "shape.b"]);
    const many = Array.from({ length: 30 }, (_, i) => `shape.s${String(i).padStart(2, "0")}`);
    expect(mergeSignals(many, [])).toHaveLength(16);
  });

  it("keeps signature.* ids first, so truncation never drops them", () => {
    const letters = "abcdefghijklmnopqrst";
    const shapes = [...letters].map((c) => `shape.${c}`);
    const merged = mergeSignals(shapes, ["volume.large_result", "signature.zeta", "signature.pg_dump"]);
    expect(merged).toHaveLength(16);
    expect(merged.slice(0, 2)).toEqual(["signature.pg_dump", "signature.zeta"]);
    expect(merged.slice(2)).toEqual(shapes.slice(0, 14));
    // Alphabetically, `shape.*` sorts before `signature.*`: a plain sort would have kept none.
    expect([...shapes, "signature.pg_dump"].sort().slice(0, 16)).not.toContain("signature.pg_dump");
    expect(mergeSignals(["volume.x", "shape.y"], ["signature.a"])).toEqual(["signature.a", "shape.y", "volume.x"]);
  });
});

describe("overflowed objects (ADR-0053 decision 3)", () => {
  const now = new Date("2026-09-28T12:00:00Z");
  const base = { policyId: null, agentId: null, targetId: null, classifier: null, expiresAt: null };
  const named = { database: "crm", schema: "public", object: "audit_log" };
  const dbStar = { database: "crm", object: "*" };
  const allStar = { database: "*", object: "*" };
  const schemaStar = { database: "crm", schema: "public", object: "*" };
  const flagged = (objects: EventObject[], over: Partial<EventFacts> = {}): EventFacts => ({ ...FACTS, objects, objectsOverflowed: true, ...over });

  it("every `*` object of a flagged event is an overflow `*`, whatever its shape; never without the flag", () => {
    for (const o of [dbStar, allStar, schemaStar]) {
      expect(isOverflowStar({ objectsOverflowed: true }, o)).toBe(true);
      expect(isOverflowStar({ objectsOverflowed: false }, o)).toBe(false);
      expect(isOverflowStar({}, o)).toBe(false);
      expect(isOverflowStar({ objectsOverflowed: null }, o)).toBe(false);
    }
    expect(isOverflowStar({ objectsOverflowed: true }, named)).toBe(false);
    // Redis / Valkey: a real `*` key pattern of a flagged event is treated as an overflow (fail closed).
    expect(isOverflowStar({ objectsOverflowed: true }, { object: "*" })).toBe(true);
    // Only the exact name: a pattern holding `*` is a name.
    expect(isOverflowStar({ objectsOverflowed: true }, { object: "user:*" })).toBe(false);
  });

  it("`objects` conditions: only the database glob applies to an overflow `*`; the database `*` is retained by every pattern", () => {
    const e = flagged([named, dbStar]);
    expect(eventMatches({ objects: { database: "crm", object: "customers" } }, e)).toEqual([1]);
    expect(eventMatches({ objects: { schema: "billing", object: "card*" } }, e)).toEqual([1]);
    expect(eventMatches({ objects: { database: "CRM ", object: "customers" } }, e)).toEqual([1]);
    expect(eventMatches({ objects: { database: "shop", object: "customers" } }, e)).toBeNull();
    expect(eventMatches({ objects: { object: "audit_*" } }, e)).toEqual([0, 1]);
    for (const pattern of [{ database: "shop" }, { database: "shop", schema: "x", object: "y" }, { object: "customers" }] as ObjectPattern[]) {
      expect(eventMatches({ objects: pattern }, flagged([named, allStar]))).toEqual([1]);
    }
    // A `*` with a schema that absorbed the overflow is still any object of its database.
    expect(eventMatches({ objects: { schema: "billing", object: "cards" } }, flagged([schemaStar]))).toEqual([0]);
    // Without the flag, as before: the literal name `*` only.
    const plain = { ...e, objectsOverflowed: undefined };
    expect(eventMatches({ objects: { database: "crm", object: "customers" } }, plain)).toBeNull();
    expect(eventMatches({ objects: { database: "crm", object: "*" } }, plain)).toEqual([0, 1]);
    expect(eventMatches({ objects: { database: "crm", object: "customers" } }, { ...e, objectsOverflowed: false })).toBeNull();
    expect(eventMatches({ objects: { database: "shop" } }, { ...flagged([named, allStar]), objectsOverflowed: undefined })).toBeNull();
    expect(overflowStarMatches({ database: "c?m" }, dbStar)).toBe(true);
  });

  it("min_score and min_sensitivity use the bound; the named values without it", () => {
    const e = flagged([named, dbStar], { sensitivity: 2, score: 4, boundSensitivity: 8, boundScore: 16 });
    expect(eventMatches({ min_score: 10 }, e)).toEqual([0, 1]);
    expect(eventMatches({ min_sensitivity: 8 }, e)).toEqual([0, 1]);
    expect(eventMatches({ min_score: 16.01 }, e)).toBeNull();
    expect(eventMatches({ min_score: 10 }, { ...e, boundScore: undefined, boundSensitivity: undefined })).toBeNull();
    expect(eventMatches({ min_sensitivity: 3 }, { ...FACTS, sensitivity: 2 })).toBeNull();
  });

  it("exceptions cover an overflow `*` only when they cover every object of its database (case rules of ADR-0054)", () => {
    const x = (location: EventExceptionScope["location"]) => ({ ...base, location });
    const e = (objects: EventObject[], engine = "postgres") => flagged(objects, { engine });
    // Named objects as before; the overflow `*` needs a whole-database exception.
    expect(exceptionCoversEvent(x({ database: "crm" }), "p", e([named, dbStar]), [0, 1], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm", schema: "*", object: "*" }), "p", e([dbStar]), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "c*" }), "p", e([dbStar]), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm", object: "audit_*" }), "p", e([named, dbStar]), [0, 1], now)).toBe(false);
    expect(exceptionCoversEvent(x({ database: "crm", object: "audit_*" }), "p", e([named, dbStar]), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm", schema: "public" }), "p", e([schemaStar]), [0], now)).toBe(false);
    expect(exceptionCoversEvent(x({ object: "*" }), "p", e([dbStar]), [0], now)).toBe(true);
    // `\*` selects the literal name only: it covers the literal `*` of an unflagged event, not an overflow.
    expect(exceptionCoversEvent(x({ database: "crm", object: "\\*" }), "p", e([dbStar]), [0], now)).toBe(false);
    expect(exceptionCoversEvent(x({ database: "crm", object: "\\*" }), "p", { ...FACTS, objects: [dbStar] }, [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "shop" }), "p", e([dbStar]), [0], now)).toBe(false);
    // The database `*`: only an exception without a database glob, or with exactly `*`.
    expect(exceptionCoversEvent(x({ database: "*" }), "p", e([allStar]), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ schema: "*" }), "p", e([allStar]), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm" }), "p", e([allStar]), [0], now)).toBe(false);
    expect(exceptionCoversEvent(x({ database: "?" }), "p", e([allStar]), [0], now)).toBe(false);
    expect(exceptionCoversEvent(x({ database: "\\*" }), "p", e([allStar]), [0], now)).toBe(false);
    // Case: with case on PostgreSQL (ADR-0054), without on MySQL; trailing spaces on MySQL only (N1).
    expect(exceptionCoversEvent(x({ database: "CRM" }), "p", e([dbStar], "postgres"), [0], now)).toBe(false);
    expect(exceptionCoversEvent(x({ database: "CRM" }), "p", e([dbStar], "mysql"), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm" }), "p", e([{ database: "crm ", object: "*" }], "mysql"), [0], now)).toBe(true);
    expect(exceptionCoversEvent(x({ database: "crm" }), "p", e([{ database: "crm ", object: "*" }], "postgres"), [0], now)).toBe(false);
    // Agent- or target-scoped exceptions apply as today.
    expect(exceptionCoversEvent({ ...base, targetId: "pg-prod-1", location: null }, "p", e([allStar]), [0], now)).toBe(true);
    expect(exceptionCoversOverflowStar({ field: "*" } as ObjectPattern, dbStar, {})).toBe(true);
  });

  it("an unflagged event (a 0.8.0 agent, or no token) behaves exactly as before, for every condition and exception", () => {
    for (const { pattern, objects, engine, location } of grid()) {
      const old = { ...FACTS, engine, objects };
      for (const variant of [{ ...old, objectsOverflowed: undefined }, { ...old, objectsOverflowed: false }]) {
        expect(eventMatches({ objects: pattern }, variant)).toEqual(literalMatches(pattern, old));
        const idx = objects.map((_, i) => i);
        expect(exceptionCoversEvent({ ...base, location }, "p", variant, idx, now)).toBe(literalCovers(location, old, idx));
      }
    }
  });

  it("fail closed: the flag only adds retained objects and only removes exception coverage", () => {
    for (const { pattern, objects, engine, location } of grid()) {
      const plain = { ...FACTS, engine, objects };
      const marked = { ...plain, objectsOverflowed: true };
      const before = eventMatches({ objects: pattern }, plain) ?? [];
      const after = eventMatches({ objects: pattern }, marked) ?? [];
      for (const i of before) expect(after).toContain(i);
      // Every overflow `*` a pattern's database glob admits is retained.
      objects.forEach((o, i) => {
        if (o.object === "*" && (o.database === "*" || pattern.database === undefined)) expect(after).toContain(i);
      });
      // For the same retained objects, an exception covers a flagged event only if it covers the unflagged one.
      for (const idx of [objects.map((_, i) => i), ...objects.map((_, i) => [i])]) {
        if (exceptionCoversEvent({ ...base, location }, "p", marked, idx, now)) {
          expect(exceptionCoversEvent({ ...base, location }, "p", plain, idx, now)).toBe(true);
        }
      }
    }
  });

  it("the dedup object is chosen on the bound sensitivities the caller passes", () => {
    expect(dedupObject([0, 1], [2, 8])).toBe(1);
    expect(dedupObject([0, 1], [2, 2])).toBe(0);
  });

  it("incident comparisons use the named score only (review H1): the caller passes it, never the bound", () => {
    const e = flagged([named, dbStar], { score: 4, boundScore: 40, signals: [] });
    // Closed incident opened by this flagged event: its recorded score is the named one (4).
    const closed = { status: "resolved", eventScore: e.score, eventSignals: [], eventAnomaly: false };
    expect(worseThanClosed(closed, { score: 10, anomaly: false, signals: [] })).toBe(true);
    expect(worseThanClosed({ ...closed, status: "false_positive" }, { score: 10, anomaly: false, signals: [] })).toBe(true);
    expect(severeEvent({ signals: [], anomaly: false, score: 10 }, e.score)).toBe(true);
    // Had the bound been recorded, the later named-object event would have been hidden.
    expect(worseThanClosed({ ...closed, eventScore: e.boundScore ?? 0 }, { score: 10, anomaly: false, signals: [] })).toBe(false);
  });
});

/** Patterns, object lists, engines and exception locations to cross (small, exhaustive). */
function grid(): { pattern: ObjectPattern; objects: EventObject[]; engine: string; location: EventExceptionScope["location"] }[] {
  const patterns: ObjectPattern[] = [{ database: "crm" }, { object: "*" }, { object: "\\*" }, { database: "shop", object: "c*" }, { schema: "public" }, { database: "*" }, { database: "CRM" }];
  const lists: EventObject[][] = [
    [{ database: "crm", schema: "public", object: "clients" }, { database: "crm", object: "*" }],
    [{ database: "*", object: "*" }],
    [{ database: "crm", schema: "public", object: "*" }],
    [{ database: "shop", object: "carts" }, { database: "shop", object: "*" }, { database: "crm", object: "*" }],
  ];
  const locations: EventExceptionScope["location"][] = [
    null,
    { database: "crm" },
    { database: "*" },
    { object: "*" },
    { object: "\\*" },
    { database: "crm", object: "clients" },
    { schema: "public" },
    { database: "CRM", schema: "*", object: "*" },
    { field: "email" },
  ];
  const out = [];
  for (const pattern of patterns) for (const objects of lists) for (const engine of ["postgres", "mysql"]) for (const location of locations) out.push({ pattern, objects, engine, location });
  return out;
}

/** The rules before ADR-0053, restated with `objectMatches`: every object (`*` included) is a literal name. */
function literalMatches(pattern: ObjectPattern, e: EventFacts): number[] | null {
  const kept = e.objects.map((_, i) => i).filter((i) => objectMatches(pattern, e.objects[i] as EventObject));
  return kept.length > 0 ? kept : null;
}

function literalCovers(location: EventExceptionScope["location"], e: EventFacts, idx: number[]): boolean {
  if (location === null) return true;
  const { field, ...parts } = location;
  if (field !== undefined && field !== "*") return false;
  if (idx.length === 0) return false;
  return idx.every((i) => objectMatches(parts, e.objects[i] as EventObject, exceptionGlobOptions(e.engine)));
}
