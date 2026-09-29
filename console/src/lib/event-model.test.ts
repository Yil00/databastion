import { describe, expect, it } from "vitest";

import { registeredClassifiers, registeredClassifiersVersions } from "@/lib/protocol/classifiers";

import {
  ANOMALY_MIN_ROWS,
  BASELINE_WARMUP,
  CLASSIFIER_WEIGHTS,
  classifierWeight,
  dedupObject,
  EMPTY_BASELINE,
  eventBucket,
  eventDedupKey,
  eventMatches,
  eventOverflowKey,
  eventScore,
  exceptionCoversEvent,
  mergeSignals,
  objectSensitivity,
  parseEventConditions,
  SENSITIVITY_CAP,
  severeEvent,
  updateBaseline,
  baselineVerdict,
  type BaselineState,
  type EventFacts,
} from "./event-model";
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
