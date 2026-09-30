import { describe, expect, it } from "vitest";

import { CLASSIFIER_REGISTRY } from "@/generated/protocol/classifiers.gen";

import {
  isRegisteredClassifier,
  isRegisteredClassifiersVersion,
  registeredClassifiers,
  registeredClassifiersVersions,
} from "./classifiers";
import { checkSemantics, scanJobRegistryDetails, validateSchema, type Schemas } from "./validate";

const PROTO_KEYS = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf", "prototype"];

describe("classifier registry lookups", () => {
  it("knows exactly the generated versions and ids", () => {
    expect(registeredClassifiersVersions()).toEqual(Object.keys(CLASSIFIER_REGISTRY));
    for (const [version, ids] of Object.entries(CLASSIFIER_REGISTRY)) {
      expect(isRegisteredClassifiersVersion(version)).toBe(true);
      expect([...(registeredClassifiers(version) ?? [])]).toEqual([...ids]);
      for (const id of ids) expect(isRegisteredClassifier(version, id)).toBe(true);
    }
    expect(isRegisteredClassifier("2026.09.1", "pii.email")).toBe(true);
  });

  it("rejects unknown versions and ids", () => {
    expect(isRegisteredClassifiersVersion("2026.10.1")).toBe(false);
    expect(registeredClassifiers("2026.10.1")).toBeNull();
    expect(isRegisteredClassifier("2026.09.1", "pii.unknown")).toBe(false);
    expect(isRegisteredClassifier("2026.10.1", "pii.email")).toBe(false);
    expect(isRegisteredClassifiersVersion(undefined)).toBe(false);
    expect(isRegisteredClassifiersVersion(20260901)).toBe(false);
    expect(isRegisteredClassifier("2026.09.1", 1)).toBe(false);
  });

  it.each(PROTO_KEYS)("never resolves %s through the prototype, as a version or as an id", (key) => {
    expect(isRegisteredClassifiersVersion(key)).toBe(false);
    expect(registeredClassifiers(key)).toBeNull();
    expect(isRegisteredClassifier("2026.09.1", key)).toBe(false);
    expect(isRegisteredClassifier("2026.09.1", `pii.${key}`)).toBe(false);
    expect(isRegisteredClassifier(key, key)).toBe(false);
  });
});

describe("outgoing scan jobs (checkSemantics on Job / JobList)", () => {
  const scanJob = (classifiersVersion: string, classifiers?: string[]) =>
    ({
      job_id: "01890a5d-ac96-774b-bcce-b302099a8057",
      type: "discovery.scan",
      created_at: "2026-09-28T10:00:00Z",
      target_id: "pg-prod-1",
      classifiers_version: classifiersVersion,
      params: { sample_rows: 200, max_duration_s: 900, ...(classifiers ? { classifiers } : {}) },
    }) as Schemas["Job"];

  it("accepts a registered version and registered ids", () => {
    const list = { jobs: [scanJob("2026.09.1"), scanJob("2026.09.1", ["pii.email", "pii.iban"])] };
    expect(validateSchema("JobList", list).ok).toBe(true);
    expect(checkSemantics("JobList", list).ok).toBe(true);
    expect(checkSemantics("Job", scanJob("2026.09.1", ["pii.email"])).ok).toBe(true);
  });

  it("rejects an unregistered version (enum on classifiers_version)", () => {
    const list = { jobs: [scanJob("2026.09.1"), scanJob("2026.10.1", ["pii.email"])] };
    expect(validateSchema("JobList", list).ok).toBe(true);
    expect(checkSemantics("JobList", list)).toEqual({
      ok: false,
      details: [{ pointer: "/jobs/1/classifiers_version", keyword: "enum" }],
    });
    expect(checkSemantics("Job", scanJob("2026.10.1"))).toEqual({
      ok: false,
      details: [{ pointer: "/classifiers_version", keyword: "enum" }],
    });
  });

  it("rejects unknown and prototype-like ids (enum on the id)", () => {
    const job = scanJob("2026.09.1", ["pii.email", "pii.unknown", "x.__proto__", "x.constructor"]);
    expect(validateSchema("Job", job).ok).toBe(true);
    expect(checkSemantics("Job", job)).toEqual({
      ok: false,
      details: [
        { pointer: "/params/classifiers/1", keyword: "enum" },
        { pointer: "/params/classifiers/2", keyword: "enum" },
        { pointer: "/params/classifiers/3", keyword: "enum" },
      ],
    });
  });

  it("ignores job types without a classifier set", () => {
    const reload = { job_id: "01890a5d-ac96-774b-bcce-b302099a8057", type: "agent.config_reload", created_at: "2026-09-28T10:00:00Z", params: {} } as unknown as Schemas["Job"];
    expect(scanJobRegistryDetails(reload, "")).toEqual([]);
  });
});
