import { and, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, agentTargets, findings } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { enqueueJob } from "@/server/jobs";
import { logger } from "@/lib/logger";
import { collectMetrics } from "@/server/metrics";
import { agentTokensHoldWarning, startupFatal, startupWarnings } from "@/server/startup-checks";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, fixtures } from "@/test/helpers";

import { CONSOLE_ACCEPTS, heldAccepts, listedAccepts, RELEASE_ACCEPTS } from "./capabilities";
import { handleEvents, handleFindings, handleHeartbeat, handlePollJobs } from "./handlers";
import { resetTokensHoldWarning, TOKENS_HOLD_WARNING_INTERVAL_MS, tokensHoldMetric, tokensHoldWarningDue } from "./token-hold";

/**
 * DATABASTION_AGENT_TOKENS_HOLD (ADR-0022 decision 8, end-of-phase-9 review L1): a held console lists
 * the tokens of the older release line and still accepts every field it knows.
 */

/** The tokens listed by 0.8.0, 0.8.1 and 0.8.2 (`git show 0.8.2:console/src/server/agent-api/capabilities.ts`). */
const LISTED_BY_0_8 = [
  "access_event.bytes",
  "engine.cas",
  "engine.redis",
  "engine.sqlserver",
  "engine.valkey",
  "job_progress.coverage",
  "target_status.note_labels.2026_10",
  "target_status.note_labels.2026_10_b",
  "target_status.notes",
];

/** Tokens added after 0.8.2, held by `0.8`. */
const ADDED_AFTER_0_8 = [
  "access_event.objects_overflowed",
  "engine.firebird",
  "engine.sqlite",
  "location.altered",
  "object_ref.altered",
  "target_status.name_case",
  "target_status.note_labels.2026_10_c",
  "target_status.note_labels.2026_10_d",
];

/** The tokens listed by 0.9.0 (`git show 0.9.0:console/src/server/agent-api/capabilities.ts`). */
const LISTED_BY_0_9 = [
  "access_event.bytes",
  "access_event.objects_overflowed",
  "engine.cas",
  "engine.redis",
  "engine.sqlserver",
  "engine.valkey",
  "job_progress.coverage",
  "location.altered",
  "object_ref.altered",
  "target_status.name_case",
  "target_status.note_labels.2026_10",
  "target_status.note_labels.2026_10_b",
  "target_status.note_labels.2026_10_c",
  "target_status.notes",
];

/** Tokens added after 0.9.0, held by `0.9` (P10-E: SQLite, then Firebird with its label revision). */
const ADDED_AFTER_0_9 = ["engine.firebird", "engine.sqlite", "target_status.note_labels.2026_10_d"];

const held = { DATABASTION_AGENT_TOKENS_HOLD: "0.8" };
const held09 = { DATABASTION_AGENT_TOKENS_HOLD: "0.9" };
/** A release line no console knows (fatal at startup). */
const UNKNOWN_LINE = "0.10";

describe("token hold: listing (unit)", () => {
  it("lists every token when unset or empty (today's behaviour)", () => {
    expect(listedAccepts({})).toEqual([...CONSOLE_ACCEPTS]);
    expect(listedAccepts({ DATABASTION_AGENT_TOKENS_HOLD: "" })).toEqual([...CONSOLE_ACCEPTS]);
    expect(heldAccepts({})).toEqual([]);
  });

  it("0.8 lists exactly the 0.8.x list and holds the tokens added since", () => {
    expect(listedAccepts(held)).toEqual(LISTED_BY_0_8);
    expect(heldAccepts(held)).toEqual(ADDED_AFTER_0_8);
    expect([...listedAccepts(held), ...heldAccepts(held)].sort()).toEqual([...CONSOLE_ACCEPTS]);
  });

  it("never holds an engine token of 0.8 nor a token of 0.8 or earlier", () => {
    for (const t of LISTED_BY_0_8.filter((t) => t.startsWith("engine."))) expect(listedAccepts(held)).toContain(t);
    expect(heldAccepts(held).filter((t) => LISTED_BY_0_8.includes(t))).toEqual([]);
  });

  it("0.9 lists exactly the 0.9.0 list and holds the SQLite and Firebird tokens (P10-E: a 0.9 replica refuses their values)", () => {
    expect(listedAccepts(held09)).toEqual(LISTED_BY_0_9);
    expect(heldAccepts(held09)).toEqual(ADDED_AFTER_0_9);
    expect([...listedAccepts(held09), ...heldAccepts(held09)].sort()).toEqual([...CONSOLE_ACCEPTS]);
    // Each release line lists at least what the previous one listed.
    for (const t of LISTED_BY_0_8) expect(listedAccepts(held09)).toContain(t);
  });

  it("holds engine.firebird and target_status.note_labels.2026_10_d together, on every release line (ADR-0060, P10-E)", () => {
    for (const env of [held, held09]) {
      expect(heldAccepts(env)).toContain("engine.firebird");
      expect(heldAccepts(env)).toContain("target_status.note_labels.2026_10_d");
      expect(listedAccepts(env)).not.toContain("engine.firebird");
      expect(listedAccepts(env)).not.toContain("target_status.note_labels.2026_10_d");
    }
    expect(listedAccepts({})).toContain("engine.firebird");
    expect(listedAccepts({})).toContain("target_status.note_labels.2026_10_d");
  });

  it("every release list is a sorted, duplicate-free subset of CONSOLE_ACCEPTS and a valid CapabilityList", () => {
    for (const [release, list] of Object.entries(RELEASE_ACCEPTS)) {
      expect([...list], release).toEqual([...new Set(list)].sort());
      for (const t of list) expect(CONSOLE_ACCEPTS as readonly string[], `${release} ${t}`).toContain(t);
      expect(validateSchema("CapabilityList", [...list]).ok).toBe(true);
    }
  });

  it("an invalid value seen at run time lists the oldest known set (fail closed)", () => {
    expect(listedAccepts({ DATABASTION_AGENT_TOKENS_HOLD: UNKNOWN_LINE })).toEqual(LISTED_BY_0_8);
  });
});

describe("token hold: startup checks (unit)", () => {
  const env = (e: Record<string, string>) => e as unknown as NodeJS.ProcessEnv;

  it("refuses to start on an unknown value, in every environment, without echoing it", () => {
    for (const NODE_ENV of ["production", "development", "test"]) {
      const fatal = startupFatal(env({ NODE_ENV, DATABASTION_AGENT_TOKENS_HOLD: "0.8.2", DATABASTION_ENCRYPTION_KEY: "k".repeat(44) }));
      expect(fatal).toContain("DATABASTION_AGENT_TOKENS_HOLD must be unset or one of: 0.8, 0.9");
      expect(fatal).toContain("Refusing to start");
      expect(fatal).not.toContain("0.8.2");
    }
  });

  it("starts with the hold unset or valid, and warns while it is set", () => {
    const base = { NODE_ENV: "production", DATABASTION_ENCRYPTION_KEY: "k".repeat(44) };
    expect(startupFatal(env({ ...base, ...held }))).toBeNull();
    expect(startupFatal(env(base))).toBeNull();
    expect(agentTokensHoldWarning(env(base))).toBeNull();
    const warning = agentTokensHoldWarning(env({ ...base, ...held }));
    expect(warning).toContain("DATABASTION_AGENT_TOKENS_HOLD=0.8");
    for (const t of ADDED_AFTER_0_8) expect(warning).toContain(t);
    expect(startupWarnings(env({ ...base, ...held }))).toContain(warning);
    expect(startupFatal(env({ ...base, ...held09 }))).toBeNull();
    const warning09 = agentTokensHoldWarning(env({ ...base, ...held09 }));
    expect(warning09).toContain("DATABASTION_AGENT_TOKENS_HOLD=0.9");
    expect(warning09).toContain("not engine.firebird, engine.sqlite, target_status.note_labels.2026_10_d;");
    expect(warning09).toContain("(ADR-0059, ADR-0060)");
  });
});

describe("token hold: recurring signals (unit, review L1)", () => {
  it("warns at the first call while held, then at most once an hour per process", () => {
    resetTokensHoldWarning();
    const t0 = 1_000_000_000_000;
    const first = tokensHoldWarningDue(t0, held);
    expect(first).toContain("DATABASTION_AGENT_TOKENS_HOLD=0.8");
    expect(first).toContain("ADR-0053, ADR-0055, ADR-0056, ADR-0059, ADR-0060");
    expect(tokensHoldWarningDue(t0 + 1, held)).toBeNull();
    expect(tokensHoldWarningDue(t0 + TOKENS_HOLD_WARNING_INTERVAL_MS - 1, held)).toBeNull();
    expect(tokensHoldWarningDue(t0 + TOKENS_HOLD_WARNING_INTERVAL_MS, held)).toBe(first);
    expect(tokensHoldWarningDue(t0 + TOKENS_HOLD_WARNING_INTERVAL_MS + 1, held)).toBeNull();
    // A clock stepped back does not silence it.
    expect(tokensHoldWarningDue(t0, held)).toBe(first);
    resetTokensHoldWarning();
  });

  it("never warns when unset, empty or invalid (invalid is fatal at startup)", () => {
    resetTokensHoldWarning();
    for (const v of [undefined, "", UNKNOWN_LINE]) expect(tokensHoldWarningDue(Date.now(), { DATABASTION_AGENT_TOKENS_HOLD: v })).toBeNull();
  });

  it("the gauge series: 1 with the release line while held, 0 without label when unset", () => {
    expect(tokensHoldMetric(held)).toEqual({ value: 1, labels: { release: "0.8" } });
    expect(tokensHoldMetric({})).toEqual({ value: 0, labels: {} });
    expect(tokensHoldMetric({ DATABASTION_AGENT_TOKENS_HOLD: "" })).toEqual({ value: 0, labels: {} });
    expect(tokensHoldMetric(held09)).toEqual({ value: 1, labels: { release: "0.9" } });
    expect(tokensHoldMetric({ DATABASTION_AGENT_TOKENS_HOLD: UNKNOWN_LINE })).toEqual({ value: 1, labels: { release: "invalid" } });
  });
});

// ------------------------------------------------------------------------------------- DB

type Auth = { agentId: string; secret: string };

function fixture<T>(name: string): T {
  const kind = name.split(".")[0] as string;
  const found = fixtures("valid", kind).find(([f]) => f === name);
  if (!found) throw new Error(`no fixture ${name}`);
  return structuredClone(found[1]) as T;
}

type Hb = { targets: { target_id: string; name_case?: unknown }[] };
type Events = { batch_id: string; events: { target_id: string; objects_overflowed?: boolean; objects: unknown[] }[] };
type Findings = { batch_id: string; job_id: string; findings: { target_id: string; location: { altered?: string[] } }[] };

describe.skipIf(!hasDb)("token hold: a held console still accepts and stores every field (PostgreSQL)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => teardown?.());
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  const heartbeat = (auth: Auth, body: unknown) => handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }));

  it("answers a heartbeat with the 0.8 list, and with the full list once the hold is removed", async () => {
    const auth = await enroll();
    const body = fixture<Hb>("HeartbeatRequest.name-case-sqlserver.json");
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.8");
    let res = await heartbeat(auth, body);
    expect(res.status).toBe(200);
    let out = (await res.json()) as { accepts: string[] };
    expect(validateSchema("HeartbeatResponse", out).ok).toBe(true);
    expect(out.accepts).toEqual(LISTED_BY_0_8);
    // The held field is still accepted and stored.
    for (const t of body.targets) {
      const [row] = await getDb()
        .select()
        .from(agentTargets)
        .where(and(eq(agentTargets.agentId, auth.agentId), eq(agentTargets.targetId, t.target_id)));
      expect(row?.nameCase, t.target_id).toEqual(t.name_case);
    }
    vi.unstubAllEnvs();
    res = await heartbeat(auth, body);
    out = (await res.json()) as { accepts: string[] };
    expect(out.accepts).toEqual([...CONSOLE_ACCEPTS]);
  });

  it("exposes the hold on /metrics and logs it from the heartbeat path at most once an hour", async () => {
    expect(await collectMetrics(getDb())).toMatch(/^databastion_console_agent_tokens_hold 0$/m);
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.8");
    expect(await collectMetrics(getDb())).toMatch(/^databastion_console_agent_tokens_hold\{release="0\.8"\} 1$/m);
    resetTokensHoldWarning();
    const warn = vi.spyOn(logger, "warn");
    const auth = await enroll();
    const body = fixture<Hb>("HeartbeatRequest.name-case-sqlserver.json");
    expect((await heartbeat(auth, body)).status).toBe(200);
    expect((await heartbeat(auth, body)).status).toBe(200);
    const holdWarnings = warn.mock.calls.filter(([m]) => typeof m === "string" && m.startsWith("DATABASTION_AGENT_TOKENS_HOLD=0.8"));
    expect(holdWarnings).toHaveLength(1);
    resetTokensHoldWarning();
  });

  it("accepts the 2026_10_c note label while holding its token", async () => {
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.8");
    const auth = await enroll();
    const res = await heartbeat(auth, fixture("HeartbeatRequest.sqlserver-labels-2026-10-c.json"));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { accepts: string[] }).accepts).not.toContain("target_status.note_labels.2026_10_c");
  });

  it("0.9: does not list engine.sqlite, yet accepts and stores a sqlite heartbeat (P10-E)", async () => {
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.9");
    const auth = await enroll();
    const body = fixture<{ targets: { target_id: string; engine: string }[] }>("HeartbeatRequest.sqlite.json");
    const res = await heartbeat(auth, body);
    expect(res.status).toBe(200);
    const out = (await res.json()) as { accepts: string[] };
    expect(out.accepts).toEqual(LISTED_BY_0_9);
    const rows = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
    expect(rows.filter((r) => r.engine === "sqlite").length).toBe(body.targets.filter((t) => t.engine === "sqlite").length);
  });

  it("0.8 and 0.9: do not list engine.firebird nor 2026_10_d, yet accept and store a firebird heartbeat with its labels (P10-E)", async () => {
    for (const [hold, listed] of [
      ["0.8", LISTED_BY_0_8],
      ["0.9", LISTED_BY_0_9],
    ] as const) {
      vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", hold);
      for (const name of ["HeartbeatRequest.firebird.json", "HeartbeatRequest.firebird-labels-2026-10-d.json"]) {
        const auth = await enroll();
        const body = fixture<{ targets: { target_id: string; engine: string; notes?: unknown[] }[] }>(name);
        const res = await heartbeat(auth, body);
        expect(res.status, `${hold} ${name}`).toBe(200);
        const out = (await res.json()) as { accepts: string[] };
        expect(out.accepts, `${hold} ${name}`).toEqual(listed);
        const rows = await getDb().select().from(agentTargets).where(eq(agentTargets.agentId, auth.agentId));
        const fb = body.targets.filter((t) => t.engine === "firebird");
        expect(rows.filter((r) => r.engine === "firebird").length, `${hold} ${name}`).toBe(fb.length);
        for (const t of fb) expect(rows.find((r) => r.targetId === t.target_id)?.notes ?? null).toEqual(t.notes ?? null);
      }
      vi.unstubAllEnvs();
    }
  });

  it("stores objects_overflowed and ObjectRef.altered of an events batch", async () => {
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.8");
    const auth = await enroll();
    const batch = fixture<Events>("EventsBatch.objects-overflowed-altered.json");
    const targets = [...new Set(batch.events.map((e) => e.target_id))].map((target_id) => ({
      target_id,
      engine: "postgres",
      reachable: true,
      audit_level: "full",
      audit_source: "pgaudit",
    }));
    const hb = {
      ts: new Date().toISOString(),
      agent_version: "0.9.0",
      uptime_s: 1,
      classifiers_version: "2026.09.1",
      connectors: ["postgres"],
      targets,
      detected_targets: [],
      spool: { bytes: 0, max_bytes: 1024, batches: 0 },
    };
    expect((await heartbeat(auth, hb)).status).toBe(200);
    // Recent timestamps: the fixture's fixed dates may be past the retention.
    const now = new Date().toISOString();
    for (const e of batch.events as Record<string, unknown>[]) {
      e.ts = now;
      delete e.ts_last;
    }
    const res = await handleEvents(agentRequest("POST", "/events", { auth, body: batch }));
    expect(res.status).toBe(202);
    const rows = await getDb().select().from(accessEvents).where(eq(accessEvents.agentId, auth.agentId)).orderBy(accessEvents.itemIndex);
    expect(rows).toHaveLength(batch.events.length);
    rows.forEach((r, i) => {
      const e = batch.events[i] as Events["events"][number];
      expect(r.objects).toEqual(e.objects);
      expect(r.objectsOverflowed).toBe(e.objects_overflowed === true ? true : null);
    });
    expect(rows.some((r) => r.objectsOverflowed === true)).toBe(true);
    expect(JSON.stringify(rows.map((r) => r.objects))).toContain('"altered"');
  });

  it("stores Location.altered of a findings batch", async () => {
    vi.stubEnv("DATABASTION_AGENT_TOKENS_HOLD", "0.8");
    const auth = await enroll();
    const body = fixture<Findings>("FindingsBatch.postgres-altered.json");
    const targetIds = [...new Set(body.findings.map((f) => f.target_id))];
    const hb = {
      ts: new Date().toISOString(),
      agent_version: "0.9.0",
      uptime_s: 1,
      classifiers_version: "2026.09.1",
      connectors: ["postgres"],
      targets: targetIds.map((target_id) => ({ target_id, engine: "postgres", reachable: true, audit_level: "limited" })),
      detected_targets: [],
      spool: { bytes: 0, max_bytes: 1024, batches: 0 },
    };
    expect((await heartbeat(auth, hb)).status).toBe(200);
    expect(targetIds).toHaveLength(1);
    const jobId = await enqueueJob(getDb(), {
      agentId: auth.agentId,
      type: "discovery.scan",
      targetId: targetIds[0] as string,
      classifiersVersion: "2026.09.1",
      params: { sample_rows: 200, max_duration_s: 900 },
    });
    expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
    body.job_id = jobId;
    const res = await handleFindings(agentRequest("POST", "/findings", { auth, body }));
    expect(res.status).toBe(202);
    const rows = await getDb().select().from(findings).where(eq(findings.agentId, auth.agentId));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.some((r) => Array.isArray(r.altered) && r.altered.length > 0)).toBe(true);
  });
});
