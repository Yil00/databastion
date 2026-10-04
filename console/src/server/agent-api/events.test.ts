import { and, eq, sql } from "drizzle-orm";
import { Client } from "pg";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { accessEvents, auditLog, eventsBatches, securityEvents } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { canonicalJson } from "@/server/findings";
import {
  BACKPRESSURE_RETRY_AFTER_S,
  DEFAULT_EVENTS_RETENTION_DAYS,
  eventStats,
  MAX_PENDING_EVENTS_PER_AGENT,
  pendingEventsOver,
  eventsBatchSha256,
  eventsRetentionDays,
  ingestEvents,
  principalKey,
  purgeAccessEvents,
} from "@/server/events";
import { integrityWriteBudget } from "@/server/integrity";
import { collectMetrics } from "@/server/metrics";
import { setPolicyJobSender } from "@/server/policy-queue";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, expectConformingError, fixtures, uuidv7 } from "@/test/helpers";

import { failuresPerAgent } from "./auth";
import { eventsPerAgent, eventsRequestsPerAgent, handleEvents, handleHeartbeat } from "./handlers";
import { MAX_FUTURE_SKEW_MS } from "./pipeline";

type Auth = { agentId: string; secret: string };
type Batch = { batch_id: string; events: Record<string, unknown>[] };

const HEARTBEAT = {
  ts: new Date().toISOString(),
  agent_version: "0.1.0",
  uptime_s: 12,
  classifiers_version: "2026.09.1",
  connectors: ["postgres", "mysql", "mongodb", "openldap", "cas"],
  targets: [
    { target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "full", audit_source: "pgaudit" },
    { target_id: "mysql-crm", engine: "mysql", reachable: true, audit_level: "partial" },
    { target_id: "mongo-app", engine: "mongodb", reachable: true, audit_level: "limited" },
    { target_id: "ldap-main", engine: "openldap", reachable: true, audit_level: "full" },
    { target_id: "cas-prod", engine: "cas", reachable: true, audit_level: "partial", audit_source: "cas_audit_log" },
  ],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

const PG_DUMP = {
  target_id: "pg-prod-1",
  ts: "2026-09-28T14:02:11Z",
  principal: { db_user: "backup", client_addr: "192.0.2.14", application: "pg_dump" },
  action: "read",
  objects: [{ database: "crm", schema: "public", object: "clients" }],
  rows: 1250000,
  signals: ["signature.pg_dump", "shape.full_table_copy"],
  source: "pgaudit",
  aggregated_count: 1,
};

const batch = (events: Record<string, unknown>[] = [PG_DUMP]): Batch => ({ batch_id: uuidv7(), events });
const post = (auth: Auth, body: unknown) => handleEvents(agentRequest("POST", "/events", { auth, body }));

async function agentWithTargets(): Promise<Auth> {
  const auth = await enroll();
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body: HEARTBEAT }))).status).toBe(200);
  return auth;
}

async function storedEvents(agentId: string) {
  return getDb().select().from(accessEvents).where(eq(accessEvents.agentId, agentId)).orderBy(accessEvents.itemIndex);
}

async function integrityRows(agentId: string, kind: string) {
  return getDb()
    .select()
    .from(securityEvents)
    .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, kind)));
}

/** Every row of every table of the console schema, as JSON text (I2 dump, like #45). */
async function databaseDump(): Promise<string> {
  const tables = await getDb().execute<{ t: string }>(
    sql`select table_name as t from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE' order by 1`,
  );
  const parts: string[] = [];
  for (const { t } of tables.rows) {
    const res = await getDb().execute(sql.raw(`select coalesce(string_agg(row_to_json(x)::text, ' '), '') as s from public."${t}" x`));
    parts.push(String(res.rows[0]?.s));
  }
  return parts.join(" ");
}

describe.skipIf(!hasDb)("POST /events (PostgreSQL)", () => {
  let teardown: () => Promise<void>;

  beforeAll(async () => {
    // The contract fixtures carry fixed dates: a long retention keeps them acceptable over time.
    process.env.DATABASTION_EVENTS_RETENTION_DAYS = "3650";
    teardown = await setupTestDatabase();
    await adminUser();
  });
  afterAll(async () => teardown?.());
  beforeEach(() => {
    failuresPerAgent.clear();
    integrityWriteBudget.clear();
    eventsPerAgent.clear();
    eventsRequestsPerAgent.clear();
  });
  afterEach(() => setPolicyJobSender(null));

  describe("contract fixtures", () => {
    it.each(fixtures("valid", "EventsBatch"))("accepts %s and stores exactly the contract fields", async (_name, body) => {
      const auth = await agentWithTargets();
      const res = await post(auth, body);
      expect(res.status).toBe(202);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const ack = (await res.json()) as unknown;
      expect(validateSchema("BatchAck", ack).ok).toBe(true);
      const b = body as Batch;
      expect(ack).toEqual({ batch_id: b.batch_id, duplicate: false });
      const rows = await storedEvents(auth.agentId);
      expect(rows).toHaveLength(b.events.length);
      rows.forEach((r, i) => {
        const e = b.events[i] as typeof PG_DUMP & { ts_last?: string; principal: Record<string, string> };
        expect(r.targetId).toBe(e.target_id);
        expect(r.ts.toISOString()).toBe(new Date(e.ts).toISOString());
        expect(r.dbUser).toBe(e.principal.db_user ?? null);
        expect(r.dbUserFingerprint).toBe(e.principal.db_user_fingerprint ?? null);
        expect(r.principalKey).toBe(principalKey(e.principal));
        expect(r.objects).toEqual(e.objects);
        expect(r.signals).toEqual(e.signals ?? []);
        expect(r.rows).toBe(e.rows ?? null);
        expect(r.bytes).toBe((e as { bytes?: number }).bytes ?? null);
        expect(r.evaluatedAt).toBeNull();
      });
      const [record] = await getDb().select().from(eventsBatches).where(eq(eventsBatches.agentId, auth.agentId));
      expect(record?.bodySha256).toBe(eventsBatchSha256(b as never));
      expect(record?.eventsCount).toBe(b.events.length);
    });

    it.each(fixtures("invalid", "EventsBatch"))("rejects %s with 400, stores nothing, raises an integrity event", async (_name, body) => {
      const auth = await agentWithTargets();
      const res = await post(auth, body);
      expect(res.status).toBe(400);
      const err = await expectConformingError(res, body);
      expect(err.code).toBe("invalid_request");
      expect(Array.isArray(err.details)).toBe(true);
      expect(await storedEvents(auth.agentId)).toHaveLength(0);
      expect(await getDb().select().from(eventsBatches).where(eq(eventsBatches.agentId, auth.agentId))).toHaveLength(0);
      const events = await integrityRows(auth.agentId, "agent.batch_rejected");
      expect(events).toHaveLength(1);
      expect(events[0]?.details).toMatchObject({ endpoint: "events", status: 400 });
    });
  });

  describe("idempotency on (agent_id, batch_id)", () => {
    it("acknowledges a replay (same content, any key order) without storing it again", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, b)).status).toBe(202);
      const reordered = JSON.parse(canonicalJson({ events: b.events, batch_id: b.batch_id })) as unknown;
      const res = await post(auth, reordered);
      expect(res.status).toBe(202);
      expect(await res.json()).toEqual({ batch_id: b.batch_id, duplicate: true });
      expect(await storedEvents(auth.agentId)).toHaveLength(1);
    });

    it("answers 409 batch_conflict on another content, with an integrity event", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, b)).status).toBe(202);
      const res = await post(auth, { ...b, events: [{ ...PG_DUMP, rows: 1 }] });
      expect(res.status).toBe(409);
      expect((await expectConformingError(res, {})).code).toBe("batch_conflict");
      expect(await storedEvents(auth.agentId)).toHaveLength(1);
      expect(await integrityRows(auth.agentId, "agent.batch_conflict")).toHaveLength(1);
    });

    it("keeps no record of a rejected batch: its id can be used again", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, { ...b, events: [{ ...PG_DUMP, target_id: "pg-elsewhere" }] })).status).toBe(404);
      expect((await post(auth, b)).status).toBe(202);
    });

    it("the same batch id of another agent is another batch", async () => {
      const a = await agentWithTargets();
      const b = await agentWithTargets();
      const body = batch();
      expect((await post(a, body)).status).toBe(202);
      expect(await (await post(b, body)).json()).toEqual({ batch_id: body.batch_id, duplicate: false });
    });
  });

  describe("console-side checks", () => {
    it("404 with item pointers for targets the agent does not own (integrity event)", async () => {
      const auth = await agentWithTargets();
      const res = await post(auth, batch([PG_DUMP, { ...PG_DUMP, target_id: "pg-elsewhere" }, { ...PG_DUMP, target_id: "other" }]));
      expect(res.status).toBe(404);
      const err = await expectConformingError(res, {});
      expect(err).toMatchObject({
        code: "not_found",
        details: [
          { pointer: "/events/1/target_id", keyword: "notFound" },
          { pointer: "/events/2/target_id", keyword: "notFound" },
        ],
      });
      expect(await storedEvents(auth.agentId)).toHaveLength(0);
      const [ev] = await integrityRows(auth.agentId, "agent.foreign_target");
      expect(ev?.details).toMatchObject({ endpoint: "events", status: 404, pointer: "/events/1/target_id" });
    });

    it("400 formatMinimum when ts_last < ts", async () => {
      const auth = await agentWithTargets();
      const res = await post(auth, batch([PG_DUMP, { ...PG_DUMP, ts_last: "2026-09-28T14:00:00Z", aggregated_count: 2 }]));
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ details: [{ pointer: "/events/1/ts_last", keyword: "formatMinimum" }] });
      expect(await storedEvents(auth.agentId)).toHaveLength(0);
    });

    it("400 formatMaximum for a timestamp more than 5 min in the future", async () => {
      const auth = await agentWithTargets();
      const future = new Date(Date.now() + MAX_FUTURE_SKEW_MS + 60_000).toISOString();
      const soon = new Date(Date.now() + MAX_FUTURE_SKEW_MS - 60_000).toISOString();
      const res = await post(auth, batch([{ ...PG_DUMP, ts: soon }, { ...PG_DUMP, ts: future }]));
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ details: [{ pointer: "/events/1/ts", keyword: "formatMaximum" }] });
      expect((await integrityRows(auth.agentId, "agent.batch_rejected"))[0]?.details).toMatchObject({ endpoint: "events" });
      expect((await post(auth, batch([{ ...PG_DUMP, ts: soon }]))).status).toBe(202);
    });

    it("400 formatMinimum for events older than the retention period, without an integrity event (L1)", async () => {
      const auth = await agentWithTargets();
      const old = new Date(Date.now() - 100 * 24 * 3600_000).toISOString();
      const b = batch([{ ...PG_DUMP, ts: new Date().toISOString() }, { ...PG_DUMP, ts: old }]);
      expect(await ingestEvents(getDb(), auth.agentId, b as never, Date.now(), 90)).toEqual({
        kind: "expired",
        details: [{ pointer: "/events/1/ts", keyword: "formatMinimum" }],
      });
      process.env.DATABASTION_EVENTS_RETENTION_DAYS = "90";
      try {
        const res = await post(auth, b);
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ details: [{ pointer: "/events/1/ts", keyword: "formatMinimum" }] });
      } finally {
        process.env.DATABASTION_EVENTS_RETENTION_DAYS = "3650";
      }
      expect(await integrityRows(auth.agentId, "agent.batch_rejected")).toHaveLength(0);
      expect(await storedEvents(auth.agentId)).toHaveLength(0);
    });

    it("flags events of a target no longer reported or with Audit disabled (L4)", async () => {
      const auth = await agentWithTargets();
      await getDb().execute(sql`update agent_targets set present = false where agent_id = ${auth.agentId} and target_id = 'mysql-crm'`);
      await getDb().execute(sql`insert into audit_configs (agent_id, target_id, enabled, aggregation_window_s, poll_interval_s)
        values (${auth.agentId}, 'mongo-app', false, 60, 10)`);
      const before = eventStats.unexpectedTarget;
      const other = (target_id: string) => ({ ...PG_DUMP, target_id });
      expect((await post(auth, batch([PG_DUMP, other("mysql-crm"), other("mongo-app")]))).status).toBe(202);
      expect((await storedEvents(auth.agentId)).map((r) => r.unexpectedTarget)).toEqual([false, true, true]);
      expect(eventStats.unexpectedTarget - before).toBe(2);
    });

    it("429 + Retry-After while the agent's backlog of unevaluated events is too large (M2)", async () => {
      const auth = await agentWithTargets();
      expect((await post(auth, batch())).status).toBe(202);
      await getDb().execute(sql`insert into access_events (agent_id, target_id, batch_id, item_index, ts, principal_key, db_user, action, objects, source, aggregated_count)
        select ${auth.agentId}, 'pg-prod-1', gen_random_uuid(), 0, now(), ${"3".repeat(64)}, 'x', 'connect', '[]'::jsonb, 'pgaudit', 1
        from generate_series(1, ${MAX_PENDING_EVENTS_PER_AGENT})`);
      expect(await pendingEventsOver(getDb(), auth.agentId)).toBe(true);
      const res = await post(auth, batch());
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe(String(BACKPRESSURE_RETRY_AFTER_S));
      expect((await expectConformingError(res, {})).code).toBe("rate_limited");
      const other = await agentWithTargets();
      expect((await post(other, batch())).status).toBe(202);
    });

    /** Fills the agent's backlog past the back-pressure threshold (events not evaluated yet). */
    async function fillBacklog(agentId: string): Promise<void> {
      await getDb().execute(sql`insert into access_events (agent_id, target_id, batch_id, item_index, ts, principal_key, db_user, action, objects, source, aggregated_count)
        select ${agentId}, 'pg-prod-1', gen_random_uuid(), 0, now(), ${"3".repeat(64)}, 'x', 'connect', '[]'::jsonb, 'pgaudit', 1
        from generate_series(1, ${MAX_PENDING_EVENTS_PER_AGENT})`);
    }

    it("answers 429 to the replay of an accepted batch under back-pressure, then duplicate once drained", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, b)).status).toBe(202);
      await fillBacklog(auth.agentId);
      // Back-pressure runs before the duplicate check: even a replay (a lost 202) gets 429.
      const throttled = await post(auth, b);
      expect(throttled.status).toBe(429);
      expect(throttled.headers.get("retry-after")).toBe("30");
      expect((await expectConformingError(throttled, {})).code).toBe("rate_limited");
      // The worker drains the backlog: the same batch is now acknowledged as a duplicate.
      await getDb().execute(sql`update access_events set evaluated_at = now() where agent_id = ${auth.agentId}`);
      const replay = await post(auth, b);
      expect(replay.status).toBe(202);
      expect(await replay.json()).toEqual({ batch_id: b.batch_id, duplicate: true });
      expect(await getDb().select().from(eventsBatches).where(eq(eventsBatches.agentId, auth.agentId))).toHaveLength(1);
    });

    it("a back-pressure 429 does not consume the per-minute stored-batch limit", async () => {
      const auth = await agentWithTargets();
      expect((await post(auth, batch())).status).toBe(202);
      expect(eventsPerAgent.count(auth.agentId)).toBe(1);
      await fillBacklog(auth.agentId);
      for (let i = 0; i < 5; i++) expect((await post(auth, batch())).status).toBe(429);
      expect(eventsPerAgent.count(auth.agentId)).toBe(1);
      // Even with the stored-batch limit almost reached, the throttled batches were not counted.
      for (let i = 1; i < eventsPerAgent.limit - 1; i++) eventsPerAgent.hit(auth.agentId);
      await getDb().execute(sql`update access_events set evaluated_at = now() where agent_id = ${auth.agentId}`);
      expect((await post(auth, batch())).status).toBe(202);
      expect(eventsPerAgent.count(auth.agentId)).toBe(eventsPerAgent.limit);
    });

    it("stores unregistered signal ids and counts them on /metrics", async () => {
      const auth = await agentWithTargets();
      const before = eventStats.unregisteredSignals;
      const unknown = { ...PG_DUMP, signals: ["signature.unregistered_example", "signature.pg_dump", "volume.huge_result"] };
      expect((await post(auth, batch([unknown, PG_DUMP]))).status).toBe(202);
      expect((await storedEvents(auth.agentId)).map((r) => r.signals)).toEqual([unknown.signals, PG_DUMP.signals]);
      expect(eventStats.unregisteredSignals - before).toBe(2);
      const text = await collectMetrics(getDb());
      expect(text).toContain("# TYPE databastion_console_events_unregistered_signals_total counter");
      expect(text).toMatch(new RegExp(`^databastion_console_events_unregistered_signals_total ${eventStats.unregisteredSignals}$`, "m"));
    });

    it("counts unexpected targets and unregistered signals after the commit only (duplicate, aborted)", async () => {
      const auth = await agentWithTargets();
      await getDb().execute(sql`update agent_targets set present = false where agent_id = ${auth.agentId} and target_id = 'mysql-crm'`);
      const odd = { ...PG_DUMP, target_id: "mysql-crm", signals: ["signature.unregistered_example"] };
      const counters = () => ({ unexpected: eventStats.unexpectedTarget, unregistered: eventStats.unregisteredSignals });
      const b = batch([odd]);
      const before = counters();
      expect((await post(auth, b)).status).toBe(202);
      expect(counters()).toEqual({ unexpected: before.unexpected + 1, unregistered: before.unregistered + 1 });
      // A replay is a duplicate: nothing stored, nothing counted.
      expect(await (await post(auth, b)).json()).toEqual({ batch_id: b.batch_id, duplicate: true });
      expect(counters()).toEqual({ unexpected: before.unexpected + 1, unregistered: before.unregistered + 1 });
      // An aborted transaction (the batch record insert fails after the events insert) counts nothing.
      await getDb().execute(sql.raw(`
        create function public.test_fail_events_batch() returns trigger language plpgsql as $$
        begin raise exception 'forced abort'; end $$`));
      await getDb().execute(sql.raw(`create trigger test_fail_events_batch before insert on public.events_batches
        for each row when (new.agent_id = '${auth.agentId}') execute function public.test_fail_events_batch()`));
      try {
        const aborted = batch([odd]);
        await expect(ingestEvents(getDb(), auth.agentId, aborted as never)).rejects.toThrow();
        expect(counters()).toEqual({ unexpected: before.unexpected + 1, unregistered: before.unregistered + 1 });
        expect(await storedEvents(auth.agentId)).toHaveLength(1);
      } finally {
        await getDb().execute(sql.raw("drop trigger if exists test_fail_events_batch on public.events_batches"));
        await getDb().execute(sql.raw("drop function if exists public.test_fail_events_batch()"));
      }
    });

    it("stores AccessEvent.bytes when the source reports it, null otherwise", async () => {
      const auth = await agentWithTargets();
      const withBytes = { ...PG_DUMP, bytes: 9_007_199_254_740_991 };
      expect((await post(auth, batch([withBytes, PG_DUMP, { ...PG_DUMP, bytes: 0 }]))).status).toBe(202);
      expect((await storedEvents(auth.agentId)).map((r) => r.bytes)).toEqual([9_007_199_254_740_991, null, 0]);
    });

    it("the replay of an accepted batch is acknowledged before the other checks", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      const now = Date.now();
      expect(await ingestEvents(getDb(), auth.agentId, b as never, now)).toMatchObject({ kind: "accepted", duplicate: false });
      // Later, the same batch would fail the future check (clock moved back): still a duplicate.
      expect(await ingestEvents(getDb(), auth.agentId, b as never, Date.parse("2020-01-01T00:00:00Z"))).toMatchObject({
        kind: "accepted",
        duplicate: true,
      });
    });
  });

  describe("pipeline", () => {
    it("401 without a valid secret; 413 above 4 MiB; 400 on a bad protocol header", async () => {
      const auth = await agentWithTargets();
      expect((await post({ ...auth, secret: `${auth.secret.slice(0, -2)}xx` }, batch())).status).toBe(401);
      const huge = handleEvents(agentRequest("POST", "/events", { auth, raw: `{"batch_id":"${uuidv7()}","events":[],"pad":"${"x".repeat(4 * 1024 * 1024)}"}` }));
      expect((await huge).status).toBe(413);
      const res = await handleEvents(agentRequest("POST", "/events", { auth, body: batch(), headers: { "X-DataBastion-Protocol": "x" } }));
      expect(res.status).toBe(400);
    });

    it("rejects a batch above 1 MiB serialized (maxBytes) even under maxItems", async () => {
      const auth = await agentWithTargets();
      const big = { ...PG_DUMP, principal: { db_user: "u".repeat(256) }, objects: Array.from({ length: 16 }, () => ({ database: "d".repeat(256), object: "o".repeat(256) })) };
      const res = await post(auth, batch(Array.from({ length: 150 }, () => big)));
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ details: [{ pointer: "", keyword: "maxBytes" }] });
    });

    it("rate limits requests per agent (429 + Retry-After)", async () => {
      const auth = await agentWithTargets();
      for (let i = 0; i < eventsRequestsPerAgent.limit; i++) eventsRequestsPerAgent.hit(auth.agentId);
      const res = await post(auth, batch());
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
      expect((await expectConformingError(res, {})).code).toBe("rate_limited");
    });

    it("counts only stored batches toward the per-agent batch limit", async () => {
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, b)).status).toBe(202);
      expect((await post(auth, b)).status).toBe(202); // duplicate: refunded
      expect((await post(auth, batch([{ ...PG_DUMP, target_id: "nope" }]))).status).toBe(404); // refunded
      expect(eventsPerAgent.count(auth.agentId)).toBe(1);
    });

    it("wakes the policy engine after an accepted batch only", async () => {
      const sent: number[] = [];
      setPolicyJobSender(async () => {
        sent.push(Date.now());
      });
      const auth = await agentWithTargets();
      const b = batch();
      expect((await post(auth, b)).status).toBe(202);
      expect((await post(auth, b)).status).toBe(202);
      expect((await post(auth, batch([{ ...PG_DUMP, target_id: "nope" }]))).status).toBe(404);
      await new Promise((r) => setTimeout(r, 10));
      expect(sent).toHaveLength(1);
    });
  });

  describe("storage and retention", () => {
    it("the runtime role can insert and evaluate events, never rewrite nor delete them (migration 0022)", async () => {
      const res = await getDb().execute(sql`
        select has_table_privilege('databastion_app', 'public.access_events', 'INSERT') as ins,
               has_table_privilege('databastion_app', 'public.access_events', 'UPDATE') as upd,
               has_table_privilege('databastion_app', 'public.access_events', 'DELETE') as del,
               has_table_privilege('databastion_app', 'public.access_events', 'TRUNCATE') as trunc,
               has_column_privilege('databastion_app', 'public.access_events', 'score', 'UPDATE') as score_upd,
               has_column_privilege('databastion_app', 'public.access_events', 'evaluated_at', 'UPDATE') as eval_upd,
               has_column_privilege('databastion_app', 'public.access_events', 'db_user', 'UPDATE') as user_upd,
               has_column_privilege('databastion_app', 'public.access_events', 'objects', 'UPDATE') as objects_upd,
               has_column_privilege('databastion_app', 'public.access_events', 'rows', 'UPDATE') as rows_upd,
               has_column_privilege('databastion_app', 'public.access_events', 'bytes', 'UPDATE') as bytes_upd,
               has_table_privilege('databastion_app', 'public.events_batches', 'UPDATE') as batch_upd,
               has_table_privilege('databastion_app', 'public.events_batches', 'DELETE') as batch_del,
               has_table_privilege('databastion_app', 'public.incident_events', 'DELETE') as link_del,
               has_table_privilege('databastion_app', 'public.principal_baselines', 'DELETE') as base_del,
               has_column_privilege('databastion_app', 'public.incidents', 'event_score', 'UPDATE') as inc_score_upd,
               has_column_privilege('databastion_app', 'public.incidents', 'principal', 'UPDATE') as inc_principal_upd,
               has_function_privilege('databastion_app', 'public.databastion_purge_access_events(integer, integer)', 'EXECUTE') as purge,
               has_function_privilege('public', 'public.databastion_purge_access_events(integer, integer)', 'EXECUTE') as purge_public`);
      expect(res.rows[0]).toEqual({
        ins: true,
        upd: false,
        del: false,
        trunc: false,
        score_upd: true,
        eval_upd: true,
        user_upd: false,
        objects_upd: false,
        rows_upd: false,
        bytes_upd: false,
        batch_upd: false,
        batch_del: false,
        link_del: false,
        base_del: false,
        inc_score_upd: true,
        inc_principal_upd: false,
        purge: true,
        purge_public: false,
      });
    });

    /** Ages stored rows as the owner (the runtime role could not): events `ts` and evaluation. */
    async function age(agentId: string, daysAgo: number[]) {
      const rows = await storedEvents(agentId);
      for (const [i, d] of daysAgo.entries()) {
        await getDb().execute(sql`update access_events set ts = now() - make_interval(days => ${d}), evaluated_at = now() where id = ${rows[i]?.id}`);
      }
    }

    it("purges evaluated events past the retention bound, in chunks; never below 7 days; never unevaluated ones", async () => {
      const auth = await agentWithTargets();
      expect((await post(auth, batch(Array.from({ length: 7 }, () => PG_DUMP)))).status).toBe(202);
      // The 7th event is old but not evaluated yet: kept.
      const rows = await storedEvents(auth.agentId);
      for (const [i, d] of [120, 100, 95, 80, 5, 3].entries()) {
        await getDb().execute(sql`update access_events set ts = now() - make_interval(days => ${d}), evaluated_at = now() where id = ${rows[i]?.id}`);
      }
      await getDb().execute(sql`update access_events set ts = now() - make_interval(days => 200), evaluated_at = null where id = ${rows[6]?.id}`);
      expect(await purgeAccessEvents(getDb(), { retentionDays: 90, chunk: 2 })).toEqual({ deleted: 3, more: false });
      expect(await storedEvents(auth.agentId)).toHaveLength(4);
      // A retention of 1 day is raised to 7: the events of 3 and 5 days survive.
      await purgeAccessEvents(getDb(), { retentionDays: 1 });
      const left = await storedEvents(auth.agentId);
      expect(left).toHaveLength(3);
      expect(left.some((r) => r.evaluatedAt === null)).toBe(true);
    });

    it("keeps the batch records 30 days longer than the events, and purges idle baselines", async () => {
      const auth = await agentWithTargets();
      const a = batch();
      const b = batch();
      expect((await post(auth, a)).status).toBe(202);
      expect((await post(auth, b)).status).toBe(202);
      await getDb().execute(sql`update events_batches set received_at = now() - interval '100 days' where batch_id = ${a.batch_id}`);
      await getDb().execute(sql`update events_batches set received_at = now() - interval '130 days' where batch_id = ${b.batch_id}`);
      await getDb().execute(sql`insert into principal_baselines (agent_id, target_id, principal_key, db_user, updated_at)
        values (${auth.agentId}, 'pg-prod-1', ${"1".repeat(64)}, 'old', now() - interval '100 days'),
               (${auth.agentId}, 'pg-prod-1', ${"2".repeat(64)}, 'recent', now() - interval '10 days')`);
      await purgeAccessEvents(getDb(), { retentionDays: 90 });
      const kept = await getDb().select({ id: eventsBatches.batchId }).from(eventsBatches).where(eq(eventsBatches.agentId, auth.agentId));
      expect(kept.map((r) => r.id)).toEqual([a.batch_id]);
      // The replay of the kept batch is still a duplicate.
      expect(await (await post(auth, a)).json()).toEqual({ batch_id: a.batch_id, duplicate: true });
      const baselines = await getDb().execute<{ db_user: string }>(sql`select db_user from principal_baselines where agent_id = ${auth.agentId}`);
      expect(baselines.rows.map((r) => r.db_user)).toEqual(["recent"]);
    });

    it("the runtime role deletes events only through the purge function", async () => {
      const auth = await agentWithTargets();
      expect((await post(auth, batch([PG_DUMP, PG_DUMP]))).status).toBe(202);
      await age(auth.agentId, [200]);
      const { url } = await createRuntimeRole();
      const client = new Client({ connectionString: url });
      await client.connect();
      try {
        await expect(client.query("delete from public.access_events")).rejects.toThrow(/permission denied/);
        await expect(client.query("update public.access_events set db_user = 'x'")).rejects.toThrow(/permission denied/);
        await expect(client.query("delete from public.events_batches")).rejects.toThrow(/permission denied/);
        await expect(client.query("delete from public.principal_baselines")).rejects.toThrow(/permission denied/);
        const res = await client.query<{ n: number }>("select public.databastion_purge_access_events(90, 100) as n");
        expect(res.rows[0]?.n).toBeGreaterThanOrEqual(1);
      } finally {
        await client.end();
      }
      expect(await storedEvents(auth.agentId)).toHaveLength(1);
    });

    it("N4: the eviction function only deletes the baselines beyond the cap, never below 10", async () => {
      const auth = await agentWithTargets();
      await getDb().execute(sql`insert into principal_baselines (agent_id, target_id, principal_key, db_user, updated_at)
        select ${auth.agentId}, 'pg-prod-1', lpad(to_hex(i), 64, '0'), 'u' || i, now() - make_interval(secs => 100 - i)
        from generate_series(1, 25) i`);
      const { url } = await createRuntimeRole();
      const client = new Client({ connectionString: url });
      await client.connect();
      const count = async () =>
        Number((await client.query<{ n: number }>("select count(*)::int as n from principal_baselines where agent_id = $1", [auth.agentId])).rows[0]?.n);
      try {
        const evict = (cap: number) =>
          client.query<{ d: number }>("select public.databastion_evict_principal_baselines($1, 'pg-prod-1', $2) as d", [auth.agentId, cap]);
        expect((await evict(30)).rows[0]?.d).toBe(0);
        expect((await evict(20)).rows[0]?.d).toBe(5);
        expect(await count()).toBe(20);
        // A cap below 10 (or 0) is raised to 10.
        expect((await evict(0)).rows[0]?.d).toBe(10);
        expect(await count()).toBe(10);
        // The most recently updated ones are kept.
        const kept = await client.query<{ db_user: string }>("select db_user from principal_baselines where agent_id = $1 order by db_user", [auth.agentId]);
        expect(kept.rows.map((r) => Number(r.db_user.slice(1))).sort((a, b) => a - b)).toEqual([16, 17, 18, 19, 20, 21, 22, 23, 24, 25]);
      } finally {
        await client.end();
      }
    });

    it("reads the retention from the environment, within [7, 3650] days", () => {
      expect(eventsRetentionDays({})).toBe(DEFAULT_EVENTS_RETENTION_DAYS);
      expect(eventsRetentionDays({ DATABASTION_EVENTS_RETENTION_DAYS: "30" })).toBe(30);
      expect(eventsRetentionDays({ DATABASTION_EVENTS_RETENTION_DAYS: "3" })).toBe(DEFAULT_EVENTS_RETENTION_DAYS);
      expect(eventsRetentionDays({ DATABASTION_EVENTS_RETENTION_DAYS: "9999" })).toBe(DEFAULT_EVENTS_RETENTION_DAYS);
      expect(eventsRetentionDays({ DATABASTION_EVENTS_RETENTION_DAYS: "x" })).toBe(DEFAULT_EVENTS_RETENTION_DAYS);
    });
  });

  it("I2: no raw value of a rejected batch, no query text, nothing outside the contract fields in the database", async () => {
    const auth = await agentWithTargets();
    for (const [, body] of fixtures("invalid", "EventsBatch")) await post(auth, body);
    const raw = {
      ...batch(),
      events: [{ ...PG_DUMP, query: "COPY public.clients TO STDOUT WHERE email = 'jane.doe@example.com'" }],
    };
    expect((await post(auth, raw)).status).toBe(400);
    for (const [, body] of fixtures("valid", "EventsBatch")) {
      expect((await post(auth, { ...(body as Batch), batch_id: uuidv7() })).status).toBe(202);
    }
    const dump = await databaseDump();
    expect(dump).toContain(auth.agentId);
    expect(dump).toContain("backup");
    for (const needle of ["jane.doe@example.com", "jane.doe", "COPY public", "TO STDOUT", "WHERE email", "uid=jdoe", "SELECT ", "‮"]) {
      expect(dump).not.toContain(needle);
    }
    // The audit log and the security events hold counts and pointers only.
    const audits = await getDb().select().from(auditLog).where(eq(auditLog.actorId, auth.agentId));
    expect(audits.length).toBeGreaterThan(0);
    expect(JSON.stringify(audits)).not.toMatch(/pg_dump|backup|clients/);
  });
});
