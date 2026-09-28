import { and, asc, desc, eq, gte, inArray, lte, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { accessEvents, agents, agentTargets, eventsBatches, incidentEvents, incidents, principalBaselines } from "@/db/schema";
import type { EventFilter } from "@/lib/events-filter";
import { baselineVerdict, isWarm, type BaselineState } from "@/lib/event-model";
import { MAX_VALIDATION_DETAILS, type Schemas, type ValidationDetail } from "@/lib/protocol/validate";

import { MAX_FUTURE_SKEW_MS } from "./agent-api/pipeline";
import { sha256Hex } from "./crypto";
import { canonicalJson } from "./findings";

/**
 * Audit access events (P4-C): ingestion of `POST /events` batches, retention, and the views.
 *
 * Events are masked by the agent before the uplink (ADR-0007): the contract has no field for query
 * text, bound parameters or returned values, every object is closed (unknown fields rejected with
 * `400` before anything is stored), and names, account names and application names are bounded and
 * pattern-checked by the schema. The console stores exactly the contract fields, never logs them,
 * and never derives a key from agent-provided text (`principal_key` is a SHA-256).
 */

type EventsBatch = Schemas["EventsBatch"];
type AccessEvent = Schemas["AccessEvent"];

export type EventsIngestOutcome =
  | { kind: "accepted"; duplicate: boolean; stored: number }
  | { kind: "batch_conflict" }
  /** `target_id` not reported by this agent: pointers `/events/<i>/target_id`. */
  | { kind: "foreign_target"; details: ValidationDetail[] }
  /** Console-side checks (timestamps more than 5 min in the future). */
  | { kind: "invalid"; details: ValidationDetail[] };

/** SHA-256 of the validated batch in canonical JSON (same rule as `/findings`). */
export function eventsBatchSha256(batch: EventsBatch): string {
  return sha256Hex(canonicalJson(batch));
}

/**
 * Grouping key of a principal (baselines, dedup): SHA-256 of `u\0<db_user>` or
 * `f\0<fingerprint>`, so that a name and a fingerprint never collide and no key holds agent text.
 */
export function principalKey(p: { db_user?: string; db_user_fingerprint?: string }): string {
  return p.db_user !== undefined ? sha256Hex(`u\u0000${p.db_user}`) : sha256Hex(`f\u0000${p.db_user_fingerprint ?? ""}`);
}

/** Principal as displayed and matched by policies: `db_user`, or its fingerprint. */
export function principalLabel(p: { dbUser: string | null; dbUserFingerprint: string | null }): string {
  return p.dbUser ?? p.dbUserFingerprint ?? "";
}

/** Timestamps of an event more than `MAX_FUTURE_SKEW_MS` ahead of the console clock (`formatMaximum`). */
function futureDetails(batch: EventsBatch, now: number): ValidationDetail[] {
  const details: ValidationDetail[] = [];
  const limit = now + MAX_FUTURE_SKEW_MS;
  batch.events.forEach((e, i) => {
    if (details.length < MAX_VALIDATION_DETAILS && Date.parse(e.ts) > limit) {
      details.push({ pointer: `/events/${i}/ts`, keyword: "formatMaximum" });
    }
    if (details.length < MAX_VALIDATION_DETAILS && e.ts_last !== undefined && Date.parse(e.ts_last) > limit) {
      details.push({ pointer: `/events/${i}/ts_last`, keyword: "formatMaximum" });
    }
  });
  return details;
}

function eventRow(agentId: string, batchId: string, e: AccessEvent, i: number) {
  return {
    agentId,
    targetId: e.target_id,
    batchId,
    itemIndex: i,
    ts: new Date(e.ts),
    tsLast: e.ts_last !== undefined ? new Date(e.ts_last) : null,
    principalKey: principalKey(e.principal),
    dbUser: e.principal.db_user ?? null,
    dbUserFingerprint: e.principal.db_user_fingerprint ?? null,
    clientAddr: e.principal.client_addr ?? null,
    application: e.principal.application ?? null,
    action: e.action,
    // Only the contract fields of each object, in a fixed shape.
    objects: e.objects.map((o) => (o.schema !== undefined ? { database: o.database, schema: o.schema, object: o.object } : { database: o.database, object: o.object })),
    rows: e.rows ?? null,
    signals: [...(e.signals ?? [])],
    source: e.source,
    aggregatedCount: e.aggregated_count,
  };
}

/**
 * Ingests a validated (schema + `checkSemantics`) events batch of `agentId`, atomically:
 * 1. idempotency on `(agent_id, batch_id)`: same content -> duplicate, other content -> conflict
 *    (before every other console-side check, so a replay is always acknowledged);
 * 2. every `target_id` was reported by the agent (`404`, item pointers `/events/<i>/target_id`);
 * 3. no timestamp more than 5 min in the future (`400`, `formatMaximum`, item pointers);
 * 4. storage of the events (pending evaluation by the worker) + the batch record.
 * Batches of one agent are serialized (transaction-scoped advisory lock).
 */
export async function ingestEvents(
  db: Database,
  agentId: string,
  batch: EventsBatch,
  now: number = Date.now(),
): Promise<EventsIngestOutcome> {
  const bodySha256 = eventsBatchSha256(batch);
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`events:${agentId}`}, 0))`);
    const [previous] = await tx
      .select({ bodySha256: eventsBatches.bodySha256 })
      .from(eventsBatches)
      .where(and(eq(eventsBatches.agentId, agentId), eq(eventsBatches.batchId, batch.batch_id)))
      .limit(1);
    if (previous) {
      return previous.bodySha256 === bodySha256
        ? { kind: "accepted" as const, duplicate: true, stored: 0 }
        : { kind: "batch_conflict" as const };
    }

    const targetIds = [...new Set(batch.events.map((e) => e.target_id))];
    const owned = await tx
      .select({ targetId: agentTargets.targetId })
      .from(agentTargets)
      .where(and(eq(agentTargets.agentId, agentId), inArray(agentTargets.targetId, targetIds)));
    const ownedIds = new Set(owned.map((t) => t.targetId));
    const foreign: ValidationDetail[] = [];
    batch.events.forEach((e, i) => {
      if (!ownedIds.has(e.target_id) && foreign.length < MAX_VALIDATION_DETAILS) {
        foreign.push({ pointer: `/events/${i}/target_id`, keyword: "notFound" });
      }
    });
    if (foreign.length > 0) return { kind: "foreign_target" as const, details: foreign };

    const future = futureDetails(batch, now);
    if (future.length > 0) return { kind: "invalid" as const, details: future };

    await tx.insert(accessEvents).values(batch.events.map((e, i) => eventRow(agentId, batch.batch_id, e, i)));
    await tx.insert(eventsBatches).values({ agentId, batchId: batch.batch_id, bodySha256, eventsCount: batch.events.length });
    return { kind: "accepted" as const, duplicate: false, stored: batch.events.length };
  });
}

// --------------------------------------------------------------------------- retention

/**
 * Retention of access events, `DATABASTION_EVENTS_RETENTION_DAYS` (default 90, accepted 7 to
 * 3650; other values fall back to the default). Events whose `ts` is older are deleted by the
 * worker (`events.purge`, hourly) through the owner-defined function of migration 0022, which
 * enforces the same [7, 3650] bound. Baselines (aggregates) and incidents are kept.
 */
export const EVENTS_RETENTION_VAR = "DATABASTION_EVENTS_RETENTION_DAYS";
export const DEFAULT_EVENTS_RETENTION_DAYS = 90;
export const PURGE_CHUNK = 10_000;

export function eventsRetentionDays(env: Readonly<Record<string, string | undefined>> = process.env): number {
  const raw = env[EVENTS_RETENTION_VAR];
  if (raw === undefined || raw.trim() === "") return DEFAULT_EVENTS_RETENTION_DAYS;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 7 && n <= 3650 ? n : DEFAULT_EVENTS_RETENTION_DAYS;
}

/** Deletes the events past the retention bound, in chunks, within `budgetMs`. */
export async function purgeAccessEvents(
  db: Database,
  opts: { retentionDays?: number; budgetMs?: number; chunk?: number } = {},
): Promise<{ deleted: number; more: boolean }> {
  const deadline = Date.now() + (opts.budgetMs ?? 50_000);
  const days = opts.retentionDays ?? eventsRetentionDays();
  const chunk = opts.chunk ?? PURGE_CHUNK;
  let deleted = 0;
  for (;;) {
    const res = await db.execute<{ n: number }>(sql`select public.databastion_purge_access_events(${days}::int, ${chunk}::int) as n`);
    const n = Number(res.rows[0]?.n ?? 0);
    deleted += n;
    if (n < chunk) return { deleted, more: false };
    if (Date.now() > deadline) return { deleted, more: true };
  }
}

// -------------------------------------------------------------------------------- views

export const MAX_LISTED_EVENTS = 500;

export interface EventView {
  id: string;
  agentId: string;
  agentName: string;
  targetId: string;
  ts: Date;
  tsLast: Date | null;
  receivedAt: Date;
  principalKey: string;
  principal: string;
  fingerprinted: boolean;
  clientAddr: string | null;
  application: string | null;
  action: string;
  objects: { database: string; schema?: string; object: string }[];
  rows: number | null;
  signals: string[];
  source: string;
  aggregatedCount: number;
  evaluated: boolean;
  sensitivity: number | null;
  score: number | null;
  anomaly: boolean | null;
  baselineRows: number | null;
  /** Incidents this event matched (bounded). */
  incidentIds: string[];
}

function eventWhere(f: EventFilter): SQL | undefined {
  const conds: SQL[] = [];
  if (f.agentId) conds.push(eq(accessEvents.agentId, f.agentId));
  if (f.targetId) conds.push(eq(accessEvents.targetId, f.targetId));
  if (f.principalKey) conds.push(eq(accessEvents.principalKey, f.principalKey));
  if (f.signal) {
    // `signature.*` families match every signal of the family; ids are exact (jsonb containment).
    if (f.signal.endsWith(".*")) {
      conds.push(sql`exists (select 1 from jsonb_array_elements_text(${accessEvents.signals}) s where starts_with(s, ${f.signal.slice(0, -1)}))`);
    } else {
      conds.push(sql`${accessEvents.signals} @> ${JSON.stringify([f.signal])}::jsonb`);
    }
  }
  if (f.from) conds.push(gte(accessEvents.ts, f.from));
  if (f.to) conds.push(lte(accessEvents.ts, f.to));
  if (f.anomalyOnly) conds.push(eq(accessEvents.anomaly, true));
  return conds.length > 0 ? and(...conds) : undefined;
}

const EVENT_COLUMNS = {
  id: accessEvents.id,
  agentId: accessEvents.agentId,
  agentName: agents.name,
  targetId: accessEvents.targetId,
  ts: accessEvents.ts,
  tsLast: accessEvents.tsLast,
  receivedAt: accessEvents.receivedAt,
  principalKey: accessEvents.principalKey,
  dbUser: accessEvents.dbUser,
  dbUserFingerprint: accessEvents.dbUserFingerprint,
  clientAddr: accessEvents.clientAddr,
  application: accessEvents.application,
  action: accessEvents.action,
  objects: accessEvents.objects,
  rows: accessEvents.rows,
  signals: accessEvents.signals,
  source: accessEvents.source,
  aggregatedCount: accessEvents.aggregatedCount,
  evaluatedAt: accessEvents.evaluatedAt,
  sensitivity: accessEvents.sensitivity,
  score: accessEvents.score,
  anomaly: accessEvents.anomaly,
  baselineRows: accessEvents.baselineRows,
  incidentIds: sql<string[]>`coalesce((select array_agg(ie.incident_id::text order by ie.created_at) from (
      select incident_id, created_at from ${incidentEvents} where ${incidentEvents.eventId} = ${accessEvents.id}
      order by created_at limit 10) ie), '{}')`,
};

type EventRow = Awaited<ReturnType<typeof selectEvents>>[number];

function selectEvents(db: Database, where: SQL | undefined, limit: number) {
  return db
    .select(EVENT_COLUMNS)
    .from(accessEvents)
    .innerJoin(agents, eq(agents.id, accessEvents.agentId))
    .where(where)
    .orderBy(desc(accessEvents.ts), desc(accessEvents.id))
    .limit(limit);
}

function toEventView({ dbUser, dbUserFingerprint, evaluatedAt, ...r }: EventRow): EventView {
  return {
    ...r,
    principal: principalLabel({ dbUser, dbUserFingerprint }),
    fingerprinted: dbUser === null,
    evaluated: evaluatedAt !== null,
    incidentIds: r.incidentIds ?? [],
  };
}

/** Latest access events matching the filter (newest first, at most `MAX_LISTED_EVENTS`). */
export async function listEvents(db: Database, filter: EventFilter = {}): Promise<EventView[]> {
  const rows = await selectEvents(db, eventWhere(filter), MAX_LISTED_EVENTS);
  return rows.map(toEventView);
}

/** Events linked to an incident (newest first, bounded). */
export async function incidentEventViews(db: Database, incidentId: string, limit = 50): Promise<EventView[]> {
  const rows = await selectEvents(
    db,
    sql`${accessEvents.id} in (select ${incidentEvents.eventId} from ${incidentEvents} where ${incidentEvents.incidentId} = ${incidentId})`,
    limit,
  );
  return rows.map(toEventView);
}

/** Number of events linked to an incident. */
export async function incidentEventCount(db: Database, incidentId: string): Promise<number> {
  const [row] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(incidentEvents)
    .where(eq(incidentEvents.incidentId, incidentId));
  return row?.n ?? 0;
}

export interface PrincipalView {
  agentId: string;
  agentName: string;
  targetId: string;
  principalKey: string;
  principal: string;
  fingerprinted: boolean;
  /** Events with `rows` counted in the baseline. */
  events: number;
  warm: boolean;
  baselineRows: number | null;
  thresholdRows: number | null;
  typicalScore: number | null;
  rowsTotal: number;
  maxScore: number;
  anomalies: number;
  firstEventAt: Date | null;
  lastEventAt: Date | null;
}

const PRINCIPAL_COLUMNS = {
  agentId: principalBaselines.agentId,
  agentName: agents.name,
  targetId: principalBaselines.targetId,
  principalKey: principalBaselines.principalKey,
  dbUser: principalBaselines.dbUser,
  dbUserFingerprint: principalBaselines.dbUserFingerprint,
  events: principalBaselines.events,
  meanLogRows: principalBaselines.meanLogRows,
  varLogRows: principalBaselines.varLogRows,
  meanLogScore: principalBaselines.meanLogScore,
  varLogScore: principalBaselines.varLogScore,
  rowsTotal: principalBaselines.rowsTotal,
  maxScore: principalBaselines.maxScore,
  anomalies: principalBaselines.anomalies,
  firstEventAt: principalBaselines.firstEventAt,
  lastEventAt: principalBaselines.lastEventAt,
};

type PrincipalRow = Awaited<ReturnType<typeof selectPrincipals>>[number];

function selectPrincipals(db: Database, where: SQL | undefined, limit: number) {
  return db
    .select(PRINCIPAL_COLUMNS)
    .from(principalBaselines)
    .innerJoin(agents, eq(agents.id, principalBaselines.agentId))
    .where(where)
    .orderBy(desc(principalBaselines.maxScore), asc(principalBaselines.targetId), asc(principalBaselines.principalKey))
    .limit(limit);
}

function toPrincipalView(r: PrincipalRow): PrincipalView {
  const state: BaselineState = {
    events: r.events,
    meanLogRows: r.meanLogRows,
    varLogRows: r.varLogRows,
    meanLogScore: r.meanLogScore,
    varLogScore: r.varLogScore,
  };
  const verdict = baselineVerdict(state, null);
  return {
    agentId: r.agentId,
    agentName: r.agentName,
    targetId: r.targetId,
    principalKey: r.principalKey,
    principal: principalLabel(r),
    fingerprinted: r.dbUser === null,
    events: r.events,
    warm: isWarm(state),
    baselineRows: verdict.baselineRows,
    thresholdRows: verdict.thresholdRows,
    typicalScore: isWarm(state) ? Math.round(Math.expm1(r.meanLogScore) * 100) / 100 : null,
    rowsTotal: r.rowsTotal,
    maxScore: r.maxScore,
    anomalies: r.anomalies,
    firstEventAt: r.firstEventAt,
    lastEventAt: r.lastEventAt,
  };
}

export const MAX_LISTED_PRINCIPALS = 200;

/** Principals with a baseline (highest score seen first), optionally for one agent / target. */
export async function listPrincipals(db: Database, filter: { agentId?: string; targetId?: string } = {}): Promise<PrincipalView[]> {
  const conds: SQL[] = [];
  if (filter.agentId) conds.push(eq(principalBaselines.agentId, filter.agentId));
  if (filter.targetId) conds.push(eq(principalBaselines.targetId, filter.targetId));
  const rows = await selectPrincipals(db, conds.length > 0 ? and(...conds) : undefined, MAX_LISTED_PRINCIPALS);
  return rows.map(toPrincipalView);
}

export async function getPrincipal(db: Database, agentId: string, targetId: string, key: string): Promise<PrincipalView | null> {
  const [row] = await selectPrincipals(
    db,
    and(eq(principalBaselines.agentId, agentId), eq(principalBaselines.targetId, targetId), eq(principalBaselines.principalKey, key)),
    1,
  );
  return row ? toPrincipalView(row) : null;
}

/** Incidents raised for a principal (newest first, bounded): ids, status, severity, policy name. */
export async function principalIncidents(db: Database, agentId: string, targetId: string, key: string, limit = 50) {
  return db
    .select({
      id: incidents.id,
      status: incidents.status,
      severity: incidents.severity,
      policyName: incidents.policyName,
      eventBucket: incidents.eventBucket,
      eventScore: incidents.eventScore,
      matchCount: incidents.matchCount,
      createdAt: incidents.createdAt,
    })
    .from(incidents)
    .where(
      and(
        eq(incidents.source, "access_event"),
        eq(incidents.agentId, agentId),
        eq(incidents.targetId, targetId),
        sql`${incidents.dedupKey} like ${`%|principal:${key}|%`}`,
      ),
    )
    .orderBy(desc(incidents.createdAt))
    .limit(limit);
}
