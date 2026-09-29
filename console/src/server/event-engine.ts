import { and, asc, desc, eq, inArray, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { accessEvents, agentTargets, findings, incidentEvents, incidents, policies, policyExceptions, principalBaselines } from "@/db/schema";
import {
  baselineEligible,
  baselineVerdict,
  coarsePrincipal,
  eventOverflowKey,
  severeEvent,
  worseThanResolved,
  dedupObject,
  eventBucket,
  eventDedupKey,
  eventMatches,
  eventScore,
  exceptionCoversEvent,
  mergeSignals,
  objectSensitivity,
  parseEventConditions,
  updateBaseline,
  type BaselineState,
  type ClassifierHit,
  type EventConditions,
  type EventExceptionScope,
  type EventFacts,
  type EventObject,
} from "@/lib/event-model";
import { logger } from "@/lib/logger";
import type { AccessIncidentOpenedPayload } from "@/lib/notification-render";
import { unregisteredSignals } from "@/lib/protocol/signals";
import {
  ACTIVE_STATUSES,
  incidentSeverityOf,
  notifyChannelsOf,
  parsePolicyActions,
  type Severity,
} from "@/lib/policy-model";

import { consoleUrl } from "./alerting-config";
import { writeAudit } from "./audit";
import { sha256Hex } from "./crypto";
import { baselinesPerTarget, clientNetwork, eventIncidentsPerPolicyHour, principalLabel } from "./events";
import type { Tx } from "./findings";
import { enqueueIncidentNotifications } from "./notifications";

/**
 * Correlation of Audit access events (P4-C, worker). Pending events (`evaluated_at` null) are
 * processed in arrival order, in chunks of `EVENT_CHUNK` per transaction; one transaction:
 * 1. computes each event's sensitivity (from the findings of its objects) and score;
 * 2. judges its volume against the principal's baseline, then updates the baseline;
 * 3. applies every enabled `access_event` policy: incidents are deduplicated per policy, agent,
 *    target, principal, database and hour (src/lib/event-model.ts), linked to every matching event
 *    (`incident_events`) and notified through the outbox, in the same transaction;
 * 4. records the evaluation on the event (`evaluated_at`, `sensitivity`, `score`, `anomaly`,
 *    `baseline_rows`), the only columns of an event the runtime role may update.
 * Evaluations are serialized by a transaction-scoped advisory lock, so the baselines see the
 * events of a principal in order and two workers never race on an incident. A lost wake-up delays
 * nothing beyond the one-minute schedule of `policies.evaluate`; a crash rolls the chunk back and it
 * is evaluated again. A policy applies to the events evaluated after its creation or change: past
 * events are not re-evaluated (unlike findings, events are occurrences, not state).
 *
 * Nothing here reads or stores a value: events carry none (ADR-0007).
 */

export const EVENT_CHUNK = 200;
/** At most this many events of one agent per chunk: agents are drained round-robin (M2). */
export const EVENT_CHUNK_PER_AGENT = 50;
const EVALUATION_LOCK = "events.evaluate";

const log = logger.child({ component: "event-engine" });

interface LoadedEventPolicy {
  id: string;
  name: string;
  revision: number;
  conditions: EventConditions;
  severity: Severity;
  notifyChannels: string[];
}

async function loadEventPolicies(tx: Tx): Promise<LoadedEventPolicy[]> {
  const rows = await tx
    .select({
      id: policies.id,
      name: policies.name,
      revision: policies.revision,
      conditions: policies.conditions,
      actions: policies.actions,
    })
    .from(policies)
    .where(and(eq(policies.enabled, true), eq(policies.source, "access_event")))
    .orderBy(asc(policies.id));
  const out: LoadedEventPolicy[] = [];
  for (const r of rows) {
    const conditions = parseEventConditions(r.conditions, { stored: true });
    const actions = parsePolicyActions(r.actions);
    if (!conditions.ok || !actions.ok) {
      log.error({ policyId: r.id }, "policy document does not validate: skipped");
      continue;
    }
    out.push({
      id: r.id,
      name: r.name,
      revision: r.revision,
      conditions: conditions.value,
      severity: incidentSeverityOf(actions.value),
      notifyChannels: notifyChannelsOf(actions.value),
    });
  }
  return out;
}

async function loadExceptions(tx: Tx): Promise<EventExceptionScope[]> {
  const rows = await tx
    .select({
      policyId: policyExceptions.policyId,
      agentId: policyExceptions.agentId,
      targetId: policyExceptions.targetId,
      classifier: policyExceptions.classifier,
      location: policyExceptions.location,
      expiresAt: policyExceptions.expiresAt,
    })
    .from(policyExceptions);
  return rows.map((r) => ({ ...r, location: (r.location as EventExceptionScope["location"]) ?? null }));
}

const PENDING_COLUMNS = {
  id: accessEvents.id,
  agentId: accessEvents.agentId,
  targetId: accessEvents.targetId,
  ts: accessEvents.ts,
  principalKey: accessEvents.principalKey,
  dbUser: accessEvents.dbUser,
  dbUserFingerprint: accessEvents.dbUserFingerprint,
  clientAddr: accessEvents.clientAddr,
  action: accessEvents.action,
  objects: accessEvents.objects,
  rows: accessEvents.rows,
  signals: accessEvents.signals,
  source: accessEvents.source,
};

type PendingEvent = {
  id: string;
  agentId: string;
  targetId: string;
  ts: Date;
  principalKey: string;
  dbUser: string | null;
  dbUserFingerprint: string | null;
  clientAddr: string | null;
  action: string;
  objects: EventObject[];
  rows: number | null;
  signals: string[];
  source: string;
};

const SEP = "\u0000";
const objectKey = (agentId: string, targetId: string, o: EventObject) =>
  [agentId, targetId, o.database, o.schema === undefined || o.schema === null ? "*" : `=${o.schema}`, o.object].join(SEP);

/**
 * Findings (false positives excluded) of the objects reached by `events`, by object key: the exact
 * schema (`=<schema>`), and `*` for any schema (events whose source logs no schema).
 */
async function loadObjectHits(tx: Tx, events: readonly PendingEvent[]): Promise<Map<string, ClassifierHit[]>> {
  const agentIds = [...new Set(events.map((e) => e.agentId))];
  const names = [...new Set(events.flatMap((e) => e.objects.map((o) => o.object)))];
  const out = new Map<string, ClassifierHit[]>();
  if (names.length === 0) return out;
  const rows = await tx
    .select({
      agentId: findings.agentId,
      targetId: findings.targetId,
      databaseName: findings.databaseName,
      schemaName: findings.schemaName,
      objectName: findings.objectName,
      classifier: findings.classifier,
      confidence: sql<number>`max(${findings.confidence})`,
    })
    .from(findings)
    .where(and(isNull(findings.falsePositiveAt), inArray(findings.agentId, agentIds), inArray(findings.objectName, names)))
    .groupBy(findings.agentId, findings.targetId, findings.databaseName, findings.schemaName, findings.objectName, findings.classifier);
  const push = (key: string, hit: ClassifierHit) => {
    const list = out.get(key);
    if (list) list.push(hit);
    else out.set(key, [hit]);
  };
  for (const r of rows) {
    const hit = { classifier: r.classifier, confidence: Number(r.confidence) };
    const o = { database: r.databaseName, object: r.objectName };
    push(objectKey(r.agentId, r.targetId, { ...o, schema: r.schemaName }), hit);
    if (r.schemaName !== null) push(objectKey(r.agentId, r.targetId, o), hit);
  }
  return out;
}

type BaselineRow = BaselineState & {
  rowsTotal: number;
  maxScore: number;
  anomalies: number;
  firstEventAt: Date | null;
  lastEventAt: Date | null;
  dbUser: string | null;
  dbUserFingerprint: string | null;
};

const baselineKey = (e: Pick<PendingEvent, "agentId" | "targetId" | "principalKey">) => [e.agentId, e.targetId, e.principalKey].join(SEP);
const targetKey = (e: Pick<PendingEvent, "agentId" | "targetId">) => `${e.agentId}${SEP}${e.targetId}`;

/**
 * Baselines of the principals of the eligible events of the chunk (events with `rows`, never
 * `connect` / `auth_failure`: H1). A target keeps at most `baselinesPerTarget()` baselines: before
 * creating new ones past the cap, the least recently updated baselines of the target are evicted
 * (owner-defined function, migration 0024), after the baselines of this chunk were touched so they
 * are never the ones evicted. New principals beyond the cap in one chunk get no baseline.
 */
async function loadBaselines(tx: Tx, events: readonly PendingEvent[]): Promise<Map<string, BaselineRow>> {
  const out = new Map<string, BaselineRow>();
  const first = new Map<string, PendingEvent>();
  for (const e of events) if (baselineEligible(e) && !first.has(baselineKey(e))) first.set(baselineKey(e), e);
  if (first.size === 0) return out;
  const select = () =>
    tx
      .select()
      .from(principalBaselines)
      .where(
        and(
          inArray(principalBaselines.agentId, [...new Set([...first.values()].map((e) => e.agentId))]),
          inArray(principalBaselines.principalKey, [...new Set([...first.values()].map((e) => e.principalKey))]),
        ),
      );
  const existing = new Set((await select()).map((r) => baselineKey(r)).filter((k) => first.has(k)));
  const fresh = [...first.entries()].filter(([k]) => !existing.has(k)).map(([, e]) => e);
  if (fresh.length > 0) {
    const cap = baselinesPerTarget();
    const byTarget = new Map<string, PendingEvent[]>();
    for (const e of fresh) byTarget.set(targetKey(e), [...(byTarget.get(targetKey(e)) ?? []), e]);
    // Touch the existing baselines of the chunk: the eviction takes the least recently updated.
    for (const k of existing) {
      const [agentId, targetId, pk] = k.split(SEP) as [string, string, string];
      await tx
        .update(principalBaselines)
        .set({ updatedAt: sql`now()` })
        .where(and(eq(principalBaselines.agentId, agentId), eq(principalBaselines.targetId, targetId), eq(principalBaselines.principalKey, pk)));
    }
    // New principals beyond the cap within one chunk get no baseline; the others are inserted,
    // then the target is brought back to the cap by evicting its least recently updated
    // baselines (N4: the function deletes only the rows beyond the cap it is given).
    const create = [...byTarget.values()].flatMap((list) => list.slice(0, cap));
    if (create.length > 0) {
      await tx
        .insert(principalBaselines)
        .values(create.map((e) => ({ agentId: e.agentId, targetId: e.targetId, principalKey: e.principalKey, dbUser: e.dbUser, dbUserFingerprint: e.dbUserFingerprint })))
        .onConflictDoNothing();
    }
    for (const list of byTarget.values()) {
      const [{ agentId, targetId }] = list as [PendingEvent];
      for (let i = 0; i < 1000; i++) {
        const res = await tx.execute<{ d: number }>(
          sql`select public.databastion_evict_principal_baselines(${agentId}::uuid, ${targetId}, ${cap}::int) as d`,
        );
        if (Number(res.rows[0]?.d ?? 0) === 0) break;
      }
    }
  }
  for (const r of await select()) {
    const key = baselineKey(r);
    if (first.has(key)) out.set(key, { ...r });
  }
  return out;
}

async function saveBaselines(tx: Tx, baselines: Map<string, BaselineRow>, touched: Set<string>): Promise<void> {
  for (const key of [...touched].sort()) {
    const b = baselines.get(key);
    if (!b) continue;
    const [agentId, targetId, pk] = key.split(SEP) as [string, string, string];
    await tx
      .update(principalBaselines)
      .set({
        events: b.events,
        meanLogRows: b.meanLogRows,
        varLogRows: b.varLogRows,
        meanLogScore: b.meanLogScore,
        varLogScore: b.varLogScore,
        rowsTotal: b.rowsTotal,
        maxScore: b.maxScore,
        anomalies: b.anomalies,
        firstEventAt: b.firstEventAt,
        lastEventAt: b.lastEventAt,
        updatedAt: sql`now()`,
      })
      .where(and(eq(principalBaselines.agentId, agentId), eq(principalBaselines.targetId, targetId), eq(principalBaselines.principalKey, pk)));
  }
}

type ApplyResult = "created" | "reopened" | "overflow_created" | "overflow" | "rematched" | "linked" | "excepted" | "no_match" | "unchanged";

interface Evaluated {
  event: PendingEvent;
  facts: EventFacts;
  objectSensitivities: number[];
}

interface LatestIncident {
  id: string;
  status: string;
  eventScore: number | null;
  eventSignals: string[] | null;
  eventAnomaly: boolean | null;
}

/** Per-chunk state: incident lookups by dedup key, and new incidents per policy in this hour. */
interface ChunkState {
  now: Date;
  hour: Date;
  cap: number;
  latest: Map<string, LatestIncident | null>;
  created: Map<string, number>;
}

async function latestIncident(tx: Tx, state: ChunkState, key: string): Promise<LatestIncident | null> {
  if (state.latest.has(key)) return state.latest.get(key) ?? null;
  const [row] = await tx
    .select({
      id: incidents.id,
      status: incidents.status,
      eventScore: incidents.eventScore,
      eventSignals: incidents.eventSignals,
      eventAnomaly: incidents.eventAnomaly,
    })
    .from(incidents)
    .where(eq(incidents.dedupKey, key))
    .orderBy(desc(incidents.createdAt), desc(incidents.id))
    .limit(1);
  state.latest.set(key, row ?? null);
  return row ?? null;
}

const capKey = (policyId: string, e: Pick<PendingEvent, "agentId" | "targetId">) => [policyId, e.agentId, e.targetId].join(SEP);

/** New (non-overflow) incidents of the policy on the event's target since the start of the hour. */
async function createdThisHour(tx: Tx, state: ChunkState, policyId: string, e: PendingEvent): Promise<number> {
  const key = capKey(policyId, e);
  const known = state.created.get(key);
  if (known !== undefined) return known;
  const [{ n } = { n: 0 }] = await tx
    .select({ n: sql<number>`count(*)::int` })
    .from(incidents)
    .where(
      and(
        eq(incidents.policyId, policyId),
        eq(incidents.agentId, e.agentId),
        eq(incidents.targetId, e.targetId),
        eq(incidents.source, "access_event"),
        eq(incidents.eventOverflow, false),
        sql`${incidents.createdAt} >= ${state.hour.toISOString()}::timestamptz`,
      ),
    );
  state.created.set(key, n);
  return n;
}

async function link(tx: Tx, incidentId: string, eventId: string): Promise<void> {
  await tx.insert(incidentEvents).values({ incidentId, eventId }).onConflictDoNothing();
}

/** Adds an event to an active incident. */
async function rematch(tx: Tx, latest: LatestIncident, e: PendingEvent, facts: EventFacts): Promise<void> {
  const signals = mergeSignals(latest.eventSignals ?? [], facts.signals);
  await tx
    .update(incidents)
    .set({
      matchCount: sql`${incidents.matchCount} + 1`,
      eventScore: sql`greatest(coalesce(${incidents.eventScore}, 0), ${facts.score}::double precision)`,
      eventRows: sql`coalesce(${incidents.eventRows}, 0) + ${e.rows ?? 0}::double precision`,
      eventSignals: signals,
      eventAnomaly: sql`coalesce(${incidents.eventAnomaly}, false) or ${facts.anomaly}`,
      lastEventAt: sql`greatest(coalesce(${incidents.lastEventAt}, ${e.ts}), ${e.ts})`,
      updatedAt: sql`now()`,
    })
    .where(eq(incidents.id, latest.id));
  latest.eventSignals = signals;
  latest.eventScore = Math.max(latest.eventScore ?? 0, facts.score);
  latest.eventAnomaly = latest.eventAnomaly === true || facts.anomaly;
  await link(tx, latest.id, e.id);
}

async function applyEventPolicy(
  tx: Tx,
  policy: LoadedEventPolicy,
  ev: Evaluated,
  exceptions: readonly EventExceptionScope[],
  state: ChunkState,
): Promise<ApplyResult> {
  const { event: e, facts } = ev;
  const kept = eventMatches(policy.conditions, facts);
  if (kept === null) return "no_match";
  if (exceptions.some((x) => exceptionCoversEvent(x, policy.id, facts, kept, state.now))) return "excepted";
  const oi = dedupObject(kept, ev.objectSensitivities);
  const database = oi === null ? null : (facts.objects[oi] as EventObject).database;
  const bucket = eventBucket(e.ts);
  const coarse = coarsePrincipal({ fingerprinted: e.dbUser === null, action: e.action });
  const key = eventDedupKey({
    policyId: policy.id,
    agentId: e.agentId,
    targetId: e.targetId,
    principalKey: coarse ? `unknown:${sha256Hex(clientNetwork(e.clientAddr))}` : e.principalKey,
    databaseKey: database === null ? "-" : sha256Hex(database),
    bucket,
  });
  const latest = await latestIncident(tx, state, key);
  if (latest && (ACTIVE_STATUSES as readonly string[]).includes(latest.status)) {
    await rematch(tx, latest, e, facts);
    return "rematched";
  }
  // M1: after a resolution, only a clearly worse event opens a new incident; otherwise the event
  // is linked to the closed incident (visible there). A false positive is only linked.
  if (latest && (latest.status !== "resolved" || !worseThanResolved(latest, facts))) {
    await link(tx, latest.id, e.id);
    return "linked";
  }
  // H1 / N1: cap of new incidents per policy, target and hour; beyond, one overflow incident of
  // the policy on that target counts the rest, except severe events, which always open their own.
  let overflow = false;
  let overflowReopenedFrom: string | null = null;
  const overflowKey = eventOverflowKey(policy.id, e.agentId, e.targetId, state.hour);
  if ((await createdThisHour(tx, state, policy.id, e)) >= state.cap) {
    const o = await latestIncident(tx, state, overflowKey);
    if (!severeEvent(facts, o?.eventScore ?? null)) {
      if (o && (ACTIVE_STATUSES as readonly string[]).includes(o.status)) {
        await rematch(tx, o, e, facts);
        return "overflow";
      }
      // A closed overflow incident: same rule as any closed incident (M1): only a worse event
      // opens a new one.
      if (o && (o.status !== "resolved" || !worseThanResolved(o, facts))) {
        await link(tx, o.id, e.id);
        return "linked";
      }
      overflow = true;
      overflowReopenedFrom = o?.id ?? null;
    }
  }
  const incidentKey = overflow ? overflowKey : key;
  const principal = overflow ? null : principalLabel(e);
  const inserted = await tx
    .insert(incidents)
    .values({
      dedupKey: incidentKey,
      source: "access_event",
      policyId: policy.id,
      policyName: policy.name,
      policyRevision: policy.revision,
      severity: policy.severity,
      notifyChannels: policy.notifyChannels,
      agentId: e.agentId,
      targetId: e.targetId,
      accessEventId: e.id,
      principal,
      eventDatabase: overflow ? null : database,
      eventBucket: overflow ? state.hour : bucket,
      eventScore: facts.score,
      eventRows: e.rows ?? 0,
      eventSignals: mergeSignals([], facts.signals),
      eventAnomaly: facts.anomaly,
      eventOverflow: overflow,
      lastEventAt: e.ts,
    })
    .onConflictDoNothing({ target: incidents.dedupKey, where: sql`${incidents.status} in ('open', 'acknowledged')` })
    .returning({ id: incidents.id });
  const row = inserted[0];
  if (!row) return "unchanged";
  state.latest.set(incidentKey, {
    id: row.id,
    status: "open",
    eventScore: facts.score,
    eventSignals: mergeSignals([], facts.signals),
    eventAnomaly: facts.anomaly,
  });
  if (!overflow) state.created.set(capKey(policy.id, e), (state.created.get(capKey(policy.id, e)) ?? 0) + 1);
  await link(tx, row.id, e.id);
  const reopenedFrom = overflow ? overflowReopenedFrom : latest?.status === "resolved" ? latest.id : null;
  await writeAudit(tx, {
    actorType: "system",
    action: "incident.create",
    targetType: "incident",
    targetId: row.id,
    details: {
      source: "access_event",
      policy_id: policy.id,
      policy_revision: policy.revision,
      access_event_id: e.id,
      agent_id: e.agentId,
      target_id: e.targetId,
      severity: policy.severity,
      overflow,
      reopened_from: reopenedFrom,
    },
  });
  const payload: AccessIncidentOpenedPayload = {
    event: "incident.opened",
    source: "access_event",
    occurred_at: state.now.toISOString(),
    url: consoleUrl(`/incidents/${row.id}`),
    incident: { id: row.id, severity: policy.severity, status: "open", reopened_from: reopenedFrom },
    policy: { id: policy.id, name: policy.name, revision: policy.revision },
    agent_id: e.agentId,
    target_id: e.targetId,
    principal: principal ?? "",
    principal_fingerprinted: e.dbUser === null,
    database: overflow ? null : database,
    hour: (overflow ? state.hour : bucket).toISOString(),
    overflow: overflow ? { limit_per_hour: state.cap } : null,
    access: {
      ts: e.ts.toISOString(),
      action: e.action,
      source: e.source,
      rows: e.rows,
      score: facts.score,
      sensitivity: facts.sensitivity,
      anomaly: facts.anomaly,
      signals: [...facts.signals],
      unregistered_signals: unregisteredSignals(facts.signals),
      objects: facts.objects.map((o) => ({ database: o.database, schema: o.schema ?? null, object: o.object })),
    },
  };
  await enqueueIncidentNotifications(tx, row.id, policy.notifyChannels, payload);
  return overflow ? "overflow_created" : reopenedFrom ? "reopened" : "created";
}

export interface EventDrainStats {
  events: number;
  created: number;
  anomalies: number;
  /** Work remains (time budget reached). */
  more: boolean;
}

/**
 * Pending events of the next chunk: at most `EVENT_CHUNK_PER_AGENT` per agent, agents interleaved
 * (round-robin on each agent's arrival order), so a busy agent never holds back the others (M2).
 * Returned in arrival order (batch reception, then position in the batch: events of one batch
 * share `received_at`), which keeps each principal's events in order for its baseline.
 */
async function pendingChunk(tx: Tx): Promise<PendingEvent[]> {
  // N5: the agents with pending events (loose index scan of `access_events_pending_idx`), then at
  // most EVENT_CHUNK_PER_AGENT events of each in arrival order (one index range per agent), never
  // a sort of the whole backlog.
  const picked = await tx.execute<{ id: string }>(sql`
    with recursive pending_agents(agent_id) as (
      (select agent_id from access_events where evaluated_at is null order by agent_id limit 1)
      union all
      select (select a.agent_id from access_events a
              where a.evaluated_at is null and a.agent_id > p.agent_id order by a.agent_id limit 1)
      from pending_agents p where p.agent_id is not null)
    select e.id from pending_agents p
    cross join lateral (
      select x.id, x.received_at, x.item_index, row_number() over (order by x.received_at, x.item_index, x.id) as rn from (
        select id, received_at, item_index from access_events
        where agent_id = p.agent_id and evaluated_at is null
        order by received_at, item_index, id
        limit ${EVENT_CHUNK_PER_AGENT}) x) e
    where p.agent_id is not null
    order by e.rn, e.received_at, e.item_index, e.id
    limit ${EVENT_CHUNK}`);
  const ids = picked.rows.map((r) => r.id);
  if (ids.length === 0) return [];
  return (await tx
    .select(PENDING_COLUMNS)
    .from(accessEvents)
    .where(and(inArray(accessEvents.id, ids), isNull(accessEvents.evaluatedAt)))
    .orderBy(asc(accessEvents.receivedAt), asc(accessEvents.itemIndex), asc(accessEvents.id))
    .for("update", { skipLocked: true })) as PendingEvent[];
}

/** Evaluates one chunk of pending events; returns the number evaluated. Exported for tests. */
export async function evaluateChunk(db: Database, stats: EventDrainStats): Promise<number> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${EVALUATION_LOCK}, 0))`);
    const events = await pendingChunk(tx);
    if (events.length === 0) return 0;
    const [{ now } = { now: new Date() }] = (await tx.execute(sql`select now() as now`)).rows as { now: Date }[];
    const nowDate = new Date(now);
    const state: ChunkState = { now: nowDate, hour: eventBucket(nowDate), cap: eventIncidentsPerPolicyHour(), latest: new Map(), created: new Map() };
    const targets = await tx
      .select({ agentId: agentTargets.agentId, targetId: agentTargets.targetId, engine: agentTargets.engine })
      .from(agentTargets)
      .where(inArray(agentTargets.agentId, [...new Set(events.map((e) => e.agentId))]));
    const engines = new Map(targets.map((t) => [`${t.agentId}${SEP}${t.targetId}`, t.engine]));
    const hits = await loadObjectHits(tx, events);
    const active = await loadEventPolicies(tx);
    const exceptions = await loadExceptions(tx);
    const baselines = await loadBaselines(tx, events);
    const touched = new Set<string>();

    for (const e of events) {
      const objectSensitivities = e.objects.map((o) => objectSensitivity(hits.get(objectKey(e.agentId, e.targetId, o)) ?? []));
      const sensitivity = objectSensitivities.reduce((m, s) => Math.max(m, s), 0);
      const score = eventScore(sensitivity, e.rows);
      const bk = baselineKey(e);
      const base = baselineEligible(e) ? baselines.get(bk) : undefined;
      const verdict = base ? baselineVerdict(base, e.rows) : { anomaly: false, baselineRows: null };
      if (base) {
        const next = updateBaseline(base, e.rows, score);
        Object.assign(base, next, {
          rowsTotal: base.rowsTotal + (e.rows ?? 0),
          maxScore: Math.max(base.maxScore, score),
          anomalies: base.anomalies + (verdict.anomaly ? 1 : 0),
          firstEventAt: base.firstEventAt === null || e.ts < base.firstEventAt ? e.ts : base.firstEventAt,
          lastEventAt: base.lastEventAt === null || e.ts > base.lastEventAt ? e.ts : base.lastEventAt,
        });
        touched.add(bk);
      }
      const facts: EventFacts = {
        agentId: e.agentId,
        targetId: e.targetId,
        engine: engines.get(`${e.agentId}${SEP}${e.targetId}`) ?? null,
        principal: principalLabel(e),
        action: e.action,
        source: e.source,
        objects: e.objects,
        rows: e.rows,
        signals: e.signals,
        sensitivity,
        score,
        anomaly: verdict.anomaly,
      };
      for (const p of active) {
        const r = await applyEventPolicy(tx, p, { event: e, facts, objectSensitivities }, exceptions, state);
        if (r === "created" || r === "reopened" || r === "overflow_created") stats.created += 1;
      }
      if (verdict.anomaly) stats.anomalies += 1;
      await tx
        .update(accessEvents)
        .set({ evaluatedAt: sql`now()`, sensitivity, score, anomaly: verdict.anomaly, baselineRows: verdict.baselineRows })
        .where(eq(accessEvents.id, e.id));
    }
    await saveBaselines(tx, baselines, touched);
    return events.length;
  });
}

/** Drains the pending access events within the deadline (epoch ms). */
export async function drainEventWork(db: Database, deadline: number): Promise<EventDrainStats> {
  const stats: EventDrainStats = { events: 0, created: 0, anomalies: 0, more: false };
  for (;;) {
    if (Date.now() > deadline) {
      stats.more = true;
      return stats;
    }
    // A chunk holds at most EVENT_CHUNK_PER_AGENT events per agent, so a short chunk does not
    // mean the backlog is empty: stop only on an empty one.
    const n = await evaluateChunk(db, stats);
    stats.events += n;
    if (n === 0) return stats;
  }
}
