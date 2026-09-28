import { and, asc, desc, eq, inArray, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { accessEvents, agentTargets, findings, incidentEvents, incidents, policies, policyExceptions, principalBaselines } from "@/db/schema";
import {
  baselineVerdict,
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
import { principalLabel } from "./events";
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
    const conditions = parseEventConditions(r.conditions);
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

async function loadBaselines(tx: Tx, events: readonly PendingEvent[]): Promise<Map<string, BaselineRow>> {
  const first = new Map<string, PendingEvent>();
  for (const e of events) if (!first.has(baselineKey(e))) first.set(baselineKey(e), e);
  await tx
    .insert(principalBaselines)
    .values(
      [...first.values()].map((e) => ({
        agentId: e.agentId,
        targetId: e.targetId,
        principalKey: e.principalKey,
        dbUser: e.dbUser,
        dbUserFingerprint: e.dbUserFingerprint,
      })),
    )
    .onConflictDoNothing();
  const rows = await tx
    .select()
    .from(principalBaselines)
    .where(
      and(
        inArray(principalBaselines.agentId, [...new Set(events.map((e) => e.agentId))]),
        inArray(principalBaselines.principalKey, [...new Set(events.map((e) => e.principalKey))]),
      ),
    );
  const out = new Map<string, BaselineRow>();
  for (const r of rows) {
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

type ApplyResult = "created" | "rematched" | "suppressed" | "excepted" | "no_match" | "unchanged";

interface Evaluated {
  event: PendingEvent;
  facts: EventFacts;
  objectSensitivities: number[];
}

async function applyEventPolicy(
  tx: Tx,
  policy: LoadedEventPolicy,
  ev: Evaluated,
  exceptions: readonly EventExceptionScope[],
  now: Date,
): Promise<ApplyResult> {
  const { event: e, facts } = ev;
  const kept = eventMatches(policy.conditions, facts);
  if (kept === null) return "no_match";
  if (exceptions.some((x) => exceptionCoversEvent(x, policy.id, facts, kept, now))) return "excepted";
  const oi = dedupObject(kept, ev.objectSensitivities);
  const database = oi === null ? null : (facts.objects[oi] as EventObject).database;
  const bucket = eventBucket(e.ts);
  const key = eventDedupKey({
    policyId: policy.id,
    agentId: e.agentId,
    targetId: e.targetId,
    principalKey: e.principalKey,
    databaseKey: database === null ? "-" : sha256Hex(database),
    bucket,
  });
  const [latest] = await tx
    .select({ id: incidents.id, status: incidents.status, eventSignals: incidents.eventSignals })
    .from(incidents)
    .where(eq(incidents.dedupKey, key))
    .orderBy(desc(incidents.createdAt), desc(incidents.id))
    .limit(1);
  const rows = e.rows ?? 0;
  if (latest && (ACTIVE_STATUSES as readonly string[]).includes(latest.status)) {
    await tx
      .update(incidents)
      .set({
        matchCount: sql`${incidents.matchCount} + 1`,
        eventScore: sql`greatest(coalesce(${incidents.eventScore}, 0), ${facts.score}::double precision)`,
        eventRows: sql`coalesce(${incidents.eventRows}, 0) + ${rows}::double precision`,
        eventSignals: mergeSignals(latest.eventSignals ?? [], facts.signals),
        lastEventAt: sql`greatest(coalesce(${incidents.lastEventAt}, ${e.ts}), ${e.ts})`,
        updatedAt: sql`now()`,
      })
      .where(eq(incidents.id, latest.id));
    await tx.insert(incidentEvents).values({ incidentId: latest.id, eventId: e.id }).onConflictDoNothing();
    return "rematched";
  }
  // Resolved or false positive: the rest of this scope (policy, principal, database, hour) is
  // considered handled; the next hour opens a new incident.
  if (latest) return "suppressed";
  const principal = principalLabel(e);
  const inserted = await tx
    .insert(incidents)
    .values({
      dedupKey: key,
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
      eventDatabase: database,
      eventBucket: bucket,
      eventScore: facts.score,
      eventRows: rows,
      eventSignals: mergeSignals([], facts.signals),
      lastEventAt: e.ts,
    })
    .onConflictDoNothing({ target: incidents.dedupKey, where: sql`${incidents.status} in ('open', 'acknowledged')` })
    .returning({ id: incidents.id });
  const row = inserted[0];
  if (!row) return "unchanged";
  await tx.insert(incidentEvents).values({ incidentId: row.id, eventId: e.id }).onConflictDoNothing();
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
    },
  });
  const payload: AccessIncidentOpenedPayload = {
    event: "incident.opened",
    source: "access_event",
    occurred_at: now.toISOString(),
    url: consoleUrl(`/incidents/${row.id}`),
    incident: { id: row.id, severity: policy.severity, status: "open", reopened_from: null },
    policy: { id: policy.id, name: policy.name, revision: policy.revision },
    agent_id: e.agentId,
    target_id: e.targetId,
    principal,
    principal_fingerprinted: e.dbUser === null,
    database,
    hour: bucket.toISOString(),
    access: {
      ts: e.ts.toISOString(),
      action: e.action,
      source: e.source,
      rows: e.rows,
      score: facts.score,
      sensitivity: facts.sensitivity,
      anomaly: facts.anomaly,
      signals: [...facts.signals],
      objects: facts.objects.map((o) => ({ database: o.database, schema: o.schema ?? null, object: o.object })),
    },
  };
  await enqueueIncidentNotifications(tx, row.id, policy.notifyChannels, payload);
  return "created";
}

export interface EventDrainStats {
  events: number;
  created: number;
  anomalies: number;
  /** Work remains (time budget reached). */
  more: boolean;
}

/** Evaluates one chunk of pending events; returns the number evaluated. */
async function evaluateChunk(db: Database, stats: EventDrainStats): Promise<number> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${EVALUATION_LOCK}, 0))`);
    const events = (await tx
      .select(PENDING_COLUMNS)
      .from(accessEvents)
      .where(isNull(accessEvents.evaluatedAt))
      .orderBy(asc(accessEvents.receivedAt), asc(accessEvents.id))
      .limit(EVENT_CHUNK)
      .for("update", { skipLocked: true })) as PendingEvent[];
    if (events.length === 0) return 0;
    const [{ now } = { now: new Date() }] = (await tx.execute(sql`select now() as now`)).rows as { now: Date }[];
    const nowDate = new Date(now);
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
      const base = baselines.get(bk);
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
        const r = await applyEventPolicy(tx, p, { event: e, facts, objectSensitivities }, exceptions, nowDate);
        if (r === "created") stats.created += 1;
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
    const n = await evaluateChunk(db, stats);
    stats.events += n;
    if (n < EVENT_CHUNK) return stats;
  }
}
