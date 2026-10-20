import { and, asc, desc, eq, inArray, isNull, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { accessEvents, agentTargets, findings, incidentEvents, incidents, policies, policyExceptions, principalBaselines } from "@/db/schema";
import {
  baselineEligible,
  baselineVerdict,
  dedupPrincipal,
  eventOverflowKey,
  severeEvent,
  worseThanClosed,
  dedupObject,
  eventBucket,
  eventDedupKey,
  eventMatches,
  eventScore,
  exceptionCoversEvent,
  isOverflowStar,
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
import { auditSourceEngine } from "@/lib/location-labels";
import { logger } from "@/lib/logger";
import { dedupDatabaseName, FINAL_SIGMA, foldName, SIGMA } from "@/lib/policy-common";
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
import { processGlobal } from "./process-global";

/**
 * Correlation of Audit access events (P4-C, worker). Pending events (`evaluated_at` null) are
 * processed in arrival order, in chunks of `EVENT_CHUNK` per transaction; one transaction:
 * 1. computes each event's sensitivity (from the findings of its objects) and score, and for an
 *    event flagged `objects_overflowed` (ADR-0053) its bound sensitivity and score, from the
 *    highest object sensitivity of the database of each `*` object (`loadDatabaseBounds`, one
 *    aggregate per target and database for the whole chunk);
 * 2. judges its volume against the principal's baseline, then updates the baseline;
 * 3. applies every enabled `access_event` policy: incidents are deduplicated per policy, agent,
 *    target, principal, database and hour (src/lib/event-model.ts), linked to every matching event
 *    (`incident_events`) and notified through the outbox, in the same transaction;
 * 4. records the evaluation on the event (`evaluated_at`, `sensitivity`, `score`, `anomaly`,
 *    `baseline_rows`, `bound_sensitivity`, `bound_score`), the only columns of an event the
 *    runtime role may update.
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
  accountNotRecorded: accessEvents.accountNotRecorded,
  clientAddr: accessEvents.clientAddr,
  action: accessEvents.action,
  objects: accessEvents.objects,
  rows: accessEvents.rows,
  signals: accessEvents.signals,
  source: accessEvents.source,
  objectsOverflowed: accessEvents.objectsOverflowed,
};

type PendingEvent = {
  id: string;
  agentId: string;
  targetId: string;
  ts: Date;
  principalKey: string;
  dbUser: string | null;
  dbUserFingerprint: string | null;
  /** No recorded account (Redis / Valkey): no baseline, `unknown:*` dedup principal. */
  accountNotRecorded: boolean;
  clientAddr: string | null;
  action: string;
  objects: EventObject[];
  rows: number | null;
  signals: string[];
  source: string;
  /** Contract `AccessEvent.objects_overflowed` (ADR-0053): true when sent, else null. */
  objectsOverflowed: boolean | null;
};

const SEP = "\u0000";
/**
 * Object key of the sensitivity lookup: database, schema and object compared with `foldName`
 * (trailing spaces dropped, Unicode lowercase) on every engine (end-of-phase-9 review N1), as the
 * agent's sensitive-object match: a looser match only raises a sensitivity and a score.
 */
const objectKey = (agentId: string, targetId: string, o: EventObject) =>
  [agentId, targetId, foldName(o.database), o.schema === undefined || o.schema === null ? "*" : `=${foldName(o.schema)}`, foldName(o.object)].join(SEP);

/**
 * Whether the console database's default collation lowercases non-ASCII letters (security review
 * L1): false under a `C` / `POSIX` character type, where PostgreSQL `lower` folds ASCII only.
 */
async function lowerFoldsUnicode(tx: Tx): Promise<boolean> {
  const r = await tx.execute<{ folds: boolean }>(sql`select lower(${"\u00c9"}::text) = ${"\u00e9"}::text as folds`);
  return r.rows[0]?.folds === true;
}

/**
 * {@link lowerFoldsUnicode} once per console database and process (the character type of a
 * database cannot change): keyed by the `Database` handle, so a new pool probes again.
 */
const lowerFoldsCache = processGlobal("eventEngine.lowerFoldsUnicode", () => new WeakMap<object, boolean>());

async function cachedLowerFoldsUnicode(db: Database, tx: Tx): Promise<boolean> {
  const known = lowerFoldsCache.get(db);
  if (known !== undefined) return known;
  const folds = await lowerFoldsUnicode(tx);
  lowerFoldsCache.set(db, folds);
  return folds;
}

/** `foldName` in SQL: `replace(lower(rtrim(x)), 'ς', 'σ')`, both letters bound as parameters. */
const sqlFold = (x: SQL) => sql`replace(lower(rtrim(${x})), ${FINAL_SIGMA}::text, ${SIGMA}::text)`;

/**
 * The name pre-filter of `loadObjectHits`:
 * - `fold`: when the database's `lower` folds Unicode: every event name and its `foldName`, both
 *   compared through `sqlFold`;
 * - `ascii`: when the database's `lower` folds ASCII only (`C` / `POSIX` ctype; security review
 *   L1), for every chunk (PR #274 review L2: a finding whose non-ASCII name folds to ASCII in
 *   JavaScript, such as the Kelvin sign `K` in `Kunden`, also matches an ASCII event name). The
 *   SQL `lower` is then exact on ASCII names only:
 *   the pre-filter keeps the findings whose ASCII name, through `sqlFold`, equals the
 *   JavaScript `foldName` of an event name (`folded`), and every finding whose name holds a
 *   non-ASCII character, left to `objectKey` (JavaScript `foldName`) to decide. Together with the
 *   chunk's (agent, target) pairs this replaces the read of every finding of the chunk's agents
 *   (phase 9 follow-up after N1).
 */
export type NamePrefilter = { kind: "fold"; names: string[] } | { kind: "ascii"; folded: string[] };

export function prefilterNames(objectNames: readonly string[], unicodeLower: boolean): NamePrefilter {
  if (!unicodeLower) return { kind: "ascii", folded: [...new Set(objectNames.map(foldName))] };
  return { kind: "fold", names: [...new Set(objectNames.flatMap((n) => [n, foldName(n)]))] };
}

/** A character outside U+0001..U+007F (a byte above 0x7F under `SQL_ASCII`), as a regex parameter. */
const NON_ASCII_RE = "[^\\x01-\\x7f]";

/**
 * Findings (false positives excluded) of the objects reached by `events`, by object key: the
 * schema (`=<schema>`), and `*` for any schema (events whose source logs no schema).
 *
 * The SQL pre-filter compares `sqlFold(object_name)` with `sqlFold(name)` for each event name and
 * for its `foldName`, so both sides go through the same PostgreSQL `lower` and the pre-filter
 * keeps every finding whose object name differs by case or trailing spaces; `objectKey` then
 * decides. PostgreSQL folds non-ASCII letters only under a UTF-8 character type (deploy/README.md:
 * the console database needs one, as the images' `en_US.utf8`); under `C` / `POSIX` every chunk
 * uses the `ascii` pre-filter of {@link prefilterNames}, restricted to the chunk's (agent, target)
 * pairs. `unicodeLower`: the probe's answer when the caller has it (cached), else probed here. No index covers `object_name`, so the expression costs no index.
 * Exported for the tests (event-engine-c-locale.test.ts).
 */
export async function loadObjectHits(
  tx: Tx,
  events: readonly Pick<PendingEvent, "agentId" | "targetId" | "objects">[],
  unicodeLower?: boolean,
): Promise<Map<string, ClassifierHit[]>> {
  const agentIds = [...new Set(events.map((e) => e.agentId))];
  const objectNames = [...new Set(events.flatMap((e) => e.objects.map((o) => o.object)))];
  const out = new Map<string, ClassifierHit[]>();
  if (objectNames.length === 0) return out;
  const pre = prefilterNames(objectNames, unicodeLower ?? (await lowerFoldsUnicode(tx)));
  let sameName: SQL;
  if (pre.kind === "fold") {
    sameName = sql`${sqlFold(sql`${findings.objectName}`)} in (${sql.join(
      pre.names.map((n) => sqlFold(sql`${n}::text`)),
      sql`, `,
    )})`;
  } else {
    const pairs = [...new Map(events.map((e) => [targetKey(e), [e.agentId, e.targetId] as const])).values()];
    sameName = sql`(${findings.agentId}, ${findings.targetId}) in (${sql.join(
      pairs.map(([a, t]) => sql`(${a}::uuid, ${t}::text)`),
      sql`, `,
    )}) and (${sqlFold(sql`${findings.objectName}`)} in (${sql.join(
      pre.folded.map((n) => sql`${n}::text`),
      sql`, `,
    )}) or ${findings.objectName} ~ ${NON_ASCII_RE}::text)`;
  }
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
    .where(and(isNull(findings.falsePositiveAt), inArray(findings.agentId, agentIds), sameName))
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

/** Key of a database bound: agent, target and the `foldName` of the database (`*`: the target). */
const databaseKey = (agentId: string, targetId: string, database: string) => [agentId, targetId, foldName(database)].join(SEP);
const wholeTargetKey = (agentId: string, targetId: string) => [agentId, targetId, ""].join(SEP);

/**
 * Highest object sensitivities per target and database, for the overflow `*` objects of the
 * chunk (ADR-0053 decision 3 item 3): `get(agentId, targetId, database)` is the highest object
 * sensitivity among the target's findings (false positives excluded) in that database, compared
 * with `foldName` as `objectKey` does, or among all the target's findings for the database `*`;
 * 0 when there is none.
 */
export interface DatabaseBounds {
  get(agentId: string, targetId: string, database: string): number;
}

const NO_BOUNDS: DatabaseBounds = { get: () => 0 };

/**
 * Loads the {@link DatabaseBounds} the chunk needs: nothing (no query) when no event of the chunk
 * is flagged with a `*` object, so a chunk without the flag reads exactly what it read before.
 * One aggregate query per chunk, always restricted to the (agent, target) pairs of the flagged
 * events (a bound never reads another target's findings) and, except for the database `*`, to
 * their databases through the same pre-filter as `loadObjectHits`: `sqlFold` when the console
 * database's `lower` folds Unicode, else the ASCII form and every non-ASCII database name, left to
 * the JavaScript `foldName` (the `C` / `POSIX`-ctype fallback). The rows are grouped per database,
 * object name and classifier in SQL and folded in JavaScript, so both paths give the same result.
 *
 * An object's sensitivity here takes its findings in every schema (as an event object without a
 * schema does, `loadObjectHits`), so the bound is at least the named sensitivity any object of the
 * database could get, whatever schema the left-out objects had (fail closed: only higher).
 *
 * The database `*` needs every finding of its target (ADR-0053 security review L1): with `cache`,
 * the bounds of a whole target are kept per process and reused while the target's findings stamp
 * ({@link findingsStamp}, one aggregate row per target, read in the same transaction) is unchanged,
 * so a target's findings are read again only after a scan, a new finding, a false-positive change
 * or a removal. Exported for the tests.
 */
export async function loadDatabaseBounds(
  tx: Tx,
  events: readonly Pick<PendingEvent, "agentId" | "targetId" | "objects" | "objectsOverflowed">[],
  unicodeLower?: boolean,
  cache?: WholeTargetCache,
): Promise<DatabaseBounds> {
  const whole = new Map<string, readonly [string, string]>();
  const perDb = new Map<string, readonly [string, string]>();
  const names = new Set<string>();
  for (const e of events) {
    for (const o of e.objects) {
      if (!isOverflowStar(e, o)) continue;
      const pair = [e.agentId, e.targetId] as const;
      if (o.database === "*") whole.set(targetKey(e), pair);
      else {
        perDb.set(targetKey(e), pair);
        names.add(o.database);
      }
    }
  }
  if (whole.size === 0 && perDb.size === 0) return NO_BOUNDS;
  const bounds = new Map<string, number>();
  // Whole targets whose cached bounds are still current: served from the cache, not read.
  const fresh = new Map<string, string>();
  if (cache && whole.size > 0) {
    const stamps = await findingsStamps(tx, [...whole.values()]);
    for (const k of [...whole.keys()]) {
      const stamp = stamps.get(k) ?? "0";
      const hit = cache.get(k);
      if (hit && hit.stamp === stamp) {
        for (const [bk, v] of hit.bounds) bounds.set(bk, v);
        whole.delete(k);
        // Its databases are known too: no per-database read for this target.
        perDb.delete(k);
      } else {
        fresh.set(k, stamp);
      }
    }
    if (whole.size === 0 && perDb.size === 0) return boundsOf(bounds);
  }
  const pairsIn = (pairs: Iterable<readonly [string, string]>) =>
    sql`(${findings.agentId}, ${findings.targetId}) in (${sql.join(
      [...pairs].map(([a, t]) => sql`(${a}::uuid, ${t}::text)`),
      sql`, `,
    )})`;
  const scopes: SQL[] = [];
  if (whole.size > 0) scopes.push(pairsIn(whole.values()));
  const dbPairs = [...perDb.entries()].filter(([k]) => !whole.has(k)).map(([, p]) => p);
  if (dbPairs.length > 0) {
    const pre = prefilterNames([...names], unicodeLower ?? (await lowerFoldsUnicode(tx)));
    const sameDb =
      pre.kind === "fold"
        ? sql`${sqlFold(sql`${findings.databaseName}`)} in (${sql.join(
            pre.names.map((n) => sqlFold(sql`${n}::text`)),
            sql`, `,
          )})`
        : sql`(${sqlFold(sql`${findings.databaseName}`)} in (${sql.join(
            pre.folded.map((n) => sql`${n}::text`),
            sql`, `,
          )}) or ${findings.databaseName} ~ ${NON_ASCII_RE}::text)`;
    scopes.push(sql`(${pairsIn(dbPairs)} and ${sameDb})`);
  }
  // One statement, so one snapshot (ADR-0053 re-review N2): the grouped rows and, for the whole
  // targets to cache, their stamp over the same rows. The stamp checked before (statement 1) only
  // decides whether to read; the cache keeps the stamp of what was read.
  const stamped = cache && fresh.size > 0 ? [...fresh.keys()].map((k) => whole.get(k) as readonly [string, string]) : [];
  const res = await tx.execute<{
    kind: "g" | "s";
    agent_id: string;
    target_id: string;
    database_name: string | null;
    object_name: string | null;
    classifier: string | null;
    confidence: number | null;
    stamp: string | null;
  }>(sql`
    with base as (
      select agent_id, target_id, database_name, object_name, classifier, confidence, id, false_positive_at
      from findings where (${sql.join(scopes, sql` or `)}))
    select 'g' as kind, agent_id, target_id, database_name, object_name, classifier, max(confidence)::float8 as confidence, null::text as stamp
    from base where false_positive_at is null
    group by agent_id, target_id, database_name, object_name, classifier
    ${
      stamped.length > 0
        ? sql`union all
    select 's', agent_id, target_id, null, null, null, null, ${STAMP_SQL}
    from base where (agent_id, target_id) in (${sql.join(
      stamped.map(([a, t]) => sql`(${a}::uuid, ${t}::text)`),
      sql`, `,
    )})
    group by agent_id, target_id`
        : sql``
    }`);
  const readStamps = new Map<string, string>();
  const rows: { agentId: string; targetId: string; databaseName: string; objectName: string; classifier: string; confidence: number }[] = [];
  for (const r of res.rows) {
    if (r.kind === "s") readStamps.set(targetKey({ agentId: r.agent_id, targetId: r.target_id }), String(r.stamp));
    else {
      rows.push({
        agentId: r.agent_id,
        targetId: r.target_id,
        databaseName: String(r.database_name),
        objectName: String(r.object_name),
        classifier: String(r.classifier),
        confidence: Number(r.confidence),
      });
    }
  }
  // Hits per object (database and object folded, any schema), then the highest per database.
  const objects = new Map<string, { db: string; target: string; hits: ClassifierHit[] }>();
  for (const r of rows) {
    const db = databaseKey(r.agentId, r.targetId, r.databaseName);
    const key = [db, foldName(r.objectName)].join(SEP);
    const entry = objects.get(key) ?? { db, target: targetKey(r), hits: [] };
    entry.hits.push({ classifier: r.classifier, confidence: Number(r.confidence) });
    objects.set(key, entry);
  }
  const raise = (k: string, v: number) => bounds.set(k, Math.max(bounds.get(k) ?? 0, v));
  const perTarget = new Map<string, Map<string, number>>();
  for (const o of objects.values()) {
    const s = objectSensitivity(o.hits);
    raise(o.db, s);
    const pair = whole.get(o.target);
    if (pair) {
      raise(wholeTargetKey(...pair), s);
      const m = perTarget.get(o.target) ?? new Map<string, number>();
      m.set(o.db, Math.max(m.get(o.db) ?? 0, s));
      m.set(wholeTargetKey(...pair), Math.max(m.get(wholeTargetKey(...pair)) ?? 0, s));
      perTarget.set(o.target, m);
    }
  }
  if (cache) for (const k of fresh.keys()) cache.set(k, { stamp: readStamps.get(k) ?? "0", bounds: perTarget.get(k) ?? new Map() });
  return boundsOf(bounds);
}

function boundsOf(bounds: ReadonlyMap<string, number>): DatabaseBounds {
  return {
    get: (agentId, targetId, database) =>
      bounds.get(database === "*" ? wholeTargetKey(agentId, targetId) : databaseKey(agentId, targetId, database)) ?? 0,
  };
}

/** Cached whole-target bounds, by {@link targetKey}: the findings stamp they were read at. */
export interface WholeTargetCache {
  get(key: string): { stamp: string; bounds: ReadonlyMap<string, number> } | undefined;
  set(key: string, value: { stamp: string; bounds: ReadonlyMap<string, number> }): void;
}

/** At most this many targets in a process's whole-target cache (the oldest entry goes first). */
export const WHOLE_TARGET_CACHE_MAX = 1024;

/** A bounded {@link WholeTargetCache} (insertion order: a refreshed entry moves last). */
export function boundedWholeTargetCache(max = WHOLE_TARGET_CACHE_MAX): WholeTargetCache {
  const m = new Map<string, { stamp: string; bounds: ReadonlyMap<string, number> }>();
  return {
    get: (k) => m.get(k),
    set: (k, v) => {
      m.delete(k);
      m.set(k, v);
      while (m.size > max) m.delete(m.keys().next().value as string);
    },
  };
}

/**
 * Stamp of each target's findings, by {@link targetKey}: the number of rows and two order-free
 * sums of 64-bit hashes (two seeds) of what the bound reads of each row: its id (which fixes its
 * database, object and classifier, `location_key`), its confidence and whether it is a false
 * positive. Any insert, removal, confidence change or false-positive change changes it, whatever
 * the commit order of concurrent scans (timestamps would not: `now()` is a transaction's start).
 * One row per target; a target without findings has none ("0").
 */
const STAMP_SQL = sql.raw(`concat_ws('|', count(*),
             sum(hashtextextended(id::text || ':' || confidence::text || ':' || (false_positive_at is null)::text, 1)::numeric),
             sum(hashtextextended(id::text || ':' || confidence::text || ':' || (false_positive_at is null)::text, 2)::numeric))`);

async function findingsStamps(tx: Tx, pairs: readonly (readonly [string, string])[]): Promise<Map<string, string>> {
  const r = await tx.execute<{ agent_id: string; target_id: string; stamp: string }>(sql`
    select agent_id, target_id, ${STAMP_SQL} as stamp
    from findings
    where (agent_id, target_id) in (${sql.join(
      pairs.map(([a, t]) => sql`(${a}::uuid, ${t}::text)`),
      sql`, `,
    )})
    group by agent_id, target_id`);
  return new Map(r.rows.map((row) => [targetKey({ agentId: row.agent_id, targetId: row.target_id }), row.stamp]));
}

/** Per console database and process (the worker): keyed by the `Database` handle. */
const wholeTargetCaches = processGlobal("eventEngine.wholeTargetBounds", () => new WeakMap<object, WholeTargetCache>());

function wholeTargetCacheOf(db: Database): WholeTargetCache {
  let c = wholeTargetCaches.get(db);
  if (!c) {
    c = boundedWholeTargetCache();
    wholeTargetCaches.set(db, c);
  }
  return c;
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
  /**
   * Bound sensitivity of each object (ADR-0053): the named one, raised to its database's bound
   * for an overflow `*`. Sets the dedup object (decision 3 item 4).
   */
  objectSensitivities: number[];
  /** Named sensitivity of each object (ADR-0053 review M1: the dedup scope without the bound). */
  namedSensitivities: number[];
}

interface LatestIncident {
  id: string;
  status: string;
  eventScore: number | null;
  eventSignals: string[] | null;
  eventAnomaly: boolean | null;
  eventRows: number | null;
  /**
   * False positive only: rows of the events linked to it since it was marked (ADR-0031 decision
   * 2, anti-splitting), kept up to date by `linkClosed` within the chunk.
   */
  rowsSinceFalsePositive: number;
}

/** Per-chunk state: incident lookups by dedup key, and new incidents per policy in this hour. */
interface ChunkState {
  now: Date;
  hour: Date;
  cap: number;
  latest: Map<string, LatestIncident | null>;
  created: Map<string, number>;
}

/**
 * Rows of the events linked to a false-positive incident since it was marked (0 for another
 * status). Table-qualified on purpose: an unqualified "id" in the subquery would resolve to ae.id.
 */
function rowsSinceFalsePositiveSql() {
  return sql<number>`case when incidents.status = 'false_positive' then coalesce((
      select sum(ae.rows) from incident_events ie join access_events ae on ae.id = ie.event_id
      where ie.incident_id = incidents.id and ie.created_at >= incidents.false_positive_at), 0) else 0 end::double precision`;
}

/**
 * The latest incident of `key`. `legacyKey`: the key of the same event before trailing spaces were
 * dropped from the database name (ADR-0021 implementation note of 2026-10-18), given only when it
 * differs. Incidents
 * opened by an earlier console under it are found too, an active one first, so an incident of the
 * hour of the upgrade keeps collecting its events instead of a second one opening.
 */
async function latestIncident(tx: Tx, state: ChunkState, key: string, legacyKey: string | null = null): Promise<LatestIncident | null> {
  if (state.latest.has(key)) return state.latest.get(key) ?? null;
  const keys = legacyKey === null || legacyKey === key ? [key] : [key, legacyKey];
  const [row] = await tx
    .select({
      id: incidents.id,
      status: incidents.status,
      eventScore: incidents.eventScore,
      eventSignals: incidents.eventSignals,
      eventAnomaly: incidents.eventAnomaly,
      eventRows: incidents.eventRows,
      rowsSinceFalsePositive: rowsSinceFalsePositiveSql(),
    })
    .from(incidents)
    .where(keys.length === 1 ? eq(incidents.dedupKey, key) : inArray(incidents.dedupKey, keys))
    .orderBy(
      ...(keys.length === 1 ? [] : [desc(sql`${incidents.status} in ('open', 'acknowledged')`)]),
      desc(incidents.createdAt),
      desc(incidents.id),
    )
    .limit(1);
  const latest = row ? { ...row, rowsSinceFalsePositive: Number(row.rowsSinceFalsePositive) } : null;
  state.latest.set(key, latest);
  return latest;
}

/** Whether `e` opens a new incident after the closed incident `closed` of its key (M1, ADR-0031). */
function worseThanClosedIncident(closed: LatestIncident, e: PendingEvent, facts: EventFacts): boolean {
  const rows = closed.status === "false_positive" ? closed.rowsSinceFalsePositive + (e.rows ?? 0) : 0;
  return worseThanClosed(closed, facts, rows);
}

/** Links an event to a closed incident (not worse), counting its rows after a false positive. */
async function linkClosed(tx: Tx, closed: LatestIncident, e: PendingEvent): Promise<void> {
  if (closed.status === "false_positive") closed.rowsSinceFalsePositive += e.rows ?? 0;
  await link(tx, closed.id, e.id);
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

/**
 * Links an event to an incident. `created_at` is the wall clock of the insert, not the transaction
 * start (`now()`): the rows linked after a false-positive mark are counted from it (ADR-0031
 * decision 2), and a chunk transaction that started before a concurrent mark links after it (PR #81
 * security review L1).
 */
async function link(tx: Tx, incidentId: string, eventId: string): Promise<void> {
  await tx.insert(incidentEvents).values({ incidentId, eventId, createdAt: sql`clock_timestamp()` }).onConflictDoNothing();
}

/**
 * Adds an event to an active incident. Only while it is still active (PR #81 security review L1):
 * when a user closed it after the chunk read it (the update waits for that transaction, then
 * re-checks the status), the event is only linked to it, as to any closed incident, and the
 * cached state is refreshed for the next events of the chunk.
 */
async function rematch(tx: Tx, latest: LatestIncident, e: PendingEvent, facts: EventFacts): Promise<void> {
  const signals = mergeSignals(latest.eventSignals ?? [], facts.signals);
  const updated = await tx
    .update(incidents)
    .set({
      matchCount: sql`${incidents.matchCount} + 1`,
      eventScore: sql`greatest(coalesce(${incidents.eventScore}, 0), ${facts.score}::double precision)`,
      eventRows: sql`coalesce(${incidents.eventRows}, 0) + ${e.rows ?? 0}::double precision`,
      eventSignals: signals,
      eventAnomaly: sql`coalesce(${incidents.eventAnomaly}, false) or ${facts.anomaly}`,
      // ADR-0053 decision 3 item 4: display only, never read back by the comparisons.
      ...overflowColumns(facts),
      lastEventAt: sql`greatest(coalesce(${incidents.lastEventAt}, ${e.ts}), ${e.ts})`,
      updatedAt: sql`now()`,
    })
    .where(and(eq(incidents.id, latest.id), inArray(incidents.status, ["open", "acknowledged"])))
    .returning({ id: incidents.id });
  if (updated.length === 0) {
    const [now] = await tx
      .select({
        status: incidents.status,
        rowsSinceFalsePositive: rowsSinceFalsePositiveSql(),
      })
      .from(incidents)
      .where(eq(incidents.id, latest.id));
    latest.status = now?.status ?? "resolved";
    latest.rowsSinceFalsePositive = Number(now?.rowsSinceFalsePositive ?? 0);
    await linkClosed(tx, latest, e);
    return;
  }
  latest.eventSignals = signals;
  latest.eventScore = Math.max(latest.eventScore ?? 0, facts.score);
  latest.eventAnomaly = latest.eventAnomaly === true || facts.anomaly;
  latest.eventRows = (latest.eventRows ?? 0) + (e.rows ?? 0);
  await link(tx, latest.id, e.id);
}

/**
 * The incident columns of ADR-0053 updated when an event joins an active incident: the highest
 * bound score (from `event_score` on an incident opened before ADR-0053; equal to it while no
 * flagged event joined) and the flag, set once a flagged event joins. Display only: no comparison
 * reads them back (review H1 of ADR-0053).
 */
function overflowColumns(facts: EventFacts) {
  const eventBoundScore = sql`greatest(coalesce(${incidents.eventBoundScore}, ${incidents.eventScore}, 0), ${facts.boundScore ?? facts.score}::double precision)`;
  return facts.objectsOverflowed === true ? { eventBoundScore, eventObjectsOverflowed: true } : { eventBoundScore };
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
  const bucket = eventBucket(e.ts);
  // ADR-0021 decision 6, implementation note of 2026-10-18 (PR #274 review M1): the database part
  // keeps the case as sent and drops trailing spaces only on the engines that ignore them.
  const keyOf = (databaseKey: string) =>
    eventDedupKey({
      policyId: policy.id,
      agentId: e.agentId,
      targetId: e.targetId,
      principalKey: dedupPrincipal({
        action: e.action,
        principalKey: e.principalKey,
        networkHash: sha256Hex(clientNetwork(e.clientAddr)),
        accountNotRecorded: e.accountNotRecorded,
        clientAddr: e.clientAddr,
      }),
      databaseKey,
      bucket,
    });
  const scopeOf = (sensitivities: readonly number[]) => {
    const oi = dedupObject(kept, sensitivities);
    const database = oi === null ? null : (facts.objects[oi] as EventObject).database;
    const keyed = database === null ? null : dedupDatabaseName(database, facts.engine);
    const key = keyOf(keyed === null ? "-" : sha256Hex(keyed));
    // Consoles before the note hashed the name as sent: only a name with trailing spaces on such an
    // engine has another key, looked up so an incident open across the upgrade keeps its events.
    const legacyKey = database === null || keyed === database ? null : keyOf(sha256Hex(database));
    return { database, key, legacyKey };
  };
  // ADR-0053 decision 3 item 4: the dedup object is chosen on the bound sensitivities.
  const bound = scopeOf(ev.objectSensitivities);
  let { database, key } = bound;
  let latest = await latestIncident(tx, state, key, bound.legacyKey);
  if (latest && (ACTIVE_STATUSES as readonly string[]).includes(latest.status)) {
    await rematch(tx, latest, e, facts);
    return "rematched";
  }
  // M1: after a resolution or a false positive, only a clearly worse event opens a new incident
  // (`worseThanClosed`); otherwise the event is linked to the closed incident (visible there).
  if (latest && !worseThanClosedIncident(latest, e, facts)) {
    // ADR-0053 security review M1 (fail closed): when the bound moved the scope to another
    // database (an overflow `*`) whose closed incident would absorb the event, the scope of the
    // named objects decides too: its active incident collects the event, and without an incident
    // there, or with a closed one the event is worse than, an incident opens under it. The bound
    // never makes a flagged event less visible than it would be without the flag.
    const named = scopeOf(ev.namedSensitivities);
    if (named.key === key) {
      await linkClosed(tx, latest, e);
      return "linked";
    }
    const namedLatest = await latestIncident(tx, state, named.key, named.legacyKey);
    if (namedLatest && (ACTIVE_STATUSES as readonly string[]).includes(namedLatest.status)) {
      await rematch(tx, namedLatest, e, facts);
      return "rematched";
    }
    if (namedLatest && !worseThanClosedIncident(namedLatest, e, facts)) {
      // Re-review N1: linked to both closed incidents, so the named scope's false positive keeps
      // counting the rows linked since it was marked (ADR-0031 decision 2, anti-splitting).
      await linkClosed(tx, latest, e);
      await linkClosed(tx, namedLatest, e);
      return "linked";
    }
    ({ database, key } = named);
    latest = namedLatest;
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
      if (o && !worseThanClosedIncident(o, e, facts)) {
        await linkClosed(tx, o, e);
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
      eventObjectsOverflowed: facts.objectsOverflowed === true ? true : null,
      eventBoundScore: facts.boundScore ?? facts.score,
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
    eventRows: e.rows ?? 0,
    rowsSinceFalsePositive: 0,
  });
  if (!overflow) state.created.set(capKey(policy.id, e), (state.created.get(capKey(policy.id, e)) ?? 0) + 1);
  await link(tx, row.id, e.id);
  const reopenedFrom = overflow ? overflowReopenedFrom : latest && !(ACTIVE_STATUSES as readonly string[]).includes(latest.status) ? latest.id : null;
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
    principal_fingerprinted: e.dbUserFingerprint !== null,
    principal_not_recorded: !overflow && e.accountNotRecorded,
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
      // ADR-0053 decision 3 item 7: the event reached more objects than it lists.
      objects_overflowed: facts.objectsOverflowed === true,
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
    const unicodeLower = await cachedLowerFoldsUnicode(db, tx);
    const hits = await loadObjectHits(tx, events, unicodeLower);
    const bounds = await loadDatabaseBounds(tx, events, unicodeLower, wholeTargetCacheOf(db));
    const active = await loadEventPolicies(tx);
    const exceptions = await loadExceptions(tx);
    const baselines = await loadBaselines(tx, events);
    const touched = new Set<string>();

    for (const e of events) {
      const objectSensitivities = e.objects.map((o) => objectSensitivity(hits.get(objectKey(e.agentId, e.targetId, o)) ?? []));
      const sensitivity = objectSensitivities.reduce((m, s) => Math.max(m, s), 0);
      const score = eventScore(sensitivity, e.rows);
      // ADR-0053 decision 3 item 3: the bound; the named values for an event without the flag.
      const boundSensitivities = objectSensitivities.map((s, i) => {
        const o = e.objects[i] as EventObject;
        return isOverflowStar(e, o) ? Math.max(s, bounds.get(e.agentId, e.targetId, o.database)) : s;
      });
      const boundSensitivity = boundSensitivities.reduce((m, s) => Math.max(m, s), 0);
      const boundScore = eventScore(boundSensitivity, e.rows);
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
        // The engine the source tells (checked against the target at ingest), else the target's
        // current one (security review L1 of ADR-0054: a target's engine may change after ingest).
        engine: auditSourceEngine(e.source) ?? engines.get(`${e.agentId}${SEP}${e.targetId}`) ?? null,
        principal: principalLabel(e),
        accountNotRecorded: e.accountNotRecorded,
        action: e.action,
        source: e.source,
        objects: e.objects,
        rows: e.rows,
        signals: e.signals,
        sensitivity,
        score,
        objectsOverflowed: e.objectsOverflowed === true,
        boundSensitivity,
        boundScore,
        anomaly: verdict.anomaly,
      };
      for (const p of active) {
        const r = await applyEventPolicy(tx, p, { event: e, facts, objectSensitivities: boundSensitivities, namedSensitivities: objectSensitivities }, exceptions, state);
        if (r === "created" || r === "reopened" || r === "overflow_created") stats.created += 1;
      }
      if (verdict.anomaly) stats.anomalies += 1;
      await tx
        .update(accessEvents)
        .set({ evaluatedAt: sql`now()`, sensitivity, score, boundSensitivity, boundScore, anomaly: verdict.anomaly, baselineRows: verdict.baselineRows })
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
