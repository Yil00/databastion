import { and, desc, eq, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { auditLog, policyExceptions } from "@/db/schema";
import { objectMatches, type EventObject } from "@/lib/event-model";
import { errorSummary, type Logger } from "@/lib/logger";
import { CASE_BLIND_EXCEPTION_ENGINES, exceptionGlobOptions, exceptionMatchesCase, UUID } from "@/lib/policy-common";
import { classifierSelected, locationMatches, type FindingFacts, type LocationPattern } from "@/lib/policy-model";

import { writeAudit } from "./audit";
import { eventsRetentionDays } from "./events";

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

/**
 * Inventory of the location exceptions whose effect changed with ADR-0054 (decision 6): the active
 * exceptions with a location that cover, compared without case but not with case, at least one
 * stored finding (false positives included) or one access event within the event retention of a
 * target whose engine compares names with case (`exceptionMatchesCase`).
 *
 * - The comparison is the console's JavaScript one (`globMatch` with and without `matchCase`, through
 *   `locationMatches` / `objectMatches`), so a console database with a `C` / `POSIX` ctype gives
 *   the result of a UTF-8 one. SQL only groups the stored rows into distinct names (exact `=` and
 *   `GROUP BY`, which fold nothing) and counts them.
 * - It compares distinct (agent, target, database, schema, object, field, classifier) names of the
 *   findings and distinct (agent, target, database, schema, object) names of the event objects,
 *   at most `NAMES_BOUND` of each per run: a run that reaches the bound says so
 *   (`boundReached`) and counts only what it compared.
 * - The findings count of an exception is the number of findings whose name it no longer covers;
 *   the events count, the number of events holding at least one object it no longer covers.
 * - Ran by the worker at its first start after the upgrade (no earlier inventory in the audit log),
 *   and on demand by an administrator from the policies page. The result is recorded in one audit
 *   entry (`policy_exception.case_inventory`) and the log with exception ids and counts only, never
 *   a glob or a name; the policies page reads the latest entry.
 *
 * The exception's policy scope is not considered: the inventory names the exceptions, whatever the
 * policies that would match the item.
 */

export const NAMES_BOUND = 20_000;
/** (exception, event name) pairs counted per run; past it the run reports `boundReached`. */
export const PAIRS_BOUND = 100_000;
/** Exceptions listed in the audit entry and the log (the count of all of them is always given). */
export const MAX_LISTED = 100;
const STATEMENT_TIMEOUT_MS = 120_000;
const LOCK_KEY = "policy_exception.case_inventory";

export interface InventoryException {
  id: string;
  agentId: string | null;
  targetId: string | null;
  classifier: string | null;
  location: LocationPattern | null;
  expiresAt: Date | null;
}

export interface FindingNameGroup {
  agentId: string;
  targetId: string;
  engine: string;
  databaseName: string;
  schemaName: string | null;
  objectName: string;
  fieldName: string;
  classifier: string;
  n: number;
}

export interface EventNameGroup {
  agentId: string;
  targetId: string;
  /** Engine of the target as last reported (null: unknown, compared with case). */
  engine: string | null;
  database: string;
  schema: string | null;
  object: string;
}

export interface InventoryEntry {
  exceptionId: string;
  findings: number;
  events: number;
}

export interface InventoryResult {
  entries: InventoryEntry[];
  findingNamesCompared: number;
  eventNamesCompared: number;
  boundReached: boolean;
}

const active = (x: InventoryException, now: Date) => x.location !== null && (x.expiresAt === null || x.expiresAt.getTime() > now.getTime());

/** Whether the location exception covers the finding name without case but not with case. */
export function findingCaseChange(x: InventoryException, g: FindingNameGroup): boolean {
  if (x.location === null || !exceptionMatchesCase(g.engine)) return false;
  if (x.agentId !== null && x.agentId !== g.agentId) return false;
  if (x.targetId !== null && x.targetId !== g.targetId) return false;
  if (x.classifier !== null && !classifierSelected([x.classifier], g.classifier)) return false;
  const strict = exceptionGlobOptions(g.engine);
  const f: FindingFacts = { ...g, confidence: 0, sampled: 0, matched: 0 };
  return locationMatches(x.location, f, { ...strict, matchCase: false }) && !locationMatches(x.location, f, strict);
}

/**
 * Whether the location exception covers the event object without case but not with case. Only
 * exceptions that can cover an event count (no classifier, no `field` glob other than `*`,
 * `exceptionCoversEvent`).
 */
export function eventCaseChange(x: InventoryException, g: EventNameGroup): boolean {
  if (x.location === null || !exceptionMatchesCase(g.engine)) return false;
  if (x.classifier !== null) return false;
  if (x.agentId !== null && x.agentId !== g.agentId) return false;
  if (x.targetId !== null && x.targetId !== g.targetId) return false;
  const { field, ...parts } = x.location;
  if (field !== undefined && field !== "*") return false;
  const o: EventObject = g.schema === null ? { database: g.database, object: g.object } : { database: g.database, schema: g.schema, object: g.object };
  const strict = exceptionGlobOptions(g.engine);
  return objectMatches(parts, o, { ...strict, matchCase: false }) && !objectMatches(parts, o, strict);
}

/**
 * The pure part of the inventory: per active location exception, the findings it no longer
 * covers (summed over the groups) and the event names it no longer covers (counted by the caller).
 */
export function compareNames(
  exceptions: readonly InventoryException[],
  findingGroups: readonly FindingNameGroup[],
  eventGroups: readonly EventNameGroup[],
  now: Date,
): { findings: Map<string, number>; eventNames: Map<string, EventNameGroup[]> } {
  const findings = new Map<string, number>();
  const eventNames = new Map<string, EventNameGroup[]>();
  for (const x of exceptions) {
    if (!active(x, now)) continue;
    let n = 0;
    for (const g of findingGroups) if (findingCaseChange(x, g)) n += g.n;
    if (n > 0) findings.set(x.id, n);
    const names = eventGroups.filter((g) => eventCaseChange(x, g));
    if (names.length > 0) eventNames.set(x.id, names);
  }
  return { findings, eventNames };
}

async function loadExceptions(tx: Tx): Promise<InventoryException[]> {
  const rows = await tx
    .select({
      id: policyExceptions.id,
      agentId: policyExceptions.agentId,
      targetId: policyExceptions.targetId,
      classifier: policyExceptions.classifier,
      location: policyExceptions.location,
      expiresAt: policyExceptions.expiresAt,
    })
    .from(policyExceptions)
    .where(sql`${policyExceptions.location} is not null`);
  return rows.map((r) => ({ ...r, location: (r.location as LocationPattern | null) ?? null }));
}

/** Rows of an engine that compares names with case (null: unknown, with case); bound parameters. */
const caseSensitiveEngine = (engine: SQL) =>
  sql`(${engine} is null or ${engine} not in (${sql.join(
    CASE_BLIND_EXCEPTION_ENGINES.map((e) => sql`${e}::text`),
    sql`, `,
  )}))`;

async function findingGroups(tx: Tx, bound: number): Promise<FindingNameGroup[]> {
  const res = await tx.execute<{
    agent_id: string;
    target_id: string;
    engine: string;
    database_name: string;
    schema_name: string | null;
    object_name: string;
    field_name: string;
    classifier: string;
    n: number;
  }>(sql`
    select f.agent_id, f.target_id, f.engine, f.database_name, f.schema_name, f.object_name, f.field_name, f.classifier,
      count(*)::int as n
    from findings f
    where ${caseSensitiveEngine(sql`f.engine`)}
    group by 1, 2, 3, 4, 5, 6, 7, 8
    order by 1, 2, 3, 4, 5, 6, 7, 8
    limit ${bound + 1}`);
  return res.rows.map((r) => ({
    agentId: r.agent_id,
    targetId: r.target_id,
    engine: r.engine,
    databaseName: r.database_name,
    schemaName: r.schema_name,
    objectName: r.object_name,
    fieldName: r.field_name,
    classifier: r.classifier,
    n: Number(r.n),
  }));
}

async function eventGroups(tx: Tx, bound: number, retentionDays: number): Promise<EventNameGroup[]> {
  const res = await tx.execute<{ agent_id: string; target_id: string; engine: string | null; database: string; schema: string | null; object: string }>(sql`
    select e.agent_id, e.target_id, t.engine, o->>'database' as database, o->>'schema' as schema, o->>'object' as object
    from access_events e
    left join agent_targets t on t.agent_id = e.agent_id and t.target_id = e.target_id
    cross join lateral jsonb_array_elements(e.objects) o
    where e.ts >= now() - make_interval(days => ${retentionDays}::int) and ${caseSensitiveEngine(sql`t.engine`)}
    group by 1, 2, 3, 4, 5, 6
    order by 1, 2, 3, 4, 5, 6
    limit ${bound + 1}`);
  return res.rows
    .filter((r) => typeof r.database === "string" && typeof r.object === "string")
    .map((r) => ({ agentId: r.agent_id, targetId: r.target_id, engine: r.engine, database: r.database, schema: r.schema, object: r.object }));
}

/** Events holding at least one of the listed names, per exception (exact `=`, one scan). */
async function countEvents(tx: Tx, names: Map<string, EventNameGroup[]>, retentionDays: number): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const pairs = [...names].filter(([, gs]) => gs.length > 0).flatMap(([x, gs]) =>
    gs.map((g) => ({ x, agent_id: g.agentId, target_id: g.targetId, database: g.database, schema: g.schema, object: g.object })),
  );
  if (pairs.length === 0) return out;
  const res = await tx.execute<{ x: string; n: number }>(sql`
    select p.x, count(distinct e.id)::int as n
    from access_events e
    cross join lateral jsonb_array_elements(e.objects) o
    join jsonb_to_recordset(${JSON.stringify(pairs)}::jsonb) as p(x uuid, agent_id uuid, target_id text, database text, schema text, object text)
      on p.agent_id = e.agent_id and p.target_id = e.target_id
      and p.database = o->>'database' and p.schema is not distinct from o->>'schema' and p.object = o->>'object'
    where e.ts >= now() - make_interval(days => ${retentionDays}::int)
    group by p.x`);
  for (const r of res.rows) out.set(String(r.x), Number(r.n));
  return out;
}

/** Computes the inventory in `tx` (read-only; bounded per run). */
export async function computeCaseInventory(
  tx: Tx,
  opts: { now?: Date; bound?: number; retentionDays?: number } = {},
): Promise<InventoryResult> {
  const now = opts.now ?? new Date();
  const bound = opts.bound ?? NAMES_BOUND;
  const retentionDays = opts.retentionDays ?? eventsRetentionDays();
  const exceptions = await loadExceptions(tx);
  if (!exceptions.some((x) => active(x, now))) return { entries: [], findingNamesCompared: 0, eventNamesCompared: 0, boundReached: false };
  const fg = await findingGroups(tx, bound);
  const eg = await eventGroups(tx, bound, retentionDays);
  const boundReached = fg.length > bound || eg.length > bound;
  const fCompared = fg.slice(0, bound);
  const eCompared = eg.slice(0, bound);
  const { findings, eventNames } = compareNames(exceptions, fCompared, eCompared, now);
  let pairs = 0;
  let pairsCut = false;
  for (const [x, names] of eventNames) {
    if (pairs + names.length > PAIRS_BOUND) {
      eventNames.set(x, names.slice(0, Math.max(0, PAIRS_BOUND - pairs)));
      pairsCut = true;
    }
    pairs += eventNames.get(x)?.length ?? 0;
  }
  const events = await countEvents(tx, eventNames, retentionDays);
  // An exception whose event names were cut by the pairs bound stays listed (`boundReached`).
  const ids = new Set([...findings.keys(), ...eventNames.keys(), ...events.keys()]);
  const entries = exceptions
    .filter((x) => ids.has(x.id))
    .map((x) => ({ exceptionId: x.id, findings: findings.get(x.id) ?? 0, events: events.get(x.id) ?? 0 }))
    .sort((a, b) => b.findings + b.events - (a.findings + a.events) || a.exceptionId.localeCompare(b.exceptionId));
  return { entries, findingNamesCompared: fCompared.length, eventNamesCompared: eCompared.length, boundReached: boundReached || pairsCut };
}

/** Audit / log details: exception ids and counts only (`<id>:<findings>:<events>`, space-separated). */
export function inventoryDetails(r: InventoryResult, trigger: "startup" | "user"): Record<string, string | number | boolean> {
  return {
    trigger,
    exceptions_listed: r.entries.length,
    exceptions: r.entries
      .slice(0, MAX_LISTED)
      .map((e) => `${e.exceptionId}:${e.findings}:${e.events}`)
      .join(" "),
    exceptions_truncated: r.entries.length > MAX_LISTED,
    finding_names_compared: r.findingNamesCompared,
    event_names_compared: r.eventNamesCompared,
    names_bound: NAMES_BOUND,
    bound_reached: r.boundReached,
  };
}

async function runLocked(
  db: Database,
  fn: (tx: Tx) => Promise<InventoryResult | null>,
): Promise<InventoryResult | null> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${LOCK_KEY}, 0))`);
    await tx.execute(sql.raw(`set local statement_timeout = ${STATEMENT_TIMEOUT_MS}`));
    return fn(tx);
  });
}

/**
 * At the worker's start: runs the inventory once, when the audit log holds none yet (the first
 * start after the upgrade to ADR-0054). Never throws; a failed run is retried at the next start.
 */
export async function runStartupCaseInventory(db: Database, log: Logger, opts: { bound?: number } = {}): Promise<InventoryResult | null> {
  try {
    const r = await runLocked(db, async (tx) => {
      const [done] = await tx.select({ id: auditLog.id }).from(auditLog).where(eq(auditLog.action, "policy_exception.case_inventory")).limit(1);
      if (done) return null;
      const res = await computeCaseInventory(tx, opts);
      await writeAudit(tx, { actorType: "system", action: "policy_exception.case_inventory", targetType: "policy_exception", details: inventoryDetails(res, "startup") });
      return res;
    });
    if (r !== null) logInventory(log, r, "startup");
    return r;
  } catch (err) {
    log.warn({ error: errorSummary(err) }, "case-sensitive exception inventory failed (retried at the next start)");
    return null;
  }
}

/** On demand (administrator, policies page): runs the inventory and audits it. */
export async function runCaseInventory(db: Database, log: Logger, actor: { userId: string; ip: string | null }): Promise<InventoryResult> {
  const r = await runLocked(db, async (tx) => {
    const res = await computeCaseInventory(tx);
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "policy_exception.case_inventory",
      targetType: "policy_exception",
      sourceIp: actor.ip,
      details: inventoryDetails(res, "user"),
    });
    return res;
  });
  if (r === null) throw new Error("inventory not run");
  logInventory(log, r, "user");
  return r;
}

function logInventory(log: Logger, r: InventoryResult, trigger: "startup" | "user"): void {
  const details = inventoryDetails(r, trigger);
  if (r.entries.length > 0 || r.boundReached) {
    log.warn(details, "location exceptions that no longer cover names differing by case only (ADR-0054): review them on the policies page");
  } else {
    log.info(details, "case-sensitive exception inventory: no exception affected (ADR-0054)");
  }
}

export interface LatestInventory {
  at: Date;
  trigger: string;
  entries: InventoryEntry[];
  exceptionsListed: number;
  truncated: boolean;
  findingNamesCompared: number;
  eventNamesCompared: number;
  boundReached: boolean;
}

/** The latest inventory, read back from its audit entry (null: none yet). */
export async function latestCaseInventory(db: Database): Promise<LatestInventory | null> {
  const [row] = await db
    .select({ at: auditLog.at, details: auditLog.details })
    .from(auditLog)
    .where(and(eq(auditLog.action, "policy_exception.case_inventory"), eq(auditLog.outcome, "success")))
    .orderBy(desc(auditLog.at), desc(auditLog.id))
    .limit(1);
  if (!row) return null;
  return parseInventoryDetails(row.at, row.details ?? {});
}

export function parseInventoryDetails(at: Date, d: Record<string, unknown>): LatestInventory {
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0);
  const entries: InventoryEntry[] = [];
  for (const item of typeof d.exceptions === "string" ? d.exceptions.split(" ") : []) {
    const [id, f, e] = item.split(":");
    if (id === undefined || !UUID.test(id)) continue;
    entries.push({ exceptionId: id, findings: num(Number(f)), events: num(Number(e)) });
  }
  return {
    at,
    trigger: d.trigger === "user" ? "user" : "startup",
    entries,
    exceptionsListed: num(d.exceptions_listed),
    truncated: d.exceptions_truncated === true,
    findingNamesCompared: num(d.finding_names_compared),
    eventNamesCompared: num(d.event_names_compared),
    boundReached: d.bound_reached === true,
  };
}
