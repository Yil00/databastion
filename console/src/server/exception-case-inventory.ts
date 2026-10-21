import { and, asc, desc, eq, sql, type SQL } from "drizzle-orm";

import type { Database } from "@/db/client";
import { auditLog, policyExceptions } from "@/db/schema";
import { objectMatches, type EventObject } from "@/lib/event-model";
import { auditSourceEngine, auditSourceTable } from "@/lib/location-labels";
import { errorSummary, type Logger } from "@/lib/logger";
import { anyWithCase, canonicalNameCase, exceptionPartOptions, withoutCase, type NameCaseRule } from "@/lib/name-case";
import { CASE_BLIND_EXCEPTION_ENGINES, exceptionMatchesCase, UUID, type PartGlobOptions } from "@/lib/policy-common";
import { classifierSelected, locationMatches, type FindingFacts, type LocationPattern } from "@/lib/policy-model";

import { writeAudit } from "./audit";
import type { CaseInventoryJob } from "./case-inventory-queue";
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
 * - The comparison is bounded too (`COMPARISON_BUDGET` exception x name evaluations, each at
 *   most 8 `globMatch` calls) and yields to the event loop between exceptions; a run that reaches
 *   it says so (`boundReached`).
 * - Counts are upper bounds (security review L2): the findings count of an exception is the number
 *   of findings whose name it no longer covers, the events count the number of events holding at
 *   least one object it no longer covers; another exception may still cover them, and an event
 *   with other objects may still raise nothing.
 * - The engine of an event is the one its source tells (`auditSourceEngine`, checked at ingest),
 *   else its target's (security review L1).
 * - Targets whose agent reports `name_case` (ADR-0055 decision 7) are compared too, with the rule
 *   they report (`exceptionPartOptions`): an exception counts when it covers a name of such a target
 *   without case but not under that rule. Their stored `name_case` is read at the run.
 * - Ran by the worker only: at its first start after the upgrade (no successful inventory in the
 *   audit log yet), on demand through the `policy_exceptions.case_inventory` queue, which an
 *   administrator fills from the policies page (security review M1), and for one target when its
 *   `name_case` changed (src/server/name-case-inventory.ts, debounced, audited apart). The result is recorded in one
 *   audit entry (`policy_exception.case_inventory`) and the log with exception ids and counts only,
 *   never a glob or a name; a failed run in a failure entry with an error code only (L3). The
 *   policies page reads the latest entries.
 *
 * The exception's policy scope is not considered: the inventory names the exceptions, whatever the
 * policies that would match the item.
 */

export const NAMES_BOUND = 20_000;
/** (exception, event name) pairs counted per run; past it the run reports `boundReached`. */
export const PAIRS_BOUND = 100_000;
/** Exceptions listed in the audit entry and the log (the count of all of them is always given). */
export const MAX_LISTED = 100;
/** Exception x name evaluations per run (each at most 8 `globMatch` calls: <= 2 * 10^7). */
export const COMPARISON_BUDGET = 2_500_000;
const STATEMENT_TIMEOUT_MS = 120_000;
const LOCK_TIMEOUT_MS = 5_000;
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
  /** The target's stored `name_case` (ADR-0055), canonical; null or absent: not reported. */
  nameCase?: NameCaseRule | null;
}

export interface EventNameGroup {
  agentId: string;
  targetId: string;
  /** Engine told by the event source, else the target's (null: unknown, compared with case). */
  engine: string | null;
  database: string;
  schema: string | null;
  object: string;
  /** The target's stored `name_case` (ADR-0055), canonical; null or absent: not reported. */
  nameCase?: NameCaseRule | null;
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
  /** Active location exceptions compared, of all of them (fewer when the budget ran out). */
  exceptionsCompared: number;
  exceptionsTotal: number;
  boundReached: boolean;
}

const active = (x: InventoryException, now: Date) => x.location !== null && (x.expiresAt === null || x.expiresAt.getTime() > now.getTime());

/** Options of a name group, computed once per group (each is compared with every exception). */
const optionsCache = new WeakMap<object, { strict: PartGlobOptions; loose: PartGlobOptions }>();
function groupOptions(g: { engine: string | null; nameCase?: NameCaseRule | null }, database: string): { strict: PartGlobOptions; loose: PartGlobOptions } {
  let o = optionsCache.get(g);
  if (o === undefined) {
    const strict = exceptionPartOptions(g.engine, g.nameCase ?? null, database);
    o = { strict, loose: withoutCase(strict) };
    optionsCache.set(g, o);
  }
  return o;
}

/**
 * Whether the location exception covers the finding name without case but not with the rule of
 * its engine and target (with case per ADR-0054, per part per the target's `name_case`, ADR-0055).
 */
export function findingCaseChange(x: InventoryException, g: FindingNameGroup): boolean {
  if (x.location === null) return false;
  const { strict, loose } = groupOptions(g, g.databaseName);
  if (!anyWithCase(strict)) return false;
  if (x.agentId !== null && x.agentId !== g.agentId) return false;
  if (x.targetId !== null && x.targetId !== g.targetId) return false;
  if (x.classifier !== null && !classifierSelected([x.classifier], g.classifier)) return false;
  const f: FindingFacts = { ...g, confidence: 0, sampled: 0, matched: 0 };
  return locationMatches(x.location, f, loose) && !locationMatches(x.location, f, strict);
}

/**
 * Whether the location exception covers the event object without case but not with case. Only
 * exceptions that can cover an event count (no classifier, no `field` glob other than `*`,
 * `exceptionCoversEvent`).
 */
export function eventCaseChange(x: InventoryException, g: EventNameGroup): boolean {
  if (x.location === null) return false;
  const { strict, loose } = groupOptions(g, g.database);
  if (!anyWithCase(strict, ["database", "schema", "object"])) return false;
  if (x.classifier !== null) return false;
  if (x.agentId !== null && x.agentId !== g.agentId) return false;
  if (x.targetId !== null && x.targetId !== g.targetId) return false;
  const { field, ...parts } = x.location;
  if (field !== undefined && field !== "*") return false;
  const o: EventObject = g.schema === null ? { database: g.database, object: g.object } : { database: g.database, schema: g.schema, object: g.object };
  return objectMatches(parts, o, loose) && !objectMatches(parts, o, strict);
}

const yieldToEventLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

/** Groups indexed by agent, target and both, for the agent / target scope of an exception. */
function scopeIndex<G extends { agentId: string; targetId: string }>(groups: readonly G[]) {
  const by = new Map<string, G[]>();
  const add = (k: string, g: G) => {
    const list = by.get(k);
    if (list) list.push(g);
    else by.set(k, [g]);
  };
  for (const g of groups) {
    add(`a\0${g.agentId}`, g);
    add(`t\0${g.targetId}`, g);
    add(`at\0${g.agentId}\0${g.targetId}`, g);
  }
  return (x: InventoryException): readonly G[] =>
    x.agentId === null && x.targetId === null
      ? groups
      : (by.get(x.agentId === null ? `t\0${x.targetId}` : x.targetId === null ? `a\0${x.agentId}` : `at\0${x.agentId}\0${x.targetId}`) ?? []);
}

export interface CompareResult {
  findings: Map<string, number>;
  eventNames: Map<string, EventNameGroup[]>;
  budgetReached: boolean;
  /** Active location exceptions compared, and all of them (security re-review N1). */
  exceptionsCompared: number;
  exceptionsTotal: number;
}

/**
 * The pure part of the inventory: per active location exception, the findings it no longer
 * covers (summed over the groups) and the event names it no longer covers (counted by the caller).
 * Each exception is charged the names in its agent / target scope only; at most `budget`
 * evaluations, in the order given (oldest exception first, `loadExceptions`): when the budget
 * runs out the remaining (newest) exceptions are left out and counted. Yields to the event loop
 * between exceptions.
 */
export async function compareNames(
  exceptions: readonly InventoryException[],
  findingGroups: readonly FindingNameGroup[],
  eventGroups: readonly EventNameGroup[],
  now: Date,
  budget = COMPARISON_BUDGET,
): Promise<CompareResult> {
  const findings = new Map<string, number>();
  const eventNames = new Map<string, EventNameGroup[]>();
  const activeOnes = exceptions.filter((x) => active(x, now));
  const findingScope = scopeIndex(findingGroups);
  const eventScope = scopeIndex(eventGroups);
  let left = budget;
  let compared = 0;
  for (const x of activeOnes) {
    const fs = findingScope(x);
    const es = eventScope(x);
    const cost = fs.length + es.length;
    if (cost > left) return { findings, eventNames, budgetReached: true, exceptionsCompared: compared, exceptionsTotal: activeOnes.length };
    left -= cost;
    compared += 1;
    let n = 0;
    for (const g of fs) if (findingCaseChange(x, g)) n += g.n;
    if (n > 0) findings.set(x.id, n);
    const names = es.filter((g) => eventCaseChange(x, g));
    if (names.length > 0) eventNames.set(x.id, names);
    await yieldToEventLoop();
  }
  return { findings, eventNames, budgetReached: false, exceptionsCompared: compared, exceptionsTotal: activeOnes.length };
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
    .where(sql`${policyExceptions.location} is not null`)
    // Deterministic order: when the comparison budget runs out, the newest are left out (N1).
    .orderBy(asc(policyExceptions.createdAt), asc(policyExceptions.id));
  return rows.map((r) => ({ ...r, location: (r.location as LocationPattern | null) ?? null }));
}

/** Rows of an engine that compares names with case (null: unknown, with case); bound parameters. */
const caseSensitiveEngine = (engine: SQL) =>
  sql`(${engine} is null or ${engine} not in (${sql.join(
    CASE_BLIND_EXCEPTION_ENGINES.map((e) => sql`${e}::text`),
    sql`, `,
  )}))`;

/** One target of an inventory run (ADR-0055 decision 7), or every target. */
export interface InventoryScope {
  agentId: string;
  targetId: string;
}

/** Rows of the scoped target only (`alias` holds `agent_id` and `target_id`); bound parameters. */
const inScope = (alias: string, scope: InventoryScope | undefined): SQL =>
  scope === undefined ? sql`true` : sql`(${sql.raw(alias)}.agent_id = ${scope.agentId}::uuid and ${sql.raw(alias)}.target_id = ${scope.targetId}::text)`;

async function findingGroups(tx: Tx, bound: number, scope?: InventoryScope): Promise<FindingNameGroup[]> {
  const res = await tx.execute<{
    agent_id: string;
    target_id: string;
    engine: string;
    database_name: string;
    schema_name: string | null;
    object_name: string;
    field_name: string;
    classifier: string;
    name_case: unknown;
    n: number;
  }>(sql`
    select f.agent_id, f.target_id, f.engine, f.database_name, f.schema_name, f.object_name, f.field_name, f.classifier,
      t.name_case, count(*)::int as n
    from findings f
    left join agent_targets t on t.agent_id = f.agent_id and t.target_id = f.target_id
    where (${caseSensitiveEngine(sql`f.engine`)} or t.name_case is not null) and ${inScope("f", scope)}
    group by 1, 2, 3, 4, 5, 6, 7, 8, 9
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
    nameCase: canonicalNameCase(r.name_case),
  }));
}

/**
 * Event rows whose engine compares names with case: the engine the source tells when it tells one
 * (MySQL / MariaDB and Redis / Valkey sources serve engines of one kind), else the target's.
 */
function caseSensitiveEvent(): SQL {
  const table = auditSourceTable();
  const list = (sources: readonly string[]) => sql.join(sources.map((x) => sql`${x}::text`), sql`, `);
  const blind = table.filter(([, engines]) => engines.every((e) => !exceptionMatchesCase(e))).map(([x]) => x);
  // ADR-0055: a target reporting `name_case` is compared with its rule, whatever the source.
  return sql`((e.source not in (${list(blind)}) and (e.source in (${list(table.map(([x]) => x))}) or ${caseSensitiveEngine(sql`t.engine`)})) or t.name_case is not null)`;
}

async function eventGroups(tx: Tx, bound: number, retentionDays: number, scope?: InventoryScope): Promise<EventNameGroup[]> {
  const res = await tx.execute<{
    agent_id: string;
    target_id: string;
    source: string;
    engine: string | null;
    database: string;
    schema: string | null;
    object: string;
    name_case: unknown;
  }>(sql`
    select e.agent_id, e.target_id, e.source, t.engine, o->>'database' as database, o->>'schema' as schema, o->>'object' as object,
      t.name_case
    from access_events e
    left join agent_targets t on t.agent_id = e.agent_id and t.target_id = e.target_id
    cross join lateral jsonb_array_elements(e.objects) o
    where e.ts >= now() - make_interval(days => ${retentionDays}::int) and ${caseSensitiveEvent()} and ${inScope("e", scope)}
    group by 1, 2, 3, 4, 5, 6, 7, 8
    order by 1, 2, 3, 4, 5, 6, 7
    limit ${bound + 1}`);
  return res.rows
    .filter((r) => typeof r.database === "string" && typeof r.object === "string")
    .map((r) => ({
      agentId: r.agent_id,
      targetId: r.target_id,
      engine: auditSourceEngine(r.source) ?? r.engine,
      database: r.database,
      schema: r.schema,
      object: r.object,
      nameCase: canonicalNameCase(r.name_case),
    }));
}

/** Events holding at least one of the listed names, per exception (exact `=`, one scan). */
async function countEvents(tx: Tx, names: Map<string, EventNameGroup[]>, retentionDays: number): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  // The same name may come from groups of two sources: one pair per (exception, name).
  const seen = new Set<string>();
  const pairs = [...names]
    .flatMap(([x, gs]) => gs.map((g) => ({ x, agent_id: g.agentId, target_id: g.targetId, database: g.database, schema: g.schema, object: g.object })))
    .filter((p) => {
      const k = JSON.stringify(p);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  if (pairs.length === 0) return out;
  const res = await tx.execute<{ x: string; n: number }>(sql`
    select p.x, count(distinct e.id)::int as n
    from access_events e
    left join agent_targets t on t.agent_id = e.agent_id and t.target_id = e.target_id
    cross join lateral jsonb_array_elements(e.objects) o
    join jsonb_to_recordset(${JSON.stringify(pairs)}::jsonb) as p(x uuid, agent_id uuid, target_id text, database text, schema text, object text)
      on p.agent_id = e.agent_id and p.target_id = e.target_id
      and p.database = o->>'database' and p.schema is not distinct from o->>'schema' and p.object = o->>'object'
    where e.ts >= now() - make_interval(days => ${retentionDays}::int) and ${caseSensitiveEvent()}
    group by p.x`);
  for (const r of res.rows) out.set(String(r.x), Number(r.n));
  return out;
}

/** Computes the inventory in `tx` (read-only; bounded per run). */
export async function computeCaseInventory(
  tx: Tx,
  opts: { now?: Date; bound?: number; retentionDays?: number; comparisonBudget?: number; scope?: InventoryScope } = {},
): Promise<InventoryResult> {
  const now = opts.now ?? new Date();
  const bound = opts.bound ?? NAMES_BOUND;
  const retentionDays = opts.retentionDays ?? eventsRetentionDays();
  const exceptions = await loadExceptions(tx);
  if (!exceptions.some((x) => active(x, now))) {
    return { entries: [], findingNamesCompared: 0, eventNamesCompared: 0, exceptionsCompared: 0, exceptionsTotal: 0, boundReached: false };
  }
  const fg = await findingGroups(tx, bound, opts.scope);
  const eg = await eventGroups(tx, bound, retentionDays, opts.scope);
  const boundReached = fg.length > bound || eg.length > bound;
  const fCompared = fg.slice(0, bound);
  const eCompared = eg.slice(0, bound);
  const { findings, eventNames, budgetReached, exceptionsCompared, exceptionsTotal } = await compareNames(exceptions, fCompared, eCompared, now, opts.comparisonBudget);
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
  return {
    entries,
    findingNamesCompared: fCompared.length,
    eventNamesCompared: eCompared.length,
    exceptionsCompared,
    exceptionsTotal,
    boundReached: boundReached || pairsCut || budgetReached,
  };
}

/** Audit / log details: exception ids and counts only (`<id>:<findings>:<events>`, space-separated). */
export function inventoryDetails(r: InventoryResult, trigger: Trigger): Record<string, string | number | boolean> {
  return {
    trigger,
    exceptions_listed: r.entries.length,
    exceptions: r.entries
      .slice(0, MAX_LISTED)
      .map((e) => `${e.exceptionId}:${e.findings}:${e.events}`)
      .join(" "),
    exceptions_truncated: r.entries.length > MAX_LISTED,
    finding_names_compared: r.findingNamesCompared,
    exceptions_compared: r.exceptionsCompared,
    exceptions_total: r.exceptionsTotal,
    event_names_compared: r.eventNamesCompared,
    names_bound: NAMES_BOUND,
    bound_reached: r.boundReached,
  };
}

/** `name_case`: the run of one target whose `name_case` changed (ADR-0055 decision 7). */
export type Trigger = "startup" | "user" | "name_case";

/**
 * Runs `fn` in a transaction under the inventory's advisory lock, taken without waiting
 * (`"busy"` when another run holds it); `lock_timeout` and `statement_timeout` are set first, so
 * no statement of the run waits or runs unbounded (security review M1).
 */
export async function runLocked(db: Database, fn: (tx: Tx) => Promise<InventoryResult | null>): Promise<InventoryResult | null | "busy"> {
  return db.transaction(async (tx) => {
    await tx.execute(sql.raw(`set local lock_timeout = ${LOCK_TIMEOUT_MS}`));
    await tx.execute(sql.raw(`set local statement_timeout = ${STATEMENT_TIMEOUT_MS}`));
    const res = await tx.execute<{ locked: boolean }>(sql`select pg_try_advisory_xact_lock(hashtextextended(${LOCK_KEY}, 0)) as locked`);
    if (res.rows[0]?.locked !== true) return "busy";
    return fn(tx);
  });
}

/**
 * A failed run: one failure audit entry with an error code only (security review L3). The
 * `actor_id` column is plain text (no foreign key), so a removed user is still named.
 */
export async function recordCaseInventoryFailure(db: Database, log: Logger, trigger: Trigger, actor: CaseInventoryJob | null, code: string): Promise<void> {
  log.warn({ trigger, error_code: code }, "case-sensitive exception inventory failed");
  try {
    await writeAudit(db, {
      actorType: actor ? "user" : "system",
      actorId: actor?.userId ?? null,
      action: "policy_exception.case_inventory",
      outcome: "failure",
      targetType: "policy_exception",
      sourceIp: actor?.ip ?? null,
      details: { trigger, error_code: code },
    });
  } catch (err) {
    log.warn({ error: errorSummary(err) }, "case-sensitive exception inventory failure not audited");
  }
}

/** SQLSTATE of a database error, else `internal`: never a message (it may quote a name). */
export const errorCode = (err: unknown) => errorSummary(err).code ?? "internal";

/**
 * At the worker's start: runs the inventory once, when the audit log holds no successful one yet
 * (the first start after the upgrade to ADR-0054). Never throws; a failed run is audited and
 * retried at the next start.
 */
export async function runStartupCaseInventory(
  db: Database,
  log: Logger,
  opts: { bound?: number; comparisonBudget?: number } = {},
): Promise<InventoryResult | null> {
  try {
    const r = await runLocked(db, async (tx) => {
      const [done] = await tx
        .select({ id: auditLog.id })
        .from(auditLog)
        .where(and(eq(auditLog.action, "policy_exception.case_inventory"), eq(auditLog.outcome, "success")))
        .limit(1);
      if (done) return null;
      const res = await computeCaseInventory(tx, opts);
      await writeAudit(tx, { actorType: "system", action: "policy_exception.case_inventory", targetType: "policy_exception", details: inventoryDetails(res, "startup") });
      return res;
    });
    // Another run holds the lock: it records its own result.
    if (r === "busy" || r === null) return null;
    logInventory(log, r, "startup");
    return r;
  } catch (err) {
    await recordCaseInventoryFailure(db, log, "startup", null, errorCode(err));
    return null;
  }
}

/**
 * On demand (worker, `policy_exceptions.case_inventory` job queued by an administrator): runs the
 * inventory and audits it as the administrator's action. Never throws: a failure, or another run
 * in progress (`inventory_running`), is audited as a failure and not retried.
 */
export async function runCaseInventory(
  db: Database,
  log: Logger,
  actor: CaseInventoryJob,
  opts: { bound?: number; comparisonBudget?: number } = {},
): Promise<InventoryResult | null> {
  try {
    const r = await runLocked(db, async (tx) => {
      const res = await computeCaseInventory(tx, opts);
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
    if (r === "busy" || r === null) {
      await recordCaseInventoryFailure(db, log, "user", actor, "inventory_running");
      return null;
    }
    logInventory(log, r, "user");
    return r;
  } catch (err) {
    await recordCaseInventoryFailure(db, log, "user", actor, errorCode(err));
    return null;
  }
}

function logInventory(log: Logger, r: InventoryResult, trigger: Trigger): void {
  const details = inventoryDetails(r, trigger);
  if (r.entries.length > 0 || r.boundReached) {
    log.warn(details, "location exceptions that no longer cover names differing by case only (ADR-0054): review them on the policies page");
  } else {
    log.info(details, "case-sensitive exception inventory: no exception affected (ADR-0054)");
  }
}

export interface InventoryFailure {
  at: Date;
  trigger: string;
  errorCode: string;
}

export interface CaseInventoryStatus {
  latest: LatestInventory | null;
  /** The latest failed run, when more recent than the latest successful one. */
  failure: InventoryFailure | null;
}

export interface LatestInventory {
  at: Date;
  trigger: string;
  entries: InventoryEntry[];
  exceptionsListed: number;
  truncated: boolean;
  findingNamesCompared: number;
  eventNamesCompared: number;
  /** Active location exceptions compared, of all of them (fewer when the budget ran out). */
  exceptionsCompared: number;
  exceptionsTotal: number;
  boundReached: boolean;
}

/** The latest inventory, read back from its audit entry (null: none yet), and a later failure. */
export async function caseInventoryStatus(db: Database): Promise<CaseInventoryStatus> {
  const latestOf = (outcome: "success" | "failure") =>
    db
      .select({ at: auditLog.at, details: auditLog.details })
      .from(auditLog)
      .where(and(eq(auditLog.action, "policy_exception.case_inventory"), eq(auditLog.outcome, outcome)))
      .orderBy(desc(auditLog.at), desc(auditLog.id))
      .limit(1);
  const [[ok], [failed]] = await Promise.all([latestOf("success"), latestOf("failure")]);
  const latest = ok ? parseInventoryDetails(ok.at, ok.details ?? {}) : null;
  let failure: InventoryFailure | null = null;
  if (failed && (!ok || failed.at.getTime() >= ok.at.getTime())) {
    const d = failed.details ?? {};
    const code = typeof d.error_code === "string" && /^[a-z0-9_]{1,40}$/i.test(d.error_code) ? d.error_code : "internal";
    failure = { at: failed.at, trigger: d.trigger === "user" ? "user" : "startup", errorCode: code };
  }
  return { latest, failure };
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
    trigger: d.trigger === "user" || d.trigger === "name_case" ? d.trigger : "startup",
    entries,
    exceptionsListed: num(d.exceptions_listed),
    truncated: d.exceptions_truncated === true,
    findingNamesCompared: num(d.finding_names_compared),
    exceptionsCompared: num(d.exceptions_compared),
    exceptionsTotal: num(d.exceptions_total),
    eventNamesCompared: num(d.event_names_compared),
    boundReached: d.bound_reached === true,
  };
}
