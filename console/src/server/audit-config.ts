import { and, desc, eq, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, auditConfigs, findings, jobs } from "@/db/schema";
import { minRowsWarning, type AuditWarning, type MinRowsWarning } from "@/lib/audit-warning";
import { objectSensitivity } from "@/lib/event-model";
import { isKeyPatternEngine } from "@/lib/location-labels";
import { logger } from "@/lib/logger";
import { checkSemantics, validateSchema, type Schemas } from "@/lib/protocol/validate";

import { agentAccepts } from "./agent-api/capabilities";
import { recordIntegrityEvent } from "./integrity";
import { RateLimiter } from "./rate-limit";
import { JOBS_CHANNEL } from "./agent-api/job-hub";
import { writeAudit } from "./audit";
import { sha256Hex } from "./crypto";
import { canonicalJson, type Tx } from "./findings";
import { lockAgentJobs } from "./job-lock";

/**
 * Audit settings per target (P4-C, and the `audit.configure` confirmation left open by P3-A).
 *
 * An administrator sets, per target: Audit on or off, the aggregation window, the polling interval,
 * `min_rows`, whether the sensitive objects are derived from the findings, and objects added by
 * hand. The console computes the contract `AuditConfigureParams` (derived objects: every object
 * with a finding that is not a false positive, with its classifiers; merged with the manual ones;
 * at most 1000, most sensitive first), validates it against the contract, and queues an
 * `audit.configure` job (pending jobs of the same target are cancelled: the settings replace the
 * previous ones as a whole).
 *
 * A change that narrows Audit needs an explicit confirmation, is audited with the counts, and
 * leaves a warning on the target until a later change that does not narrow it:
 * - `disabled`: Audit was enabled and is turned off;
 * - `emptied`: `sensitive_objects` was not empty and becomes empty;
 * - `shrunk`: the change removes many objects: at least `SHRINK_MIN_REMOVED` (20), or at least
 *   `SHRINK_RATIO` (50 %) of the objects sent last time.
 * The confirmation is the digest of the exact settings shown to the administrator: if the findings
 * change in between, the digest no longer matches and the change must be confirmed again.
 *
 * `min_rows` on a key-pattern (Redis / Valkey) target is saved, with a `minRowsWarning` in the
 * answer and the audit entry (#235 review N2): it is not a narrowing of the sensitive objects,
 * but it drops the target's events that carry no signal and name no listed key pattern, since
 * they have no row count.
 *
 * Key patterns as sensitive objects (phase 9 follow-ups, contract `SensitiveObject`,
 * `sensitive_object.key_pattern`, ADR-0022 decision 3): on a Redis / Valkey target, objects named
 * by a key pattern (`user:*:email`, from findings or typed by hand) are sent only when the agent's
 * latest heartbeat listed the token (`agents.accepts`); otherwise they are left out and counted
 * (`skippedKeyPatterns`), since an older agent cannot decode them and would lose the whole job.
 * On any other target, a hand-typed object that is not an `Identifier` is refused (`invalid`).
 */

export const SHRINK_MIN_REMOVED = 20;
export const SHRINK_RATIO = 0.5;
export const MAX_SENSITIVE_OBJECTS = 1000;
export const MAX_OBJECT_CLASSIFIERS = 32;
/** Contract defaults (`AuditConfigureParams`), made explicit in every job. */
export const AUDIT_DEFAULTS = { aggregation_window_s: 60, poll_interval_s: 10 } as const;

export type AuditConfigureParams = Schemas["AuditConfigureParams"];
export type SensitiveObject = Schemas["SensitiveObject"];
export type { AuditWarning } from "@/lib/audit-warning";

export interface AuditConfigInput {
  enabled: boolean;
  aggregationWindowS: number;
  pollIntervalS: number;
  minRows: number | null;
  deriveFromFindings: boolean;
  manualObjects: SensitiveObject[];
  /** Digest of the settings the administrator confirmed (see `settingsDigest`). */
  confirm: string | null;
}

const INPUT_KEYS = ["enabled", "aggregation_window_s", "poll_interval_s", "min_rows", "derive_from_findings", "manual_objects", "confirm"];
const DIGEST = /^[0-9a-f]{64}$/;

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Strict validation of the user request body (unknown keys rejected); returns the failing field. */
export function parseAuditConfigInput(v: unknown): { ok: true; value: AuditConfigInput } | { ok: false; error: string } {
  if (!isObj(v)) return { ok: false, error: "body" };
  if (Object.keys(v).some((k) => !INPUT_KEYS.includes(k))) return { ok: false, error: "unknown_key" };
  if (typeof v.enabled !== "boolean") return { ok: false, error: "enabled" };
  const int = (x: unknown, min: number, max: number) => typeof x === "number" && Number.isSafeInteger(x) && x >= min && x <= max;
  const aggregation = v.aggregation_window_s ?? AUDIT_DEFAULTS.aggregation_window_s;
  if (!int(aggregation, 1, 300)) return { ok: false, error: "aggregation_window_s" };
  const poll = v.poll_interval_s ?? AUDIT_DEFAULTS.poll_interval_s;
  if (!int(poll, 1, 3600)) return { ok: false, error: "poll_interval_s" };
  const minRows = v.min_rows ?? null;
  if (minRows !== null && !int(minRows, 0, Number.MAX_SAFE_INTEGER)) return { ok: false, error: "min_rows" };
  const derive = v.derive_from_findings ?? true;
  if (typeof derive !== "boolean") return { ok: false, error: "derive_from_findings" };
  const manual = v.manual_objects ?? [];
  if (!Array.isArray(manual) || manual.length > MAX_SENSITIVE_OBJECTS) return { ok: false, error: "manual_objects" };
  const objects: SensitiveObject[] = [];
  for (const o of manual) {
    const r = validateSchema("SensitiveObject", o);
    if (!r.ok || !checkSemantics("SensitiveObject", r.value).ok) return { ok: false, error: "manual_objects" };
    objects.push({ ...r.value, classifiers: [...r.value.classifiers] });
  }
  const confirm = v.confirm ?? null;
  if (confirm !== null && (typeof confirm !== "string" || !DIGEST.test(confirm))) return { ok: false, error: "confirm" };
  return {
    ok: true,
    value: {
      enabled: v.enabled,
      aggregationWindowS: aggregation as number,
      pollIntervalS: poll as number,
      minRows: minRows as number | null,
      deriveFromFindings: derive,
      manualObjects: objects,
      confirm: confirm as string | null,
    },
  };
}

/**
 * Identity of a sensitive object (database, schema, object), exact on purpose (end-of-phase-9
 * review N1): the agent matches `sensitive_objects` without case or trailing spaces, so the
 * spelling sent never narrows its filter, and keeping every catalog spelling (`Customers` next to
 * `customers`, distinct tables on PostgreSQL) keeps both for an agent that still compares
 * exactly. Merging spellings would only save list slots.
 */
export function objectIdentity(o: Pick<SensitiveObject, "database" | "schema" | "object">): string {
  return JSON.stringify([o.database, o.schema ?? null, o.object]);
}

interface DerivedObject extends SensitiveObject {
  sensitivity: number;
}

/** Objects of the target with at least one finding that is not a false positive, with their classifiers. */
export async function deriveSensitiveObjects(db: Database | Tx, agentId: string, targetId: string): Promise<DerivedObject[]> {
  const rows = await db
    .select({
      database: findings.databaseName,
      schema: findings.schemaName,
      object: findings.objectName,
      classifier: findings.classifier,
      confidence: sql<number>`max(${findings.confidence})`,
    })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), eq(findings.targetId, targetId), isNull(findings.falsePositiveAt)))
    .groupBy(findings.databaseName, findings.schemaName, findings.objectName, findings.classifier);
  const byObject = new Map<string, { o: SensitiveObject; hits: { classifier: string; confidence: number }[] }>();
  for (const r of rows) {
    const o: SensitiveObject = r.schema === null ? { database: r.database, object: r.object, classifiers: [] } : { database: r.database, schema: r.schema, object: r.object, classifiers: [] };
    const key = objectIdentity(o);
    const entry = byObject.get(key) ?? { o, hits: [] };
    entry.hits.push({ classifier: r.classifier, confidence: Number(r.confidence) });
    byObject.set(key, entry);
  }
  return [...byObject.values()].map(({ o, hits }) => ({
    ...o,
    classifiers: [...new Set(hits.map((h) => h.classifier))].sort().slice(0, MAX_OBJECT_CLASSIFIERS),
    sensitivity: objectSensitivity(hits),
  }));
}

/** The capability token of key patterns as `SensitiveObject.object` (contract `HeartbeatRequest.accepts`). */
export const KEY_PATTERN_TOKEN = "sensitive_object.key_pattern" as const;

/** Whether `object` is a contract `KeyPattern` that is not an `Identifier` (the `ObjectName` second branch). */
export function isKeyPatternObject(object: string): boolean {
  return !validateSchema("Identifier", object).ok && validateSchema("KeyPattern", object).ok;
}

/**
 * Objects the agent can receive as `SensitiveObject`s (P9-E review M3, phase 9 follow-ups): an
 * `Identifier` always; a key pattern (`user:*:email`, a Redis / Valkey finding) only when
 * `keyPatterns` (a Redis / Valkey target whose agent listed {@link KEY_PATTERN_TOKEN}). The others
 * are left out (counted in `skipped`), so the save never fails and Audit can always be turned off.
 */
export function sendableDerivedObjects<T extends SensitiveObject>(derived: readonly T[], keyPatterns = false): { objects: T[]; skipped: number } {
  const objects = derived.filter((o) => validateSchema("Identifier", o.object).ok || (keyPatterns && isKeyPatternObject(o.object)));
  return { objects, skipped: derived.length - objects.length };
}

/** Whether the agent's stored capability list (`agents.accepts`) names {@link KEY_PATTERN_TOKEN}. */
export function agentAcceptsKeyPatterns(accepts: unknown): boolean {
  return agentAccepts(accepts, KEY_PATTERN_TOKEN);
}

/**
 * Merges derived and manual objects (classifiers united per object), most sensitive first (manual
 * objects rank first: an administrator added them on purpose), bounded to the contract's 1000.
 */
export function mergeSensitiveObjects(
  derived: readonly DerivedObject[],
  manual: readonly SensitiveObject[],
): { objects: SensitiveObject[]; truncated: number } {
  const merged = new Map<string, { o: SensitiveObject; rank: number }>();
  for (const m of manual) {
    const key = objectIdentity(m);
    const prev = merged.get(key);
    const classifiers = [...new Set([...(prev?.o.classifiers ?? []), ...m.classifiers])];
    merged.set(key, { o: { ...m, classifiers }, rank: Number.POSITIVE_INFINITY });
  }
  for (const d of derived) {
    const key = objectIdentity(d);
    const prev = merged.get(key);
    const { sensitivity, ...o } = d;
    const classifiers = [...new Set([...(prev?.o.classifiers ?? []), ...o.classifiers])];
    merged.set(key, { o: { ...(prev?.o ?? o), classifiers }, rank: Math.max(prev?.rank ?? 0, sensitivity) });
  }
  const sorted = [...merged.values()]
    .map(({ o, rank }) => ({ o: { ...o, classifiers: [...o.classifiers].sort().slice(0, MAX_OBJECT_CLASSIFIERS) }, rank }))
    .sort((a, b) => b.rank - a.rank || (objectIdentity(a.o) < objectIdentity(b.o) ? -1 : 1));
  return {
    objects: sorted.slice(0, MAX_SENSITIVE_OBJECTS).map((x) => x.o),
    truncated: Math.max(0, sorted.length - MAX_SENSITIVE_OBJECTS),
  };
}

export function buildAuditParams(input: AuditConfigInput, objects: SensitiveObject[]): AuditConfigureParams | null {
  const params: AuditConfigureParams = {
    enabled: input.enabled,
    aggregation_window_s: input.aggregationWindowS,
    poll_interval_s: input.pollIntervalS,
    ...(input.minRows !== null ? { min_rows: input.minRows } : {}),
    sensitive_objects: objects,
  };
  const schema = validateSchema("AuditConfigureParams", params);
  if (!schema.ok || !checkSemantics("AuditConfigureParams", schema.value).ok) return null;
  return schema.value;
}

/** Digest of the settings, for the confirmation step. */
export function settingsDigest(params: AuditConfigureParams): string {
  return sha256Hex(canonicalJson(params));
}

export interface AuditChange {
  previousCount: number;
  nextCount: number;
  added: number;
  removed: number;
  warning: AuditWarning | null;
}

/** What a change does to the sensitive objects sent last time, and whether it narrows Audit. */
export function assessAuditChange(
  previous: { enabled: boolean; objects: readonly SensitiveObject[] } | null,
  next: { enabled: boolean; objects: readonly SensitiveObject[] },
): AuditChange {
  const before = new Set((previous?.objects ?? []).map(objectIdentity));
  const after = new Set(next.objects.map(objectIdentity));
  const removed = [...before].filter((k) => !after.has(k)).length;
  const added = [...after].filter((k) => !before.has(k)).length;
  let warning: AuditWarning | null = null;
  if (previous) {
    if (previous.enabled && !next.enabled) warning = "disabled";
    else if (before.size > 0 && after.size === 0) warning = "emptied";
    else if (removed >= SHRINK_MIN_REMOVED || (before.size > 0 && removed / before.size >= SHRINK_RATIO)) warning = "shrunk";
  }
  return { previousCount: before.size, nextCount: after.size, added, removed, warning };
}

export interface AuditConfigView {
  agentId: string;
  targetId: string;
  engine: string;
  present: boolean;
  auditLevel: string;
  configured: boolean;
  enabled: boolean;
  aggregationWindowS: number;
  pollIntervalS: number;
  minRows: number | null;
  deriveFromFindings: boolean;
  manualObjects: SensitiveObject[];
  sentObjects: SensitiveObject[];
  /** The agent's latest heartbeat listed {@link KEY_PATTERN_TOKEN} (key patterns can be sent). */
  agentAcceptsKeyPatterns: boolean;
  warning: AuditWarning | null;
  warningRemoved: number | null;
  updatedAt: Date | null;
  /**
   * `deliveredWithoutKeyPatterns`: key patterns left out of its last delivery, the agent no longer
   * listing `sensitive_object.key_pattern` (security review of #280, M2); null when none.
   */
  lastJob: { id: string; status: string; errorCode: string | null; createdAt: Date; deliveredWithoutKeyPatterns: number | null } | null;
}

/** Audit settings of a target (defaults when never configured), or null for an unknown target. */
export async function getAuditConfig(db: Database, agentId: string, targetId: string): Promise<AuditConfigView | null> {
  const [t] = await db
    .select({ engine: agentTargets.engine, present: agentTargets.present, auditLevel: agentTargets.auditLevel })
    .from(agentTargets)
    .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)))
    .limit(1);
  if (!t) return null;
  const [agent] = await db.select({ accepts: agents.accepts }).from(agents).where(eq(agents.id, agentId)).limit(1);
  const [c] = await db
    .select()
    .from(auditConfigs)
    .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.targetId, targetId)))
    .limit(1);
  const [job] = await db
    .select({ id: jobs.id, status: jobs.status, error: jobs.error, createdAt: jobs.createdAt, withoutKeys: jobs.deliveredWithoutKeyPatterns })
    .from(jobs)
    .where(and(eq(jobs.agentId, agentId), eq(jobs.targetId, targetId), eq(jobs.type, "audit.configure")))
    .orderBy(desc(jobs.createdAt))
    .limit(1);
  return {
    agentId,
    targetId,
    engine: t.engine,
    present: t.present,
    auditLevel: t.auditLevel,
    configured: c !== undefined,
    enabled: c?.enabled ?? false,
    aggregationWindowS: c?.aggregationWindowS ?? AUDIT_DEFAULTS.aggregation_window_s,
    pollIntervalS: c?.pollIntervalS ?? AUDIT_DEFAULTS.poll_interval_s,
    minRows: c?.minRows ?? null,
    deriveFromFindings: c?.deriveFromFindings ?? true,
    manualObjects: (c?.manualObjects ?? []) as unknown as SensitiveObject[],
    sentObjects: (c?.sentObjects ?? []) as unknown as SensitiveObject[],
    agentAcceptsKeyPatterns: agentAcceptsKeyPatterns(agent?.accepts),
    warning: (c?.warning as AuditWarning | null | undefined) ?? null,
    warningRemoved: c?.warningRemoved ?? null,
    updatedAt: c?.updatedAt ?? null,
    lastJob: job
      ? { id: job.id, status: job.status, errorCode: job.error?.code ?? null, createdAt: job.createdAt, deliveredWithoutKeyPatterns: job.withoutKeys ?? null }
      : null,
  };
}

/** Audit settings summary of every target of an agent (agent page). */
export async function auditSummaries(db: Database, agentId: string): Promise<Map<string, { enabled: boolean; objects: number; warning: AuditWarning | null; warningRemoved: number | null }>> {
  const rows = await db
    .select({
      targetId: auditConfigs.targetId,
      enabled: auditConfigs.enabled,
      objects: sql<number>`jsonb_array_length(${auditConfigs.sentObjects})::int`,
      warning: auditConfigs.warning,
      warningRemoved: auditConfigs.warningRemoved,
    })
    .from(auditConfigs)
    .where(eq(auditConfigs.agentId, agentId));
  return new Map(rows.map((r) => [r.targetId, { enabled: r.enabled, objects: r.objects, warning: r.warning as AuditWarning | null, warningRemoved: r.warningRemoved }]));
}

export type AuditConfigureOutcome =
  | { outcome: "queued"; jobId: string; change: AuditChange; truncated: number; skippedKeyPatterns: number; minRowsWarning: MinRowsWarning | null }
  /** A narrowing change without (or with an outdated) confirmation: nothing is queued. */
  | {
      outcome: "confirmation_required";
      change: AuditChange;
      digest: string;
      truncated: number;
      skippedKeyPatterns: number;
      minRowsWarning: MinRowsWarning | null;
    }
  | { outcome: "not_found" }
  | { outcome: "invalid" };

/**
 * Computes the settings of `input` for the target, and, unless a confirmation is required and
 * missing, queues the `audit.configure` job and records the settings. Always audited
 * (`audit.configure`), including refusals.
 */
export async function configureAudit(
  db: Database,
  agentId: string,
  targetId: string,
  input: AuditConfigInput,
  actor: { userId: string; ip: string | null },
): Promise<AuditConfigureOutcome> {
  const result = await db.transaction(async (tx): Promise<AuditConfigureOutcome> => {
    return queueAuditSettings(tx, agentId, targetId, input, actor);
  });
  if (result.outcome !== "queued") {
    await writeAudit(db, {
      actorType: "user",
      actorId: actor.userId,
      action: "audit.configure",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
      details: {
        target_id: targetId,
        reason: result.outcome,
        ...(result.outcome === "confirmation_required"
          ? {
              warning: result.change.warning,
              previous_objects: result.change.previousCount,
              next_objects: result.change.nextCount,
              removed_objects: result.change.removed,
              min_rows_warning: result.minRowsWarning,
            }
          : {}),
      },
    });
  }
  return result;
}

/** The settings computation and queueing of {@link configureAudit}, inside its transaction. */
async function queueAuditSettings(
  tx: Tx,
  agentId: string,
  targetId: string,
  input: AuditConfigInput,
  actor: { userId: string; ip: string | null },
): Promise<AuditConfigureOutcome> {
    // Serializes the changes of the agent's settings (and its jobs), as for scan requests.
    const [agent] = await tx
      .select({ revokedAt: agents.revokedAt, lockedAt: agents.lockedAt, accepts: agents.accepts })
      .from(agents)
      .where(eq(agents.id, agentId))
      .for("update")
      .limit(1);
    if (!agent || agent.revokedAt || agent.lockedAt) return { outcome: "not_found" };
    await lockAgentJobs(tx, agentId);
    const [target] = await tx
      .select({ present: agentTargets.present, engine: agentTargets.engine })
      .from(agentTargets)
      .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)))
      .limit(1);
    if (!target?.present) return { outcome: "not_found" };
    const keyPatternTarget = isKeyPatternEngine(target.engine);
    const rowsWarning = minRowsWarning(keyPatternTarget, input.minRows);
    // A key pattern names a Redis / Valkey object only (contract `SensitiveObject`, as `ObjectRef`).
    if (!keyPatternTarget && input.manualObjects.some((o) => !validateSchema("Identifier", o.object).ok)) return { outcome: "invalid" };
    // Key patterns go only to an agent that listed the token (ADR-0022 decision 3); otherwise
    // they are left out and counted (M3), from the findings and from the manual objects alike.
    const keyPatterns = keyPatternTarget && agentAcceptsKeyPatterns(agent.accepts);
    const { objects: derived, skipped: skippedDerived } = sendableDerivedObjects(
      input.deriveFromFindings ? await deriveSensitiveObjects(tx, agentId, targetId) : [],
      keyPatterns,
    );
    const { objects: manual, skipped: skippedManual } = sendableDerivedObjects(input.manualObjects, keyPatterns);
    const skippedKeyPatterns = skippedDerived + skippedManual;
    const { objects, truncated } = mergeSensitiveObjects(derived, manual);
    // Turning Audit off always works (M3): the objects are only a hint while it is off.
    const params = buildAuditParams(input, objects) ?? (input.enabled ? null : buildAuditParams(input, []));
    if (!params) return { outcome: "invalid" };
    const [previous] = await tx
      .select({ enabled: auditConfigs.enabled, sentObjects: auditConfigs.sentObjects })
      .from(auditConfigs)
      .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.targetId, targetId)))
      .limit(1);
    const change = assessAuditChange(
      previous ? { enabled: previous.enabled, objects: previous.sentObjects as unknown as SensitiveObject[] } : null,
      { enabled: params.enabled, objects: params.sensitive_objects ?? [] },
    );
    const digest = settingsDigest(params);
    if (change.warning !== null && input.confirm !== digest) {
      return { outcome: "confirmation_required", change, digest, truncated, skippedKeyPatterns, minRowsWarning: rowsWarning };
    }
    // The settings replace the previous ones as a whole: jobs not delivered yet are superseded.
    await tx
      .update(jobs)
      .set({ status: "cancelled", finishedAt: sql`now()` })
      .where(and(eq(jobs.agentId, agentId), eq(jobs.targetId, targetId), eq(jobs.type, "audit.configure"), eq(jobs.status, "pending")));
    const [job] = await tx
      .insert(jobs)
      .values({ agentId, type: "audit.configure", targetId, params: { ...params }, createdBy: actor.userId })
      .returning({ id: jobs.id });
    if (!job) throw new Error("job insert returned no row");
    const values = {
      enabled: params.enabled,
      aggregationWindowS: input.aggregationWindowS,
      pollIntervalS: input.pollIntervalS,
      minRows: input.minRows,
      deriveFromFindings: input.deriveFromFindings,
      manualObjects: input.manualObjects as unknown as Record<string, unknown>[],
      sentObjects: (params.sensitive_objects ?? []) as unknown as Record<string, unknown>[],
      lastJobId: job.id,
      warning: change.warning,
      warningRemoved: change.warning !== null ? change.removed : null,
      updatedAt: sql`now()`,
      updatedBy: actor.userId,
    };
    await tx
      .insert(auditConfigs)
      .values({ agentId, targetId, ...values })
      .onConflictDoUpdate({ target: [auditConfigs.agentId, auditConfigs.targetId], set: values });
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "audit.configure",
      targetType: "job",
      targetId: job.id,
      sourceIp: actor.ip,
      details: {
        ...auditDetails(agentId, targetId, params, input, change, derived.length, truncated, true),
        skipped_key_patterns: skippedKeyPatterns,
        min_rows_warning: rowsWarning,
      },
    });
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    return { outcome: "queued", jobId: job.id, change, truncated, skippedKeyPatterns, minRowsWarning: rowsWarning };
}

/**
 * Requeues of an agent's Audit settings after a capability change, per agent and hour (re-review
 * N1), shared by the console processes with the per-process fallback (an audit budget, as the
 * integrity limiters, ADR-0024 decision 4). An upgrade or a downgrade needs one; 4 leave room for a
 * rollback and a retry.
 */
export const auditRequeueBudget = RateLimiter.shared("audit.requeue_per_agent", 4, 60 * 60_000, "local");
/** The `accepts_flapping` integrity events of an agent past {@link auditRequeueBudget}: one per hour. */
export const acceptsFlappingAlertBudget = RateLimiter.shared("audit.requeue_flapping_alerts", 1, 60 * 60_000, "local");

/**
 * One target of {@link requeueAuditSettingsOnAcceptsChange} (re-review N2): the objects sent last
 * time keep their plain names (`Identifier`s, never derived again from today's findings); only the
 * key patterns are added (from the findings, if derived, and the manual objects, most sensitive
 * first, within what the 1000 cap leaves after the plain names) or removed, as the agent can now
 * receive them. Nothing is queued when that changes nothing. The stored warning is kept unless this
 * requeue removes objects, which records its own (`shrunk` or `emptied`). Whether the job was queued.
 */
async function requeueKeyPatterns(db: Database, agentId: string, targetId: string, deferred: boolean): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [agent] = await tx
      .select({ revokedAt: agents.revokedAt, lockedAt: agents.lockedAt, accepts: agents.accepts })
      .from(agents)
      .where(eq(agents.id, agentId))
      .for("update")
      .limit(1);
    if (!agent || agent.revokedAt || agent.lockedAt) return false;
    await lockAgentJobs(tx, agentId);
    const [c] = await tx
      .select()
      .from(auditConfigs)
      .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.targetId, targetId)))
      .limit(1);
    if (!c?.enabled) return false;
    const sent = c.sentObjects as unknown as SensitiveObject[];
    const plain = sent.filter((o) => validateSchema("Identifier", o.object).ok);
    let keys: SensitiveObject[] = [];
    if (agentAcceptsKeyPatterns(agent.accepts)) {
      const derived = c.deriveFromFindings ? (await deriveSensitiveObjects(tx, agentId, targetId)).filter((o) => isKeyPatternObject(o.object)) : [];
      const manual = (c.manualObjects as unknown as SensitiveObject[]).filter((o) => isKeyPatternObject(o.object));
      keys = mergeSensitiveObjects(derived, manual).objects.slice(0, Math.max(0, MAX_SENSITIVE_OBJECTS - plain.length));
    }
    const next = [...plain, ...keys];
    const change = assessAuditChange({ enabled: true, objects: sent }, { enabled: true, objects: next });
    if (change.added === 0 && change.removed === 0) return false;
    const input: AuditConfigInput = {
      enabled: true,
      aggregationWindowS: c.aggregationWindowS,
      pollIntervalS: c.pollIntervalS,
      minRows: c.minRows ?? null,
      deriveFromFindings: c.deriveFromFindings,
      manualObjects: c.manualObjects as unknown as SensitiveObject[],
      confirm: null,
    };
    const params = buildAuditParams(input, next);
    if (!params) return false;
    await tx
      .update(jobs)
      .set({ status: "cancelled", finishedAt: sql`now()` })
      .where(and(eq(jobs.agentId, agentId), eq(jobs.targetId, targetId), eq(jobs.type, "audit.configure"), eq(jobs.status, "pending")));
    const [job] = await tx.insert(jobs).values({ agentId, type: "audit.configure", targetId, params: { ...params }, createdBy: null }).returning({ id: jobs.id });
    if (!job) throw new Error("job insert returned no row");
    // Only a requeue that removes objects records a warning; otherwise the stored one stays.
    const narrows = change.removed > 0;
    await tx
      .update(auditConfigs)
      .set({
        sentObjects: next as unknown as Record<string, unknown>[],
        lastJobId: job.id,
        ...(narrows ? { warning: change.warning ?? "shrunk", warningRemoved: change.removed } : {}),
        updatedAt: sql`now()`,
      })
      .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.targetId, targetId)));
    await writeAudit(tx, {
      actorType: "system",
      action: "audit.configure",
      targetType: "job",
      targetId: job.id,
      details: {
        agent_id: agentId,
        target_id: targetId,
        reason: "agent_accepts_changed",
        previous_objects: change.previousCount,
        next_objects: change.nextCount,
        added_objects: change.added,
        removed_objects: change.removed,
        key_patterns: keys.length,
        warning: narrows ? (change.warning ?? "shrunk") : null,
        // #280 re-review L-a: queued from a heartbeat after a change the budget had deferred.
        deferred,
      },
    });
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    return true;
  });
}

/**
 * Marks the agent's Audit settings requeue as due (#280 re-review L-a): the heartbeat that changed
 * its capability tokens was stored (delivery reads `agents.accepts`, so it must follow the latest
 * heartbeat, ADR-0022 decision 3), but its settings were not queued again, because the requeue
 * budget was spent or the requeue failed. Fail closed: the change is never dropped; a later
 * heartbeat queues the settings from the agent's latest tokens once the budget allows. Only for an
 * agent with enabled Audit settings on a present Redis / Valkey target (nothing to requeue
 * otherwise).
 *
 * The mark always moves forward, under the agent's row lock (security review of 34db5b8, L1): a
 * requeue running meanwhile (another replica) clears the mark only if it still holds the value
 * that requeue read before it started, so a change marked during that requeue keeps its mark and
 * is acted on later. The new value is strictly later than the old one, even within a millisecond.
 * The audit entry `audit.requeue_deferred` is written only when the mark was not set, not at every
 * heartbeat while it stays set, so at most once more per hour than the budget's requeues. Whether
 * the entry was written by this call.
 */
export async function deferAuditRequeue(db: Database, agentId: string, reason: "budget_spent" | "requeue_failed"): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [agent] = await tx
      .select({ dueAt: agents.auditRequeueDueAt })
      .from(agents)
      .where(and(eq(agents.id, agentId), isNull(agents.revokedAt), isNull(agents.lockedAt)))
      .for("update")
      .limit(1);
    if (!agent) return false;
    const configs = await tx
      .select({ engine: agentTargets.engine })
      .from(auditConfigs)
      .innerJoin(agentTargets, and(eq(agentTargets.agentId, auditConfigs.agentId), eq(agentTargets.targetId, auditConfigs.targetId)))
      .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.enabled, true), eq(agentTargets.present, true)));
    if (!configs.some((c) => isKeyPatternEngine(c.engine))) return false;
    await tx
      .update(agents)
      .set({
        auditRequeueDueAt: sql`greatest(date_trunc('milliseconds', now()), ${agents.auditRequeueDueAt} + interval '1 millisecond')`,
      })
      .where(eq(agents.id, agentId));
    if (agent.dueAt !== null) return false;
    await writeAudit(tx, {
      actorType: "system",
      action: "audit.requeue_deferred",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      details: { agent_id: agentId, reason },
    });
    return true;
  });
}

/** {@link deferAuditRequeue}, never throwing (logged): the caller's other steps still run (L2). */
async function deferAuditRequeueLogged(db: Database, agentId: string, reason: "budget_spent" | "requeue_failed"): Promise<void> {
  try {
    await deferAuditRequeue(db, agentId, reason);
  } catch (e) {
    logger.error({ agentId, reason, err: e instanceof Error ? e.name : "error" }, "audit settings requeue not marked as due");
  }
}

/**
 * Test hook only (never set outside tests): called before each target's requeue, so a test can
 * make it fail or move the agent's mark meanwhile. A plain module object, like `pollClock`.
 */
export const auditRequeueTestHooks: { beforeTarget: ((agentId: string, targetId: string) => Promise<void>) | null } = { beforeTarget: null };

/** What made the heartbeat handler call {@link requeueAuditSettingsOnAcceptsChange}. */
export type AuditRequeueCause = "accepts_changed" | "due";

/**
 * Security review of #280, M2: when a heartbeat changes the agent's stored capability list
 * (`agents.accepts`: an upgrade that starts listing `sensitive_object.key_pattern`, or a downgrade
 * that stops), the enabled Audit settings of its Redis / Valkey targets are computed again from the
 * stored settings and queued when their objects change, so key patterns are neither withheld from
 * an upgraded agent nor silently lost by a downgraded one. Audited as `audit.configure` by the
 * system, with `reason: "agent_accepts_changed"`. At most `auditRequeueBudget` per agent and
 * hour (re-review N1). Returns the number of jobs queued.
 *
 * #280 re-review L-a: past the budget, the change is not acted on but it is not dropped either:
 * the agent is marked (`agents.audit_requeue_due_at`, audited as `audit.requeue_deferred`) and
 * every later heartbeat calls this again (`cause: "due"`, refused locally at no store cost while the
 * window lasts) until the budget allows a requeue, which starts from the agent's latest tokens and
 * clears the mark if it has not moved since the requeue read it. A requeue that throws marks the
 * agent the same way. A due call past the budget raises no `accepts_flapping` event: only a change
 * does, even when marking fails (L2).
 */
export async function requeueAuditSettingsOnAcceptsChange(db: Database, agentId: string, cause: AuditRequeueCause = "accepts_changed"): Promise<number> {
  // Re-review N1: an agent that flips its tokens at every heartbeat must not write jobs, settings
  // and audit entries without bound. Past the budget, one integrity event an hour, no requeue.
  if (!(await auditRequeueBudget.reserveShared(agentId)).ok) {
    if (cause === "accepts_changed") {
      await deferAuditRequeueLogged(db, agentId, "budget_spent");
      if ((await acceptsFlappingAlertBudget.reserveShared(agentId)).ok) {
        await recordIntegrityEvent(db, { agentId, kind: "accepts_flapping", endpoint: "heartbeat", status: 200, ip: null });
      }
    }
    return 0;
  }
  try {
    // Read before the requeue: a mark moved meanwhile (by a concurrent heartbeat) is a later value
    // and stays, so its change is acted on too (L1).
    const [mark] = await db.select({ dueAt: agents.auditRequeueDueAt }).from(agents).where(eq(agents.id, agentId)).limit(1);
    const rows = await db
      .select({ targetId: auditConfigs.targetId, engine: agentTargets.engine })
      .from(auditConfigs)
      .innerJoin(agentTargets, and(eq(agentTargets.agentId, auditConfigs.agentId), eq(agentTargets.targetId, auditConfigs.targetId)))
      .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.enabled, true), eq(agentTargets.present, true)));
    let queued = 0;
    for (const { targetId, engine } of rows) {
      if (!isKeyPatternEngine(engine)) continue;
      if (auditRequeueTestHooks.beforeTarget) await auditRequeueTestHooks.beforeTarget(agentId, targetId);
      if (await requeueKeyPatterns(db, agentId, targetId, cause === "due")) queued++;
    }
    if (mark?.dueAt) {
      await db
        .update(agents)
        .set({ auditRequeueDueAt: null })
        .where(and(eq(agents.id, agentId), eq(agents.auditRequeueDueAt, mark.dueAt)));
    }
    return queued;
  } catch (e) {
    // Fail closed: the settings are queued again from a later heartbeat (best effort here: the
    // database may be what failed, and the caller logs the original error).
    await deferAuditRequeueLogged(db, agentId, "requeue_failed");
    throw e;
  }
}

function auditDetails(
  agentId: string,
  targetId: string,
  params: AuditConfigureParams,
  input: AuditConfigInput,
  change: AuditChange,
  derived: number,
  truncated: number,
  confirmed: boolean,
): Record<string, string | number | boolean | null> {
  return {
    agent_id: agentId,
    target_id: targetId,
    enabled: params.enabled,
    aggregation_window_s: input.aggregationWindowS,
    poll_interval_s: input.pollIntervalS,
    min_rows: input.minRows,
    derive_from_findings: input.deriveFromFindings,
    derived_objects: derived,
    manual_objects: input.manualObjects.length,
    previous_objects: change.previousCount,
    next_objects: change.nextCount,
    added_objects: change.added,
    removed_objects: change.removed,
    truncated_objects: truncated,
    warning: change.warning,
    confirmed: change.warning !== null && confirmed,
  };
}
