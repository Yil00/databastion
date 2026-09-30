import { and, desc, eq, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, auditConfigs, findings, jobs } from "@/db/schema";
import type { AuditWarning } from "@/lib/audit-warning";
import { objectSensitivity } from "@/lib/event-model";
import { checkSemantics, validateSchema, type Schemas } from "@/lib/protocol/validate";

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

/** Identity of a sensitive object (database, schema, object). */
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
  warning: AuditWarning | null;
  warningRemoved: number | null;
  updatedAt: Date | null;
  lastJob: { id: string; status: string; errorCode: string | null; createdAt: Date } | null;
}

/** Audit settings of a target (defaults when never configured), or null for an unknown target. */
export async function getAuditConfig(db: Database, agentId: string, targetId: string): Promise<AuditConfigView | null> {
  const [t] = await db
    .select({ engine: agentTargets.engine, present: agentTargets.present, auditLevel: agentTargets.auditLevel })
    .from(agentTargets)
    .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)))
    .limit(1);
  if (!t) return null;
  const [c] = await db
    .select()
    .from(auditConfigs)
    .where(and(eq(auditConfigs.agentId, agentId), eq(auditConfigs.targetId, targetId)))
    .limit(1);
  const [job] = await db
    .select({ id: jobs.id, status: jobs.status, error: jobs.error, createdAt: jobs.createdAt })
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
    warning: (c?.warning as AuditWarning | null | undefined) ?? null,
    warningRemoved: c?.warningRemoved ?? null,
    updatedAt: c?.updatedAt ?? null,
    lastJob: job ? { id: job.id, status: job.status, errorCode: job.error?.code ?? null, createdAt: job.createdAt } : null,
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
  | { outcome: "queued"; jobId: string; change: AuditChange; truncated: number }
  /** A narrowing change without (or with an outdated) confirmation: nothing is queued. */
  | { outcome: "confirmation_required"; change: AuditChange; digest: string; truncated: number }
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
    // Serializes the changes of the agent's settings (and its jobs), as for scan requests.
    const [agent] = await tx
      .select({ revokedAt: agents.revokedAt, lockedAt: agents.lockedAt })
      .from(agents)
      .where(eq(agents.id, agentId))
      .for("update")
      .limit(1);
    if (!agent || agent.revokedAt || agent.lockedAt) return { outcome: "not_found" };
    await lockAgentJobs(tx, agentId);
    const [target] = await tx
      .select({ present: agentTargets.present })
      .from(agentTargets)
      .where(and(eq(agentTargets.agentId, agentId), eq(agentTargets.targetId, targetId)))
      .limit(1);
    if (!target?.present) return { outcome: "not_found" };
    const derived = input.deriveFromFindings ? await deriveSensitiveObjects(tx, agentId, targetId) : [];
    const { objects, truncated } = mergeSensitiveObjects(derived, input.manualObjects);
    const params = buildAuditParams(input, objects);
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
      return { outcome: "confirmation_required", change, digest, truncated };
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
      details: auditDetails(agentId, targetId, params, input, change, derived.length, truncated, true),
    });
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    return { outcome: "queued", jobId: job.id, change, truncated };
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
            }
          : {}),
      },
    });
  }
  return result;
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
