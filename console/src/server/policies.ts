import { asc, eq, isNull, or, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, policies, policyExceptions } from "@/db/schema";
import {
  DESCRIPTION_MAX,
  isClassifierSelector,
  isDescription,
  isPlainObject,
  isPolicyName,
  parseLocationPattern,
  parsePolicyActions,
  parsePolicyConditions,
  POLICY_SOURCES,
  REASON_MAX,
  incidentSeverityOf,
  notifyChannelsOf,
  type FindingConditions,
  type LocationPattern,
  type PolicyAction,
  type PolicySource,
  type Severity,
} from "@/lib/policy-model";
import { validateSchema } from "@/lib/protocol/validate";

import { writeAudit } from "./audit";

/**
 * Policies and exceptions (P3-A): validation of the user input, storage and audit. Every write is
 * an administrator action (checked by the user API) and writes an audit entry holding identifiers
 * and flags only: never the policy name, description or exception reason (free text), never a
 * sampled value (a policy holds none).
 */

type Actor = { userId: string; ip: string | null };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface PolicyInput {
  name: string;
  description: string | null;
  enabled: boolean;
  source: PolicySource;
  conditions: FindingConditions;
  actions: PolicyAction[];
}

const POLICY_KEYS = ["name", "description", "enabled", "source", "conditions", "actions"] as const;

/**
 * Validates a create (`partial: false`: `name`, `conditions`, `actions` required) or an update
 * (`partial: true`: any subset) body. Unknown keys are rejected. Returns the first failing field.
 */
export function parsePolicyInput(
  v: unknown,
  partial: boolean,
  current?: { source: PolicySource },
): { ok: true; value: Partial<PolicyInput> } | { ok: false; error: string } {
  if (!isPlainObject(v)) return { ok: false, error: "body" };
  const unknown = Object.keys(v).find((k) => !(POLICY_KEYS as readonly string[]).includes(k));
  if (unknown !== undefined) return { ok: false, error: "unknown_key" };
  if (Object.keys(v).length === 0) return { ok: false, error: "body" };
  const out: Partial<PolicyInput> = {};
  if (v.source !== undefined) {
    if (typeof v.source !== "string" || !(POLICY_SOURCES as readonly string[]).includes(v.source)) {
      return { ok: false, error: "source" };
    }
    // The source of an existing policy is fixed: its documents were validated for it.
    if (current && v.source !== current.source) return { ok: false, error: "source" };
    out.source = v.source as PolicySource;
  }
  const source = out.source ?? current?.source ?? "finding";
  if (v.name !== undefined || !partial) {
    if (!isPolicyName(v.name)) return { ok: false, error: "name" };
    out.name = v.name.trim();
  }
  if (v.description !== undefined) {
    if (v.description !== null && !isDescription(v.description, DESCRIPTION_MAX)) return { ok: false, error: "description" };
    out.description = v.description === null || v.description.trim() === "" ? null : v.description;
  }
  if (v.enabled !== undefined) {
    if (typeof v.enabled !== "boolean") return { ok: false, error: "enabled" };
    out.enabled = v.enabled;
  }
  if (v.conditions !== undefined || !partial) {
    const c = parsePolicyConditions(source, v.conditions);
    if (!c.ok) return c;
    out.conditions = c.value;
  }
  if (v.actions !== undefined || !partial) {
    const a = parsePolicyActions(v.actions);
    if (!a.ok) return a;
    out.actions = a.value;
  }
  return { ok: true, value: out };
}

/** Audit details of a policy: identifiers, flags and counts only (no free text). */
function policyAuditDetails(p: { enabled: boolean; source: string; conditions: FindingConditions; actions: PolicyAction[]; revision: number }) {
  return {
    source: p.source,
    enabled: p.enabled,
    revision: p.revision,
    condition_keys: Object.keys(p.conditions).sort().join(","),
    classifiers: p.conditions.classifiers?.join(",") ?? null,
    severity: incidentSeverityOf(p.actions),
    notify_channels: notifyChannelsOf(p.actions).join(","),
  };
}

function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: unknown; cause?: { code?: unknown } } | null)?.code ?? (err as { cause?: { code?: unknown } } | null)?.cause?.code;
  return code === "23505";
}

export type PolicyWriteOutcome =
  | { outcome: "ok"; id: string }
  | { outcome: "not_found" }
  | { outcome: "name_taken" };

export async function createPolicy(db: Database, input: PolicyInput, actor: Actor): Promise<PolicyWriteOutcome> {
  try {
    return await db.transaction(async (tx) => {
      const [row] = await tx
        .insert(policies)
        .values({
          name: input.name,
          description: input.description,
          enabled: input.enabled,
          source: input.source,
          conditions: input.conditions as Record<string, unknown>,
          actions: input.actions as unknown as Record<string, unknown>[],
          createdBy: actor.userId,
          updatedBy: actor.userId,
        })
        .returning({ id: policies.id, revision: policies.revision });
      if (!row) throw new Error("policy insert returned no row");
      await writeAudit(tx, {
        actorType: "user",
        actorId: actor.userId,
        action: "policy.create",
        targetType: "policy",
        targetId: row.id,
        sourceIp: actor.ip,
        details: policyAuditDetails({ ...input, revision: row.revision }),
      });
      return { outcome: "ok" as const, id: row.id };
    });
  } catch (err) {
    if (isUniqueViolation(err)) return { outcome: "name_taken" };
    throw err;
  }
}

/** Current source of a policy (to validate an update), or null. */
export async function policySource(db: Database, id: string): Promise<PolicySource | null> {
  const [row] = await db.select({ source: policies.source }).from(policies).where(eq(policies.id, id)).limit(1);
  return row?.source ?? null;
}

/**
 * Updates a policy. A change of conditions, actions or enablement bumps `revision` and
 * `changed_at` (the worker re-evaluates the existing findings); a rename or a new description only
 * bumps `revision`.
 */
export async function updatePolicy(db: Database, id: string, input: Partial<PolicyInput>, actor: Actor): Promise<PolicyWriteOutcome> {
  const reevaluate = input.conditions !== undefined || input.actions !== undefined || input.enabled !== undefined;
  try {
    return await db.transaction(async (tx) => {
      const [row] = await tx
        .update(policies)
        .set({
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.description !== undefined ? { description: input.description } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          ...(input.conditions !== undefined ? { conditions: input.conditions as Record<string, unknown> } : {}),
          ...(input.actions !== undefined ? { actions: input.actions as unknown as Record<string, unknown>[] } : {}),
          revision: sql`${policies.revision} + 1`,
          updatedAt: sql`now()`,
          updatedBy: actor.userId,
          ...(reevaluate ? { changedAt: sql`now()` } : {}),
        })
        .where(eq(policies.id, id))
        .returning({
          enabled: policies.enabled,
          source: policies.source,
          conditions: policies.conditions,
          actions: policies.actions,
          revision: policies.revision,
        });
      await writeAudit(tx, {
        actorType: "user",
        actorId: actor.userId,
        action: "policy.update",
        outcome: row ? "success" : "failure",
        targetType: "policy",
        targetId: id,
        sourceIp: actor.ip,
        details: row
          ? {
              ...policyAuditDetails({
                enabled: row.enabled,
                source: row.source,
                conditions: row.conditions as FindingConditions,
                actions: row.actions as unknown as PolicyAction[],
                revision: row.revision,
              }),
              changed: Object.keys(input).sort().join(","),
            }
          : { reason: "not_found" },
      });
      return row ? { outcome: "ok" as const, id } : { outcome: "not_found" as const };
    });
  } catch (err) {
    if (isUniqueViolation(err)) return { outcome: "name_taken" };
    throw err;
  }
}

/** Deletes a policy and its exceptions; its incidents are kept (policy name snapshot). */
export async function deletePolicy(db: Database, id: string, actor: Actor): Promise<boolean> {
  return db.transaction(async (tx) => {
    const rows = await tx.delete(policies).where(eq(policies.id, id)).returning({ id: policies.id });
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "policy.delete",
      outcome: rows.length > 0 ? "success" : "failure",
      targetType: "policy",
      targetId: id,
      sourceIp: actor.ip,
      details: rows.length > 0 ? undefined : { reason: "not_found" },
    });
    return rows.length > 0;
  });
}

export interface PolicyView {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  source: PolicySource;
  conditions: FindingConditions;
  actions: PolicyAction[];
  severity: Severity;
  notifyChannels: string[];
  revision: number;
  updatedAt: Date;
  /** The worker has applied the latest change to the existing findings. */
  evaluated: boolean;
}

export async function listPolicies(db: Database): Promise<PolicyView[]> {
  const rows = await db
    .select({
      id: policies.id,
      name: policies.name,
      description: policies.description,
      enabled: policies.enabled,
      source: policies.source,
      conditions: policies.conditions,
      actions: policies.actions,
      revision: policies.revision,
      updatedAt: policies.updatedAt,
      evaluated: sql<boolean>`${policies.evaluatedAt} is not null and ${policies.evaluatedAt} >= ${policies.changedAt}`,
    })
    .from(policies)
    .orderBy(asc(sql`lower(${policies.name})`));
  return rows.map((r) => {
    const actions = r.actions as unknown as PolicyAction[];
    return {
      ...r,
      conditions: r.conditions as FindingConditions,
      actions,
      severity: incidentSeverityOf(actions),
      notifyChannels: notifyChannelsOf(actions),
    };
  });
}

export async function getPolicy(db: Database, id: string): Promise<PolicyView | null> {
  return (await listPolicies(db)).find((p) => p.id === id) ?? null;
}

// ------------------------------------------------------------------------ exceptions

export interface ExceptionInput {
  policyId: string | null;
  agentId: string | null;
  targetId: string | null;
  classifier: string | null;
  location: LocationPattern | null;
  reason: string;
  expiresAt: Date | null;
}

const EXCEPTION_KEYS = ["policy_id", "agent_id", "target_id", "classifier", "location", "reason", "expires_at"] as const;
/** At most ~10 years ahead: an expiry is a reminder, not a way around the "no silent forever" rule. */
const MAX_EXPIRY_MS = 3653 * 24 * 3600_000;

export function parseExceptionInput(v: unknown, now = Date.now()): { ok: true; value: ExceptionInput } | { ok: false; error: string } {
  if (!isPlainObject(v)) return { ok: false, error: "body" };
  if (Object.keys(v).some((k) => !(EXCEPTION_KEYS as readonly string[]).includes(k))) return { ok: false, error: "unknown_key" };
  const opt = <T>(x: unknown, check: (y: unknown) => y is T): T | null | undefined =>
    x === undefined || x === null ? null : check(x) ? x : undefined;
  const policyId = opt(v.policy_id, (x): x is string => typeof x === "string" && UUID.test(x));
  if (policyId === undefined) return { ok: false, error: "policy_id" };
  const agentId = opt(v.agent_id, (x): x is string => typeof x === "string" && UUID.test(x));
  if (agentId === undefined) return { ok: false, error: "agent_id" };
  const targetId = opt(v.target_id, (x): x is string => validateSchema("TargetId", x).ok);
  if (targetId === undefined) return { ok: false, error: "target_id" };
  const classifier = opt(v.classifier, isClassifierSelector);
  if (classifier === undefined) return { ok: false, error: "classifier" };
  let location: LocationPattern | null = null;
  if (v.location !== undefined && v.location !== null) {
    const l = parseLocationPattern(v.location);
    if (!l.ok) return l;
    location = l.value;
  }
  if (agentId === null && targetId === null && classifier === null && location === null) {
    // An exception always has a scope: it can never silence every finding.
    return { ok: false, error: "scope" };
  }
  if (typeof v.reason !== "string" || v.reason.trim() === "" || !isDescription(v.reason, REASON_MAX)) {
    return { ok: false, error: "reason" };
  }
  let expiresAt: Date | null = null;
  if (v.expires_at !== undefined && v.expires_at !== null) {
    const t = typeof v.expires_at === "string" && validateSchema("Timestamp", v.expires_at).ok ? Date.parse(v.expires_at) : NaN;
    if (!Number.isFinite(t) || t <= now || t > now + MAX_EXPIRY_MS) return { ok: false, error: "expires_at" };
    expiresAt = new Date(t);
  }
  return { ok: true, value: { policyId, agentId, targetId, classifier, location, reason: v.reason.trim(), expiresAt } };
}

export type ExceptionWriteOutcome = { outcome: "ok"; id: string } | { outcome: "unknown_policy" } | { outcome: "unknown_agent" };

export async function createException(db: Database, input: ExceptionInput, actor: Actor): Promise<ExceptionWriteOutcome> {
  return db.transaction(async (tx) => {
    if (input.policyId) {
      const [p] = await tx.select({ id: policies.id }).from(policies).where(eq(policies.id, input.policyId)).limit(1);
      if (!p) return { outcome: "unknown_policy" as const };
    }
    if (input.agentId) {
      const [a] = await tx.select({ id: agents.id }).from(agents).where(eq(agents.id, input.agentId)).limit(1);
      if (!a) return { outcome: "unknown_agent" as const };
    }
    const [row] = await tx
      .insert(policyExceptions)
      .values({ ...input, createdBy: actor.userId })
      .returning({ id: policyExceptions.id });
    if (!row) throw new Error("exception insert returned no row");
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "policy_exception.create",
      targetType: "policy_exception",
      targetId: row.id,
      sourceIp: actor.ip,
      details: {
        policy_id: input.policyId,
        agent_id: input.agentId,
        target_id: input.targetId,
        classifier: input.classifier,
        location: input.location !== null,
        expires_at: input.expiresAt?.toISOString() ?? null,
      },
    });
    return { outcome: "ok" as const, id: row.id };
  });
}

/**
 * Deletes an exception. The policies it covered are marked changed, so the worker re-evaluates
 * the existing findings that the exception was suppressing.
 */
export async function deleteException(db: Database, id: string, actor: Actor): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [row] = await tx
      .delete(policyExceptions)
      .where(eq(policyExceptions.id, id))
      .returning({ policyId: policyExceptions.policyId });
    if (row) {
      await tx
        .update(policies)
        .set({ changedAt: sql`now()` })
        .where(row.policyId === null ? undefined : eq(policies.id, row.policyId));
    }
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "policy_exception.delete",
      outcome: row ? "success" : "failure",
      targetType: "policy_exception",
      targetId: id,
      sourceIp: actor.ip,
      details: row ? { policy_id: row.policyId } : { reason: "not_found" },
    });
    return row !== undefined;
  });
}

export interface ExceptionView {
  id: string;
  policyId: string | null;
  policyName: string | null;
  agentId: string | null;
  agentName: string | null;
  targetId: string | null;
  classifier: string | null;
  location: LocationPattern | null;
  reason: string;
  expiresAt: Date | null;
  createdAt: Date;
}

export async function listExceptions(db: Database, policyId?: string): Promise<ExceptionView[]> {
  const rows = await db
    .select({
      id: policyExceptions.id,
      policyId: policyExceptions.policyId,
      policyName: policies.name,
      agentId: policyExceptions.agentId,
      agentName: agents.name,
      targetId: policyExceptions.targetId,
      classifier: policyExceptions.classifier,
      location: policyExceptions.location,
      reason: policyExceptions.reason,
      expiresAt: policyExceptions.expiresAt,
      createdAt: policyExceptions.createdAt,
    })
    .from(policyExceptions)
    .leftJoin(policies, eq(policies.id, policyExceptions.policyId))
    .leftJoin(agents, eq(agents.id, policyExceptions.agentId))
    .where(policyId ? or(eq(policyExceptions.policyId, policyId), isNull(policyExceptions.policyId)) : undefined)
    .orderBy(asc(policyExceptions.createdAt));
  return rows.map((r) => ({ ...r, location: (r.location as LocationPattern | null) ?? null }));
}
