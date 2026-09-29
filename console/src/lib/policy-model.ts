import { registeredClassifiers, registeredClassifiersVersions } from "@/lib/protocol/classifiers";
import { validateSchema } from "@/lib/protocol/validate";

import { parseEventConditions, type EventConditions } from "./event-model";
import { SEVERITIES, type Severity } from "./incident-lifecycle";
import {
  ENGINES,
  fail,
  globMatch,
  isGlob,
  isPlainObject,
  onlyKeys,
  stringList,
  TEXT,
  UUID,
  type Parsed,
} from "./policy-common";

export * from "./incident-lifecycle";
export { globMatch, isGlob, isPlainObject, MAX_GLOB_LENGTH, MAX_LIST_ITEMS, type Parsed } from "./policy-common";
export type { EventConditions } from "./event-model";

/**
 * Policy model (P3-A): condition -> action documents, their strict validation, glob matching on
 * normalized names and the incident lifecycle (P3-B). Pure functions only: shared by the user API,
 * the worker and the UI.
 *
 * Condition document, source `finding` (every key optional, all present keys must hold: AND; the
 * values of a list: OR):
 * - `classifiers`: registered classifier ids (any registered classifier set) or families (`pii.*`);
 * - `agent_ids`, `target_ids`, `engines`;
 * - `location`: globs (`*`, `?`, `\` escapes, case-insensitive) on the normalized `database`,
 *   `schema`, `object`, `field` names;
 * - `min_confidence`, `min_match_ratio` (matched / sampled) in [0, 1], `min_matched` >= 0.
 * Source `access_event` (P4-C): see src/lib/event-model.ts. A document is validated against the
 * keys of its policy's source, so an old document never changes meaning.
 *
 * Actions: exactly one `create_incident` (with a severity) and up to `MAX_NOTIFY` `notify` actions
 * naming a channel reference (stored only; delivery is P3-C).
 *
 * No document ever holds a sampled value: only identifiers, globs on normalized names and numbers.
 */

export const POLICY_SOURCES = ["finding", "access_event"] as const;
export type PolicySource = (typeof POLICY_SOURCES)[number];


export { ENGINES } from "./policy-common";

export const LOCATION_PARTS = ["database", "schema", "object", "field"] as const;
export type LocationPart = (typeof LOCATION_PARTS)[number];
export type LocationPattern = Partial<Record<LocationPart, string>>;

export interface FindingConditions {
  classifiers?: string[];
  agent_ids?: string[];
  target_ids?: string[];
  engines?: string[];
  location?: LocationPattern;
  min_confidence?: number;
  min_matched?: number;
  min_match_ratio?: number;
}

/** Condition document of a policy, per source. */
export type PolicyConditions = FindingConditions | EventConditions;

export type PolicyAction = { type: "create_incident"; severity: Severity } | { type: "notify"; channel: string };

export const MAX_NOTIFY = 5;
export const NAME_MAX = 100;
export const DESCRIPTION_MAX = 500;
export const REASON_MAX = 500;

/** Channel reference (P3-C resolves it to an SMTP or webhook channel): a slug, never an address. */
export const CHANNEL_REF = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const CLASSIFIER_FAMILY = /^([a-z]+)\.\*$/;


/** Every classifier id of every registered classifier set. */
function allRegisteredClassifiers(): Set<string> {
  const all = new Set<string>();
  for (const version of registeredClassifiersVersions()) {
    for (const id of registeredClassifiers(version) ?? []) all.add(id);
  }
  return all;
}

/** A registered classifier id, or a family (`pii.*`) of at least one registered id. */
export function isClassifierSelector(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const all = allRegisteredClassifiers();
  const family = CLASSIFIER_FAMILY.exec(v);
  if (family) return [...all].some((id) => id.startsWith(`${family[1]}.`));
  return all.has(v);
}

export function classifierSelected(selectors: readonly string[], classifier: string): boolean {
  return selectors.some((s) => (s.endsWith(".*") ? classifier.startsWith(s.slice(0, -1)) : s === classifier));
}


export function parseLocationPattern(v: unknown): Parsed<LocationPattern> {
  if (!isPlainObject(v)) return fail("location");
  if (onlyKeys(v, LOCATION_PARTS) !== null) return fail("location");
  const out: LocationPattern = {};
  for (const part of LOCATION_PARTS) {
    const g = v[part];
    if (g === undefined) continue;
    if (!isGlob(g)) return fail(`location.${part}`);
    out[part] = g;
  }
  if (Object.keys(out).length === 0) return fail("location");
  return { ok: true, value: out };
}

const unit = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 1;

const FINDING_KEYS = [
  "classifiers",
  "agent_ids",
  "target_ids",
  "engines",
  "location",
  "min_confidence",
  "min_matched",
  "min_match_ratio",
] as const;

/** Strict validation of a condition document for `source` (unknown keys rejected). */
export function parsePolicyConditions(source: PolicySource, v: unknown): Parsed<PolicyConditions> {
  if (source === "access_event") return parseEventConditions(v);
  if (source !== "finding") return fail("source");
  return parseFindingConditions(v);
}

/** Strict validation of a condition document of source `finding`. */
export function parseFindingConditions(v: unknown): Parsed<FindingConditions> {
  if (!isPlainObject(v)) return fail("conditions");
  const unknown = onlyKeys(v, FINDING_KEYS);
  if (unknown !== null) return fail("conditions");
  const out: FindingConditions = {};
  if (v.classifiers !== undefined) {
    const r = stringList(v.classifiers, "classifiers", isClassifierSelector);
    if (!r.ok) return r;
    out.classifiers = r.value;
  }
  if (v.agent_ids !== undefined) {
    const r = stringList(v.agent_ids, "agent_ids", (s) => UUID.test(s));
    if (!r.ok) return r;
    out.agent_ids = r.value;
  }
  if (v.target_ids !== undefined) {
    const r = stringList(v.target_ids, "target_ids", (s) => validateSchema("TargetId", s).ok);
    if (!r.ok) return r;
    out.target_ids = r.value;
  }
  if (v.engines !== undefined) {
    const r = stringList(v.engines, "engines", (s) => (ENGINES as readonly string[]).includes(s));
    if (!r.ok) return r;
    out.engines = r.value;
  }
  if (v.location !== undefined) {
    const r = parseLocationPattern(v.location);
    if (!r.ok) return r;
    out.location = r.value;
  }
  if (v.min_confidence !== undefined) {
    if (!unit(v.min_confidence)) return fail("min_confidence");
    out.min_confidence = v.min_confidence;
  }
  if (v.min_match_ratio !== undefined) {
    if (!unit(v.min_match_ratio)) return fail("min_match_ratio");
    out.min_match_ratio = v.min_match_ratio;
  }
  if (v.min_matched !== undefined) {
    const n = v.min_matched;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 10_000) return fail("min_matched");
    out.min_matched = n;
  }
  return { ok: true, value: out };
}

/** Strict validation of an action list: one `create_incident`, at most `MAX_NOTIFY` distinct `notify`. */
export function parsePolicyActions(v: unknown): Parsed<PolicyAction[]> {
  if (!Array.isArray(v) || v.length < 1 || v.length > 1 + MAX_NOTIFY) return fail("actions");
  const out: PolicyAction[] = [];
  const channels = new Set<string>();
  let incident = 0;
  for (const a of v) {
    if (!isPlainObject(a)) return fail("actions");
    if (a.type === "create_incident") {
      if (onlyKeys(a, ["type", "severity"]) !== null) return fail("actions");
      if (typeof a.severity !== "string" || !(SEVERITIES as readonly string[]).includes(a.severity)) {
        return fail("actions.severity");
      }
      incident += 1;
      out.push({ type: "create_incident", severity: a.severity as Severity });
    } else if (a.type === "notify") {
      if (onlyKeys(a, ["type", "channel"]) !== null) return fail("actions");
      if (typeof a.channel !== "string" || !CHANNEL_REF.test(a.channel) || channels.has(a.channel)) {
        return fail("actions.channel");
      }
      channels.add(a.channel);
      out.push({ type: "notify", channel: a.channel });
    } else {
      return fail("actions.type");
    }
  }
  // v1: every policy creates an incident; `notify` actions are attached to it (delivery: P3-C).
  if (incident !== 1) return fail("actions.create_incident");
  return { ok: true, value: out };
}

export function incidentSeverityOf(actions: readonly PolicyAction[]): Severity {
  const a = actions.find((x): x is Extract<PolicyAction, { type: "create_incident" }> => x.type === "create_incident");
  return a?.severity ?? "medium";
}

export function notifyChannelsOf(actions: readonly PolicyAction[]): string[] {
  return actions.flatMap((a) => (a.type === "notify" ? [a.channel] : []));
}

export function isPolicyName(v: unknown): v is string {
  return typeof v === "string" && v.trim().length >= 1 && v.length <= NAME_MAX && TEXT.test(v);
}

export function isDescription(v: unknown, max = DESCRIPTION_MAX): v is string {
  return typeof v === "string" && v.length <= max && TEXT.test(v);
}

// ------------------------------------------------------------------------- matching

/** The finding fields a policy may look at (no sample, no fingerprint). */
export interface FindingFacts {
  agentId: string;
  targetId: string;
  engine: string;
  databaseName: string;
  schemaName: string | null;
  objectName: string;
  fieldName: string;
  classifier: string;
  confidence: number;
  sampled: number;
  matched: number;
}

export function locationMatches(pattern: LocationPattern, f: FindingFacts): boolean {
  const names: Record<LocationPart, string | null> = {
    database: f.databaseName,
    schema: f.schemaName,
    object: f.objectName,
    field: f.fieldName,
  };
  return LOCATION_PARTS.every((part) => {
    const g = pattern[part];
    if (g === undefined) return true;
    const name = names[part];
    // A location without a schema (MySQL, MongoDB...) only matches a schema glob of `*`.
    return name === null ? g === "*" : globMatch(g, name);
  });
}

export function findingMatches(c: FindingConditions, f: FindingFacts): boolean {
  if (c.classifiers && !classifierSelected(c.classifiers, f.classifier)) return false;
  if (c.agent_ids && !c.agent_ids.includes(f.agentId)) return false;
  if (c.target_ids && !c.target_ids.includes(f.targetId)) return false;
  if (c.engines && !c.engines.includes(f.engine)) return false;
  if (c.location && !locationMatches(c.location, f)) return false;
  if (c.min_confidence !== undefined && f.confidence < c.min_confidence) return false;
  if (c.min_matched !== undefined && f.matched < c.min_matched) return false;
  if (c.min_match_ratio !== undefined) {
    const ratio = f.sampled > 0 ? f.matched / f.sampled : 0;
    if (ratio < c.min_match_ratio) return false;
  }
  return true;
}

export interface ExceptionScope {
  policyId: string | null;
  agentId: string | null;
  targetId: string | null;
  classifier: string | null;
  location: LocationPattern | null;
  expiresAt: Date | null;
}

/** The exception is active at `now` and covers `f` for `policyId` (every set scope must match). */
export function exceptionCovers(e: ExceptionScope, policyId: string, f: FindingFacts, now: Date): boolean {
  if (e.expiresAt !== null && e.expiresAt.getTime() <= now.getTime()) return false;
  if (e.policyId !== null && e.policyId !== policyId) return false;
  if (e.agentId !== null && e.agentId !== f.agentId) return false;
  if (e.targetId !== null && e.targetId !== f.targetId) return false;
  if (e.classifier !== null && !classifierSelected([e.classifier], f.classifier)) return false;
  if (e.location !== null && !locationMatches(e.location, f)) return false;
  return true;
}

