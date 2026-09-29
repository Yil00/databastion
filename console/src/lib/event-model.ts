import { EVENT_ACTIONS } from "@/lib/protocol/enums";
import { validateSchema } from "@/lib/protocol/validate";

import {
  ENGINES,
  fail,
  globMatch,
  isGlob,
  isPlainObject,
  onlyKeys,
  stringList,
  UUID,
  type Parsed,
} from "./policy-common";

/**
 * Audit correlation model (P4-C): sensitivity and score of an access event, per-principal
 * baselines, policy conditions of source `access_event`, and the incident dedup scope. Pure
 * functions only (worker, user API, UI and tests). Nothing here ever sees a value: events carry
 * none (ADR-0007), only names, counts and signals.
 *
 * ## Sensitivity (per object)
 * From the Discovery findings of the object (same agent, target, database, schema and object; any
 * column; false positives excluded): for each classifier found, its weight (table below) times the
 * highest confidence among the object's columns for it, summed over the classifiers and capped at
 * `SENSITIVITY_CAP`. An object without finding has sensitivity 0. An event's sensitivity is the
 * highest sensitivity among its objects. An event object without a schema (MySQL, MongoDB, LDAP, or
 * a source that does not log it) matches the findings of that database and object in any schema.
 *
 * ## Score (per event)
 * `score = sensitivity x log10(1 + rows)`, rounded to 2 decimals; 0 when the event reports no
 * `rows` (the source gives no volume) or reaches no sensitive object. The logarithm keeps a dump of
 * 1 M rows of a mildly sensitive table (email only: 3 x 6 = 18) comparable to 1 000 rows of card
 * numbers (8 x 3 = 24): volume counts in orders of magnitude, sensitivity linearly. For an event
 * pre-aggregated by the agent, `rows` is the total of the merged events.
 *
 * ## Baselines (per agent, target and principal)
 * Exponentially weighted mean and variance of `x = ln(1 + rows)` over the principal's events that
 * report `rows`, with weight `alpha = max(BASELINE_ALPHA, 1 / n)` for the n-th event (the plain
 * mean during warm-up, then an EWMA whose memory is about 1 / alpha = 20 events). The baseline is
 * warm after `BASELINE_WARMUP` events. A warm baseline flags an event as an anomaly when
 * `rows >= ANOMALY_MIN_ROWS` and `x > mean + max(ln(ANOMALY_FACTOR), ANOMALY_SIGMAS x sd)`: at least
 * ten times the principal's typical volume, and three standard deviations above it. The verdict
 * uses the baseline before the event; the event then updates it with `x` capped at that threshold
 * (so one dump cannot inflate the baseline, while a lasting increase still raises it gradually).
 * The same statistics are kept on `ln(1 + score)` for display. Only these aggregates are stored.
 */

// ---------------------------------------------------------------------------- scoring

/**
 * Weight of each classifier of the registry (`shared/protocol/classifiers.json`), from the harm of
 * a disclosure: credentials and payment data first, then national identifiers, then contact data.
 * An id missing here gets the weight of its family, then `DEFAULT_WEIGHT`.
 */
export const CLASSIFIER_WEIGHTS: Readonly<Record<string, number>> = {
  "secret.aws_key": 10,
  "secret.password_hash": 8,
  "pii.card_number": 8,
  "pii.iban": 7,
  "pii.nir": 7,
  "pii.birth_date": 3,
  "pii.email": 3,
  "pii.phone": 3,
  "pii.postal_address": 3,
  "pii.person_name": 2,
};
export const FAMILY_WEIGHTS: Readonly<Record<string, number>> = { secret: 8, pii: 2 };
export const DEFAULT_WEIGHT = 1;
export const SENSITIVITY_CAP = 30;

export function classifierWeight(id: string): number {
  if (Object.hasOwn(CLASSIFIER_WEIGHTS, id)) return CLASSIFIER_WEIGHTS[id] as number;
  const family = id.split(".")[0] ?? "";
  if (Object.hasOwn(FAMILY_WEIGHTS, family)) return FAMILY_WEIGHTS[family] as number;
  return DEFAULT_WEIGHT;
}

const round2 = (n: number) => Math.round(n * 100) / 100;
const unitClamp = (n: number) => (Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0);

export interface ClassifierHit {
  classifier: string;
  confidence: number;
}

/** Sensitivity of one object from its findings (see the module comment). */
export function objectSensitivity(hits: readonly ClassifierHit[]): number {
  const best = new Map<string, number>();
  for (const h of hits) best.set(h.classifier, Math.max(best.get(h.classifier) ?? 0, unitClamp(h.confidence)));
  let s = 0;
  for (const [classifier, confidence] of best) s += classifierWeight(classifier) * confidence;
  return round2(Math.min(SENSITIVITY_CAP, s));
}

/** Volume x sensitivity score of an event. */
export function eventScore(sensitivity: number, rows: number | null | undefined): number {
  if (rows === null || rows === undefined || !(rows > 0) || !(sensitivity > 0)) return 0;
  return round2(sensitivity * Math.log10(1 + rows));
}

// -------------------------------------------------------------------------- baselines

/**
 * Only events that report a volume and read or change data feed a baseline: never `connect` or
 * `auth_failure` (security review H1: a login attempt with a random account name must not create
 * a baseline).
 */
export function baselineEligible(e: { action: string; rows: number | null | undefined }): boolean {
  return e.rows !== null && e.rows !== undefined && e.rows >= 0 && e.action !== "connect" && e.action !== "auth_failure";
}

export const BASELINE_ALPHA = 0.05;
export const BASELINE_WARMUP = 20;
export const ANOMALY_FACTOR = 10;
export const ANOMALY_SIGMAS = 3;
export const ANOMALY_MIN_ROWS = 1000;

export interface BaselineState {
  /** Events with `rows` counted so far. */
  events: number;
  meanLogRows: number;
  varLogRows: number;
  meanLogScore: number;
  varLogScore: number;
}

export const EMPTY_BASELINE: BaselineState = { events: 0, meanLogRows: 0, varLogRows: 0, meanLogScore: 0, varLogScore: 0 };

export interface BaselineVerdict {
  warm: boolean;
  anomaly: boolean;
  /** Typical volume `exp(mean) - 1` of a warm baseline, else null. */
  baselineRows: number | null;
  /** Volume above which an event is an anomaly (warm baseline), else null. */
  thresholdRows: number | null;
}

const threshold = (mean: number, variance: number) =>
  mean + Math.max(Math.log(ANOMALY_FACTOR), ANOMALY_SIGMAS * Math.sqrt(Math.max(0, variance)));

export function isWarm(state: Pick<BaselineState, "events">): boolean {
  return state.events >= BASELINE_WARMUP;
}

/** Verdict on an event volume against the baseline before the event. */
export function baselineVerdict(state: BaselineState, rows: number | null | undefined): BaselineVerdict {
  if (!isWarm(state)) return { warm: false, anomaly: false, baselineRows: null, thresholdRows: null };
  const limit = threshold(state.meanLogRows, state.varLogRows);
  const verdict = {
    warm: true,
    baselineRows: round2(Math.expm1(state.meanLogRows)),
    thresholdRows: round2(Math.expm1(limit)),
  };
  if (rows === null || rows === undefined || !(rows >= 0)) return { ...verdict, anomaly: false };
  return { ...verdict, anomaly: rows >= ANOMALY_MIN_ROWS && Math.log1p(rows) > limit };
}

function ewStep(mean: number, variance: number, x: number, alpha: number): [number, number] {
  const diff = x - mean;
  const incr = alpha * diff;
  return [mean + incr, Math.max(0, (1 - alpha) * (variance + diff * incr))];
}

/** The baseline after an event (unchanged when the event reports no `rows`). */
export function updateBaseline(state: BaselineState, rows: number | null | undefined, score: number): BaselineState {
  if (rows === null || rows === undefined || !(rows >= 0)) return state;
  const warm = isWarm(state);
  const n = state.events + 1;
  const alpha = Math.max(BASELINE_ALPHA, 1 / n);
  let x = Math.log1p(rows);
  let y = Math.log1p(Math.max(0, score));
  if (warm) {
    x = Math.min(x, threshold(state.meanLogRows, state.varLogRows));
    y = Math.min(y, threshold(state.meanLogScore, state.varLogScore));
  }
  const [meanLogRows, varLogRows] = ewStep(state.meanLogRows, state.varLogRows, x, alpha);
  const [meanLogScore, varLogScore] = ewStep(state.meanLogScore, state.varLogScore, y, alpha);
  return { events: n, meanLogRows, varLogRows, meanLogScore, varLogScore };
}

// ------------------------------------------------------------------------- conditions

/** Contract `AccessEvent.action` (checked against the generated types in src/lib/protocol/enums.ts). */
export { EVENT_ACTIONS };
/**
 * A signal id of the contract (`Signal`: 1 to 6 words of 1 to 16 letters, no digit, ADR-0022), or a
 * family: `signature.*`, `shape.*`, `volume.*`. Checked on every new or changed policy.
 */
export const SIGNAL_SELECTOR = /^(signature|shape|volume)\.([a-z]{1,16}(_[a-z]{1,16}){0,5}|\*)$/;
/**
 * The selector accepted before the contract pattern was narrowed (P4-D). Only used to load stored
 * policy documents (`parseEventConditions(v, { stored: true })`), so a policy written earlier with a
 * digit in a signal id keeps being evaluated (that id can no longer match a conforming signal; its
 * other conditions still apply). Saving the policy again requires the narrowed form.
 */
export const LEGACY_SIGNAL_SELECTOR = /^(signature|shape|volume)\.([a-z0-9_]{1,55}|\*)$/;
export const OBJECT_PARTS = ["database", "schema", "object"] as const;
export type ObjectPart = (typeof OBJECT_PARTS)[number];
export type ObjectPattern = Partial<Record<ObjectPart, string>>;
/** Upper bound of the score and sensitivity thresholds (well above the highest possible score). */
export const MAX_SCORE_THRESHOLD = 1_000_000;

/**
 * Condition document of source `access_event` (every key optional, all present keys must hold;
 * the values of a list are alternatives). At least one of the selective keys is required, so a
 * policy never turns every access into an incident.
 * - `signals`: signal ids or families (`signature.*`); the event carries at least one of them;
 * - `event_actions`: `connect`, `auth_failure`, `read`, `write`, `ddl`, `dcl`;
 * - `sources` (contract `AuditSource`), `agent_ids`, `target_ids`, `engines` (of the target);
 * - `principals`, `exclude_principals`: globs on the principal (`db_user`, or the
 *   `hmac-sha256:...` fingerprint sent in its place);
 * - `objects`: globs on the normalized `database`, `schema`, `object` names; at least one object of
 *   the event matches (an event without object never does);
 * - `min_rows`, `min_score`, `min_sensitivity`: thresholds (an event without `rows` never reaches
 *   `min_rows`);
 * - `anomaly`: `true` to match only events above the principal's baseline.
 */
export interface EventConditions {
  signals?: string[];
  event_actions?: string[];
  sources?: string[];
  agent_ids?: string[];
  target_ids?: string[];
  engines?: string[];
  principals?: string[];
  exclude_principals?: string[];
  objects?: ObjectPattern;
  min_rows?: number;
  min_score?: number;
  min_sensitivity?: number;
  anomaly?: true;
}

export const EVENT_CONDITION_KEYS = [
  "signals",
  "event_actions",
  "sources",
  "agent_ids",
  "target_ids",
  "engines",
  "principals",
  "exclude_principals",
  "objects",
  "min_rows",
  "min_score",
  "min_sensitivity",
  "anomaly",
] as const;

export const SELECTIVE_EVENT_KEYS = [
  "signals",
  "event_actions",
  "principals",
  "objects",
  "min_rows",
  "min_score",
  "min_sensitivity",
  "anomaly",
] as const;

export function parseObjectPattern(v: unknown): Parsed<ObjectPattern> {
  if (!isPlainObject(v) || onlyKeys(v, OBJECT_PARTS) !== null) return fail("objects");
  const out: ObjectPattern = {};
  for (const part of OBJECT_PARTS) {
    const g = v[part];
    if (g === undefined) continue;
    if (!isGlob(g)) return fail(`objects.${part}`);
    out[part] = g;
  }
  if (Object.keys(out).length === 0) return fail("objects");
  return { ok: true, value: out };
}

const threshold01 = (n: unknown): n is number =>
  typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= MAX_SCORE_THRESHOLD;

/**
 * Strict validation of a condition document of source `access_event` (unknown keys rejected).
 * `stored: true` when loading a document saved earlier: signal selectors are then checked with
 * {@link LEGACY_SIGNAL_SELECTOR}, so a narrower pattern never silently disables a stored policy.
 */
export function parseEventConditions(v: unknown, opts: { stored?: boolean } = {}): Parsed<EventConditions> {
  if (!isPlainObject(v)) return fail("conditions");
  if (onlyKeys(v, EVENT_CONDITION_KEYS) !== null) return fail("conditions");
  const out: EventConditions = {};
  const selector = opts.stored ? LEGACY_SIGNAL_SELECTOR : SIGNAL_SELECTOR;
  const lists: [keyof EventConditions & string, (s: string) => boolean][] = [
    ["signals", (s) => s.length <= 64 && selector.test(s)],
    ["event_actions", (s) => (EVENT_ACTIONS as readonly string[]).includes(s)],
    ["sources", (s) => validateSchema("AuditSource", s).ok],
    ["agent_ids", (s) => UUID.test(s)],
    ["target_ids", (s) => validateSchema("TargetId", s).ok],
    ["engines", (s) => (ENGINES as readonly string[]).includes(s)],
    ["principals", isGlob],
    ["exclude_principals", isGlob],
  ];
  for (const [key, check] of lists) {
    if (v[key] === undefined) continue;
    const r = stringList(v[key], key, check);
    if (!r.ok) return r;
    (out as Record<string, unknown>)[key] = r.value;
  }
  if (v.objects !== undefined) {
    const r = parseObjectPattern(v.objects);
    if (!r.ok) return r;
    out.objects = r.value;
  }
  if (v.min_rows !== undefined) {
    const n = v.min_rows;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) return fail("min_rows");
    out.min_rows = n;
  }
  for (const key of ["min_score", "min_sensitivity"] as const) {
    if (v[key] === undefined) continue;
    if (!threshold01(v[key])) return fail(key);
    out[key] = v[key];
  }
  if (v.anomaly !== undefined) {
    if (v.anomaly !== true) return fail("anomaly");
    out.anomaly = true;
  }
  if (!SELECTIVE_EVENT_KEYS.some((k) => out[k] !== undefined)) return fail("conditions");
  return { ok: true, value: out };
}

// --------------------------------------------------------------------------- matching

export interface EventObject {
  database: string;
  schema?: string | null;
  object: string;
}

/** The event fields a policy may look at (no value: events carry none). */
export interface EventFacts {
  agentId: string;
  targetId: string;
  /** Engine last reported for the target. */
  engine: string | null;
  /** `db_user`, or the `hmac-sha256:` fingerprint sent in its place. */
  principal: string;
  action: string;
  source: string;
  objects: readonly EventObject[];
  rows: number | null;
  signals: readonly string[];
  sensitivity: number;
  score: number;
  anomaly: boolean;
}

export function signalSelected(selectors: readonly string[], signal: string): boolean {
  return selectors.some((s) => (s.endsWith(".*") ? signal.startsWith(s.slice(0, -1)) : s === signal));
}

/** An object without schema only matches a schema glob of `*` (as for finding locations). */
export function objectMatches(pattern: ObjectPattern, o: EventObject): boolean {
  return OBJECT_PARTS.every((part) => {
    const g = pattern[part];
    if (g === undefined) return true;
    const name = part === "schema" ? (o.schema ?? null) : o[part];
    return name === null ? g === "*" : globMatch(g, name);
  });
}

/**
 * Indexes of the event objects retained by the conditions (every object without an `objects`
 * key), or `null` when the event does not match.
 */
export function eventMatches(c: EventConditions, e: EventFacts): number[] | null {
  if (c.agent_ids && !c.agent_ids.includes(e.agentId)) return null;
  if (c.target_ids && !c.target_ids.includes(e.targetId)) return null;
  if (c.engines && (e.engine === null || !c.engines.includes(e.engine))) return null;
  if (c.sources && !c.sources.includes(e.source)) return null;
  if (c.event_actions && !c.event_actions.includes(e.action)) return null;
  if (c.signals && !e.signals.some((s) => signalSelected(c.signals as string[], s))) return null;
  if (c.principals && !c.principals.some((g) => globMatch(g, e.principal))) return null;
  if (c.exclude_principals && c.exclude_principals.some((g) => globMatch(g, e.principal))) return null;
  if (c.min_rows !== undefined && (e.rows === null || e.rows < c.min_rows)) return null;
  if (c.min_score !== undefined && e.score < c.min_score) return null;
  if (c.min_sensitivity !== undefined && e.sensitivity < c.min_sensitivity) return null;
  if (c.anomaly && !e.anomaly) return null;
  const all = e.objects.map((_, i) => i);
  if (!c.objects) return all;
  const pattern = c.objects;
  const kept = all.filter((i) => objectMatches(pattern, e.objects[i] as EventObject));
  return kept.length > 0 ? kept : null;
}

export interface EventExceptionScope {
  policyId: string | null;
  agentId: string | null;
  targetId: string | null;
  classifier: string | null;
  location: Partial<Record<"database" | "schema" | "object" | "field", string>> | null;
  expiresAt: Date | null;
}

/**
 * Policy exceptions applied to an event (every set scope must hold): agent, target, and a location
 * whose `database` / `schema` / `object` globs cover every retained object (a `field` glob other
 * than `*` never covers an event, which names no field). A classifier-scoped exception concerns
 * findings only and never covers an event.
 */
export function exceptionCoversEvent(
  x: EventExceptionScope,
  policyId: string,
  e: EventFacts,
  objectIdx: readonly number[],
  now: Date,
): boolean {
  if (x.expiresAt !== null && x.expiresAt.getTime() <= now.getTime()) return false;
  if (x.policyId !== null && x.policyId !== policyId) return false;
  if (x.agentId !== null && x.agentId !== e.agentId) return false;
  if (x.targetId !== null && x.targetId !== e.targetId) return false;
  if (x.classifier !== null) return false;
  if (x.location !== null) {
    const { field, ...parts } = x.location;
    if (field !== undefined && field !== "*") return false;
    if (objectIdx.length === 0) return false;
    return objectIdx.every((i) => objectMatches(parts, e.objects[i] as EventObject));
  }
  return true;
}

// ------------------------------------------------------------------------------ dedup

/**
 * Dedup scope of the incidents raised from events: one incident per policy, agent, target,
 * principal, database and UTC hour of the event `ts`. The principal part is coarse for events
 * whose account is unknown (a fingerprint sent instead of the name) and for failed
 * authentications: all of them from one client address count as one principal
 * (`unknown:<sha256 of the client network>`: IPv4 /24, IPv6 /64, IPv4-mapped IPv6 as IPv4,
 * `local` kept), so random account names or rotating addresses cannot open one incident each
 * (security review H1, re-review N2). On top of that, a policy opens at most a configured number
 * of incidents per hour on one target; the further matches go to one overflow incident of the
 * policy on that target, except severe events (`severeEvent`). The database is the one of the most sensitive
 * retained object (the first on a tie), none for an event without object. While that incident is
 * open or acknowledged, the later events of the scope are added to it (`match_count`, rows, highest
 * score, signals). Once it is a false positive, the later events of the scope in that hour are
 * only linked to it. Once it is resolved, a later event of the hour opens a new incident only when
 * it is worse (`worseThanResolved`), else it is linked to it; the next hour opens a new incident. A `pg_dump` of a whole database (one event per table) thus
 * raises one incident per policy and hour, not one per table.
 */
export const EVENT_BUCKET_MS = 3600_000;

export function eventBucket(ts: Date): Date {
  return new Date(Math.floor(ts.getTime() / EVENT_BUCKET_MS) * EVENT_BUCKET_MS);
}

/** Whether the event's principal is grouped by client address in the dedup scope. */
export function coarsePrincipal(e: { fingerprinted: boolean; action: string }): boolean {
  return e.fingerprinted || e.action === "auth_failure";
}

/** Key parts are identifiers and hashes only: never agent-provided free text. */
export function eventDedupKey(k: {
  policyId: string;
  agentId: string;
  targetId: string;
  /** The principal key, or `unknown:<sha256 of client_addr>` for a coarse principal. */
  principalKey: string;
  /** SHA-256 (hex) of the database name, or `-`. */
  databaseKey: string;
  bucket: Date;
}): string {
  return `policy:${k.policyId}|agent:${k.agentId}|target:${k.targetId}|principal:${k.principalKey}|database:${k.databaseKey}|hour:${k.bucket.toISOString()}`;
}

/**
 * Key of the overflow incident of a policy on one target for an hour (console clock). The cap and
 * the overflow are per (policy, agent, target), so noise on one target never pushes the incidents
 * of another target into an overflow (re-review N1).
 */
export function eventOverflowKey(policyId: string, agentId: string, targetId: string, hour: Date): string {
  return `policy:${policyId}|agent:${agentId}|target:${targetId}|overflow|hour:${hour.toISOString()}`;
}

/**
 * A severe event opens its own incident even when the hourly cap is reached (re-review N1): it
 * carries a `signature.*` signal (a dump or export tool), is above its principal's baseline, or
 * scores higher than anything the overflow incident of its scope has counted so far. A
 * `signature.*` id is severe whether or not it is in this console's signal registry (fail-safe:
 * an id registered after this console was built is still a dump or export tool).
 */
export function severeEvent(e: { signals: readonly string[]; anomaly: boolean; score: number }, overflowMaxScore: number | null): boolean {
  if (e.signals.some((s) => s.startsWith("signature."))) return true;
  if (e.anomaly) return true;
  return overflowMaxScore !== null && e.score > overflowMaxScore;
}

/**
 * After the incident of a scope was resolved, a later event of the same scope opens a new
 * incident only when it is clearly worse: a higher score, above the baseline while the incident
 * was not, or a signal the incident did not have (security review M1). Otherwise it is only
 * linked to the resolved incident.
 */
export function worseThanResolved(
  resolved: { eventScore: number | null; eventSignals: readonly string[] | null; eventAnomaly: boolean | null },
  e: { score: number; anomaly: boolean; signals: readonly string[] },
): boolean {
  if (e.score > (resolved.eventScore ?? 0)) return true;
  if (e.anomaly && resolved.eventAnomaly !== true) return true;
  const known = new Set(resolved.eventSignals ?? []);
  return e.signals.some((s) => !known.has(s));
}

/** Index of the retained object that sets the dedup database: the most sensitive, first on a tie. */
export function dedupObject(objectIdx: readonly number[], sensitivities: readonly number[]): number | null {
  let best: number | null = null;
  for (const i of objectIdx) {
    if (best === null || (sensitivities[i] ?? 0) > (sensitivities[best] ?? 0)) best = i;
  }
  return best;
}

export const MAX_INCIDENT_SIGNALS = 16;

/**
 * Union of signals, bounded to {@link MAX_INCIDENT_SIGNALS}: the `signature.*` ids first (sorted),
 * then the others (sorted), so truncation never drops a signature signal in favour of `shape.*` or
 * `volume.*` ones (the severe family decides the cap bypass and the "worse than resolved" check).
 */
export function mergeSignals(a: readonly string[], b: readonly string[]): string[] {
  const all = [...new Set([...a, ...b])];
  const severe = all.filter((s) => s.startsWith("signature.")).sort();
  const others = all.filter((s) => !s.startsWith("signature.")).sort();
  return [...severe, ...others].slice(0, MAX_INCIDENT_SIGNALS);
}
