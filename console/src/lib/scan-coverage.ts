/**
 * Coverage of a Discovery scan (contract `JobProgress`, capability `job_progress.coverage`,
 * ADR-0022): how much of the target's scope a scan actually sampled. The agent reports
 * `objects_sampled` and one `skipped_*` counter per reason on the scan's terminal status; the
 * console stores the whole `progress` map with the job (`jobs.progress`, see
 * `applyJobStatus` in src/server/jobs.ts) and derives the view below from it.
 *
 * Why it matters: a paced scan that reaches its deadline stops before the next object, reports the
 * objects left as `skipped_limit` and still **succeeds** (ADR-0035 decision 3). Without coverage,
 * "succeeded" reads as "the whole target was covered", which is a detection gap. The UI therefore
 * flags a succeeded scan that skipped objects as partial (src/components/console/scan-coverage.tsx).
 *
 * Coverage is counts only, never an object name nor a value (I2). The stored map is re-checked on
 * read (defense in depth): only safe non-negative integers are kept.
 */

/** A known skip reason: its contract counter, a short label and, when actionable, a remedy. */
export interface SkipReason {
  key: string;
  label: string;
  hint: string | null;
}

/** The contract `skipped_*` counters, in display order (most actionable first). */
export const SKIP_REASONS: readonly SkipReason[] = [
  {
    key: "skipped_limit",
    label: "time budget or connector limit",
    hint: "raise the scan budget (and the agent's limits.max_scan_duration_s) or the agent's limits.discovery_duty_cycle_percent, or narrow the scan with filters",
  },
  {
    key: "skipped_error",
    label: "sampling failed",
    hint: "the agent log names the failure (e.g. a statement timeout); raise the per-query timeout if needed",
  },
  {
    key: "skipped_not_readable",
    label: "not readable by the agent's account",
    hint: "grant the agent's account read access to them (see the engine's recommended grants)",
  },
  {
    key: "skipped_row_level_security",
    label: "row-level security",
    hint: "row-level security keeps them from the agent's account (ADR-0012)",
  },
  {
    key: "skipped_unsupported",
    label: "kind not sampled (views, merge tables, other storage engines)",
    hint: null,
  },
  {
    key: "skipped_remote",
    label: "data held outside the target (never read)",
    hint: null,
  },
];

const KNOWN_KEYS = new Set(SKIP_REASONS.map((r) => r.key));
/** A `skipped_*` counter this console does not know (a newer contract): shown raw. */
const UNKNOWN_SKIP_KEY = /^skipped_[a-z][a-z0-9_]{0,47}$/;

export interface SkippedCount {
  key: string;
  label: string;
  hint: string | null;
  count: number;
  /** The reason is not in this console's list (shown raw). */
  known: boolean;
}

export interface ScanCoverage {
  /** `objects_sampled`, when reported. */
  sampled: number | null;
  /** `objects_total`, when reported. */
  total: number | null;
  /** The non-zero `skipped_*` counters, known reasons first in {@link SKIP_REASONS} order. */
  skipped: SkippedCount[];
  /** `objects_total - objects_done` when both are reported and positive: objects never reached. */
  unreached: number;
  /** Sum of the skipped and unreached objects. */
  notSampled: number;
  /** At least one coverage counter was reported (`objects_sampled`, `skipped_*` or the totals). */
  reported: boolean;
}

function count(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

/** The coverage of a stored `jobs.progress` value (anything else yields an empty coverage). */
export function parseCoverage(progress: unknown): ScanCoverage {
  const empty: ScanCoverage = { sampled: null, total: null, skipped: [], unreached: 0, notSampled: 0, reported: false };
  if (progress === null || typeof progress !== "object" || Array.isArray(progress)) return empty;
  const p = progress as Record<string, unknown>;
  const own = (k: string) => (Object.hasOwn(p, k) ? count(p[k]) : null);
  const skipped: SkippedCount[] = [];
  let reported = false;
  for (const r of SKIP_REASONS) {
    const n = own(r.key);
    if (n === null) continue;
    reported = true;
    if (n > 0) skipped.push({ ...r, count: n, known: true });
  }
  for (const k of Object.keys(p).sort()) {
    if (KNOWN_KEYS.has(k) || !UNKNOWN_SKIP_KEY.test(k)) continue;
    const n = own(k);
    if (n === null) continue;
    reported = true;
    if (n > 0) skipped.push({ key: k, label: k, hint: null, count: n, known: false });
  }
  const sampled = own("objects_sampled");
  const total = own("objects_total");
  const done = own("objects_done");
  const unreached = total !== null && done !== null && total > done ? total - done : 0;
  reported ||= sampled !== null || total !== null;
  const notSampled = skipped.reduce((s, c) => s + c.count, 0) + unreached;
  return { sampled, total, skipped, unreached, notSampled, reported };
}

export interface CoverageWarning {
  /** Short badge text. */
  badge: string;
  /** Plain-text explanation with the remedies of the reasons involved. */
  text: string;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * The warning of a **succeeded** scan whose coverage reports objects not sampled, or `null`. A
 * failed or cancelled scan already reads as incomplete; its counters are still listed.
 */
export function coverageWarning(status: string, coverage: ScanCoverage): CoverageWarning | null {
  if (status !== "succeeded" || coverage.notSampled === 0) return null;
  const limit = coverage.skipped.find((c) => c.key === "skipped_limit");
  const lead = limit
    ? `Partial: ${plural(limit.count, "object")} not sampled (time budget or connector limit); ${limit.hint}.`
    : `Partial: ${plural(coverage.notSampled, "object")} not sampled.`;
  const others: string[] = [];
  const otherSkipped = coverage.notSampled - coverage.unreached - (limit?.count ?? 0);
  if (limit && otherSkipped > 0) {
    others.push(`${plural(otherSkipped, "other object")} not sampled for the reasons listed.`);
  }
  if (coverage.unreached > 0) others.push(`${plural(coverage.unreached, "object")} never reached (scan stopped early).`);
  return { badge: "partial coverage", text: [lead, ...others].join(" ") };
}
