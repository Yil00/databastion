import { createHash, timingSafeEqual } from "node:crypto";

import { sql } from "drizzle-orm";

import { readEnvOrFile, type Env } from "@/config/env";
import type { Database } from "@/db/client";
import { logger } from "@/lib/logger";

import { argon2Stats } from "./crypto";

/**
 * Prometheus `/metrics` (ADR-0004): console metrics plus the agent metrics received in heartbeats.
 * Prometheus scrapes only the console; agents are never scraped.
 *
 * FROZEN names (the dev Grafana dashboard and user alerts depend on them; renaming one is a breaking
 * change to document in the CHANGELOG):
 *
 * Console-computed, per agent (label `agent_id`; enrolled / online agents only, not revoked or locked):
 * - `databastion_agent_last_seen_seconds`   seconds since the last heartbeat (absent before the first)
 * - `databastion_agent_up`                  1 when the last heartbeat is < 90 s old, else 0
 * - `databastion_agent_clock_skew_seconds`  agent clock minus console clock at the last heartbeat
 * - `databastion_agent_target_reachable`    labels `agent_id`, `target_id`: 1 / 0
 * - `databastion_agent_target_audit_level`  labels `agent_id`, `target_id`: full 3, partial 2, limited 1, none 0
 * Agent-reported (from the heartbeat, prefix `databastion_agent_reported_`):
 * - `databastion_agent_reported_uptime_seconds`, `..._spool_bytes`, `..._spool_max_bytes`, `..._spool_batches`
 * - `databastion_agent_reported_<name>`         heartbeat `metrics.<name>`, label `agent_id`
 * - `databastion_agent_reported_target_<name>`  heartbeat `targets[].metrics.<name>`, labels `agent_id`, `target_id`
 * Console (whole installation):
 * - `databastion_agents{status}`, `databastion_jobs{status}`, `databastion_enrollment_tokens_active`,
 *   `databastion_security_events`, `databastion_console_argon2_operations_total` (this process),
 *   `databastion_metrics_series_dropped` (series dropped by the caps of the last scrape).
 *
 * Agent-provided names are restricted by the contract to `^[a-z][a-z0-9_]{0,63}$` (values: numbers).
 * Names on `RESERVED_REPORTED_NAMES` (or starting with `target_` at agent level) are ignored, so an
 * agent cannot shadow a console-computed series. Cardinality caps: `MAX_AGENTS` agents,
 * `MAX_REPORTED_SERIES` agent-reported series per scrape.
 */

export const SILENT_AFTER_S = 90;
export const MAX_AGENTS = 1000;
export const MAX_REPORTED_SERIES = 50_000;
const METRIC_NAME = /^[a-z][a-z0-9_]{0,63}$/;

export const RESERVED_REPORTED_NAMES: ReadonlySet<string> = new Set([
  "last_seen_seconds",
  "up",
  "revoked",
  "locked",
  "status",
  "info",
  "clock_skew_seconds",
  "uptime_seconds",
  "spool_bytes",
  "spool_max_bytes",
  "spool_batches",
]);

export function isReportedNameAllowed(name: string, level: "agent" | "target"): boolean {
  if (!METRIC_NAME.test(name) || RESERVED_REPORTED_NAMES.has(name)) return false;
  return level === "target" || !name.startsWith("target_");
}

const AUDIT_LEVEL_VALUE: Record<string, number> = { full: 3, partial: 2, limited: 1, none: 0 };

type Labels = Record<string, string>;
interface Family {
  type: "gauge" | "counter";
  help: string;
  samples: { labels: Labels; value: number }[];
}

export class Exposition {
  private readonly families = new Map<string, Family>();

  add(name: string, type: Family["type"], help: string, value: number, labels: Labels = {}): void {
    if (!Number.isFinite(value)) return;
    let family = this.families.get(name);
    if (!family) {
      family = { type, help, samples: [] };
      this.families.set(name, family);
    }
    family.samples.push({ labels, value });
  }

  /** Prometheus text format 0.0.4. Samples of a family are grouped under one HELP / TYPE. */
  render(): string {
    const out: string[] = [];
    for (const [name, family] of this.families) {
      out.push(`# HELP ${name} ${family.help}`, `# TYPE ${name} ${family.type}`);
      for (const s of family.samples) {
        const labels = Object.entries(s.labels)
          .map(([k, v]) => `${k}="${escapeLabel(v)}"`)
          .join(",");
        out.push(`${name}${labels ? `{${labels}}` : ""} ${formatValue(s.value)}`);
      }
    }
    return out.join("\n") + "\n";
  }
}

export function escapeLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

function formatValue(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toString();
}

interface AgentMetricsRow extends Record<string, unknown> {
  id: string;
  last_seen_s: number | string | null;
  clock_skew_ms: number | null;
  uptime_s: number | null;
  spool: Record<string, unknown> | null;
  metrics: Record<string, unknown> | null;
}

interface TargetMetricsRow extends Record<string, unknown> {
  agent_id: string;
  target_id: string;
  reachable: boolean;
  audit_level: string;
  metrics: Record<string, unknown> | null;
}

interface CountRow extends Record<string, unknown> {
  k: string;
  n: number | string;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export async function collectMetrics(db: Database): Promise<string> {
  const x = new Exposition();
  let dropped = 0;
  let reported = 0;
  const addReported = (name: string, help: string, value: number, labels: Labels) => {
    if (reported >= MAX_REPORTED_SERIES) {
      dropped++;
      return;
    }
    reported++;
    x.add(name, "gauge", help, value, labels);
  };

  const agentRows = (
    await db.execute<AgentMetricsRow>(sql`
      select id, extract(epoch from (now() - last_seen_at)) as last_seen_s, clock_skew_ms, uptime_s,
        spool, metrics
      from agents where revoked_at is null and locked_at is null
      order by enrolled_at, id limit ${MAX_AGENTS + 1}`)
  ).rows;
  if (agentRows.length > MAX_AGENTS) {
    dropped += agentRows.length - MAX_AGENTS;
    agentRows.length = MAX_AGENTS;
  }
  const exported = new Set<string>();
  for (const a of agentRows) {
    exported.add(a.id);
    const labels = { agent_id: a.id };
    if (a.last_seen_s !== null) {
      const age = Math.max(0, Number(a.last_seen_s));
      x.add("databastion_agent_last_seen_seconds", "gauge", "Seconds since the last heartbeat of the agent.", Math.round(age * 1000) / 1000, labels);
      x.add("databastion_agent_up", "gauge", `1 when the last heartbeat is less than ${SILENT_AFTER_S} s old.`, age < SILENT_AFTER_S ? 1 : 0, labels);
    } else {
      x.add("databastion_agent_up", "gauge", `1 when the last heartbeat is less than ${SILENT_AFTER_S} s old.`, 0, labels);
    }
    if (a.clock_skew_ms !== null) {
      x.add("databastion_agent_clock_skew_seconds", "gauge", "Agent clock minus console clock at the last heartbeat.", a.clock_skew_ms / 1000, labels);
    }
    if (a.uptime_s !== null) {
      addReported("databastion_agent_reported_uptime_seconds", "Agent-reported uptime.", a.uptime_s, labels);
    }
    for (const [field, name] of [
      ["bytes", "spool_bytes"],
      ["max_bytes", "spool_max_bytes"],
      ["batches", "spool_batches"],
    ] as const) {
      const v = num(a.spool?.[field]);
      if (v !== null) addReported(`databastion_agent_reported_${name}`, `Agent-reported spool ${field}.`, v, labels);
    }
    for (const [name, value] of Object.entries(a.metrics ?? {})) {
      const v = num(value);
      if (v === null || !isReportedNameAllowed(name, "agent")) continue;
      addReported(`databastion_agent_reported_${name}`, "Agent-reported metric (heartbeat).", v, labels);
    }
  }

  const targetRows = (
    await db.execute<TargetMetricsRow>(sql`
      select agent_id, target_id, reachable, audit_level::text as audit_level, metrics
      from agent_targets where present order by agent_id, target_id`)
  ).rows;
  for (const t of targetRows) {
    if (!exported.has(t.agent_id)) continue;
    const labels = { agent_id: t.agent_id, target_id: t.target_id };
    x.add("databastion_agent_target_reachable", "gauge", "Whether the agent reached the target at its last check.", t.reachable ? 1 : 0, labels);
    const level = AUDIT_LEVEL_VALUE[t.audit_level];
    if (level !== undefined) {
      x.add("databastion_agent_target_audit_level", "gauge", "Audit level of the target: full 3, partial 2, limited 1, none 0.", level, labels);
    }
    for (const [name, value] of Object.entries(t.metrics ?? {})) {
      const v = num(value);
      if (v === null || !isReportedNameAllowed(name, "target")) continue;
      addReported(`databastion_agent_reported_target_${name}`, "Agent-reported target metric (heartbeat).", v, labels);
    }
  }

  const counts = async (query: ReturnType<typeof sql>) =>
    (await db.execute<CountRow>(query)).rows.map((r) => [r.k, Number(r.n)] as const);
  for (const [status, n] of await counts(sql`select status::text as k, count(*) as n from agents group by status`)) {
    x.add("databastion_agents", "gauge", "Agents by status.", n, { status });
  }
  for (const [status, n] of await counts(sql`select status::text as k, count(*) as n from jobs group by status`)) {
    x.add("databastion_jobs", "gauge", "Jobs by status.", n, { status });
  }
  const [[, tokens] = ["", 0]] = await counts(sql`
    select 'active' as k, count(*) as n from enrollment_tokens
    where consumed_at is null and revoked_at is null and expires_at > now()`);
  x.add("databastion_enrollment_tokens_active", "gauge", "Unused, unrevoked, unexpired enrollment tokens.", tokens);
  const [[, events] = ["", 0]] = await counts(sql`select 'all' as k, count(*) as n from security_events`);
  x.add("databastion_security_events", "gauge", "Security events recorded (e.g. rotation conflicts).", events);
  x.add("databastion_console_argon2_operations_total", "counter", "argon2id operations started by this process.", argon2Stats.started);
  x.add("databastion_metrics_series_dropped", "gauge", "Series dropped by the cardinality caps in this scrape.", dropped);
  return x.render();
}

// ------------------------------------------------------------------------ authentication

export type MetricsAuth = "ok" | "disabled" | "unauthorized";

let warnedShortToken = false;
export const MIN_METRICS_TOKEN_LENGTH = 32;

/**
 * `Authorization: Bearer <DATABASTION_METRICS_TOKEN(_FILE)>`, compared in constant time (SHA-256 of
 * both sides, so lengths never leak). Unset (or shorter than 32 characters): the endpoint is
 * disabled (`404`).
 */
export function checkMetricsAuth(req: Request, env: Env = process.env): MetricsAuth {
  const expected = readEnvOrFile("DATABASTION_METRICS_TOKEN", env);
  if (expected === undefined) return "disabled";
  if (expected.length < MIN_METRICS_TOKEN_LENGTH) {
    if (!warnedShortToken) {
      warnedShortToken = true;
      logger.error(`DATABASTION_METRICS_TOKEN is shorter than ${MIN_METRICS_TOKEN_LENGTH} characters: /metrics disabled`);
    }
    return "disabled";
  }
  const presented = /^Bearer (\S+)$/.exec(req.headers.get("authorization") ?? "")?.[1] ?? "";
  const a = createHash("sha256").update(presented).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b) && presented.length > 0 ? "ok" : "unauthorized";
}
