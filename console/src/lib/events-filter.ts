import { validateSchema } from "@/lib/protocol/validate";

import type { SearchParams } from "./findings-filter";

/**
 * Filter of the access events view
 * (`/events?agent=&target=&principal=&signal=&from=&to=&anomaly=1`). `principal` is the principal
 * key (SHA-256 hex, see `principalKey`), never the account name, so no agent text goes into URLs.
 */
export interface EventFilter {
  agentId?: string;
  targetId?: string;
  principalKey?: string;
  /** A contract `Signal` id, or a family (`signature.*`, `shape.*`, `volume.*`). */
  signal?: string;
  from?: Date;
  to?: Date;
  anomalyOnly?: boolean;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY = /^[0-9a-f]{64}$/;
const FAMILY = /^(signature|shape|volume)\.\*$/;

const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : undefined);

function time(v: string | undefined): Date | undefined {
  if (!v || v.length > 40) return undefined;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t) : undefined;
}

/** Query string -> filter; values that do not match the expected formats are ignored. */
export function parseEventFilter(sp: SearchParams): EventFilter {
  const agent = one(sp.agent);
  const target = one(sp.target);
  const principal = one(sp.principal);
  const signal = one(sp.signal);
  return {
    agentId: agent && UUID.test(agent) ? agent : undefined,
    targetId: target && validateSchema("TargetId", target).ok ? target : undefined,
    principalKey: principal && KEY.test(principal) ? principal : undefined,
    signal: signal && (FAMILY.test(signal) || validateSchema("Signal", signal).ok) ? signal : undefined,
    from: time(one(sp.from)),
    to: time(one(sp.to)),
    anomalyOnly: one(sp.anomaly) === "1",
  };
}

/** URL of the events view for a filter (inverse of {@link parseEventFilter}). */
export function eventsHref(q: {
  agent?: string;
  target?: string;
  principal?: string;
  signal?: string;
  from?: string;
  to?: string;
  anomaly?: boolean;
}): string {
  const params = new URLSearchParams();
  if (q.agent) params.set("agent", q.agent);
  if (q.target) params.set("target", q.target);
  if (q.principal) params.set("principal", q.principal);
  if (q.signal) params.set("signal", q.signal);
  if (q.from) params.set("from", q.from);
  if (q.to) params.set("to", q.to);
  if (q.anomaly) params.set("anomaly", "1");
  const s = params.toString();
  return s ? `/events?${s}` : "/events";
}

export function principalHref(agentId: string, targetId: string, principalKey: string): string {
  const params = new URLSearchParams({ agent: agentId, target: targetId, principal: principalKey });
  return `/events/principal?${params.toString()}`;
}
