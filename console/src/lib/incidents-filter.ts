import { validateSchema } from "@/lib/protocol/validate";
import { INCIDENT_STATUSES, isSeverity, type IncidentStatus, type Severity } from "@/lib/policy-model";

import type { SearchParams } from "./findings-filter";

/**
 * Filter of the incidents view (`/incidents?status=&severity=&agent=&target=`). `status` is a
 * status, `active` (open + acknowledged, the default) or `all`. Values that do not match are
 * ignored.
 */
export interface IncidentsQuery {
  status: IncidentStatus | "active" | "all";
  severity?: Severity;
  agentId?: string;
  targetId?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : undefined);

export function parseIncidentsQuery(sp: SearchParams): IncidentsQuery {
  const status = one(sp.status);
  const severity = one(sp.severity);
  const agent = one(sp.agent);
  const target = one(sp.target);
  return {
    status:
      status === "all" || status === "active" || (INCIDENT_STATUSES as readonly string[]).includes(status ?? "")
        ? (status as IncidentsQuery["status"])
        : "active",
    severity: isSeverity(severity) ? severity : undefined,
    agentId: agent && UUID.test(agent) ? agent : undefined,
    targetId: target && validateSchema("TargetId", target).ok ? target : undefined,
  };
}

export function queryStatuses(q: IncidentsQuery): IncidentStatus[] | undefined {
  if (q.status === "all") return undefined;
  if (q.status === "active") return ["open", "acknowledged"];
  return [q.status];
}

export function incidentsHref(q: Partial<IncidentsQuery>): string {
  const params = new URLSearchParams();
  if (q.status && q.status !== "active") params.set("status", q.status);
  if (q.severity) params.set("severity", q.severity);
  if (q.agentId) params.set("agent", q.agentId);
  if (q.targetId) params.set("target", q.targetId);
  const s = params.toString();
  return s ? `/incidents?${s}` : "/incidents";
}
