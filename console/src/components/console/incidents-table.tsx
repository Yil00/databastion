import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { incidentsHref } from "@/lib/incidents-filter";
import type { IncidentStatus, Severity } from "@/lib/incident-lifecycle";
import type { IncidentView } from "@/server/incidents";

import { locationLabel } from "./findings-table";

/**
 * Incidents view parts (server components). Agent-provided strings (target ids, names) and
 * admin-typed policy names are rendered as React text nodes: escaped, never HTML. An incident holds
 * no sampled value; masked samples are only shown on the detail page, from the linked finding.
 */

const SEVERITY_VARIANT = { critical: "destructive", high: "destructive", medium: "default", low: "secondary" } as const;
const STATUS_VARIANT = { open: "default", acknowledged: "secondary", resolved: "outline", false_positive: "outline" } as const;

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  open: "open",
  acknowledged: "acknowledged",
  resolved: "resolved",
  false_positive: "false positive",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={SEVERITY_VARIANT[severity]}>{severity}</Badge>;
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge variant={STATUS_VARIANT[status]}>{STATUS_LABEL[status]}</Badge>;
}

export function incidentLocation(i: Pick<IncidentView, "location" | "access">): string {
  if (i.access) {
    const who = i.access.principal.startsWith("hmac-sha256:") ? "fingerprinted account" : i.access.principal;
    return `${who} on ${i.access.database ?? "(no object)"}`;
  }
  return i.location ? locationLabel(i.location) : "(finding no longer available)";
}

export function IncidentsTable({ incidents, now }: { incidents: IncidentView[]; now: number }) {
  if (incidents.length === 0) return <p className="text-sm text-muted-foreground">No incident.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Policy</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Location</TableHead>
          <TableHead>Classifier</TableHead>
          <TableHead>Opened</TableHead>
          <TableHead>Matches</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {incidents.map((i) => (
          <TableRow key={i.id}>
            <TableCell>
              <SeverityBadge severity={i.severity} />
            </TableCell>
            <TableCell>
              <IncidentStatusBadge status={i.status} />
            </TableCell>
            <TableCell>
              <Link className="hover:underline" prefetch={false} href={`/incidents/${i.id}`}>
                {i.policyName}
              </Link>
            </TableCell>
            <TableCell>
              {i.agentId && i.targetId ? (
                <Link
                  className="hover:underline"
                  prefetch={false}
                  href={incidentsHref({ status: "all", agentId: i.agentId, targetId: i.targetId })}
                >
                  {i.agentName ?? "?"} / {i.targetId}
                </Link>
              ) : (
                (i.targetId ?? "")
              )}
            </TableCell>
            <TableCell className="max-w-64 break-all whitespace-normal">{incidentLocation(i)}</TableCell>
            <TableCell>{i.access ? `score ${i.access.score ?? 0}` : (i.classifier ?? "")}</TableCell>
            <TableCell>{formatAge(i.createdAt, now)}</TableCell>
            <TableCell>{i.matchCount}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
