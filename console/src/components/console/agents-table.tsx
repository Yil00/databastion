import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { displayStatus, formatAge } from "@/lib/agent-status";

import { StatusBadge } from "./status-badge";

export interface AgentListItem {
  id: string;
  name: string;
  hostname: string;
  version: string;
  status: string;
  lastSeenAt: Date | null;
  revokedAt: Date | null;
  lockedAt: Date | null;
  targets: { targetId: string; auditLevel: string; present: boolean }[];
}

/**
 * Agents list. Every agent-reported string (name, hostname, version, target ids) is rendered as a
 * React text node: escaped, never interpreted as HTML.
 */
export function AgentsTable({ agents, now }: { agents: AgentListItem[]; now: number }) {
  if (agents.length === 0) {
    return <p className="text-sm text-muted-foreground">No agent enrolled yet.</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Hostname</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Last seen</TableHead>
          <TableHead>Targets (audit level)</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {agents.map((a) => (
          <TableRow key={a.id}>
            <TableCell>
              <Link href={`/agents/${a.id}`} className="font-medium hover:underline">
                {a.name}
              </Link>
            </TableCell>
            <TableCell>{a.hostname}</TableCell>
            <TableCell>{a.version}</TableCell>
            <TableCell>
              <StatusBadge status={displayStatus(a, now)} />
            </TableCell>
            <TableCell title={a.lastSeenAt?.toISOString()}>{formatAge(a.lastSeenAt, now)}</TableCell>
            <TableCell className="flex flex-wrap gap-1 whitespace-normal">
              {a.targets.filter((t) => t.present).length === 0 && <span className="text-muted-foreground">none</span>}
              {a.targets
                .filter((t) => t.present)
                .map((t) => (
                  <Badge key={t.targetId} variant="outline">
                    {t.targetId}: {t.auditLevel}
                  </Badge>
                ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
