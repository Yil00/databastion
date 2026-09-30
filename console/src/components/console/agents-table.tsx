import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { displayStatus, formatAge } from "@/lib/agent-status";
import { renderTargetNote, type StoredTargetNote } from "@/lib/target-notes";

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
  targets: { targetId: string; auditLevel: string; present: boolean; notes?: readonly StoredTargetNote[] }[];
}

/**
 * Agents list. Every agent-reported string (name, hostname, version, target ids, rendered target
 * notes) is rendered as a React text node or attribute: escaped, never interpreted as HTML. The
 * full notes are on the agent's page.
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
                  <Badge
                    key={t.targetId}
                    variant="outline"
                    title={t.notes && t.notes.length > 0 ? t.notes.map((n) => renderTargetNote(n).text).join("\n") : undefined}
                  >
                    {t.targetId}: {t.auditLevel}
                    {t.notes && t.notes.length > 0 && (
                      <span className="ml-1 text-muted-foreground">
                        ({t.notes.length} note{t.notes.length > 1 ? "s" : ""})
                      </span>
                    )}
                  </Badge>
                ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
