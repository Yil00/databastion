import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { eventsHref, principalHref } from "@/lib/events-filter";
import type { EventView, PrincipalView } from "@/server/events";

/**
 * Access events view parts (server components). Every agent-provided string (principal,
 * application, client address, object names, signals) is rendered as a React text node: escaped,
 * never HTML. Events carry no value (ADR-0007): only who, which objects, how many rows, signals.
 */

export function objectsLabel(objects: EventView["objects"], max = 3): string {
  const names = objects.map((o) => [o.database, o.schema, o.object].filter((x) => x !== undefined).join("."));
  return names.length > max ? `${names.slice(0, max).join(", ")} and ${names.length - max} more` : names.join(", ");
}

export function formatCount(n: number | null): string {
  if (n === null) return "";
  return n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)} M` : n >= 10_000 ? `${Math.round(n / 1000)} k` : String(Math.round(n));
}

/** Size in bytes, binary units (contract `AccessEvent.bytes`); empty when not reported. */
export function formatBytes(n: number | null): string {
  if (n === null) return "";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return u === 0 ? `${n} B` : `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

export function PrincipalLabel({ principal, fingerprinted }: { principal: string; fingerprinted: boolean }) {
  if (!fingerprinted) return <span className="break-all">{principal}</span>;
  return (
    <span title="The agent sent a fingerprint instead of the account name (unknown or non-conforming name)">
      fingerprint {principal.slice("hmac-sha256:".length, "hmac-sha256:".length + 12)}…
    </span>
  );
}

export function EventsTable({ events, now }: { events: EventView[]; now: number }) {
  if (events.length === 0) return <p className="text-sm text-muted-foreground">No access event.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Principal</TableHead>
          <TableHead>Client</TableHead>
          <TableHead>Action</TableHead>
          <TableHead>Objects</TableHead>
          <TableHead>Rows / bytes</TableHead>
          <TableHead>Signals</TableHead>
          <TableHead>Score</TableHead>
          <TableHead>Incidents</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((e) => (
          <TableRow key={e.id}>
            <TableCell title={e.ts.toISOString()}>
              {formatAge(e.ts, now)}
              {e.aggregatedCount > 1 && <div className="text-xs text-muted-foreground">x{e.aggregatedCount}</div>}
            </TableCell>
            <TableCell>
              <Link className="hover:underline" prefetch={false} href={eventsHref({ agent: e.agentId, target: e.targetId })}>
                {e.agentName} / {e.targetId}
              </Link>
              <div className="text-xs text-muted-foreground">{e.source}</div>
            </TableCell>
            <TableCell className="max-w-48 whitespace-normal">
              <Link className="hover:underline" prefetch={false} href={principalHref(e.agentId, e.targetId, e.principalKey)}>
                <PrincipalLabel principal={e.principal} fingerprinted={e.fingerprinted} />
              </Link>
            </TableCell>
            <TableCell className="max-w-40 break-all whitespace-normal text-xs">
              {e.clientAddr ?? ""}
              {e.application ? <div className="text-muted-foreground">{e.application}</div> : null}
            </TableCell>
            <TableCell>{e.action}</TableCell>
            <TableCell className="max-w-64 break-all whitespace-normal text-xs">{objectsLabel(e.objects)}</TableCell>
            <TableCell>
              {formatCount(e.rows)}
              {e.bytes !== null && (
                <div className="text-xs text-muted-foreground" title={`${e.bytes} bytes, as reported by the source`}>
                  {formatBytes(e.bytes)}
                </div>
              )}
            </TableCell>
            <TableCell className="max-w-48 whitespace-normal">
              <div className="flex flex-wrap gap-1">
                {e.signals.map((s) => (
                  <Link key={s} prefetch={false} href={eventsHref({ signal: s })}>
                    <Badge variant="outline">{s}</Badge>
                  </Link>
                ))}
                {e.anomaly && <Badge variant="destructive">above baseline</Badge>}
                {e.unexpectedTarget && (
                  <Badge variant="outline" title="Received for a target the agent no longer reports, or whose Audit settings are disabled">
                    unexpected target
                  </Badge>
                )}
              </div>
            </TableCell>
            <TableCell>
              {e.evaluated ? (e.score ?? 0) : <span className="text-muted-foreground">pending</span>}
              {e.evaluated && e.sensitivity !== null && e.sensitivity > 0 && (
                <div className="text-xs text-muted-foreground">sensitivity {e.sensitivity}</div>
              )}
            </TableCell>
            <TableCell className="text-xs">
              {e.incidentIds.map((id) => (
                <div key={id}>
                  <Link className="hover:underline" prefetch={false} href={`/incidents/${id}`}>
                    {id.slice(0, 8)}
                  </Link>
                </div>
              ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function PrincipalsTable({ principals, now }: { principals: PrincipalView[]; now: number }) {
  if (principals.length === 0) return <p className="text-sm text-muted-foreground">No principal yet.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Principal</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Events</TableHead>
          <TableHead>Typical rows</TableHead>
          <TableHead>Highest score</TableHead>
          <TableHead>Anomalies</TableHead>
          <TableHead>Last event</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {principals.map((p) => (
          <TableRow key={`${p.agentId}/${p.targetId}/${p.principalKey}`}>
            <TableCell className="max-w-48 whitespace-normal">
              <Link className="hover:underline" prefetch={false} href={principalHref(p.agentId, p.targetId, p.principalKey)}>
                <PrincipalLabel principal={p.principal} fingerprinted={p.fingerprinted} />
              </Link>
            </TableCell>
            <TableCell>
              {p.agentName} / {p.targetId}
            </TableCell>
            <TableCell>{p.events}</TableCell>
            <TableCell>{p.warm ? formatCount(p.baselineRows) : <span className="text-muted-foreground">warming up</span>}</TableCell>
            <TableCell>{p.maxScore}</TableCell>
            <TableCell>{p.anomalies}</TableCell>
            <TableCell>{formatAge(p.lastEventAt, now)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
