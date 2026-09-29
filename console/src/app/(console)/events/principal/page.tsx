import Link from "next/link";
import { notFound } from "next/navigation";

import { EventsTable, formatCount, PrincipalLabel } from "@/components/console/events-table";
import { IncidentStatusBadge, SeverityBadge } from "@/components/console/incidents-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDb } from "@/db/client";
import { formatAge } from "@/lib/agent-status";
import { ANOMALY_FACTOR, ANOMALY_MIN_ROWS, ANOMALY_SIGMAS, BASELINE_WARMUP } from "@/lib/event-model";
import { eventsHref, parseEventFilter } from "@/lib/events-filter";
import type { SearchParams } from "@/lib/findings-filter";
import { getPrincipal, listEvents, principalIncidents } from "@/server/events";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/**
 * One principal of one target (P4-C): its baseline (aggregates only), its latest events and the
 * incidents raised for it. `?agent=&target=&principal=<key>`.
 */
export default async function PrincipalPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  await requirePageSession();
  const filter = parseEventFilter(await searchParams);
  if (!filter.agentId || !filter.targetId || !filter.principalKey) notFound();
  const db = getDb();
  const p = await getPrincipal(db, filter.agentId, filter.targetId, filter.principalKey);
  if (!p) notFound();
  const [events, incidents] = await Promise.all([
    listEvents(db, { agentId: p.agentId, targetId: p.targetId, principalKey: p.principalKey }),
    principalIncidents(db, p.agentId, p.targetId, p.principalKey),
  ]);
  const now = requestTime();
  const facts: [string, string][] = [
    ["Target", `${p.agentName} / ${p.targetId}`],
    ["Events in the baseline", `${p.events}${p.warm ? "" : ` (warming up: ${BASELINE_WARMUP} needed)`}`],
    ["Typical rows per event", p.warm ? formatCount(p.baselineRows) : "not yet"],
    [
      "Anomaly above",
      p.warm
        ? `${formatCount(p.thresholdRows)} rows (at least ${ANOMALY_FACTOR}x typical, ${ANOMALY_SIGMAS} sd, and ${ANOMALY_MIN_ROWS} rows)`
        : "not yet",
    ],
    ["Typical score", p.typicalScore === null ? "not yet" : String(p.typicalScore)],
    ["Highest score", String(p.maxScore)],
    ["Rows read in total", formatCount(p.rowsTotal)],
    ["Anomalies", String(p.anomalies)],
    ["First event", p.firstEventAt?.toISOString() ?? "never"],
    ["Last event", formatAge(p.lastEventAt, now)],
  ];
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <Link className="text-sm text-muted-foreground hover:underline" prefetch={false} href={eventsHref({ agent: p.agentId, target: p.targetId })}>
          Access events
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight break-all">
          <PrincipalLabel principal={p.principal} fingerprinted={p.fingerprinted} />
        </h1>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Baseline</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
            {facts.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Incidents</CardTitle>
        </CardHeader>
        <CardContent>
          {incidents.length === 0 ? (
            <p className="text-sm text-muted-foreground">No incident.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Hour</TableHead>
                  <TableHead>Events</TableHead>
                  <TableHead>Score</TableHead>
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
                    <TableCell>{i.eventBucket?.toISOString().slice(0, 13).replace("T", " ")}:00 UTC</TableCell>
                    <TableCell>{i.matchCount}</TableCell>
                    <TableCell>{i.eventScore ?? ""}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Latest events</CardTitle>
        </CardHeader>
        <CardContent>
          <EventsTable events={events} now={now} />
        </CardContent>
      </Card>
    </div>
  );
}
