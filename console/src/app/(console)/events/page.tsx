import Link from "next/link";

import { EventsTable, PrincipalsTable } from "@/components/console/events-table";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { getDb } from "@/db/client";
import { eventsHref, parseEventFilter } from "@/lib/events-filter";
import type { SearchParams } from "@/lib/findings-filter";
import { eventsRetentionDays, listEvents, listPrincipals, MAX_LISTED_EVENTS } from "@/server/events";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/**
 * Audit access events (P4-C), newest first, with filters on target, principal, signal, time and
 * the baseline anomaly flag; and the principals with a baseline. Events hold no value (ADR-0007):
 * who, which objects, how many rows, signals and the console's score.
 */
export default async function EventsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  await requirePageSession();
  const filter = parseEventFilter(await searchParams);
  const db = getDb();
  const [events, principals] = await Promise.all([
    listEvents(db, filter),
    listPrincipals(db, { agentId: filter.agentId, targetId: filter.targetId }),
  ]);
  const now = requestTime();
  const filtered = Object.values(filter).some((v) => v !== undefined && v !== false);
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Access events</h1>
        {filtered && (
          <Link className="ml-auto text-sm hover:underline" prefetch={false} href={eventsHref({})}>
            Clear filters
          </Link>
        )}
      </div>
      <form method="get" action="/events" className="flex flex-wrap items-end gap-3 text-sm">
        {filter.agentId && <input type="hidden" name="agent" value={filter.agentId} />}
        {filter.targetId && <input type="hidden" name="target" value={filter.targetId} />}
        {filter.principalKey && <input type="hidden" name="principal" value={filter.principalKey} />}
        <div className="flex flex-col gap-1">
          <Label htmlFor="events-signal">Signal (id or family such as signature.*)</Label>
          <Input id="events-signal" name="signal" maxLength={64} defaultValue={filter.signal ?? ""} autoComplete="off" />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor="events-from">From (UTC, e.g. 2026-09-28T14:00Z)</Label>
          <Input id="events-from" name="from" maxLength={40} defaultValue={filter.from?.toISOString() ?? ""} autoComplete="off" />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor="events-to">To (UTC)</Label>
          <Input id="events-to" name="to" maxLength={40} defaultValue={filter.to?.toISOString() ?? ""} autoComplete="off" />
        </div>
        <div className="flex items-center gap-2 pb-2">
          <input id="events-anomaly" name="anomaly" value="1" type="checkbox" defaultChecked={filter.anomalyOnly} className="size-4" />
          <Label htmlFor="events-anomaly">Above baseline only</Label>
        </div>
        <Button type="submit" size="sm">
          Filter
        </Button>
      </form>
      {filtered && (
        <p className="text-sm text-muted-foreground">
          Filtered{filter.targetId ? ` on target ${filter.targetId}` : ""}
          {filter.principalKey ? " on one principal" : ""}
          {filter.agentId && !filter.targetId ? " on one agent" : ""}.
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {events.length >= MAX_LISTED_EVENTS && (
            <p className="text-sm text-muted-foreground">Showing the latest {MAX_LISTED_EVENTS} events: narrow the filters to see older ones.</p>
          )}
          <p className="text-xs text-muted-foreground">
            Events are kept {eventsRetentionDays()} days. The score is the sensitivity of the most sensitive object reached
            (from Discovery findings) times log10(1 + rows).
          </p>
          <EventsTable events={events} now={now} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Principals</CardTitle>
        </CardHeader>
        <CardContent>
          <PrincipalsTable principals={principals} now={now} />
        </CardContent>
      </Card>
    </div>
  );
}
