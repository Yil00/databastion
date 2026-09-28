import Link from "next/link";

import { IncidentsTable, STATUS_LABEL } from "@/components/console/incidents-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import type { SearchParams } from "@/lib/findings-filter";
import { INCIDENT_STATUSES, SEVERITIES } from "@/lib/incident-lifecycle";
import { incidentsHref, parseIncidentsQuery, queryStatuses, type IncidentsQuery } from "@/lib/incidents-filter";
import { activeIncidentCounts, listIncidents, MAX_LISTED_INCIDENTS } from "@/server/incidents";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

function FilterLinks({
  label,
  current,
  options,
  href,
}: {
  label: string;
  current: string | undefined;
  options: { value: string | undefined; label: string }[];
  href: (value: string | undefined) => string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <span className="text-muted-foreground">{label}:</span>
      {options.map((o) => (
        <Link
          key={o.label}
          prefetch={false}
          href={href(o.value)}
          aria-current={o.value === current ? "true" : undefined}
          className={o.value === current ? "font-semibold underline" : "hover:underline"}
        >
          {o.label}
        </Link>
      ))}
    </div>
  );
}

/** Incidents raised by policies (P3-B), active ones first; filters on status, severity and target. */
export default async function IncidentsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  await requirePageSession();
  const q = parseIncidentsQuery(await searchParams);
  const db = getDb();
  const [rows, counts] = await Promise.all([
    listIncidents(db, { statuses: queryStatuses(q), severity: q.severity, agentId: q.agentId, targetId: q.targetId }),
    activeIncidentCounts(db),
  ]);
  const with_ = (over: Partial<IncidentsQuery>) => incidentsHref({ ...q, ...over });
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Incidents</h1>
        <p className="ml-auto text-sm text-muted-foreground">
          Active: {counts.critical} critical, {counts.high} high, {counts.medium} medium, {counts.low} low
        </p>
      </div>
      <div className="flex flex-col gap-2">
        <FilterLinks
          label="Status"
          current={q.status}
          options={[
            { value: "active", label: "active" },
            ...INCIDENT_STATUSES.map((s) => ({ value: s, label: STATUS_LABEL[s] })),
            { value: "all", label: "all" },
          ]}
          href={(v) => with_({ status: v as IncidentsQuery["status"] })}
        />
        <FilterLinks
          label="Severity"
          current={q.severity}
          options={[{ value: undefined, label: "any" }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]}
          href={(v) => with_({ severity: v as IncidentsQuery["severity"] })}
        />
        {q.targetId && (
          <p className="text-sm text-muted-foreground">
            Target {q.targetId}.{" "}
            <Link className="hover:underline" prefetch={false} href={with_({ agentId: undefined, targetId: undefined })}>
              All targets
            </Link>
          </p>
        )}
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{q.status === "active" ? "Active incidents" : "Incidents"}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {rows.length >= MAX_LISTED_INCIDENTS && (
            <p className="text-sm text-muted-foreground">
              Showing the first {MAX_LISTED_INCIDENTS} incidents: filter by status, severity or target to see the others.
            </p>
          )}
          <IncidentsTable incidents={rows} now={requestTime()} />
        </CardContent>
      </Card>
    </div>
  );
}
