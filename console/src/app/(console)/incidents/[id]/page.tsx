import Link from "next/link";
import { notFound } from "next/navigation";

import { DeliveriesTable } from "@/components/console/deliveries-table";
import { EventsTable, PrincipalLabel, SignalBadge } from "@/components/console/events-table";
import { FindingsTable } from "@/components/console/findings-table";
import { IncidentActions } from "@/components/console/incident-actions";
import { IncidentStatusBadge, SeverityBadge } from "@/components/console/incidents-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import { formatAge } from "@/lib/agent-status";
import { isFingerprint, locationPartLabels } from "@/lib/location-labels";
import { incidentEventCount, incidentEventViews } from "@/server/events";
import { getFindingView } from "@/server/findings";
import { getIncident } from "@/server/incidents";
import { listDeliveries } from "@/server/notifications";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Incident detail: lifecycle, policy, and the linked finding or access events (P4-C). The finding's masked samples are
 * decrypted server side through the findings view path and rendered into this per-request page
 * only (`Cache-Control: no-store`); the incident itself stores no sampled value.
 */
export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requirePageSession();
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const db = getDb();
  const incident = await getIncident(db, id);
  if (!incident) notFound();
  const [finding, deliveries, events, eventCount] = await Promise.all([
    incident.findingId ? getFindingView(db, incident.findingId) : null,
    listDeliveries(db, { incidentId: incident.id }),
    incident.access ? incidentEventViews(db, incident.id) : [],
    incident.access ? incidentEventCount(db, incident.id) : 0,
  ]);
  const access = incident.access;
  const now = requestTime();
  const isAdmin = session.user.role === "admin";
  const trail: [string, Date | null, string | null][] = [
    ["Opened", incident.createdAt, "policy engine"],
    ["Acknowledged", incident.acknowledgedAt, incident.acknowledgedBy],
    ["Resolved", incident.resolvedAt, incident.resolvedBy],
    ["False positive", incident.falsePositiveAt, incident.falsePositiveBy],
  ];
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex flex-col gap-1">
          <Link className="text-sm text-muted-foreground hover:underline" href="/incidents" prefetch={false}>
            Incidents
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight break-words">{incident.policyName}</h1>
          <div className="flex gap-2">
            <SeverityBadge severity={incident.severity} />
            <IncidentStatusBadge status={incident.status} />
          </div>
        </div>
        <div className="ml-auto">
          <IncidentActions incidentId={incident.id} status={incident.status} isAdmin={isAdmin} csrfToken={session.csrfToken} />
        </div>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Policy</dt>
            <dd>
              {incident.policyId ? (
                <Link className="hover:underline" prefetch={false} href={`/policies/${incident.policyId}`}>
                  {incident.policyName}
                </Link>
              ) : (
                <>{incident.policyName} (deleted)</>
              )}{" "}
              <span className="text-muted-foreground">rev. {incident.policyRevision}</span>
            </dd>
            <dt className="text-muted-foreground">Target</dt>
            <dd>
              {incident.agentName ?? "?"} / {incident.targetId ?? "?"}
            </dd>
            {access ? (
              <>
                <dt className="text-muted-foreground">Principal</dt>
                <dd className="break-all">
                  {access.overflow ? (
                    "several: the policy reached its hourly limit of new incidents, the further matches of the hour are counted here"
                  ) : (
                    <PrincipalLabel principal={access.principal} fingerprinted={isFingerprint(access.principal)} engine={incident.engine} />
                  )}
                </dd>
                <dt className="text-muted-foreground first-letter:uppercase">{locationPartLabels(incident.engine).database}</dt>
                <dd>
                  {access.database ?? "none"}{" "}
                  <span className="text-muted-foreground">
                    hour starting {access.bucket?.toISOString().slice(0, 13).replace("T", " ")}:00 UTC
                  </span>
                </dd>
                <dt className="text-muted-foreground">Matches</dt>
                <dd>
                  {incident.matchCount} event{incident.matchCount > 1 ? "s" : ""}, {Math.round(access.rows ?? 0)} rows, highest score{" "}
                  {access.score ?? 0}
                </dd>
                <dt className="text-muted-foreground">Signals</dt>
                <dd className="flex flex-wrap items-center gap-1">
                  {access.signals.length > 0 ? access.signals.map((s) => <SignalBadge key={s} signal={s} />) : "none"}
                  {access.anomaly ? " (and a volume above the principal's baseline)" : ""}
                </dd>
              </>
            ) : (
              <>
                <dt className="text-muted-foreground">Classifier</dt>
                <dd>{incident.classifier ?? ""}</dd>
                <dt className="text-muted-foreground">Matches</dt>
                <dd>
                  {incident.matchCount} scan{incident.matchCount > 1 ? "s" : ""}
                  {incident.findingMatched !== null ? `, ${incident.findingMatched} values matched at the last one` : ""}
                </dd>
              </>
            )}
            <dt className="text-muted-foreground">Notify</dt>
            <dd>{incident.notifyChannels.length > 0 ? incident.notifyChannels.join(", ") : "none"}</dd>
            {trail
              .filter(([, at]) => at !== null)
              .map(([label, at, by]) => (
                <div key={label} className="contents">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd>
                    {formatAge(at, now)}
                    {by ? ` by ${by}` : ""}
                    <span className="ml-2 text-xs text-muted-foreground">{at?.toISOString()}</span>
                  </dd>
                </div>
              ))}
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Notifications</CardTitle>
        </CardHeader>
        <CardContent>
          <DeliveriesTable deliveries={deliveries} now={now} />
        </CardContent>
      </Card>
      {access ? (
        <Card>
          <CardHeader>
            <CardTitle>Access events</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {eventCount > events.length && (
              <p className="text-sm text-muted-foreground">
                Showing the latest {events.length} of {eventCount} events (older ones may have been purged by the retention).
              </p>
            )}
            {eventCount === 0 && (
              <p className="text-sm text-muted-foreground">The events of this incident are past the retention and were purged.</p>
            )}
            <EventsTable events={events} now={now} />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Linked finding</CardTitle>
          </CardHeader>
          <CardContent>
            {finding ? (
              <FindingsTable findings={[finding]} csrfToken={session.csrfToken} now={now} canMark={false} />
            ) : (
              <p className="text-sm text-muted-foreground">The finding is no longer available (agent or target removed).</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
