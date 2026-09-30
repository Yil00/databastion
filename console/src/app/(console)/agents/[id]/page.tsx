import Link from "next/link";
import { notFound } from "next/navigation";

import { AgentActions } from "@/components/console/agent-actions";
import { findingsHref } from "@/components/console/findings-table";
import { ScanCoverageView } from "@/components/console/scan-coverage";
import { ScanDialog } from "@/components/console/scan-dialog";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { TargetNotes } from "@/components/console/target-notes";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDb } from "@/db/client";
import { displayStatus, formatAge } from "@/lib/agent-status";
import { auditWarningText } from "@/lib/audit-warning";
import { eventsHref } from "@/lib/events-filter";
import { getAgentDetail } from "@/server/agents";
import { auditSummaries } from "@/server/audit-config";
import { AUDIT_STREAM_ALERT_INTERVAL_S, streamStopped } from "@/server/audit-stream-alerts";
import { DROPPED_BATCHES_ALERT_INTERVAL_S } from "@/server/dropped-batches";
import { rotationBlocked } from "@/server/rotation";
import { latestScans, scanStatusLabel } from "@/server/scans";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Spool state of the latest heartbeat (agent-reported counts; `dropped_*` count since agent start). */
function spoolText(spool: Record<string, number> | null): string {
  if (!spool) return "unknown";
  const n = (k: string) => (typeof spool[k] === "number" ? spool[k] : null);
  const parts = [`${n("batches") ?? "?"} batches, ${n("bytes") ?? "?"} of ${n("max_bytes") ?? "?"} bytes`];
  if (n("dropped_batches") !== null) parts.push(`${n("dropped_batches")} batches dropped since agent start`);
  if (n("dropped_items") !== null) parts.push(`${n("dropped_items")} items dropped`);
  return parts.join(", ");
}

/** Agent-reported strings are rendered as text nodes only (never as HTML). */
export default async function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requirePageSession();
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const agent = await getAgentDetail(getDb(), id);
  if (!agent) notFound();
  const [scans, audits] = await Promise.all([latestScans(getDb(), id), auditSummaries(getDb(), id)]);
  const now = requestTime();
  const isAdmin = session.user.role === "admin";
  const status = displayStatus(agent, now);
  const active = status !== "revoked" && status !== "locked";
  const rotating = rotationBlocked(
    { pendingSecretHash: agent.rotationPending ? "pending" : null, graceExpiresAt: agent.graceExpiresAt, promotedAt: agent.promotedAt },
    now,
  );
  const facts: [string, string][] = [
    ["Hostname", agent.hostname],
    ["Version", agent.version],
    ["Platform", [agent.os, agent.arch].filter(Boolean).join(" / ") || "unknown"],
    ["Connectors", agent.connectors.join(", ") || "none"],
    ["Classifiers", agent.classifiersVersion ?? "unknown"],
    ["Enrolled", agent.enrolledAt.toISOString()],
    ["Last seen", formatAge(agent.lastSeenAt, now)],
    ["Clock skew", agent.clockSkewMs === null ? "unknown" : `${(agent.clockSkewMs / 1000).toFixed(1)} s`],
    ["Secret rotation", agent.rotationPending ? "pending" : agent.promotedAt ? `last ${agent.promotedAt.toISOString()}` : "never"],
    ["Spool", spoolText(agent.spool)],
  ];
  const dropped = agent.droppedAlerts;
  const heldBack = agent.droppedBatchesUnalerted;
  const stoppedTargets = agent.targets.filter((t) => t.present && streamStopped(t.notes));
  const stopAlerts = agent.streamStopAlerts;
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{agent.name}</h1>
        <StatusBadge status={status} />
        {isAdmin && active && (
          <div className="ml-auto">
            <AgentActions agentId={agent.id} agentName={agent.name} csrfToken={session.csrfToken} rotationBlocked={rotating} />
          </div>
        )}
      </div>
      {status === "locked" && (
        <p role="alert" className="rounded-md border border-destructive p-3 text-sm text-destructive">
          This agent was locked after a secret rotation conflict: another party may hold its secret. Revoke it and
          re-enroll the host with a new enrollment token.
        </p>
      )}
      <Card>
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
      {(dropped.length > 0 || heldBack > 0) && (
        <Card>
          <CardHeader>
            <CardTitle>Dropped batches</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <p>
              The agent reported spool batches it dropped (spool full, or rejected by the console): findings or access
              events that never reached the console. At most one alert per agent and hour is sent to the system-alert
              channels; later drops are counted in the next one. The Audit or Discovery results of that time may be
              incomplete.
            </p>
            {heldBack > 0 && (
              <p role="alert" className="text-destructive">
                {heldBack} more batch{heldBack === 1 ? "" : "es"} dropped
                {agent.droppedBatchesSince ? ` since ${agent.droppedBatchesSince.toISOString()}` : ""}, to be alerted
                {agent.droppedBatchesAlertedAt
                  ? ` after ${new Date(agent.droppedBatchesAlertedAt.getTime() + DROPPED_BATCHES_ALERT_INTERVAL_S * 1000).toISOString()}`
                  : " shortly"}
                .
              </p>
            )}
            {dropped.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Alerted</TableHead>
                    <TableHead>Batches dropped</TableHead>
                    <TableHead>Since</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {dropped.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell>{e.at.toISOString()}</TableCell>
                      <TableCell>{e.droppedBatches ?? "unknown"}</TableCell>
                      <TableCell>{e.since ?? ""}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
      {(stoppedTargets.length > 0 || stopAlerts.length > 0) && (
        <Card>
          <CardHeader>
            <CardTitle>Audit streams stopped</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            {stoppedTargets.length > 0 && (
              <p role="alert" className="text-destructive">
                The agent stopped the Audit stream of {stoppedTargets.map((t) => t.targetId).join(", ")} after repeated
                internal errors: Audit of {stoppedTargets.length === 1 ? "this target" : "these targets"} is off until Audit is
                reconfigured on the target or the agent restarts (the agent log names the code location).
              </p>
            )}
            <p>
              An alert goes to the system-alert channels at most once per agent every{" "}
              {Math.round(AUDIT_STREAM_ALERT_INTERVAL_S / 60)} minutes, and is repeated while a stream stays stopped
              {agent.auditStreamStopsUnalerted > 0 && agent.auditStreamStopsAlertedAt
                ? `; the next one is due after ${new Date(agent.auditStreamStopsAlertedAt.getTime() + AUDIT_STREAM_ALERT_INTERVAL_S * 1000).toISOString()}`
                : ""}
              .
            </p>
            {stopAlerts.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Alerted</TableHead>
                    <TableHead>Targets stopped</TableHead>
                    <TableHead>Since</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {stopAlerts.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell>{e.at.toISOString()}</TableCell>
                      <TableCell>{e.stoppedStreams ?? "unknown"}</TableCell>
                      <TableCell>{e.since ?? ""}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Targets</CardTitle>
        </CardHeader>
        <CardContent>
          {agent.targets.length === 0 ? (
            <p className="text-sm text-muted-foreground">No target reported yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Engine</TableHead>
                  <TableHead>Server version</TableHead>
                  <TableHead>Reachable</TableHead>
                  <TableHead>Audit level</TableHead>
                  <TableHead>Audit source</TableHead>
                  <TableHead>Last error</TableHead>
                  <TableHead>Notes</TableHead>
                  <TableHead>Reported</TableHead>
                  <TableHead>Last scan</TableHead>
                  <TableHead>Audit settings</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {agent.targets.map((t) => (
                  <TableRow key={t.targetId} className={t.present ? undefined : "text-muted-foreground"}>
                    <TableCell>
                      {t.targetId}
                      {!t.present && " (removed)"}
                    </TableCell>
                    <TableCell>{[t.engine, t.edition].filter(Boolean).join(" ")}</TableCell>
                    <TableCell>{t.serverVersion ?? ""}</TableCell>
                    <TableCell>{t.reachable ? "yes" : "no"}</TableCell>
                    <TableCell>
                      {t.auditLevel}
                      {streamStopped(t.notes) && (
                        <Badge variant="destructive" className="ml-2">
                          stream stopped
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{t.auditSource ?? ""}</TableCell>
                    <TableCell>{t.lastError ?? ""}</TableCell>
                    <TableCell className="max-w-80 whitespace-normal">
                      <TargetNotes notes={t.notes} />
                    </TableCell>
                    <TableCell>{formatAge(t.lastReportedAt, now)}</TableCell>
                    <TableCell className="max-w-72 whitespace-normal">
                      {(() => {
                        const scan = scans.get(t.targetId);
                        if (!scan) return "never";
                        return (
                          <>
                            {`${scanStatusLabel(scan, agent.classifiersVersion)}, ${formatAge(scan.createdAt, now)}`}
                            <ScanCoverageView status={scan.status} coverage={scan.coverage} />
                          </>
                        );
                      })()}
                    </TableCell>
                    <TableCell className="max-w-56 whitespace-normal">
                      {(() => {
                        const a = audits.get(t.targetId);
                        const label = !a ? "not configured" : a.enabled ? `enabled, ${a.objects} sensitive objects` : "disabled";
                        return (
                          <>
                            <Link className="hover:underline" prefetch={false} href={`/agents/${agent.id}/targets/${t.targetId}/audit`}>
                              {label}
                            </Link>
                            {a?.warning && (
                              <p role="alert" className="text-xs text-destructive">
                                {auditWarningText(a.warning, a.warningRemoved)}
                              </p>
                            )}
                          </>
                        );
                      })()}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-start gap-2">
                        <Link className="text-sm hover:underline" prefetch={false} href={findingsHref({ agent: agent.id, target: t.targetId })}>
                          Findings
                        </Link>
                        <Link className="text-sm hover:underline" prefetch={false} href={eventsHref({ agent: agent.id, target: t.targetId })}>
                          Events
                        </Link>
                        {isAdmin && active && t.present && (
                          <ScanDialog
                            agentId={agent.id}
                            targetId={t.targetId}
                            csrfToken={session.csrfToken}
                            disabled={["pending", "delivered", "running"].includes(scans.get(t.targetId)?.status ?? "")}
                          />
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
