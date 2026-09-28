import Link from "next/link";
import { notFound } from "next/navigation";

import { AgentActions } from "@/components/console/agent-actions";
import { findingsHref } from "@/components/console/findings-table";
import { ScanDialog } from "@/components/console/scan-dialog";
import { StatusBadge } from "@/components/console/status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDb } from "@/db/client";
import { displayStatus, formatAge } from "@/lib/agent-status";
import { auditWarningText } from "@/lib/audit-warning";
import { eventsHref } from "@/lib/events-filter";
import { getAgentDetail } from "@/server/agents";
import { auditSummaries } from "@/server/audit-config";
import { rotationBlocked } from "@/server/rotation";
import { latestScans, scanStatusLabel } from "@/server/scans";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

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
  ];
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
                    <TableCell>{t.auditLevel}</TableCell>
                    <TableCell>{t.auditSource ?? ""}</TableCell>
                    <TableCell>{t.lastError ?? ""}</TableCell>
                    <TableCell>{formatAge(t.lastReportedAt, now)}</TableCell>
                    <TableCell>
                      {(() => {
                        const scan = scans.get(t.targetId);
                        if (!scan) return "never";
                        return `${scanStatusLabel(scan, agent.classifiersVersion)}, ${formatAge(scan.createdAt, now)}`;
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
