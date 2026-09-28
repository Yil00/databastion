import Link from "next/link";
import { notFound } from "next/navigation";

import { AuditForm } from "@/components/console/audit-form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDb } from "@/db/client";
import { formatAge } from "@/lib/agent-status";
import { validateSchema } from "@/lib/protocol/validate";
import { getAgentDetail } from "@/server/agents";
import { auditWarningText } from "@/lib/audit-warning";
import { deriveSensitiveObjects, getAuditConfig, SHRINK_MIN_REMOVED, SHRINK_RATIO } from "@/server/audit-config";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHOWN = 50;

/** Audit settings of one target (P4-C): what was sent last, what the findings suggest now, the form (admin). */
export default async function AuditSettingsPage({ params }: { params: Promise<{ id: string; targetId: string }> }) {
  const session = await requirePageSession();
  const { id, targetId } = await params;
  if (!UUID.test(id) || !validateSchema("TargetId", targetId).ok) notFound();
  const db = getDb();
  const [agent, config] = await Promise.all([getAgentDetail(db, id), getAuditConfig(db, id, targetId)]);
  if (!agent || !config) notFound();
  const derived = await deriveSensitiveObjects(db, id, targetId);
  derived.sort((a, b) => b.sensitivity - a.sensitivity);
  const now = requestTime();
  const isAdmin = session.user.role === "admin";
  const active = agent.revokedAt === null && agent.lockedAt === null && config.present;
  const facts: [string, string][] = [
    ["Engine", config.engine],
    ["Audit level reported", config.auditLevel],
    ["Settings", config.configured ? (config.enabled ? "enabled" : "disabled") : "never sent"],
    ["Sensitive objects sent", String(config.sentObjects.length)],
    ["Objects with findings now", String(derived.length)],
    [
      "Last settings job",
      config.lastJob ? `${config.lastJob.status}${config.lastJob.errorCode ? ` (${config.lastJob.errorCode})` : ""}, ${formatAge(config.lastJob.createdAt, now)}` : "none",
    ],
  ];
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <Link className="text-sm text-muted-foreground hover:underline" prefetch={false} href={`/agents/${id}`}>
          {agent.name}
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight">Audit settings of {targetId}</h1>
      </div>
      {config.warning && (
        <p role="alert" className="rounded-md border border-destructive p-3 text-sm text-destructive">
          {auditWarningText(config.warning, config.warningRemoved)}
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
      {isAdmin && active && (
        <Card>
          <CardHeader>
            <CardTitle>Change the settings</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <p className="text-sm text-muted-foreground">
              The settings replace the previous ones as a whole. Turning Audit off, emptying the sensitive objects, or removing at
              least {SHRINK_MIN_REMOVED} of them or {SHRINK_RATIO * 100} % of those sent last time asks for a confirmation and leaves a
              warning on the target. Detection thresholds and scoring stay in the console.
            </p>
            <AuditForm
              agentId={id}
              targetId={targetId}
              csrfToken={session.csrfToken}
              initial={{
                enabled: config.configured ? config.enabled : true,
                aggregationWindowS: config.aggregationWindowS,
                pollIntervalS: config.pollIntervalS,
                minRows: config.minRows,
                deriveFromFindings: config.deriveFromFindings,
                manualObjects: config.manualObjects,
              }}
            />
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Objects with findings (most sensitive first)</CardTitle>
        </CardHeader>
        <CardContent>
          {derived.length === 0 ? (
            <p className="text-sm text-muted-foreground">No finding on this target: run a Discovery scan first, or add objects by hand.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Object</TableHead>
                  <TableHead>Classifiers</TableHead>
                  <TableHead>Sensitivity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {derived.slice(0, SHOWN).map((o) => (
                  <TableRow key={`${o.database}/${o.schema ?? ""}/${o.object}`}>
                    <TableCell className="break-all">{[o.database, o.schema, o.object].filter((x) => x !== undefined).join(" / ")}</TableCell>
                    <TableCell>{o.classifiers.join(", ")}</TableCell>
                    <TableCell>{o.sensitivity}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {derived.length > SHOWN && <p className="mt-2 text-sm text-muted-foreground">And {derived.length - SHOWN} more.</p>}
        </CardContent>
      </Card>
    </div>
  );
}
