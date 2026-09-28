import Link from "next/link";
import { notFound } from "next/navigation";

import { incidentsHref } from "@/lib/incidents-filter";
import { conditionLines, ExceptionsTable, policyFormValues } from "@/components/console/policies-table";
import { ExceptionForm, PolicyRowActions } from "@/components/console/policy-actions";
import { PolicyForm } from "@/components/console/policy-form";
import { SeverityBadge } from "@/components/console/incidents-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import { channelStates, listChannels } from "@/server/channels";
import { getPolicy, listExceptions } from "@/server/policies";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** One policy: its conditions, exceptions and (admin) the edit form. */
export default async function PolicyPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requirePageSession();
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const db = getDb();
  const [policy, exceptions] = await Promise.all([getPolicy(db, id), listExceptions(db, id)]);
  if (!policy) notFound();
  const isAdmin = session.user.role === "admin";
  const [states, channelRows] = await Promise.all([channelStates(db, policy.notifyChannels), isAdmin ? listChannels(db) : []]);
  const channels = channelRows.map((c) => ({ slug: c.slug, enabled: c.enabled }));
  const broken = policy.notifyChannels.filter((c) => states[c] !== "ok");
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex flex-col gap-1">
          <Link className="text-sm text-muted-foreground hover:underline" href="/policies" prefetch={false}>
            Policies
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight break-words">{policy.name}</h1>
          {policy.description && <p className="text-sm text-muted-foreground">{policy.description}</p>}
        </div>
        {isAdmin && (
          <div className="ml-auto">
            <PolicyRowActions policyId={policy.id} policyName={policy.name} enabled={policy.enabled} csrfToken={session.csrfToken} />
          </div>
        )}
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Rule</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 text-sm">
          <p>
            {policy.enabled ? "Enabled" : "Disabled"}, revision {policy.revision}
            {policy.enabled && !policy.evaluated ? " (being applied to the existing findings)" : ""}.
          </p>
          <p>When a finding matches:</p>
          <ul className="list-disc pl-6">
            {conditionLines(policy.conditions).map((line, i) => (
              <li key={i} className="break-all">
                {line}
              </li>
            ))}
          </ul>
          <p className="flex items-center gap-2">
            open an incident of severity <SeverityBadge severity={policy.severity} />
            {policy.notifyChannels.length > 0 ? ` and notify ${policy.notifyChannels.join(", ")}` : ""}.
          </p>
          {broken.length > 0 && (
            <p role="alert" className="text-sm text-destructive">
              {broken.map((c) => `${c}: ${states[c] === "disabled" ? "channel disabled" : "no such channel"}`).join("; ")}. Incidents
              are still opened; these notifications are recorded as skipped.
            </p>
          )}
          <Link className="hover:underline" prefetch={false} href={incidentsHref({ status: "all" })}>
            See the incidents
          </Link>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Exceptions</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <ExceptionsTable exceptions={exceptions} isAdmin={isAdmin} csrfToken={session.csrfToken} now={requestTime()} />
          {isAdmin && <ExceptionForm csrfToken={session.csrfToken} policyId={policy.id} />}
        </CardContent>
      </Card>
      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>Edit</CardTitle>
          </CardHeader>
          <CardContent>
            <PolicyForm csrfToken={session.csrfToken} policyId={policy.id} initial={policyFormValues(policy)} channels={channels} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
