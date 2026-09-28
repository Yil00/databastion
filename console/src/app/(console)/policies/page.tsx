import { ExceptionsTable, PoliciesTable } from "@/components/console/policies-table";
import { ExceptionForm } from "@/components/console/policy-actions";
import { PolicyForm } from "@/components/console/policy-form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import { listChannels } from "@/server/channels";
import { listExceptions, listPolicies } from "@/server/policies";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/**
 * Policies (P3-A): condition -> action rules applied by the worker to the findings, and their
 * exceptions. Everyone reads them; only administrators create, edit or delete (audited).
 */
export default async function PoliciesPage() {
  const session = await requirePageSession();
  const isAdmin = session.user.role === "admin";
  const db = getDb();
  const [rows, exceptions, channelRows] = await Promise.all([listPolicies(db), listExceptions(db), isAdmin ? listChannels(db) : []]);
  const channels = channelRows.map((c) => ({ slug: c.slug, enabled: c.enabled }));
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-semibold tracking-tight">Policies</h1>
      <Card>
        <CardHeader>
          <CardTitle>Policies</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">
            A finding matching every condition of an enabled policy opens one incident per policy; later scans of the same
            location update it instead of opening another.
          </p>
          <PoliciesTable policies={rows} isAdmin={isAdmin} csrfToken={session.csrfToken} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Exceptions</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            A finding covered by an exception opens no incident. Exceptions of a single policy are managed on its page.
          </p>
          <ExceptionsTable exceptions={exceptions} isAdmin={isAdmin} csrfToken={session.csrfToken} now={requestTime()} />
          {isAdmin && <ExceptionForm csrfToken={session.csrfToken} />}
        </CardContent>
      </Card>
      {isAdmin ? (
        <Card>
          <CardHeader>
            <CardTitle>New policy</CardTitle>
          </CardHeader>
          <CardContent>
            <PolicyForm csrfToken={session.csrfToken} channels={channels} />
          </CardContent>
        </Card>
      ) : (
        <p className="text-sm text-muted-foreground">Only administrators can create or change policies.</p>
      )}
    </div>
  );
}
