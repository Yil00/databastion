import { notFound } from "next/navigation";

import { DeliveriesTable } from "@/components/console/deliveries-table";
import { ChannelForm, ChannelsTable } from "@/components/console/notification-channels";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDb } from "@/db/client";
import { listChannels } from "@/server/channels";
import { listDeliveries } from "@/server/notifications";
import { requestTime, requirePageSession } from "@/server/ui-session";

export const dynamic = "force-dynamic";

/**
 * Notification channels (P3-C, admin only): e-mail (SMTP) and HMAC-signed webhooks, referenced by
 * name from the policies' notify actions; channels flagged for console alerts also receive the
 * silent-agent, agent-integrity and dropped-batches alerts. No secret is ever rendered here.
 */
export default async function NotificationsPage() {
  const session = await requirePageSession();
  if (session.user.role !== "admin") notFound();
  const db = getDb();
  const [channels, deliveries] = await Promise.all([listChannels(db), listDeliveries(db, {}, 100)]);
  const now = requestTime();
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-semibold tracking-tight">Notifications</h1>
      <Card>
        <CardHeader>
          <CardTitle>Channels</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">
            A policy notifies the channels it names when it opens an incident. Notifications carry identifiers, counts,
            names and a link to the console, never a data value (masked or not). A name with no channel, or a disabled
            channel, is recorded as skipped on the incident. The names they carry, the database account (principal) above
            all, can be chosen by database clients: webhook receivers and e-mail consumers must escape them wherever they
            render them (see the console README, &quot;Alerting&quot;).
          </p>
          <ChannelsTable
            csrfToken={session.csrfToken}
            channels={channels.map((c) => ({
              id: c.id,
              slug: c.slug,
              type: c.type,
              enabled: c.enabled,
              systemAlerts: c.systemAlerts,
              config: c.config,
              secretSet: c.secretSet,
            }))}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>New channel</CardTitle>
        </CardHeader>
        <CardContent>
          <ChannelForm csrfToken={session.csrfToken} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Recent deliveries</CardTitle>
        </CardHeader>
        <CardContent>
          <DeliveriesTable deliveries={deliveries} now={now} showEvent />
        </CardContent>
      </Card>
    </div>
  );
}
