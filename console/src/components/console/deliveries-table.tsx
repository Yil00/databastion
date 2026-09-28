import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatAge } from "@/lib/agent-status";
import { deliveryErrorText, type DeliveryStatus } from "@/lib/notification-model";

/**
 * Notification deliveries (server component): per channel and event, the status, attempts and
 * the last error as a closed code with its explanation (never a server response).
 */

export interface DeliveryRow {
  id: string;
  event: string;
  channelSlug: string;
  status: DeliveryStatus;
  attempts: number;
  lastAttemptAt: Date | null;
  nextAttemptAt: Date;
  deliveredAt: Date | null;
  lastError: string | null;
  createdAt: Date;
}

const STATUS_VARIANT = {
  delivered: "secondary",
  pending: "outline",
  sending: "outline",
  failed: "destructive",
  skipped: "destructive",
} as const;

export function deliveryState(d: DeliveryRow, now: number): string {
  if (d.status === "delivered") return `delivered ${formatAge(d.deliveredAt, now)}`;
  if (d.status === "pending" && d.attempts > 0) {
    const s = Math.max(0, Math.round((d.nextAttemptAt.getTime() - now) / 1000));
    return `retry in ${s < 60 ? `${s} s` : `${Math.ceil(s / 60)} min`}`;
  }
  if (d.status === "pending") return "queued";
  if (d.status === "sending") return "sending";
  return d.status;
}

export function DeliveriesTable({ deliveries, now, showEvent = false }: { deliveries: DeliveryRow[]; now: number; showEvent?: boolean }) {
  if (deliveries.length === 0) return <p className="text-sm text-muted-foreground">No notification.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Channel</TableHead>
          {showEvent && <TableHead>Event</TableHead>}
          <TableHead>Status</TableHead>
          <TableHead>Attempts</TableHead>
          <TableHead>Last attempt</TableHead>
          <TableHead>Error</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {deliveries.map((d) => (
          <TableRow key={d.id}>
            <TableCell className="break-all">{d.channelSlug}</TableCell>
            {showEvent && <TableCell>{d.event}</TableCell>}
            <TableCell>
              <Badge variant={STATUS_VARIANT[d.status]}>{d.status}</Badge>{" "}
              <span className="text-xs text-muted-foreground">{deliveryState(d, now)}</span>
            </TableCell>
            <TableCell>{d.attempts}</TableCell>
            <TableCell>{formatAge(d.lastAttemptAt, now)}</TableCell>
            <TableCell className="text-sm">{d.lastError ? `${d.lastError}: ${deliveryErrorText(d.lastError)}` : ""}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
