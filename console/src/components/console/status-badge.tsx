import { Badge } from "@/components/ui/badge";
import type { DisplayStatus } from "@/lib/agent-status";

const VARIANT = {
  online: "default",
  silent: "secondary",
  revoked: "outline",
  locked: "destructive",
} as const;

export function StatusBadge({ status }: { status: DisplayStatus }) {
  return <Badge variant={VARIANT[status]}>{status}</Badge>;
}
