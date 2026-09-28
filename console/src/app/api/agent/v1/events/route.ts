import { handleEventsNotImplemented } from "@/server/agent-api/handlers";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** POST /api/agent/v1/events: Audit (phase 4). `501` with a contract `Error` body; body never read. */
export function POST(): Response {
  return handleEventsNotImplemented();
}
