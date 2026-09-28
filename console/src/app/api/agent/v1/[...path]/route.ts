import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Placeholder for the agent API endpoints not implemented yet (`/findings`, `/events`, `/rotate`,
 * and any unknown path). The request body is never read. Implemented endpoints are sibling routes
 * (`enroll/`, `heartbeat/`, `jobs/`, `jobs/[job_id]/status/`), which take precedence. See ./README.md.
 */
function notImplemented(): NextResponse {
  return NextResponse.json(
    { error: "not_implemented" },
    { status: 501, headers: { "Cache-Control": "no-store" } },
  );
}

export const GET = notImplemented;
export const POST = notImplemented;
export const PUT = notImplemented;
export const PATCH = notImplemented;
export const DELETE = notImplemented;
