import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Placeholder for the agent API (/api/agent/v1/*). No endpoint is implemented
 * yet and the request body is never read. Real endpoints will be added as
 * sibling routes, validated against the schemas generated from
 * shared/protocol/ (unknown fields rejected). See ./README.md.
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
