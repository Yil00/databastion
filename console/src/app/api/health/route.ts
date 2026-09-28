import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * Liveness probe. Does not touch the database and exposes no version,
 * hostname or configuration detail.
 */
export function GET(): NextResponse {
  return NextResponse.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
