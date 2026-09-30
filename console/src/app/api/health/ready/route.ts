import { sql } from "drizzle-orm";
import { NextResponse } from "next/server";

import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store" };

/**
 * Readiness probe: checks that the internal database answers. The response
 * is deliberately generic; the cause is only logged server-side.
 */
export async function GET(): Promise<NextResponse> {
  try {
    await getDb().execute(sql`select 1`);
    return NextResponse.json({ status: "ok" }, { headers: NO_STORE });
  } catch (err) {
    logger.warn({ error: errorSummary(err) }, "readiness check failed");
    return NextResponse.json({ status: "unavailable" }, { status: 503, headers: NO_STORE });
  }
}
