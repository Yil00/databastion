import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { checkMetricsAuth, collectMetrics } from "@/server/metrics";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store" } as const;

/**
 * GET /metrics (Prometheus text format, ADR-0004). Bearer token from DATABASTION_METRICS_TOKEN(_FILE);
 * `404` when unset. Must only be reachable from the internal network (see console/README.md).
 */
export async function GET(req: Request): Promise<Response> {
  let auth;
  try {
    auth = checkMetricsAuth(req);
  } catch (err) {
    logger.error({ error: errorSummary(err) }, "metrics token configuration error");
    return new Response("not found\n", { status: 404, headers: NO_STORE });
  }
  if (auth === "disabled") return new Response("not found\n", { status: 404, headers: NO_STORE });
  if (auth === "unauthorized") {
    return new Response("unauthorized\n", {
      status: 401,
      headers: { ...NO_STORE, "WWW-Authenticate": 'Bearer realm="databastion-metrics"' },
    });
  }
  try {
    return new Response(await collectMetrics(getDb()), {
      status: 200,
      headers: { ...NO_STORE, "Content-Type": "text/plain; version=0.0.4; charset=utf-8" },
    });
  } catch (err) {
    logger.error({ error: errorSummary(err) }, "metrics collection failed");
    return new Response("unavailable\n", { status: 503, headers: NO_STORE });
  }
}
