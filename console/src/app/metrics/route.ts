import { metricsOnMainPort, serveMetrics } from "@/server/metrics";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * GET /metrics on the main port (Prometheus text format, ADR-0004). Bearer token from
 * DATABASTION_METRICS_TOKEN(_FILE); `404` when unset, and `404` when DATABASTION_METRICS_PORT moves
 * /metrics to its dedicated listener (src/server/metrics-listener.ts). See console/README.md.
 */
export async function GET(req: Request): Promise<Response> {
  if (!metricsOnMainPort()) {
    return new Response("not found\n", { status: 404, headers: { "Cache-Control": "no-store" } });
  }
  return serveMetrics(req);
}
