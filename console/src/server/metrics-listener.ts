import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { errorSummary, logger } from "@/lib/logger";

import { serveMetrics, type MetricsListenerConfig } from "./metrics";

/**
 * Dedicated `/metrics` listener of the web process (P1-D), started by src/instrumentation.ts when
 * DATABASTION_METRICS_PORT is set. A plain `node:http` server next to the Next.js standalone server:
 * Next.js serves a single port, and a custom server would replace the generated standalone
 * `server.js`. It serves ONLY `GET /metrics` (same bearer token, same answers as the main-port
 * route); anything else is `404` / `405`, request bodies are never read.
 */

const MAX_CONNECTIONS = 16;
const TIMEOUT_MS = 10_000;

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = (req.url ?? "").split("?", 1)[0];
  if (path !== "/metrics") {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }).end("not found\n");
    return;
  }
  if (req.method !== "GET") {
    res
      .writeHead(405, { Allow: "GET", "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" })
      .end("method not allowed\n");
    return;
  }
  const headers = new Headers();
  const authorization = req.headers.authorization;
  if (authorization !== undefined) headers.set("authorization", authorization);
  const answer = await serveMetrics(new Request("http://metrics.internal/metrics", { headers }));
  res.writeHead(answer.status, Object.fromEntries(answer.headers.entries()));
  res.end(await answer.text());
}

export function createMetricsServer(): Server {
  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      logger.error({ error: errorSummary(err) }, "metrics listener request failed");
      if (!res.headersSent) res.writeHead(503, { "Cache-Control": "no-store" });
      res.end();
    });
  });
  server.maxConnections = MAX_CONNECTIONS;
  server.headersTimeout = TIMEOUT_MS;
  server.requestTimeout = TIMEOUT_MS;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  return server;
}

/** Starts the listener; resolves once bound (rejects on bind errors such as EADDRINUSE). */
export function startMetricsListener(config: MetricsListenerConfig): Promise<Server> {
  const server = createMetricsServer();
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, () => {
      server.off("error", reject);
      // Never keeps the process alive on its own (Next.js owns the shutdown).
      server.unref();
      server.on("error", (err) => logger.error({ error: errorSummary(err) }, "metrics listener error"));
      resolve(server);
    });
  });
}
