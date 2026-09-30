// Image HEALTHCHECK (distroless: run by the image's Node.js, no shell). The web process is probed
// on /api/health (liveness, no database access); other commands (worker, one-shot migrate) report
// healthy while PID 1 runs.

import { readFileSync } from "node:fs";

let argv;
try {
  argv = readFileSync("/proc/1/cmdline", "utf8").split("\0");
} catch {
  process.exit(1);
}
if (!argv.some((arg) => arg === "server.js" || arg.endsWith("/server.js"))) {
  process.exit(0);
}
const port = process.env.PORT || "3000";
fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(4000) }).then(
  (res) => process.exit(res.ok ? 0 : 1),
  () => process.exit(1),
);
