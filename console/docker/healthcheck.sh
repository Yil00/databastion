#!/bin/sh
# Image HEALTHCHECK. The web process is probed on /api/health (liveness, no database access);
# other commands (worker, one-shot migrate) report healthy while PID 1 runs.
set -eu
if tr '\0' ' ' < /proc/1/cmdline | grep -q 'server.js'; then
  exec node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health', { signal: AbortSignal.timeout(4000) }).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"
fi
exit 0
