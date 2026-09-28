#!/bin/sh
# DataBastion console image entrypoint: `web` (default), `worker`, `migrate`, `bootstrap-admin`.
# Secrets come from *_FILE variables (Docker secrets); nothing is written to the filesystem.
set -eu

cmd="${1:-web}"
case "$cmd" in
  web)
    cd /app/web
    exec node server.js
    ;;
  worker)
    cd /app/console
    exec node --import tsx src/worker/index.ts
    ;;
  migrate)
    cd /app/console
    exec node --import tsx src/db/migrate.ts
    ;;
  bootstrap-admin)
    cd /app/console
    exec node --import tsx src/cli/bootstrap-admin.ts
    ;;
  *)
    echo "usage: entrypoint.sh web|worker|migrate|bootstrap-admin" >&2
    exit 64
    ;;
esac
