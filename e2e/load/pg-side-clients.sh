#!/bin/bash
# Side account of the PostgreSQL Audit run (ADR-0048), run by run.sh next to pgbench in the `pg-side`
# service (the target's image, for its `psql` client):
#   - load_pgmon, a monitoring-like account (member of pg_monitor) running a table bloat estimate on
#     `pg_stats` every 10 seconds, as check_postgres, pgwatch or the widely copied ioguix queries do:
#     `avg_width` and `null_frac` only, no value column, but the relation is `pg_stats`, a statistics
#     view that holds column values (ADR-0048: every read of it is reported).
# One session, kept for the whole run, as those tools do. The statement is written to the client one
# period at a time, so it runs it as it comes. Prints one line:
#   side <account> <statements issued> <0 | 1: the client failed>
#
#   pg-side-clients.sh DURATION_S
set -euo pipefail
dur="$1"
[[ "$dur" =~ ^[0-9]+$ ]] || { echo "pg-side-clients.sh: DURATION_S must be a number" >&2; exit 2; }
# The load accounts' password (a Docker secret), for the client only: never on a command line.
PGPASSWORD="$(cat /run/secrets/load_client_password)"
export PGPASSWORD
end=$(( $(date +%s) + dur ))

# Table bloat estimate (simplified ioguix form): the expected heap pages from the average row width
# and null fraction of each column, against the pages the table holds.
BLOAT=(
  "SELECT s.schemaname, s.tablename, c.relpages, c.reltuples, ceil(c.reltuples * (24 + sum((1 - s.null_frac) * s.avg_width)) / current_setting('block_size')::numeric) AS expected_pages, max(s.null_frac) AS max_null_frac FROM pg_stats s JOIN pg_namespace n ON n.nspname = s.schemaname JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = s.tablename WHERE s.schemaname NOT IN ('pg_catalog', 'information_schema') GROUP BY s.schemaname, s.tablename, c.relpages, c.reltuples ORDER BY c.relpages DESC LIMIT 100;"
)

# feed ACCOUNT PERIOD STATEMENT...: the statements every PERIOD seconds until the end; the count in
# /tmp.
feed() {
  local account="$1" period="$2" n=0
  shift 2
  while [ "$(date +%s)" -lt "$end" ]; do
    printf '%s\n' "$@"
    n=$((n + $#))
    printf '%s\n' "$n" >"/tmp/issued.$account"
    sleep "$period"
  done
}

# run ACCOUNT PERIOD STATEMENT...: one session of ACCOUNT running what feed writes.
run() {
  local account="$1" rc=0
  printf '0\n' >"/tmp/issued.$account"
  # As pgbench's load_app: no TLS on the harness's internal network (dev-only).
  feed "$@" | psql -X -q -A -t -v ON_ERROR_STOP=1 -h target-pg -U "$account" -d shop >/dev/null || rc=$?
  printf 'side %s %s %s\n' "$account" "$(cat "/tmp/issued.$account")" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
}

run load_pgmon 10 "${BLOAT[@]}"
