#!/bin/bash
# Side accounts of the PostgreSQL Audit run (ADR-0048, ADR-0050), run by run.sh next to pgbench in
# the `pg-side` service (the target's image, for its `psql` client):
#   - load_pgmon, a monitoring-like account (member of pg_monitor) running a table bloat estimate on
#     `pg_stats` every 10 seconds, as check_postgres, pgwatch or the widely copied ioguix queries do:
#     `avg_width` and `null_frac` only, no value column, but the relation is `pg_stats`, a statistics
#     view that holds column values (ADR-0048: every read of it is reported);
#   - load_pgexp, an exporter-like account (no grant) reading `pg_roles`, `pg_proc` and
#     `pg_subscription` without their secret columns every 5 seconds (ADR-0050: the no-secret
#     shape, no event);
#   - load_pgbouncer, a PgBouncer-like account (member of pg_read_all_data) running PgBouncer's
#     default `auth_query` on `pg_shadow` every second (ADR-0050: a secret read, at most one event
#     per principal, object set and aggregation window).
# One session per account, kept for the whole run, as those tools do. The statements are written to
# the client one period at a time, so it runs them as they come. Prints one line per account:
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

# An exporter's role, function and subscription metrics (postgres_exporter-style queries): names
# and attributes, never rolconfig, proconfig or subconninfo.
EXPORTER=(
  "SELECT r.rolname, r.rolsuper, r.rolcanlogin, r.rolconnlimit FROM pg_catalog.pg_roles r;"
  "SELECT n.nspname, p.proname, p.prokind FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema');"
  "SELECT subname, subenabled FROM pg_subscription;"
)
# PgBouncer's default auth_query (its documentation), for the workload's account.
AUTH_QUERY=("SELECT usename, passwd FROM pg_shadow WHERE usename='load_app';")

run load_pgmon 10 "${BLOAT[@]}" &
mon=$!
run load_pgexp 5 "${EXPORTER[@]}" &
exp=$!
run load_pgbouncer 1 "${AUTH_QUERY[@]}" &
bouncer=$!
wait "$mon" "$exp" "$bouncer"
