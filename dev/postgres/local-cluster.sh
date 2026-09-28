#!/usr/bin/env bash
# Throwaway PostgreSQL cluster for the PostgreSQL connector integration tests, for hosts without
# Docker. The dev environment (`make dev`, PostgreSQL 17 + pgaudit) remains the reference; this
# cluster uses the host's server binaries (no pgaudit unless installed), loads the same seed
# (dev/seed/out/postgres.sql) into `shop` and creates the agent role with the same script as the
# container (postgres/initdb/20-databastion.sh: ADR-0012 minimal variant).
#
#   dev/postgres/local-cluster.sh start   # initdb (first time), start, seed; prints the test env
#   dev/postgres/local-cluster.sh env     # prints the test environment variables
#   dev/postgres/local-cluster.sh stop    # stops the server and deletes the cluster
#
# Listens on 127.0.0.1 only (DATABASTION_PG_LOCAL_PORT, default 55432) and on a Unix socket in the
# data directory (DATABASTION_PG_LOCAL_DIR, default /tmp/databastion-pg-local). Dev-only passwords
# from dev/.env.example. As root, the server runs as the `postgres` OS user.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEV="$(dirname "$HERE")"
DIR="${DATABASTION_PG_LOCAL_DIR:-/tmp/databastion-pg-local}"
PORT="${DATABASTION_PG_LOCAL_PORT:-55432}"
DATA="$DIR/data"
# Dev-only credentials (dev/.env.example).
set -a
# shellcheck disable=SC1091
. "$DEV/.env.example"
set +a

bindir() {
  if [ -n "${PG_BINDIR:-}" ]; then echo "$PG_BINDIR"; return; fi
  local d
  d="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -n 1 || true)"
  if [ -n "$d" ]; then echo "$d"; return; fi
  dirname "$(command -v postgres)"
}
BIN="$(bindir)"

as_owner() {
  if [ "$(id -u)" = 0 ]; then runuser -u postgres -- "$@"; else "$@"; fi
}

env_vars() {
  cat <<EOF
export DATABASTION_TEST_PG_URL='postgresql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${PORT}/shop'
export DATABASTION_TEST_PG_ADMIN_URL='postgresql://postgres:${POSTGRES_ADMIN_PASSWORD}@127.0.0.1:${PORT}/shop'
EOF
}

start() {
  mkdir -p "$DIR"
  if [ "$(id -u)" = 0 ]; then chown postgres: "$DIR"; fi
  chmod 0700 "$DIR"
  local fresh=0
  if [ ! -f "$DATA/PG_VERSION" ]; then
    fresh=1
    local pwfile="$DIR/admin-password"
    (umask 077; printf '%s\n' "$POSTGRES_ADMIN_PASSWORD" >"$pwfile")
    if [ "$(id -u)" = 0 ]; then chown postgres: "$pwfile"; fi
    as_owner "$BIN/initdb" -D "$DATA" -U postgres --pwfile="$pwfile" -A scram-sha-256 \
      --auth-local=trust -E UTF8 --locale=C.UTF-8 >/dev/null
    rm -f "$pwfile"
  fi
  if ! as_owner "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
    as_owner "$BIN/pg_ctl" -D "$DATA" -l "$DIR/server.log" -w start -o \
      "-c listen_addresses=127.0.0.1 -p $PORT -c unix_socket_directories=$DIR \
       -c shared_preload_libraries=pg_stat_statements -c max_connections=50" >/dev/null
  fi
  if [ "$fresh" = 1 ]; then
    as_owner "$BIN/psql" -h "$DIR" -p "$PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
      -c 'CREATE DATABASE shop'
    as_owner "$BIN/psql" -h "$DIR" -p "$PORT" -U postgres -d shop -v ON_ERROR_STOP=1 -q \
      -f - <"$DEV/seed/out/postgres.sql"
    # Same script as the container entrypoint (psql via PGHOST / PGPORT).
    as_owner env PGHOST="$DIR" PGPORT="$PORT" PATH="$BIN:$PATH" POSTGRES_USER=postgres \
      POSTGRES_DB=shop DATABASTION_DB_PASSWORD="$DATABASTION_DB_PASSWORD" \
      bash "$HERE/initdb/20-databastion.sh" >/dev/null
  fi
  env_vars
}

stop() {
  if [ -f "$DATA/PG_VERSION" ]; then
    as_owner "$BIN/pg_ctl" -D "$DATA" -m fast -w stop >/dev/null 2>&1 || true
  fi
  rm -rf "$DIR"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  env) env_vars ;;
  *) echo "usage: $0 start|env|stop" >&2; exit 2 ;;
esac
