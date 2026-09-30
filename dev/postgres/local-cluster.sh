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
# data directory (DATABASTION_PG_LOCAL_DIR, default /tmp/databastion-pg-local). With pgaudit
# installed on the host (`postgresql-<major>-pgaudit`), the server also loads pgaudit and writes
# its log as jsonlog and csvlog under $DIR/log (DATABASTION_TEST_PG_AUDIT_LOG / _AUDIT_CSVLOG, for
# the Audit integration tests). Dev-only passwords
# from dev/.env.example. As root, the server runs as the `postgres` OS user. TLS with a throwaway
# CA (DATABASTION_TEST_PG_CA_FILE); pg_hba lines for the md5 / cleartext refusal tests.
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

has_pgaudit() {
  [ -f "$(dirname "$BIN")/lib/pgaudit.so" ]
}

env_vars() {
  cat <<EOF
export DATABASTION_TEST_PG_URL='postgresql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${PORT}/shop'
export DATABASTION_TEST_PG_ADMIN_URL='postgresql://postgres:${POSTGRES_ADMIN_PASSWORD}@127.0.0.1:${PORT}/shop'
export DATABASTION_TEST_PG_CA_FILE='${DIR}/tls/ca.pem'
EOF
  if has_pgaudit; then
    cat <<EOF
export DATABASTION_TEST_PG_AUDIT_LOG='${DIR}/log/postgresql.json'
export DATABASTION_TEST_PG_AUDIT_CSVLOG='${DIR}/log/postgresql.csv'
EOF
  fi
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
    # Connector test roles authenticated with MD5 / cleartext passwords: the connector must
    # refuse both without TLS (security review M2).
    { printf 'host all databastion_it_md5 127.0.0.1/32 md5\n'
      printf 'host all databastion_it_clear 127.0.0.1/32 password\n'
      cat "$DATA/pg_hba.conf"; } >"$DIR/pg_hba.conf.new"
    as_owner cp "$DIR/pg_hba.conf.new" "$DATA/pg_hba.conf"
    rm -f "$DIR/pg_hba.conf.new"
    # Throwaway CA and server certificate (SAN IP:127.0.0.1) for the connector's verify_full
    # test; the openssl CLI is test tooling only (the agent links rustls).
    mkdir -p "$DIR/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=databastion-it-ca \
      -keyout "$DIR/tls/ca.key" -out "$DIR/tls/ca.pem" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=127.0.0.1 \
      -keyout "$DIR/tls/server.key" -out "$DIR/tls/server.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1\n' >"$DIR/tls/ext.cnf"
    openssl x509 -req -in "$DIR/tls/server.csr" -CA "$DIR/tls/ca.pem" -CAkey "$DIR/tls/ca.key" \
      -CAcreateserial -days 2 -extfile "$DIR/tls/ext.cnf" -out "$DIR/tls/server.pem" 2>/dev/null
    rm -f "$DIR/tls/ca.key" "$DIR/tls/server.csr"
    chmod 0600 "$DIR/tls/server.key"
    if [ "$(id -u)" = 0 ]; then chown -R postgres: "$DIR/tls"; fi
  fi
  if ! as_owner "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
    # Audit (P4-A): with pgaudit installed on the host, the same audit settings as the dev image
    # (docker-compose.yml), and the server log written as both jsonlog and csvlog (dev only, so
    # that the connector's two parsers run against a real server).
    local preload=pg_stat_statements audit_opts=""
    if has_pgaudit; then
      preload=pgaudit,pg_stat_statements
      mkdir -p "$DIR/log"
      if [ "$(id -u)" = 0 ]; then chown postgres: "$DIR/log"; fi
      chmod 0755 "$DIR/log"
      audit_opts="-c logging_collector=on -c log_destination=jsonlog,csvlog \
        -c log_directory=$DIR/log -c log_filename=postgresql.log -c log_file_mode=0644 \
        -c log_connections=on -c pgaudit.log=none -c pgaudit.role=databastion_auditor \
        -c pgaudit.log_relation=on -c pgaudit.log_catalog=off -c pgaudit.log_parameter=off \
        -c pgaudit.log_rows=on -c pg_stat_statements.track=all"
    fi
    as_owner "$BIN/pg_ctl" -D "$DATA" -l "$DIR/server.log" -w start -o \
      "-c listen_addresses=127.0.0.1 -p $PORT -c unix_socket_directories=$DIR \
       -c shared_preload_libraries=$preload -c max_connections=50 \
       -c ssl=on -c ssl_cert_file=$DIR/tls/server.pem -c ssl_key_file=$DIR/tls/server.key \
       $audit_opts" \
      >/dev/null
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
