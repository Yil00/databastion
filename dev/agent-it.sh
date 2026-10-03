#!/usr/bin/env bash
# Connector integration tests against the running dev environment (`make dev`), one engine at a
# time, with the same variables and DATABASTION_TEST_REQUIRE as the "dev image" step of the
# matching CI job (.github/workflows/ci.yml: agent-pg, agent-mysql, agent-mongodb, agent-openldap).
#
#   dev/agent-it.sh postgres|mysql|mongodb|openldap|all     (or: make agent-it [ENGINE=...])
#
# Not covered here (CI-only extra steps, see ci.yml): the PostgreSQL local cluster (TLS, weak
# authentication), the MongoDB verify_full TLS server and the Percona Server for MongoDB auditLog
# service, and SASL EXTERNAL over ldapi://. Dev-only credentials from dev/.env; nothing is printed
# from them. Every docker call is bounded by `timeout`; the cargo runs by the caller's `timeout`.
# The engine-matrix workflow (.github/workflows/engine-matrix.yml) runs this script against other
# engine versions, selected by the DATABASTION_DEV_*_IMAGE variables of docker-compose.yml.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ENGINE="${1:-all}"
COMPOSE_FILE="$ROOT/dev/docker-compose.yml"
compose() { timeout 60 docker compose -f "$COMPOSE_FILE" "$@"; }

[ -f dev/.env ] || { echo "dev/.env is missing: run \`make dev\` first" >&2; exit 2; }
set -a
# shellcheck disable=SC1091 # dev-only values, created by `make dev`
. dev/.env
set +a

# The services a run needs must be up (started by `make dev`).
require_services() {
  local running s
  running="$(compose ps --status running --services 2>/dev/null || true)"
  for s in "$@"; do
    if ! grep -qx "$s" <<<"$running"; then
      echo "dev service '$s' is not running: run \`make dev\` first (make dev-ps shows the status)" >&2
      exit 2
    fi
  done
}

cargo_it() { (cd agent && cargo test -p "$1" --all-features --locked -- --nocapture "${@:2}"); }

it_postgres() {
  require_services postgres
  # Another PostgreSQL image needs its own tag: e2e and the load harness refer to the default name.
  if [ -n "${DATABASTION_DEV_POSTGRES_IMAGE:-}" ] && [ -z "${DATABASTION_DEV_POSTGRES_TAG:-}" ]; then
    echo "DATABASTION_DEV_POSTGRES_IMAGE is set: set DATABASTION_DEV_POSTGRES_TAG too (dev/README.md)" >&2
    exit 2
  fi
  export DATABASTION_TEST_PG_URL="postgresql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/shop"
  export DATABASTION_TEST_PG_ADMIN_URL="postgresql://postgres:${POSTGRES_ADMIN_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/shop"
  # The pgaudit log format of the service (docker-compose.yml): jsonlog by default, csvlog for
  # PostgreSQL 13 and 14, where jsonlog does not exist (engine-matrix workflow).
  case "${DATABASTION_DEV_POSTGRES_LOG_FORMAT:-jsonlog}" in
    jsonlog) export DATABASTION_TEST_PG_AUDIT_LOG="$ROOT/dev/.state/logs/postgres/postgresql.json" ;;
    csvlog) export DATABASTION_TEST_PG_AUDIT_CSVLOG="$ROOT/dev/.state/logs/postgres/postgresql.csv" ;;
    *) echo "DATABASTION_DEV_POSTGRES_LOG_FORMAT must be jsonlog or csvlog" >&2; exit 2 ;;
  esac
  export DATABASTION_TEST_REQUIRE=pg,admin,pss,pgaudit,pgaudit-log
  cargo_it databastion-connector-postgres
}

it_mysql() {
  require_services mysql mariadb percona
  mkdir -p dev/.state/tls
  compose exec -T mysql cat /var/lib/mysql/ca.pem > dev/.state/tls/mysql-ca.pem
  compose exec -T mariadb cat /var/lib/mysql/databastion-tls/ca.pem > dev/.state/tls/mariadb-ca.pem
  compose exec -T percona cat /var/lib/mysql/ca.pem > dev/.state/tls/percona-ca.pem
  export DATABASTION_TEST_MYSQL_URL="mysql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${MYSQL_PORT}/hr"
  export DATABASTION_TEST_MYSQL_ADMIN_URL="mysql://root:${MYSQL_ROOT_PASSWORD}@127.0.0.1:${MYSQL_PORT}/"
  export DATABASTION_TEST_MYSQL_CA_FILE="$ROOT/dev/.state/tls/mysql-ca.pem"
  export DATABASTION_TEST_MARIADB_URL="mysql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${MARIADB_PORT}/support"
  export DATABASTION_TEST_MARIADB_ADMIN_URL="mysql://root:${MARIADB_ROOT_PASSWORD}@127.0.0.1:${MARIADB_PORT}/"
  export DATABASTION_TEST_MARIADB_CA_FILE="$ROOT/dev/.state/tls/mariadb-ca.pem"
  DATABASTION_TEST_MARIADB_NETWORK_HOST="$(timeout 60 docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(compose ps -q mariadb)")"
  export DATABASTION_TEST_MARIADB_NETWORK_HOST
  export DATABASTION_TEST_MARIADB_AUDIT_LOG="$ROOT/dev/.state/logs/mariadb/server_audit.log"
  export DATABASTION_TEST_PERCONA_URL="mysql://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${PERCONA_PORT}/hr"
  export DATABASTION_TEST_PERCONA_ADMIN_URL="mysql://root:${PERCONA_ROOT_PASSWORD}@127.0.0.1:${PERCONA_PORT}/"
  export DATABASTION_TEST_PERCONA_CA_FILE="$ROOT/dev/.state/tls/percona-ca.pem"
  export DATABASTION_TEST_PERCONA_AUDIT_LOG="$ROOT/dev/.state/logs/percona/audit_filter.log"
  local exec_in="timeout 120 docker compose -f $COMPOSE_FILE exec -T"
  export DATABASTION_TEST_MARIADB_DUMP_CMD="$exec_in -e MYSQL_PWD=${MARIADB_ROOT_PASSWORD} mariadb mariadb-dump -uroot --single-transaction support"
  export DATABASTION_TEST_MYSQL_DUMP_CMD="$exec_in -e MYSQL_PWD=${MYSQL_ROOT_PASSWORD} mysql mysqldump -uroot --single-transaction hr"
  export DATABASTION_TEST_PERCONA_DUMP_CMD="$exec_in -e MYSQL_PWD=${PERCONA_ROOT_PASSWORD} percona mysqldump -h 127.0.0.1 --protocol=TCP -uroot --single-transaction hr"
  export DATABASTION_TEST_REQUIRE=mysql,mariadb,mysql-admin,mariadb-admin,mysql-tls,mariadb-tls,federated,pam,network,mariadb-audit,percona,percona-audit,mysqldump
  cargo_it databastion-connector-mysql
}

it_mongodb() {
  require_services mongo
  local log="$ROOT/dev/.state/logs/mongodb/mongod.log"
  # mongod may create its log 0600 (CI: `sudo chmod a+r`).
  if [ ! -r "$log" ]; then
    sudo -n chmod a+r "$log" || { echo "cannot read $log: run \`sudo chmod a+r $log\`" >&2; exit 2; }
  fi
  export DATABASTION_TEST_MONGO_URL="mongodb://databastion:${DATABASTION_DB_PASSWORD}@127.0.0.1:${MONGO_PORT}/app?authSource=admin"
  export DATABASTION_TEST_MONGO_ADMIN_URL="mongodb://root:${MONGO_ROOT_PASSWORD}@127.0.0.1:${MONGO_PORT}/?authSource=admin"
  export DATABASTION_TEST_MONGO_LOG="$log"
  export DATABASTION_TEST_MONGO_DUMP_CMD="timeout 120 docker compose -f $COMPOSE_FILE exec -T mongo mongodump --quiet --uri 'mongodb://root:${MONGO_ROOT_PASSWORD}@127.0.0.1:27017/?authSource=admin' --db app --collection users --archive=/dev/null"
  export DATABASTION_TEST_MONGO_EXPORT_CMD="timeout 120 docker compose -f $COMPOSE_FILE exec -T mongo mongoexport --quiet --uri 'mongodb://root:${MONGO_ROOT_PASSWORD}@127.0.0.1:27017/?authSource=admin' --db app --collection users --out /dev/null"
  export DATABASTION_TEST_REQUIRE=mongo,mongo-admin,mongo-log,mongodump
  cargo_it databastion-connector-mongodb
}

it_openldap() {
  require_services openldap
  mkdir -p dev/.state/tls
  compose exec -T openldap cat /var/lib/ldap/tls/ca.pem > dev/.state/tls/ldap-ca.pem
  export DATABASTION_TEST_LDAP_URL="ldap://127.0.0.1:${LDAP_PORT}"
  export DATABASTION_TEST_LDAP_PASSWORD="$DATABASTION_DB_PASSWORD"
  export DATABASTION_TEST_LDAP_ADMIN_PASSWORD="$LDAP_ADMIN_PASSWORD"
  export DATABASTION_TEST_LDAPS_URL="ldaps://localhost:${LDAPS_PORT}"
  export DATABASTION_TEST_LDAP_CA_FILE="$ROOT/dev/.state/tls/ldap-ca.pem"
  export DATABASTION_TEST_LDAP_EXPORT_CMD="timeout 120 docker compose -f $COMPOSE_FILE exec -T openldap ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,dc=example,dc=org -w '${LDAP_ADMIN_PASSWORD}' -b dc=example,dc=org -E pr=20/noprompt '(objectClass=*)'"
  export DATABASTION_TEST_REQUIRE=ldap,ldap-admin,ldap-export,ldap-tls
  cargo_it databastion-connector-openldap --test-threads 1
}

case "$ENGINE" in
  postgres | mysql | mongodb | openldap) "it_$ENGINE" ;;
  # Subshells: each engine exports its own DATABASTION_TEST_REQUIRE.
  all) for e in postgres mysql mongodb openldap; do (echo "== $e"; "it_$e"); done ;;
  *) echo "unknown ENGINE '$ENGINE' (postgres, mysql, mongodb, openldap or all)" >&2; exit 2 ;;
esac
