#!/usr/bin/env bash
# Smoke tests of a running dev environment (`make dev` first). Used by .github/workflows/dev-env.yml
# and runnable locally with `make dev-smoke`. Credentials are read inside the containers (env) or
# from dev/.env; nothing is printed.
set -euo pipefail
cd "$(dirname "$0")"
C=(docker compose -f docker-compose.yml)
set -a; . ./.env; set +a

fail=0
ok()   { echo "ok   - $*"; }
ko()   { echo "FAIL - $*"; fail=1; }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else ko "$name"; fi; }
# retry <tries> <cmd…>: engines flush their logs asynchronously.
retry() { local n=$1; shift; for _ in $(seq "$n"); do "$@" && return 0; sleep 2; done; return 1; }
ex() { local svc=$1; shift; "${C[@]}" exec -T "$svc" sh -c "$*"; }
must_fail() { ! "$@"; }

echo "# Ports bound to 127.0.0.1 only"
ports=$("${C[@]}" ps --format '{{.Ports}}')
check "no port published on 0.0.0.0 / ::" must_fail grep -Eq '0\.0\.0\.0:|\[::\]:|:::' <<<"$ports"

echo "# PostgreSQL + pgaudit"
PSQL='PGPASSWORD="$DATABASTION_DB_PASSWORD" psql -h 127.0.0.1 -U databastion -d shop -v ON_ERROR_STOP=1 -Atq'
check "read-only account can read" ex postgres "$PSQL -c 'SELECT count(*) FROM crm.customers' | grep -Eq '^[1-9]'"
check "read-only account cannot write" must_fail ex postgres "$PSQL -c 'DELETE FROM billing.invoices WHERE id = -1'"
# ADR-0012 minimal variant: no pg_read_all_data, so the credential-bearing catalogs are denied.
# Asserted as privileges (not "the query failed"), so a connection error cannot pass for a denial.
check "read-only account cannot read pg_authid / pg_user_mapping" ex postgres \
  "$PSQL -c \"SELECT has_table_privilege('pg_catalog.pg_authid', 'SELECT')
     OR has_table_privilege('pg_catalog.pg_user_mapping', 'SELECT')\" | grep -qx f"
check "read-only account attributes (no superuser / createdb / createrole / replication / bypassrls, limit 4)" \
  ex postgres "$PSQL -c \"SELECT concat_ws(',', rolsuper, rolcreatedb, rolcreaterole, rolreplication,
     rolbypassrls, rolconnlimit) FROM pg_roles WHERE rolname = current_user\" | grep -qx 'f,f,f,f,f,4'"
check "read-only account role defaults (read-only, timeouts)" ex postgres \
  "$PSQL -c \"SELECT current_setting('default_transaction_read_only') = 'on'
     AND current_setting('statement_timeout')::interval = '30s'
     AND current_setting('lock_timeout')::interval = '2s'
     AND current_setting('idle_in_transaction_session_timeout')::interval = '60s'\" | grep -qx t"
check "read-only account is a member of pg_read_all_stats only" ex postgres \
  "$PSQL -c \"SELECT string_agg(b.rolname, '+' ORDER BY b.rolname) FROM pg_auth_members m
     JOIN pg_roles b ON b.oid = m.roleid WHERE m.member = 'databastion'::regrole\" | grep -qx pg_read_all_stats"
check "pgaudit SESSION log line after a SELECT" retry 15 ex postgres \
  "grep 'AUDIT: SESSION' /var/log/databastion/postgresql.json | grep -q 'crm.customers'"
check "pgaudit OBJECT log line (databastion_auditor)" retry 15 ex postgres \
  "grep 'AUDIT: OBJECT' /var/log/databastion/postgresql.json | grep -q 'crm.customers'"
check "log_connections in jsonlog" ex postgres "grep -q 'connection authorized: user=databastion' /var/log/databastion/postgresql.json"
check "jsonlog visible on the host" test -s .state/logs/postgres/postgresql.json

echo "# MariaDB + server_audit"
MARIADB='MYSQL_PWD="$DATABASTION_DB_PASSWORD" mariadb -h 127.0.0.1 -u databastion -N'
check "read-only account can read" ex mariadb "$MARIADB -e 'SELECT COUNT(*) FROM support.tickets' | grep -Eq '^[1-9]'"
check "read-only account cannot write" must_fail ex mariadb "$MARIADB -e 'DELETE FROM support.tickets WHERE id = -1'"
check "server_audit log records the query" retry 15 ex mariadb \
  "grep databastion /var/log/databastion/server_audit.log | grep -q tickets"
check "audit log non-empty on the host" test -s .state/logs/mariadb/server_audit.log

echo "# MySQL + performance_schema"
MYSQL='MYSQL_PWD="$DATABASTION_DB_PASSWORD" mysql -h 127.0.0.1 -u databastion -N'
check "read-only account can read" ex mysql "$MYSQL -e 'SELECT COUNT(*) FROM hr.employees' | grep -Eq '^[1-9]'"
check "read-only account cannot write" must_fail ex mysql "$MYSQL -e 'DELETE FROM hr.employees WHERE id = -1'"
check "events_statements_history_long records the query" ex mysql \
  "$MYSQL -e \"SELECT COUNT(*) FROM performance_schema.events_statements_history_long WHERE SQL_TEXT LIKE '%hr.employees%'\" | grep -Eq '^[1-9]'"

echo "# MongoDB (Community: profiler + JSON logs)"
MONGO='mongosh --quiet --norc "mongodb://databastion:$DATABASTION_DB_PASSWORD@127.0.0.1:27017/app?authSource=admin"'
check "read-only account can read" ex mongo "$MONGO --eval 'if (db.users.countDocuments() < 1) quit(1)'"
check "read-only account cannot write" must_fail ex mongo "$MONGO --eval 'db.users.insertOne({smoke: 1})'"
check "slow-operation JSON log mentions app.users" retry 15 ex mongo \
  "grep '\"Slow query\"' /var/log/databastion/mongod.log | grep -q '\"app.users\"'"

echo "# OpenLDAP + accesslog"
BIND='-x -H ldap://127.0.0.1 -D cn=databastion,ou=services,dc=example,dc=org -w "$DATABASTION_DB_PASSWORD" -LLL'
check "service account can search the tree" ex openldap \
  "ldapsearch $BIND -b dc=example,dc=org '(objectClass=inetOrgPerson)' mail | grep -q '^mail:'"
check "service account cannot read userPassword" must_fail ex openldap \
  "ldapsearch $BIND -b dc=example,dc=org '(objectClass=inetOrgPerson)' userPassword | grep -qi '^userPassword'"
check "cn=accesslog has an entry for the search" retry 10 ex openldap \
  "ldapsearch $BIND -b cn=accesslog '(&(objectClass=auditSearch)(reqAuthzID=cn=databastion,ou=services,dc=example,dc=org))' reqStart | grep -q '^reqStart:'"

echo "# Mailpit, Prometheus, Grafana"
check "Mailpit API up" curl -fsS "http://127.0.0.1:${MAILPIT_UI_PORT}/api/v1/info"
printf 'Subject: DataBastion smoke test\r\n\r\nhello\r\n' > .state/smoke-mail.txt
check "Mailpit accepts SMTP" curl -fsS "smtp://127.0.0.1:${MAILPIT_SMTP_PORT}" \
  --mail-from dev@example.org --mail-rcpt ops@example.org -T .state/smoke-mail.txt
check "Mailpit stored the message" retry 5 sh -c \
  "curl -fsS http://127.0.0.1:${MAILPIT_UI_PORT}/api/v1/messages | grep -q 'DataBastion smoke test'"
check "Prometheus ready" curl -fsS "http://127.0.0.1:${PROMETHEUS_PORT}/-/ready"
check "Prometheus has the console scrape job" retry 10 sh -c \
  "curl -fsS http://127.0.0.1:${PROMETHEUS_PORT}/api/v1/targets | grep -q databastion-console"
check "Grafana healthy" curl -fsS "http://127.0.0.1:${GRAFANA_PORT}/api/health"
check "Grafana dashboard provisioned" retry 15 curl -fsS -u "admin:${GRAFANA_ADMIN_PASSWORD}" \
  "http://127.0.0.1:${GRAFANA_PORT}/api/dashboards/uid/databastion-overview"

exit "$fail"
