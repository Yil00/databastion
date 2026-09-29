# Sourced by the Percona Server entrypoint after 10-seed.sql (`mysql` is the entrypoint's client
# command array). Agent account, ADR-0018 minimal variant: SELECT on the application database only,
# TLS required, at most 4 sessions. No performance_schema grant: Audit reads the audit_log_filter
# JSON log from the file system (P4-B). '%' because the agent connects through the published port
# in dev; restrict the host in production.
#
# Audit: install the audit_log_filter component and log everything, except root@localhost (the
# compose healthcheck), so that the tests see every statement of the other accounts.
databastion_percona() {
  local pw
  # Single quotes doubled and backslashes escaped (default sql_mode): any dev password works.
  pw="$(printf '%s' "$DATABASTION_DB_PASSWORD" | sed -e 's/\\/\\\\/g' -e "s/'/''/g")"
  "${mysql[@]}" < /usr/share/percona-server/audit_log_filter_linux_install.sql
  "${mysql[@]}" <<EOSQL
CREATE USER 'databastion'@'%' IDENTIFIED WITH caching_sha2_password BY '${pw}'
  REQUIRE SSL WITH MAX_USER_CONNECTIONS 4;
GRANT SELECT ON hr.* TO 'databastion'@'%';
SELECT audit_log_filter_set_filter('log_all', '{"filter": {"log": true}}');
SELECT audit_log_filter_set_filter('log_none', '{"filter": {"log": false}}');
SELECT audit_log_filter_set_user('%', 'log_all');
SELECT audit_log_filter_set_user('root@localhost', 'log_none');
EOSQL
}
databastion_percona
