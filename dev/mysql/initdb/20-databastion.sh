# Sourced by the MySQL entrypoint after 10-seed.sql. Agent account, ADR-0018 minimal variant:
# SELECT on the application database only (no global privilege: SELECT ON *.* would expose the
# mysql.user password hashes; no PROCESS, no SHOW VIEW), TLS required, at most 4 sessions (a scan, a
# check() and the separate KILL QUERY session of the connector). No performance_schema grant yet:
# Audit (P4-B) adds it. '%' because the agent connects through the published port in dev; restrict
# the host in production.
databastion_agent_account() {
  # Single quotes doubled and backslashes escaped (default sql_mode): any dev password works.
  local pw
  pw="$(printf '%s' "$DATABASTION_DB_PASSWORD" | sed -e 's/\\/\\\\/g' -e "s/'/''/g")"
  docker_process_sql --database=mysql <<EOSQL
CREATE USER 'databastion'@'%' IDENTIFIED WITH caching_sha2_password BY '${pw}'
  REQUIRE SSL WITH MAX_USER_CONNECTIONS 4;
GRANT SELECT ON hr.* TO 'databastion'@'%';
EOSQL
}
databastion_agent_account
