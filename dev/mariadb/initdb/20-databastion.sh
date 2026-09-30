# Sourced by the MariaDB entrypoint after 10-seed.sql. Agent account, ADR-0018 minimal variant:
# SELECT on the application database only (no global privilege: SELECT ON *.* would expose the
# mysql.global_priv password hashes; no PROCESS, no SHOW VIEW), TLS required, at most 4 sessions (a
# scan, a check() and the separate KILL QUERY session of the connector), and a 30 s statement timeout
# on the account as a safety net (the connector sets its own). No performance_schema grant: Audit
# (P4-B) reads the server_audit log from the file system (the integration tests create their own
# account with the performance_schema grant for the fallback source). '%' because the agent
# connects through the published port in dev; restrict the host in production.
docker_process_sql --database=mysql <<EOSQL
CREATE USER 'databastion'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${DATABASTION_DB_PASSWORD}")'
  REQUIRE SSL WITH MAX_USER_CONNECTIONS 5 MAX_STATEMENT_TIME 30;
GRANT SELECT ON support.* TO 'databastion'@'%';
EOSQL
