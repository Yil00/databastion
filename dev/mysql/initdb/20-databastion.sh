# Sourced by the MySQL entrypoint after 10-seed.sql. Read-only account from docs/05-security.md.
# Grants are server-wide (SELECT ON *.*) as documented; Discovery itself excludes the system schemas
# mysql, information_schema, performance_schema and sys. '%' because the agent connects through the
# published port in dev; restrict the host in production.
# DATABASTION_DB_PASSWORD must not contain a single quote (dev-only value from dev/.env).
docker_process_sql --database=mysql <<EOSQL
CREATE USER 'databastion'@'%' IDENTIFIED BY '${DATABASTION_DB_PASSWORD}';
GRANT SELECT, PROCESS, SHOW VIEW ON *.* TO 'databastion'@'%';
GRANT SELECT ON performance_schema.* TO 'databastion'@'%';
EOSQL
