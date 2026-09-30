# shellcheck shell=bash
# Sourced (no exec bit) by the MariaDB entrypoint of target-mariadb, after the seed, the agent
# account (dev's 20-databastion.sh) and the TLS material: the workload account of the load harness
# (e2e/load/run.sh). sysbench connects with it, never with the agent's account. SELECT on
# `support.*` only (the scaled tables are created there by run.sh). The password comes from the
# Docker secret into a local shell variable of the entrypoint (not exported, never on a command
# line); server_audit logs no DCL here (QUERY_DML only).
# shellcheck disable=SC2154 # docker_process_sql / docker_sql_escape_string_literal: entrypoint
load_client_password="$(cat /run/secrets/load_client_password)"
docker_process_sql --database=mysql <<EOSQL
CREATE USER 'load_app'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${load_client_password}")';
GRANT SELECT ON support.* TO 'load_app'@'%';
EOSQL
unset load_client_password
