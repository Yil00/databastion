# shellcheck shell=bash
# Sourced (no exec bit) by the MariaDB entrypoint of target-mariadb, after the seed, the agent
# account (dev's 20-databastion.sh) and the TLS material: the workload account of the load harness
# (e2e/load/run.sh). sysbench connects with it, never with the agent's account. No privilege here:
# run.sh grants SELECT table by table on the load tables it creates in `support` (seed.py), as on
# PostgreSQL. The password comes from the
# Docker secret into a local shell variable of the entrypoint (not exported, never on a command
# line); server_audit logs no DCL here (QUERY_DML only).
# shellcheck disable=SC2154 # docker_process_sql / docker_sql_escape_string_literal: entrypoint
load_client_password="$(cat /run/secrets/load_client_password)"
# The side accounts of the Audit run (ADR-0045, side-clients.sh), same password: load_monitor, a
# monitoring-like reader (performance_schema and PROCESS, as PMM or mysqld_exporter), and
# load_builtins, table-less built-in calls only (no privilege).
docker_process_sql --database=mysql <<EOSQL
CREATE USER 'load_app'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${load_client_password}")';
CREATE USER 'load_monitor'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${load_client_password}")';
GRANT SELECT ON performance_schema.* TO 'load_monitor'@'%';
GRANT PROCESS ON *.* TO 'load_monitor'@'%';
CREATE USER 'load_builtins'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${load_client_password}")';
EOSQL
unset load_client_password
