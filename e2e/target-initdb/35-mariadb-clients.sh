# shellcheck shell=bash
# Sourced (no exec bit) by the MariaDB entrypoint of target-mariadb, after the seed, the agent account
# (dev's 20-databastion.sh) and the TLS material: the two client accounts of the Audit test (P4-D),
# used from the separate my-client container, never the agent's account. e2e_exporter runs
# mariadb-dump, e2e_analyst runs queries whose text holds ground-truth literals and an INTO OUTFILE
# attempt (refused: no FILE privilege), and e2e_admin (the global CREATE USER privilege only, no
# data access) runs the password-bearing DCL of the Audit test (CREATE USER / ALTER USER ...
# IDENTIFIED BY, ROADMAP phase 7). e2e_exporter / e2e_analyst: SELECT on support.* only
# (mariadb-dump runs with --single-transaction --no-tablespaces, so neither LOCK TABLES nor PROCESS
# is needed). The password comes from the Docker secret into a local shell variable of the
# entrypoint (not exported, never on a command line); server_audit logs no DCL here (QUERY_DML;
# run.sh adds QUERY_DCL at run time, after the initialization, for the DCL test).
# shellcheck disable=SC2154 # docker_process_sql / docker_sql_escape_string_literal: entrypoint
e2e_client_password="$(cat /run/secrets/client_password)"
docker_process_sql --database=mysql <<EOSQL
CREATE USER 'e2e_exporter'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${e2e_client_password}")';
CREATE USER 'e2e_analyst'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${e2e_client_password}")';
GRANT SELECT ON support.* TO 'e2e_exporter'@'%', 'e2e_analyst'@'%';
CREATE USER 'e2e_admin'@'%' IDENTIFIED BY '$(docker_sql_escape_string_literal "${e2e_client_password}")';
GRANT CREATE USER ON *.* TO 'e2e_admin'@'%';
EOSQL
unset e2e_client_password
