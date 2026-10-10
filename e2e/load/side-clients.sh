#!/bin/bash
# Side accounts of the MariaDB Audit run (ADR-0045), run by run.sh next to sysbench in the `my-side`
# service (the target's image, for its `mariadb` client):
#   - load_monitor, a monitoring-like reader (PMM / mysqld_exporter style): the digest summary,
#     `performance_schema.threads` and `information_schema.PROCESSLIST`, once a second;
#   - load_builtins, an application's table-less built-in calls and driver session probes, once a
#     second.
# One session per account, kept for the whole run, as those tools do. The statements are written to
# the client one second at a time, so it runs them as they come. Prints one line per account:
#   side <account> <statements issued> <0 | 1: the client failed>
#
#   side-clients.sh DURATION_S
set -euo pipefail
dur="$1"
[[ "$dur" =~ ^[0-9]+$ ]] || { echo "side-clients.sh: DURATION_S must be a number" >&2; exit 2; }
# The load accounts' password (a Docker secret), for the client only: never on a command line.
MYSQL_PWD="$(cat /run/secrets/load_client_password)"
export MYSQL_PWD
end=$(( $(date +%s) + dur ))

MONITOR=(
  "SELECT SCHEMA_NAME, DIGEST, COUNT_STAR, SUM_TIMER_WAIT FROM performance_schema.events_statements_summary_by_digest ORDER BY SUM_TIMER_WAIT DESC LIMIT 50;"
  "SELECT THREAD_ID, PROCESSLIST_ID, PROCESSLIST_USER, PROCESSLIST_COMMAND, PROCESSLIST_STATE FROM performance_schema.threads;"
  "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE FROM information_schema.PROCESSLIST;"
)
BUILTINS=(
  "SELECT NOW();"
  "SELECT LAST_INSERT_ID();"
  "SELECT DATABASE();"
  "SELECT @@session.auto_increment_increment AS auto_increment_increment, @@character_set_client AS character_set_client, @@max_allowed_packet AS max_allowed_packet, @@sql_mode AS sql_mode;"
  "SELECT CONNECTION_ID(), VERSION(), USER(), CURRENT_USER();"
  "SET NAMES utf8mb4;"
  "SELECT UTC_TIMESTAMP(), UNIX_TIMESTAMP(), CONCAT('a', 'b'), IFNULL(NULL, 1), COALESCE(NULL, 2);"
  "SELECT 1;"
)

# feed ACCOUNT STATEMENT...: the statements once a second until the end; the count in /tmp.
feed() {
  local account="$1" n=0
  shift
  while [ "$(date +%s)" -lt "$end" ]; do
    printf '%s\n' "$@"
    n=$((n + $#))
    printf '%s\n' "$n" >"/tmp/issued.$account"
    sleep 1
  done
}

# run ACCOUNT STATEMENT...: one session of ACCOUNT running what feed writes.
run() {
  local account="$1" rc=0
  printf '0\n' >"/tmp/issued.$account"
  # The load accounts have no TLS requirement (as sysbench's load_app); dev-only, on the
  # harness's internal network.
  feed "$@" | mariadb -h mariadb -P 3306 -u "$account" --skip-ssl -N -B >/dev/null || rc=$?
  printf 'side %s %s %s\n' "$account" "$(cat "/tmp/issued.$account")" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
}

run load_monitor "${MONITOR[@]}" &
monitor_pid=$!
run load_builtins "${BUILTINS[@]}" &
builtins_pid=$!
wait "$monitor_pid"
wait "$builtins_pid"
