#!/usr/bin/env bash
# Captures the digests (DIGEST_TEXT) of the agent's performance_schema poll and stats texts as each
# running dev MySQL / MariaDB / Percona service renders them, in the format of the connector's
# fixture agent/crates/connector-mysql/src/audit/testdata/poll_digests.tsv (server, kind, table,
# with_program, digest; tab-separated). ROADMAP phase 9 follow-up "#256: the interrupted-poll digest
# fixtures on the other matrix versions": the engine matrix runs it after `dev/agent-it.sh mysql`,
# whose tests sent every poll and stats text, and uploads the result; the maintainer (or an
# agent-engineer) copies the rows of a new version into the fixture. Nothing is changed on the
# servers.
#
#   dev/capture-poll-digests.sh [SERVICE...]   (default: mysql mariadb percona; output on stdout)
#
# Read as root over each container's own client, from events_statements_summary_by_digest (every
# digest the server saw since its start, the cut ones included: a cut digest is the poll's digest at
# the server's limit, which is what an interrupted poll leaves). The digest texts are the agent's
# constant poll texts, normalized by the server: no value, no dev data. Dev-only credentials from
# dev/.env, passed through the environment (never a command line).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE_FILE="$ROOT/dev/docker-compose.yml"
[ -f dev/.env ] || { echo "dev/.env is missing: run \`make dev\` first" >&2; exit 2; }
set -a
# shellcheck disable=SC1091 # dev-only values, created by `make dev`
. dev/.env
set +a

SERVICES=("$@")
[ "${#SERVICES[@]}" -gt 0 ] || SERVICES=(mysql mariadb percona)

# The two families of texts: the polls start with `SELECT h.THREAD_ID, h.EVENT_ID`, the stats with
# the `events_statements_current` subquery (sql::ps_statements and sql::ps_stats).
WHERE_TEXTS="WHERE DIGEST_TEXT LIKE 'SELECT \`h\` . \`THREAD_ID\` , \`h\` . \`EVENT_ID\`%'
     OR DIGEST_TEXT LIKE 'SELECT ( SELECT \`c\` . \`TIMER_START\` FROM \`performance_schema\` . \`events_statements_current\`%'"
QUERY="SELECT DISTINCT DIGEST_TEXT FROM performance_schema.events_statements_summary_by_digest $WHERE_TEXTS ORDER BY DIGEST_TEXT;"
# Fallback when the digest summary is off (consumer statements_digest): the statement history.
QUERY_HISTORY="SELECT DISTINCT DIGEST_TEXT FROM performance_schema.events_statements_history_long $WHERE_TEXTS ORDER BY DIGEST_TEXT;"
LIMITS="SELECT VERSION(), @@max_digest_length, @@performance_schema_max_digest_length;"

# sql SERVICE < SQL: rows, tab-separated, no header, as root inside the service.
sql() {
  local svc="$1"
  case "$svc" in
    mysql) MYSQL_PWD="$MYSQL_ROOT_PASSWORD" timeout 120 docker compose -f "$COMPOSE_FILE" exec -T -e MYSQL_PWD \
      mysql mysql -uroot -N -B ;;
    mariadb) MYSQL_PWD="$MARIADB_ROOT_PASSWORD" timeout 120 docker compose -f "$COMPOSE_FILE" exec -T -e MYSQL_PWD \
      mariadb mariadb -uroot -N -B ;;
    percona) MYSQL_PWD="$PERCONA_ROOT_PASSWORD" timeout 120 docker compose -f "$COMPOSE_FILE" exec -T -e MYSQL_PWD \
      percona mysql -h 127.0.0.1 --protocol=TCP -uroot -N -B ;;
    *) echo "unknown service '$svc' (mysql, mariadb or percona)" >&2; return 2 ;;
  esac
}

echo "# Digests (DIGEST_TEXT) of the performance_schema poll and stats texts, captured by"
echo "# dev/capture-poll-digests.sh on $(date -u +%Y-%m-%d) from the dev services: server, kind, table,"
echo "# with_program, digest. '?' where the server cut the digest before the field could be read."
status=0
for svc in "${SERVICES[@]}"; do
  if ! limits="$(printf '%s\n' "$LIMITS" | sql "$svc")"; then
    echo "# $svc: not reachable" ; status=1; continue
  fi
  IFS=$'\t' read -r version max_digest ps_max_digest <<<"$limits"
  case "$svc" in
    mariadb) label="mariadb-${version%%-*}" ;;
    *) label="${svc}-${version}" ;;
  esac
  echo "# ${label}: max_digest_length ${max_digest}, performance_schema_max_digest_length ${ps_max_digest}"
  rows="$(printf '%s\n' "$QUERY" | sql "$svc")" || rows=""
  if [ -z "$rows" ]; then
    echo "# ${label}: no poll or stats digest in events_statements_summary_by_digest: from events_statements_history_long"
    rows="$(printf '%s\n' "$QUERY_HISTORY" | sql "$svc")" || rows=""
  fi
  if [ -z "$rows" ]; then
    echo "# ${label}: no poll or stats digest found"
    status=1
    continue
  fi
  awk -v server="$label" -F '\t' '
    {
      d = $0
      kind = (d ~ /^SELECT `h` \. `THREAD_ID`/) ? "poll" : "stats"
      table = "?"
      if (match(d, /FROM `performance_schema` \. `events_statements_[a-z_]+` `h`/)) {
        t = substr(d, RSTART, RLENGTH)
        sub(/^FROM `performance_schema` \. `/, "", t)
        sub(/` `h`$/, "", t)
        table = t
      }
      prog = "-"
      if (kind == "poll") {
        if (index(d, "`session_connect_attrs`") > 0) prog = "true"
        else if (index(d, ", ? FROM `performance_schema` . `events_statements_") > 0) prog = "false"
        else prog = "?"
      }
      printf "%s\t%s\t%s\t%s\t%s\n", server, kind, table, prog, d
    }' <<<"$rows" | sort -t $'\t' -k2,2 -k3,3 -k4,4
done
exit "$status"
