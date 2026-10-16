#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# End-to-end Valkey and Redis targets (ROADMAP P9-D, ADR-0052 decisions 4, 7, 8 and 13): the console
# and the agent (the e2e images) with the dev Valkey 9.0 and Redis 8.10 services (dev/redis: the
# committed keyspace, the agent's ACL user with the decision 4 allow-list, `default` off, TLS only,
# the slow log at every command). Compose: docker-compose.yml merged with docker-compose.redis.yml
# (project databastion-e2e-redis); the client traffic comes from e2e/redis_scenario.py on the host.
# For each of valkey-e2e (engine valkey) and redis-e2e (engine redis):
#   - enrollment; the console lists `engine.redis` and `engine.valkey`: the target is reported,
#     reachable over verified TLS, as the engine it is (no check.server_is_* note), with the honest
#     audit level: None before any other client's slow-log entry, then Limited from the slow log
#     (`audit.slow_operations_only`), never Partial or Full;
#   - Discovery (while the Audit stream runs) against dev/ground-truth.json: every expected
#     classifier, no negative control, key names that embed values stored as their normalized
#     patterns (`user:*:profile`, `*:*`), never raw;
#   - the agent's own commands are never reported: no event at all before the first client command
#     (positive control: the server's slow log holds the agent's own commands, seen and left out);
#   - Audit: a dump-like sweep as e2e_exporter (`KEYS *` per database, then every key whole:
#     `shape.keyspace_enumeration`, attributed to the user through its open connection) and a full
#     synchronization (`SYNC`, as `redis-cli --rdb`: `signature.full_sync`, no recorded account)
#     raise critical incidents; reads of keys whose names embed ground-truth values as e2e_analyst
#     (objects: the learned patterns);
#   - I2: no ground-truth value (key and field names included) in the console database, the console
#     and agent logs, the pages or the agent's state; the analyst's key names nowhere on the console
#     side (positive control: they are in the server's own slow log); no generated secret in any
#     container log.
# See e2e/README.md "Redis and Valkey targets". Requires: docker (compose v2.24+), openssl, curl,
# jq, python3.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit; the logs are redacted in place before they can be uploaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
export E2E_VALKEY_PORT="${E2E_VALKEY_PORT:-16379}"
export E2E_REDIS_PORT="${E2E_REDIS_PORT:-16389}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs-redis}"
PROJECT="databastion-e2e-redis"
LOG_TAG="e2e-redis"  # read by lib.sh
I2_CHECK="$HERE/i2_check.py"
SCENARIO="$HERE/redis_scenario.py"
GROUND_TRUTH="$HERE/../dev/ground-truth.json"
POLICY_DUMP="e2e redis export"
POLICY_READS="e2e redis reads"
DUMP_INCIDENT_LIMIT_S=120
SCAN_TIMEOUT_S=600
EVENTS_TIMEOUT_S=240
# target id, engine (ground truth and agent.yaml), compose service, host port, network alias, CLI
TARGETS=("valkey-e2e valkey target-valkey ${E2E_VALKEY_PORT} valkey valkey-cli"
  "redis-e2e redis target-redis ${E2E_REDIS_PORT} redis redis-cli")

# The images are the dev services' (dev/docker-compose.yml): the same pins.
for name in VALKEY REDIS; do
  dev_img="$(sed -n "s/.*DATABASTION_DEV_${name}_IMAGE:-\\([^}]*\\)}.*/\\1/p" "$HERE/../dev/docker-compose.yml")"
  e2e_img="$(sed -n "s/.*E2E_${name}_IMAGE:-\\([^}]*\\)}.*/\\1/p" "$HERE/docker-compose.redis.yml")"
  if [ -z "$dev_img" ] || [ "$dev_img" != "$e2e_img" ]; then
    echo "the ${name} image of docker-compose.redis.yml must be the one of dev/docker-compose.yml" >&2
    exit 1
  fi
done
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  unset E2E_CONSOLE_IMAGE E2E_AGENT_IMAGE E2E_VALKEY_IMAGE E2E_REDIS_IMAGE
fi

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e-redis.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"
COMPOSE_ARGS=(-p "$PROJECT" -f "$HERE/docker-compose.yml" -f "$HERE/docker-compose.redis.yml")
# shellcheck source=lib.sh
. "$HERE/lib.sh"
SERVICES=(db migrate web worker proxy redis-tls-init target-valkey target-redis agent)

cleanup() {
  local status=$?
  set +e
  phase_done exit
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs "${SERVICES[@]}"
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  redact_dir "$E2E_LOG_DIR" "$P"
  log "tearing down"
  timeout 180 docker compose "${COMPOSE_ARGS[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$E2E_WORK_DIR"
  phase_done teardown
  log "timings: ${TIMINGS}total $(( $(date +%s) - T_RUN ))s"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# I2 scanner positive control: every searchable value of both engines is in the committed keyspace.
for e in valkey redis; do
  timeout 60 python3 "$I2_CHECK" coverage --ground-truth "$GROUND_TRUTH" --engine "$e" \
    "$HERE/../dev/seed/out/redis.txt" >&2 || fail "I2 scanner positive control failed for $e (see above)"
done

# --------------------------------------------------------------------------- secrets, CA, ACL, agent.yaml
console_secrets
put_secret target_agent_password "$(rand_hex 24)"         # ACL user databastion (both servers)
put_secret target_redis_admin_password "$(rand_hex 24)"   # ACL user admin: stays in the targets
put_secret target_client_password "$(rand_hex 24)"        # e2e_exporter, e2e_analyst
test_ca "e2e Redis"
: >"$T/redis-ca.pem"   # the targets' dev CA, copied out once they started
# The test clients' ACL users (dev/redis/entrypoint.sh appends the file): the exporter reads
# everything and may run a full synchronization; the analyst reads.
mkdir -p "$E2E_WORK_DIR/redis"
client_sha="$(printf '%s' "$(cat "$S/target_client_password")" | sha256sum | cut -d' ' -f1)"
umask 022
{
  echo "user e2e_exporter on #${client_sha} ~* resetchannels -@all +@read +select +sync +psync +replconf +ping"
  echo "user e2e_analyst on #${client_sha} ~* resetchannels -@all +@read +select +ping"
} >"$E2E_WORK_DIR/redis/clients.acl"
umask 077
unset client_sha

{
  cat <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  statement_timeout_ms: 5000
  max_scan_duration_s: 900
targets:
EOF
  for spec in "${TARGETS[@]}"; do
    read -r id engine _ _ alias _ <<<"$spec"
    cat <<EOF
  - id: ${id}
    engine: ${engine}
    host: ${alias}
    port: 6379
    account: databastion
    secret:
      file: /run/databastion-secrets/target_agent_password
    redis:
      tls: verify_full
      ca_file: /etc/databastion/redis-ca.pem
EOF
  done
} >"$E2E_WORK_DIR/agent/agent.yaml"
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# admin_cli SERVICE CLI ARGS...: as `admin` on the server's Unix socket inside the target (dev
# tooling, never the agent); the password through the client's environment, read in the container.
admin_cli() {
  local svc="$1" cli="$2"
  shift 2
  # shellcheck disable=SC2016 # expanded by the container shell, on purpose
  timeout 60 docker compose "${COMPOSE_ARGS[@]}" exec -T "$svc" bash -c \
    'REDISCLI_AUTH="$(cat /run/secrets/target_redis_admin_password)" exec "$0" -s /tmp/databastion-dev.sock --user admin --no-auth-warning "$@"' \
    "$cli" "$@"
}
# client SUBCOMMAND PORT USER ARGS...: e2e/redis_scenario.py from the host (the published TLS port).
client() {
  local sub="$1" port="$2" user="$3"
  shift 3
  timeout 300 python3 "$SCENARIO" "$sub" --port "$port" --ca "$T/redis-ca.pem" --user "$user" \
    --password-file "$S/target_client_password" "$@"
}

# --------------------------------------------------------------------------- build + start
IMAGES=("${E2E_CONSOLE_IMAGE:-databastion-console:e2e}" "${E2E_AGENT_IMAGE:-databastion-agent:e2e}")
if [ "${E2E_SKIP_BUILD:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-}" != true ]; then
  log "E2E_SKIP_BUILD=1: using the existing images ${IMAGES[*]}"
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "E2E_SKIP_BUILD=1 but image $img is missing"
  done
else
  log "building images (web, agent)"
  timeout 1800 docker compose "${COMPOSE_ARGS[@]}" build web agent
fi
phase_done build

log "starting the console, Valkey and Redis"
timeout 600 docker compose "${COMPOSE_ARGS[@]}" up -d db web worker proxy target-valkey target-redis
start_console
for spec in "${TARGETS[@]}"; do
  read -r _ _ svc _ _ cli <<<"$spec"
  deadline=$(( $(date +%s) + 180 ))
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$svc")" 2>/dev/null)" = healthy ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$svc not healthy within 180 s"
    sleep 2
  done
  docker inspect "$(compose ps -q "$svc")" --format '{{json .Config.Env}}' \
    | jq -e 'any(test("PASSWORD")) | not' >/dev/null || fail "a password in $svc's environment"
  log "$svc: $(admin_cli "$svc" "$cli" INFO server | tr -d '\r' | grep -E '^(redis_version|valkey_version|server_name):' | tr '\n' ' ')"
done
compose exec -T target-valkey cat /tls/ca.pem >"$T/redis-ca.pem" || fail "cannot copy the dev CA of the targets"
grep -q 'BEGIN CERTIFICATE' "$T/redis-ca.pem" || fail "no dev CA in target-valkey"
chmod 0644 "$T/redis-ca.pem"
phase_done start

# The agent's ACL user (ADR-0052 decision 4): `default` off; no write, admin or dangerous command;
# the exact read allow-list (ACL DRYRUN as admin: the agent's own check() proves it the same way).
log "checking the agent's ACL user (ADR-0052 decision 4: read-only allow-list, I4)"
for spec in "${TARGETS[@]}"; do
  read -r _ _ svc _ _ cli <<<"$spec"
  [ "$(admin_cli "$svc" "$cli" ACL GETUSER default | tr -d '\r' | sed -n '/^flags$/{n;p}' | grep -c '^off$')" = 1 ] \
    || fail "$svc: the default user is not off"
  for cmd in "set x 1" "del x" "config get maxmemory" "flushall" "keys *" "monitor" "debug sleep 0" "eval return 0 0" "acl list"; do
    # shellcheck disable=SC2086 # the command's words
    out="$(admin_cli "$svc" "$cli" ACL DRYRUN databastion $cmd | tr -d '\r')"
    [ "$out" != OK ] || fail "$svc: the agent's user may run '${cmd%% *}'"
  done
  for cmd in "scan 0" "type x" "getrange x 0 1" "slowlog get 1" "info stats" "client list"; do
    # shellcheck disable=SC2086 # the command's words
    out="$(admin_cli "$svc" "$cli" ACL DRYRUN databastion $cmd | tr -d '\r')"
    [ "$out" = OK ] || fail "$svc: the agent's user may not run '${cmd%% *}' (${out%% *})"
  done
done

# --------------------------------------------------------------------------- enroll + run
log "bootstrapping the administrator; enrolling the agent"
admin_login e2e-redis
enroll_agent target_agent_password
log "enrolled agent $AGENT_ID; starting it"
timeout 60 docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps agent
# The console lists engine.redis and engine.valkey (capabilities.ts): the agent reports both.
wait_online 120 "valkey-e2e:valkey" "redis-e2e:redis"
for spec in "${TARGETS[@]}"; do
  read -r id engine _ <<<"$spec"
  t="$(target_json "$id")"
  log "target ${id}: $(target_summary "$t")"
  notes="$(notes_of "$t")"
  for c in check.server_is_valkey check.server_is_redis privilege.refused privilege.over_privileged; do
    [[ " $notes " != *" $c "* ]] || fail "${id}: the heartbeat reports $c"
  done
  jq -e '.auditLevel == "none"' <<<"$t" >/dev/null || fail "${id}: audit level $(jq -r .auditLevel <<<"$t") before Audit, expected none"
done
AGENT_IP="$(docker inspect "$(compose ps -q agent)" --format '{{json .NetworkSettings.Networks}}' \
  | jq -r --arg n "${PROJECT}_agent-net" '.[$n].IPAddress')"
[[ "$AGENT_IP" =~ ^[0-9.]+$ ]] || fail "no address of the agent on agent-net"
phase_done enroll

# --------------------------------------------------------------------------- Discovery
# A first scan before Audit: the stream names objects by the patterns a completed scan learned
# (without one, every object is `*`, docs/08-engine-capabilities.md "Redis / Valkey Audit").
log "Discovery: valkey-e2e and redis-e2e (before Audit)"
scan_targets "$SCAN_TIMEOUT_S" valkey-e2e redis-e2e
for spec in "${TARGETS[@]}"; do
  read -r id engine _ <<<"$spec"
  findings_json "$id" >"$E2E_WORK_DIR/findings.json" || fail "cannot read the findings of $id"
  timeout 60 python3 "$I2_CHECK" findings --ground-truth "$GROUND_TRUTH" --engine "$engine" \
    --require-expected-classifiers --forbid-negative-controls "$E2E_WORK_DIR/findings.json" >&2 \
    || fail "findings check of ${id} failed (see above)"
  log "${id}: $(jq length "$E2E_WORK_DIR/findings.json") finding(s)"
done
rm -f -- "$E2E_WORK_DIR/findings.json"
phase_done discovery

# --------------------------------------------------------------------------- Audit setup
TARGET_IDS="$(printf '%s\n' "${TARGETS[@]}" | awk '{print $1}' | jq -Rsc 'split("\n") | map(select(length > 0))')"
log "Audit: policies '${POLICY_DUMP}' (shape.keyspace_enumeration, signature.full_sync) and '${POLICY_READS}' (read)"
create_policy "$POLICY_DUMP" critical "$(jq -nc --argjson t "$TARGET_IDS" '{signals: ["shape.keyspace_enumeration", "signature.full_sync"], target_ids: $t}')"
create_policy "$POLICY_READS" medium "$(jq -nc --argjson t "$TARGET_IDS" '{event_actions: ["read"], target_ids: $t}')"
for spec in "${TARGETS[@]}"; do
  read -r id _ <<<"$spec"
  log "Audit: enabling Audit on ${id}"
  enable_audit "$id"
done
T_AUDIT="$(date +%s)"
phase_done audit-setup

# A second scan with the Audit streams running: its own commands are in the slow logs and must not
# come back as events. E2E_REDIS_SCAN_UNDER_AUDIT=0 skips it (the check below then covers check()
# and the stream's own polls only).
if [ "${E2E_REDIS_SCAN_UNDER_AUDIT:-1}" = 1 ]; then
  log "Discovery: valkey-e2e and redis-e2e again (Audit on)"
  scan_targets "$SCAN_TIMEOUT_S" valkey-e2e redis-e2e
  phase_done discovery-audit-on
else
  log "E2E_REDIS_SCAN_UNDER_AUDIT=0: no Discovery scan while the Audit streams run"
fi

# The agent's own commands are never reported: after the scans and two poll intervals, no event at
# all (nobody else used the servers since the streams started).
sleep 25
own_failed=""
for spec in "${TARGETS[@]}"; do
  read -r id _ <<<"$spec"
  n="$(console_sql "SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${id}'")"
  if [ "$n" != 0 ]; then
    # Diagnostic without any value: principal kind, action, source, address, the object patterns
    # (learned patterns or `*`), signals, count; and the command names of the agent's slow-log
    # entries (never their arguments).
    console_sql "SELECT string_agg(coalesce(db_user, CASE WHEN account_not_recorded THEN 'not_recorded' ELSE 'fp' END)
        || ' ' || action || ' ' || source || ' ' || coalesce(client_addr, '-') || ' objects ' || objects::text
        || ' signals ' || signals::text || ' count ' || aggregated_count, '; ')
      FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '${id}'" >&2 || true
    read -r _ _ svc _ _ cli <<<"$spec"
    admin_cli "$svc" "$cli" --json SLOWLOG GET 1024 2>/dev/null | jq -r --arg ip "$AGENT_IP" \
      '.[] | select((.[4] // "") | startswith($ip + ":")) | (.[3][0] | ascii_upcase) + (if (.[3][0] | ascii_downcase) == "client" or (.[3][0] | ascii_downcase) == "slowlog" or (.[3][0] | ascii_downcase) == "acl" or (.[3][0] | ascii_downcase) == "commandlog" then " " + (.[3][1] // "") else "" end)' \
      | sort | uniq -c | sort -rn >&2 || true
    log "${id}: $n event(s) before any client command: the agent's own activity surfaced"
    own_failed+=" $id"
  fi
done
[ -z "$own_failed" ] || fail "the agent's own commands were reported on:${own_failed}"
log "Audit: no event before the first client command (check(), Discovery and the polls left out)"

# --------------------------------------------------------------------------- client traffic
# The analyst's keys: names that embed ground-truth values (an e-mail, a phone number), taken from
# the ground truth (needle ids of the name values) and checked against the committed keyspace.
python3 - "$GROUND_TRUTH" "$HERE/../dev/seed/out/redis.txt" "$E2E_WORK_DIR/analyst.keys" "$E2E_WORK_DIR/analyst.ids" <<'PY'
import json, sys
gt, seed, keys_out, ids_out = sys.argv[1:5]
g = json.load(open(gt, encoding="utf-8"))
text = open(seed, encoding="utf-8").read()
picks = []
for i, loc in enumerate(g["locations"]):
    if loc.get("engine") != "valkey" or not loc.get("name_contains_value"):
        continue
    if loc["object"] == "user:*:profile" and loc["field"] == "#key":
        for j in (0, 1):
            picks.append(("0", "hash", f"user:{loc['name_values'][j]}:profile", f"L{i}.n{j}"))
    elif loc["object"] == "phone:*":
        picks.append(("0", "string", f"phone:{loc['name_values'][0]}", f"L{i}.n0"))
if len(picks) != 3 or any(f'"{k}"' not in text for _, _, k, _ in picks):
    sys.exit("analyst keys: not found in the ground truth / keyspace")
with open(keys_out, "w", encoding="utf-8") as f:
    f.writelines(f"{db}\t{t}\t{k}\n" for db, t, k, _ in picks)
with open(ids_out, "w", encoding="utf-8") as f:
    f.write(" ".join(n for *_, n in picks))
PY
ANALYST_IDS="$(cat "$E2E_WORK_DIR/analyst.ids")"
# The redis engine's needle ids differ (other location indexes): mapped by location key.
declare -A ENGINE_IDS=()
for e in valkey redis; do
  ENGINE_IDS[$e]="$(python3 - "$GROUND_TRUTH" "$e" "$ANALYST_IDS" <<'PY'
import json, sys
g = json.load(open(sys.argv[1], encoding="utf-8"))
locs = g["locations"]
out = []
for nid in sys.argv[3].split():
    li, nj = nid[1:].split(".")
    src = locs[int(li)]
    for i, loc in enumerate(locs):
        if loc.get("engine") == sys.argv[2] and all(loc.get(k) == src.get(k) for k in ("database", "container", "object", "field")):
            out.append(f"L{i}.{nj}")
            break
print(" ".join(out))
PY
)"
done
T0_MS="$(date +%s%3N)"
for spec in "${TARGETS[@]}"; do
  read -r id engine svc port _ <<<"$spec"
  log "Audit ($id): sweep as e2e_exporter (KEYS * on db0 and db1, every key read), held open past a poll"
  out="$(client sweep "$port" e2e_exporter --db 0 --db 1 --linger 15)" || fail "the sweep of $id failed (see above)"
  log "Audit ($id): sweep $out"
  log "Audit ($id): reads of value-bearing key names as e2e_analyst (${ENGINE_IDS[$engine]})"
  out="$(client queries "$port" e2e_analyst --keys-file "$E2E_WORK_DIR/analyst.keys" --linger 15)" \
    || fail "the analyst's reads on $id failed (see above)"
  log "Audit ($id): queries $out"
  sync_before="$(admin_cli "$svc" "$(awk '{print $6}' <<<"$spec")" INFO stats | tr -d '\r' | sed -n 's/^sync_full://p')"
  out="$(client sync "$port" e2e_exporter --settle 0)" || fail "the full synchronization of $id failed (see above)"
  sync_after="$(admin_cli "$svc" "$(awk '{print $6}' <<<"$spec")" INFO stats | tr -d '\r' | sed -n 's/^sync_full://p')"
  log "Audit ($id): SYNC $out; INFO sync_full ${sync_before} -> ${sync_after}"
  [ "$sync_after" -gt "$sync_before" ] || fail "$id: SYNC did not increase sync_full"
done
rm -f -- "$E2E_WORK_DIR/analyst.keys"
phase_done traffic

# --------------------------------------------------------------------------- Audit checks
events_state() {
  console_sql "SELECT concat_ws(',',
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'
       AND db_user = 'e2e_exporter' AND signals ? 'shape.keyspace_enumeration'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'
       AND account_not_recorded AND signals ? 'signature.full_sync'),
    (SELECT coalesce(sum(aggregated_count), 0) FROM access_events WHERE agent_id = '${AGENT_ID}'
       AND target_id = '$1' AND db_user = 'e2e_analyst' AND action = 'read'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'
       AND policy_name = '${POLICY_DUMP}' AND principal = 'e2e_exporter'),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'
       AND policy_name = '${POLICY_DUMP}' AND coalesce(principal, '') = ''),
    (SELECT count(*) FROM incidents WHERE agent_id = '${AGENT_ID}' AND target_id = '$1'
       AND policy_name = '${POLICY_READS}' AND principal = 'e2e_analyst'),
    (SELECT count(*) FROM access_events WHERE agent_id = '${AGENT_ID}' AND evaluated_at IS NULL))"
}
for spec in "${TARGETS[@]}"; do
  read -r id engine svc _ _ cli <<<"$spec"
  log "Audit ($id): waiting for the events and incidents (at most ${EVENTS_TIMEOUT_S} s)"
  deadline=$(( $(date +%s) + EVENTS_TIMEOUT_S ))
  while :; do
    st="$(events_state "$id")" || fail "cannot read the Audit state of $id"
    IFS=, read -r n_enum n_sync n_reads n_inc_dump n_inc_sync n_inc_reads n_pending <<<"$st"
    if [ "$n_enum" -ge 1 ] && [ "$n_sync" -ge 1 ] && [ "$n_reads" -ge 3 ] && [ "$n_inc_dump" -ge 1 ] \
        && [ "$n_inc_sync" -ge 1 ] && [ "$n_inc_reads" -ge 1 ] && [ "$n_pending" = 0 ]; then break; fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "Audit ($id): incomplete within ${EVENTS_TIMEOUT_S} s: enumeration ${n_enum}, full_sync ${n_sync}, analyst reads ${n_reads}/3, incidents export ${n_inc_dump} sync ${n_inc_sync} reads ${n_inc_reads}, not evaluated ${n_pending}"
    sleep 3
  done
  if [ "$id" = valkey-e2e ]; then
    DUMP_LATENCY_MS=$(( $(date +%s%3N) - T0_MS ))
    log "Audit: first sweep start -> every incident of valkey-e2e: ${DUMP_LATENCY_MS} ms (limit ${DUMP_INCIDENT_LIMIT_S} s)"
    [ "$DUMP_LATENCY_MS" -lt $(( DUMP_INCIDENT_LIMIT_S * 1000 )) ] || fail "Audit: the incidents took ${DUMP_LATENCY_MS} ms"
  fi
  log "Audit ($id): enumeration events ${n_enum}, full_sync events ${n_sync}, analyst reads ${n_reads}"
  # The level once another client's entry was read: Limited, from the slow log, never above.
  wait_target_state "$id" 120 '.auditLevel == "limited" and .auditSource == "redis_slowlog"
      and ([.notes[]?.code] | index("audit.slow_operations_only"))' "audit level limited (redis_slowlog)"
  t="$TARGET_STATE"
  log "${id}: audit level limited (redis_slowlog); notes: $(notes_of "$t")"
  # The analyst's objects: learned patterns or `*`, never the raw key names (i2_check.py audit
  # below). The dev keyspace holds keys in db0 and db1, and slow-log entries carry no database, so
  # the stream cannot pick a database's patterns: every object is `*` here (docs/08, "Redis / Valkey
  # Audit", What is kept).
  objs="$(console_sql "SELECT string_agg(DISTINCT coalesce(o->>'database', '-') || '/' || (o->>'object'), ' ')
    FROM access_events e, jsonb_array_elements(e.objects) o
    WHERE e.agent_id = '${AGENT_ID}' AND e.target_id = '${id}' AND e.db_user = 'e2e_analyst'")"
  log "Audit ($id): the analyst's event objects: $objs"
  events_json "$id" >"$E2E_WORK_DIR/events.json" || fail "cannot read the access events of $id"
  incidents_json "$id" >"$E2E_WORK_DIR/incidents.json" || fail "cannot read the incidents of $id"
  log "Audit ($id): sources $(jq -c '[.[].source] | unique' "$E2E_WORK_DIR/events.json"), signals $(jq -c '[.[].signals[]?] | unique' "$E2E_WORK_DIR/events.json")"
  timeout 60 python3 "$I2_CHECK" audit --ground-truth "$GROUND_TRUTH" --engine "$engine" --agent-account databastion \
    --events "$E2E_WORK_DIR/events.json" --incidents "$E2E_WORK_DIR/incidents.json" \
    --require-event "e2e_exporter:shape.keyspace_enumeration" --require-event "@not_recorded:signature.full_sync" \
    --require-event e2e_analyst --require-incident "${POLICY_DUMP}:e2e_exporter" \
    --require-incident "${POLICY_DUMP}:@not_recorded" --require-incident "${POLICY_READS}:e2e_analyst" >&2 \
    || fail "Audit check of ${id} failed (see above)"
  # No event names the agent's address (its own entries are left out, whatever their principal).
  n="$(jq --arg ip "$AGENT_IP" '[.[] | select((.client_addr // "") | startswith($ip))] | length' "$E2E_WORK_DIR/events.json")"
  [ "$n" = 0 ] || fail "Audit ($id): $n event(s) from the agent's own address"
  rm -f -- "$E2E_WORK_DIR/events.json" "$E2E_WORK_DIR/incidents.json"

  # The source side: the server's slow log holds the analyst's key names (positive control of the
  # needle scans below) and the agent's own commands (seen and left out, not missed).
  admin_cli "$svc" "$cli" SLOWLOG GET 1024 >"$E2E_WORK_DIR/slowlog.txt" || fail "cannot read the slow log of $id"
  needles=()
  for nid in ${ENGINE_IDS[$engine]}; do needles+=(--needle "$nid"); done
  rc=0
  timeout 120 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$engine" \
    --label "$id slow log (positive control)" "${needles[@]}" "$E2E_WORK_DIR/slowlog.txt" \
    >"$E2E_WORK_DIR/literal-control.out" 2>&1 || rc=$?
  for nid in ${ENGINE_IDS[$engine]}; do
    if [ "$rc" != 1 ] || ! grep -q "^LEAK ${nid//./\\.} " "$E2E_WORK_DIR/literal-control.out"; then
      fail "Audit ($id): key name $nid not in the server's slow log (positive control)"
    fi
  done
  n_own="$(grep -cF "${AGENT_IP}:" "$E2E_WORK_DIR/slowlog.txt" || true)"
  [ "$n_own" -ge 1 ] || fail "Audit ($id): no entry of the agent's address in the slow log (positive control of 'no own event')"
  log "Audit ($id): the slow log holds the analyst's key names and ${n_own} line(s) of the agent's own entries (left out)"
  rm -f -- "$E2E_WORK_DIR/slowlog.txt" "$E2E_WORK_DIR/literal-control.out"
done
phase_done audit

# --------------------------------------------------------------------------- I2 and secret hygiene
log "I2: the console database, the logs, the pages and the agent's state"
dump_logs "${SERVICES[@]}"
for f in agent.log web.log worker.log; do
  [ -s "$E2E_LOG_DIR/$f" ] || fail "$f is empty: the scans would prove nothing"
done
D="$E2E_WORK_DIR/dump"
collect_console_side "$D" valkey-e2e redis-e2e
grep -qF 'e2e_exporter' "$D/pages/incidents.html" || fail "the incidents page does not list e2e_exporter (page scan control)"
grep -qF 'valkey-e2e' "$D/pages/findings.html" || fail "the findings page does not name valkey-e2e (page scan control)"
i2_failed=0
for e in valkey redis; do
  i2_canary "$e"
  timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$e" --label "$e console side" \
    "$D" >&2 || i2_failed=1
  timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$e" --label "$e logs" \
    --exclude 'target-valkey.log' --exclude 'target-redis.log' "$E2E_LOG_DIR" >&2 || i2_failed=1
  needles=()
  for nid in ${ENGINE_IDS[$e]}; do needles+=(--needle "$nid"); done
  timeout 300 python3 "$I2_CHECK" scan --ground-truth "$GROUND_TRUTH" --engine "$e" --label "$e analyst key names" \
    "${needles[@]}" --exclude 'target-valkey.log' --exclude 'target-redis.log' "$D" "$E2E_LOG_DIR" >&2 || i2_failed=1
done
pattern_canary
leaks=0
secret_hygiene "$D" 'target-valkey.log' 'target-redis.log' || leaks=1
log "I2: $(find "$P" -type f | wc -l) secret(s) searched"
rm -rf -- "$D"
[ "$i2_failed" = 0 ] || fail "invariant I2: ground-truth value(s) or key name(s) of the Redis / Valkey targets in clear text (ids above)"
[ "$leaks" = 0 ] || fail "a secret reached the console, a log or the agent's state (names above)"
phase_done i2
log "all checks passed (sweep -> incidents ${DUMP_LATENCY_MS} ms; Audit on since $(( $(date +%s) - T_AUDIT )) s)"
