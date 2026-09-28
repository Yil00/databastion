#!/usr/bin/env bash
# End-to-end enrollment / revocation test (phase 1 exit criterion):
#   "end-to-end enrollment in containers; revocation effective in < 60 s".
# See e2e/README.md. Requires: docker (compose v2), openssl, curl, jq.
#
# Every secret is generated here at run time (never committed), kept under a private temporary
# directory and removed on exit. Logs of every container are written to $E2E_LOG_DIR and
# checked for secrets before teardown.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-8443}"
E2E_LOG_DIR="${E2E_LOG_DIR:-$HERE/.logs}"
REVOCATION_LIMIT_MS=60000
HOSTNAME_CONSOLE="console.e2e.internal"
BASE_URL="https://${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}"
AGENT_401_MESSAGE="console rejected the current secret (401)"

log() { printf '[e2e %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }

for tool in docker openssl curl jq timeout; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

umask 077
E2E_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/databastion-e2e.XXXXXX")"
export E2E_WORK_DIR
mkdir -p "$E2E_LOG_DIR"

# Every docker call is bounded (`timeout`): a hung daemon cannot stall the job.
compose() { timeout 120 docker compose -f "$HERE/docker-compose.yml" "$@"; }

dump_logs() {
  local svc
  compose logs --no-color --timestamps >"$E2E_LOG_DIR/all.log" 2>&1 || true
  for svc in db migrate web worker proxy target-pg agent; do
    compose logs --no-color --timestamps "$svc" >"$E2E_LOG_DIR/$svc.log" 2>&1 || true
  done
}

cleanup() {
  local status=$?
  set +e
  log "collecting logs into $E2E_LOG_DIR"
  dump_logs
  compose ps -a >"$E2E_LOG_DIR/ps.txt" 2>&1
  log "tearing down"
  timeout 120 docker compose -f "$HERE/docker-compose.yml" --profile tools down -v --remove-orphans \
    >/dev/null 2>&1
  rm -rf "$E2E_WORK_DIR"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --------------------------------------------------------------------------- secrets
rand_hex() { openssl rand -hex "$1"; }
mkdir -p "$E2E_WORK_DIR/secrets" "$E2E_WORK_DIR/tls" "$E2E_WORK_DIR/agent"
S="$E2E_WORK_DIR/secrets"
# Secret files are bind-mounted into containers running as other uids (postgres, 10001): they
# are 0644 inside a 0700 directory, so only this user (and the containers) can reach them.
put_secret() { umask 022; printf '%s' "$2" >"$S/$1"; umask 077; }
DB_PASSWORD="$(rand_hex 24)"
DB_OWNER_PASSWORD="$(rand_hex 24)"
DB_APP_PASSWORD="$(rand_hex 24)"
ENCRYPTION_KEY="$(openssl rand -base64 32)"
METRICS_TOKEN="$(rand_hex 32)"
ADMIN_PASSWORD="$(rand_hex 24)"
TARGET_PG_PASSWORD="$(rand_hex 24)"
put_secret db_password "$DB_PASSWORD"
put_secret db_owner_password "$DB_OWNER_PASSWORD"
put_secret db_app_password "$DB_APP_PASSWORD"
put_secret db_owner_url "postgresql://databastion_owner:${DB_OWNER_PASSWORD}@db:5432/databastion"
put_secret db_url "postgresql://databastion_runtime:${DB_APP_PASSWORD}@db:5432/databastion"
put_secret encryption_key "$ENCRYPTION_KEY"
put_secret metrics_token "$METRICS_TOKEN"
put_secret admin_password "$ADMIN_PASSWORD"
put_secret target_pg_password "$TARGET_PG_PASSWORD"
chmod 0700 "$S"

# --------------------------------------------------------------------------- test CA
log "generating the throwaway test CA and the proxy certificate"
T="$E2E_WORK_DIR/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=DataBastion e2e test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$T/ca.key" -out "$T/ca.crt" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=${HOSTNAME_CONSOLE}" -keyout "$T/server.key" -out "$T/server.csr" 2>/dev/null
cat >"$T/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${HOSTNAME_CONSOLE}
EOF
openssl x509 -req -in "$T/server.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$T/server.ext" -out "$T/server.crt" 2>/dev/null
rm -f "$T/ca.key" "$T/server.csr" "$T/server.ext" "$T/ca.srl"
# Readable by the proxy (uid 10001) and the agent through the bind mounts; $T itself is 0700.
chmod 0644 "$T/ca.crt" "$T/server.crt" "$T/server.key"

# --------------------------------------------------------------------------- agent.yaml
cat >"$E2E_WORK_DIR/agent/agent.yaml" <<EOF
console:
  url: ${BASE_URL}
  ca_file: /etc/databastion/console-ca.pem
  long_poll_wait_s: 25
state_dir: /var/lib/databastion
limits:
  max_sample_rows: 100
  statement_timeout_ms: 5000
  max_scan_duration_s: 300
targets:
  - id: pg-e2e
    engine: postgres
    host: target-pg
    port: 5432
    account: postgres
    secret:
      file: /run/databastion-secrets/target_pg_password
EOF
chmod 0644 "$E2E_WORK_DIR/agent/agent.yaml"

# --------------------------------------------------------------------------- HTTP helpers
CURL=(curl -sS --max-time 40 --cacert "$T/ca.crt"
  --resolve "${HOSTNAME_CONSOLE}:${E2E_HTTPS_PORT}:127.0.0.1"
  -b "$E2E_WORK_DIR/cookies" -c "$E2E_WORK_DIR/cookies")
CSRF=""
# api METHOD PATH [BODY_FILE] -> prints "<status>\n<body>" ; body never logged.
api() {
  local method="$1" path="$2" body="${3:-}" out="$E2E_WORK_DIR/resp"
  local args=(-X "$method" -o "$out" -w '%{http_code}' -H "Origin: ${BASE_URL}")
  [ -n "$CSRF" ] && args+=(-H "X-CSRF-Token: ${CSRF}")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  local code
  code="$("${CURL[@]}" "${args[@]}" "${BASE_URL}${path}")" || code="000"
  printf '%s\n' "$code"
  cat "$out" 2>/dev/null || true
}
status_of() { head -n1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }

# --------------------------------------------------------------------------- build + start
log "building images (console, agent)"
timeout 1500 docker compose -f "$HERE/docker-compose.yml" build

log "starting console DB, migrate, web, worker, TLS proxy and the target PostgreSQL"
# No `--wait`: it treats the exited one-shot `migrate` as a failure on some Compose versions.
# `up` itself blocks on the depends_on conditions (db healthy, migrate done, web healthy).
timeout 400 docker compose -f "$HERE/docker-compose.yml" up -d db web worker proxy target-pg

log "waiting for console readiness through the TLS proxy"
deadline=$(( $(date +%s) + 120 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "console not ready through the proxy within 120 s"
  sleep 1
done

[ "$(compose ps -a --format '{{.ExitCode}}' migrate)" = "0" ] || fail "migrate did not succeed"

# --------------------------------------------------------------------------- admin + token
log "bootstrapping the administrator"
timeout 120 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T \
  bootstrap-admin >"$E2E_LOG_DIR/bootstrap-admin.log" 2>&1 || fail "bootstrap-admin failed"

log "logging in through the user API"
jq -n --rawfile p "$S/admin_password" '{username: "e2e-admin", password: $p}' \
  >"$E2E_WORK_DIR/login.json"
r="$(api POST /api/auth/login "$E2E_WORK_DIR/login.json")"
rm -f "$E2E_WORK_DIR/login.json"
[ "$(status_of "$r")" = 200 ] || fail "login: HTTP $(status_of "$r")"
CSRF="$(body_of "$r" | jq -r '.csrf_token')"
[ -n "$CSRF" ] && [ "$CSRF" != null ] || fail "login: no CSRF token"
SESSION_COOKIE="$(awk '$6 ~ /databastion_session$/ {print $7}' "$E2E_WORK_DIR/cookies")"
[ -n "$SESSION_COOKIE" ] || fail "login: no session cookie"

log "creating an enrollment token"
printf '{"label":"e2e"}' >"$E2E_WORK_DIR/token-req.json"
r="$(api POST /api/enrollment-tokens "$E2E_WORK_DIR/token-req.json")"
[ "$(status_of "$r")" = 201 ] || fail "enrollment token: HTTP $(status_of "$r")"
ENROLLMENT_TOKEN="$(body_of "$r" | jq -r '.token')"
[[ "$ENROLLMENT_TOKEN" == dbe_* ]] || fail "enrollment token: unexpected format"

# --------------------------------------------------------------------------- agent files
files_root() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    agent-files "$1"
}
files_agent() {
  timeout 60 docker compose -f "$HERE/docker-compose.yml" --profile tools run --rm -T --no-deps \
    --user 10001:10001 agent-files "$1"
}

log "creating the agent state volume from the image (checks its owner and mode)"
timeout 60 docker compose -f "$HERE/docker-compose.yml" run --rm -T --no-deps agent --version \
  >"$E2E_LOG_DIR/agent-version.log" 2>&1 || fail "agent --version failed"
state_mode="$(files_root 'stat -c "%u:%g %a" /state')"
[ "$state_mode" = "10001:10001 700" ] || fail "state volume is '$state_mode', expected '10001:10001 700'"
files_root 'chmod 0700 /secrets && chown 10001:10001 /secrets'
printf '%s' "$TARGET_PG_PASSWORD" | files_agent 'umask 077; cat > /secrets/target_pg_password'
printf '%s' "$ENROLLMENT_TOKEN" | files_agent 'umask 077; cat > /secrets/enrollment_token'

# --------------------------------------------------------------------------- enroll + run
log "enrolling the agent (databastion-agent enroll)"
timeout 120 docker compose -f "$HERE/docker-compose.yml" run --rm -T agent \
  enroll --config /etc/databastion/agent.yaml \
  --token-file /run/databastion-secrets/enrollment_token \
  >"$E2E_LOG_DIR/agent-enroll.log" 2>&1 || fail "agent enroll failed (see agent-enroll.log)"
files_agent 'rm -f /secrets/enrollment_token'

identity="$(files_agent 'cat /state/identity.json')"
AGENT_ID="$(jq -r '.agent_id' <<<"$identity")"
AGENT_SECRET="$(jq -r '.agent_secret' <<<"$identity")"
unset identity
[ -n "$AGENT_ID" ] && [ "$AGENT_ID" != null ] || fail "no agent_id in identity.json"
[ -n "$AGENT_SECRET" ] && [ "$AGENT_SECRET" != null ] || fail "no agent_secret in identity.json"
log "enrolled agent $AGENT_ID"

log "starting databastion-agent run"
timeout 60 docker compose -f "$HERE/docker-compose.yml" up -d --no-deps agent

agent_json() {
  local r
  r="$(api GET /api/agents)"
  [ "$(status_of "$r")" = 200 ] || return 1
  body_of "$r" | jq -c --arg id "$AGENT_ID" '.agents[] | select(.id == $id)'
}

log "waiting for the agent to be online with its target reported"
deadline=$(( $(date +%s) + 90 ))
online=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  a="$(agent_json || true)"
  if [ -n "$a" ] && jq -e '.status == "online" and any(.targets[]; .targetId == "pg-e2e" and .engine == "postgres" and .present)' \
      <<<"$a" >/dev/null; then
    online="$a"
    break
  fi
  sleep 2
done
[ -n "$online" ] || fail "agent not online with target pg-e2e within 90 s"
log "agent online; target pg-e2e: $(jq -c '.targets[] | select(.targetId == "pg-e2e") | {reachable, auditLevel, lastError}' <<<"$online")"

log "checking /metrics (scraped inside the console network, not through the proxy)"
metrics="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" exec -T web node -e '
  const t = require("fs").readFileSync("/run/secrets/metrics_token", "utf8").trim();
  fetch("http://127.0.0.1:3000/metrics", { headers: { authorization: "Bearer " + t } })
    .then(async (r) => { if (!r.ok) process.exit(2); process.stdout.write(await r.text()); })
    .catch(() => process.exit(3));')" || fail "/metrics scrape failed"
grep -Eq "^databastion_agent_up\{agent_id=\"${AGENT_ID}\"\} 1\$" <<<"$metrics" \
  || fail "/metrics: databastion_agent_up{agent_id=\"$AGENT_ID\"} 1 not found"
unset metrics
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/metrics")"
[ "$code" = 404 ] || fail "/metrics is reachable through the proxy (HTTP $code)"

# --------------------------------------------------------------------------- revocation
agent_401_count() {
  timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color agent 2>/dev/null \
    | grep -cF "$AGENT_401_MESSAGE" || true
}
before_401="$(agent_401_count)"
log "revoking the agent through the user API"
t0="$(now_ms)"
r="$(api POST "/api/agents/${AGENT_ID}/revoke")"
[ "$(status_of "$r")" = 204 ] || fail "revoke: HTTP $(status_of "$r")"

t_401=""
while [ $(( $(now_ms) - t0 )) -lt "$REVOCATION_LIMIT_MS" ]; do
  if [ "$(agent_401_count)" -gt "$before_401" ]; then t_401="$(now_ms)"; break; fi
  sleep 0.5
done
[ -n "$t_401" ] || fail "the agent did not log a fatal 401 within 60 s of the revocation"
latency=$(( t_401 - t0 ))
log "revocation latency (revoke call -> agent fatal 401): ${latency} ms"
[ "$latency" -lt "$REVOCATION_LIMIT_MS" ] || fail "revocation latency ${latency} ms >= 60 s"
[ "$(agent_json | jq -r '.status')" = revoked ] || fail "console does not show the agent as revoked"

log "checking that the agent stops polling /jobs (10 s window)"
sleep 2
window_start="$(date +%s)"
sleep 10
polls="$(timeout 30 docker compose -f "$HERE/docker-compose.yml" logs --no-color proxy 2>/dev/null \
  | sed -n 's/^[^{]*\({.*\)$/\1/p' \
  | jq -R 'fromjson? // empty' 2>/dev/null \
  | jq -s --argjson from "$window_start" \
      '[.[] | select((.request.uri // "") | startswith("/api/agent/v1/jobs")) | select(.ts >= $from)] | length')"
[ "$polls" = 0 ] || fail "the agent still polled /jobs $polls time(s) after the revocation"

# --------------------------------------------------------------------------- secret hygiene
log "checking that no secret appears in any log (I2 / secret hygiene)"
dump_logs
patterns="$E2E_WORK_DIR/patterns"
{
  printf 'enrollment_token\t%s\n' "$ENROLLMENT_TOKEN"
  printf 'agent_secret\t%s\n' "$AGENT_SECRET"
  printf 'admin_password\t%s\n' "$ADMIN_PASSWORD"
  printf 'metrics_token\t%s\n' "$METRICS_TOKEN"
  printf 'session_cookie\t%s\n' "$SESSION_COOKIE"
  printf 'db_password\t%s\n' "$DB_PASSWORD"
  printf 'db_owner_password\t%s\n' "$DB_OWNER_PASSWORD"
  printf 'db_app_password\t%s\n' "$DB_APP_PASSWORD"
  printf 'encryption_key\t%s\n' "$ENCRYPTION_KEY"
  printf 'target_pg_password\t%s\n' "$TARGET_PG_PASSWORD"
} >"$patterns"
leaks=0
while IFS=$'\t' read -r name value; do
  # Fixed-string search; only the secret's name is ever printed.
  if grep -rqF -- "$value" "$E2E_LOG_DIR"; then
    log "LEAK: $name found in $(grep -rlF -- "$value" "$E2E_LOG_DIR" | xargs -n1 basename | tr '\n' ' ')"
    leaks=$((leaks + 1))
  fi
done <"$patterns"
rm -f "$patterns"
[ "$leaks" -eq 0 ] || fail "$leaks secret(s) found in container logs"

log "all checks passed (revocation latency ${latency} ms)"
