#!/usr/bin/env bash
# "Installation < 15 min" test (ROADMAP phase 7): a fresh install that follows deploy/README.md,
# "Install", step by step, timed from the download of the deployment files to the first heartbeat
# of the enrolled agent. CI: .github/workflows/packaging.yml (job `install-test`).
#
#   CONSOLE_IMAGE=<image ref> AGENT_DEB=<path to .deb> deploy/install-test.sh
#
# Run on a throwaway Linux host with systemd, Docker Engine + Compose v2, sudo, curl, jq, openssl
# and git (a GitHub-hosted ubuntu-24.04 runner): it edits /etc/hosts, installs the .deb on the host
# and starts the service. Ports 80 and 443 must be free.
#
# Where the test cannot do literally what a person does, it does the closest scripted equivalent:
# - "Download the deployment files": databastion-deploy-<version>.tar.gz is made here from this
#   checkout exactly as publish.yml makes the release asset (`git archive` of deploy/, gzip -n), and
#   checked against a SHA256SUMS computed here (the release's is signed; its cosign check is not
#   run: pull-request artifacts are unsigned);
# - DNS: an /etc/hosts entry for the console name (done before the clock starts);
# - the console UI steps (log in, create an enrollment token, see the agent online): the same user
#   API calls the UI makes (session cookie + X-CSRF-Token);
# - images: CONSOLE_IMAGE is either the published image (pulled by `docker compose up`, inside the
#   timed window) or, on pull requests, the image built from the checkout (built before the clock
#   starts: not timed, a pull of the published image is).
# Everything else is the documented command, as written in deploy/README.md.
#
# Environment: CONSOLE_IMAGE, AGENT_DEB (required); INSTALL_LIMIT_S (default 900);
# INSTALL_DOMAIN (default console.databastion.test); INSTALL_KEEP=1 keeps the install afterwards.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
: "${CONSOLE_IMAGE:?set CONSOLE_IMAGE}"
: "${AGENT_DEB:?set AGENT_DEB}"
LIMIT_S="${INSTALL_LIMIT_S:-900}"
DOMAIN="${INSTALL_DOMAIN:-console.databastion.test}"
BASE_URL="https://${DOMAIN}"
AGENT_DEB="$(cd "$(dirname "$AGENT_DEB")" && pwd)/$(basename "$AGENT_DEB")"

log() { printf '[install %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
mask() { if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$1"; fi; }

WORK="$(mktemp -d)"
chmod 0700 "$WORK"
DIR="$WORK/databastion"   # the administrator's deployment directory
TIMINGS=""
T_START=0
T_PHASE=0
phase_done() {
  local now
  now="$(date +%s)"
  TIMINGS+="$1 $((now - T_PHASE))s; "
  T_PHASE="$now"
}

cleanup() {
  local rc=$?
  set +e
  if [ -f "$DIR/compose.yaml" ]; then
    if [ "$rc" != 0 ]; then
      (cd "$DIR" && timeout 60 docker compose --profile proxy ps -a && \
        timeout 60 docker compose --profile proxy logs --no-color --tail=100) >&2
      sudo journalctl -u databastion-agent --no-pager -n 100 >&2
    fi
    if [ "${INSTALL_KEEP:-0}" != 1 ]; then
      (cd "$DIR" && timeout 120 docker compose --profile proxy --profile tools down -v --remove-orphans) \
        >/dev/null 2>&1
    fi
  fi
  if [ "${INSTALL_KEEP:-0}" != 1 ]; then
    sudo systemctl disable --now databastion-agent >/dev/null 2>&1
    sudo dpkg -P databastion-agent >/dev/null 2>&1
    rm -rf "$WORK"
  fi
  exit "$rc"
}
trap cleanup EXIT

# --------------------------------------------------------------------------- before the clock
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || fail "systemd is not running here"
docker compose version >/dev/null || fail "docker compose v2 is required"
[ -f "$AGENT_DEB" ] || fail "no such .deb: $AGENT_DEB"
if ! getent hosts "$DOMAIN" >/dev/null; then
  log "DNS stand-in: $DOMAIN -> 127.0.0.1 in /etc/hosts"
  echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts >/dev/null
fi

log "clock starts (limit ${LIMIT_S} s)"
T_START="$(date +%s)"
T_PHASE="$T_START"

# --------------------------------------------------------------------------- 1. console files
# README "1. Console": download the deployment bundle, check it, unpack it.
VERSION="test"
mkdir -p "$DIR"
cd "$DIR"
git -C "$ROOT" archive --format=tar --prefix="databastion-deploy-${VERSION}/" HEAD deploy \
  | gzip -n -9 >"databastion-deploy-${VERSION}.tar.gz"
sha256sum "databastion-deploy-${VERSION}.tar.gz" >SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS >/dev/null
tar -xzf "databastion-deploy-${VERSION}.tar.gz" --strip-components=2 "databastion-deploy-${VERSION}/deploy"
cp docker-compose.example.yml compose.yaml
cp .env.example .env
sed -i \
  -e "s|^DATABASTION_CONSOLE_IMAGE=.*|DATABASTION_CONSOLE_IMAGE=${CONSOLE_IMAGE}|" \
  -e "s|^DATABASTION_DOMAIN=.*|DATABASTION_DOMAIN=${DOMAIN}|" \
  -e "s|^DATABASTION_TLS=.*|DATABASTION_TLS=internal|" \
  .env
./init-secrets.sh >/dev/null
mask "$(cat secrets/admin_password)"
phase_done files

# --------------------------------------------------------------------------- 2. console start
log "docker compose --profile proxy up -d"
timeout 600 docker compose --profile proxy up -d --quiet-pull >"$WORK/up.log" 2>&1 \
  || { cat "$WORK/up.log" >&2; fail "docker compose up failed"; }
[ "$(docker compose ps -a --format '{{.ExitCode}}' migrate)" = 0 ] || fail "migrate did not succeed"
# README: with DATABASTION_TLS=internal, the root certificate of Caddy's CA (created with the first
# certificate) is what browsers and agents trust.
deadline=$(( $(date +%s) + 120 ))
until docker compose exec -T proxy cat /data/caddy/pki/authorities/local/root.crt >"$WORK/console-ca.pem" 2>/dev/null \
    && grep -q 'BEGIN CERTIFICATE' "$WORK/console-ca.pem"; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "Caddy's root certificate did not appear within 120 s"
  sleep 2
done
CURL=(curl -sS --max-time 30 --cacert "$WORK/console-ca.pem" -b "$WORK/cookies" -c "$WORK/cookies")
deadline=$(( $(date +%s) + 180 ))
until [ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL/api/health/ready" 2>/dev/null)" = 200 ]; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "the console is not ready at $BASE_URL within 180 s"
  sleep 2
done
phase_done console-up

# --------------------------------------------------------------------------- 3. administrator
log "docker compose run --rm bootstrap-admin"
timeout 120 docker compose run --rm -T bootstrap-admin >"$WORK/bootstrap.log" 2>&1 \
  || { cat "$WORK/bootstrap.log" >&2; fail "bootstrap-admin failed"; }

# UI stand-in: log in, then create an enrollment token (Enrollment tokens page).
api() {  # api METHOD PATH [JSON] -> "<status>\n<body>"
  local args=(-X "$1" -o "$WORK/resp" -w '%{http_code}' -H "Origin: ${BASE_URL}")
  [ -f "$WORK/csrf.hdr" ] && args+=(-H "@$WORK/csrf.hdr")
  [ -n "${3:-}" ] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  local code
  code="$("${CURL[@]}" "${args[@]}" "${BASE_URL}$2")" || code=000
  printf '%s\n' "$code"
  cat "$WORK/resp" 2>/dev/null || true
}
admin_user="$(sed -n 's/^DATABASTION_ADMIN_USERNAME=//p' .env)"
jq -n --rawfile p secrets/admin_password --arg u "${admin_user:-admin}" '{username: $u, password: $p}' \
  >"$WORK/login.json"
r="$(api POST /api/auth/login "@$WORK/login.json")"
rm -f "$WORK/login.json"
[ "$(head -n 1 <<<"$r")" = 200 ] || fail "login: HTTP $(head -n 1 <<<"$r")"
csrf="$(tail -n +2 <<<"$r" | jq -r .csrf_token)"
mask "$csrf"
( umask 077; printf 'X-CSRF-Token: %s\n' "$csrf" >"$WORK/csrf.hdr" )
# README: delete the bootstrap password file once logged in.
rm -f secrets/admin_password
r="$(api POST /api/enrollment-tokens '{"label":"install-test"}')"
[ "$(head -n 1 <<<"$r")" = 201 ] || fail "enrollment token: HTTP $(head -n 1 <<<"$r")"
token="$(tail -n +2 <<<"$r" | jq -r .token)"
mask "$token"
[[ "$token" == dbe_* ]] || fail "unexpected enrollment token format"
phase_done admin-token

# --------------------------------------------------------------------------- 4. agent (.deb)
# README "2. Agent", on the database host (here the same host).
log "apt-get install ./$(basename "$AGENT_DEB")"
cp "$AGENT_DEB" "$WORK/"
# Logs and work files belong to this user: redirections outside sudo are deliberate (SC2024).
# shellcheck disable=SC2024
(cd "$WORK" && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "./$(basename "$AGENT_DEB")" \
  >"$WORK/apt.log" 2>&1) || { cat "$WORK/apt.log" >&2; fail "apt-get install failed"; }
# Configuration: console URL, the pinned console CA (DATABASTION_TLS=internal), and the targets
# (none here: the test covers installation and enrollment, not a database).
sudo install -m 0644 "$WORK/console-ca.pem" /etc/databastion/console-ca.pem
sudo sed -i \
  -e "s|^  url: .*|  url: ${BASE_URL}|" \
  -e "s|^  # ca_file: /etc/databastion/console-ca.pem|  ca_file: /etc/databastion/console-ca.pem|" \
  /etc/databastion/agent.yaml
# shellcheck disable=SC2024
sudo awk '/^targets:/ {print "targets: []"; skip = 1; next}
  skip && /^[^ #-]|^# metrics/ {skip = 0}
  !skip {print}' /etc/databastion/agent.yaml >"$WORK/agent.yaml"
sudo install -m 0640 -o root -g databastion "$WORK/agent.yaml" /etc/databastion/agent.yaml
sudo grep -qx "  url: ${BASE_URL}" /etc/databastion/agent.yaml || fail "console.url not set"
sudo grep -qx 'targets: \[\]' /etc/databastion/agent.yaml || fail "targets not replaced"

log "enroll"
printf '%s' "$token" | sudo install -m 0600 -o databastion -g databastion /dev/stdin \
  /etc/databastion/secrets/enrollment-token
unset token
# shellcheck disable=SC2024
sudo runuser -u databastion -- databastion-agent enroll --config /etc/databastion/agent.yaml \
  --token-file /etc/databastion/secrets/enrollment-token >"$WORK/enroll.log" 2>&1 \
  || { cat "$WORK/enroll.log" >&2; fail "databastion-agent enroll failed"; }
sudo rm -f /etc/databastion/secrets/enrollment-token
agent_id="$(jq -r 'select(.fields.message == "enrollment complete") | .fields.agent_id' "$WORK/enroll.log")"
[ -n "$agent_id" ] || fail "no agent id in the enrollment output"
log "enrolled agent $agent_id"

log "systemctl enable --now databastion-agent"
sudo systemctl enable --now databastion-agent >/dev/null 2>&1 || fail "systemctl enable --now failed"

# UI stand-in: the Agents page shows the agent online (first heartbeat accepted).
deadline=$(( $(date +%s) + 120 ))
agent=""
while :; do
  r="$(api GET /api/agents)"
  if [ "$(head -n 1 <<<"$r")" = 200 ]; then
    agent="$(tail -n +2 <<<"$r" | jq -c --arg id "$agent_id" '.agents[] | select(.id == $id)')"
    [ -n "$agent" ] && [ "$(jq -r .status <<<"$agent")" = online ] && break
  fi
  [ "$(date +%s)" -lt "$deadline" ] || fail "the agent is not online within 120 s (last: ${agent:-none})"
  sleep 2
done
phase_done agent-online
T_END="$(date +%s)"
TOTAL=$(( T_END - T_START ))

# --------------------------------------------------------------------------- after the clock
log "agent online: $(jq -c '{status, version}' <<<"$agent")"
sudo systemctl is-active --quiet databastion-agent || fail "the service is not active"
[ "$(systemctl show -p NRestarts --value databastion-agent)" = 0 ] || fail "the service restarted"
# Invariant I1 at run time: the agent process holds no listening socket.
pid="$(systemctl show -p MainPID --value databastion-agent)"
[ "$pid" -gt 0 ] || fail "no main PID"
if sudo ss -H -ltnup | grep -F "pid=${pid},"; then fail "the agent listens on a port (I1)"; fi
log "ok  no listening socket held by the agent (pid $pid)"
# The unit's socket restrictions, enforced: a probe run under the installed unit's own [Service]
# settings (ExecStart replaced) must be refused listen() on an unbound socket and bind() to a port,
# and still be allowed an outbound connect().
probe=databastion-listen-probe
cat >"$WORK/probe.py" <<'PY'
import socket
import sys

for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    s = socket.socket(family)
    try:
        s.listen(1)
        sys.exit(f"listen() allowed ({family.name})")
    except PermissionError:
        pass
s = socket.socket()
try:
    s.bind(("127.0.0.1", 0))
    sys.exit("bind() allowed")
except PermissionError:
    pass
socket.create_connection(("127.0.0.1", 443), 5).close()
print("probe ok")
PY
# /run is visible (read-only) under the unit's sandbox; /tmp is private.
sudo install -m 0644 "$WORK/probe.py" "/run/${probe}.py"
sed -e "s|^ExecStart=.*|ExecStart=/usr/bin/python3 /run/${probe}.py|" -e 's|^Type=exec|Type=oneshot|' \
  -e '/^Restart=/d' -e '/^RestartSec=/d' -e '/^\[Install\]/,$d' \
  /usr/lib/systemd/system/databastion-agent.service | sudo tee "/run/systemd/system/${probe}.service" >/dev/null
sudo systemctl daemon-reload
if ! sudo systemctl start "${probe}.service"; then
  sudo journalctl -u "${probe}.service" --no-pager -o cat >&2
  fail "the socket probe under the unit's settings failed (see above)"
fi
sudo journalctl -u "${probe}.service" --no-pager -o cat | grep -qx 'probe ok' || fail "the socket probe printed no result"
sudo rm -f "/run/systemd/system/${probe}.service" "/run/${probe}.py"
sudo systemctl daemon-reload
log "ok  under the unit's settings: listen() and bind() refused, outbound connect() allowed"
if sudo journalctl -u databastion-agent --no-pager -o cat | grep -F '"level":"ERROR"'; then
  fail "the agent logged errors"
fi
log "ok  no error in the agent journal"

log "timings: ${TIMINGS}total ${TOTAL}s (limit ${LIMIT_S}s)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  # shellcheck disable=SC2016
  printf '### Installation time\n\n%s\n\n**Total: %d s** (limit %d s), console image `%s`\n' \
    "$TIMINGS" "$TOTAL" "$LIMIT_S" "$CONSOLE_IMAGE" >>"$GITHUB_STEP_SUMMARY"
fi
[ "$TOTAL" -lt "$LIMIT_S" ] || fail "installation took ${TOTAL} s (limit ${LIMIT_S} s)"
log "PASS: installed, enrolled and online in ${TOTAL} s"
