#!/usr/bin/env bash
# Smoke test of the opt-in Apereo CAS dev service (`make dev-cas` first; run with
# `make dev-cas-smoke`). Checks, from the host:
# - the registry is loaded: a registered service is accepted, an unknown one refused, the OIDC
#   discovery document is served (the OIDC services loaded);
# - a fake user logs in through /cas/login for a registered service, and the service ticket is
#   validated (p3/serviceValidate); a login with a wrong password fails;
# - the audit log, read as the agent (uid 10001, its group), holds one JSON object per line with
#   the records of these actions (AUTHENTICATION_SUCCESS, SERVICE_TICKET_CREATED for that service,
#   SERVICE_TICKET_VALIDATE_SUCCESS, AUTHENTICATION_FAILED), no `headers` key, and not the service
#   ticket in clear (CAS masks ticket ids in its logs);
# - the ADR-0041 decision 6 permissions: registry directory 0750 and files 0640, log directory 2750
#   and log 0640, owner the CAS user, group the agent's; the agent can read them and write none
#   (even through a read-write mount); another user can read none; the ticket table is readable
#   by the agent's database account through its `type`, `creation_time` and `expiration_time`
#   columns only.
# Nothing secret is printed: passwords go to curl on stdin, logins, tickets and audit records are
# compared in Python and never echoed.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
if [ -f ./.env ]; then set -a; . ./.env; set +a; fi

C=(docker compose -f docker-compose.yml)
PORT=${CAS_PORT:-8280}
BASE="http://127.0.0.1:$PORT/cas"
USER_PASSWORD=${CAS_DEV_USER_PASSWORD:-dev-only-cas-user}
LOGIN=camille.martin@example.org
FAILING_LOGIN=hugo.durand@example.net
SERVICE=https://intranet.example.org/login
CAS_UID=10041
AGENT_UID=10001
AGENT_GID=${DATABASTION_DEV_AGENT_GID:-10001}
CURL=(curl -sS --max-time 20 --max-filesize 4194304 --proto "=http")
STARTED=$(date -u +%Y-%m-%dT%H:%M:%S)

fail=0
ok() { echo "ok   - $*"; }
ko() { echo "FAIL - $*"; fail=1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# as <uid:gid> <shell command>: runs a command in the cas-files-init container definition (busybox,
# no network) as that user, with dev/.state mounted read-write at /state: denials come from the
# permissions, not from a read-only mount.
as() { "${C[@]}" run --rm --no-deps -T -u "$1" --entrypoint sh cas-files-init -c "$2"; }

# urlenc <text>
urlenc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# login <user> <service or ""> <prefix>: GET the login form, then POST the credentials (password
# on stdin). Writes <prefix>.code and <prefix>.headers.
login() {
  local user=$1 service=$2 prefix=$tmp/$3 query="" execution
  [ -z "$service" ] || query="?service=$(urlenc "$service")"
  "${CURL[@]}" -c "$prefix.jar" -b "$prefix.jar" -o "$prefix.form" "$BASE/login$query" || return 1
  execution=$(python3 -c 'import re, sys; m = re.search(r"name=\"execution\" value=\"([^\"]+)\"", open(sys.argv[1], encoding="utf-8").read()); print(m.group(1) if m else "")' "$prefix.form")
  [ -n "$execution" ] || return 1
  printf '%s' "$4" | "${CURL[@]}" -c "$prefix.jar" -b "$prefix.jar" -o /dev/null -D "$prefix.headers" \
    -w '%{http_code}' --data-urlencode "username=$user" --data-urlencode "password@-" \
    --data-urlencode "execution=$execution" --data-urlencode "_eventId=submit" \
    "$BASE/login$query" >"$prefix.code"
}

echo "# Service registry ($BASE)"
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/login?service=$(urlenc "$SERVICE")" || true)
if [ "$code" = 200 ]; then ok "registered CAS service accepted (login form)"
else ko "registered CAS service accepted (HTTP $code; is the service up? make dev-cas)"; fi
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/login?service=$(urlenc https://unknown.example.net/)" || true)
if [ "$code" = 401 ] || [ "$code" = 403 ]; then ok "unregistered service refused (HTTP $code)"
else ko "unregistered service refused (HTTP $code)"; fi
if "${CURL[@]}" -o "$tmp/oidc.json" "$BASE/oidc/.well-known/openid-configuration"; then
  if python3 - "$tmp/oidc.json" "$BASE/oidc" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if d.get("issuer") == sys.argv[2] else 1)
PY
  then ok "OIDC discovery document (issuer $BASE/oidc)"; else ko "OIDC discovery issuer"; fi
else
  ko "OIDC discovery document reachable"
fi

echo "# Login, service ticket, failed login"
st=""
if login "$LOGIN" "$SERVICE" ok "$USER_PASSWORD" && [ "$(cat "$tmp/ok.code")" = 302 ]; then
  st=$(python3 - "$tmp/ok.headers" "$SERVICE" <<'PY'
import sys, urllib.parse
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if line.lower().startswith("location:"):
        url = urllib.parse.urlparse(line.split(":", 1)[1].strip())
        base = urllib.parse.urlunparse(url._replace(query="", fragment=""))
        tickets = urllib.parse.parse_qs(url.query).get("ticket", [])
        if base == sys.argv[2] and len(tickets) == 1 and tickets[0].startswith("ST-"):
            print(tickets[0])
PY
)
fi
if [ -n "$st" ]; then
  ok "fake user logged in, redirected to the service with a service ticket"
  printf '%s' "$st" >"$tmp/st"
  if "${CURL[@]}" -o "$tmp/validate.xml" "$BASE/p3/serviceValidate?service=$(urlenc "$SERVICE")&ticket=$(urlenc "$st")" \
    && python3 - "$tmp/validate.xml" "$LOGIN" <<'PY'
import sys, xml.etree.ElementTree as ET
ns = {"cas": "http://www.yale.edu/tp/cas"}
user = ET.parse(sys.argv[1]).getroot().find("cas:authenticationSuccess/cas:user", ns)
sys.exit(0 if user is not None and user.text == sys.argv[2] else 1)
PY
  then ok "service ticket validated (p3/serviceValidate, the user's login)"; else ko "service ticket validated"; fi
else
  ko "fake user logged in with a service ticket (CAS_DEV_USER_PASSWORD from dev/.env)"
fi
if login "$FAILING_LOGIN" "" bad "wrong-$USER_PASSWORD" && [ "$(cat "$tmp/bad.code")" = 401 ]; then
  ok "login with a wrong password refused (HTTP 401)"
else
  ko "login with a wrong password refused"
fi

echo "# Audit log, read as the agent (uid $AGENT_UID, gid $AGENT_GID)"
# CAS writes asynchronously: a few tries.
got=0
for _ in 1 2 3 4 5; do
  if as "$AGENT_UID:$AGENT_GID" 'tail -c 1048576 /state/logs/cas/cas_audit.log' >"$tmp/audit.log" 2>/dev/null \
    && python3 - "$tmp/audit.log" "$STARTED" "$LOGIN" "$FAILING_LOGIN" "$SERVICE" >"$tmp/audit.out" <<'PY'
import json, sys
path, started, login, failing, service = sys.argv[1:]
lines = [l for l in open(path, encoding="utf-8", errors="replace").read().splitlines() if l.strip()]
records, bad = [], 0
for l in lines:
    try:
        r = json.loads(l)
    except ValueError:
        bad += 1
        continue
    if isinstance(r, dict):
        records.append(r)
    else:
        bad += 1
recent = [r for r in records if str(r.get("when", ""))[:19] >= started]
def has(action, pred):
    return any(r.get("action") == action and pred(r) for r in recent)
what = lambda r: r.get("what") if isinstance(r.get("what"), dict) else {}
checks = {
    "every line is one JSON object": bad == 0 and bool(records),
    "AUTHENTICATION_SUCCESS of the user": has("AUTHENTICATION_SUCCESS", lambda r: r.get("who") == login),
    "SERVICE_TICKET_CREATED for the service": has("SERVICE_TICKET_CREATED",
        lambda r: r.get("who") == login and what(r).get("service") == service),
    "SERVICE_TICKET_VALIDATE_SUCCESS": has("SERVICE_TICKET_VALIDATE_SUCCESS", lambda r: True),
    "AUTHENTICATION_FAILED of the failing login": has("AUTHENTICATION_FAILED", lambda r: r.get("who") == failing),
    "no record carries request headers": not any("headers" in r for r in records),
    "records carry who, what, action, when, client address and user agent":
        all({"who", "what", "action", "when", "clientIpAddress", "userAgent"} <= r.keys() for r in recent),
}
for name, good in checks.items():
    print(("ok   - " if good else "FAIL - ") + name)
sys.exit(0 if all(checks.values()) else 1)
PY
  then got=1; break; fi
  sleep 2
done
cat "$tmp/audit.out" 2>/dev/null || true
[ "$got" = 1 ] || ko "audit records of the smoke actions (see above)"
if [ -s "$tmp/st" ]; then
  if python3 - "$tmp/audit.log" "$tmp/st" <<'PY'
import sys
log = open(sys.argv[1], encoding="utf-8", errors="replace").read()
sys.exit(1 if open(sys.argv[2], encoding="utf-8").read() in log else 0)
PY
  then ok "the service ticket is not in the audit log in clear (CAS masks ticket ids)"
  else ko "the service ticket is in the audit log in clear"; fi
fi

echo "# Permissions (ADR-0041 decision 6)"
# stat as root, metadata only: mode owner group links name, for the two directories and their files.
if as 0:0 'stat -c "%a %u %g %h %F %n" /state/cas/services /state/cas/services/* /state/logs/cas /state/logs/cas/cas_audit.log' >"$tmp/stat" 2>/dev/null; then
  if python3 - "$tmp/stat" "$CAS_UID" "$AGENT_GID" <<'PY'
import sys
cas, agent = sys.argv[2], sys.argv[3]
rows = [l.split(" ", 5) for l in open(sys.argv[1]).read().splitlines()]
want = {"/state/cas/services": "750", "/state/logs/cas": "2750", "/state/logs/cas/cas_audit.log": "640"}
ok = bool(rows)
for mode, uid, gid, links, kind, name in rows:
    expected = want.get(name, "640")
    if mode != expected or uid != cas or gid != agent:
        ok = False
    if name.startswith("/state/cas/services/") and (kind != "regular file" or links != "1" or not name.endswith(".json")):
        ok = False
sys.exit(0 if ok else 1)
PY
  then ok "registry 0750 / 0640 and log directory 2750 / log 0640, owner $CAS_UID, group $AGENT_GID, single-link .json files"
  else ko "registry and audit log modes, owner and group"; fi
else
  ko "registry and audit log present (make dev-cas)"
fi
reads='cat /state/cas/services/*.json >/dev/null && cat /state/logs/cas/cas_audit.log >/dev/null'
if as "$AGENT_UID:$AGENT_GID" "$reads" >/dev/null 2>&1; then ok "the agent can read the registry and the audit log"
else ko "the agent can read the registry and the audit log"; fi
writes='touch /state/cas/services/x.json || touch /state/logs/cas/x || : >>/state/logs/cas/cas_audit.log || : >>/state/cas/services/Intranet-1001.json || chmod 0666 /state/logs/cas/cas_audit.log'
if as "$AGENT_UID:$AGENT_GID" "$writes" >/dev/null 2>&1; then ko "the agent cannot write the registry nor the audit log"
else ok "the agent cannot write the registry nor the audit log (read-write mount, denied by the permissions)"; fi
if as 10099:10099 'ls /state/cas/services || cat /state/logs/cas/cas_audit.log' >/dev/null 2>&1; then
  ko "another user cannot read the registry nor the audit log"
else ok "another user cannot read the registry nor the audit log"; fi

echo "# Ticket table (JPA ticket registry, database cas)"
# Expanded inside the container (its DATABASTION_DB_PASSWORD), not here.
# shellcheck disable=SC2016
PSQL='PGPASSWORD="$DATABASTION_DB_PASSWORD" psql -X -h 127.0.0.1 -U databastion -d cas -v ON_ERROR_STOP=1 -Atq'
if "${C[@]}" exec -T postgres sh -c "$PSQL -c \"SELECT count(*) > 0 FROM (SELECT type, count(*) FROM public.cas_tickets GROUP BY type) t\"" 2>/dev/null | grep -qx t; then
  ok "the agent account counts tickets per type (the CAS store guard's aggregate)"
else ko "the agent account counts tickets per type"; fi
if "${C[@]}" exec -T postgres sh -c "$PSQL -c \"SELECT has_table_privilege('public.cas_tickets', 'SELECT')
     OR has_any_column_privilege('public.cas_tickets', 'INSERT, UPDATE, REFERENCES')
     OR has_column_privilege('public.cas_tickets', 'id', 'SELECT') OR has_column_privilege('public.cas_tickets', 'body', 'SELECT')
     OR has_column_privilege('public.cas_tickets', 'parent_id', 'SELECT') OR has_column_privilege('public.cas_tickets', 'principal_id', 'SELECT')
     OR has_column_privilege('public.cas_tickets', 'service', 'SELECT') OR has_column_privilege('public.cas_tickets', 'attributes', 'SELECT')\"" 2>/dev/null | grep -qx f; then
  ok "the agent account cannot read the ticket ids, bodies, principals nor attributes"
else ko "the agent account holds no privilege on the ticket credentials"; fi

exit "$fail"
