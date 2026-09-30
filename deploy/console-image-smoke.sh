#!/usr/bin/env bash
# Smoke test of a built console image (CI: packaging.yml, before the installation test).
#
#   deploy/console-image-smoke.sh IMAGE
#
# Seconds, no database: the entrypoint dispatcher and the TypeScript runner load and run as the
# image's user; the healthcheck script runs; the image has no shell and runs as uid 10001.
set -euo pipefail

image="${1:?usage: $0 IMAGE}"
log() { printf '[console-smoke] %s\n' "$*"; }
fail() { printf '[console-smoke] FAIL: %s\n' "$*" >&2; exit 1; }
run() { docker run --rm --pull never --read-only --tmpfs /tmp --cap-drop ALL "$@"; }

user="$(docker image inspect -f '{{.Config.User}}' "$image")"
[ "$user" = "10001:10001" ] || fail "image user is '$user', expected 10001:10001"
log "ok  runs as $user"

rc=0
out="$(run "$image" no-such-command 2>&1)" || rc=$?
if [ "$rc" != 64 ] || ! grep -q 'usage: entrypoint' <<<"$out"; then
  echo "$out"; fail "entrypoint: exit $rc, expected 64 with its usage line"
fi
log "ok  entrypoint loads (usage, exit 64)"

rc=0
out="$(run "$image" migrate 2>&1)" || rc=$?
if [ "$rc" = 0 ] || ! grep -q 'Missing configuration' <<<"$out"; then
  echo "$out"; fail "migrate without a database: exit $rc, expected a configuration error"
fi
log "ok  migrate starts under tsx and stops on the missing configuration"

run --entrypoint /nodejs/bin/node "$image" /usr/local/lib/databastion/healthcheck.mjs \
  || fail "healthcheck script failed outside the web process"
log "ok  healthcheck script runs"

if run --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then
  fail "the image has a shell"
fi
log "ok  no /bin/sh"
log "PASS"
