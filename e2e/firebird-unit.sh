#!/usr/bin/env bash
# The Firebird bare-host identity load and readers check under the shipped systemd unit (security
# review F1 of the Firebird lot; ADR-0060 R45 items 1 and 2, R48).
#
#   e2e/firebird-unit.sh PATH/TO/databastion_connector_firebird-<hash> [PATH/TO/databastion-agent_<version>_<arch>.deb]
#
# The first argument is the connector's library test binary (`cargo test --locked -p
# databastion-connector-firebird --lib --no-run`), built for this system's glibc (CI builds it in the
# agent Dockerfile's pinned builder image, Debian 12). Run as root on a system whose PID 1 is
# systemd, never on a host you care about: CI runs it in the throwaway privileged Debian 12 /
# Ubuntu 24.04 container of e2e/sqlite-unit.sh (.github/workflows/packaging.yml, job deb-install),
# after that script. Installs the .deb if given (otherwise databastion-agent must be installed).
#
# Why: deploy/deb/databastion-agent.service has RestrictSUIDSGID=yes, so systemd's seccomp filter
# answers openat2 with ENOSYS. The Firebird connector runs in the agent's process: its identity
# files are opened by databastion_core::fs::open_no_links, which falls back to a component walk on
# ENOSYS. Before that fallback every bare-host target reported host_identity_refused (passwd:
# not_readable) and a false audit.log_readable_by_others.
#
# What it does: creates a throwaway server account (system user, removed on exit), runs the test
# binary's `it::unit::prepare` phase as root (under a 0755 directory in /srv: the user guide's
# named-user ACL log layout, owner the server account, read for databastion; and root-owned link
# chains with refused links next to them), then starts databastion-agent.service itself with a
# drop-in under /run that replaces ExecStart (the test binary's `it::unit::check` phase), Restart,
# Environment and the output redirection only: every other property of
# /usr/lib/systemd/system/databastion-agent.service applies, User=databastion and its
# SystemCallFilter / RestrictSUIDSGID lines included. Under the unit, the check asserts that openat2
# answers ENOSYS, that the host's own /etc/passwd, /etc/group, /etc/nsswitch.conf (and subuid /
# subgid when present) load under the production rules (root-owned, links followed only under
# /etc), that the readers check of the seeded log passes (audit.rs adds
# audit.log_readable_by_others exactly when it fails), and that root-owned link chains are followed
# while a link of another owner, a link in an ancestor and a link out of the base are refused.
# Container detection is forced off for the readers check (this runs in a container): the bare-host
# path is what is exercised. Prints verdicts and closed reasons only. Removes the drop-in, the
# seeded files, the binary copy and the server account on exit (the .deb stays installed).
#
# Requires: systemd (PID 1), useradd / userdel.
set -euo pipefail

bin="${1:-}"
deb="${2:-}"
UNIT=databastion-agent.service
UNIT_FILE=/usr/lib/systemd/system/$UNIT
DROPIN_DIR=/run/systemd/system/$UNIT.d
DROPIN=$DROPIN_DIR/zz-firebird-unit-check.conf
RUN_DIR=/run/databastion-firebird-unit-check
DATA_DIR=/srv/databastion-firebird-unit-check
# Not under /run: a container's /run tmpfs is mounted noexec.
BIN_DIR=/usr/local/lib/databastion-firebird-unit-check
SERVER=dbfbunit
TEST=it::unit

log() { printf '[firebird-unit] %s\n' "$*"; }
fail() { printf '[firebird-unit] FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root (in a throwaway container or VM)"
[ "$(cat /proc/1/comm)" = systemd ] || fail "systemd is not PID 1 here"
[ -n "$bin" ] && [ -f "$bin" ] || fail "usage: $0 TEST_BINARY [DEB]"

created_user=0
cleanup() {
  local status=$?
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1
  rm -f "$DROPIN"
  rmdir "$DROPIN_DIR" 2>/dev/null
  systemctl daemon-reload
  systemctl reset-failed "$UNIT" >/dev/null 2>&1
  rm -rf "$RUN_DIR" "$DATA_DIR" "$BIN_DIR"
  [ "$created_user" = 1 ] && userdel "$SERVER" >/dev/null 2>&1
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT

deadline=$(( $(date +%s) + 120 ))
while :; do
  state="$(timeout 30 systemctl is-system-running --wait 2>/dev/null || true)"
  case "$state" in running | degraded) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "systemd did not finish starting (state '${state}')"
  sleep 1
done
. /etc/os-release
log "system: ${PRETTY_NAME}, $(uname -m), kernel $(uname -r), $(systemctl --version | head -n 1)"

if [ -n "$deb" ]; then
  log "dpkg -i $(basename "$deb")"
  DEBIAN_FRONTEND=noninteractive dpkg -i "$deb" >/dev/null
fi
[ -f "$UNIT_FILE" ] && [ -x /usr/bin/databastion-agent ] || fail "databastion-agent is not installed"
[ "$(systemctl show -p ActiveState --value "$UNIT")" = inactive ] || fail "$UNIT is already running: not on this host"
grep -qx 'RestrictSUIDSGID=yes' "$UNIT_FILE" || fail "the shipped unit no longer has RestrictSUIDSGID=yes: review this check"

! id "$SERVER" >/dev/null 2>&1 || fail "account $SERVER already exists: not on this host"
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVER"
created_user=1
server_uid="$(id -u "$SERVER")"
server_gid="$(id -g "$SERVER")"
agent_uid="$(id -u databastion)"
log "server account: uid ${server_uid}, gid ${server_gid}; agent account: uid ${agent_uid}"

rm -rf "$DATA_DIR"
install -d -o root -g root -m 0755 "$DATA_DIR"
install -d -o root -g root -m 0755 "$RUN_DIR"
install -d -o root -g root -m 0755 "$BIN_DIR"
install -o root -g root -m 0755 "$bin" "$BIN_DIR/fbtest"
common=(FIREBIRD_UNIT_CHECK_DIR="$DATA_DIR" FIREBIRD_UNIT_SERVER_UID="$server_uid" FIREBIRD_UNIT_SERVER_GID="$server_gid")
log "prepare (as root): the ACL log layout and the link chains under ${DATA_DIR}"
env -i PATH=/usr/bin:/bin FIREBIRD_UNIT_CHECK=prepare FIREBIRD_UNIT_AGENT_UID="$agent_uid" "${common[@]}" \
  timeout 60 "$BIN_DIR/fbtest" --exact "$TEST::prepare" --test-threads=1 >"$RUN_DIR/prepare.out" 2>&1 \
  || { sed 's/^/[firebird-unit]   prepare: /' "$RUN_DIR/prepare.out"; fail "prepare failed"; }
grep -q '^test result: ok\. 1 passed' "$RUN_DIR/prepare.out" || fail "prepare did not run"

: >"$RUN_DIR/out"
install -d -m 0755 "$DROPIN_DIR"
cat >"$DROPIN" <<EOF
# e2e/firebird-unit.sh only (removed on exit): the connector's test binary instead of the agent.
[Service]
ExecStart=
ExecStart=$BIN_DIR/fbtest --exact $TEST::check --nocapture --test-threads=1
Restart=no
Environment=FIREBIRD_UNIT_CHECK=check ${common[*]}
StandardOutput=append:$RUN_DIR/out
StandardError=append:$RUN_DIR/out
EOF
systemctl daemon-reload
dropins="$(systemctl show -p DropInPaths --value "$UNIT")"
[ "$dropins" = "$DROPIN" ] || fail "unexpected drop-ins for $UNIT: '${dropins}'"
fragment="$(systemctl show -p FragmentPath --value "$UNIT")"
[ -n "$fragment" ] && [ "$(readlink -f -- "$fragment")" = "$(readlink -f -- "$UNIT_FILE")" ] \
  || fail "$UNIT is not loaded from $UNIT_FILE (FragmentPath: ${fragment:-none})"
[ "$(systemctl show -p RestrictSUIDSGID --value "$UNIT")" = yes ] || fail "RestrictSUIDSGID is not in effect"

log "systemctl start $UNIT (the shipped unit, ExecStart, Restart, Environment and the output redirection replaced)"
systemctl start "$UNIT" || true
deadline=$(( $(date +%s) + 60 ))
while :; do
  active="$(systemctl show -p ActiveState --value "$UNIT")"
  case "$active" in inactive | failed) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "$UNIT still ${active} after 60 s"
  sleep 0.5
done
result="$(systemctl show -p Result --value "$UNIT")"
status="$(systemctl show -p ExecMainStatus --value "$UNIT")"
grep '^\[firebird-unit\]\|^test \|^test result\|panicked\|firebird-unit-check' "$RUN_DIR/out" \
  | sed 's/^/[firebird-unit]   unit output: /' || true
[ "$result" = success ] && [ "$status" = 0 ] \
  || { sed 's/^/[firebird-unit]   unit output: /' "$RUN_DIR/out"; fail "$UNIT ended with Result=${result} ExecMainStatus=${status}"; }
grep -q '^test result: ok\. 1 passed' "$RUN_DIR/out" || fail "the check did not run"
grep -q '\[firebird-unit\] openat2 ENOSYS' "$RUN_DIR/out" || fail "no openat2 ENOSYS proof under the unit"
grep -q '^firebird-unit-check-ok$' "$RUN_DIR/out" || fail "the check did not report success"
! grep -q 'host_identity_refused' "$RUN_DIR/out" || fail "host_identity_refused under the unit"
! grep -q 'log_readable_by_others' "$RUN_DIR/out" || fail "log_readable_by_others under the unit"
log "ok  under ${UNIT}'s own sandbox (openat2 answered ENOSYS): the bare host's identity files loaded, the readers check passed, the link rules held"
