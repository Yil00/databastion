#!/usr/bin/env bash
# The SQLite reader under the shipped systemd unit (ROADMAP P10-A; ADR-0059 decision 4 and its
# implementation note of 2026-10-24: "the systemd unit must allow what the reader needs").
#
#   e2e/sqlite-unit.sh [PATH/TO/databastion-agent_<version>_<arch>.deb]
#
# Run as root on a system whose PID 1 is systemd, never on a host you care about: CI runs it in a
# throwaway privileged Debian 12 / Ubuntu 24.04 container with systemd as PID 1
# (.github/workflows/packaging.yml, job deb-install); the maintainer may run it on a Debian 12 VM
# with Debian's own kernel (e2e/README.md, "SQLite reader under the systemd unit"). Installs the
# .deb if given (otherwise databastion-agent must be installed), seeds a small SQLite file
# (root:databastion 0640 in a 0750 directory under /srv, read-only for the unit through
# ProtectSystem=strict), and starts databastion-agent.service itself with a drop-in under /run that
# replaces ExecStart (and Restart) only: every other property of
# /usr/lib/systemd/system/databastion-agent.service applies, its SystemCallFilter lines included.
# ExecStart is e2e/sqlite_unit_driver.py, the agent's stand-in, which starts the installed binary's
# reader mode as the agent does and drives one unit of work (open, catalog, sample, close).
# Nothing here needs a console, an enrollment or a secret. Removes the drop-in, the seeded file and
# the driver copy on exit (the .deb stays installed).
#
# Requires: systemd (PID 1), python3 (with its sqlite3 module).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deb="${1:-}"
UNIT=databastion-agent.service
UNIT_FILE=/usr/lib/systemd/system/$UNIT
DROPIN_DIR=/run/systemd/system/$UNIT.d
DROPIN=$DROPIN_DIR/zz-sqlite-unit-check.conf
RUN_DIR=/run/databastion-sqlite-unit-check
DATA_DIR=/srv/databastion-sqlite-unit-check
DB=$DATA_DIR/app.db
ROWS=20

log() { printf '[sqlite-unit] %s\n' "$*"; }
fail() { printf '[sqlite-unit] FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root (in a throwaway container or VM)"
[ "$(cat /proc/1/comm)" = systemd ] || fail "systemd is not PID 1 here"
command -v python3 >/dev/null || fail "python3 is required"

cleanup() {
  local status=$?
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1
  rm -f "$DROPIN"
  rmdir "$DROPIN_DIR" 2>/dev/null
  systemctl daemon-reload
  systemctl reset-failed "$UNIT" >/dev/null 2>&1
  rm -rf "$RUN_DIR" "$DATA_DIR"
  if [ "$status" -eq 0 ]; then log "PASS"; else log "exit status $status"; fi
  exit "$status"
}
trap cleanup EXIT

# A container just started: PID 1 may not answer yet.
deadline=$(( $(date +%s) + 120 ))
while :; do
  state="$(timeout 30 systemctl is-system-running --wait 2>/dev/null || true)"
  case "$state" in running | degraded) break ;; esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "systemd did not finish starting (state '${state}')"
  sleep 1
done
. /etc/os-release
log "system: ${PRETTY_NAME}, $(uname -m), kernel $(uname -r), $(systemctl --version | head -n 1)"
log "LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'securityfs not mounted')"
# landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION): 444 on x86_64 and aarch64.
abi="$(python3 -I -c 'import ctypes; libc = ctypes.CDLL(None, use_errno=True); r = libc.syscall(444, None, 0, 1); print(r if r > 0 else "unavailable-errno-%d" % ctypes.get_errno())')"
log "Landlock ABI: ${abi}"
[[ "$abi" =~ ^[0-9]+$ ]] || fail "Landlock is not enabled on this kernel: SQLite targets are refused (coverage.reader_sandbox_unavailable)"

if [ -n "$deb" ]; then
  log "dpkg -i $(basename "$deb")"
  DEBIAN_FRONTEND=noninteractive dpkg -i "$deb" >/dev/null
fi
[ -f "$UNIT_FILE" ] && [ -x /usr/bin/databastion-agent ] || fail "databastion-agent is not installed"
log "$(/usr/bin/databastion-agent --version)"
[ "$(systemctl show -p ActiveState --value "$UNIT")" = inactive ] || fail "$UNIT is already running: not on this host"

# The unit's effective filter, as this systemd resolved it: the reader's sandbox calls must be in
# it (systemd drops a name it does not know with a warning, which would leave the call refused).
filter="$(systemctl show -p SystemCallFilter --value "$UNIT")"
for call in landlock_create_ruleset landlock_add_rule landlock_restrict_self seccomp prctl execve; do
  tr ' ' '\n' <<<"$filter" | grep -qx "$call" || fail "this systemd's filter for $UNIT does not allow $call"
done
for call in bind listen accept accept4 io_uring_setup; do
  ! tr ' ' '\n' <<<"$filter" | grep -qx "$call" || fail "this systemd's filter for $UNIT allows $call"
done
log "ok  the unit's resolved filter allows landlock_*, seccomp, prctl and execve, and refuses bind / listen / accept / io_uring"

log "seeding ${DB} (rollback journal, ${ROWS} rows of fake addresses)"
rm -rf "$DATA_DIR"
install -d -o root -g databastion -m 0750 "$DATA_DIR"
python3 -I - "$DB" "$ROWS" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("PRAGMA journal_mode = DELETE")
con.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT NOT NULL)")
con.executemany("INSERT INTO clients (email) VALUES (?)",
                [("client%d@example.test" % i,) for i in range(int(sys.argv[2]))])
con.commit()
con.close()
PY
[ ! -e "$DB-journal" ] || fail "a -journal was left next to the seeded file"
chown root:databastion "$DB"
chmod 0640 "$DB"

install -d -o root -g root -m 0755 "$RUN_DIR"
install -o root -g root -m 0644 "$HERE/sqlite_unit_driver.py" "$RUN_DIR/driver.py"
: >"$RUN_DIR/out"
install -d -m 0755 "$DROPIN_DIR"
cat >"$DROPIN" <<EOF
# e2e/sqlite-unit.sh only (removed on exit): the agent's stand-in instead of the agent.
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I -B $RUN_DIR/driver.py $DB
Restart=no
StandardOutput=append:$RUN_DIR/out
StandardError=append:$RUN_DIR/out
EOF
systemctl daemon-reload
dropins="$(systemctl show -p DropInPaths --value "$UNIT")"
[ "$dropins" = "$DROPIN" ] || fail "unexpected drop-ins for $UNIT: '${dropins}'"
[ "$(systemctl show -p FragmentPath --value "$UNIT")" = "$UNIT_FILE" ] || fail "$UNIT is not loaded from $UNIT_FILE"

log "systemctl start $UNIT (the shipped unit, ExecStart replaced)"
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
sed 's/^/[sqlite-unit]   unit output: /' "$RUN_DIR/out"
# Result=success: the stand-in exited 0 (a signal gives Result=signal or core-dump).
[ "$result" = success ] && [ "$status" = 0 ] \
  || fail "$UNIT ended with Result=${result} ExecMainStatus=${status}"
grep -q '^sqlite-unit-check-ok ' "$RUN_DIR/out" || fail "the stand-in did not report success"
log "ok  under ${UNIT}'s own sandbox: the reader applied Landlock and its seccomp filter on top of the unit's, read the seeded file and exited 0"
