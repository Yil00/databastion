#!/usr/bin/env bash
# Installs a databastion-agent .deb and checks what it put on the system, then upgrade, remove
# and purge. Run as root in a throwaway Debian / Ubuntu container (CI: .github/workflows/packaging.yml),
# never on a host you care about.
#
#   deploy/deb/test-install.sh PATH/TO/databastion-agent_<version>_<arch>.deb [EXPECTED_VERSION]
#
# EXPECTED_VERSION: the version `databastion-agent --version` must print (optional).
set -euo pipefail

deb="${1:?usage: $0 DEB [EXPECTED_VERSION]}"
expected_version="${2:-}"
[ "$(id -u)" = 0 ] || { echo "run as root (in a container)" >&2; exit 1; }
unit=/usr/lib/systemd/system/databastion-agent.service

log() { printf '[deb-test] %s\n' "$*"; }
fail() { printf '[deb-test] FAIL: %s\n' "$*" >&2; exit 1; }
# expect_stat PATH "owner:group mode"
expect_stat() {
  local got
  got="$(stat -c '%U:%G %a' "$1")" || fail "$1 is missing"
  [ "$got" = "$2" ] || fail "$1 is '$got', expected '$2'"
  log "ok  $1 $got"
}

. /etc/os-release
log "system: ${PRETTY_NAME}, $(dpkg --print-architecture)"
if ! command -v systemd-analyze >/dev/null; then
  log "installing systemd (systemd-analyze only; systemd is not running in this container)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends systemd >/dev/null
fi

log "dpkg -i $(basename "$deb")"
dpkg -i "$deb"

log "system user"
entry="$(getent passwd databastion)" || fail "no databastion user"
IFS=: read -r _ _ uid gid _ home shell <<<"$entry"
[ "$uid" -lt 1000 ] || fail "databastion is not a system user (uid $uid)"
[ "$(getent group databastion | cut -d: -f3)" = "$gid" ] || fail "databastion's primary group is not databastion"
[ "$home" = /nonexistent ] && [ ! -e /nonexistent ] || fail "home is '$home' (expected /nonexistent, not created)"
[ "$shell" = /usr/sbin/nologin ] || fail "login shell is '$shell'"
pw="$(getent shadow databastion | cut -d: -f2)"
case "$pw" in '!'*|'*'*) ;; *) fail "the databastion account has a usable password" ;; esac
log "ok  databastion uid=$uid gid=$gid home=$home shell=$shell (password locked)"

log "files, owners and modes"
expect_stat /usr/bin/databastion-agent "root:root 755"
expect_stat /etc/databastion "root:databastion 750"
expect_stat /etc/databastion/secrets "root:databastion 750"
expect_stat /etc/databastion/agent.yaml "root:databastion 640"
expect_stat /var/lib/databastion "databastion:databastion 700"
expect_stat /etc/databastion/agent.env "root:root 600"
expect_stat "$unit" "root:root 644"
for f in agent.yaml agent.env; do
  dpkg-query -W -f='${Conffiles}\n' databastion-agent | grep -q "^ /etc/databastion/$f " \
    || fail "/etc/databastion/$f is not a conffile"
done
cmp -s /etc/databastion/agent.yaml /usr/share/databastion-agent/agent.example.yaml \
  || fail "agent.yaml differs from agent.example.yaml"
log "ok  /etc/databastion/agent.yaml is a conffile (agent.example.yaml)"

log "invariant I1: no listener in the package"
if dpkg -L databastion-agent | grep -E '\.socket$'; then fail "the package ships a socket unit"; fi
if grep -E '^(ListenStream|ListenDatagram|ListenSequentialPacket|Sockets)=' "$unit"; then
  fail "the unit declares a listening socket"
fi
grep -qx 'SocketBindDeny=any' "$unit" || fail "SocketBindDeny=any missing from the unit"
grep -qx 'SystemCallFilter=~bind listen accept accept4' "$unit" || fail "bind / listen / accept not denied by the unit"
grep -qx 'SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register' "$unit" \
  || fail "io_uring not denied by the unit"
log "ok  no socket unit, no Listen*=, SocketBindDeny=any, bind / listen / accept / accept4 / io_uring denied"

log "no core dumps"
grep -qx 'LimitCORE=0' "$unit" || fail "the unit does not set LimitCORE=0"
log "ok  LimitCORE=0"

log "systemd-analyze verify"
out="$(systemd-analyze verify "$unit" 2>&1)" || { echo "$out"; fail "systemd-analyze verify failed"; }
[ -z "$out" ] || { echo "$out"; fail "systemd-analyze verify reported warnings"; }
log "ok  systemd-analyze verify: no warning"
# Exposure score (0 = most restricted, 10 = unrestricted); the unit scores about 1.5.
if systemd-analyze security --help 2>/dev/null | grep -q -- '--offline'; then
  systemd-analyze security --offline=true --threshold=20 --no-pager "$unit" | tail -n 1
  log "ok  systemd-analyze security: exposure <= 2.0"
fi

log "databastion-agent --version"
v="$(runuser -u databastion -- /usr/bin/databastion-agent --version)"
log "    $v"
[[ "$v" == "databastion-agent "* ]] || fail "unexpected --version output"
if [ -n "$expected_version" ] && [ "$v" != "databastion-agent ${expected_version}" ]; then
  fail "--version is '$v', expected 'databastion-agent ${expected_version}'"
fi

log "the agent refuses to run without an identity (not enrolled)"
rc=0
runuser -u databastion -- timeout 20 /usr/bin/databastion-agent run --config /etc/databastion/agent.yaml \
  >/tmp/agent-run.log 2>&1 || rc=$?
case "$rc" in
  0) fail "run succeeded without an identity" ;;
  124) cat /tmp/agent-run.log; fail "run did not stop within 20 s without an identity" ;;
esac
grep -q 'agent is not enrolled' /tmp/agent-run.log || { cat /tmp/agent-run.log; fail "run failed for another reason"; }
log "ok  exit $rc: not enrolled (the state directory and the configuration were accepted)"

log "reinstall with a modified configuration: the change and the permissions are kept"
echo "# local change" >>/etc/databastion/agent.yaml
dpkg -i --force-confold "$deb" >/dev/null
tail -n 1 /etc/databastion/agent.yaml | grep -qx '# local change' || fail "the local agent.yaml change was lost"
expect_stat /etc/databastion/agent.yaml "root:databastion 640"
expect_stat /var/lib/databastion "databastion:databastion 700"

log "upgrade to a newer version: owners, modes, local configuration and state kept"
touch /var/lib/databastion/marker
rm -rf /tmp/deb-upgrade
dpkg-deb -R "$deb" /tmp/deb-upgrade
old_version="$(sed -n 's/^Version: //p' /tmp/deb-upgrade/DEBIAN/control)"
sed -i "s/^Version: .*/Version: ${old_version}+upgradetest/" /tmp/deb-upgrade/DEBIAN/control
dpkg-deb -b /tmp/deb-upgrade /tmp/databastion-agent-upgrade.deb >/dev/null
dpkg -i --force-confold /tmp/databastion-agent-upgrade.deb >/dev/null
[ "$(dpkg-query -W -f='${Version}' databastion-agent)" = "${old_version}+upgradetest" ] || fail "upgrade not applied"
tail -n 1 /etc/databastion/agent.yaml | grep -qx '# local change' || fail "the local agent.yaml change was lost on upgrade"
[ -e /var/lib/databastion/marker ] || fail "the state was lost on upgrade"
expect_stat /etc/databastion "root:databastion 750"
expect_stat /etc/databastion/agent.yaml "root:databastion 640"
expect_stat /var/lib/databastion "databastion:databastion 700"

log "remove: binary and unit gone, configuration kept"
dpkg -r databastion-agent
[ ! -e /usr/bin/databastion-agent ] && [ ! -e "$unit" ] || fail "files left after remove"
[ -f /etc/databastion/agent.yaml ] && [ -e /var/lib/databastion/marker ] || fail "configuration or state removed by remove"
log "ok"

log "purge: configuration and state gone, user kept"
dpkg -P databastion-agent
[ ! -e /etc/databastion/agent.yaml ] && [ ! -e /var/lib/databastion ] || fail "files left after purge"
getent passwd databastion >/dev/null || fail "the system user was removed"
log "ok"

log "PASS"
