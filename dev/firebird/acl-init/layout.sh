#!/bin/sh
# The dev audit log layout (ADR-0060 refinement of 2026-10-31, R52 item 1): the server (uid 84)
# owns the directory and the log, no group or other access, and the agent (uid
# DATABASTION_DEV_AGENT_UID, 10001 by default) reads them through a named-user ACL; the directory's
# default ACL gives the next log file (after a rotation) the same entries. No group grants read, so
# the readers check holds with any host group file (R47 item 4).
#   log:                u::rw,g::---,o::---,u:<agent>:r      (mask r)
#   directory, access:  u::rwx,g::---,o::---,u:<agent>:rx    (mask rx)
#   directory, default: u::rw,g::---,m::r,o::---,u:<agent>:r
# Applied again at every start: a volume prepared by the earlier group layout (0640, directory
# 2750 with the agent's gid) is moved to this one.
set -eu
A="${DATABASTION_DEV_AGENT_UID:-10001}"
case "$A" in '' | *[!0-9]*) echo "acl-layout: DATABASTION_DEV_AGENT_UID must be numeric" >&2; exit 1 ;; esac
[ "$A" -ne 0 ] && [ "$A" -ne 84 ] || { echo "acl-layout: DATABASTION_DEV_AGENT_UID must not be 0 or 84" >&2; exit 1; }
D=/a
L="$D/audit.log"
# Security review N7: never follow a link planted on the volume.
for p in "$D" "$L"; do
  [ ! -L "$p" ] || { echo "acl-layout: a symbolic link on the volume, refused" >&2; exit 1; }
done
[ -e "$L" ] || touch "$L"
[ -f "$L" ] || { echo "acl-layout: the log is not a regular file" >&2; exit 1; }
chown -h 84:84 "$D" "$L"
chmod 0700 "$D"
chmod 0600 "$L"
setfacl -P -b "$D" "$L"
setfacl -P -k "$D"
setfacl -P -m "u::rwx,g::---,o::---,u:$A:rx,m::rx" "$D"
setfacl -P -d -m "u::rw,g::---,m::r,o::---,u:$A:r" "$D"
setfacl -P -m "u::rw,g::---,o::---,u:$A:r,m::r" "$L"
# Rotated files already there: the log's entries. The server names them audit.<timestamp>.log
# (PluginLogWriter, at the last dot of the log's name); an external rotation, audit.log.* or
# audit.log-*.
for f in "$D"/audit.*.log "$L".* "$L"-*; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  chown -h 84:84 "$f"
  chmod 0600 "$f"
  setfacl -P -b "$f"
  setfacl -P -m "u::rw,g::---,o::---,u:$A:r,m::r" "$f"
done
getfacl -cp "$D" "$L" >/dev/null
echo "firebird audit layout: named-user ACLs for uid $A"
