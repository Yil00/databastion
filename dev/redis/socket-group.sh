#!/usr/bin/env bash
# Prints the gid that the opt-in override redis/compose.socket.yml may give the dev Valkey / Redis
# servers (DATABASTION_DEV_REDIS_SOCKET_GID), and refuses (exit 1) a group another user is in
# (#317 security review L2): whoever is in that group can connect to the published sockets.
#
#   dev/redis/socket-group.sh          the current user's primary group
#   dev/redis/socket-group.sh <group>  a dedicated group (name or gid, made with `groupadd`)
#
# Accepted only when the current user is in the group (as primary group or member), no other user
# is a member, no other user has it as primary group, and it is not gid 0: a private group (the
# usual Debian, Ubuntu and Fedora scheme) passes, a shared `users` / `staff` / `docker` does not.
# Users from a directory service that `getent passwd` does not list are not seen.
set -euo pipefail

user="$(id -un)"
refuse() {
  echo "dev/redis/socket-group.sh: $1; use a dedicated group (dev/README.md)" >&2
  exit 1
}

entry="$(getent group "${1:-$(id -g)}")" || refuse "no group ${1:-$(id -g)}"
IFS=: read -r name _ gid members <<<"$entry"
[ "$gid" != 0 ] || refuse "gid 0 (root) is never used"
[ -z "$members" ] || [ "$members" = "$user" ] || refuse "group $name has other members: $members"
others="$(getent passwd | awk -F: -v g="$gid" -v u="$user" '$4 == g && $1 != u { print $1 }' | paste -sd, -)"
[ -z "$others" ] || refuse "group $name is the primary group of $others"
[ "$(id -g "$user")" = "$gid" ] || [ "$members" = "$user" ] || refuse "$user is not in group $name"
echo "$gid"
