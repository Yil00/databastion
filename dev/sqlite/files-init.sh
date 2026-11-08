#!/bin/sh
# One-shot of the opt-in SQLite dev profile (Compose service `sqlite-files-init`: busybox as root, no
# network, CHOWN / DAC_OVERRIDE / FOWNER / FSETID only). Gives the directory of the seeded SQLite
# files the permissions of ADR-0059 decision 2: owner the application's account, group the agent's
# group, mode 2750 (setgid: every file the writer creates there, its -wal, -shm and -journal
# included, gets the agent's group), so the agent's account can read and never write. Only
# dev/.state/sqlite is mounted (at /state; `make dev-dirs` creates it), never the rest of dev/.state.
#   setup  creates dev/.state/sqlite/data (2750, owner SQLITE_UID, group AGENT_GID); existing files
#          keep their content, their owner and group are reset and their mode set to 0640.
#   clean  removes it (`make dev-reset`: the host user cannot, the files are not theirs).
# SQLITE_UID is the application's account (the writer sidecar runs as it; 10020 by default,
# DATABASTION_DEV_SQLITE_UID changes it); AGENT_GID the agent's group (10001 in the agent and e2e
# images; DATABASTION_DEV_AGENT_GID changes it). Neither may be 0, nor equal to each other's role:
# the agent's account must not own the files.
set -eu
SQLITE_UID=${DATABASTION_DEV_SQLITE_UID:-10020}
AGENT_GID=${DATABASTION_DEV_AGENT_GID:-10001}
for v in "$SQLITE_UID" "$AGENT_GID"; do
  case "$v" in '' | *[!0-9]*) echo "files-init: the uid and gid must be numeric" >&2; exit 1 ;; esac
  [ "$v" -ne 0 ] || { echo "files-init: the uid and gid must not be 0" >&2; exit 1; }
done
[ "$SQLITE_UID" -ne 10001 ] || { echo "files-init: the application's uid must not be the agent's (10001)" >&2; exit 1; }

data=/state/data
case "${1:-setup}" in
setup)
  mkdir -p "$data"
  chown "$SQLITE_UID:$AGENT_GID" "$data"
  # After chown, which clears the setgid bit.
  chmod 2750 "$data"
  find "$data" -mindepth 1 -maxdepth 1 -type f ! -type l -exec chown -h "$SQLITE_UID:$AGENT_GID" {} + \
    -exec chmod 0640 {} +
  echo "files-init: SQLite directory 2750, owner $SQLITE_UID, group $AGENT_GID"
  ;;
clean)
  rm -rf "$data"
  ;;
*)
  echo "usage: files-init.sh setup|clean" >&2
  exit 2
  ;;
esac
