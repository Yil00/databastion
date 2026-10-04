#!/bin/sh
# One-shot of the opt-in CAS dev service (Compose service `cas-files-init`: busybox as root, no
# network, CHOWN / DAC_OVERRIDE / FOWNER / FSETID only; FSETID keeps the setgid bit of a directory
# whose group is not root's). Gives the host-mounted CAS files the permissions
# of ADR-0041 decision 6: owner the CAS user, group the agent's group, nothing writable by the
# agent, nothing readable by others.
# Only dev/.state/cas and dev/.state/logs are mounted (at /state/cas and /state/logs; `make dev-dirs`
# creates them), never the rest of dev/.state (the metrics token).
#   setup  dev/cas/services (mounted at /src/services) copied to dev/.state/cas/services: directory
#          0750, files 0640; dev/.state/logs/cas (CAS writes cas_audit.log there, 0640): directory
#          2750, setgid so that every log file gets the agent's group.
#   clean  removes both (`make dev-reset`: the host user cannot, they are not theirs).
# CAS_UID is the CAS user of dev/cas/Dockerfile; AGENT_GID the agent's group (10001 in the agent
# and e2e images; DATABASTION_DEV_AGENT_GID changes it).
set -eu
CAS_UID=10041
AGENT_GID=${DATABASTION_DEV_AGENT_GID:-10001}
case "$AGENT_GID" in '' | *[!0-9]*) echo "files-init: DATABASTION_DEV_AGENT_GID must be numeric" >&2; exit 1 ;; esac
[ "$AGENT_GID" -ne 0 ] || { echo "files-init: DATABASTION_DEV_AGENT_GID must not be 0" >&2; exit 1; }

# dir <path> <mode>: owner CAS_UID, group AGENT_GID, then the mode (chmod after chown: chown
# clears the setgid bit).
dir() {
  mkdir -p "$1"
  chown "$CAS_UID:$AGENT_GID" "$1"
  chmod "$2" "$1"
}

case "${1:-setup}" in
setup)
  reg=/state/cas/services
  dir "$reg" 0750
  # Synchronized in place (CAS keeps the directory mounted): stale entries go, every definition
  # is (re)installed as a fresh single-link file.
  for f in "$reg"/* "$reg"/.[!.]*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    [ -f "/src/services/${f##*/}" ] && [ ! -L "$f" ] || rm -rf "$f"
  done
  n=0
  for f in /src/services/*.json; do
    [ -f "$f" ] || continue
    rm -f "$reg/${f##*/}"
    install -o "$CAS_UID" -g "$AGENT_GID" -m 0640 "$f" "$reg/${f##*/}"
    n=$((n + 1))
  done
  logs=/state/logs/cas
  dir "$logs" 2750
  # Regular files only, never through a symlink (CAS, which owns the directory, may be running).
  find "$logs" -mindepth 1 -type f ! -type l -exec chown -h "$CAS_UID:$AGENT_GID" {} + \
    -exec chmod 0640 {} +
  echo "files-init: $n service definition(s) staged; registry 0750 and log directory 2750, owner $CAS_UID, group $AGENT_GID"
  ;;
clean)
  rm -rf /state/cas/services /state/logs/cas
  ;;
*)
  echo "usage: files-init.sh setup|clean" >&2
  exit 2
  ;;
esac
