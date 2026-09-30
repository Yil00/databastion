#!/bin/sh
# Generates the console secrets of the Docker Compose deployment (deploy/README.md) into ./secrets.
#
#   ./init-secrets.sh
#
# Idempotent: an existing file is never overwritten (the database passwords are fixed at the first
# `docker compose up`; the encryption key protects stored data). The connection URLs are derived
# from the password files. Requires openssl.
#
# The files are 0644 inside a 0700 directory: Compose bind-mounts each one into containers that run
# as other users (postgres, 10001), and the directory keeps every other host user out.
set -eu

cd "$(dirname "$0")"
umask 077
mkdir -p secrets
chmod 0700 secrets

# put NAME VALUE: writes secrets/NAME (no trailing newline) unless it exists.
put() {
  if [ -e "secrets/$1" ]; then
    echo "secrets/$1: kept"
    return
  fi
  printf '%s' "$2" >"secrets/$1.tmp"
  chmod 0644 "secrets/$1.tmp"
  mv "secrets/$1.tmp" "secrets/$1"
  echo "secrets/$1: created"
}

put db_password "$(openssl rand -hex 24)"         # bootstrap superuser (initdb only)
put db_owner_password "$(openssl rand -hex 24)"   # databastion_owner (migrate)
put db_app_password "$(openssl rand -hex 24)"     # databastion_runtime (web, worker)
put db_owner_url "postgresql://databastion_owner:$(cat secrets/db_owner_password)@db:5432/databastion"
put db_url "postgresql://databastion_runtime:$(cat secrets/db_app_password)@db:5432/databastion"
put encryption_key "$(openssl rand -base64 32)"   # keep a copy offline: stored secrets need it
put metrics_token "$(openssl rand -hex 32)"       # also given to Prometheus
# First administrator's password, read by `docker compose run --rm bootstrap-admin`. Replace it
# with your own (12 to 128 characters) before that step if you prefer; delete the file afterwards.
put admin_password "$(openssl rand -base64 18)"
