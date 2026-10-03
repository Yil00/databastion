#!/bin/bash
# Entrypoint wrapper of the MariaDB dev service (dev, e2e and load compose files): creates the
# DEV-ONLY TLS material that databastion.cnf points ssl_ca / ssl_cert / ssl_key to, then hands over
# to the image's docker-entrypoint.sh with the original arguments.
#
# The material must exist before any server starts: MariaDB 10.11 aborts on a missing ssl_* file
# (`SSL_CTX_set_default_verify_paths failed`), including the temporary server of the
# initialization, where 11.4 and later only log a warning. A throwaway CA signs a server
# certificate for 127.0.0.1, ::1, localhost and the compose service name `mariadb`; the CA key is
# deleted once the certificate is signed. Everything lives in the data directory, so the CA the
# tests pin stays the same across restarts; it is only created when a file is missing (a new data
# volume or tmpfs). Export the CA for the tests with:
#   docker compose -f dev/docker-compose.yml exec -T mariadb cat /var/lib/mysql/databastion-tls/ca.pem
set -euo pipefail

databastion_dev_tls() {
  local dir=/var/lib/mysql/databastion-tls tmp
  if [ -s "$dir/ca.pem" ] && [ -s "$dir/server-cert.pem" ] && [ -s "$dir/server-key.pem" ]; then
    return 0
  fi
  tmp="$(mktemp -d)"
  # The throwaway CA key must not outlive a failed step (set -e): removed on any exit.
  # shellcheck disable=SC2064 # expanded now: $tmp is local to this function
  trap "rm -rf '$tmp'" EXIT
  mkdir -p "$dir"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost,DNS:mariadb,IP:127.0.0.1,IP:::1' > "$tmp/ext"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=DataBastion dev CA (mariadb)" \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=mariadb" -keyout "$tmp/server-key.pem" \
    -out "$tmp/server.csr" 2>/dev/null
  openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca-key.pem" \
    -CAcreateserial -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/server-cert.pem" 2>/dev/null
  install -m 0644 "$tmp/ca.pem" "$dir/ca.pem"
  install -m 0644 "$tmp/server-cert.pem" "$dir/server-cert.pem"
  install -m 0600 "$tmp/server-key.pem" "$dir/server-key.pem"
  rm -rf "$tmp"
  trap - EXIT
  # Started as root (the image default): the server runs as `mysql` and must read the key.
  if [ "$(id -u)" = 0 ]; then
    chown -R mysql:mysql "$dir"
  fi
  echo "databastion-tls-entrypoint: created the dev-only TLS material in $dir" >&2
}

# Only for a server start (the image's own test, as in docker-entrypoint.sh), not for a one-off
# command such as `mariadbd --help` or a shell.
case "${1:-}" in
  mariadbd | mysqld | -*) databastion_dev_tls ;;
esac

exec docker-entrypoint.sh "$@"
