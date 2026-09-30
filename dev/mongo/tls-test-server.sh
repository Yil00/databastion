#!/usr/bin/env bash
# Throwaway TLS-only MongoDB server for the MongoDB connector's TLS integration test
# (`verify_full` against a real server; connector-mongodb/src/it.rs, `tls_real_server_*`).
#
#   dev/mongo/tls-test-server.sh start   # generate a test CA, start the server, create the
#                                        # ADR-0026 agent account; prints the test environment
#   dev/mongo/tls-test-server.sh stop    # remove the container and the generated files
#
# Same pinned image as the dev `mongo` service (dev/docker-compose.yml), started with
# `--tlsMode requireTLS` and `--auth`, published on 127.0.0.1 only (DATABASTION_MONGO_TLS_PORT,
# default 27018). The CA and the server key are generated at run time in a private temporary
# directory (DATABASTION_MONGO_TLS_DIR, default $RUNNER_TEMP or /tmp, then
# databastion-mongo-tls) and deleted by `stop`; the CA private key is deleted as soon as the server
# certificate is signed. Nothing generated here is ever committed.
#
# The server certificate names `localhost` only (no IP address SAN), so the test also checks that
# `verify_full` refuses the same server reached as 127.0.0.1. Dev-only passwords from
# dev/.env.example.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEV="$(dirname "$HERE")"
BASE="${DATABASTION_MONGO_TLS_DIR:-${RUNNER_TEMP:-/tmp}/databastion-mongo-tls}"
PORT="${DATABASTION_MONGO_TLS_PORT:-27018}"
NAME=databastion-mongo-tls
# Dev-only credentials (dev/.env.example).
set -a
# shellcheck disable=SC1091
. "$DEV/.env.example"
set +a

image() {
  sed -n 's/^    image: \(mongo:[^ ]*@sha256:[0-9a-f]*\)$/\1/p' "$DEV/docker-compose.yml" | head -n 1
}

shell() {
  # mongosh inside the container, over TLS, verified against the test CA.
  docker exec "$NAME" mongosh --quiet --norc --tls --tlsCAFile /tls/ca.pem "$@"
}

start() {
  local img
  img="$(image)"
  [ -n "$img" ] || { echo "no pinned mongo image in dev/docker-compose.yml" >&2; exit 1; }
  stop >/dev/null 2>&1 || true
  mkdir -p "$BASE"
  chmod 0755 "$BASE"
  local tmp
  tmp="$(mktemp -d)"
  # Test CA and a server certificate for `localhost` only.
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=DataBastion test MongoDB CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$tmp/ca.key" -out "$BASE/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$tmp/server.key" -out "$tmp/server.csr" 2>/dev/null
  printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$tmp/ext.cnf"
  openssl x509 -req -in "$tmp/server.csr" -CA "$BASE/ca.pem" -CAkey "$tmp/ca.key" \
    -CAcreateserial -days 2 -extfile "$tmp/ext.cnf" -out "$tmp/server.crt" 2>/dev/null
  cat "$tmp/server.crt" "$tmp/server.key" > "$BASE/server.pem"
  rm -rf "$tmp"
  # Read by mongod as the image's `mongodb` user (dev only, throwaway key).
  chmod 0644 "$BASE/ca.pem" "$BASE/server.pem"
  docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:27017" -v "$BASE:/tls:ro" "$img" \
    mongod --bind_ip_all --auth --tlsMode requireTLS \
    --tlsCertificateKeyFile /tls/server.pem --tlsCAFile /tls/ca.pem \
    --tlsAllowConnectionsWithoutCertificates >/dev/null
  local i
  for i in $(seq 1 60); do
    if shell "mongodb://localhost:27017/admin" --eval 'db.runCommand({ping: 1})' >/dev/null 2>&1; then
      break
    fi
    [ "$i" = 60 ] && { docker logs --tail 100 "$NAME" >&2; exit 1; }
    sleep 1
  done
  # Localhost exception: the first user, then the ADR-0026 role and account and a probe collection
  # holding FAKE values (reserved example.com domain).
  shell "mongodb://localhost:27017/admin" --eval "
    db.createUser({user: 'root', pwd: '${MONGO_ROOT_PASSWORD}', roles: ['root']});" >/dev/null
  shell "mongodb://root:${MONGO_ROOT_PASSWORD}@localhost:27017/admin?authSource=admin" --eval "
    db.createRole({role: 'databastionDiscovery',
      privileges: [{resource: {db: 'app', collection: ''}, actions: ['find', 'listCollections']}],
      roles: []});
    db.createUser({user: 'databastion', pwd: '${DATABASTION_DB_PASSWORD}',
      mechanisms: ['SCRAM-SHA-256'], roles: [{role: 'databastionDiscovery', db: 'admin'}]});
    const app = db.getSiblingDB('app');
    const docs = [];
    for (let i = 0; i < 50; i++) { docs.push({n: i, email: 'tls.probe' + i + '@example.com'}); }
    app.tls_probe.insertMany(docs);" >/dev/null
  cat <<EOF
export DATABASTION_TEST_MONGO_TLS_URL='mongodb://databastion:${DATABASTION_DB_PASSWORD}@localhost:${PORT}/app?authSource=admin'
export DATABASTION_TEST_MONGO_TLS_CA_FILE='${BASE}/ca.pem'
EOF
}

stop() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$BASE"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
