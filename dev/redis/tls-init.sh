#!/bin/sh
# DEV-ONLY TLS material for the `valkey` and `redis` services (one-shot `redis-tls-init`, run in the
# pinned PostgreSQL image for its openssl: the Valkey and Redis images have none). On the first run
# of the `redis-tls` volume, a throwaway CA signs a server certificate naming localhost, both
# service names, 127.0.0.1 and ::1; the CA key is deleted at once. The files belong to uid 999
# (the servers' user in both images). Export the CA with:
#   docker compose -f dev/docker-compose.yml --profile redis exec -T valkey cat /tls/ca.pem
set -eu
dir=/tls
if [ -s "$dir/server.pem" ] && [ -s "$dir/server.key" ]; then exit 0; fi
tmp="$(mktemp -d)"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost,DNS:valkey,DNS:redis,IP:127.0.0.1,IP:::1' > "$tmp/ext"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=DataBastion dev CA (redis)" \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=valkey" -keyout "$tmp/server.key" -out "$tmp/server.csr" 2>/dev/null
openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca-key.pem" -CAcreateserial \
  -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/server.pem" 2>/dev/null
install -o 999 -g 999 -m 0644 "$tmp/ca.pem" "$dir/ca.pem"
install -o 999 -g 999 -m 0644 "$tmp/server.pem" "$dir/server.pem"
install -o 999 -g 999 -m 0600 "$tmp/server.key" "$dir/server.key"
rm -rf "$tmp"
