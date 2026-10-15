#!/bin/bash
# DataBastion dev SQL Server (opt-in profile `sqlserver`, ADR-0051 decision 9). DEV-ONLY.
# 1. On the first start of the data volume, a throwaway CA signs a server certificate naming
#    localhost, the compose service name, 127.0.0.1 and ::1 (ADR-0051 decision 2: the fallback
#    self-signed certificate is refused by the connector); the CA key is deleted at once.
# 2. mssql.conf points SQL Server at it with forced encryption (strict encryption, TDS 8.0, with
#    DATABASTION_DEV_SQLSERVER_FORCE_STRICT=1 on images whose mssql-conf knows `forcestrict`).
# 3. sqlservr starts; on the first start the seed (dev/seed/out/sqlserver.sql), the agent account
#    (initdb/20-databastion.sql) and the audit setup (initdb/30-audit.sql) are applied with the
#    image's own sqlcmd as `sa` (dev tooling, never the agent).
# 4. The healthcheck reads a marker written once the server answers, so it never logs in itself
#    (no audit or Extended Events noise).
set -euo pipefail

DATA=/var/opt/mssql
TLS="$DATA/databastion-tls"
READY="$DATA/.databastion-ready"
SEEDED="$DATA/.databastion-seeded"
SQLCMD=(/opt/mssql-tools18/bin/sqlcmd -S 127.0.0.1 -U sa -C -b -I)
# A server forcing strict encryption disconnects a TDS 7.x client (error 17819): the seeding
# sessions then use strict encryption too, with the dev server certificate pinned (-J).
if [ "${DATABASTION_DEV_SQLSERVER_FORCE_STRICT:-0}" = 1 ]; then
  SQLCMD=(/opt/mssql-tools18/bin/sqlcmd -S 127.0.0.1 -U sa -N s -J "$TLS/server.pem" -b -I)
fi
rm -f "$READY"

if [ ! -s "$TLS/server.pem" ] || [ ! -s "$TLS/server.key" ]; then
  mkdir -p "$TLS"
  tmp="$(mktemp -d)"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost,DNS:sqlserver,IP:127.0.0.1,IP:::1' > "$tmp/ext"
  # The CA's extensions from a config file of their own, not -addext: OpenSSL 1.1.1 (the 2019
  # image) adds the default config's v3_ca extensions as well, and a certificate with a duplicate
  # basicConstraints is refused by the agent's verifier.
  printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = v3_ca' 'prompt = no' \
    '[dn]' 'CN = DataBastion dev CA (sqlserver)' '[v3_ca]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' > "$tmp/ca.cnf"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -config "$tmp/ca.cnf" \
    -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=sqlserver" -keyout "$tmp/server.key" \
    -out "$tmp/server.csr" 2>/dev/null
  openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca-key.pem" \
    -CAcreateserial -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/server.pem" 2>/dev/null
  install -m 0644 "$tmp/ca.pem" "$TLS/ca.pem"
  install -m 0644 "$tmp/server.pem" "$TLS/server.pem"
  install -m 0600 "$tmp/server.key" "$TLS/server.key"
  rm -rf "$tmp"
fi

{
  echo "[network]"
  echo "tlscert = $TLS/server.pem"
  echo "tlskey = $TLS/server.key"
  echo "forceencryption = 1"
  if [ "${DATABASTION_DEV_SQLSERVER_FORCE_STRICT:-0}" = 1 ]; then echo "forcestrict = 1"; fi
  echo "[memory]"
  echo "memorylimitmb = ${MSSQL_MEMORY_LIMIT_MB:-2048}"
} > "$DATA/mssql.conf"
mkdir -p "$DATA/audit" "$DATA/xe"

# 2022 and 2025 start sqlservr through launch_sqlservr.sh; the 2019 image has no such wrapper (its
# own entrypoint, permissions_check.sh, only prints a message before running sqlservr).
if [ -x /opt/mssql/bin/launch_sqlservr.sh ]; then
  /opt/mssql/bin/launch_sqlservr.sh /opt/mssql/bin/sqlservr &
else
  /opt/mssql/bin/sqlservr &
fi
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"' TERM INT

for _ in $(seq 1 120); do
  if SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" "${SQLCMD[@]}" -Q "SET NOCOUNT ON; SELECT 1" >/dev/null 2>&1; then break; fi
  kill -0 "$pid" 2>/dev/null || { echo "sqlservr exited during startup" >&2; exit 1; }
  sleep 2
done

if [ ! -f "$SEEDED" ]; then
  echo "databastion: seeding (first start of the volume)"
  export SQLCMDPASSWORD="$MSSQL_SA_PASSWORD"
  "${SQLCMD[@]}" -i /databastion/seed/10-seed.sql >/dev/null
  "${SQLCMD[@]}" -v DATABASTION_PASSWORD="$DATABASTION_SQLSERVER_PASSWORD" -i /databastion/initdb/20-databastion.sql
  "${SQLCMD[@]}" -i /databastion/initdb/30-audit.sql
  unset SQLCMDPASSWORD
  touch "$SEEDED"
  echo "databastion: seed, agent account and audit setup applied"
fi
touch "$READY"
wait "$pid"
