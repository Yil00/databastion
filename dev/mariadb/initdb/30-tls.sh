# Sourced by the MariaDB entrypoint after 20-databastion.sh. DEV-ONLY TLS material, so that the
# agent connects with its default `tls: verify_full` and a pinned CA (MariaDB 11.4 otherwise uses
# an in-memory self-signed certificate that names no host). A throwaway CA signs a server
# certificate for 127.0.0.1, ::1, localhost and the compose service name; the CA key is deleted
# once the certificate is signed. databastion.cnf points ssl_ca / ssl_cert / ssl_key here; the
# temporary server of the initialization starts without them (MariaDB logs a TLS warning and goes
# on), the final server loads them. Export the CA for the tests with:
#   docker compose -f dev/docker-compose.yml exec -T mariadb cat /var/lib/mysql/databastion-tls/ca.pem
databastion_dev_tls() {
  local dir=/var/lib/mysql/databastion-tls tmp
  tmp="$(mktemp -d)"
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
}
databastion_dev_tls
