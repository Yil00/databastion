# Sourced by the MySQL entrypoint after 20-databastion.sh. DEV-ONLY TLS material, so that the agent
# connects with its default `tls: verify_full` and a pinned CA (the certificates MySQL generates
# itself name no host). A throwaway CA signs a server certificate for 127.0.0.1, ::1, localhost and
# the compose service name; the CA key is deleted once the certificate is signed. MySQL reads
# ca.pem / server-cert.pem / server-key.pem from its data directory at the next start (the final
# server started after initialization). Export the CA for the tests with:
#   docker compose -f dev/docker-compose.yml exec -T mysql cat /var/lib/mysql/ca.pem
databastion_dev_tls() {
  local dir=/var/lib/mysql tmp
  tmp="$(mktemp -d)"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost,DNS:mysql,IP:127.0.0.1,IP:::1' > "$tmp/ext"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=DataBastion dev CA (mysql)" \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$tmp/ca-key.pem" -out "$tmp/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=mysql" -keyout "$tmp/server-key.pem" \
    -out "$tmp/server.csr" 2>/dev/null
  openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca-key.pem" \
    -CAcreateserial -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/server-cert.pem" 2>/dev/null
  install -m 0644 "$tmp/ca.pem" "$dir/ca.pem"
  install -m 0644 "$tmp/server-cert.pem" "$dir/server-cert.pem"
  install -m 0600 "$tmp/server-key.pem" "$dir/server-key.pem"
  # Auto-generated material signed by MySQL's own CA: no longer consistent with ca.pem.
  rm -f "$dir/ca-key.pem" "$dir/client-cert.pem" "$dir/client-key.pem"
  rm -rf "$tmp"
}
databastion_dev_tls
