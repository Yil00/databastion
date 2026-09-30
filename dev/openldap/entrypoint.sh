#!/usr/bin/env bash
# First start: build cn=config, load the seed and the service account offline, then run slapd.
set -euo pipefail

# Each password comes from the environment (dev/.env) or, when <VAR>_FILE is set, from that file (the
# e2e harness passes Docker secrets: the password is then neither in the environment nor on a
# command line, `slappasswd -T` hashes the file's contents as they are, so no trailing newline).
if [ -z "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then
  : "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required (dev/.env)}"
fi
if [ -z "${DATABASTION_DB_PASSWORD_FILE:-}" ]; then
  : "${DATABASTION_DB_PASSWORD:?DATABASTION_DB_PASSWORD is required (dev/.env)}"
fi
# ssha VAR: the {SSHA} hash of the password in $VAR, or in the file named by $VAR_FILE.
ssha() {
  local file_var="${1}_FILE" h
  if [ -n "${!file_var:-}" ]; then
    # slappasswd warns on stderr about a file readable by others (Docker secrets are).
    h=$(slappasswd -h '{SSHA}' -T "${!file_var}" 2>/dev/null)
  else
    h=$(slappasswd -h '{SSHA}' -s "${!1}")
  fi
  [ -n "$h" ] || { echo "databastion-ldap: cannot hash $1" >&2; return 1; }
  printf '%s' "$h"
}
SEED_LDIF=${SEED_LDIF:-/seed/openldap.ldif}
SERVICE_DN="cn=databastion,ou=services,dc=example,dc=org"
CONF_DIR=/etc/ldap/slapd.d

if [ ! -e "$CONF_DIR/cn=config.ldif" ]; then
  echo "databastion-ldap: initializing configuration and seed" >&2
  tmp=$(mktemp -d)
  admin_hash=$(ssha LDAP_ADMIN_PASSWORD)
  service_hash=$(ssha DATABASTION_DB_PASSWORD)
  sed -e "s|@ADMIN_PW_HASH@|${admin_hash}|" -e "s|@SERVICE_DN@|${SERVICE_DN}|g" \
    /usr/local/share/databastion/config.ldif > "$tmp/config.ldif"
  mkdir -p /var/lib/ldap/accesslog /var/lib/ldap/data /run/slapd
  slapadd -n 0 -F "$CONF_DIR" -l "$tmp/config.ldif"
  {
    cat "$SEED_LDIF"
    printf '\ndn: %s\nobjectClass: applicationProcess\nobjectClass: simpleSecurityObject\ncn: databastion\ndescription: DataBastion agent read-only service account (dev only)\nuserPassword: %s\n' \
      "$SERVICE_DN" "$service_hash"
  } > "$tmp/data.ldif"
  slapadd -F "$CONF_DIR" -b dc=example,dc=org -l "$tmp/data.ldif"
  rm -rf "$tmp"
fi

# DEV ONLY TLS: a CA and a server certificate for localhost / 127.0.0.1 / openldap, generated once
# per data volume. The CA key is deleted at once; tests read ca.pem with `docker compose exec`.
TLS_DIR=/var/lib/ldap/tls
if [ ! -e "$TLS_DIR/server.pem" ]; then
  echo "databastion-ldap: generating the dev-only TLS certificates" >&2
  mkdir -p "$TLS_DIR"
  tmp=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=DataBastion dev LDAP CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$tmp/ca.key" -out "$TLS_DIR/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$TLS_DIR/server.key" -out "$tmp/server.csr" 2>/dev/null
  printf '%s\n' "subjectAltName=DNS:localhost,DNS:openldap,IP:127.0.0.1,IP:::1" "basicConstraints=CA:FALSE" \
    "keyUsage=digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" > "$tmp/ext.cnf"
  openssl x509 -req -in "$tmp/server.csr" -CA "$TLS_DIR/ca.pem" -CAkey "$tmp/ca.key" \
    -CAcreateserial -days 3650 -extfile "$tmp/ext.cnf" -out "$TLS_DIR/server.pem" 2>/dev/null
  rm -rf "$tmp"
  chmod 0640 "$TLS_DIR/server.key"
fi

mkdir -p /run/slapd
chown -R openldap:openldap "$CONF_DIR" /var/lib/ldap /run/slapd
# ldapi:// is used by the healthcheck only (EXTERNAL bind as root, cn=config): it never touches the
# audited database, so healthchecks do not pollute cn=accesslog.
exec slapd -d stats -u openldap -g openldap -F "$CONF_DIR" -h "ldap:/// ldaps:/// ldapi:///"
