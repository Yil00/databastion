#!/usr/bin/env bash
# First start: build cn=config, load the seed and the service account offline, then run slapd.
set -euo pipefail

: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required (dev/.env)}"
: "${DATABASTION_DB_PASSWORD:?DATABASTION_DB_PASSWORD is required (dev/.env)}"
SEED_LDIF=${SEED_LDIF:-/seed/openldap.ldif}
SERVICE_DN="cn=databastion,ou=services,dc=example,dc=org"
CONF_DIR=/etc/ldap/slapd.d

if [ ! -e "$CONF_DIR/cn=config.ldif" ]; then
  echo "databastion-ldap: initializing configuration and seed" >&2
  tmp=$(mktemp -d)
  admin_hash=$(slappasswd -h '{SSHA}' -s "$LDAP_ADMIN_PASSWORD")
  service_hash=$(slappasswd -h '{SSHA}' -s "$DATABASTION_DB_PASSWORD")
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

mkdir -p /run/slapd
chown -R openldap:openldap "$CONF_DIR" /var/lib/ldap /run/slapd
# ldapi:// is used by the healthcheck only (EXTERNAL bind as root, cn=config): it never touches the
# audited database, so healthchecks do not pollute cn=accesslog.
exec slapd -d stats -u openldap -g openldap -F "$CONF_DIR" -h "ldap:/// ldapi:///"
