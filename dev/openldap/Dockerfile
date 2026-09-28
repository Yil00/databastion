# OpenLDAP for the DataBastion dev environment, built from Debian's maintained slapd package.
# Why not a third-party image: osixia/openldap is unmaintained since 2021, and the Bitnami catalog
# stopped publishing free versioned tags in 2025 (moved to bitnamilegacy). Debian's slapd receives
# security updates and ships the accesslog overlay as a module.
FROM debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends slapd ldap-utils; \
    rm -rf /var/lib/apt/lists/*; \
    # Drop the package's default configuration and database: the entrypoint builds ours on first start.
    rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*

COPY config.ldif /usr/local/share/databastion/config.ldif
COPY entrypoint.sh /usr/local/bin/databastion-ldap-entrypoint

EXPOSE 389
ENTRYPOINT ["bash", "/usr/local/bin/databastion-ldap-entrypoint"]
