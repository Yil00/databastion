# The init step of the dev Firebird service's audit log layout (ADR-0060 refinement of 2026-10-31,
# R52 item 1): `setfacl` on the image the service already pins (Firebird 5.0.4, Debian 13), so no
# other base image is pulled. Runs once per `make dev-firebird` as firebird-audit-init, as root with
# CHOWN, FOWNER and DAC_OVERRIDE only, no network. The `acl` package is not version-pinned yet:
# its Debian 13 version is to be confirmed with a build before it is pinned (dev only; the base
# image itself is pinned by digest).
FROM firebirdsql/firebird:5.0.4@sha256:1529560400fc7847f015c57fc9d70729c44d9a9d8f9000df19c5ce1950b4c202

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends acl; \
    rm -rf /var/lib/apt/lists/*; \
    command -v setfacl getfacl

COPY layout.sh /databastion/acl-layout.sh
ENTRYPOINT ["/bin/sh", "/databastion/acl-layout.sh"]
