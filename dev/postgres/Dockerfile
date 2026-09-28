# PostgreSQL 17 + pgaudit (PGDG package; the official image already ships the PGDG apt repository).
FROM postgres:17.11-bookworm@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}-pgaudit"; \
    rm -rf /var/lib/apt/lists/*
