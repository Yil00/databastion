# PostgreSQL + pgaudit (PGDG package; the official image already ships the PGDG apt repository).
# PG_IMAGE: the base image, pinned by tag AND index digest. Default: PostgreSQL 17, the dev and CI
# reference (keep it equal to the default of DATABASTION_DEV_POSTGRES_IMAGE in
# dev/docker-compose.yml; the e2e harnesses build this file without the argument). The
# engine-matrix workflow overrides it. PG_MAJOR comes from the base image: the pgaudit package
# follows it.
ARG PG_IMAGE=postgres:17.11-bookworm@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
FROM ${PG_IMAGE}

# The images of PostgreSQL 18+ default to /var/lib/postgresql/<major>/docker and refuse a volume
# mounted at /var/lib/postgresql/data: the data directory stays there for every major (the value
# the images of 14 to 17 already use).
ENV PGDATA=/var/lib/postgresql/data

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}-pgaudit"; \
    rm -rf /var/lib/apt/lists/*
