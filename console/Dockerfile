# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# DataBastion console image: one image, four commands (see docker/entrypoint.mjs):
#   web      Next.js standalone server (UI, user API, agent API), port 3000; /metrics on the
#            dedicated listener DATABASTION_METRICS_PORT (e.g. 9464) when set, else on port 3000
#   worker   pg-boss worker
#   migrate  applies the versioned SQL migrations (DATABASE_MIGRATION_URL(_FILE)), then exits
#   bootstrap-admin  creates the first administrator (refused once a user exists)
# Build context: console/ (the generated protocol types are committed under src/generated/).
#   docker build -t databastion-console console/
# Runs as uid/gid 10001 with a read-only root filesystem (only /tmp needs to be writable).
# Runtime: distroless Node.js (glibc, Node.js, CA certificates and tzdata; no shell, no package
# manager). The entrypoint and the healthcheck are Node.js scripts run by the image's own node.
# Base images are pinned by tag AND digest (multi-arch index digest, so the pin holds on amd64 and
# arm64). To update: bump the tag, then take the new index digest, e.g.
#   docker buildx imagetools inspect node:<tag> --format '{{json .Manifest.Digest}}'
#   docker buildx imagetools inspect gcr.io/distroless/nodejs24-debian13:nonroot \
#     --format '{{json .Manifest.Digest}}'

# Node 24 LTS (package.json "engines") for the build stages.
ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
# Runtime: distroless Node.js 24 (Debian 13), `nonroot` tag (the user is overridden below).
# Native modules (@node-rs/argon2) are N-API prebuilt binaries for glibc: built on Debian 12,
# they run on the newer glibc of Debian 13. Node.js 24.21.0 at the time of the pin.
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs24-debian13:nonroot@sha256:bb6b03d81066993293a10feda7250e8e1cc034035fe9b61cfceededa7c8bf04d

# ---------------------------------------------------------------- dependencies
FROM ${NODE_IMAGE} AS deps
WORKDIR /src
ENV COREPACK_HOME=/opt/corepack
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# All dependencies (the build needs the dev ones).
RUN pnpm install --frozen-lockfile

# ---------------------------------------------------------------- build (web)
FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1 NEXT_OUTPUT_STANDALONE=1 NODE_ENV=production
RUN pnpm build

# ------------------------------------------------- production deps (worker, migrate)
FROM ${NODE_IMAGE} AS prod-deps
WORKDIR /src
ENV COREPACK_HOME=/opt/corepack
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# `tsx` is a production dependency: worker / migrate / bootstrap-admin run from TypeScript sources.
RUN pnpm install --frozen-lockfile --prod

# ------------------------------------------------ runtime user (passwd / group entries)
# Distroless has no useradd: the runtime image's own passwd / group files, plus the dedicated
# uid/gid 10001 (no login shell, no home), as in the previous Debian-based runtime.
FROM ${RUNTIME_IMAGE} AS runtime-base
FROM ${NODE_IMAGE} AS users
COPY --from=runtime-base /etc/passwd /etc/group /out/
RUN echo 'databastion:x:10001:10001:DataBastion console:/nonexistent:/sbin/nologin' >> /out/passwd \
 && echo 'databastion:x:10001:' >> /out/group

# ---------------------------------------------------------------- runtime
FROM ${RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="databastion-console" \
      org.opencontainers.image.source="https://github.com/yil00/databastion" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    TSX_DISABLE_CACHE=1 \
    PATH=/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY --from=users --chown=root:root --chmod=0644 /out/passwd /out/group /etc/
WORKDIR /app
# web: Next.js standalone server (traced node_modules only) + static assets.
COPY --from=build --chown=root:root /src/.next/standalone /app/web
COPY --from=build --chown=root:root /src/.next/static /app/web/.next/static
# worker / migrate / bootstrap-admin: sources + migrations + production node_modules.
COPY --from=prod-deps --chown=root:root /src/node_modules /app/console/node_modules
COPY --chown=root:root package.json tsconfig.json /app/console/
COPY --chown=root:root drizzle /app/console/drizzle
COPY --chown=root:root src /app/console/src
COPY --chown=root:root --chmod=0644 docker/entrypoint.mjs docker/healthcheck.mjs /usr/local/lib/databastion/
# Files are owned by root and not writable by the runtime user.
USER 10001:10001
# 9464: suggested DATABASTION_METRICS_PORT (internal network only, never published).
EXPOSE 3000 9464
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/nodejs/bin/node", "/usr/local/lib/databastion/healthcheck.mjs"]
ENTRYPOINT ["/nodejs/bin/node", "/usr/local/lib/databastion/entrypoint.mjs"]
CMD ["web"]
