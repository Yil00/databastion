# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# DataBastion console image: one image, three commands (see docker/entrypoint.sh):
#   web      Next.js standalone server (UI, user API, agent API, /metrics), port 3000
#   worker   pg-boss worker
#   migrate  applies the versioned SQL migrations (DATABASE_MIGRATION_URL(_FILE)), then exits
#   bootstrap-admin  creates the first administrator (refused once a user exists)
# Build context: console/ (the generated protocol types are committed under src/generated/).
#   docker build -t databastion-console console/
# Runs as uid/gid 10001 with a read-only root filesystem (only /tmp needs to be writable).
# Base images are pinned by tag AND digest (multi-arch index digest, so the pin holds on amd64 and
# arm64). To update: bump the tag, then take the new index digest, e.g.
#   docker buildx imagetools inspect node:<tag> --format '{{json .Manifest.Digest}}'

# Node 24 LTS (package.json "engines"); same base for every stage.
ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

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

# ---------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime
LABEL org.opencontainers.image.title="databastion-console" \
      org.opencontainers.image.source="https://github.com/yil00/databastion" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    TSX_DISABLE_CACHE=1
WORKDIR /app
# The node user of the base image is replaced by a dedicated uid/gid 10001 (compose: user 10001:10001).
RUN groupadd --system --gid 10001 databastion \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin databastion
# web: Next.js standalone server (traced node_modules only) + static assets.
COPY --from=build --chown=root:root /src/.next/standalone /app/web
COPY --from=build --chown=root:root /src/.next/static /app/web/.next/static
# worker / migrate / bootstrap-admin: sources + migrations + production node_modules.
COPY --from=prod-deps --chown=root:root /src/node_modules /app/console/node_modules
COPY --chown=root:root package.json tsconfig.json /app/console/
COPY --chown=root:root drizzle /app/console/drizzle
COPY --chown=root:root src /app/console/src
COPY --chown=root:root --chmod=0755 docker/entrypoint.sh docker/healthcheck.sh /usr/local/bin/
# Files are owned by root and not writable by the runtime user.
USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/usr/local/bin/healthcheck.sh"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
