# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# DataBastion agent image.
# Build context: agent/ (the generated protocol types are committed under crates/protocol/).
#   docker build -t databastion-agent agent/
#
# Runtime: distroless `cc` (glibc + libgcc, no shell, no package manager). The binary is
# dynamically linked against glibc (default Rust target, `ring` needs libgcc_s), so `static`
# would require a musl build; `cc` keeps the default, tested target with the smallest
# userland that runs it. Runs as uid/gid 10001 (no passwd entry needed).
#
# Mounts expected at runtime (nothing secret is baked into the image):
#   /etc/databastion/agent.yaml   configuration, read-only
#   /var/lib/databastion          state volume: identity (0600), HMAC key, spool; dir 0700
#   secrets (enrollment token, target passwords) as read-only files referenced by agent.yaml
#
# No HEALTHCHECK: the agent opens no listener (invariant I1), so there is nothing to probe from
# inside the container without a shell; its health is reported by the console (heartbeats,
# `databastion_agent_up`, ADR-0004).
#
# Base images are pinned by tag and digest.

# ---------------------------------------------------------------- build
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build
WORKDIR /src
COPY . .
# Default features (every connector), exactly the lock file.
RUN cargo build --release --locked -p databastion-agent \
 && install -D -m 0755 target/release/databastion-agent /out/databastion-agent \
 && install -d -m 0700 -o 10001 -g 10001 /out/varlib/databastion

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
LABEL org.opencontainers.image.title="databastion-agent" \
      org.opencontainers.image.source="https://github.com/yil00/databastion" \
      org.opencontainers.image.licenses="Apache-2.0"
# Binary owned by root, not writable by the runtime user.
COPY --from=build --chown=0:0 --chmod=0755 /out/databastion-agent /usr/local/bin/databastion-agent
# State directory: owned by the agent user, 0700 (the agent refuses a group / world writable
# state_dir). An empty named volume mounted here inherits this owner and mode.
# The parent is copied so that `databastion/` is itself a copied entry and keeps its 0700 mode:
# copying `/out/state` onto `/var/lib/databastion` would only copy its (empty) contents and
# create the destination directory with the default 0755.
COPY --from=build --chown=10001:10001 /out/varlib/ /var/lib/
USER 10001:10001
VOLUME ["/var/lib/databastion"]
ENTRYPOINT ["/usr/local/bin/databastion-agent"]
CMD ["run", "--config", "/etc/databastion/agent.yaml"]
