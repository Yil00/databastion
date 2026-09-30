# Deploying DataBastion

How to install the console (Docker Compose) and the agent (`.deb` package with a systemd
service), and how to verify what you download. The CI runs this exact path and times it:
[Installation test](#installation-test-under-15-minutes).

| File | Role |
|------|------|
| [docker-compose.example.yml](docker-compose.example.yml) | Console: web, worker, migrations, internal PostgreSQL, optional Caddy HTTPS proxy |
| [docker-compose.own-proxy.example.yml](docker-compose.own-proxy.example.yml) | Publishes the console on `127.0.0.1:8080` for your own reverse proxy (instead of Caddy) |
| [.env.example](.env.example) | Settings read by Compose (image, DNS name, TLS mode) |
| [init-secrets.sh](init-secrets.sh) | Generates the console secrets into `./secrets` |
| [Caddyfile](Caddyfile) | HTTPS reverse proxy of the `proxy` profile |
| [initdb/](initdb/) | Console database roles (first start of PostgreSQL) |
| [deb/](deb/) | Agent `.deb`: nfpm configuration, systemd unit, maintainer scripts, build and test scripts |
| [install-test.sh](install-test.sh) | The timed installation test (CI) |
| [console-image-smoke.sh](console-image-smoke.sh) | Seconds-long check of a built console image (CI) |

Supported: console on any Linux host with Docker Engine and Compose v2; agent `.deb` on Debian 12
and Ubuntu 24.04 (amd64, arm64), with systemd. The agent image (`ghcr.io/yil00/databastion-agent`)
is the alternative for container hosts ([agent README](../agent/README.md#docker-image)).

## Verify the artifacts
Every release publishes, from [publish.yml](../.github/workflows/publish.yml) only:

- `ghcr.io/yil00/databastion-console` and `ghcr.io/yil00/databastion-agent`: multi-architecture
  (amd64, arm64) images, distroless (no shell, no package manager), non-root (uid 10001), base
  images pinned by digest, signed with cosign *keyless* (GitHub OIDC, Sigstore public-good
  instance), with an SBOM (SPDX) and a SLSA provenance attestation per platform;
- on the GitHub release: `databastion-agent_<version>_<arch>.deb` (amd64, arm64), built from the
  binary of the signed agent image; `databastion-deploy-<version>.tar.gz`, the deployment files of
  this directory (a reproducible `git archive` of `deploy/` at the tag); `image-digests.txt` (the
  two image references with their digest); `SHA256SUMS` of those files, and its cosign bundle
  `SHA256SUMS.cosign.bundle`.

Signatures are made only by the publish workflow of this repository, **in the run triggered by the
push of the release tag** ([ADR-0034](../docs/adr/0034-release-signing-from-tag-push.md)), so the
exact certificate identity is known for each version: check it exactly, not with a pattern. Install
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3 or later (the release
bundles use the Sigstore bundle format), then:

```bash
VERSION=0.1.0
ID=(--certificate-identity "https://github.com/Yil00/databastion/.github/workflows/publish.yml@refs/tags/$VERSION"
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
    --certificate-github-workflow-trigger push)

# Release files first: the checksum list, then every file against it.
base="https://github.com/Yil00/databastion/releases/download/$VERSION"
curl -fsSL -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.cosign.bundle" -O "$base/image-digests.txt"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle "${ID[@]}"
sha256sum --check --ignore-missing SHA256SUMS

# Images, by the digests of the verified image-digests.txt. Stops at the first failure (the
# subshell keeps `exit` from closing your terminal): do not install anything if it prints FAILED.
(
  while read -r ref; do
    cosign verify "$ref" "${ID[@]}" >/dev/null || { echo "FAILED: $ref"; exit 1; }
    echo "verified: $ref"
  done < image-digests.txt
) && echo "all images verified"

# SBOM and provenance of each platform (attached to the signed index, so covered by the signature).
agent_ref="$(grep '/databastion-agent:' image-digests.txt)"
docker buildx imagetools inspect "$agent_ref" --format '{{json .SBOM}}'
docker buildx imagetools inspect "$agent_ref" --format '{{json .Provenance}}'
```

A tag can be moved in a registry; a digest cannot. **Pinning the digest is required**: `.env` takes
the console line of the verified `image-digests.txt`
(`DATABASTION_CONSOLE_IMAGE=ghcr.io/yil00/databastion-console:0.1.0@sha256:<digest>`), and Compose
then pulls exactly that image.

## Install
About 10 minutes on a prepared host, most of it the image download. You need:

- a Linux host for the console with Docker Engine and Compose v2, `openssl`, `curl`; a DNS name for
  the console that the agents can resolve (e.g. `databastion.example.com`); ports 80 and 443 if you
  use the bundled HTTPS proxy;
- on each database host: Debian 12 or Ubuntu 24.04 with systemd, outbound HTTPS to the console.
  The agent accepts no inbound connection (invariant I1): no firewall opening is needed on that host.

### 1. Console
On the console host, in an empty directory (as a user allowed to run `docker`), with the
`SHA256SUMS` verified [above](#verify-the-artifacts):

```bash
VERSION=0.1.0
curl -fsSLO "https://github.com/Yil00/databastion/releases/download/$VERSION/databastion-deploy-$VERSION.tar.gz"
sha256sum --check --ignore-missing SHA256SUMS            # must print "databastion-deploy-...: OK"
tar -xzf "databastion-deploy-$VERSION.tar.gz" --strip-components=2 "databastion-deploy-$VERSION/deploy"
cp docker-compose.example.yml compose.yaml
cp .env.example .env
```

Edit `.env`: `DATABASTION_CONSOLE_IMAGE` (the console line of `image-digests.txt`, digest
included), `DATABASTION_DOMAIN` (the console's DNS name) and `DATABASTION_TLS`:

- your e-mail address: the bundled Caddy proxy gets a Let's Encrypt certificate (the DNS name must
  reach this host on ports 80 and 443);
- `internal`: a certificate from Caddy's own CA, for a name that is not reachable from the Internet;
  the agents then pin that CA (step 2). Your browser will warn until you trust the same root
  certificate.

Then generate the secrets and start:

```bash
./init-secrets.sh                        # ./secrets: database passwords, encryption key, ...
docker compose --profile proxy up -d     # pulls the images, runs the migrations, starts everything
```

`secrets/encryption_key` protects the secrets the console stores (notification channels, masked
samples): keep a copy offline.

**Your own reverse proxy instead of Caddy**: `cp docker-compose.own-proxy.example.yml
compose.own-proxy.yaml`, add `COMPOSE_FILE=compose.yaml:compose.own-proxy.yaml` to `.env`, start
with `docker compose up -d` (no `proxy` profile), and put your HTTPS reverse proxy (TLS 1.3
available, one hop that overwrites `X-Forwarded-For`, `/metrics` not forwarded) in front of
`127.0.0.1:8080`; adapt the steps that mention Caddy. The console trusts one proxy hop
(`DATABASTION_TRUST_PROXY=1`): a local process connecting to `127.0.0.1:8080` directly could choose
the client address the rate limits see, which is why the bundled-proxy setup publishes no port.

Create the first administrator, then log in at `https://<DATABASTION_DOMAIN>` with
`DATABASTION_ADMIN_USERNAME` (default `admin`) and the password in `secrets/admin_password`
(put your own password in that file, 12 to 128 characters, before this step if you prefer):

```bash
docker compose run --rm bootstrap-admin
cat secrets/admin_password               # log in with it, then:
rm secrets/admin_password
```

With `DATABASTION_TLS=internal`, copy Caddy's root certificate for the agents:

```bash
docker compose exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > console-ca.pem
```

In the console, **Enrollment tokens** → create a token. It is shown once and is valid 24 hours,
for one agent.

### 2. Agent (`.deb`)
On the database host. Verify the download first ([above](#verify-the-artifacts)).

```bash
VERSION=0.1.0
ARCH="$(dpkg --print-architecture)"      # amd64 or arm64
curl -fsSLO "https://github.com/Yil00/databastion/releases/download/$VERSION/databastion-agent_${VERSION}_${ARCH}.deb"
sha256sum --check --ignore-missing SHA256SUMS          # the list verified with cosign
sudo apt-get install "./databastion-agent_${VERSION}_${ARCH}.deb"
```

The package creates the `databastion` system user, installs the configuration
`/etc/databastion/agent.yaml` (from [agent.example.yaml](../agent/agent.example.yaml)) and the
`databastion-agent` service, **neither enabled nor started** before enrollment.

Edit `/etc/databastion/agent.yaml` (`sudoedit /etc/databastion/agent.yaml`):

- `console.url`: `https://<DATABASTION_DOMAIN>`;
- with `DATABASTION_TLS=internal`: copy `console-ca.pem` to the host and uncomment
  `ca_file: /etc/databastion/console-ca.pem`:
  `sudo install -m 0644 console-ca.pem /etc/databastion/console-ca.pem`;
- `targets`: replace the examples with your databases (each engine's least-privilege account:
  [docs/05-security.md](../docs/05-security.md)), or `targets: []` to enroll first and declare the
  targets later (then `sudo systemctl restart databastion-agent`).

Target passwords stay on this host (invariant I3): one file per target, referenced as
`secret: {file: /etc/databastion/secrets/<target-id>}`, owned by the agent user and `0600`
(paste the password, then Ctrl-D):

```bash
sudo install -m 0600 -o databastion -g databastion /dev/stdin /etc/databastion/secrets/pg-main
```

Enroll with the token from the console (paste it, then Ctrl-D), start the service:

```bash
sudo install -m 0600 -o databastion -g databastion /dev/stdin /etc/databastion/secrets/enrollment-token
sudo runuser -u databastion -- databastion-agent enroll \
  --config /etc/databastion/agent.yaml --token-file /etc/databastion/secrets/enrollment-token
sudo rm /etc/databastion/secrets/enrollment-token
sudo systemctl enable --now databastion-agent
```

`enroll` runs as the `databastion` user so that the identity it writes to `/var/lib/databastion` is
owned by the account the service runs as (the agent refuses state files it does not own).

### 3. Check
The **Agents** page shows the agent *online* within a heartbeat (about 30 seconds), then its
targets. On the database host: `systemctl status databastion-agent`, logs with
`journalctl -u databastion-agent` (JSON; never a sampled value). No port is open:
`sudo ss -ltnup | grep databastion` prints nothing.

## Agent package reference
| Path | Owner, mode | Content |
|------|-------------|---------|
| `/usr/bin/databastion-agent` | `root:root 0755` | The binary of the agent image |
| `/etc/databastion/` | `root:databastion 0750` | Configuration directory |
| `/etc/databastion/agent.yaml` | `root:databastion 0640` | Configuration (dpkg conffile: kept, or offered for merge, on upgrade) |
| `/etc/databastion/agent.env` | `root:root 0600` | Optional service environment (proxy, log level; conffile) |
| `/etc/databastion/secrets/` | `root:databastion 0750` | Your target password files (`databastion 0600`) |
| `/var/lib/databastion/` | `databastion:databastion 0700` | State: identity, local HMAC key, spool, audit cursors |
| `/usr/lib/systemd/system/databastion-agent.service` | `root:root 0644` | The service ([unit](deb/databastion-agent.service)) |
| `/usr/share/databastion-agent/agent.example.yaml` | `root:root 0644` | The documented example, to compare after an upgrade |

The `databastion` user is a system account without login shell, home directory or password,
created before the files are unpacked, so the archive gives every path its final owner and mode
(no window with other owners during an upgrade). `dpkg-statoverride` entries are respected.

**Service hardening.** The unit runs the agent as `databastion` with no capability and
`NoNewPrivileges`, a read-only system (`ProtectSystem=strict`, only `/var/lib/databastion`
writable), no access to `/home`, a private `/tmp` and `/dev`, IPv4 / IPv6 / Unix sockets only,
and, as defence in depth for invariant I1 (the agent itself opens no listener), `SocketBindDeny=any`
(the kernel refuses a bind to an IP port) and `listen()`, `accept()`, `accept4()` refused by the
system-call filter (a `listen()` on an unbound socket would otherwise pick a port by itself); the
`@system-service` system-call set without `@privileged`, `MemoryDenyWriteExecute`,
`RestrictNamespaces`, `LockPersonality`, and the kernel protections (`ProtectKernel*`,
`ProtectControlGroups`, `ProtectClock`, `ProtectHostname`). `systemd-analyze security
databastion-agent` rates it about 1.5 ("OK"). `/proc` stays visible: local engine detection reads
process names (never command lines) and `/proc/net/tcp` ([ADR-0006](../docs/adr/0006-target-discovery.md)).
`Restart=on-failure` (10 s apart, at most 5 starts in 10 minutes).

**Customizing** (`sudo systemctl edit databastion-agent`, a drop-in; never edit the unit):

- **Audit log files** (PostgreSQL, MariaDB `server_audit`, MySQL / Percona JSON, MongoDB): the agent
  reads them locally and **refuses a file it owns or could write** ([agent README](../agent/README.md#audit-log-files)).
  Give it read access through a group, never ownership: add the log file's group, e.g.
  ```ini
  [Service]
  SupplementaryGroups=adm
  ```
  for Debian's PostgreSQL logs (`postgres:adm 0640`; `adm` also reads the system logs), or a
  dedicated group (`chgrp databastion` on the log directory, files `0640`), or an ACL
  (`setfacl -m g:databastion:rX` on the directory and `g:databastion:r` on the files). The file
  must not be writable by that group.
- **A Unix socket under `/tmp`** (MongoDB's default `/tmp/mongodb-27017.sock`): `PrivateTmp=yes`
  hides the host's `/tmp`. Use TCP on the loopback, or `BindReadOnlyPaths=/tmp/mongodb-27017.sock`.
  Sockets under `/run` (PostgreSQL, MySQL, `ldapi`) need nothing.
- **Another `state_dir`**: add it to `ReadWritePaths=`.
- **Proxy and log level**: `HTTPS_PROXY`, `NO_PROXY`, `DATABASTION_LOG` in
  `/etc/databastion/agent.env` (shipped with comments only, a conffile, `KEY=value` lines,
  `root:root 0600`: keep it so, systemd reads it as root).

**Upgrade.** Console first, then the agents ([RELEASE.md](../RELEASE.md#compatibility)). Console:
set the new `DATABASTION_CONSOLE_IMAGE` in `.env`, then `docker compose --profile proxy up -d`
(migrations run first). Agent: `sudo apt-get install ./databastion-agent_<new>_<arch>.deb`; a
running service is restarted, the identity and a modified `agent.yaml` are kept.

**Removal.** Revoke the agent in the console, then `sudo apt-get remove databastion-agent` (stops
and disables the service, keeps configuration and state) or `sudo apt-get purge databastion-agent`
(also deletes `agent.yaml`, `agent.env` and `/var/lib/databastion`: identity, HMAC key, spool).
The `databastion` user and your files under `/etc/databastion/secrets` are kept: after a purge,
delete the target passwords yourself (`sudo rm -rf /etc/databastion/secrets /etc/databastion`) and
rotate them on the databases if the host is being decommissioned.

## Building the `.deb`
```bash
docker build -t databastion-agent agent/                     # the published image's Dockerfile
id="$(docker create databastion-agent)"; docker cp "$id:/usr/local/bin/databastion-agent" .; docker rm "$id"
NFPM="$(deploy/deb/install-nfpm.sh)"                          # pinned nfpm, via the Go checksum database
NFPM="$NFPM" deploy/deb/build.sh --binary ./databastion-agent --arch amd64 --version 0.1.0 --out dist
```

The package is reproducible: the same binary, version and commit give the same bytes (file times
from `SOURCE_DATE_EPOCH`, the commit time; explicit modes; root-owned archive entries). The glibc
dependency is computed from the binary's symbol versions. [nfpm](https://nfpm.goreleaser.com) (MIT)
is a build tool only: nothing of it ships in the package.

## Installation test (under 15 minutes)
[install-test.sh](install-test.sh) (CI job `Packaging / install-test`, [packaging.yml](../.github/workflows/packaging.yml))
runs the [Install](#install) steps above on a fresh runner, `DATABASTION_TLS=internal`, and times
them from the download of the deployment files to the agent shown online. It fails beyond 15
minutes, and checks afterwards that the service is active without restart, holds no listening
socket and logged no error; then it runs a probe under the installed unit's own `[Service]`
settings, which must be refused `listen()` and `bind()` and allowed an outbound connection. Its
stand-ins are listed at the top of the script: the deployment bundle made from the checkout as
publish.yml makes it (checksum checked, no cosign on unsigned pull-request artifacts), an
`/etc/hosts` entry for DNS, the user API calls the UI makes. On pull
requests the console image is built from the checkout before the clock starts; on releases
([publish.yml](../.github/workflows/publish.yml)) the published image is pulled inside the timed
window, with the released `.deb`.

The `.deb` itself is tested by [deb/test-install.sh](deb/test-install.sh) in Debian 12 and Ubuntu
24.04 containers, amd64 and arm64: user, files, owners and modes, conffile, `systemd-analyze
verify` and `security`, no socket unit or listener, `--version`, the refusal to run before
enrollment, reinstall with a modified configuration, an upgrade to a newer version, remove, purge.
