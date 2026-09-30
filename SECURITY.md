# Security policy

## Supported versions
| Version | Supported |
|---------|-----------|
| 0.1.x | Yes: security fixes are released as `0.1.Z` patch versions |
| Pre-releases (`0.1.0-alpha.N`, `-beta.N`, `-rc.N`) | No: upgrade to the latest `0.1.x` release |
| Unreleased commits of `main` / `dev` | No |

The console and the agent share one version number and are released together ([RELEASE.md](RELEASE.md#2-versions)). A fix may require upgrading both: the console first, then the agents.

## Reporting a vulnerability
**Do not open a public issue, discussion or pull request.** Report privately through GitHub Security Advisories: in this repository, **Security** tab → **Report a vulnerability**. There is no security e-mail address; the private advisory is the only channel.

Please include: the affected version or commit, the component (agent, connector, console, protocol), the configuration involved, reproduction steps and the estimated impact. Do not send real sensitive data: reproduce with the fake data of the dev environment ([dev/README.md](dev/README.md)).

## Commitment
- Acknowledgment within 72 h
- Initial assessment within 7 days
- Fix and security advisory coordinated with the person who reported the issue: the fix is prepared in the private advisory, released as a hotfix ([RELEASE.md](RELEASE.md#security-fix)), and the advisory is published at the same time as the release

## Scope
In scope, in this repository:
- **Agent** (`agent/`): the `databastion-agent` binary, its connectors (PostgreSQL, MySQL / MariaDB, MongoDB, OpenLDAP), the classifiers and masking, the local state files, and the image built from `agent/Dockerfile`.
- **Console** (`console/`): the web and worker processes, the user API and UI, the agent API (`/api/agent/v1`), the internal database migrations and roles, alerting, and the image built from `console/Dockerfile`.
- **Protocol** (`shared/protocol/`): the agent ↔ console contract (`openapi.yaml`, schemas, registries) and how each side enforces it.
- The [deployment example](deploy/docker-compose.example.yml) and the release workflows, where they make a deployment or a published artifact insecure.

Out of scope: the dev environment and the test harnesses (`dev/`, `e2e/`, whose dev-only deviations are documented), vulnerabilities of the monitored engines themselves, and deployments that turn off a documented safeguard (for example `DATABASTION_ALERTING_INSECURE_DEV`, `insecure_dev_http`, `tls: disable_insecure`).

## Invariants
Breaking one of the security invariants I1 to I5 is a vulnerability: report it privately as above. I6 and I7 are project rules, not security properties: report a breach of them as a regular issue. Details: [docs/05-security.md](docs/05-security.md).

| # | Invariant |
|---|-----------|
| I1 | Agents open no inbound port; only the agent initiates connections (HTTPS 443) |
| I2 | No raw sensitive value leaves the agent: masked samples and HMAC fingerprints only |
| I3 | Database credentials never leave the agent host |
| I4 | The agent only reads, with a dedicated least-privilege account |
| I5 | No network scanning: declared targets and local detection only |
| I6 | The protocol is defined by `shared/protocol/openapi.yaml`; no hand-written protocol types |
| I7 | The public repository is Apache 2.0 only; no Enterprise code |

Also particularly sensitive: bypassing agent or console authentication, tampering with the console audit log or the agent-integrity alerts, and agent privilege escalation on the monitored databases.

## Verifying release artifacts
The console and agent images are published to GHCR by [publish.yml](.github/workflows/publish.yml): multi-arch (amd64, arm64), signed with cosign in keyless mode (GitHub OIDC), with an SBOM and a provenance attestation. Under ADR-0034 (added by the packaging PR), images and release artifacts are signed by `publish.yml` only, in the run triggered by the push of the release tag. The certificate identity is therefore exact for each version: check it exactly, never with a pattern.

1. Resolve the digest of the tag (a tag can be moved in a registry; a digest cannot):
   ```bash
   VERSION=0.1.0
   IMAGE=ghcr.io/yil00/databastion-agent
   docker buildx imagetools inspect "$IMAGE:$VERSION" --format '{{json .Manifest}}' | jq -r .digest
   # or: crane digest "$IMAGE:$VERSION"
   ```
2. Verify the signature of that digest:
   ```bash
   cosign verify "$IMAGE@sha256:<digest>" \
     --certificate-identity "https://github.com/Yil00/databastion/.github/workflows/publish.yml@refs/tags/$VERSION" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-github-workflow-trigger push
   ```
3. Deploy exactly that digest (`$IMAGE:$VERSION@sha256:<digest>`), never the bare tag.

Same steps for `ghcr.io/yil00/databastion-console`. The full verification steps, including the agent `.deb` packages and the signed `SHA256SUMS`, are in RELEASE.md section 4 and deploy/README.md, both updated by the packaging PR. Until that PR is merged, the `.deb` packages and `SHA256SUMS` are not published.
