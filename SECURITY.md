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
A way to break one of these is a vulnerability. Details: [docs/05-security.md](docs/05-security.md).

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
The console and agent images are published to GHCR by [publish.yml](.github/workflows/publish.yml) when a release or pre-release tag is created: multi-arch (amd64, arm64), signed with cosign in keyless mode (GitHub OIDC), with an SBOM and a provenance attestation. Verify the signature before deploying ([RELEASE.md](RELEASE.md#4-published-artifacts)):

```bash
cosign verify ghcr.io/yil00/databastion-agent:<tag> \
  --certificate-identity-regexp '^https://github.com/Yil00/databastion/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Same command for `ghcr.io/yil00/databastion-console:<tag>`. Then pin the verified digest (`image:<tag>@sha256:<digest>`), as the [deployment example](deploy/docker-compose.example.yml) explains.

Not available yet: the agent `.deb` package and the `SHA256SUMS` file with its signature are planned for v0.1.0 ([ROADMAP](docs/ROADMAP.md) phase 7); their verification will be documented with the packaging.
