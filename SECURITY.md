# Security policy

## Supported versions
| Version | Supported |
|---------|-----------|
| 0.6.x | Yes: security fixes are released as `0.6.Z` patch versions |
| 0.1.x, 0.2.x, 0.3.x, 0.4.x, 0.5.x | No: upgrade to the latest `0.6.x` release |
| Pre-releases (`X.Y.Z-alpha.N`, `-beta.N`, `-rc.N`) | No: upgrade to the latest `0.6.x` release |
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
- **Agent** (`agent/`): the `databastion-agent` binary, its connectors (PostgreSQL, MySQL / MariaDB, MongoDB, OpenLDAP, Apereo CAS), the classifiers and masking, the local state files, and the image built from `agent/Dockerfile`.
- **Console** (`console/`): the web and worker processes, the user API and UI, local and OpenID Connect login, the agent API (`/api/agent/v1`), the internal database migrations and roles, alerting, and the image built from `console/Dockerfile`.
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

## Known limitations and residual risks
These are known and documented; reporting them again is not needed, but a way to go beyond what is described is a vulnerability. Details are in [docs/05-security.md](docs/05-security.md), [docs/08-engine-capabilities.md](docs/08-engine-capabilities.md) and the linked ADRs; the release notes list them under "Known limitations" ([CHANGELOG.md](CHANGELOG.md)).

- **Audit coverage depends on the engine**: each target reports Full, Partial, Limited or None; MySQL / MariaDB, MongoDB and Apereo CAS are never Full ([docs/08, matrix](docs/08-engine-capabilities.md#matrix)).
- **Records lost while the agent is stopped**: the rest of a log rotated by rename, MySQL / MariaDB statements held in a rotated file, and `performance_schema` history that wrapped ([docs/08](docs/08-engine-capabilities.md#audit-log-files-and-failing-streams-every-engine)). A log truncated in place while the agent was stopped is fixed by #97.
- **Paced Discovery**: at the defaults (1 % duty cycle, 3600 s budget) a scan covers about 36 s of query time; large targets show "partial coverage" ([ADR-0035](docs/adr/0035-discovery-pacing.md)). Since #98 the console delivers one scan per agent at a time, so a pass over N targets of one agent takes about N × the scan budget ([ADR-0036](docs/adr/0036-console-discovery-scan-scheduling.md)).
- **PostgreSQL statement text on the agent host**: `pg_read_all_stats` exposes other users' raw statement text, including passwords typed as literals, and `pg_stat_statements` keeps DCL passwords in clear; protect the agent's credentials and host accordingly ([docs/05](docs/05-security.md#recommended-database-accounts-read-only)). Holders of those credentials can run the agent's allow-listed table-less statements on `pg_stat_statements` unreported ([docs/08](docs/08-engine-capabilities.md#the-agents-own-account)).
- **MongoDB abandoned authentications** (since #100): an authentication abandoned before any proof gives no event, so a client that knows account names can confirm they exist and collect their SCRAM salt and iteration count unreported; every wrong proof is still reported ([docs/08](docs/08-engine-capabilities.md#known-limits-2)).
- **Failed-login flood**: junk names can keep root out of the named groups at about 100 times root's volume, and an events flood can evict findings down to a quarter of the spool ([agent/README.md](agent/README.md#failed-login-flood)).
- **Per-record isolation**: dropped statements reach the counters and the `agent.audit_stream_stopped` alert, not the policies ([ADR-0032](docs/adr/0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md)).
- **Carried forward**: name-normalization gaps ([ADR-0009](docs/adr/0009-name-normalization-and-item-sanitization.md)); OpenLDAP `check()` does not probe `userPKCS12`; e-mail notifications are plain text only; the system-alert budget needs the same setting on every console process ([ADR-0033](docs/adr/0033-system-alert-budget.md)); webhook and e-mail consumers must escape principals ([docs/05](docs/05-security.md#alerting)).
- **OpenID Connect login** (since 0.4.0): without refresh tokens, a user disabled at the provider keeps their console session until its maximum age (12 h by default); with OIDC on, `DATABASTION_LOCAL_LOGIN=enabled` lets local users bypass the provider's policies; the role, group and domain expressions are written by the operator and must not read user-editable claims ([docs/05](docs/05-security.md#console-login-with-openid-connect)).
- **Apereo CAS** (since 0.4.0): client addresses come from `X-Forwarded-For` unless a proxy overwrites it; CAS stores that match no CAS store guard rule are sampled like any table until the first ticket id is read ([docs/05](docs/05-security.md#apereo-cas-connector)). Since 0.6.0 the token responses of token-only grants name their client ([ADR-0044](docs/adr/0044-cas-token-only-grants-client-naming.md)); a token request record lost where the agent cannot see it can attribute a response to another client of the same addresses and user agent within 5 s. YAML registries are read by the agent's own parser ([ADR-0046](docs/adr/0046-cas-yaml-registry-parser-without-unsafe-libyaml.md)); `unsafe-libyaml`, archived by its author, stays in the agent binary for `agent.yaml`, which only root can write ([docs/08](docs/08-engine-capabilities.md#known-limits-4)).
- **MySQL / MariaDB Audit blind spots** (since 0.5.0 the stream fails closed on hidden statements, #168; since 0.6.0, [ADR-0045](docs/adr/0045-mysql-mariadb-statement-text-tables-and-unqualified-calls.md), reads of other sessions' statement texts, `LOAD_FILE()`, cut texts and unqualified calls of names that are not built in are reported, the calls as reads of `*` that do not say what the function read): reads that touch only `information_schema`, `performance_schema` or `sys` outside the statement-text tables produce no event (including `performance_schema.error_log` and the replication error tables, which can quote statements); an `EXPLAIN` without `ANALYZE` produces no event, and on MySQL `EXPLAIN` then `SHOW WARNINGS` shows the row values of const tables; `CREATE … AS SELECT` does not name what it reads; on a server series newer than the agent's built-in lists, a stored function named after a built-in the server removed is taken as built in (upgrade the agent with the server); whoever holds the agent's credential at its address can replay its constant `performance_schema` poll unreported; grant `performance_schema`, `PROCESS`, `FILE` and `EXECUTE` on `SQL SECURITY DEFINER` functions sparingly ([docs/08](docs/08-engine-capabilities.md#known-limits-1)).
- **Audit log paths**: since 0.4.0 a final symlink and a file with more than one hard link are refused, but symlinks in parent directories are still followed; outside CAS targets, the directory permissions must keep others from replacing a parent directory ([ADR-0043](docs/adr/0043-audit-logs-opened-without-following-a-final-symlink.md)).
- **Upgrades**: upgrade the console first, then the agents; the 0.5.0 worker upgrades the pg-boss schema at its first start (back up the console database first); a 0.4.0 or later agent holds its `cas` targets, findings and events until the console lists `engine.cas` ([ADR-0042](docs/adr/0042-hold-items-of-unlisted-engines.md)). Agents built before #60 (before 0.1.0) cannot decode `HeartbeatResponse.accepts` ([ADR-0022](docs/adr/0022-protocol-capability-negotiation.md)).
- **Release trust**: a single maintainer approves releases ([RELEASE.md](RELEASE.md#repository-configuration-one-time)).

## Verifying release artifacts
The console and agent images are published to GHCR by [publish.yml](.github/workflows/publish.yml): multi-arch (amd64, arm64), signed with cosign in keyless mode (GitHub OIDC), with an SBOM and a provenance attestation. Under [ADR-0034](docs/adr/0034-release-signing-from-tag-push.md), images and release artifacts are signed by `publish.yml` only, in the run triggered by the push of the release tag. The certificate identity is therefore exact for each version: check it exactly, never with a pattern.

1. Resolve the digest of the tag (a tag can be moved in a registry; a digest cannot):
   ```bash
   VERSION=0.6.0
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

Same steps for `ghcr.io/yil00/databastion-console`. The full verification steps, including the agent `.deb` packages and the signed `SHA256SUMS`, are in [RELEASE.md § 4](RELEASE.md#4-published-artifacts) and [deploy/README.md](deploy/README.md#verify-the-artifacts).
