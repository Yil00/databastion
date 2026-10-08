# Tutorial – first steps with DataBastion

This tutorial is for newcomers. Part A installs the latest release (v0.4.0 at the time of writing) and takes you to a first Discovery scan and a first incident. Part B sets up a development machine with `make`: the seeded databases, the console and an agent running on your host, and the tests.

The commands can be copied as they are into bash or zsh. They contain no comments, because zsh does not accept `#` comments on an interactive command line by default.

Before you start, read what DataBastion can and cannot see on each engine: [08-engine-capabilities.md](08-engine-capabilities.md). The known limitations are listed (under 0.1.0) in the [CHANGELOG](../CHANGELOG.md) and in [SECURITY.md](../SECURITY.md#known-limitations-and-residual-risks).

- [Part A – Try DataBastion from the release](#part-a--try-databastion-from-the-release)
- [Part B – Develop with make](#part-b--develop-with-make)

---

## Part A – Try DataBastion from the release
The full procedure, with every command, is in [deploy/README.md](../deploy/README.md). This part summarizes it and says what you should see at each step. It takes about 15 minutes on a prepared host.

You need:
- a Linux host for the console, with Docker Engine, Compose v2, `openssl` and `curl`, and a DNS name for it that the agents can resolve;
- a database host running Debian 12 or Ubuntu 24.04 with systemd, which can open outbound HTTPS connections to the console. The agent opens no port on that host;
- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3 or later, to check the signatures.

### A1. Verify the artifacts
Follow [Verify the artifacts](../deploy/README.md#verify-the-artifacts). The release files and the images are signed only by the publish workflow, in the run triggered by the release tag. Check the signer's identity exactly, not with a pattern. For v0.4.0 it is:

```
https://github.com/Yil00/databastion/.github/workflows/publish.yml@refs/tags/0.4.0
```

For another version, replace `0.4.0` with the version (`.../publish.yml@refs/tags/<version>`). The OIDC issuer is `https://token.actions.githubusercontent.com`.

**You should see**: `Verified OK` for `SHA256SUMS`, one `OK` line per file you downloaded, `verified: …` for each image and then `all images verified`. If anything prints `FAILED`, do not install anything.

### A2. Install the console with Docker Compose
Follow [Install › 1. Console](../deploy/README.md#1-console): extract the deployment bundle, copy `docker-compose.example.yml` to `compose.yaml` and `.env.example` to `.env`, and edit `.env`. Set `DATABASTION_CONSOLE_IMAGE` to the console line of the verified `image-digests.txt`, with its digest. Then run `./init-secrets.sh` and `docker compose --profile proxy up -d`, and create the first administrator with `docker compose run --rm bootstrap-admin`.

**You should see**: `docker compose ps` lists `console`, `worker`, `db` and `proxy` running, and `migrate` exited with code 0. The login page answers at `https://<your console DNS name>`, and you can log in as `admin` with the password from `secrets/admin_password`. Delete that file once you have logged in.

Keep a copy of `secrets/encryption_key` offline. Without it, the stored notification secrets and masked samples cannot be read.

### A3. Install the agent `.deb`
Follow [Install › 2. Agent (`.deb`)](../deploy/README.md#2-agent-deb). On the database host:
1. Install the package with `apt-get`.
2. Create a read-only account for the agent in each database ([05-security.md](05-security.md#recommended-database-accounts-read-only)).
3. Set `console.url` and `targets` in `/etc/databastion/agent.yaml`. Put each target's password in its own `0600` file under `/etc/databastion/secrets/`.

**You should see**: the package creates the `databastion` user and the `databastion-agent` service. The service is neither enabled nor started yet.

### A4. Enroll the agent
In the console, open **Enrollment tokens** and create a token. It is shown once, is valid for 24 hours and works for one agent. On the database host, run `databastion-agent enroll` as the `databastion` user, delete the token file, then `systemctl enable --now databastion-agent` ([same section](../deploy/README.md#2-agent-deb)).

**You should see**: within about 30 seconds the **Agents** page shows the agent *online*, then its targets with their reachability and audit level. On the database host, `sudo ss -ltnup | grep databastion` prints nothing, because the agent listens on no port ([3. Check](../deploy/README.md#3-check)).

If a target shows an error, `journalctl -u databastion-agent` gives the reason (the agent logs JSON and never logs a sampled value). Check the target's account, TLS settings and secret file. The [user guide](10-user-guide.md#6-declare-targets) describes each key.

### A5. First Discovery scan
1. To get an incident from the scan, create a policy first: on **Policies**, add a policy on findings, for example for the classifier family `pii.*`, with the action "create an incident" ([user guide § 11](10-user-guide.md#11-policies-incidents-and-notifications)).
2. On the agent page, click **Scan** on a target. You can keep the default parameters.

**You should see**: the scan is listed as running on the agent page. Scans are paced to keep the database load low, so expect minutes rather than seconds ([user guide § 9](10-user-guide.md#9-discovery-scans-and-findings)). When the scan ends, **Findings** lists the locations that hold sensitive data, with masked samples (at most 4 digits kept). If the agent page shows a "partial coverage" badge, the scan ran out of time: § 9 of the user guide explains how to give it more.

### A6. First incident
**You should see**: **Incidents** lists one incident per matching finding, most severe first. Open one and walk through its lifecycle: acknowledge it, then resolve it or mark it as a false positive.

To be notified, add an e-mail or webhook channel on **Notifications** and attach it to the policy. To detect bulk exports such as `pg_dump`, enable Audit on the target ([user guide § 10](10-user-guide.md#10-audit-enabling-it-and-reading-events)). What Audit can see depends on the engine and its configuration ([08-engine-capabilities.md](08-engine-capabilities.md#matrix)).

---

## Part B – Develop with make
Run every command from the root of a clone of the repository. `make help` lists every target by section. Targets marked LONG or INTERACTIVE in that list run for a long time or until you press Ctrl-C.

```sh
git clone https://github.com/Yil00/databastion.git
cd databastion
make help
```

### B1. Prerequisites
```sh
make doctor
```

**You should see**: one line per tool with its version, then `All required tools found.` The required tools are git, make, `timeout`, Node.js 24 (22.22+ also works for development) with npm, corepack and pnpm, the stable Rust toolchain with rustfmt and clippy, Python 3, and Docker with Compose v2. If a tool is missing, `doctor` lists it and fails. Optional tools (cargo-deny, shellcheck, jq, openssl, curl) are reported as `not found` without failing; some CI gates, `make e2e` and `make load-test` need them. A warning says when the Docker daemon is not reachable.

### B2. Install the dependencies
```sh
make install
```

This installs the dependencies the way CI does: the console's pnpm packages (frozen lockfile), the root and `shared/protocol/` npm packages, and the Rust crates of the agent and of its fuzz workspace.

**You should see**: no error. The first run takes a few minutes.

### B3. Start the dev environment
```sh
make dev
```

`make dev` copies `dev/.env.example` to `dev/.env` if it is missing, creates the engine log directories and a metrics token in `dev/.state/`, builds the images, starts everything and waits until every service is healthy. It starts databases seeded with **fake** personal data, plus the tooling around the console. Every port is published on `127.0.0.1` only ([dev/README.md](../dev/README.md#services)):

| Service | Address | Notes |
|---------|---------|-------|
| PostgreSQL 17 + pgaudit | `127.0.0.1:5432`, database `shop` | Audit level Full |
| MySQL 8.4 Community | `127.0.0.1:3306`, database `hr` | `performance_schema` |
| MariaDB 11.4 | `127.0.0.1:3307`, database `support` | `server_audit` log |
| Percona Server 8.4 | `127.0.0.1:3308`, database `hr` | `audit_log_filter` JSON log |
| MongoDB 8.0 Community | `127.0.0.1:27017`, database `app` | profiler and server log |
| OpenLDAP | `127.0.0.1:1389` (LDAPS 1636), `dc=example,dc=org` | `cn=accesslog` |
| Mailpit | <http://127.0.0.1:8025> (SMTP `127.0.0.1:1025`) | catches the alert e-mails |
| Prometheus | <http://127.0.0.1:9090> | scrapes the console `/metrics` |
| Grafana | <http://127.0.0.1:3001> | user `admin`, password `GRAFANA_ADMIN_PASSWORD` from `dev/.env` |

The agent's read-only account is `databastion` on every engine, with the password `DATABASTION_DB_PASSWORD` from `dev/.env`. Percona Server for MongoDB is opt-in and not started by `make dev` ([dev/README.md](../dev/README.md#connector-integration-tests)).

**You should see**: `Dev environment ready.` `make dev-ps` shows every service `healthy`, and `make dev-logs` shows the last log lines of each service.

Check the environment:

```sh
make dev-smoke
```

**You should see**: the smoke test passes. It checks that the agent accounts work and cannot read the password tables, that the audit logs are written, and that the Mailpit, Prometheus and Grafana UIs answer.

### B4. Run the console
The console is not containerized in the dev environment: it runs on your host and needs its own PostgreSQL database. The simplest option is a throwaway PostgreSQL 17 container on port 5433. The commands below write its connection string, a dev encryption key (for masked samples and notification channel secrets) and the metrics token path to `dev/.state/console.env` (mode `0600`, git-ignored), so that each terminal can load it:

```sh
pw="$(openssl rand -hex 16)"
docker run -d --name databastion-console-db -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD="$pw" postgres:17
(umask 077 && printf 'export DATABASE_URL=postgresql://postgres:%s@127.0.0.1:5433/postgres\nexport DATABASTION_ENCRYPTION_KEY=%s\nexport DATABASTION_METRICS_TOKEN_FILE=%s/dev/.state/metrics_token\n' "$pw" "$(openssl rand -hex 32)" "$PWD" > dev/.state/console.env)
```

Apply the migrations and create the first administrator. `pnpm admin:bootstrap` has no make target; it runs from `console/`:

```sh
. dev/.state/console.env
make console-migrate
(umask 077 && openssl rand -base64 18 > dev/.state/admin_password)
(cd console && DATABASTION_BOOTSTRAP_ADMIN_USERNAME=admin DATABASTION_BOOTSTRAP_ADMIN_PASSWORD_FILE="$PWD/../dev/.state/admin_password" corepack pnpm admin:bootstrap)
```

**You should see**: the migrations apply without error and the bootstrap command logs `first administrator created`. Here a single database superuser runs both the migrations and the console, which is acceptable in development only: production uses separate owner and runtime roles ([console/README.md](../console/README.md#database-roles)). Expect a startup warning about it.

Start the web process and the worker, each in its own terminal (they run until Ctrl-C):

```sh
. dev/.state/console.env
make console-dev
```

```sh
. dev/.state/console.env
make console-worker
```

**You should see**: the console at <http://localhost:3000>. Log in as `admin` with the password in `dev/.state/admin_password`. Within a minute or so, the console target in Prometheus (<http://127.0.0.1:9090/targets>) turns UP, since the console uses the same metrics token as Prometheus. Every console variable is described in [console/README.md](../console/README.md#configuration).

To receive alert e-mails, add an e-mail channel on **Notifications** with the SMTP relay `127.0.0.1`, port `1025`, and no authentication. The e-mails then show up in Mailpit.

### B5. Run an agent
Build the agent:

```sh
make agent-build
```

**You should see**: the binary `agent/target/release/databastion-agent`.

Write a dev configuration for the agent. It points to the dev console over `http://` (`insecure_dev_http`, allowed only for a loopback IP literal), keeps its state in `dev/.state/agent`, and declares the dev PostgreSQL as its only target (no TLS, allowed on a loopback address). The password is passed by reference, as the name of an environment variable:

```sh
cat > dev/.state/agent.yaml <<EOF
console:
  url: http://127.0.0.1:3000
  insecure_dev_http: true
state_dir: $PWD/dev/.state/agent
targets:
  - id: pg-shop
    engine: postgres
    host: 127.0.0.1
    port: 5432
    account: databastion
    secret:
      env: DATABASTION_PG_PASSWORD
    postgres:
      databases: [shop]
      tls: disable
EOF
```

Every key is documented in [agent/agent.example.yaml](../agent/agent.example.yaml). To try Audit from the pgaudit log as well, see [Audit log files](../agent/README.md#audit-log-files) in the agent README. Without a log file, PostgreSQL Audit falls back to `pg_stat_statements` (Limited).

In the console, create a token on **Enrollment tokens**. Paste it into a file (paste, press Enter, then Ctrl-D), then enroll the agent and delete the token file:

```sh
(umask 077 && cat > dev/.state/agent-token)
agent/target/release/databastion-agent enroll --config dev/.state/agent.yaml --token-file dev/.state/agent-token
rm dev/.state/agent-token
```

Run the agent (until Ctrl-C), with the password variable taken from `dev/.env`:

```sh
set -a; . dev/.env; set +a
export DATABASTION_PG_PASSWORD="$DATABASTION_DB_PASSWORD"
make agent-run AGENT_CONFIG=dev/.state/agent.yaml
```

`make agent-run` builds and runs the agent with `cargo run`. Set `DATABASTION_LOG=debug` for more detailed logs ([agent/README.md](../agent/README.md#commands)).

**You should see**: the agent's JSON logs in the terminal. The **Agents** page shows the agent *online* and the `pg-shop` target reachable. Launch a scan from the agent page as in [A5](#a5-first-discovery-scan). The findings match the seeded values listed in `dev/ground-truth.json`.

### B6. Tests
| Command | What it runs | Needs |
|---------|--------------|-------|
| `make check` | Every linter and fast unit test, the documentation links, the seed check and the protocol registry check: what CI runs, minus the containers and the slow gates. Run it before opening a PR | `make install`; `git fetch origin` first, because the registry check compares with `origin/dev` and `origin/main` |
| `make ci` | `make check` plus the other non-container CI gates: license gate, console production build, held-out classifier gate, minimal agent build, cargo-deny, fuzz smoke run (slow) | cargo-deny |
| `make agent-it ENGINE=postgres` | Connector integration tests against the running dev environment, as the CI connector jobs run them. `ENGINE` is `postgres`, `mysql`, `mongodb`, `openldap` or `all` | `make dev` |
| `make e2e` | LONG: the end-to-end harness in containers (console, agent, targets, the invariant I2 check), at most `E2E_TIMEOUT` seconds (default 2700) | Docker, openssl, curl, jq |
| `make load-test` | LONG (about 1 h): the load and database impact test, at most `LOAD_TIMEOUT` seconds (default 3600) | Docker |

```sh
git fetch origin
make check
```

**You should see**: every step passes and `make` exits with status 0. Console tests that need a database or Mailpit are skipped with a message when `TEST_DATABASE_URL` (or the PostgreSQL binaries) or `DATABASTION_TEST_SMTP` are not set ([console/README.md](../console/README.md#configuration)).

```sh
make agent-it ENGINE=postgres
```

**You should see**: `cargo test` results with no failure. Checks that cannot run in the dev environment are skipped and print `skipped: …`. For MongoDB the script may ask you to make `mongod.log` readable (`sudo chmod a+r` on the path it prints).

To run a single component's checks, use the targets of its section in `make help`: `console-lint`, `console-typecheck`, `console-test`, `agent-lint`, `agent-test`, `protocol-check` and the others.

### B7. Stop and reset
```sh
make dev-down
```

This stops the dev environment and keeps the data volumes.

```sh
make dev-reset
```

This stops the environment, deletes its volumes and `dev/.state` (the metrics token, the console connection file, the agent's configuration and identity), and reloads the seed on the next `make dev`. Remove the console database container too, then start again from B3:

```sh
docker rm -f databastion-console-db
```

### Which target do I use?
| I want to… | Target |
|------------|--------|
| See every target | `make help` |
| Check my tools | `make doctor` |
| Install the dependencies | `make install` |
| Start, check, stop or reset the databases | `make dev`, `make dev-smoke`, `make dev-down`, `make dev-reset` |
| See the services' state or logs | `make dev-ps`, `make dev-logs` (`TAIL=500` for more lines) |
| Change the seed data | `make seed`, then `make dev-reset dev` |
| Run the console | `make console-migrate`, `make console-dev`, `make console-worker` |
| Build or run the agent | `make agent-build`, `make agent-run AGENT_CONFIG=…` |
| Format the code | `make fmt` |
| Check my change before a PR | `make check` (`make ci` for the slow gates too) |
| Test a connector against real servers | `make agent-it ENGINE=…` |
| Check the protocol after editing `openapi.yaml` | `make protocol-check` |
| Run the end-to-end or load tests | `make e2e`, `make load-test` |
| Dry-run a release (maintainer, branch `main` only) | `make release-dry` |

### Troubleshooting
- **`Cannot connect to the Docker daemon`**, or the warning from `make doctor`: start Docker (`sudo systemctl start docker`), and make sure your user can run `docker` without sudo (it must be in the `docker` group; log out and back in after adding it). `make dev`, `make agent-it`, `make e2e` and `make load-test` need the daemon.
- **A service is not healthy after `make dev`**: run `make dev-ps` and `make dev-logs`. If the volumes were created by an older version of the dev environment, run `make dev-reset dev`. A port already used on your host can be changed in `dev/.env`.
- **No space left on device**: the agent builds (`agent/target`, several GB), the fuzz workspace (`agent/fuzz/target`) and the Docker images take a lot of disk space. Free some with `cargo clean` in `agent/` and in `agent/fuzz/`, and with `docker system prune` (it removes stopped containers and unused images).
- **A command stops after a while with no error**: long targets are wrapped in `timeout`. Raise the limit with the variable listed at the end of `make help`, for example `make agent-it ENGINE=all CARGO_TIMEOUT=3600`.
- **`make check` fails in `protocol-append-only`**: run `git fetch origin` first. The check compares the registries with `origin/dev` and `origin/main`.
- **`make release-dry` fails**: it only runs on the branch `main`, after `make install`. Releases are made by the maintainer through CI ([RELEASE.md](../RELEASE.md)).
- **The agent refuses to start or to enroll**: read the error in its log. Common causes are an `http://` console URL without `insecure_dev_http: true` or with a host name instead of `127.0.0.1`, a `state_dir` with the wrong owner or mode (it must be yours and `0700`), and an unset password variable.
