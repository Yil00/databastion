# End-to-end tests

Phase 1 exit criterion ([ROADMAP](../docs/ROADMAP.md)): *end-to-end enrollment in containers;
revocation effective in < 60 s*. [`run.sh`](run.sh) drives
[`docker-compose.yml`](docker-compose.yml); the CI job is
[`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml).

## What runs
| Service | Image | Role |
|---------|-------|------|
| `db` | PostgreSQL 17 | Console internal database; roles created by `deploy/initdb/` |
| `migrate` | `console/Dockerfile` | One-shot migrations as the owner role |
| `web`, `worker` | `console/Dockerfile` | Console processes (runtime role) |
| `proxy` | Caddy | TLS 1.3 reverse proxy, certificate from a throwaway CA; `/metrics` answers `404` |
| `target-pg` | PostgreSQL 17 | Declared target of the agent (heartbeat target status); [`target-initdb/`](target-initdb/) creates the agent's read-only role |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | `databastion-agent`, HTTPS only (`ca_file` pins the test CA) |
| `bootstrap-admin`, `agent-files` | console / PostgreSQL | One-shot helpers (`tools` profile) |

Networks: the agent sits on an `internal` network with the proxy and the target only; it
cannot reach the console database or the outside. Only the proxy is published, on
`127.0.0.1:${E2E_HTTPS_PORT:-8443}`. Every service runs with a read-only root filesystem,
`cap_drop: ALL` (PostgreSQL gets back what its entrypoint needs) and `no-new-privileges`.

## Flow
1. Generate every secret (database passwords, metrics token, admin password, target superuser
   and agent passwords) and the test CA + proxy certificate into a private temporary directory,
   write `agent.yaml`. The agent connects to the target as `databastion_agent` (minimal
   variant of [ADR-0012](../docs/adr/0012-postgresql-agent-grants.md): `LOGIN`, no superuser /
   createdb / createrole / replication / bypassrls, `CONNECTION LIMIT 4`, `CONNECT`,
   `pg_read_all_stats`, role defaults `default_transaction_read_only = on` and statement / lock /
   idle-in-transaction timeouts; no per-schema grants while `app` has no application schema: I4); the superuser password never leaves `target-pg`.
2. Build the console and agent images, start the console stack and the target, wait for
   `/api/health/ready` through the proxy.
3. `bootstrap-admin` with the random password (Docker secret file), log in through the user API
   (session cookie + `X-CSRF-Token`), create an enrollment token.
4. Hand the token to the agent as a `0600` file owned by uid 10001 (sent on stdin, never on a
   command line), run `databastion-agent enroll --token-file …` and assert that
   `identity.json` is `10001:10001 0600`, then `databastion-agent run`.
5. Assert through `GET /api/agents` that the agent is `online` with target `pg-e2e` reported
   and `reachable` (the PostgreSQL connector connects with `databastion_agent`, TLS disabled on
   the internal network through the explicit insecure opt-in
   `postgres: {databases: [app], tls: disable_insecure}` in `agent.yaml`, SCRAM only; the audit
   level, `none` without `pg_stat_statements`, is printed but not asserted), that `databastion_agent` has exactly the
   attributes above (memberships exactly `pg_read_all_stats`, role settings in
   `pg_db_role_setting` exactly the four defaults) and, in its own session, gets the defaults and
   is denied `pg_authid` / `pg_user_mapping`, and that `/metrics` (scraped from inside the web
   container with the metrics token) shows `databastion_agent_up{agent_id="…"} 1`.
6. Revoke the agent through the user API; within 60 s the agent must log
   `console rejected the current secret (401)`; the measured latency is printed and the test
   fails at 60 s or more. The console must show `revoked`, and the proxy access log must show no
   `/api/agent/v1/jobs` request during a 10 s window afterwards.
7. Dump every container log (plus the one-shot command outputs); fail if `agent.log` or
   `web.log` is empty; run a positive control (a random canary written to the log directory must
   be found by the scan and redacted, then it is removed); fail if any generated secret
   (enrollment token, agent secret, admin password, session cookie, metrics token, database and
   target passwords, encryption key) appears in clear text.
8. `pg_dump` the console database into the private temporary directory (never the log
   directory) and fail if the agent secret, the enrollment token, the admin password or a
   target password is stored in clear text.

Each secret is registered in a private pattern file as soon as it is generated or obtained
(and masked with `::add-mask::` under GitHub Actions); values are matched from files
(`grep -Ff`), never passed on a command line. On exit, whatever the result: logs are written to
`$E2E_LOG_DIR` (default `e2e/.logs/`, ignored by git), every registered secret is replaced in
them by `<REDACTED:name>` (a file that cannot be redacted is deleted), then the stack and its
volumes are removed and the temporary directory is deleted.

## Running locally
Requirements: Docker with Compose v2, `openssl`, `curl`, `jq`, bash.

```sh
e2e/run.sh
E2E_HTTPS_PORT=9443 e2e/run.sh      # if 8443 is taken on 127.0.0.1
```

The first run builds both images (several minutes). No secret is written to the repository;
nothing listens outside `127.0.0.1`.
