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
| `target-pg` | PostgreSQL 17 | Declared target of the agent (heartbeat target status) |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | `databastion-agent`, HTTPS only (`ca_file` pins the test CA) |
| `bootstrap-admin`, `agent-files` | console / PostgreSQL | One-shot helpers (`tools` profile) |

Networks: the agent sits on an `internal` network with the proxy and the target only; it
cannot reach the console database or the outside. Only the proxy is published, on
`127.0.0.1:${E2E_HTTPS_PORT:-8443}`. Every service runs with a read-only root filesystem,
`cap_drop: ALL` (PostgreSQL gets back what its entrypoint needs) and `no-new-privileges`.

## Flow
1. Generate every secret (database passwords, metrics token, admin password, target password)
   and the test CA + proxy certificate into a private temporary directory, write `agent.yaml`.
2. Build the console and agent images, start the console stack and the target, wait for
   `/api/health/ready` through the proxy.
3. `bootstrap-admin` with the random password (Docker secret file), log in through the user API
   (session cookie + `X-CSRF-Token`), create an enrollment token.
4. Hand the token to the agent as a `0600` file owned by uid 10001 (sent on stdin, never on a
   command line), run `databastion-agent enroll --token-file …`, then `databastion-agent run`.
5. Assert through `GET /api/agents` that the agent is `online` with target `pg-e2e` reported
   (the PostgreSQL connector is still a stub: the target is reported unreachable, audit level
   `none`, which is printed but not asserted), and that `/metrics` (scraped from inside the web
   container with the metrics token) shows `databastion_agent_up{agent_id="…"} 1`.
6. Revoke the agent through the user API; within 60 s the agent must log
   `console rejected the current secret (401)`; the measured latency is printed and the test
   fails at 60 s or more. The console must show `revoked`, and the proxy access log must show no
   `/api/agent/v1/jobs` request during a 10 s window afterwards.
7. Dump every container log (plus the one-shot command outputs) and fail if any generated
   secret (enrollment token, agent secret, admin password, session cookie, metrics token,
   database passwords, encryption key) appears in clear text.

On exit, whatever the result: logs are written to `$E2E_LOG_DIR` (default `e2e/.logs/`,
ignored by git), the stack and its volumes are removed, the temporary directory is deleted.

## Running locally
Requirements: Docker with Compose v2, `openssl`, `curl`, `jq`, bash.

```sh
e2e/run.sh
E2E_HTTPS_PORT=9443 e2e/run.sh      # if 8443 is taken on 127.0.0.1
```

The first run builds both images (several minutes). No secret is written to the repository;
nothing listens outside `127.0.0.1`.
