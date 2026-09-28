# End-to-end tests

Phase 1 exit criterion ([ROADMAP](../docs/ROADMAP.md)): *end-to-end enrollment in containers;
revocation effective in < 60 s*; and the invariant I2 test (P2-E): *no value of
[`dev/ground-truth.json`](../dev/ground-truth.json) in clear text in the console, including
value-bearing object and field names*. [`run.sh`](run.sh) drives
[`docker-compose.yml`](docker-compose.yml); the CI job is
[`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml).

## What runs
| Service | Image | Role |
|---------|-------|------|
| `db` | PostgreSQL 17 | Console internal database; roles created by `deploy/initdb/` |
| `migrate` | `console/Dockerfile` | One-shot migrations as the owner role |
| `web`, `worker` | `console/Dockerfile` | Console processes (runtime role) |
| `proxy` | Caddy | TLS 1.3 reverse proxy, certificate from a throwaway CA; `/metrics` answers `404` |
| `target-pg` | PostgreSQL 17 | Declared target of the agent, database `shop` loaded with the committed dev seed [`dev/seed/out/postgres.sql`](../dev/seed/out/postgres.sql) (schemas `crm`, `billing`, `ops`, value-bearing table names included); [`target-initdb/`](target-initdb/) creates the agent's read-only role and its per-schema Discovery grants |
| `agent` | [`agent/Dockerfile`](../agent/Dockerfile) | `databastion-agent`, HTTPS only (`ca_file` pins the test CA), `DATABASTION_LOG=debug` so the I2 log scan covers debug-level logging |
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
   idle-in-transaction timeouts; Discovery grants `USAGE` + `SELECT` on `crm`, `billing`, `ops`
   and default privileges, after the seed: I4); the superuser password never leaves `target-pg`.
   Before anything starts, the I2 scanner's positive control checks that every searchable
   PostgreSQL value of the ground truth is visible in the committed seed.
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
   `postgres: {databases: [shop], tls: disable_insecure}` in `agent.yaml`, SCRAM only; the audit
   level, `none` without `pg_stat_statements`, is printed but not asserted), that `databastion_agent` has exactly the
   attributes above (memberships exactly `pg_read_all_stats`, role settings in
   `pg_db_role_setting` exactly the four defaults) and, in its own session, gets the defaults and
   is denied `pg_authid` / `pg_user_mapping`, that its Discovery grants are exactly `USAGE`
   (no `CREATE`) on the seeded schemas, `SELECT` on their tables and no write privilege outside
   the system catalogs, and that `/metrics` (scraped from inside the web
   container with the metrics token) shows `databastion_agent_up{agent_id="…"} 1`.
6. Discovery (P2-E): launch a `discovery.scan` of `pg-e2e` through the user API (admin session +
   CSRF) and wait for the job to succeed (240 s at most). The agent reports the job status before
   its spooled findings batches are uploaded, so the test then waits (90 s at most) for a
   heartbeat received after the job ended whose spool status (`agents.spool`) reports no batch
   left and no dropped batch or item, checks that the agent log shows no lost / dropped /
   rejected result batch, and that the stored findings count is stable.
   [`i2_check.py findings`](i2_check.py) asserts at least one finding, the presence of
   `pii.email`, `pii.card_number`, `pii.iban` and `secret.aws_key`, that the value-bearing table
   `crm.export_client_<phone>` is stored under its `expected_normalized_name` (`*`) and that no
   finding stores a raw value-bearing name; it also prints how many ground-truth locations were
   found (informational). The findings page is fetched with the session (masked samples are
   decrypted there; they are encrypted at rest in the database); [`i2_check.py page`](i2_check.py)
   asserts it is complete (every finding listed, fewer than the 500-row listing cap, every
   finding with stored samples renders them, none `unavailable`) and that no masked sample keeps
   more than 4 digits (a partial masking regression the value search cannot see).
7. Revoke the agent through the user API; within 60 s the agent must log
   `console rejected the current secret (401)`; the measured latency is printed and the test
   fails at 60 s or more. The console must show `revoked`, and the proxy access log must show no
   `/api/agent/v1/jobs` request during a 10 s window afterwards.
8. Dump every container log (plus the one-shot command outputs); fail if `agent.log` or
   `web.log` is empty; run a positive control (a random canary written to the log directory must
   be found by the scan and redacted, then it is removed); fail if any generated secret
   (enrollment token, agent secret, admin password, session cookie, metrics token, database and
   target passwords, encryption key) appears in clear text.
9. `pg_dump` the console database into the private temporary directory (never the log
   directory) and fail if the agent secret, the enrollment token, the admin password or a
   target password is stored in clear text.
10. Invariant I2: [`i2_check.py scan`](i2_check.py) searches the plain dump of the whole console
    database (every schema, `pgboss` included), every container log except `target-pg`'s own
    (the source database; `all.log` includes it) and the rendered findings page for every
    PostgreSQL value of the ground truth and every value-bearing name. A canary file holding
    one ground-truth value must be reported by the log scan first (positive control).

### What "in clear" means (I2)
The definition is in the docstring of [`i2_check.py`](i2_check.py); unit tests in
[`test_i2_check.py`](test_i2_check.py) (`python3 -m unittest discover -s e2e -p 'test_*.py'`),
including pg_dump COPY-format and React Server Components payload excerpts with planted leaks.
- Case-, accent- and NFC / NFD-insensitive substring search, on the file as is and after decoding
  JSON `\uXXXX`, URL `%XX`, HTML character references and SQL doubled quotes.
- Values with fewer than 8 letters / digits must stand at word boundaries (`_` is a boundary:
  `archive_lucas_martin` matches `martin`, `Martinez` does not).
- Phones, cards, IBANs, NIRs and digit names (at least 9 letters / digits, 6 of them digits) are
  also searched without separators (space, `.`, `-`, `/`, `(`, `)`, `+`, `_`), in national and
  international phone forms and as the national significant number, IBANs also as their BBAN,
  never as part of a longer digit run. Masked samples (at most 4 digits, `*` elsewhere) cannot
  match: `*` is not a separator.
- E-mail local parts with at least 8 letters / digits are extra needles, at word boundaries.
- Partial digit runs (e.g. 8 of 16 card digits) are not searched in the dump and logs (the seed's
  shared prefixes would match timestamps and hashes); the findings page check bounds the clear
  digits of every masked sample instead.
- Excluded, and counted in the output: values with fewer than 4 letters / digits (`Ava`, `Mia`,
  `Noé`, `Léa`, `Zoé`), and folded single words listed in `COMMON_WORDS` with a justification
  (empty today).
- Output: counts, needle ids (`L<location>.v<value>`, `.n<name value>`, `.object`), the location
  (a value-bearing name is shown as `<value-bearing name>`) and the file name; never a value.

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
