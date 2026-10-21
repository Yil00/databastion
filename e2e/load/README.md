# Load / database impact tests

ROADMAP phase 7, "Load / database impact tests". [`run.sh`](run.sh) drives
[`docker-compose.yml`](docker-compose.yml) (the e2e stack reduced to the console, a PostgreSQL, a
MariaDB and a MongoDB target, the agent and two workload clients) and measures:

1. **Database CPU impact of Discovery** (MVP criterion of
   [docs/04-mvp-scope.md](../../docs/04-mvp-scope.md): *< 2 % CPU during Discovery, bounded
   sampling*), on PostgreSQL, MariaDB and MongoDB, with a scaled-up seed generated at run time.
2. **The Audit path under load**: a sustained, fixed-rate workload (pgbench on PostgreSQL, sysbench on
   MariaDB) without, then with Audit: the agent keeps up, nothing is dropped, the latency the workload
   sees with and without Audit.
3. **Agent resource bounds**: CPU and RSS of the agent over the 10-minute Audit run, bounded and
   without monotonic growth (a cheap proxy of the 72 h stability test, which the maintainer runs).

The SQL Server, Valkey / Redis and CAS targets have runs of their own on the same model:
[SQL Server target](#sql-server-target), [Valkey and Redis targets](#valkey-and-redis-targets) and
[CAS target](#cas-target).

The CI job is `load` in [`.github/workflows/load.yml`](../../.github/workflows/load.yml): weekly,
on demand (`workflow_dispatch`, with the Audit run length as input) and on pull requests labelled
`load-test`. It is **not** part of the required `CI result` check (about 30 minutes). It uploads
`results.json` and `results.md` (also written to the job summary) as the `load-results` artifact,
and the redacted logs when it fails. The unit tests of the harness run on every pull request.
On pull requests the job runs when the `load-test` label is added, and again on every new commit
while the label stays. **For a pull request from a fork, remove the label when new commits arrive and
re-apply it only after reviewing them**: the job runs the pull request's code (with `contents: read`
and no secret, but on a runner for about 30 minutes). Before redaction, the run scans its logs and
results for every generated secret (with a canary as positive control, as `e2e/run.sh`); a hit is
logged as `LEAK:` and fails the run. The raw pgbench / sysbench summaries go to the logs only.

**Status (CI load job on commit `d04bbf6`, the final head of PR #93, 2026-09-30): every check passes.** Discovery impact
while a scan runs: 0.32 % on MariaDB, 0.27 % on MongoDB, 0.05 % on PostgreSQL. Audit:
`events_accounted` exactly 1 (nothing lost, nothing counted twice). Agent peak RSS: 40.7 MiB.

The first local runs (2026-09-30, `LOAD_PG_AUDIT=pss`) had two failing checks, both findings about
the agent rather than harness defects, fixed since then (PR 93):
- Discovery: objects were sampled back to back, without pacing, so each server worked at about 20 to
  25 % of one core while a scan ran (about 10 to 12 % of a 2-CPU server for PostgreSQL and MariaDB,
  about 5 % for MongoDB). Scans are now paced at a bounded duty cycle
  (`limits.discovery_duty_cycle_percent`, ADR-0035).
- MariaDB Audit: about 12 % of the statements were counted twice when concurrent sessions interleaved
  their `server_audit` records. The agent now groups the records of a statement per connection.

In those runs the Audit path otherwise kept up (nothing spooled or dropped, events stored within about
65 s), the workload's p95 latency did not move with Audit on, and the agent stayed at about
0.012 core and 28 to 36 MiB RSS over 10 minutes at 600 statements per second, without growth.

## Running it
Requirements: Docker with Compose v2 on a cgroup v2 (or v1) Linux host, `openssl`, `curl`, `jq`,
`python3`, bash. At least 4 CPUs and 8 GB of memory are advised (the three targets get 2 CPUs each).

```sh
e2e/load/run.sh                                  # about 30 minutes (images built first)
LOAD_SOAK_S=120 LOAD_BASELINE_S=60 e2e/load/run.sh   # shorter Audit run, for a quick look
LOAD_SKIP_BUILD=1 e2e/load/run.sh                # reuse the images built by e2e/run.sh
python3 -m unittest discover -s e2e/load -p 'test_*.py'   # unit tests (no Docker)
```

`LOAD_SKIP_BUILD=1` (ignored under GitHub Actions) uses `databastion-console:e2e`,
`databastion-agent:e2e` and `databastion-dev/postgres:17.11-pgaudit` as built by `e2e/run.sh`
(`LOAD_CONSOLE_IMAGE`, `LOAD_AGENT_IMAGE`, `LOAD_TARGET_PG_IMAGE` name other tags). Where the apt
mirrors that `dev/postgres` needs are blocked, `LOAD_PG_AUDIT=pss` (local runs only, refused under
GitHub Actions, as e2e's `E2E_PG_AUDIT=pss`) runs `target-pg` on the plain pinned image with
`pg_stat_statements` only: the agent's PostgreSQL Audit source is then `pg_stat_statements`
(Limited), and the pgaudit logging cost is absent from the Discovery and workload measurements.
Behind an HTTP proxy, add `console.e2e.internal` to `NO_PROXY`.

Results go to `$LOAD_RESULTS_DIR` (default `e2e/load/.results/`), logs to `$LOAD_LOG_DIR` (default
`e2e/load/.logs/`); both are ignored by git. The exit status is non-zero when a check fails; every
check is listed in `results.md` with its value and limit. As in [`e2e/run.sh`](../run.sh), every
secret is generated at run time, registered, masked under GitHub Actions and redacted from the logs
before they are kept; the stack and its volumes are removed on exit. Nothing listens outside
`127.0.0.1` (the TLS proxy, on `LOAD_HTTPS_PORT`, default 8543, so the harness can run next to a
local `e2e/run.sh`).

| Variable | Default | Meaning |
|----------|---------|---------|
| `LOAD_TABLES`, `LOAD_ROWS` | 400, 1 000 000 | Scaled seed of PostgreSQL and MariaDB: tables, rows over them |
| `LOAD_MONGO_TABLES`, `LOAD_MONGO_ROWS` | 200, 500 000 | Scaled seed of MongoDB: collections, documents |
| `LOAD_DB_CPUS` | 2 | CPU limit of each target container: the "CPU capacity" of the Discovery impact |
| `LOAD_SAMPLE_ROWS` | 200 | Rows sampled per object (the console default; the scan also uses its defaults of 900 s and 30 s per statement) |
| `LOAD_IDLE_S` | 45 | Length of each idle baseline |
| `LOAD_PG_RATE`, `LOAD_MARIADB_RATE` | 300, 300 | Workload statements per second (fixed rate) |
| `LOAD_CLIENTS` | 4 | Workload connections per engine |
| `LOAD_WORKLOAD_TABLES` | 40 | Tables the workload reads: the first ones of the plan (pgbench takes at most 128 scripts) |
| `LOAD_BASELINE_S` | 120 | Workload without Audit |
| `LOAD_SOAK_S` | 600 | Workload with Audit: the Audit measurements and the agent resource run (at most 1800) |
| `LOAD_DRAIN_TIMEOUT_S` | 300 | Longest wait for the Audit run's events after the workload |
| `LOAD_PG_AUDIT` | `pgaudit` | `pss`: local runs without the pgaudit image (above) |
| `LOAD_HTTPS_PORT` | 8543 | Port of the TLS proxy on 127.0.0.1 |
| `LOAD_SQLSERVER_AUDIT_SOURCE` | `sqlserver_audit` | `sqlserver.sh` only: `sqlserver_xevents` for the Extended Events source ([below](#extended-events-source-catch-up-noise-282-review-n3)) |
| `LOAD_SQLSERVER_STATS_RESET_S` | 0 | `sqlserver.sh` only: drop the load schema's auto-created statistics every N seconds of the Audit run |
| `LOAD_LIMIT_<NAME>` | see below | Every field of `loadlib.Limits`, upper case, e.g. `LOAD_LIMIT_DISCOVERY_PCT=2.0`, `LOAD_LIMIT_DRAIN_S=240`, `LOAD_LIMIT_AGENT_REF_CPU_CORES=0.013` (the release reference of the agent checks) |

## Flow
1. Secrets, test CA, `agent.yaml` (targets `pg-load`, `mariadb-load`, `mongo-load`, the e2e accounts:
   ADR-0012 minimal role with the pgaudit jsonlog, ADR-0018 minimal account over verified TLS with
   the `server_audit` log, ADR-0026 account), workload scripts ([`seed.py`](seed.py)).
2. Build and start the console and the targets. The targets are the e2e ones (same images, the e2e
   and dev init scripts, the committed dev seed) plus the workload account `load_app`
   ([`initdb/`](initdb/)), granted `SELECT` table by table on the load tables; a CPU limit of `LOAD_DB_CPUS` each. Their
   Docker healthchecks run every 2 s while starting, then every 60 s: each check is a process inside
   the target's cgroup (30 to 70 ms of CPU), noise the idle baselines would otherwise absorb.
3. Start the sampler ([`loadlib.py sample`](loadlib.py)): every 0.5 s, each target's cgroup CPU
   counter, read on the host (`/proc/<pid>/cgroup` of the container's main process, then cgroup v2
   `cpu.stat` `usage_usec` or v1 `cpuacct.usage`), and the host's CPU counters.
4. **Scaled seed**, generated by the servers themselves from [`seed.py`](seed.py) (nothing large on
   disk, nothing committed): 400 tables in 4 schemas (PostgreSQL) or in `support` (MariaDB), every
   tenth table 20 times larger than the others (about 17 000 rows against 860), kinds `contact`
   (e-mail, phone), `billing` (IBAN with valid check digits, amount), `plain` (no sensitive column) and
   `mixed`; 200 collections in `app` (MongoDB). Synthetic, deterministic values: e-mails under example domains, phones in the ARCEP
   fiction range `+33 6 39 98`, IBANs with an unassigned bank code (`99xxx`). Sampling is bounded per object, so a scan's length depends on the number of objects, not
   rows: with 40 tables the scans lasted 0.2 to 0.5 s, dominated by fixed costs (connection,
   authentication, a new backend's catalog cache) and too short for the sampling interval; hundreds of
   objects give scans of a few seconds whose steady state is measured. PostgreSQL gets `VACUUM (ANALYZE)` and a `CHECKPOINT`, MariaDB `ANALYZE TABLE`; then the
   harness waits (at most 180 s) until every target uses at most 0.02 core over 10 s (background work of the load).
5. Enroll the agent (not started). **Idle baseline A**: `LOAD_IDLE_S` seconds, targets alone.
6. Start the agent; wait until it is online with the three targets reachable; start sampling the
   agent (every second: cgroup CPU, `VmRSS` / `VmHWM` of its process) and the heartbeat poller (every
   10 s: `agents.spool` and `agents.metrics` as the console stored them). **Idle baseline B**: agent
   running, no job.
7. **Discovery**: one `discovery.scan` per target, one after the other, through the user API with the
   console defaults. The scan window is the job's `first_delivered_at` → `finished_at` (console clock =
   host clock). The agent account's statement statistics are read before and after (PostgreSQL
   `pg_stat_statements` execution time, planning included when tracked, MariaDB
   `performance_schema` statement time), at
   least 2 s outside the window (these reads run inside the target's cgroup). Then a heartbeat must
   report an empty spool with nothing dropped, and every target must have findings.
8. **Workload without Audit**: pgbench (`-M simple`, one point-select script per workload table,
   picked at random, `-R` fixed rate, per-transaction log) and sysbench (a Lua point-select script
   over the same tables, `--rate`, 95th percentile; the password in a `--config-file` on its tmpfs)
   run together for `LOAD_BASELINE_S` seconds, as `load_app`. Next to them on `target-mariadb`, the
   **side accounts** of [ADR-0045](../../docs/adr/0045-mysql-mariadb-statement-text-tables-and-unqualified-calls.md)
   ([`side-clients.sh`](side-clients.sh), service `my-side`, the target image's `mariadb` client),
   one session each, once a second: `load_monitor`, a monitoring-like reader (`SELECT` on
   `performance_schema` and `PROCESS`, as PMM or `mysqld_exporter`) of
   `events_statements_summary_by_digest`, `performance_schema.threads` and
   `information_schema.PROCESSLIST`; `load_builtins` (no privilege), a table-less built-in mix
   (`NOW()`, `LAST_INSERT_ID()`, `DATABASE()`, a Connector/J-style `@@session` probe,
   `CONNECTION_ID()`, `VERSION()`, `USER()`, `SET NAMES`, `SELECT 1`). Next to them, the **statistics
   readers** of [ADR-0048](../../docs/adr/0048-statistics-catalogs-as-reads.md), one session each,
   every 10 s: on `target-mariadb`, `load_colstats` (`SELECT` on `mysql.column_stats` only) reads
   the engine-independent column statistics of `support`, minimum and maximum values included; on
   `target-pg` ([`pg-side-clients.sh`](pg-side-clients.sh), service `pg-side`, the target image's
   `psql`), `load_pgmon`, a monitoring-like account (member of `pg_monitor`), runs a table bloat
   estimate on `pg_stats` (`avg_width`, `null_frac`, joined with `pg_class` and `pg_namespace`, as
   check_postgres or pgwatch do). Next to it, the readers of the **credential-bearing catalogs** of
   [ADR-0050](../../docs/adr/0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md):
   `load_pgexp`, an exporter-like account with no grant, reads `pg_roles`, `pg_proc` and
   `pg_subscription` without their secret columns every 5 s (the no-secret shape: no event), and
   `load_pgbouncer`, a PgBouncer-like account (member of `pg_read_all_data`), runs PgBouncer's
   default `auth_query` on `pg_shadow` every second (a secret read). They run in both phases, so
   the latency comparison sees the same load; their statements are not in the workload counts.
9. Audit on for `pg-load` and `mariadb-load` (`audit.configure` through the user API, contract
   defaults: aggregation 60 s, poll 10 s, no `min_rows`, so every event is reported); wait for the
   agent's "audit source" line. The stream starts at the end of the log: the baseline is not replayed.
10. **Workload with Audit**: the same, for `LOAD_SOAK_S` seconds.
11. **Drain**: wait until the stored `read` events of `load_app` account for every statement issued,
    then for a heartbeat with an empty spool. For diagnosis: the stored statements per 10 s of event
    time, and the workload's statements in the target's own audit log since the Audit run started
    (MariaDB: `QUERY` records of `load_app` in `server_audit.log` and its rotations; PostgreSQL:
    pgaudit `SESSION` records; none in `pss` mode), read after the measurements.
12. Report ([`loadlib.py report`](loadlib.py)): `results.json`, `results.md`.

## What is measured and asserted

### 1. Database CPU impact of Discovery (asserted: < 2 %)
Per target:

```
impact % = 100 x (C_db[scan] - r_idle x d_measured) / (d_scan x capacity)
```

A scan shorter than 60 s is asserted on `max(d_scan, 60 s)` instead of `d_scan` (the "Over 60 s"
column): below the 0.5 s CPU sampling and a session's fixed cost, a sub-second average measures noise
(the CAS ticket aggregate, a 0.6 s scan using 0.04 s of CPU, read 3.6 % over the scan and 0.03 % over
a minute). Scans of a minute or more, the paced Discovery scans of `run.sh`, are judged on their own
duration as before. The per-scan figure stays in the report.

- `C_db[scan]`: CPU time of the target's container (cgroup) from the last sample at or before the
  job's delivery to the agent to the first sample at or after the console recorded its end
  (`d_measured`, which contains the scan window).
- `r_idle`: the container's CPU rate during **idle baseline A** (targets alone, their Docker
  healthchecks included, before the agent starts). Subtracting it leaves everything the agent caused
  during the scan, Discovery **and** its periodic heartbeat checks: the conservative choice.
  `impact_pct_vs_agent_idle` (baseline B, agent running) is reported too, for the scan alone.
- `d_scan`: `finished_at - first_delivered_at` of the job.
- `capacity`: the container's CPU limit read from its cgroup (`cpu.max`, `LOAD_DB_CPUS` = 2 by
  default: a small production server), capped by the host's CPU count.

So "2 %" is **the average share of the database server's CPU capacity that the agent added while the
scan ran**. The numerator covers a slightly longer interval than the denominator: the figure errs on
the high side. Also reported: the absolute CPU seconds, the same share of **one** core
(`one_core_pct`, independent of `LOAD_DB_CPUS`), the host's CPU use during the scan (a saturated
runner is visible), the attributable CPU per object and the scan time per object, the same CPU
spread over one minute when the scan is shorter (`impact_pct_60s`: what a CPU graph at a one-minute
resolution shows), and the agent account's own statement time from the engine's statistics
(`stmt_exec_ms`, a cross-check; not asserted: execution time is not CPU time, and MongoDB has none).

### 2. Audit path under load
| Check | Limit | Meaning |
|-------|-------|---------|
| `audit.<target>.workload_ran` | issued > 0, 0 failed | pgbench `failed transactions`, sysbench `ignored errors` |
| `audit.<target>.events_accounted` | 0.99 to 1.01 | sum of `aggregated_count` of `load_app`'s `read` events / statements issued during the Audit run: nothing lost, nothing counted twice |
| `audit.<target>.drain_s` | ≤ 240 s | end of the workload → last of those events stored (`received_at`); includes the 60 s aggregation window by design |
| `audit.<target>.p95_latency_ms` | ≤ 3 × p95 without Audit + 5 ms | p95 latency of the workload with Audit vs without (pgbench: per-transaction log, from the scheduled start; sysbench: its 95th percentile). Generous on purpose: shared CI runners are noisy |
| `audit.mariadb-load.monitor_ran`, `.builtins_ran` | issued > 0, 0 failed | the side accounts ran in both phases (statements counted for the Audit run) |
| `audit.mariadb-load.monitor_reported` | `threads` and `PROCESSLIST` named | the reader's reads of [statement-text tables](../../docs/08-engine-capabilities.md#statement-text-tables) are events naming them (ADR-0045 part (a); the digest summary has no statement text on MariaDB and stays quiet) |
| `audit.mariadb-load.monitor_one_event_per_window` | ≤ 0 | per principal, action, source and object set: events − (⌊span / 60 s⌋ + 2), where span is first `ts` → last `ts_last`. The agent's aggregation windows last at least 60 s (the contract default) and follow each other, so that is the most windows such a span can meet: at most one event per window. It catches an unaggregated stream (one event per statement), not a single extra event |
| `audit.<target>.stats_ran`, `.stats_reported`, `.stats_one_event_per_window` | as `monitor_*` | the statistics readers of [ADR-0048](../../docs/adr/0048-statistics-catalogs-as-reads.md) (`pg-load`: `load_pgmon`, expected object `shop.pg_catalog.pg_stats`; `mariadb-load`: `load_colstats`, `mysql.column_stats`): ran without failure, their reads are events naming the statistics relation, and at most one event per principal, action, source and object set per aggregation window (same bound as `monitor_one_event_per_window`) |
| `audit.pg-load.secrets_ran`, `.secrets_reported`, `.secrets_one_event_per_window` | as `monitor_*` | the PgBouncer-like `auth_query` of [ADR-0050](../../docs/adr/0050-postgresql-credential-and-value-bearing-catalogs-as-reads.md) (`load_pgbouncer`, expected object `shop.pg_catalog.pg_shadow`): ran without failure, its reads are events naming `pg_shadow`, at most one per principal, action, source and object set per aggregation window |
| `audit.pg-load.catalogs_ran`, `.catalogs_no_event` | ran, 0 non-connect events | the exporter-like reader of `pg_roles`, `pg_proc` and `pg_subscription` without their secret columns (`load_pgexp`, ADR-0050 decision 2) ran without failure and gave no event |
| `audit.pg-load.pgaudit_catalog_volume_reported` | measured, `log_catalog` on, > 0 reader records | the pgaudit log volume over the Audit run was measured with `pgaudit.log_catalog = on` (as the database's sessions see it) and holds the statistics reader's records (pgaudit mode only); the volume itself is reported, not asserted |
| `audit.mariadb-load.builtins_no_event` | 0, with ≥ 1 event | events of `load_builtins` other than its connection: table-less built-in calls are never unknown calls (ADR-0045 part (b)); its connection event must be there, so that the check cannot pass on a stream that never saw the account |
| `agent.spool_bounded` | ≤ 1000 batches | peak `spool.batches` over the heartbeats of the run |
| `agent.spool_drained` | 0 | a heartbeat after the drain reports an empty spool |
| `agent.no_dropped_batches` | 0 | `spool.dropped_batches` and `dropped_items` (the documented drops happen only when the spool is full, `spool` in [`agent.example.yaml`](../../agent/agent.example.yaml)) |
| `agent.<counter>` | 0 | `events_lost_total`, `findings_lost_total`, `audit_stream_failures_total`, `audit_records_skipped_total`, `audit_record_panics_total`, `connector_panics_total`, `batches_rejected_total` |
| `agent.log_no_lost_batches` | 0 lines | the agent log has no lost / dropped / rejected batch line (as e2e) |

**pgaudit log volume** (pgaudit mode, ADR-0048 open question 6): over the Audit run (workload start to
end, by the log lines' timestamps), the lines and bytes of the server's `jsonlog` file, its MiB per
hour, and the pgaudit records and bytes per role: `load_app` (the workload), `load_pgmon` (the
statistics reader: catalog-only statements, logged because `log_catalog = on`), `load_pgexp` and
`load_pgbouncer` (the ADR-0050 readers), `databastion_agent`
(the agent's own `check()` and Discovery catalog reads, logged for the same reason) and `other`.
Counts and sizes only, read inside the container.

Reported without assertion: the workload's statements found in the target's own audit log (received
> source means the agent counted some twice; source > issued, that the server logged more), the
stored statements per 10 s, the added p95 in ms and %, pgbench p99 and service-time p95 (latency minus
schedule lag), the targets' CPU with and without Audit (the engine's own logging cost is present in
both phases: the "without" phase has pgaudit / `server_audit` on, the agent's stream off), the event
lag p95 (`received_at - ts_last`), the agent's CPU per 1000 statements.

### 3. Agent resources
| Check | Limit | Meaning |
|-------|-------|---------|
| `agent.cpu_cores_audit_on` | ≤ 1 core | agent container CPU over the Audit run (from 5 s after its start) |
| `agent.rss_peak_mb` | ≤ 256 MiB | peak `VmRSS` of the agent process over the whole run |
| `agent.rss_no_monotonic_growth` | see below | `VmRSS` over the Audit run |
| `agent.cpu_no_monotonic_growth` | see below | CPU rate over 30 segments of the Audit run |
| `agent.cpu_vs_release_reference` | ≤ 0.033 core | ADR-0048: with the statistics readers, the agent's CPU over the Audit run against the 0.6.0 release run (0.013 core, `dev` `2b55117`, run 38038485048): reference + max(0.02 core, 100 %), the noise between CI runs (0.012 to 0.024 core so far) |
| `agent.rss_vs_release_reference` | ≤ 58 MiB | the same for the peak `VmRSS` (reference 42 MiB): + max(16 MiB, 25 %) |

Growth verdict: the first 20 % of the run is a warm-up; the rest is cut into three equal parts. It
fails when the three medians strictly increase **and** the last exceeds the first by more than
max(8 MiB, 10 %) (RSS) or max(0.05 core, 50 %) (CPU). A plateau after a warm-up, a spike or noise
passes. The least-squares slope (MiB per hour) is reported. This only catches a fast leak; the 72 h
test remains the reference.

A check without data (a sample series missing, a workload that printed no summary) counts as failed.

## CAS target
[ADR-0041](../../docs/adr/0041-cas-connector.md) decision 14 ("Load"), ROADMAP P8-D. [`cas.sh`](cas.sh)
runs the e2e CAS stack ([`../docker-compose.cas.yml`](../docker-compose.cas.yml), the CAS 8.0 dev
overlay and its JPA ticket registry, see [e2e/README.md](../README.md#cas-target)) with
[`docker-compose.cas.yml`](docker-compose.cas.yml) here (CPU limits `LOAD_CAS_CPUS` / `LOAD_DB_CPUS`,
default 2, and 60 s healthchecks), Compose project `databastion-load-cas`. The CAS connector reads
local files only: there is no database to measure for its sources. The CI job is `load-cas` in
[`load.yml`](../../.github/workflows/load.yml), next to `load`, with the same triggers (artifact
`load-cas-results`).

1. Workload from the host, [`../cas_scenario.py`](../cas_scenario.py) `load`: `LOAD_CAS_RATE`
   successful logins per second (default 4, the three e-mail users in turn, each with a validated
   service ticket) and `LOAD_CAS_FAIL_RATE` failed ones (default 1, random names, one client
   address: past 16 names in 10 minutes they join the `*` aggregate), on `LOAD_CAS_WORKERS` threads
   (16): `LOAD_CAS_WARMUP_S` (90) not measured (a freshly started CAS is several times slower for
   its first minute or two: the first local run measured a p95 of 5 s cold against 0.45 s warm),
   then `LOAD_BASELINE_S` without Audit and `LOAD_SOAK_S` with Audit on `cas-load`: about 17 audit
   records per second (four per login: authentication, ticket-granting ticket, service ticket, its
   validation). The defaults leave CAS headroom on its 2 CPUs: in a local run at 10 logins per
   second it was saturated (p95 of the credential POST above 1 s, the schedule finishing late), which
   measures CAS's queue, not the agent. A workload window ends when its last login returned. The
   dev `log4j2.xml` rotates the log at 10 MB: a long run (or a higher rate) crosses a rotation.
2. The same report as `run.sh` ([`loadlib.py report`](loadlib.py)), on the target `cas-load`
   (container `cas`): `issued` is the records that give an event (per successful login a `connect`
   and a `read`, per failed one an `auth_failure`), so `audit.cas-load.events_accounted` (0.99 to
   1.01) compares the sum of `aggregated_count` of the stored `connect`, `read` and `auth_failure`
   events with them; `p95_latency_ms` is the credential POST's p95 with and without Audit (the
   agent only reads the log); the CAS container's CPU with and without Audit; the records of those
   actions in the CAS audit log and its rotations since the Audit run started (source side, not
   asserted); the agent's CPU, RSS, growth, spool and counters as in `run.sh`.
3. The CAS store guard's ticket aggregate: after the workload, `cas_tickets` holds the run's
   ticket-granting tickets (thousands; CAS keeps them for 8 hours). One Discovery scan of the
   PostgreSQL target `casdb-load` (the ADR-0012 role with the decision 6 column grants), measured as
   the database scans of `run.sh`: `discovery.casdb-load.db_cpu_impact_pct` < 2 % of `cas-db`'s CPU
   capacity.

```sh
e2e/load/cas.sh                                     # about 25 minutes (images built first)
LOAD_SOAK_S=120 LOAD_BASELINE_S=60 e2e/load/cas.sh  # a quick look
LOAD_SKIP_BUILD=1 e2e/load/cas.sh                   # reuse the images built by e2e/cas.sh
```

Results go to `$LOAD_RESULTS_DIR` (default `e2e/load/.results-cas/`), logs to `$LOAD_LOG_DIR`
(default `e2e/load/.logs-cas/`); the TLS proxy listens on `127.0.0.1:${LOAD_HTTPS_PORT:-8543}` and
CAS on `127.0.0.1:${LOAD_CAS_PORT:-8282}`. `LOAD_SKIP_BUILD=1` (ignored under GitHub Actions) uses
`databastion-console:e2e`, `databastion-agent:e2e` and `databastion-dev/cas:8.0.2-overlay`
(`E2E_CONSOLE_IMAGE`, `E2E_AGENT_IMAGE`, `E2E_CAS_IMAGE` name other tags). Secrets are generated,
registered, scanned for and redacted as in `run.sh`.

**Status**: first CI run on `dev` 684966d (run 37235163505, PASS): 4 logins and 1 failed login per second for 600 s with Audit, 5 400 events for 5 400 records, drain 65.2 s, CAS POST p95 +0.8 ms, agent 0.0007 core and 17.9 MiB peak RSS without growth, ticket-aggregate scan 0.803 % of a 2-CPU server (0.03 % over 60 s); see [docs/08](../../docs/08-engine-capabilities.md). Earlier, A local run (2026-10-04, 10 logins and 2 failed logins per second, 60 s
without and 120 s with Audit, `LOAD_IDLE_S=20`; a 4-CPU host shared with everything else) passed
every check: 2640 events for 2640 records issued and 2640 in the CAS audit log (one rotation
crossed), drained 70 s after the workload (the 60 s aggregation window included), the agent at
0.0014 core and 18.6 MiB peak RSS without growth, nothing spooled or dropped; the ticket aggregate's
scan of 1800 tickets took 1.2 s and 1.1 % of `cas-db`'s 2 CPUs (26 ms of CPU, mostly the fixed cost
of a session: a one-object scan is short). CAS itself was saturated at that rate (above), hence the
lower defaults. With them and a 30 s warm-up (60 s with Audit), the next local run also passed: 540
events for 540 records, p95 of the credential POST 551 ms without Audit and 306 ms with it, CAS at
1.4 to 1.6 cores, the agent at 0.001 core and 18 MiB. The numbers of record come from the CI job.

## SQL Server target
ROADMAP P9-D, [ADR-0051](../../docs/adr/0051-sqlserver-connector.md) "End-to-end and load".
[`sqlserver.sh`](sqlserver.sh) runs the e2e SQL Server stack
([`../docker-compose.sqlserver.yml`](../docker-compose.sqlserver.yml): the dev SQL Server 2022 Express
service, see [e2e/README.md](../README.md#sql-server-target)) with
[`docker-compose.sqlserver.yml`](docker-compose.sqlserver.yml) here (CPU limit `LOAD_DB_CPUS`, default
2, and 60 s healthchecks), Compose project `databastion-load-sqlserver`, target `mssql-load` (the
agent login of the minimal variant, `tls: auto` with the dev CA, the RLS opt-in, `audit: {source:
sqlserver_audit, audit_name: databastion_audit}`). The CI job is `load-sqlserver` in
[`load.yml`](../../.github/workflows/load.yml), next to `load`, with the same triggers (artifact
`load-sqlserver-results`, 75 min budget). Express, as everywhere in CI (ADR-0051 open question 13):
its limits (one socket or four cores, 1 410 MB of buffer pool, 10 GB per database) are far above
this run's.

1. **Settle.** SQL Server runs start-up background work for its first minutes: bursts of about
   5 CPU-seconds were seen up to 5 minutes after the start of an idle server, none in the 9 minutes
   after. The baselines and the scan start once the server has been up `LOAD_MSSQL_SETTLE_S`
   (default 480) seconds; in a first local run without it, those bursts fell into the scan window
   and doubled the measured impact.
2. **Scaled seed**, generated by the server ([`seed.py sqlserver`](seed.py): `GENERATE_SERIES`,
   the same synthetic values as the other engines): `LOAD_MSSQL_TABLES` tables (default 100) sharing
   `LOAD_MSSQL_ROWS` rows (default 500 000) in the schema `load` of `retail`, granted to the agent
   login and to the workload login `load_app` (schema `SELECT`), then a `CHECKPOINT`.
3. **Discovery**: one paced scan with the console defaults (`LOAD_SAMPLE_ROWS`, 900 s), measured as
   in `run.sh` (`discovery.mssql-load.db_cpu_impact_pct` < 2 % of the server's CPU capacity). The
   cross-check `stmt_exec_ms` is the worker time of every statement in the server's plan cache
   during the scan (`sys.dm_exec_query_stats`, read as `sa` before and after, outside the window).
4. **Workload**: `LOAD_CLIENTS` (4) `sqlcmd` sessions as `load_app` in the `mssql-client` container,
   each a T-SQL loop ([`seed.py tsql`](seed.py)) of point selects on the first
   `LOAD_WORKLOAD_TABLES` (40) load tables, `LOAD_MSSQL_RATE` (300) statements per second in total
   on an absolute schedule (`WAITFOR DELAY`): `LOAD_WARMUP_S` (30) unmeasured, then
   `LOAD_BASELINE_S` without Audit and `LOAD_SOAK_S` with Audit (contract defaults: 60 s
   aggregation, 10 s polls). Each executed `SELECT` is one SQL Server Audit record (measured: a loop
   of 100 gives 100 `SL` records with 100 transaction ids), so `issued` is the statements run, and
   `audit.mssql-load.events_accounted` compares the stored `read` events of `load_app` with them;
   the audit file's `SL` records of `load_app` since the Audit run started are the "In the target's
   log" column.
5. **Latency.** `sqlcmd` cannot time single statements, and the server's clock (`SYSUTCDATETIME`)
   advances in steps of about 4.1 ms on Linux (measured), so each in-loop time of a sub-millisecond
   `SELECT` is 0 or one step: no percentile is meaningful. The mean over many statements is an
   unbiased estimate of the mean duration (a step falls inside a statement with probability
   duration / step), so the latency figure (`p95_ms`, named `latency_metric` in the report) is the
   **mean in-loop duration per workload statement**, compared with the same bound as the other
   engines' p95. Neither the plan cache nor Query Store gave per-phase counts for these batches
   (measured: no plan cache entry; Query Store's AUTO capture starts late). The schedule lag p95 of
   the sessions is reported too.

```sh
e2e/load/sqlserver.sh                                   # about 40 minutes (images built first)
LOAD_SOAK_S=120 LOAD_BASELINE_S=60 LOAD_MSSQL_TABLES=40 LOAD_MSSQL_ROWS=80000 e2e/load/sqlserver.sh
LOAD_SKIP_BUILD=1 e2e/load/sqlserver.sh                 # reuse the images built by e2e/sqlserver.sh
LOAD_MSSQL_DIAG=1 e2e/load/sqlserver.sh                 # local only: the scan's top statements
```

### Extended Events source: catch-up noise (#282 review N3)

`LOAD_SQLSERVER_AUDIT_SOURCE=sqlserver_xevents` (default `sqlserver_audit`; workflow input
`sqlserver_audit_source` of `load.yml`) runs the same measurement with the Extended Events source:
`audit: {source: sqlserver_xevents, xe_session: databastion_xe}` (the dev session, as
[`e2e/sqlserver.sh`](../sqlserver.sh) with `E2E_SQLSERVER_AUDIT_SOURCE`), and the agent login holds
that source's grant only (the two SQL Server Audit grants revoked, `VIEW SERVER PERFORMANCE STATE`
granted, before the agent starts). Every statement of the workload's T-SQL loop is an Extended
Events event (`SET`, `IF`, `WAITFOR`, the table-variable insert: about 30 per workload `SELECT`), so
the default rate is 50 `SELECT`s per second with this source (`LOAD_MSSQL_RATE`, workflow input
`sqlserver_rate`), about 1 500 events per second, within the session's 8 files of 64 MB over a
600 s run. `LOAD_SQLSERVER_STATS_RESET_S=N` (default 0, off; workflow input
`sqlserver_stats_reset_s`) drops the load schema's auto-created statistics as `sa` every N seconds
of the Audit run (`DROP STATISTICS`, logged as `statistics resets: …`), so that the ORM-style
session's next reporting queries (`GROUP BY a0.status`) build them again in `load_orm`'s session:
statistics builds under load, which the stream may defer (ADR-0051 refinement of 2026-10-18). The
`sa` drops are DDL events of `sa`, always reported; they are not in the figures below.

The stream lag (both sources): while it waits for the drain, the run samples the statements stored
every 5 s, logs `drain: <stored>/<expected> statements stored <s> s after the workload` every 30 s,
and records a `drain` fact (`facts.jsonl`, not a check): the samples (seconds since the last
workload statement, statements stored), `stored_at_workload_end` and `rate_per_s`, the statements
stored per second during the drain. `drain_s` (the check) is the time from the last workload
statement to the last of them stored, `null` when the drain times out; the `drain` fact still shows
how far behind the stream was and how fast it caught up. The agent logs one `info` line per cycle
that ends behind its source ("Audit stream behind its source", with `reads` and `elapsed_ms`): the
agent's read rate, about `reads × 500 / elapsed_ms × 1000` events per second at most. Load run
39687119269 (Extended Events, 50 `SELECT`s/s, before the fix) stored 15 028 of 30 000 `SELECT`s
300 s after the workload: a stream still in its first start's history phase waited the poll
interval after every 20 reads, about 700 events/s against 1 500 written.

After the drain, the run prints (and writes to `$LOAD_RESULTS_DIR/xe-catchup.json` and
`xe-catchup.md`, the latter added to the job summary on exit, once the results directory is
redacted), never as a check:

- `XE-CATCHUP load-sqlserver cuts=… episodes=… longest_episode_s=… episodes_at_60s_cap=…`: the
  agent's debug line "a statistics build not paired yet: the read ends before it" since Audit
  started, one per read cut before an unpaired build (deferrals and full-read cuts alike: the
  agent logs both the same way), grouped in runs of cuts at most 30 s apart; a run that lasts about
  60 s reached the hold bound (`MAX_DEFERRAL`), after which nothing is deferred until the stream
  has caught up, and builds still unpaired are reported. The agent has no counter of the builds
  reported that way (the connector's left-out counts are test-only), hence the two sides below.
- `XE-BUILDS … principal=… statistics_builds_in_session_files=…`: the statistics builds
  (`sp_statement_completed` whose text is the `StatMan` grammar) in the session's files since
  Audit started, per principal (as `sa`, counts only); `XE-SELECTS`: `load_app`'s workload
  `SELECT`s there since the soak started (also the report's "In the target's log" column).
- `XE-NOISE … principal=load_app|load_orm events=… read_statements=… issued=…
  excess_read_statements=… unknown_star_events=… star_only_events=…`: the console's events of the
  workload principals. A reported build is a read of its table and its internal statements reads
  of `*`: the noise shows as read statements beyond those issued and as events naming `*` that the
  agent did not flag overflowed (`star_only`: `*` is the event's only object, the shape of a build's
  internal statement); `load_orm`'s overflowed reporting queries are counted apart.

```sh
LOAD_SQLSERVER_AUDIT_SOURCE=sqlserver_xevents LOAD_SQLSERVER_STATS_RESET_S=10 e2e/load/sqlserver.sh
```

`LOAD_MSSQL_DIAG=1` (refused under GitHub Actions) writes the 15 statements that used the most CPU
during the scan (their first 70 characters, which may name a value-bearing table) to
`diag-top-statements.txt` in the log directory. Results go to `$LOAD_RESULTS_DIR` (default
`e2e/load/.results-sqlserver/`), logs to `$LOAD_LOG_DIR` (default `e2e/load/.logs-sqlserver/`).

**Status: CI run 38978357006 on `dev` at `a529e13` (2026-10-16, soak 600 s): PASS.** Discovery 0.74 % of the
2-CPU server (111 tables, 500 000 rows, 224.6 s scan); Audit 180 000 / 180 000 statements at 300/s, drain 11.9 s;
no added latency; agent 0.009 core and 21.1 MiB, no growth, no loss. The earlier local runs below
found the SQL Server Audit loss fixed by #253.

Earlier local runs (2026-10-16), with a debug build of the agent (its CPU
figures are upper bounds) on a 4-CPU host shared with the console:
- Discovery: **0.884 %** of the 2-CPU server at the CI seed (100 load tables, 500 000 rows, 111
  tables with the dev seed; a 444 s scan; 0.161 % against the agent-idle baseline), **0.719 %**
  with 40 tables (208 s). A first run without the settle period read 3.09 %: the start-up bursts
  fell into the scan window.
- Audit at 300 statements/s: 36 000 of 36 000 statements stored (120 s with Audit), then 53 826 of
  54 000 (180 s) and 89 785 of 90 000 (300 s). Every statement was in the audit file
  (`fn_get_audit_file`), no agent counter showed a loss (`events_lost_total`,
  `audit_records_skipped_total`, panics, spool: all 0), and the source side had no grouping-key
  collision and at most about 300 records per audit buffer (a probe at the same rate). The ratio
  stays within the 1 % bound, but `drain_s` failed (not every statement arrived): buffers larger
  than the 500-record client-side skip, fixed by #253 (server-side skip).
- Latency: the mean duration per statement was 0.419 ms without and with Audit; the server's CPU
  0.217 / 0.249 core without / with the agent's stream.
- Agent: 0.114 core with Audit on (debug build: 377 ms of CPU per 1 000 statements), 35.4 MiB peak
  RSS, no growth, nothing spooled or dropped.

## Valkey and Redis targets
ROADMAP P9-D, [ADR-0052](../../docs/adr/0052-redis-valkey-connector.md) decision 13 ("Load").
[`redis.sh`](redis.sh) runs the e2e Valkey / Redis stack
([`../docker-compose.redis.yml`](../docker-compose.redis.yml), see
[e2e/README.md](../README.md#valkey-and-redis-targets)) with
[`docker-compose.redis.yml`](docker-compose.redis.yml) here (CPU limit `LOAD_DB_CPUS`, 60 s
healthchecks), Compose project `databastion-load-redis`, one server: `LOAD_REDIS_ENGINE=valkey` (the
default, Valkey 9.0.6) or `redis` (Redis 8.10.2), target `valkey-load` or `redis-load`
(`tls: verify_full`, the agent's defaults: every database, all key patterns, `max_keys` 100 000). The
CI job is `load-redis` in [`load.yml`](../../.github/workflows/load.yml) (a matrix over Valkey and Redis since #258, artifacts
`load-valkey-results` and `load-redis-results`, 60 min budget each).

1. **Scaled keyspace**, written by the server (`EVAL` of [`seed.py redis`](seed.py) in chunks of
   100 000, as `admin` on its socket): `LOAD_REDIS_KEYS` keys (default 1 000 000) in `db0` next to
   the dev keyspace, `load:s:<n>` strings (an e-mail address) and, every tenth, `load:h:<n>` hashes
   (e-mail, phone, status), then a `BGSAVE` and a quiet wait.
2. **Discovery**: one paced scan (`LOAD_SAMPLE_ROWS` keys per pattern, 900 s), measured as in
   `run.sh`; the "Objects" column is the keyspace size (the walk stops at `max_keys` per database and
   counts the rest `skipped_limit`, docs/08).
3. **Workload** from the host ([`../redis_scenario.py load`](../redis_scenario.py)): `GET`s of 1 000
   string keys as the ACL user `load_app` (`~load:*`, `+get`), `LOAD_REDIS_RATE` per second
   (default 200) over `LOAD_CLIENTS` (4) TLS connections opened before the schedule and held after
   it, `LOAD_BASELINE_S` without Audit and `LOAD_SOAK_S` with Audit, which polls every
   `LOAD_REDIS_POLL_S` (default 1) seconds (`audit.configure` `poll_interval_s`, with
   `limits.min_audit_poll_interval_s: 1` in `agent.yaml`). The slow log logs every command
   (`slowlog-log-slower-than 0`) and keeps `LOAD_REDIS_SLOWLOG_MAX_LEN` (4 096) entries; the agent
   reads at most 512 per poll, so the rate times the poll interval must stay well below 512: the
   default 200 per second leaves room for the agent's own entries and a late poll.
   `audit.<target>.events_accounted` compares the stored `read` events of `load_app` (attributed
   through the open connections) with the `GET`s that returned; the "In the target's log" column
   is the server's `cmdstat_get` calls over the Audit run (`INFO commandstats`). The server's CPU
   with and without Audit is the cost of the agent's polls (`SLOWLOG GET` / `COMMANDLOG GET`,
   `CLIENT LIST`, `INFO`).
4. **Latency**: `p95_ms` is the client-measured service time of a `GET` (sent to reply, named in
   the report), the latency from the scheduled start is reported too.

```sh
e2e/load/redis.sh                                          # about 30 minutes (images built first)
LOAD_SOAK_S=120 LOAD_BASELINE_S=60 LOAD_REDIS_KEYS=200000 e2e/load/redis.sh
LOAD_REDIS_ENGINE=redis LOAD_SKIP_BUILD=1 e2e/load/redis.sh
```

Results go to `$LOAD_RESULTS_DIR` (default `e2e/load/.results-redis/`), logs to `$LOAD_LOG_DIR`
(default `e2e/load/.logs-redis/`); the target's TLS port is published on
`127.0.0.1:${LOAD_VALKEY_PORT:-16479}` (or `LOAD_REDIS_PORT`, 16489) for the host-side client, by
this run's overlay ([`docker-compose.redis.yml`](docker-compose.redis.yml)) through `redis-net`, an
ordinary bridge network: the target has egress for the run's length (the end-to-end run's targets
do not: [e2e/README.md](../README.md#valkey-and-redis-targets)).

**Status: CI run 38978357006 on `dev` at `a529e13` (2026-10-16, soak 600 s): PASS.** Discovery 0.267 % (1 000 146
keys, 51.9 s scan); Audit 120 000 / 120 000 GETs at 200/s, drain 6 s; no added latency; agent 0.0024 core
and 17.1 MiB, no growth, no loss.

Earlier local runs (2026-10-16), Valkey 9.0.6, a debug build of the agent
(its CPU figures are upper bounds) on a 4-CPU host shared with the console; 60 s without and 180 s
with Audit; every check passed:
- Discovery of 1 000 146 keys (the walk stops at 100 000 per database): **0.133 %** of the 2-CPU
  server (262 s scan, 0.70 CPU-second attributable).
- Audit with the slow log at every command, polled every second, at 200 `GET`s per second:
  36 000 of 36 000 stored, attributed to `load_app`; nothing else reported (the agent's own polls
  left out). A second, shorter run (200 000 keys, 60 s with Audit; Discovery 0.146 %) after a fix of
  the workload's end time: 12 000 of 12 000, drained 63.8 s after the last `GET` (the 60 s
  aggregation window included).
- The polls' cost: the server at 0.0387 core without and 0.0413 core with the stream; the `GET`
  service time p95 1.127 ms without and 1.081 ms with Audit.
- Agent: 0.019 core with Audit on (97 ms of CPU per 1 000 commands), 32.7 MiB peak RSS, no growth,
  nothing spooled or dropped.

## Event census (ADR-0053 decision 6, informational)

[ADR-0053](../../docs/adr/0053-overflowed-event-objects-flag.md) is accepted only after the rate of
events whose objects overflowed the agent's bound (15 named objects per event, then `*`) is measured,
and its open question 1 asks for the rate of events naming an unknown-object `*`. Neither is in the
protocol, so the agent core counts them locally: once per heartbeat, when the counts changed, it logs
one `audit event census` info line per engine (`agent/crates/core/src/audit/census.rs`) with the
events spooled since it started (after aggregation and the `audit.configure` filter), the raw
statements they stand for (`aggregated_count`), the overflowed events, the events naming a `*` without
having overflowed (dynamic SQL, user code, a text the connector could not analyse; on Redis / Valkey
also a real `*` key pattern), each with their statements, and the events filtered. Counts and engine
names only (I2); nothing reaches the console (I6).

Every load run (`run.sh`, `cas.sh`, `sqlserver.sh`, `redis.sh`) and every end-to-end run
(`e2e/run.sh`, `cas.sh`, `sqlserver.sh`, `redis.sh`) prints, on exit, the agent's last census line per
engine as `CENSUS <label> engine=<engine> events=… overflowed=… unknown_star=… overflowed_rate=…`
in its log (`loadlib.py census`), and an "Event census" section in the job summary. Every run also
reads the console database on exit (read-only, the queries of `loadlib.py census-sql`) and adds:

- `CENSUS-CONSOLE` lines: per target and principal (an account name as stored, `fp:` and the first 8
  hex digits of a fingerprint, `(not-recorded)` for Redis / Valkey events without an account), the
  events stored, the statements, the events naming `*`, those the agent flagged
  `objects_overflowed` (ADR-0053) and the longest object list;
- `STAR-EVENTS` lines: the events naming `*`, grouped by target, source, action, principal kind
  (`account`, `fingerprint`, `not_recorded`), signals, the databases of their `*` objects, whether
  `*` is their only object and whether they were flagged overflowed; and `STAR-FINDINGS` lines: per
  target and database, the distinct finding objects (on Redis / Valkey the key patterns that
  Discovery reported, from the scan whose patterns Audit maps keys to) and whether `*` is one of
  them. No object name other than `*`, no principal name, no value (I2). For the Valkey question of
  ADR-0053 decision 6: the agent never learns `*` as a key pattern (`LearnedPatterns` ignores it),
  so a slow-log read of `*` is a key that matched no learned pattern (or one the second gate masked,
  a guarded CAS key, an oversized or non-UTF-8 key), a command whose keys the agent cannot place, a
  script (`EVAL` and the like, a write of `*`), an `ACL LOG` entry (source `redis_acl_log`) or a full synchronization
  (source `redis_sync`, signal `signature.full_sync`, principal `not_recorded`).

The job summary sections are not written by `loadlib.py`: each harness appends the
`census-<label>.md` files to the summary in its exit handler, after the leak scan and redaction of
their directory. The census is also kept as files: `census-<label>.json` and `.md` in the results directory of the
load runs (the `load-*-results` artifacts) and in `<log dir>/census/` of the end-to-end runs (the CI
artifacts `e2e-census`, `e2e-cas-census`, `e2e-sqlserver-census`, `e2e-redis-census`, and
`e2e-sqlserver-census-<version>-<source>` from the engine matrix, uploaded whatever the result).
None of this is a check: the run never fails on it.

The **ORM-style workload** runs next to the workload, in both phases (so the latency comparison is
unchanged), as `load_orm`: on `target-pg` and `target-mariadb` in the side clients, on SQL Server in
its own `sqlcmd` session. Every 2 s it runs one cycle of 18 statements generated by
`seed.py orm` from the scaled seed (fake data only): six lazy loads (N+1 primary-key selects), eager
loading over 2 to 6 tables (`LEFT JOIN`s), `select_related`-like chains over 8, 12 and 15 tables (at
the bound, not past it), a pagination count over a 3-table join, and three reporting queries over
16, 20 (`UNION ALL`) and 24 tables, past the bound. Every statement is bounded by primary-key
predicates. Three statements of 18 read more than 15 tables; after the 60 s aggregation, each of the
18 shapes gives about one event per window. MongoDB has no Audit in the load run, and Redis /
Valkey commands read key patterns, not joins: their census only shows the base rates of their
traffic.

## Not covered, and why
- **Prometheus / Grafana**: not used. The agent has no metrics listener (invariant I1, ADR-0004;
  `metrics.local_listen` is rejected by the configuration loader today), so there is nothing to scrape
  on the agent side; its counters reach the console in heartbeats, and the harness reads them from the
  console database (`agents.spool`, `agents.metrics`). The console's own `/metrics` is not needed for
  these measurements.
- **MySQL Community, Percona, OpenLDAP**: Discovery impact is measured on three engines; the Audit
  load on the two whose sources are log files the agent tails. The OpenLDAP audit proof searches
  (`reqDN:dnSubtreeMatch:=…` on `cn=accesslog`, run by `check()` at most every 10 minutes, ROADMAP
  item from the end-of-phase-6 review I5) need a large accesslog and their own window: not measured
  yet.
- **MongoDB Audit under load**: the server-log source would need `--slowms 0` and a workload client;
  not in this harness yet.
- Discovery with Audit on (the agent's own reads in the audit stream) is exercised by `e2e/run.sh`,
  not measured here.
- The harness runs one agent; the console's own load is not measured.
