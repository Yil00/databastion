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
| `LOAD_LIMIT_<NAME>` | see below | Every field of `loadlib.Limits`, upper case, e.g. `LOAD_LIMIT_DISCOVERY_PCT=2.0`, `LOAD_LIMIT_DRAIN_S=240` |

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
   run together for `LOAD_BASELINE_S` seconds, as `load_app`.
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
| `agent.spool_bounded` | ≤ 1000 batches | peak `spool.batches` over the heartbeats of the run |
| `agent.spool_drained` | 0 | a heartbeat after the drain reports an empty spool |
| `agent.no_dropped_batches` | 0 | `spool.dropped_batches` and `dropped_items` (the documented drops happen only when the spool is full, `spool` in [`agent.example.yaml`](../../agent/agent.example.yaml)) |
| `agent.<counter>` | 0 | `events_lost_total`, `findings_lost_total`, `audit_stream_failures_total`, `audit_records_skipped_total`, `audit_record_panics_total`, `connector_panics_total`, `batches_rejected_total` |
| `agent.log_no_lost_batches` | 0 lines | the agent log has no lost / dropped / rejected batch line (as e2e) |

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
