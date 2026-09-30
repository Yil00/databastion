# ADR-0035: Discovery pacing to a bounded duty cycle per scan

- **Status**: Proposed
- **Date**: 2026-09-30
- **Context references**: ROADMAP phase 7 "Load / database impact tests"; the load harness of #92 ([e2e/load/README.md](../../e2e/load/README.md)); PR #93 (commit `3c2a0e9`); `agent/crates/core/src/pacing.rs`, `agent/crates/core/src/job.rs` (`ScanJob::paced`), `agent/crates/core/src/runtime.rs` (scan worker), `agent/crates/core/src/config.rs`; [agent/README.md](../../agent/README.md)

## Context
The MVP criterion in [04-mvp-scope.md](../04-mvp-scope.md) is "impact on the monitored database < 2 % CPU during Discovery". It is read literally, per scan: the share of the server's CPU that the agent adds while a scan runs. It is not relaxed to an average over a longer window.

Sampling was already bounded per object (rows, bytes, statement timeout), but objects were sampled back to back. The #92 harness measured 20 to 25 % of one database core while a scan ran: about 1.5 ms of database CPU per object for 7 to 8 ms of scan time per object. Bounding each query does not bound the scan's share of the server's time; only the time between queries does.

## Decision
1. **The core paces every connector's Discovery.** After each unit of work against the target (an object's sampling, a catalog read or a listing), `ScanJob::paced` sleeps `busy × (100 − d) / d`, rounded up. `busy` is the agent's wall-clock time for that unit. A scan uses one connection and a statement runs on one server core, so `busy` bounds the database CPU the unit used on that connection. The agent's time in queries is then at most `d` % of the scan's time, so a scan costs the server at most `d` % of one core. Every connector (PostgreSQL, MySQL / MariaDB, MongoDB, OpenLDAP) goes through it; none paces itself.
2. **`d` is `limits.discovery_duty_cycle_percent`** in `agent.yaml`: default 1, range 1 to 100, `100` disables pacing. It is a local limit: the console cannot set or raise it. The default of 1 % keeps a one-core server under the 2 % criterion, with margin for what is not paced (connection setup).
3. **Scans run one at a time per agent** (the scan worker), so the scans of several targets on one server cannot add up.
4. **Pauses are cancellable.** The core gives each scan a cancel token, fired when the scan stops (end of its window, suspension after a revocation, agent shutdown) and when it is dropped. A pause selects on it; the paced call then returns `Cancelled` and the connector returns `ConnectorError::Cancelled`.
5. **The agent acknowledges a scan with `running` before it starts** (contract `pollJobs`: a delivered job without a status is delivered again after the 120 s lease, and the console gives it up after 5 deliveries). Without it, a paced scan longer than about 10 minutes would be failed by the console while it runs.

## Consequences
- A scan takes about `100 / d` times its query time. Measured on MariaDB 11.4 with 200 tables (debug build): 120 s and 0.35 % of one core paced, against 6.6 s and 5.4 % unpaced.
- Large databases need a larger scan budget (the job's `max_duration_s`, console default 900 s, capped by `limits.max_scan_duration_s`, default 3600 s), or a higher `d` where the server has spare cores. At 1 %, 900 s covers about 9 s of query time. A scan that reaches its budget ends `failed` with `timeout`, with the findings produced so far.
- The bound is conservative: latency (network, I/O and lock waits) counts as busy time, so a slow link or a busy server lengthens the pauses without adding database CPU.
- A running scan is not delivered again after an agent restart: it has a `running` status. The console marks it `failed` (`timeout`) once `delivered_at + max_duration_s + 1 h` has passed (swept when the next scan of that agent is requested).
- Queued scans (at most 16 per agent) are acknowledged only when they start. While a long paced scan runs, a queued scan's lease can expire 5 times and the console then fails it. A console follow-up covers this (acknowledge queued scans or extend the lease of a queued `discovery.scan`) and reviews the 900 s default (ROADMAP phase 7).
- Residual: PostgreSQL parallel query workers are not disabled for the scan's connection. A sampling query that the planner runs in parallel can use more than one core during its `busy` time, so on PostgreSQL the bound is per connection, not strictly per core.
- Not paced: connection setup (once per scan or database, and after a budget stop or an idle session). The end of a scan logs its busy and paused time (`scan pacing`).

## Rejected alternatives
- **A per-minute average criterion.** A short unpaced scan spread over one minute is about 0.5 % (#92), but the server still runs at 20 to 25 % of a core while the scan lasts. That reading relaxes the MVP criterion instead of meeting it.
- **Server-side CPU accounting** (reading the engine's own statement or session CPU statistics). No engine exposes it uniformly, some need extra privileges (against I4), and some would count other clients too. The agent's wall-clock time is available on every engine and is an upper bound.
- **Adapting the pause to the remaining budget** (pausing less so the scan finishes within `max_duration_s`). The database impact would then depend on the scan budget and on the database size, and the criterion would no longer hold for large databases. A scan that does not fit its budget ends with `timeout` and says so.
- **Capping individual pauses.** A long unit of work (a large sample, a slow catalog read) would then be followed by too short a pause, and the duty cycle would be exceeded exactly on the heaviest objects.
