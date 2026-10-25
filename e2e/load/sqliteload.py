#!/usr/bin/env python3
"""Measurement and report of the SQLite load run (e2e/load/sqlite.sh, ADR-0059 decision 10 "Load").
Python standard library only; unit tests in test_sqliteload.py. The samples and the generic helpers
(percentiles, CPU rates, the check list) are loadlib.py's.

SQLite has no server whose CPU a scan could cost: the impact measured is on a concurrent writer,
the application (sqlite_writer.py run), in WAL mode and in rollback-journal mode, with its busy
timeout at 0 and at 5 s, during a paced Discovery scan against a baseline without scan.

Subcommands
  window --records CSV --wal CSV --summary FILE --mode wal|rollback --busy-timeout-ms B
         --phase baseline|scan [--t0 T --t1 T]
      One `sqlite_run` fact (a JSON line) from a writer run: its summary, and over the transactions
      started in [T0, T1] (the scan's delivery to its end; the whole run without them) the commits,
      the SQLITE_BUSY / SQLITE_LOCKED answers, the failed transactions, the commit latency
      percentiles (committed transactions) and the -wal size (peak in the window, at the end).
  report --facts FILE --samples FILE... --out DIR
      Evaluates the checks below, writes results.json and results.md, exits 1 if a check failed.

Checks (limits from LOAD_LIMIT_SQLITE_<NAME>, ADR-0059 decision 10, proposed to the maintainer):
  - every run: the writer kept its rate in the baseline (issued >= 95 % of rate x duration) and each
    scan succeeded;
  - WAL mode, busy timeout 0 and 5 s: no SQLITE_BUSY during the scan, the commit p95 within 5 % of
    the baseline (plus 0.5 ms for the runner's timer noise), and the -wal peak at most
    max(2 x the baseline's peak, the baseline's peak + 8 MiB) (checkpoint starvation);
  - rollback mode, busy timeout 5 s: no failed commit, the commit p99 at most max_statement_ms
    (500 ms) above the baseline's;
  - rollback mode, busy timeout 0: the SQLITE_BUSY count and rate measured, not judged (ADR-0059
    open question 8: the `rollback_mode` default is revisited with this figure);
  - the agent's container (the agent and its reader processes) under 2 % of one core over each scan,
    its memory (cgroup anonymous memory, readers included) at most 256 MiB at its peak, and nothing
    dropped in its log.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loadlib import Checks, load_jsonl, percentile, rate, series  # noqa: E402

MIB = 1024 * 1024
MODES = ("wal", "rollback")
BUSY_TIMEOUTS = (0, 5000)


@dataclass
class SqliteLimits:
    workload_min_ratio: float = 0.95  # issued / (rate x duration) in the baseline
    wal_p95_factor: float = 1.05  # ADR-0059: within 5 % of the baseline
    wal_p95_slack_ms: float = 0.5
    wal_busy: int = 0
    wal_peak_factor: float = 2.0
    wal_peak_slack_mib: float = 8.0
    rollback_failed: int = 0  # with a 5 s busy timeout
    rollback_p99_added_ms: float = 500.0  # sqlite.max_statement_ms, the default
    agent_cpu_cores: float = 0.02  # 2 % of one core over a scan
    agent_memory_mb: float = 256.0
    agent_lost: int = 0

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "SqliteLimits":
        lim = cls()
        for f in lim.__dataclass_fields__:
            key = "LOAD_LIMIT_SQLITE_" + f.upper()
            if env.get(key, "") != "":
                setattr(lim, f, type(getattr(lim, f))(env[key]))
        return lim


def _r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


# ------------------------------------------------------------------------------------ window
def read_records(path: str) -> list[tuple[float, float, int, str]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) != 4:
                continue
            try:
                out.append((float(parts[0]), float(parts[1]), int(parts[2]), parts[3]))
            except ValueError:
                continue
    return out


def read_wal(path: str) -> list[tuple[float, int]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                try:
                    out.append((float(parts[0]), int(parts[1])))
                except ValueError:
                    continue
    return out


def window_stats(records: list[tuple[float, float, int, str]], wal: list[tuple[float, int]],
                 t0: float | None, t1: float | None) -> dict:
    lo = t0 if t0 is not None else float("-inf")
    hi = t1 if t1 is not None else float("inf")
    rs = [r for r in records if lo <= r[0] <= hi]
    lat = [r[1] for r in rs if r[2] == 1]
    busy = sum(1 for r in rs if r[2] == 0 and r[3])
    failed = sum(1 for r in rs if r[2] == 0)
    span = (min(hi, rs[-1][0]) - max(lo, rs[0][0])) if rs else 0.0
    ws = [b for t, b in wal if lo <= t <= hi]
    return {
        "transactions": len(rs), "committed": len(lat), "busy": busy, "failed": failed,
        "busy_per_s": _r(busy / span, 3) if span > 0 else None,
        "p50_ms": _r(percentile(lat, 50.0)), "p95_ms": _r(percentile(lat, 95.0)),
        "p99_ms": _r(percentile(lat, 99.0)), "max_ms": _r(max(lat)) if lat else None,
        "wal_peak_bytes": max(ws) if ws else (max(b for _, b in wal) if wal else None),
        "wal_end_bytes": wal[-1][1] if wal else None,
        "t0": _r(t0), "t1": _r(t1),
    }


def cmd_window(args: argparse.Namespace) -> int:
    with open(args.summary, encoding="utf-8") as f:
        summary = json.loads(f.read().strip().splitlines()[-1])
    stats = window_stats(read_records(args.records), read_wal(args.wal), args.t0, args.t1)
    print(json.dumps({"kind": "sqlite_run", "mode": args.mode, "busy_timeout_ms": args.busy_timeout_ms,
                      "phase": args.phase, "summary": summary, "stats": stats}, separators=(",", ":")))
    return 0


# ------------------------------------------------------------------------------------ report
def _one(facts: list[dict], kind: str, **match: object) -> dict | None:
    for f in facts:
        if f.get("kind") == kind and all(f.get(k) == v for k, v in match.items()):
            return f
    return None


def build_report(facts: list[dict], samples: list[dict], lim: SqliteLimits) -> tuple[dict, Checks]:
    ck = Checks()
    cfg = _one(facts, "config") or {}
    rate_cfg = cfg.get("rate")
    base_s = cfg.get("baseline_s")
    runs: dict[str, dict] = {}
    scans: dict[str, dict] = {}
    cpu = series(samples, "agent", "cpu_usec")
    for mode in MODES:
        for busy in BUSY_TIMEOUTS:
            key = f"{mode}.b{busy}"
            base = _one(facts, "sqlite_run", mode=mode, busy_timeout_ms=busy, phase="baseline")
            scan_run = _one(facts, "sqlite_run", mode=mode, busy_timeout_ms=busy, phase="scan")
            scan = _one(facts, "scan", mode=mode, busy_timeout_ms=busy)
            b = (base or {}).get("stats") or {}
            s = (scan_run or {}).get("stats") or {}
            runs[key] = {"baseline": b, "scan": s, "summary_baseline": (base or {}).get("summary"),
                         "summary_scan": (scan_run or {}).get("summary")}
            # The writer kept its rate (else the runner, not the agent, sets the figures).
            issued = ((base or {}).get("summary") or {}).get("issued")
            want = rate_cfg * base_s * lim.workload_min_ratio if rate_cfg and base_s else None
            ck.add(f"sqlite.{key}.workload_ran", None if issued is None or want is None else issued >= want,
                   issued, None if want is None else round(want), "baseline transactions issued")
            # The scan.
            sc: dict = {}
            if scan:
                t0, t1 = scan.get("t0"), scan.get("t1")
                cores = rate(cpu, t0, t1, 1e6) if t0 is not None and t1 is not None else None
                sc = {"target": scan.get("target"), "status": scan.get("status"),
                      "scan_s": _r(t1 - t0, 1) if t0 is not None and t1 is not None else None,
                      "progress": scan.get("progress"), "findings": scan.get("findings"),
                      "agent_cores": _r(cores, 4), "agent_one_core_pct": _r(cores * 100, 3) if cores is not None else None}
            scans[key] = sc
            ck.add(f"sqlite.{key}.scan_succeeded", (sc.get("status") == "succeeded") if sc else None,
                   sc.get("status"), "succeeded")
            ck.add(f"agent.{key}.cpu_cores_scan",
                   None if sc.get("agent_cores") is None else sc["agent_cores"] <= lim.agent_cpu_cores,
                   sc.get("agent_cores"), lim.agent_cpu_cores, "agent container (agent and readers) over the scan")
            if mode == "wal":
                ck.add(f"sqlite.{key}.busy_during_scan", None if s.get("busy") is None else s["busy"] <= lim.wal_busy,
                       s.get("busy"), lim.wal_busy, "SQLITE_BUSY / SQLITE_LOCKED answers to the writer")
                bp, sp = b.get("p95_ms"), s.get("p95_ms")
                limit = None if bp is None else _r(bp * lim.wal_p95_factor + lim.wal_p95_slack_ms)
                ck.add(f"sqlite.{key}.p95_ms", None if sp is None or limit is None else sp <= limit, sp, limit,
                       f"commit p95, baseline {bp} ms (+{round((lim.wal_p95_factor - 1) * 100)} % + {lim.wal_p95_slack_ms} ms)")
                bw, sw = b.get("wal_peak_bytes"), s.get("wal_peak_bytes")
                wl = None if bw is None else max(bw * lim.wal_peak_factor, bw + lim.wal_peak_slack_mib * MIB)
                ck.add(f"sqlite.{key}.wal_peak_mib", None if sw is None or wl is None else sw <= wl,
                       None if sw is None else _r(sw / MIB, 2), None if wl is None else _r(wl / MIB, 2),
                       f"-wal peak during the scan, baseline {None if bw is None else _r(bw / MIB, 2)} MiB")
            elif busy > 0:
                ck.add(f"sqlite.{key}.failed_during_scan",
                       None if s.get("failed") is None else s["failed"] <= lim.rollback_failed,
                       s.get("failed"), lim.rollback_failed, "failed commits with a 5 s busy timeout")
                bp, sp = b.get("p99_ms"), s.get("p99_ms")
                added = None if bp is None or sp is None else _r(sp - bp)
                ck.add(f"sqlite.{key}.p99_added_ms", None if added is None else added < lim.rollback_p99_added_ms,
                       added, lim.rollback_p99_added_ms, f"commit p99 {sp} ms against {bp} ms (max_statement_ms)")
            else:
                ck.skip(f"sqlite.{key}.busy_during_scan", s.get("busy"), None,
                        f"measured, not judged (ADR-0059 open question 8): {s.get('busy_per_s')} per second, "
                        f"{s.get('failed')} failed of {s.get('transactions')}")
    mem = [v for v in (x.get("c", {}).get("agent") or {} for x in samples) if isinstance(v, dict)]
    anon = [m["anon"] for m in mem if isinstance(m.get("anon"), (int, float))]
    rss = [m["rss"] for m in mem if isinstance(m.get("rss"), (int, float))]
    peak_mb = _r(max(anon) / MIB, 1) if anon else None
    ck.add("agent.memory_mb_peak", None if peak_mb is None else peak_mb <= lim.agent_memory_mb, peak_mb,
           lim.agent_memory_mb, "cgroup anonymous memory of the agent's container (readers included)")
    idle = _one(facts, "window", name="idle_agent")
    idle_cores = rate(cpu, idle["t0"], idle["t1"], 1e6) if idle else None
    lost = (_one(facts, "agent_log") or {}).get("lost")
    ck.add("agent.no_loss", None if lost is None else lost <= lim.agent_lost, lost, lim.agent_lost,
           "dropped findings or batches in the agent's log")
    rep = {
        "pass": ck.passed, "config": cfg,
        "seeds": [f for f in facts if f.get("kind") == "seed"],
        "runs": runs, "scans": scans,
        "agent": {"cpu_cores_idle": _r(idle_cores, 4), "memory_mb_peak": peak_mb,
                  "rss_mb_peak": _r(max(rss) / MIB, 1) if rss else None, "lost": lost},
        "checks": ck.items,
    }
    return rep, ck


def render_markdown(rep: dict) -> str:
    def fmt(v: object) -> str:
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:g}"
        if isinstance(v, (dict, list)):
            return json.dumps(v, separators=(",", ":"))
        return str(v)

    mib = lambda b: None if b is None else round(b / MIB, 2)  # noqa: E731
    out = ["# DataBastion load results: SQLite targets", "", f"**Result: {'PASS' if rep.get('pass') else 'FAIL'}**", ""]
    cfg = rep.get("config") or {}
    if cfg:
        out += ["Configuration: " + ", ".join(f"`{k}={fmt(v)}`" for k, v in sorted(cfg.items()) if k != "kind"), ""]
    for s in rep.get("seeds") or []:
        out.append(f"- seed `{fmt(s.get('mode'))}`: {fmt(mib(s.get('bytes')))} MiB, {fmt(s.get('tables'))} tables, "
                   f"written by SQLite {fmt(s.get('sqlite_version'))} in {fmt(s.get('seconds'))} s")
    out += ["", "## 1. The writer (the application) with and without a scan", "",
            "Commit latency of `BEGIN IMMEDIATE`, one INSERT, one UPDATE, `COMMIT` at a fixed rate; the scan "
            "phase counts the transactions started while the scan ran (delivery to end).", "",
            "| Mode | Busy timeout (ms) | Phase | Transactions | Committed | Busy | Failed | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) | -wal peak (MiB) | -wal end (MiB) |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for key, r in sorted((rep.get("runs") or {}).items()):
        mode, busy = key.split(".b")
        for phase in ("baseline", "scan"):
            s = r.get(phase) or {}
            out.append(f"| {mode} | {busy} | {phase} | {fmt(s.get('transactions'))} | {fmt(s.get('committed'))} | "
                       f"{fmt(s.get('busy'))} | {fmt(s.get('failed'))} | {fmt(s.get('p50_ms'))} | {fmt(s.get('p95_ms'))} | "
                       f"{fmt(s.get('p99_ms'))} | {fmt(s.get('max_ms'))} | {fmt(mib(s.get('wal_peak_bytes')))} | "
                       f"{fmt(mib(s.get('wal_end_bytes')))} |")
    out += ["", "## 2. The scans", "",
            "| Mode | Busy timeout (ms) | Target | Status | Scan (s) | Findings | Agent (cores) | % of one core | Coverage |",
            "|---|---|---|---|---|---|---|---|---|"]
    for key, s in sorted((rep.get("scans") or {}).items()):
        mode, busy = key.split(".b")
        out.append(f"| {mode} | {busy} | {fmt(s.get('target'))} | {fmt(s.get('status'))} | {fmt(s.get('scan_s'))} | "
                   f"{fmt(s.get('findings'))} | {fmt(s.get('agent_cores'))} | {fmt(s.get('agent_one_core_pct'))} | "
                   f"{fmt(s.get('progress'))} |")
    ag = rep.get("agent") or {}
    out += ["", "## 3. Agent resources", ""] + [f"- `{k}`: {fmt(v)}" for k, v in sorted(ag.items())]
    out += ["", "## Checks", "", "| Check | Result | Value | Limit | Note |", "|---|---|---|---|---|"]
    for c in rep.get("checks") or []:
        res = "skipped" if c.get("skipped") else {True: "pass", False: "**FAIL**", None: "**no data**"}[c["pass"]]
        out.append(f"| `{c['name']}` | {res} | {fmt(c['value'])} | {fmt(c['limit'])} | {c.get('note', '')} |")
    return "\n".join(out) + "\n"


def cmd_report(args: argparse.Namespace) -> int:
    facts = load_jsonl([args.facts])
    samples = load_jsonl(args.samples)
    samples.sort(key=lambda s: s.get("t", 0))
    rep, ck = build_report(facts, samples, SqliteLimits.from_env(dict(os.environ)))
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(args.out, "results.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(rep))
    for c in ck.items:
        if c.get("skipped"):
            print(f"sqliteload: check {c['name']}: skipped ({c['note']})", file=sys.stderr)
        elif c["pass"] is not True:
            print(f"sqliteload: check {c['name']}: {'failed' if c['pass'] is False else 'no data'} "
                  f"(value {c['value']}, limit {c['limit']})", file=sys.stderr)
    return 0 if ck.passed else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("window")
    w.add_argument("--records", required=True)
    w.add_argument("--wal", required=True)
    w.add_argument("--summary", required=True)
    w.add_argument("--mode", choices=MODES, required=True)
    w.add_argument("--busy-timeout-ms", type=int, required=True)
    w.add_argument("--phase", choices=("baseline", "scan"), required=True)
    w.add_argument("--t0", type=float)
    w.add_argument("--t1", type=float)
    r = sub.add_parser("report")
    r.add_argument("--facts", required=True)
    r.add_argument("--samples", nargs="+", required=True)
    r.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    return {"window": cmd_window, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
