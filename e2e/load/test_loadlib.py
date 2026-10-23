"""Unit tests of loadlib.py (python3 -m unittest discover -s e2e/load -p 'test_*.py')."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import loadlib as L  # noqa: E402

SYSBENCH_1_0 = """
SQL statistics:
    queries performed:
        read:                            36012
        write:                           0
        other:                           0
        total:                           36012
    transactions:                        36012  (300.08 per sec.)
    queries:                             36012  (300.08 per sec.)
    ignored errors:                      0      (0.00 per sec.)
    reconnects:                          0      (0.00 per sec.)

General statistics:
    total time:                          120.0071s
    total number of events:              36012

Latency (ms):
         min:                                    0.21
         avg:                                    0.48
         max:                                   12.03
         95th percentile:                        0.94
         sum:                                17285.66
"""

SYSBENCH_1_1 = """
SQL statistics:
    queries performed:
        read:                            180011
        write:                           0
        other:                           0
        total:                           180011
    transactions:                        180011 (300.01 per sec.)
    queries:                             180011 (300.01 per sec.)
    ignored errors:                      2      (0.00 per sec.)
    reconnects:                          0      (0.00 per sec.)

Throughput:
    events/s (eps):                      300.0145
    time elapsed:                        600.0023s
    total number of events:              180011

Latency (ms):
         min:                                    0.19
         avg:                                    0.51
         max:                                   40.01
         95th percentile:                        1.01
         sum:                                91805.61
"""

PGBENCH = """pgbench (17.11 (Debian 17.11-1.pgdg120+1))
transaction type: multiple scripts
scaling factor: 1
query mode: simple
number of clients: 4
number of threads: 2
maximum number of tries: 1
duration: 120 s
number of transactions actually processed: 36004
number of failed transactions: 0 (0.000%)
latency average = 0.612 ms
"""


def fake_tree(root: str, v2: bool, pid: int = 4242) -> None:
    proc = os.path.join(root, "proc")
    cg = os.path.join(root, "cg")
    os.makedirs(os.path.join(proc, str(pid)))
    with open(os.path.join(proc, "stat"), "w") as f:
        f.write("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 100 0 50 800 50 0 0 0 0 0\n")
    with open(os.path.join(proc, str(pid), "status"), "w") as f:
        f.write("Name:\tdatabastion-age\nVmHWM:\t   20480 kB\nVmRSS:\t   10240 kB\n")
    if v2:
        with open(os.path.join(proc, str(pid), "cgroup"), "w") as f:
            f.write("0::/system.slice/docker-abc.scope\n")
        d = os.path.join(cg, "system.slice", "docker-abc.scope")
        os.makedirs(d)
        with open(os.path.join(d, "cpu.stat"), "w") as f:
            f.write("usage_usec 1500000\nuser_usec 1000000\nsystem_usec 500000\n")
        with open(os.path.join(d, "memory.stat"), "w") as f:
            f.write("anon 4096000\nfile 999\n")
        with open(os.path.join(d, "cpu.max"), "w") as f:
            f.write("200000 100000\n")
    else:
        with open(os.path.join(proc, str(pid), "cgroup"), "w") as f:
            f.write("12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n1:name=systemd:/docker/abc\n")
        d = os.path.join(cg, "cpu,cpuacct", "docker", "abc")
        os.makedirs(d)
        with open(os.path.join(d, "cpuacct.usage"), "w") as f:
            f.write("2500000000\n")
        with open(os.path.join(d, "cpu.cfs_quota_us"), "w") as f:
            f.write("-1\n")
        with open(os.path.join(d, "cpu.cfs_period_us"), "w") as f:
            f.write("100000\n")
        m = os.path.join(cg, "memory", "docker", "abc")
        os.makedirs(m)
        with open(os.path.join(m, "memory.stat"), "w") as f:
            f.write("cache 5\nrss 777\ntotal_rss 888\n")


class ParseTest(unittest.TestCase):
    def test_proc_cgroup(self) -> None:
        self.assertEqual(L.parse_proc_cgroup("0::/system.slice/docker-x.scope\n"), {"": "/system.slice/docker-x.scope"})
        v1 = L.parse_proc_cgroup("4:cpu,cpuacct:/docker/x\n9:memory:/docker/x\nbogus\n")
        self.assertEqual(v1["cpu"], "/docker/x")
        self.assertEqual(v1["cpuacct"], "/docker/x")
        self.assertEqual(v1["memory"], "/docker/x")

    def test_cpu_max(self) -> None:
        self.assertEqual(L.parse_cpu_max("200000 100000\n"), 2.0)
        self.assertEqual(L.parse_cpu_max("50000 100000"), 0.5)
        self.assertIsNone(L.parse_cpu_max("max 100000"))
        self.assertIsNone(L.parse_cpu_max(""))
        self.assertIsNone(L.parse_cpu_max(None))

    def test_status_and_stat(self) -> None:
        self.assertEqual(L.parse_proc_status("VmRSS:\t  100 kB\nVmHWM: 200 kB\n"), {"VmRSS": 102400, "VmHWM": 204800})
        self.assertEqual(L.parse_proc_stat("cpu  10 1 5 100 4 1 1 0 0 0\n"), (18, 122))
        self.assertIsNone(L.parse_proc_stat("intr 1\n"))


class CgroupTest(unittest.TestCase):
    def test_v2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake_tree(d, v2=True)
            cg = L.Cgroup.resolve(4242, f"{d}/proc", f"{d}/cg")
            self.assertTrue(cg.v2)
            self.assertEqual(cg.cpu_usec(), 1_500_000)
            self.assertEqual(cg.anon_bytes(), 4_096_000)
            self.assertEqual(cg.capacity(4), 2.0)
            self.assertEqual(cg.capacity(1), 1.0)

    def test_v1(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake_tree(d, v2=False)
            cg = L.Cgroup.resolve(4242, f"{d}/proc", f"{d}/cg")
            self.assertFalse(cg.v2)
            self.assertEqual(cg.cpu_usec(), 2_500_000)
            self.assertEqual(cg.anon_bytes(), 888)
            self.assertEqual(cg.capacity(4), 4.0)  # no quota: the host's CPUs

    def test_missing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cg = L.Cgroup.resolve(1, f"{d}/proc", f"{d}/cg")
            self.assertIsNone(cg.cpu_usec())
            self.assertIsNone(cg.anon_bytes())

    def test_sample_once_and_sampler(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake_tree(d, v2=True)
            calls = []

            def pid_of(cid: str) -> int | None:
                calls.append(cid)
                return 4242 if cid == "cid-agent" else None

            state: dict = {}
            line = L.sample_once({"agent": "cid-agent", "gone": "cid-gone"}, state, 4, pid_of,
                                 f"{d}/proc", f"{d}/cg")
            self.assertEqual(line["host"], {"busy": 100 + 50, "total": 1000, "cpus": 4})
            self.assertEqual(line["c"]["agent"]["cpu_usec"], 1_500_000)
            self.assertEqual(line["c"]["agent"]["rss"], 10240 * 1024)
            self.assertEqual(line["c"]["agent"]["hwm"], 20480 * 1024)
            self.assertEqual(line["c"]["agent"]["cap"], 2.0)
            self.assertIsNone(line["c"]["gone"])
            # The resolved pid is cached; a missing container is looked up again.
            L.sample_once({"agent": "cid-agent", "gone": "cid-gone"}, state, 4, pid_of, f"{d}/proc", f"{d}/cg")
            self.assertEqual(calls.count("cid-agent"), 1)
            self.assertEqual(calls.count("cid-gone"), 2)
            out = os.path.join(d, "s.jsonl")
            n = [0]

            def stop() -> bool:
                n[0] += 1
                return n[0] > 3

            wrote = L.run_sampler({"agent": "cid-agent"}, out, 0.01, stop, pid_of=pid_of,
                                  proc_root=f"{d}/proc", cg_root=f"{d}/cg")
            self.assertGreaterEqual(wrote, 1)
            rows = L.load_jsonl([out])
            self.assertEqual(len(rows), wrote)
            self.assertEqual(rows[0]["c"]["agent"]["anon"], 4_096_000)


def samples_linear(name: str, t0: float, t1: float, step: float, rate_cores: float, rss=None, cap=2.0,
                   bursts=()) -> list[dict]:
    """Cumulative CPU of `rate_cores` plus bursts (t_start, t_end, cores) of extra usage."""
    out = []
    t = t0
    usec = 0.0
    prev = t0
    while t <= t1 + 1e-9:
        dt = t - prev
        extra = 0.0
        for a, b, c in bursts:
            lo, hi = max(a, prev), min(b, t)
            if hi > lo:
                extra += (hi - lo) * c
        usec += (dt * rate_cores + extra) * 1e6
        c = {"cpu_usec": int(usec), "cap": cap}
        if rss is not None:
            c["rss"] = int(rss(t))
        out.append({"t": round(t, 3), "c": {name: c}, "host": {"busy": int(t * 10), "total": int(t * 40), "cpus": 4}})
        prev = t
        t += step
    return out


class SeriesTest(unittest.TestCase):
    def test_bracket_inner_rate(self) -> None:
        s = [(0.0, 0.0), (1.0, 10.0), (2.0, 20.0), (3.0, 30.0)]
        self.assertEqual(L.bracket(s, 0.5, 2.5), (30.0, 0.0, 3.0))
        self.assertEqual(L.bracket(s, 1.0, 2.0), (10.0, 1.0, 2.0))
        self.assertIsNone(L.bracket(s, -1, 2))
        self.assertIsNone(L.bracket(s, 1, 4))
        self.assertEqual(L.inner(s, 0.5, 2.5), (10.0, 1.0, 2.0))
        self.assertEqual(L.rate(s, 0, 3), 10.0)
        self.assertIsNone(L.rate(s, 0.1, 0.9))

    def test_percentile_median(self) -> None:
        v = list(range(1, 101))
        self.assertEqual(L.percentile(v, 95), 95)
        self.assertEqual(L.percentile(v, 100), 100)
        self.assertEqual(L.percentile([5.0], 95), 5.0)
        self.assertIsNone(L.percentile([], 95))
        self.assertEqual(L.median([3, 1, 2]), 2)
        self.assertEqual(L.median([4, 1, 2, 3]), 2.5)

    def test_slope(self) -> None:
        pts = [(t * 60.0, 100 + t) for t in range(10)]  # +1 per minute
        self.assertAlmostEqual(L.slope_per_hour(pts), 60.0)
        self.assertIsNone(L.slope_per_hour(pts[:2]))

    def test_growth(self) -> None:
        flat = [(float(t), 50.0 + (t % 3) * 0.5) for t in range(600)]
        self.assertTrue(L.growth(flat, 0.2, 8, 0.1)["ok"])
        leak = [(float(t), 50.0 + t * 0.05) for t in range(600)]  # +30 MiB over the run
        g = L.growth(leak, 0.2, 8, 0.1)
        self.assertFalse(g["ok"])
        self.assertGreater(g["slope_per_hour"], 100)
        slow = [(float(t), 50.0 + t * 0.005) for t in range(600)]  # +3 MiB: within tolerance
        self.assertTrue(L.growth(slow, 0.2, 8, 0.1)["ok"])
        spike = [(float(t), 50.0 + (40.0 if 300 < t < 320 else 0.0)) for t in range(600)]
        self.assertTrue(L.growth(spike, 0.2, 8, 0.1)["ok"])
        # A warm-up ramp followed by a plateau is not growth.
        warm = [(float(t), min(80.0, 20.0 + t)) for t in range(600)]
        self.assertTrue(L.growth(warm, 0.2, 8, 0.1)["ok"])
        self.assertIsNone(L.growth(flat[:3], 0.2, 8, 0.1)["ok"])

    def test_quiet_rates(self) -> None:
        s = samples_linear("db", 0, 100, 0.5, 0.01, bursts=[(90, 100, 1.0)])
        r = L.quiet_rates(s, ["db", "absent"], 80, 5)
        self.assertAlmostEqual(r["db"], 0.01, places=3)
        self.assertIsNone(r["absent"])
        self.assertAlmostEqual(L.quiet_rates(s, ["db"], 100, 5)["db"], 1.01, places=2)

    def test_segment_rates(self) -> None:
        s = samples_linear("a", 0, 100, 0.5, 0.25)
        r = L.segment_rates(L.series(s, "a", "cpu_usec"), 0, 100, 10, 1e6)
        self.assertEqual(len(r), 10)
        for _, v in r:
            self.assertAlmostEqual(v, 0.25, places=3)


class DiscoveryImpactTest(unittest.TestCase):
    def test_impact(self) -> None:
        # Idle 0.01 core; a scan from t=100 to t=120 adds 0.1 core; capacity 2 CPUs.
        s = samples_linear("db", 0, 200, 0.5, 0.01, bursts=[(100, 120, 0.1)])
        d = L.discovery_impact(s, "db", 100.2, 119.8, (10, 60))
        self.assertAlmostEqual(d["idle_cores"], 0.01, places=3)
        # Numerator over the bracket [100.0, 120.0] (2.0 CPU-s by the burst), denominator 19.6 s x 2.
        self.assertAlmostEqual(d["attributable_cpu_s"], 2.0, places=2)
        self.assertAlmostEqual(d["impact_pct"], 100 * 2.0 / (19.6 * 2), places=1)
        self.assertEqual(d["capacity_cpus"], 2.0)
        self.assertIsNotNone(d["one_core_pct"])

    def test_no_data(self) -> None:
        self.assertIn("error", L.discovery_impact([], "db", 1, 2, (0, 1)))
        s = samples_linear("db", 0, 50, 0.5, 0.01)
        self.assertIn("error", L.discovery_impact(s, "db", 10, 20, None))


class WorkloadParseTest(unittest.TestCase):
    def test_pgbench(self) -> None:
        self.assertEqual(L.pgbench_summary(PGBENCH), {"processed": 36004, "failed": 0})
        self.assertEqual(L.pgbench_summary("nothing"), {"processed": None, "failed": 0})
        lat, svc = L.pgbench_latencies([
            "0 1 1882 3 1790739367 518100 84\n",
            "1 1 1925 27 1790739367 522087 309\n",
            "2 3 failed 0 1790739367 522087 0\n",
            "short line\n",
            "3 1 1000 0 1790739367 1\n",  # no schedule lag column (no --rate)
        ])
        self.assertEqual(lat, [1.882, 1.925, 1.0])
        self.assertEqual(svc, [1.798, 1.616, 1.0])

    def test_sysbench(self) -> None:
        a = L.sysbench_summary(SYSBENCH_1_0)
        self.assertEqual(a["events"], 36012)
        self.assertEqual(a["reads"], 36012)
        self.assertEqual(a["errors"], 0)
        self.assertEqual(a["p95_ms"], 0.94)
        self.assertEqual(a["avg_ms"], 0.48)
        b = L.sysbench_summary(SYSBENCH_1_1)
        self.assertEqual((b["events"], b["reads"], b["errors"], b["p95_ms"]), (180011, 180011, 2, 1.01))
        self.assertIsNone(L.sysbench_summary("")["p95_ms"])

    def test_cli(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(f"{d}/sum", "w") as f:
                f.write(PGBENCH)
            with open(f"{d}/log.1", "w") as f:
                f.write("".join(f"0 {i} {1000 + i} 0 1 1 10\n" for i in range(100)))
            with open(f"{d}/sb", "w") as f:
                f.write(SYSBENCH_1_1)
            from contextlib import redirect_stdout
            from io import StringIO
            buf = StringIO()
            with redirect_stdout(buf):
                self.assertEqual(L.main(["pgbench", "--summary", f"{d}/sum", "--log", f"{d}/log.1"]), 0)
            r = json.loads(buf.getvalue())
            self.assertEqual((r["processed"], r["logged"], r["p95_ms"]), (36004, 100, 1.094))
            buf = StringIO()
            with redirect_stdout(buf):
                self.assertEqual(L.main(["sysbench", "--summary", f"{d}/sb"]), 0)
            self.assertEqual(json.loads(buf.getvalue())["reads"], 180011)


def scenario(impact_cores: float = 0.005, received_ratio: float = 1.0, dropped: int = 0,
             leak_mb_per_s: float = 0.0, p95_on: float = 1.2, missing_idle: bool = False,
             drain_cores: float = 0.0) -> tuple[list, list, list]:
    """A whole run: idle 0-60 (no agent), idle 60-120 (agent), scan 130-160, workload off 200-320,
    workload on 340-940, drain done at 1000."""
    facts = [
        {"kind": "config", "tables": 40, "rows": 1000000, "db_cpus": 2},
        {"kind": "target", "target": "pg-load", "container": "target-pg"},
        {"kind": "window", "name": "idle_agent", "t0": 60, "t1": 120},
        {"kind": "scan", "target": "pg-load", "t0": 130, "t1": 160, "status": "succeeded", "rows": 1000000,
         "stmt_exec_ms": 120.5, "stmt_calls": 90, "tables": 40},
        {"kind": "window", "name": "workload_audit_off", "t0": 200, "t1": 320},
        {"kind": "window", "name": "workload_audit_on", "t0": 340, "t1": 940},
        {"kind": "workload", "target": "pg-load", "phase": "off", "tool": "pgbench", "rate": 300, "issued": 36000,
         "failed": 0, "p95_ms": 1.0},
        {"kind": "workload", "target": "pg-load", "phase": "on", "tool": "pgbench", "rate": 300, "issued": 180000,
         "failed": 0, "p95_ms": p95_on},
        {"kind": "events", "target": "pg-load", "received": int(180000 * received_ratio), "events": 400,
         "lag_p95_s": 65.0, "drain_s": 80.0},
        {"kind": "source", "target": "pg-load", "statements": 180000, "rotated_files": 0},
        {"kind": "events_timeline", "target": "pg-load", "buckets": [[340, 3000], [350, 3000]]},
        {"kind": "findings", "target": "pg-load", "count": 77},
        {"kind": "spool_drained", "ok": True, "batches": 0},
        {"kind": "agent_log", "lost": 0},
    ]
    if not missing_idle:
        facts.append({"kind": "window", "name": "idle_no_agent", "t0": 0, "t1": 60})
    db = samples_linear("target-pg", 0, 1000, 0.5, 0.01,
                        bursts=[(60, 1000, 0.002), (130, 160, impact_cores * 1), (200, 940, 0.3),
                                (940, 1000, drain_cores)])
    agent = samples_linear("agent", 60, 1000, 1.0, 0.0, cap=4.0, bursts=[(340, 940, 0.05)],
                           rss=lambda t: (40 + max(0.0, t - 340) * leak_mb_per_s) * 2**20)
    for s in agent:
        s["c"]["agent"]["hwm"] = s["c"]["agent"]["rss"]
    samples = sorted(db + agent, key=lambda s: s["t"])
    metrics = {k: 0 for k in ("events_lost_total", "findings_lost_total", "audit_stream_failures_total",
                              "audit_records_skipped_total", "audit_record_panics_total",
                              "connector_panics_total", "batches_rejected_total")}
    hbs = [{"t": t, "spool": {"batches": b, "bytes": b * 1000, "dropped_batches": 0, "dropped_items": 0},
            "metrics": metrics} for t, b in ((300, 0), (600, 3), (900, 2))]
    hbs.append({"t": 1000, "spool": {"batches": 0, "bytes": 0, "dropped_batches": dropped, "dropped_items": 0},
                "metrics": metrics})
    return facts, samples, hbs


class ReportTest(unittest.TestCase):
    def names(self, ck: L.Checks, ok: bool | None) -> set[str]:
        return {c["name"] for c in ck.items if c["pass"] is ok}

    def test_pass(self) -> None:
        facts, samples, hbs = scenario()
        rep, ck = L.build_report(facts, samples, hbs, L.Limits())
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        d = rep["discovery"]["pg-load"]
        # Against the idle baseline without the agent: the scan (0.005 core) plus the agent's own idle
        # load (0.002 core, its heartbeat checks) over 30 s on 2 CPUs: 0.35 %. Against the agent's
        # idle rate: the scan alone, 0.25 %. The bracket adds at most one idle sample each side.
        self.assertAlmostEqual(d["impact_pct"], 0.35, delta=0.02)
        self.assertAlmostEqual(d["impact_pct_vs_agent_idle"], 0.25, delta=0.02)
        self.assertEqual(d["findings"], 77)
        self.assertAlmostEqual(d["attributable_ms_per_object"], d["attributable_cpu_s"] * 1000 / 40, places=1)
        self.assertEqual(d["scan_ms_per_object"], 750.0)
        # A 30 s scan shown over a one-minute window: half the impact.
        self.assertAlmostEqual(d["impact_pct_60s"], d["impact_pct"] / 2, places=2)
        a = rep["audit"]["pg-load"]
        self.assertEqual(a["events_ratio"], 1.0)
        self.assertEqual(a["source_statements"], 180000)
        self.assertEqual(a["events_timeline_10s"], [[340, 3000], [350, 3000]])
        self.assertAlmostEqual(a["p95_added_ms"], 0.2)
        self.assertAlmostEqual(rep["agent"]["cpu_cores_audit_on"], 0.05, places=3)
        self.assertTrue(rep["agent"]["rss_growth"]["ok"])
        md = L.render_markdown(rep)
        self.assertIn("**Result: PASS**", md)
        self.assertIn("| pg-load |", md)

    def test_failures(self) -> None:
        rep, ck = L.build_report(*scenario(impact_cores=0.03), L.Limits())  # 1.5 % ... below
        self.assertTrue(rep["pass"])
        # The scenario's scan lasts 30 s, so it is judged over 60 s: 2.5 % over the scan is 1.25 %.
        rep, ck = L.build_report(*scenario(impact_cores=0.05), L.Limits())
        self.assertTrue(rep["pass"])
        self.assertAlmostEqual(rep["discovery"]["pg-load"]["impact_judged_pct"],
                               rep["discovery"]["pg-load"]["impact_pct_60s"])
        rep, ck = L.build_report(*scenario(impact_cores=0.1), L.Limits())  # 5 % over the scan, 2.5 % over 60 s
        self.assertEqual(self.names(ck, False), {"discovery.pg-load.db_cpu_impact_pct"})
        rep, ck = L.build_report(*scenario(received_ratio=0.9), L.Limits())
        self.assertEqual(self.names(ck, False), {"audit.pg-load.events_accounted"})
        rep, ck = L.build_report(*scenario(dropped=2), L.Limits())
        self.assertEqual(self.names(ck, False), {"agent.no_dropped_batches"})
        rep, ck = L.build_report(*scenario(leak_mb_per_s=0.05), L.Limits())
        self.assertIn("agent.rss_no_monotonic_growth", self.names(ck, False))
        rep, ck = L.build_report(*scenario(p95_on=9.0), L.Limits())
        self.assertEqual(self.names(ck, False), {"audit.pg-load.p95_latency_ms"})
        rep, ck = L.build_report(*scenario(missing_idle=True), L.Limits())
        self.assertFalse(rep["pass"])
        self.assertIn("discovery.pg-load.db_cpu_impact_pct", self.names(ck, None))

    def test_side_accounts(self) -> None:
        # ADR-0045: the monitoring-like reader and the built-in mix of the MariaDB Audit run.
        def side(excess: int = 0, non_connect: int = 0, objects: list | None = None,
                 failed: int = 0, builtin_events: int = 1) -> list[dict]:
            exp = ["performance_schema.threads", "information_schema.PROCESSLIST"]
            return [
                {"kind": "side", "target": "mariadb-load", "account": "load_monitor", "phase": "off",
                 "issued": 360, "failed": 0},
                {"kind": "side", "target": "mariadb-load", "account": "load_monitor", "phase": "on",
                 "issued": 1800, "failed": failed},
                {"kind": "side", "target": "mariadb-load", "account": "load_builtins", "phase": "on",
                 "issued": 4200, "failed": 0},
                {"kind": "side_events", "target": "mariadb-load", "account": "load_monitor", "role": "monitor",
                 "events": 22, "received": 1200, "groups": 2, "max_events_per_group": 11, "max_excess": excess,
                 "non_connect": 22, "objects": exp if objects is None else objects, "expected": exp,
                 "window_s": 60},
                {"kind": "side_events", "target": "mariadb-load", "account": "load_builtins", "role": "builtins",
                 "events": builtin_events + non_connect, "received": builtin_events + non_connect,
                 "groups": 1, "max_events_per_group": 1, "max_excess": -11, "non_connect": non_connect, "objects": [], "expected": [], "window_s": 60},
            ]
        facts, samples, hbs = scenario()
        rep, ck = L.build_report(facts + side(), samples, hbs, L.Limits())
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        names = {c["name"] for c in ck.items}
        for n in ("monitor_ran", "monitor_reported", "monitor_one_event_per_window", "builtins_ran",
                  "builtins_no_event"):
            self.assertIn(f"audit.mariadb-load.{n}", names)
        self.assertEqual(rep["side"]["mariadb-load/monitor"]["issued_audit_on"], 1800)
        self.assertIn("| mariadb-load/monitor | load_monitor | 1800 |", L.render_markdown(rep))
        # Names compared without case (the agent keeps the server's).
        rep, ck = L.build_report(facts + side(objects=["performance_schema.threads",
                                                       "information_schema.processlist"]),
                                 samples, hbs, L.Limits())
        self.assertTrue(rep["pass"])
        for kw, failing in ((dict(excess=1), "monitor_one_event_per_window"),
                            (dict(non_connect=3), "builtins_no_event"),
                            (dict(objects=["performance_schema.threads"]), "monitor_reported"),
                            (dict(failed=2), "monitor_ran"),
                            # Nothing seen at all: the stream may have missed the account.
                            (dict(builtin_events=0), "builtins_no_event")):
            rep, ck = L.build_report(facts + side(**kw), samples, hbs, L.Limits())
            self.assertEqual(self.names(ck, False), {f"audit.mariadb-load.{failing}"}, kw)
        # Without the side facts (the CAS harness, an older run): no side check.
        rep, ck = L.build_report(facts, samples, hbs, L.Limits())
        self.assertNotIn("side", rep)
        self.assertFalse(any(".monitor_" in c["name"] for c in ck.items))

    def test_secret_catalog_readers(self) -> None:
        # ADR-0050: the PgBouncer-like auth_query on pg_shadow (reported, one event per window) and
        # the exporter-like reader of pg_roles, pg_proc and pg_subscription without secret columns
        # (no event).
        def side(excess: int = 0, objects: list | None = None, exporter_events: int = 0) -> list[dict]:
            exp = ["shop.pg_catalog.pg_shadow"]
            return [
                {"kind": "side", "target": "pg-load", "account": "load_pgbouncer", "phase": "on",
                 "issued": 600, "failed": 0},
                {"kind": "side_events", "target": "pg-load", "account": "load_pgbouncer", "role": "secrets",
                 "events": 11, "received": 600, "groups": 1, "max_events_per_group": 11,
                 "max_excess": excess, "non_connect": 11,
                 "objects": (exp if objects is None else objects), "expected": exp, "window_s": 60},
                {"kind": "side", "target": "pg-load", "account": "load_pgexp", "phase": "on",
                 "issued": 360, "failed": 0},
                {"kind": "side_events", "target": "pg-load", "account": "load_pgexp", "role": "catalogs",
                 "events": exporter_events, "received": exporter_events, "groups": 0,
                 "max_events_per_group": None, "max_excess": None, "non_connect": exporter_events,
                 "objects": [], "expected": [], "window_s": 60},
            ]

        facts, samples, hbs = scenario()
        lim = L.Limits(agent_ref_cpu_cores=0.03)
        rep, ck = L.build_report(facts + side(), samples, hbs, lim)
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        names = {c["name"] for c in ck.items}
        for n in ("audit.pg-load.secrets_ran", "audit.pg-load.secrets_reported",
                  "audit.pg-load.secrets_one_event_per_window", "audit.pg-load.catalogs_ran",
                  "audit.pg-load.catalogs_no_event"):
            self.assertIn(n, names)
        for kw, failing in ((dict(excess=1), {"audit.pg-load.secrets_one_event_per_window"}),
                            (dict(objects=[]), {"audit.pg-load.secrets_reported"}),
                            (dict(exporter_events=3), {"audit.pg-load.catalogs_no_event"})):
            rep, ck = L.build_report(facts + side(**kw), samples, hbs, lim)
            self.assertEqual(self.names(ck, False), failing, kw)

    def test_statistics_readers(self) -> None:
        # ADR-0048: the pg_stats bloat reader and the mysql.column_stats reader, the pgaudit log volume
        # with log_catalog = on, and the agent against the release reference.
        def stats(excess: int = 0, objects: list | None = None, pgmon_records: int = 360,
                  log_catalog: str = "on", volume: bool = True) -> list[dict]:
            out = [{"kind": "config", "tables": 40, "rows": 1000000, "db_cpus": 2, "pg_audit": "pgaudit",
                    "stats_readers": True}]
            for target, account, exp in (("pg-load", "load_pgmon", ["shop.pg_catalog.pg_stats"]),
                                         ("mariadb-load", "load_colstats", ["mysql.column_stats"])):
                out += [
                    {"kind": "side", "target": target, "account": account, "phase": "on", "issued": 60,
                     "failed": 0},
                    {"kind": "side_events", "target": target, "account": account, "role": "stats",
                     "events": 11, "received": 61, "groups": 2, "max_events_per_group": 10,
                     "max_excess": excess, "non_connect": 10,
                     "objects": (exp if objects is None else objects), "expected": exp, "window_s": 60},
                ]
            if volume:
                out.append({"kind": "pgaudit_volume", "target": "pg-load", "log_catalog": log_catalog,
                            "soak_s": 600, "lines": 400000, "bytes": 120000000,
                            "audit": {"load_app": {"records": 180000, "bytes": 90000000},
                                      "load_pgmon": {"records": pgmon_records, "bytes": 400000},
                                      "databastion_agent": {"records": 1200, "bytes": 900000}}})
            return out

        facts, samples, hbs = scenario()
        # The scenario's agent runs at 0.05 core: within the reference only with a wider limit.
        lim = L.Limits(agent_ref_cpu_cores=0.03)
        base = [f for f in facts if f["kind"] != "config"]
        rep, ck = L.build_report(base + stats(), samples, hbs, lim)
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        names = {c["name"] for c in ck.items}
        for n in ("audit.pg-load.stats_ran", "audit.pg-load.stats_reported",
                  "audit.pg-load.stats_one_event_per_window", "audit.mariadb-load.stats_reported",
                  "audit.mariadb-load.stats_one_event_per_window", "audit.pg-load.pgaudit_catalog_volume_reported",
                  "agent.cpu_vs_release_reference", "agent.rss_vs_release_reference"):
            self.assertIn(n, names)
        v = rep["pgaudit_volume"]
        self.assertEqual(v["per_role"]["load_pgmon"]["records_per_s"], 0.6)
        self.assertEqual(v["log_mib_per_hour"], 686.6)
        md = L.render_markdown(rep)
        self.assertIn("`pgaudit.log_catalog = on`", md)
        self.assertIn("| load_pgmon | 360 |", md)
        self.assertIn("| pg-load/stats | load_pgmon |", md)
        for kw, failing in ((dict(excess=1), {"audit.pg-load.stats_one_event_per_window",
                                              "audit.mariadb-load.stats_one_event_per_window"}),
                            (dict(objects=[]), {"audit.pg-load.stats_reported", "audit.mariadb-load.stats_reported"}),
                            (dict(pgmon_records=0), {"audit.pg-load.pgaudit_catalog_volume_reported"}),
                            (dict(log_catalog="off"), {"audit.pg-load.pgaudit_catalog_volume_reported"})):
            rep, ck = L.build_report(base + stats(**kw), samples, hbs, lim)
            self.assertEqual(self.names(ck, False), failing, kw)
        rep, ck = L.build_report(base + stats(volume=False), samples, hbs, lim)
        self.assertEqual(self.names(ck, None), {"audit.pg-load.pgaudit_catalog_volume_reported"})
        # The default reference (0.013 core, limit 0.033): the scenario's 0.05 core fails it.
        rep, ck = L.build_report(base + stats(), samples, hbs, L.Limits())
        self.assertEqual(self.names(ck, False), {"agent.cpu_vs_release_reference"})
        rep, ck = L.build_report(base + stats(), samples, hbs, L.Limits(agent_ref_cpu_cores=0.03, agent_ref_rss_mb=20.0))
        self.assertEqual(self.names(ck, False), {"agent.rss_vs_release_reference"})
        # Without the statistics readers (an older run, the CAS harness): no reference or volume check.
        rep, ck = L.build_report(facts, samples, hbs, L.Limits())
        self.assertFalse(any("reference" in c["name"] or "pgaudit" in c["name"] for c in ck.items))

    def test_cas_run(self) -> None:
        # The facts e2e/load/cas.sh writes: the login workload on cas-load (container cas, no scan of
        # its own: the connector reads files), the ticket aggregate's scan on casdb-load (cas-db).
        facts, samples, hbs = scenario()
        ren = {"pg-load": "cas-load"}
        cas_facts = []
        for f in facts:
            f = dict(f)
            if f.get("kind") in ("scan", "findings"):
                f["target"] = "casdb-load"
            elif f.get("kind") == "target":
                cas_facts.append({"kind": "target", "target": "casdb-load", "container": "cas-db"})
                f = {"kind": "target", "target": "cas-load", "container": "cas"}
            elif "target" in f:
                f["target"] = ren[f["target"]]
            if f.get("kind") == "workload":
                f.update({"tool": "cas_scenario", "rate": 10, "logins": f["issued"] // 2, "failed_logins": 0})
            cas_facts.append(f)
        cas_facts[0] = {"kind": "config", "harness": "cas", "cas_login_rate": 10}
        for smp in samples:
            if "target-pg" in smp["c"]:
                c = smp["c"].pop("target-pg")
                smp["c"]["cas"] = dict(c)
                smp["c"]["cas-db"] = dict(c)
        rep, ck = L.build_report(cas_facts, samples, hbs, L.Limits())
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        names = {c["name"] for c in ck.items}
        self.assertIn("audit.cas-load.events_accounted", names)
        self.assertIn("audit.cas-load.p95_latency_ms", names)
        self.assertIn("discovery.casdb-load.db_cpu_impact_pct", names)
        self.assertNotIn("discovery.cas-load.db_cpu_impact_pct", names)
        self.assertEqual(rep["audit"]["cas-load"]["tool"], "cas_scenario")
        self.assertIsNotNone(rep["audit"]["cas-load"]["db_cores_audit_on"])
        self.assertIn("| casdb-load |", L.render_markdown(rep))

    def test_latency_metric_named(self) -> None:
        # The SQL Server and Redis runs report another latency figure in p95_ms and name it.
        facts, samples, hbs = scenario()
        for f in facts:
            if f.get("kind") == "workload":
                f["latency_metric"] = "mean elapsed time per workload statement"
        rep, ck = L.build_report(facts, samples, hbs, L.Limits())
        self.assertTrue(rep["pass"])
        c = [c for c in ck.items if c["name"] == "audit.pg-load.p95_latency_ms"][0]
        self.assertIn("latency figure: mean elapsed time per workload statement", c["note"])
        self.assertEqual(rep["audit"]["pg-load"]["latency_metric"], "mean elapsed time per workload statement")
        # Without it, the note is unchanged.
        facts, samples, hbs = scenario()
        _, ck = L.build_report(facts, samples, hbs, L.Limits())
        c = [c for c in ck.items if c["name"] == "audit.pg-load.p95_latency_ms"][0]
        self.assertNotIn("latency figure", c["note"])

    def test_limits_from_env(self) -> None:
        lim = L.Limits.from_env({"LOAD_LIMIT_DISCOVERY_PCT": "1.5", "LOAD_LIMIT_SPOOL_MAX_BATCHES": "7",
                                 "LOAD_LIMIT_DRAIN_S": ""})
        self.assertEqual((lim.discovery_pct, lim.spool_max_batches, lim.drain_s), (1.5, 7, 240.0))

    def test_report_cli(self) -> None:
        facts, samples, hbs = scenario()
        with tempfile.TemporaryDirectory() as d:
            for name, rows in (("facts", facts), ("samples", samples), ("hb", hbs)):
                with open(f"{d}/{name}.jsonl", "w") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in rows))
                    if name == "samples":
                        f.write('{"t": 12')  # a line cut by the sampler's termination
            rc = L.main(["report", "--facts", f"{d}/facts.jsonl", "--samples", f"{d}/samples.jsonl",
                         "--heartbeats", f"{d}/hb.jsonl", "--out", f"{d}/out"])
            self.assertEqual(rc, 0)
            with open(f"{d}/out/results.json") as f:
                self.assertTrue(json.load(f)["pass"])
            self.assertTrue(os.path.exists(f"{d}/out/results.md"))


def with_drain(facts: list, at_end: int | None = 20000, want: int = 180000, p95_off: float | None = 44.0,
               p95_drain: float | None = 41.0, window: bool = True) -> list:
    """The scenario's facts plus sqlserver.sh's catch-up facts: the drain window (940-1000, after the
    workload), the `drain` fact and the latency probes before Audit and during the drain."""
    out = list(facts)
    if window:
        out.append({"kind": "window", "name": "drain_pg-load", "t0": 940, "t1": 1000})
    samples = [[0.0, at_end], [60.0, want]]
    out.append({"kind": "drain", "target": "pg-load", "want": want, "stored": want, "samples": samples,
                "stored_at_workload_end": at_end, "rate_per_s": 2666.7})
    for ph, v in (("off", p95_off), ("drain", p95_drain)):
        out.append({"kind": "probe", "target": "pg-load", "phase": ph, "blocks": 0 if v is None else 6,
                    "mean_us": v, "p95_us": v})
    return out


class DrainChecksTest(unittest.TestCase):
    NAMES = {"audit.pg-load.db_cores_drain", "audit.pg-load.db_cores_drain_vs_audit_on",
             "audit.pg-load.drain_probe_p95_us"}

    def checks(self, ck: L.Checks) -> dict[str, dict]:
        return {c["name"]: c for c in ck.items if c["name"] in self.NAMES}

    def test_no_drain_fact_no_check(self) -> None:
        # run.sh, cas.sh and redis.sh record no `drain` fact: no catch-up check at all.
        rep, ck = L.build_report(*scenario(), L.Limits())
        self.assertEqual(self.checks(ck), {})
        self.assertNotIn("drain_happened", rep["audit"]["pg-load"])
        self.assertNotIn("Catch-up after the workload", L.render_markdown(rep))

    def test_pass_as_run_39695590686(self) -> None:
        facts, samples, hbs = scenario(drain_cores=0.2)
        rep, ck = L.build_report(with_drain(facts), samples, hbs, L.Limits())
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True])
        got = self.checks(ck)
        self.assertEqual(set(got), self.NAMES)
        self.assertTrue(all(c["pass"] is True for c in got.values()))
        a = rep["audit"]["pg-load"]
        self.assertTrue(a["drain_happened"])
        self.assertAlmostEqual(a["db_cores_drain"], 0.212, delta=0.01)
        self.assertEqual(got["audit.pg-load.db_cores_drain"]["limit"], "<= 1.0")
        self.assertAlmostEqual(a["db_cores_audit_on"], 0.312, delta=0.01)
        # 44 us before Audit: max(88, 1044).
        self.assertEqual(got["audit.pg-load.drain_probe_p95_us"]["limit"], "<= 1044.0")
        md = L.render_markdown(rep)
        self.assertIn("Catch-up after the workload", md)
        self.assertIn("| `audit.pg-load.drain_probe_p95_us` | pass |", md)

    def test_failures(self) -> None:
        # More than half the 2-CPU capacity during the drain: both CPU checks fail.
        facts, samples, hbs = scenario(drain_cores=1.2)
        rep, ck = L.build_report(with_drain(facts), samples, hbs, L.Limits())
        self.assertFalse(rep["pass"])
        failed = {c["name"] for c in ck.items if c["pass"] is False}
        self.assertEqual(failed, {"audit.pg-load.db_cores_drain", "audit.pg-load.db_cores_drain_vs_audit_on"})
        # Above the Audit-on run's 0.312 + 0.25, below 1 core: only the relative check fails.
        facts, samples, hbs = scenario(drain_cores=0.7)
        _, ck = L.build_report(with_drain(facts), samples, hbs, L.Limits())
        self.assertEqual({c["name"] for c in ck.items if c["pass"] is False},
                         {"audit.pg-load.db_cores_drain_vs_audit_on"})
        # The probe 1.1 ms slower during the drain (off + 1 ms is the larger bound below 1 ms).
        facts, samples, hbs = scenario()
        _, ck = L.build_report(with_drain(facts, p95_drain=1145.0), samples, hbs, L.Limits())
        self.assertEqual({c["name"] for c in ck.items if c["pass"] is False}, {"audit.pg-load.drain_probe_p95_us"})
        # Above 1 ms before Audit, the factor is the larger bound: 2 x 1500 = 3000.
        _, ck = L.build_report(with_drain(facts, p95_off=1500.0, p95_drain=2900.0), samples, hbs, L.Limits())
        self.assertTrue(self.checks(ck)["audit.pg-load.drain_probe_p95_us"]["pass"])
        self.assertEqual(self.checks(ck)["audit.pg-load.drain_probe_p95_us"]["limit"], "<= 3000.0")
        _, ck = L.build_report(with_drain(facts, p95_off=1500.0, p95_drain=3100.0), samples, hbs, L.Limits())
        self.assertIs(self.checks(ck)["audit.pg-load.drain_probe_p95_us"]["pass"], False)
        # Limits from the environment.
        lim = L.Limits.from_env({"LOAD_LIMIT_DRAIN_DB_CPU_SHARE": "0.005"})
        _, ck = L.build_report(with_drain(facts), samples, hbs, lim)
        self.assertIs(self.checks(ck)["audit.pg-load.db_cores_drain"]["pass"], False)

    def test_skipped_when_no_drain(self) -> None:
        # Every statement stored when the workload ended: reported as skipped, the run still passes,
        # even with figures that would fail.
        facts, samples, hbs = scenario(drain_cores=1.5)
        for kw in ({"at_end": 180000}, {"at_end": 0, "want": 0}):
            rep, ck = L.build_report(with_drain(facts, p95_drain=None, **kw), samples, hbs, L.Limits())
            got = self.checks(ck)
            self.assertEqual(set(got), self.NAMES)
            self.assertTrue(all(c.get("skipped") and c["pass"] is None for c in got.values()), got)
            self.assertNotIn("audit.pg-load.db_cores_drain", {c["name"] for c in ck.items if c["pass"] is False})
            self.assertIn("| `audit.pg-load.db_cores_drain` | skipped |", L.render_markdown(rep))
        rep, ck = L.build_report(with_drain(facts, p95_drain=None, at_end=180000), samples, hbs, L.Limits())
        self.assertTrue(rep["pass"], [c for c in ck.items if c["pass"] is not True and not c.get("skipped")])
        self.assertFalse(rep["audit"]["pg-load"]["drain_happened"])

    def test_no_data_fails_when_a_drain_happened(self) -> None:
        facts, samples, hbs = scenario()
        rep, ck = L.build_report(with_drain(facts, p95_drain=None, window=False), samples, hbs, L.Limits())
        self.assertFalse(rep["pass"])
        got = self.checks(ck)
        self.assertTrue(all(c["pass"] is None and not c.get("skipped") for c in got.values()), got)

    def test_cli_prints_skipped(self) -> None:
        facts, samples, hbs = scenario()
        facts = with_drain(facts, at_end=180000)
        with tempfile.TemporaryDirectory() as d:
            for name, rows in (("facts", facts), ("samples", samples), ("hb", hbs)):
                with open(f"{d}/{name}.jsonl", "w") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in rows))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = L.main(["report", "--facts", f"{d}/facts.jsonl", "--samples", f"{d}/samples.jsonl",
                             "--heartbeats", f"{d}/hb.jsonl", "--out", f"{d}/out"])
            self.assertEqual(rc, 0)
            self.assertIn("loadlib: check audit.pg-load.db_cores_drain: skipped (no drain:", err.getvalue())
            with open(f"{d}/out/results.json") as f:
                self.assertTrue(json.load(f)["pass"])


class CensusTest(unittest.TestCase):
    @staticmethod
    def line(engine: str, events: int, **kw: int) -> str:
        fields = {"message": "audit event census", "engine": engine, "events": events,
                  "statements": events, "overflowed": 0, "overflowed_statements": 0, "unknown_star": 0,
                  "unknown_star_statements": 0, "filtered": 0}
        fields.update(kw)
        rec = {"timestamp": "2026-10-20T10:00:00Z", "level": "INFO", "fields": fields,
               "target": "databastion_core::audit::census"}
        return "agent-1  | 2026-10-20T10:00:00.000000000Z " + json.dumps(rec)

    def test_last_line_per_engine_wins(self) -> None:
        lines = [
            self.line("postgres", 10, overflowed=1),
            "agent-1  | not json at all audit event census",
            self.line("mariadb", 5, unknown_star=2),
            self.line("postgres", 20, overflowed=3, overflowed_statements=7),
            '{"fields": {"message": "audit stream started", "engine": "postgres", "events": 99}}',
            self.line("BAD ENGINE", 1),
            self.line("redis", -1),
        ]
        c = L.census_from_log(lines)
        self.assertEqual(sorted(c), ["mariadb", "postgres"])
        self.assertEqual(c["postgres"]["events"], 20)
        self.assertEqual(c["postgres"]["overflowed_statements"], 7)
        self.assertEqual(c["mariadb"]["unknown_star"], 2)
        out = L.census_lines(c, "load")
        self.assertIn("CENSUS load engine=postgres events=20", out[1])
        self.assertIn("overflowed_rate=15.000%", out[1])
        md = L.census_markdown(c, [], "load")
        self.assertIn("| postgres | 20 | 20 | 3 | 7 |", md)

    def test_cmd_census_never_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "agent.log")
            with open(log, "w", encoding="utf-8") as f:
                f.write(self.line("sqlserver", 4, overflowed=1) + "\n")
            con = os.path.join(d, "console.json")
            with open(con, "w", encoding="utf-8") as f:
                json.dump([{"target": "mssql-load", "db_user": "load_orm", "events": 4, "statements": 9,
                            "star_events": 1, "star_statements": 3, "max_objects": 16}, {"bad": 1}], f)
            args = argparse.Namespace(log=log, console=con, label="t", out_dir=d)
            self.assertEqual(L.cmd_census(args), 0)
            with open(os.path.join(d, "census-t.md"), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("| sqlserver | 4 |", text)
            self.assertIn("| mssql-load | load_orm | 4 | 9 | 1 | 3 | - | - | 16 |", text)
            args = argparse.Namespace(log=os.path.join(d, "missing"), console=None, label="t", out_dir=None)
            self.assertEqual(L.cmd_census(args), 0)


    def test_console_names_carry_no_markup(self) -> None:
        self.assertEqual(L._console_name("<img src=x onerror=a()>&amp;"), "?img?src=x?onerror=a()??amp;")
        row = {"target": "<b>t</b>", "db_user": "a&b", "events": 1, "statements": 1, "star_events": 0,
               "star_statements": 0, "max_objects": 1}
        md = L.census_markdown({}, L.console_rows([row]), "t")
        for c in "<>&":
            self.assertNotIn(c, md.split("| Target |")[1])
        events, findings = L.star_rows({"events": [{"target": "<t>", "source": "s&", "action": "read",
                                                    "principal_kind": "account", "signals": "-",
                                                    "star_databases": ">db", "only_star": True, "overflowed": False,
                                                    "events": 1, "statements": 1, "rows_sum": 0}],
                                        "findings": [{"target": "t", "engine": "valkey", "database": "<d>",
                                                      "objects": 1, "star_object": False}]})
        self.assertEqual((events[0]["target"], events[0]["source"], events[0]["star_databases"]), ("?t?", "s?", "?db"))
        self.assertEqual(findings[0]["database"], "?d?")
        self.assertEqual(L.xe_builds("build <x>&y 2\n"), {"build": {"?x??y": 2}})

    def test_console_rows_are_safe_to_print(self) -> None:
        good = {"target": "mssql-load", "db_user": "\\fb45bc05628d$", "events": 4, "statements": 4,
                "star_events": 0, "star_statements": 0, "max_objects": 2}
        bad_name = dict(good, db_user="a|b`c d\n::error::x\r\u0007")
        rows = L.console_rows([good, bad_name, dict(good, target=7), dict(good, events=-1),
                               dict(good, events=True), dict(good, events="4"), {"target": "t"}, 3])
        self.assertEqual([r["db_user"] for r in rows], ["\\fb45bc05628d$", "a?b?c?d?::error::x??"])
        self.assertEqual(L.console_rows({"x": 1}), [])
        self.assertEqual(len(L.console_rows([dict(good, db_user="u" * 500)])[0]["db_user"]),
                         L.CONSOLE_NAME_MAX)
        md = L.census_markdown({}, rows, "load")
        for line in md.splitlines():
            if line.startswith("| mssql-load"):
                self.assertEqual(line.count("|"), 10)


    def test_census_sql_filters_on_a_uuid_only(self) -> None:
        q = L.census_sql("0f8e2c3a-1b2c-4d5e-8f90-123456789abc")
        self.assertIn("agent_id = '0f8e2c3a-1b2c-4d5e-8f90-123456789abc'", q)
        self.assertIn("objects_overflowed IS TRUE", q)
        self.assertIn("WHERE TRUE GROUP BY", L.census_sql())
        with self.assertRaises(ValueError):
            L.census_sql("x' OR '1'='1")
        self.assertIn("FROM findings WHERE TRUE", L.star_sql())
        args = argparse.Namespace(agent_id="bad", star=True)
        self.assertEqual(L.cmd_census_sql(args), 2)

    def test_console_rows_keep_the_overflow_flag_counts(self) -> None:
        row = {"target": "pg", "db_user": "fp:0123abcd", "events": 3, "statements": 5, "star_events": 1,
               "star_statements": 1, "overflowed_events": 1, "overflowed_statements": 2, "max_objects": 16}
        rows = L.console_rows([row, dict(row, overflowed_events=-2)])
        self.assertEqual(rows[0]["overflowed_statements"], 2)
        self.assertIsNone(rows[1]["overflowed_events"])

    def test_star_rows_and_out_dir(self) -> None:
        ev = {"target": "valkey-e2e", "source": "redis_slowlog", "action": "read", "principal_kind": "account",
              "signals": "-", "star_databases": "db0", "only_star": True, "overflowed": False, "events": 10,
              "statements": 120, "rows_sum": 0}
        data = {"events": [ev, dict(ev, events=-1), dict(ev, only_star="yes"), dict(ev, source="a\nb c"), 7],
                "findings": [{"target": "valkey-e2e", "engine": "valkey", "database": "db0", "objects": 4,
                              "star_object": False}, {"target": 1}]}
        events, findings = L.star_rows(data)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1]["source"], "a?b?c")
        self.assertEqual(len(findings), 1)
        out = L.star_lines(events, findings, "e2e-redis")
        self.assertIn("STAR-EVENTS e2e-redis target=valkey-e2e source=redis_slowlog action=read principal=account "
                      "signals=- star_databases=db0 only_star=true overflowed=false events=10", out[0])
        self.assertIn("STAR-FINDINGS e2e-redis target=valkey-e2e engine=valkey database=db0 finding_objects=4 "
                      "star_object=false", out[2])
        self.assertEqual(L.star_rows([1]), ([], []))
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "agent.log")
            with open(log, "w", encoding="utf-8") as f:
                f.write(self.line("valkey", 10, unknown_star=10) + "\n")
            star = os.path.join(d, "star.json")
            with open(star, "w", encoding="utf-8") as f:
                json.dump(data, f)
            out_dir = os.path.join(d, "census")
            args = argparse.Namespace(log=log, console=None, star=star, label="e2e redis/x", out_dir=out_dir)
            self.assertEqual(L.cmd_census(args), 0)
            with open(os.path.join(out_dir, "census-e2e_redis_x.json"), encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["agent"]["valkey"]["unknown_star"], 10)
            self.assertEqual(len(doc["star_events"]), 2)
            with open(os.path.join(out_dir, "census-e2e_redis_x.md"), encoding="utf-8") as f:
                md = f.read()
            self.assertIn("| valkey-e2e | redis_slowlog | read | account | - | db0 | yes | no | 10 | 120 | 0 |", md)


class XeCatchupTest(unittest.TestCase):
    @staticmethod
    def cut(ts: str) -> str:
        rec = {"timestamp": ts, "level": "DEBUG", "target": "databastion_connector_sqlserver::audit::xe",
               "fields": {"message": L.XE_CUT_MESSAGE, "target_id": "mssql-load"}}
        return "agent-1  | " + json.dumps(rec)

    def test_runs_of_cuts_and_the_cap(self) -> None:
        lines = [self.cut(f"2026-10-21T10:00:{s:02d}.123456Z") for s in range(0, 60, 5)]
        lines += [self.cut("2026-10-21T10:01:00.5Z"), "agent-1  | not json " + L.XE_CUT_MESSAGE]
        lines += [self.cut("2026-10-21T10:05:00Z"), self.cut("2026-10-21T10:05:10+00:00")]
        lines += [self.cut("2026-10-21T09:00:00Z"), self.cut("bad time")]
        since = L._log_time({"timestamp": "2026-10-21T09:30:00Z"})
        times = L.xe_cut_times(lines, since)
        self.assertEqual(len(times), 15)
        r = L.xe_catchup(lines, {"build": {"load_orm": 7}}, [], {}, since, 30.0)
        self.assertEqual((r["cuts"], r["episodes"], r["episodes_at_cap"]), (15, 2, 1))
        self.assertEqual(r["longest_episode_s"], 60.4)

    def test_builds_noise_and_command(self) -> None:
        b = L.xe_builds("build load_orm 4\nbuild load_orm 1\nselect load_app 900\nbuild a|b 2\njunk\nbuild x y\n")
        self.assertEqual(b, {"build": {"load_orm": 5, "a?b": 2}, "select": {"load_app": 900}})
        noise = L.xe_noise_rows([{"db_user": "load_orm", "events": 5, "statements": 41, "read_statements": 40,
                                  "unknown_star_events": 2,
                                  "unknown_star_statements": 3, "star_only_events": 1, "star_only_statements": 2,
                                  "overflowed_events": 1}, {"db_user": "x"}])
        r = L.xe_catchup([], b, noise, {"load_orm": 36}, None, 30.0)
        self.assertEqual(r["principals"][0]["excess_statements"], 4)
        out = L.xe_catchup_lines(r, "load-sqlserver")
        self.assertIn("XE-CATCHUP load-sqlserver cuts=0 episodes=0", out[0])
        self.assertIn("XE-NOISE load-sqlserver principal=load_orm events=5 statements=41 read_statements=40 issued=36 "
                      "excess_read_statements=4",
                      out[-1])
        with tempfile.TemporaryDirectory() as d:
            con = os.path.join(d, "noise.json")
            with open(con, "w", encoding="utf-8") as f:
                json.dump([{"db_user": "load_app", "events": 1, "statements": 9, "read_statements": 9, "unknown_star_events": 0,
                            "unknown_star_statements": 0, "star_only_events": 0, "star_only_statements": 0,
                            "overflowed_events": 0}], f)
            summary, js = os.path.join(d, "s.md"), os.path.join(d, "x.json")
            args = argparse.Namespace(log=os.path.join(d, "missing.log"), builds=None, console=con,
                                      issued=["load_app=9", "bad", "x=y"], since=None, gap=30.0, label="t",
                                      md=summary, json=js)
            self.assertEqual(L.cmd_xe_catchup(args), 0)
            with open(js, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["principals"][0]["excess_statements"], 0)
            with open(summary, encoding="utf-8") as f:
                self.assertIn("| load_app | 1 | 9 | 9 | 9 | 0 |", f.read())

    @staticmethod
    def retry(ts: str, reason: str) -> str:
        rec = {"timestamp": ts, "level": "DEBUG", "target": "databastion_connector_sqlserver::audit::xe::size",
               "fields": {"message": L.XE_RETRY_MESSAGE, "target_id": "mssql-load", "reason": reason,
                          "asked": 2000, "next": 500, "cancels_total": 1, "timeouts_total": 0}}
        return "agent-1  | " + json.dumps(rec)

    def test_retried_reads(self) -> None:
        # ADR-0051 refinement of 2026-10-22: cancels above 12 MiB (two within 10 minutes, one 10 minutes
        # later), a timeout, and lines before `since`, of another reason or not JSON, left out.
        lines = [self.retry("2026-10-22T10:00:00Z", "response above 12 MiB"),
                 self.retry("2026-10-22T10:09:59Z", "response above 12 MiB"),
                 self.retry("2026-10-22T10:20:00Z", "response above 12 MiB"),
                 self.retry("2026-10-22T10:21:00Z", "statement timeout"),
                 self.retry("2026-10-22T09:00:00Z", "response above 12 MiB"),
                 self.retry("2026-10-22T10:22:00Z", "something else"),
                 "agent-1  | not json " + L.XE_RETRY_MESSAGE]
        since = L._log_time({"timestamp": "2026-10-22T09:30:00Z"})
        self.assertEqual(L.xe_retries(lines, since), {"cancels": 3, "timeouts": 1, "max_cancels_per_10min": 2})
        self.assertEqual(L.xe_retries(lines[2:3], since)["max_cancels_per_10min"], 1)
        self.assertEqual(L.xe_retries([], None), {"cancels": 0, "timeouts": 0, "max_cancels_per_10min": 0})
        r = L.xe_catchup(lines, {}, [], {}, since, 30.0)
        self.assertEqual(r["reads"]["cancels"], 3)
        out = L.xe_catchup_lines(r, "load-sqlserver")
        self.assertIn("XE-READS load-sqlserver cancels=3 timeouts=1 max_cancels_per_10min=2", out)
        self.assertIn("Reads cancelled above 12 MiB and read again smaller: **3**", L.xe_catchup_markdown(r, "x"))


class XeReadChecksTest(unittest.TestCase):
    NAMES = {"audit.pg-load.xe_cancels_per_10min", "audit.pg-load.xe_timeouts"}

    def run_with(self, fact: dict | None) -> tuple[dict, dict[str, dict]]:
        facts, samples, hbs = scenario()
        if fact is not None:
            facts = facts + [{"kind": "xe_reads", "target": "pg-load", **fact}]
        rep, ck = L.build_report(facts, samples, hbs, L.Limits())
        return rep, {c["name"]: c for c in ck.items if c["name"] in self.NAMES}

    def test_checks(self) -> None:
        # No fact (SQL Server Audit, the other harnesses): no check.
        self.assertEqual(self.run_with(None)[1], {})
        rep, got = self.run_with({"cancels": 1, "timeouts": 0, "max_cancels_per_10min": 1, "large_bursts": 10})
        self.assertEqual(set(got), self.NAMES)
        self.assertTrue(all(c["pass"] is True for c in got.values()), got)
        self.assertTrue(rep["pass"])
        self.assertEqual(rep["audit"]["pg-load"]["xe_large_bursts"], 10)
        _, got = self.run_with({"cancels": 2, "timeouts": 0, "max_cancels_per_10min": 2, "large_bursts": 10})
        self.assertIs(got["audit.pg-load.xe_cancels_per_10min"]["pass"], False)
        _, got = self.run_with({"cancels": 0, "timeouts": 1, "max_cancels_per_10min": 0, "large_bursts": 0})
        self.assertIs(got["audit.pg-load.xe_timeouts"]["pass"], False)
        # The agent's log not read: no data, failed.
        rep, got = self.run_with({"cancels": None, "timeouts": None, "max_cancels_per_10min": None})
        self.assertFalse(rep["pass"])
        self.assertTrue(all(c["pass"] is None for c in got.values()))


if __name__ == "__main__":
    unittest.main()


class ProbeFactTest(unittest.TestCase):
    def test_probe_lines(self) -> None:
        text = "PROBE 40\nPROBE 60\nnoise\nPROBE x\nPROBE 50\n"
        f = L.probe_fact(text, "t", "drain")
        self.assertEqual((f["blocks"], f["mean_us"], f["p95_us"]), (3, 50.0, 60.0))
        self.assertIsNone(L.probe_fact("", "t", "off")["p95_us"])
