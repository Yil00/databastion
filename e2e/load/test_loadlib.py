"""Unit tests of loadlib.py (python3 -m unittest discover -s e2e/load -p 'test_*.py')."""

from __future__ import annotations

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
             leak_mb_per_s: float = 0.0, p95_on: float = 1.2, missing_idle: bool = False) -> tuple[list, list, list]:
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
                        bursts=[(60, 1000, 0.002), (130, 160, impact_cores * 1), (200, 940, 0.3)])
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


if __name__ == "__main__":
    unittest.main()
