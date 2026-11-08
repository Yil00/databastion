"""Unit tests of the SQLite load run's writer (sqlite_writer.py) and report (sqliteload.py).
Run with `make test-load` (python3 -m unittest discover -s e2e/load -p 'test_*.py')."""

import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlite_writer as sw  # noqa: E402
import sqliteload as sl  # noqa: E402


def run_json(fn, argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = fn(argv)
    return rc, json.loads(buf.getvalue().strip().splitlines()[-1])


class Writer(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.dir = Path(self.d.name)

    def tearDown(self):
        self.d.cleanup()

    def test_seed_size_mode_and_no_overwrite(self):
        db = self.dir / "w.db"
        rc, out = run_json(sw.main, ["seed", "--out", str(db), "--size-mb", "4", "--tables", "2",
                                     "--journal-mode", "wal"])
        self.assertEqual(rc, 0)
        self.assertTrue(out["seeded"])
        self.assertGreater(db.stat().st_size, 4 * 1024 * 1024)
        self.assertEqual(db.read_bytes()[18], 2)
        self.assertEqual(db.stat().st_mode & 0o777, 0o640)
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        self.assertEqual(con.execute("SELECT count(*) FROM load_writes").fetchone()[0], sw.WRITES_ROWS)
        con.close()
        rc, out = run_json(sw.main, ["seed", "--out", str(db), "--size-mb", "4", "--journal-mode", "wal"])
        self.assertFalse(out["seeded"])

    def test_run_counts_busy_commits_with_a_reader_holding_a_shared_lock(self):
        db = self.dir / "r.db"
        run_json(sw.main, ["seed", "--out", str(db), "--size-mb", "1", "--tables", "1", "--journal-mode", "delete"])
        stop = threading.Event()

        def reader():
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, isolation_level=None)
            while not stop.is_set():
                con.execute("BEGIN")
                con.execute("SELECT count(*) FROM load_t01").fetchone()
                time.sleep(0.15)
                con.execute("COMMIT")
                time.sleep(0.15)
            con.close()

        th = threading.Thread(target=reader)
        th.start()
        try:
            rc, out = run_json(sw.main, ["run", "--db", str(db), "--rate", "100", "--duration", "1.5",
                                         "--busy-timeout-ms", "0", "--records", str(self.dir / "r.csv"),
                                         "--wal", str(self.dir / "w.csv")])
        finally:
            stop.set()
            th.join()
        self.assertEqual(rc, 0)
        self.assertGreater(out["busy"], 0)
        self.assertEqual(out["busy"], out["busy_at"]["commit"])
        self.assertEqual(out["issued"], out["committed"] + out["failed"])
        recs = sl.read_records(str(self.dir / "r.csv"))
        self.assertEqual(len(recs), out["issued"])
        self.assertEqual(sum(1 for r in recs if r[2] == 0), out["failed"])
        self.assertEqual(os.stat(self.dir / "r.csv").st_mode & 0o777, 0o644)

    def test_wal_run_with_a_reader_is_never_busy(self):
        db = self.dir / "w.db"
        run_json(sw.main, ["seed", "--out", str(db), "--size-mb", "1", "--tables", "1", "--journal-mode", "wal"])
        holder = sqlite3.connect(db)
        holder.execute("SELECT 1").fetchone()
        rc, out = run_json(sw.main, ["run", "--db", str(db), "--rate", "100", "--duration", "1",
                                     "--busy-timeout-ms", "0", "--records", str(self.dir / "r.csv"),
                                     "--wal", str(self.dir / "w.csv")])
        holder.close()
        self.assertEqual(out["busy"], 0)
        self.assertEqual(out["journal_mode"], "wal")
        wal = sl.read_wal(str(self.dir / "w.csv"))
        self.assertTrue(wal and wal[-1][1] > 0)


def fact_run(mode, busy, phase, p95, p99=None, busy_n=0, failed=0, wal=1 << 20, issued=600):
    return {"kind": "sqlite_run", "mode": mode, "busy_timeout_ms": busy, "phase": phase,
            "summary": {"issued": issued},
            "stats": {"transactions": issued, "committed": issued - failed, "busy": busy_n, "failed": failed,
                      "busy_per_s": busy_n / 10, "p50_ms": 1.0, "p95_ms": p95, "p99_ms": p99 or p95 * 2,
                      "max_ms": 50.0, "wal_peak_bytes": wal, "wal_end_bytes": wal}}


class Report(unittest.TestCase):
    def facts(self, over=None):
        over = over or {}
        f = [{"kind": "config", "harness": "sqlite", "rate": 200, "baseline_s": 3}]
        for mode in sl.MODES:
            for busy in sl.BUSY_TIMEOUTS:
                f.append(fact_run(mode, busy, "baseline", 2.0))
                f.append(over.get((mode, busy)) or fact_run(mode, busy, "scan", 2.05))
                f.append({"kind": "scan", "mode": mode, "busy_timeout_ms": busy, "target": f"load-{mode}",
                          "status": "succeeded", "t0": 100.0, "t1": 110.0, "progress": {}, "findings": 3})
        f.append({"kind": "window", "name": "idle_agent", "t0": 90.0, "t1": 99.0})
        f.append({"kind": "agent_log", "lost": 0})
        return f

    def samples(self, cores=0.01):
        return [{"t": float(t), "c": {"agent": {"cpu_usec": t * cores * 1e6, "anon": 40 << 20, "rss": 30 << 20}}}
                for t in range(80, 121)]

    def test_passes_within_the_limits(self):
        rep, ck = sl.build_report(self.facts(), self.samples(), sl.SqliteLimits())
        self.assertTrue(ck.passed, [c for c in ck.items if c["pass"] is not True])
        names = {c["name"] for c in ck.items}
        self.assertIn("sqlite.wal.b0.p95_ms", names)
        self.assertIn("sqlite.rollback.b5000.p99_added_ms", names)
        skipped = [c for c in ck.items if c.get("skipped")]
        self.assertEqual([c["name"] for c in skipped], ["sqlite.rollback.b0.busy_during_scan"])
        md = sl.render_markdown(rep)
        self.assertIn("**Result: PASS**", md)
        self.assertIn("| wal | 0 | scan |", md)

    def test_wal_busy_latency_and_growth_fail(self):
        over = {("wal", 0): fact_run("wal", 0, "scan", 2.7, busy_n=1, wal=20 << 20)}
        _, ck = sl.build_report(self.facts(over), self.samples(), sl.SqliteLimits())
        failed = {c["name"] for c in ck.items if c["pass"] is False}
        self.assertEqual(failed, {"sqlite.wal.b0.busy_during_scan", "sqlite.wal.b0.p95_ms",
                                  "sqlite.wal.b0.wal_peak_mib"})

    def test_rollback_with_a_busy_timeout_fails_on_a_failed_commit_or_p99(self):
        over = {("rollback", 5000): fact_run("rollback", 5000, "scan", 3.0, p99=520.0, failed=1)}
        _, ck = sl.build_report(self.facts(over), self.samples(), sl.SqliteLimits())
        failed = {c["name"] for c in ck.items if c["pass"] is False}
        self.assertEqual(failed, {"sqlite.rollback.b5000.failed_during_scan", "sqlite.rollback.b5000.p99_added_ms"})

    def test_agent_cpu_and_missing_data(self):
        _, ck = sl.build_report(self.facts(), self.samples(cores=0.05), sl.SqliteLimits())
        self.assertTrue(any(c["name"].endswith("cpu_cores_scan") and c["pass"] is False for c in ck.items))
        _, ck = sl.build_report([{"kind": "config", "rate": 200, "baseline_s": 3}], [], sl.SqliteLimits())
        self.assertFalse(ck.passed)
        self.assertTrue(all(c["pass"] is None or c.get("skipped") for c in ck.items))

    def test_limits_from_env(self):
        lim = sl.SqliteLimits.from_env({"LOAD_LIMIT_SQLITE_WAL_P95_FACTOR": "1.2", "LOAD_LIMIT_SQLITE_WAL_BUSY": "3"})
        self.assertEqual((lim.wal_p95_factor, lim.wal_busy), (1.2, 3))

    def test_window_counts_only_the_scan(self):
        recs = [(1.0, 1.0, 1, ""), (5.0, 9.0, 1, ""), (6.0, 0.2, 0, "commit"), (20.0, 1.0, 1, "")]
        wal = [(1.0, 10), (5.5, 99), (20.0, 20)]
        s = sl.window_stats(recs, wal, 4.0, 10.0)
        self.assertEqual((s["transactions"], s["committed"], s["busy"], s["failed"]), (2, 1, 1, 1))
        self.assertEqual((s["p95_ms"], s["wal_peak_bytes"], s["wal_end_bytes"]), (9.0, 99, 20))
        whole = sl.window_stats(recs, wal, None, None)
        self.assertEqual(whole["transactions"], 4)


if __name__ == "__main__":
    unittest.main()
