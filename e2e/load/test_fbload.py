"""Unit tests of fbload.py (trace parsing, 8g burst ordering, the dependent-set reads, the workload
file), of loadlib.py's Firebird section and of seed.py's Firebird generators. No Docker, no driver:
python3 -m unittest discover -s e2e/load -p 'test_*.py'."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fbload  # noqa: E402
import loadlib  # noqa: E402
import seed  # noqa: E402

DB = "/var/lib/firebird/data/crm.fdb"


def rec(ts: str, event: str, att: int | None = None, user: str = "U1", body: str = "", pid: int = 16) -> str:
    out = f"2026-11-03T17:53:{ts} ({pid}:0x7f5efbbeddc0) {event}\n"
    if att is not None:
        out += f"\t{DB} (ATT_{att}, {user}:NONE, NONE, TCPv4:127.0.0.1/52654)\n\t/opt/firebird/bin/isql:22\n"
    return out + body + "\n"


def lines(text: str) -> list[bytes]:
    return [ln + b"\n" for ln in text.encode().split(b"\n")][:-1]


STMT = ("\t\t(TRA_11, CONCURRENCY | WAIT | READ_WRITE)\n\nStatement 109:\n" + "-" * 79 + "\n"
        "SELECT NOTE FROM T1 WHERE ID = 1\n1 records fetched\n      7 ms, 1 read(s), 4 fetch(es)\n\n"
        "Table                              Natural     Index\n" + "*" * 60 + "\nT1      1\n")


class TraceTest(unittest.TestCase):
    def test_records_keep_header_attachment_fetched_and_duration(self):
        text = rec("14.9650", "TRACE_INIT", body="\tSESSION_1 Firebird Audit\n") + \
            rec("14.9670", "EXECUTE_STATEMENT_FINISH", 4, body=STMT)
        rs = list(fbload.records(lines(text)))
        self.assertEqual([r.event for r in rs], ["TRACE_INIT", "EXECUTE_STATEMENT_FINISH"])
        r = rs[1]
        self.assertEqual((r.att, r.user, r.db, r.fetched, r.ms), (4, b"U1", DB.encode(), 1, 7))
        self.assertEqual(rs[0].size + rs[1].size, len(text.encode()))
        # Nothing of the body but counts is kept.
        self.assertFalse(any(b"SELECT" in (v if isinstance(v, bytes) else b"") for v in vars(r).values()))

    def test_statements_of_a_user_since(self):
        text = rec("10.0000", "EXECUTE_STATEMENT_FINISH", 4, "LOAD_APP", STMT) + \
            rec("20.0000", "FAILED EXECUTE_STATEMENT_FINISH", 4, "LOAD_APP", STMT) + \
            rec("21.0000", "EXECUTE_STATEMENT_FINISH", 5, "OTHER", STMT) + \
            rec("22.0000", "START_TRANSACTION", 4, "LOAD_APP")
        recs = list(fbload.records(lines(text)))
        since = fbload.parse_ts(b"2026-11-03T17:53:15.0000")
        self.assertEqual(fbload.statements_of(recs, b"LOAD_APP", None), {"statements": 2, "failed": 1})
        self.assertEqual(fbload.statements_of(recs, b"LOAD_APP", since), {"statements": 1, "failed": 1})

    def test_burst_order_inversion_late_time_and_open(self):
        text = (rec("01.0000", "ATTACH_DATABASE", 3, "DATABASTION_AGENT") + rec("02.0000", "DETACH_DATABASE", 3, "DATABASTION_AGENT")
                + rec("10.0000", "ATTACH_DATABASE", 10, "LOAD_BURST") + rec("10.1000", "ATTACH_DATABASE", 12, "LOAD_BURST")
                + rec("10.2000", "ATTACH_DATABASE", 40, "LOAD_BURST") + rec("11.5000", "ATTACH_DATABASE", 11, "LOAD_BURST")
                + rec("11.6000", "ATTACH_DATABASE", 13, "LOAD_BURST")
                # A second burst while the first is still attached: it does not open the database.
                + rec("30.0000", "ATTACH_DATABASE", 50, "LOAD_BURST"))
        bursts = fbload.burst_order(fbload.records(lines(text)), b"LOAD_BURST", 5.0)
        self.assertEqual(len(bursts), 2)
        b = bursts[0]
        self.assertTrue(b["opened_database"])
        self.assertEqual(b["attaches"], 5)
        self.assertEqual(b["late_records"], 2)
        # 11 below 40: 29 ids; first raised above 11 at 10.1 (id 12), read at 11.5: 1.4 s.
        self.assertEqual(b["max_inversion"], 29)
        # 13: first raised above by 40 at 10.2, read at 11.6: also 1.4 s.
        self.assertAlmostEqual(b["latest_late_s"], 1.4, places=3)
        self.assertFalse(bursts[1]["opened_database"])

    def test_burst_order_since(self):
        text = rec("01.0000", "ATTACH_DATABASE", 1, "LOAD_BURST") + rec("40.0000", "ATTACH_DATABASE", 2, "LOAD_BURST")
        since = fbload.parse_ts(b"2026-11-03T17:53:30.0000")
        self.assertEqual([b["attaches"] for b in fbload.burst_order(fbload.records(lines(text)), b"LOAD_BURST", 5.0, since)], [1])

    def test_catalog_reads(self):
        body = STMT.replace("SELECT NOTE FROM T1 WHERE ID = 1",
                            "SELECT CAST(D.RDB$DEPENDENT_NAME AS VARCHAR(252) CHARACTER SET OCTETS) FROM RDB$DEPENDENCIES D "
                            "WHERE D.RDB$DEPENDENT_TYPE IN (1, 2)").replace("1 records fetched", "33525 records fetched")
        text = rec("10.0000", "EXECUTE_STATEMENT_FINISH", 7, "DATABASTION_AGENT", body) + \
            rec("11.0000", "EXECUTE_STATEMENT_FINISH", 7, "LOAD_APP", body)
        out = fbload.catalog_reads(fbload.records(lines(text)), b"DATABASTION_AGENT", None)
        self.assertEqual(out["dependencies"], {"reads": 1, "ms_max": 7, "ms_p50": 7, "rows_max": 33525})
        self.assertEqual(out["view_relations"]["reads"], 0)
        self.assertEqual(out["sum_per_check_ms"], {"checks": 1, "max": 7, "p50": 7})

    def test_workload_file_and_schedule(self):
        self.assertEqual(fbload.parse_statements("10\tSELECT 1 FROM T WHERE ID = ?\n"), [("SELECT 1 FROM T WHERE ID = ?", 10)])
        for bad in ("", "x\tSELECT ?", "10\tSELECT 1", "0\tSELECT ?"):
            with self.assertRaises(ValueError):
                fbload.parse_statements(bad)
        self.assertEqual(fbload.schedule(3, 0.5, 100.0, 0.1), [100.1, 100.6, 101.1])


class StateIoTest(unittest.TestCase):
    def test_writes_bytes_and_sizes(self):
        ck = "fb-load.firebird_audit_trace.checkpoint"
        lg = "fb-load.firebird_ledger.counters"
        samples = [
            {"t": 0.0, "audit": {ck: [100, 1, 10], lg: [50, 5, 1]}},
            {"t": 0.5, "audit": {ck: [120, 2, 11], lg: [50, 5, 1]}},
            {"t": 1.0, "audit": {ck: [120, 2, 11], lg: [60, 6, 2]}},
            {"t": 2.0, "audit": {ck: [140, 3, 12], lg: [60, 6, 2], "fb-load.firebird_audit_trace.cursor": [30, 9, 1]}},
        ]
        io = loadlib.fb_state_io(samples)
        self.assertEqual(io["span_s"], 2.0)
        self.assertEqual(io["checkpoint"]["writes"], 2)
        self.assertEqual(io["checkpoint"]["bytes_written"], 260)
        self.assertEqual(io["checkpoint"]["min_write_gap_s"], 1.5)
        self.assertEqual((io["checkpoint"]["size_min"], io["checkpoint"]["size_max"], io["checkpoint"]["size_last"]), (100, 140, 140))
        self.assertEqual(io["ledger"]["writes"], 1)
        self.assertEqual(io["other_audit_state"]["writes"], 0)


class FirebirdSectionTest(unittest.TestCase):
    def facts(self, **over):
        f = [
            {"kind": "config", "harness": "firebird", "parts": "load,schema", "bursts": 1, "burst_size": 3,
             "firebird_version": "5.0.4"},
            {"kind": "fb_level", "level": "partial"},
            {"kind": "fb_own_events", "events": 0, "statements": 0},
            {"kind": "fb_bursts", "bursts": [{"attaches": 3, "opened_database": True, "max_inversion": 2,
                                              "latest_late_s": 0.5, "late_records": 1}],
             "ambiguous_before": 0, "ambiguous_after": 0},
            {"kind": "fb_3m", "scenario": "opentx_8x8_within", "statements_expected": 64,
             "events": {"statements": 64, "star_statements": 0}, "ambiguous_before": 0, "ambiguous_after": 0, "client": {}},
            {"kind": "fb_3m", "scenario": "opentx_2x24_per_binding", "statements_expected": 48,
             "events": {"statements": 50, "star_statements": 2}, "ambiguous_before": 0, "ambiguous_after": 3, "client": {}},
            {"kind": "fb_schema", "objects": 11425},
            {"kind": "fb_schema_read", "phase": "complete", "cut_warnings": 0, "checks": 3,
             "dependencies": {"rows_max": 33525, "ms_max": 120}, "view_relations": {"ms_max": 5},
             "field_sources": {"ms_max": 3}, "routines": {"ms_max": 20}, "sum_per_check_ms": {"max": 150}},
            {"kind": "fb_schema_read", "phase": "cut", "cut_warnings": 2, "checks": 3},
            {"kind": "fb_flood", "phase": "complete", "user": "LOAD_EXPR", "issued": 10,
             "events": {"statements": 10, "star_statements": 10, "events": 2, "star_events": 2}},
        ]
        return f

    def test_checks(self):
        ck = loadlib.Checks()
        state = [{"t": 0.0, "audit": {"x.firebird_audit_trace.checkpoint": [10, 1, 1], "x.firebird_ledger.counters": [5, 1, 1]}},
                 {"t": 10.0, "audit": {"x.firebird_audit_trace.checkpoint": [12, 2, 2], "x.firebird_ledger.counters": [5, 1, 1]}}]
        fb = loadlib.firebird_section(self.facts(), state, ck)
        by = {c["name"]: c for c in ck.items}
        self.assertTrue(ck.passed, [c for c in ck.items if c["pass"] is not True and not c.get("skipped")])
        self.assertTrue(by["firebird.8g_max_inversion_ids"]["pass"])
        self.assertTrue(by["firebird.3m.opentx_8x8_within.no_ambiguous_record"]["pass"])
        self.assertTrue(by["firebird.3m.opentx_2x24_per_binding.ambiguous_records"]["skipped"])
        self.assertTrue(by["firebird.schema_read_complete"]["pass"])
        self.assertTrue(by["firebird.schema_cut_detected"]["pass"])
        self.assertEqual(fb["flood"]["complete"]["LOAD_EXPR"]["star_share"], 1.0)
        md = "\n".join(loadlib.render_firebird(fb, str))
        self.assertIn("8g attach bursts", md)

    def test_bounds_fail(self):
        f = self.facts()
        f[3]["bursts"][0]["max_inversion"] = 300
        f[7]["cut_warnings"] = 1
        ck = loadlib.Checks()
        loadlib.firebird_section(f, [], ck)
        by = {c["name"]: c for c in ck.items}
        self.assertFalse(by["firebird.8g_max_inversion_ids"]["pass"])
        self.assertFalse(by["firebird.schema_read_complete"]["pass"])
        # No state samples: no data, which fails.
        self.assertIsNone(by["firebird.checkpoint_written"]["pass"])
        self.assertFalse(ck.passed)

    def test_other_harness(self):
        self.assertIsNone(loadlib.firebird_section([{"kind": "config", "harness": "sqlserver"}], [], loadlib.Checks()))


class SeedTest(unittest.TestCase):
    def test_fb_vars_prefix_outside_literals(self):
        self.assertEqual(seed._fb_vars("VALUES (G, 'G B S', MOD(G, 4), B || S, GEN_ID(X, 1))"),
                         "VALUES (:G, 'G B S', MOD(:G, 4), :B || :S, GEN_ID(X, 1))")

    def test_firebird_seed(self):
        sql = seed.firebird_sql(seed.plan(4, 400))
        self.assertIn("CREATE TABLE LOAD_T004", sql)
        self.assertIn("GRANT DEFAULT DATABASTION_READER TO USER DATABASTION_AGENT^", sql)
        for u in seed.FB_LOAD_USERS:
            self.assertIn(f"GRANT DEFAULT LOAD_READER TO USER {u}^", sql)
        self.assertEqual(seed.fb_iban_mod_parts(), 10 ** 15 % 97)

    def test_schema_counts_and_sql(self):
        s = seed.FbSchema()
        c = s.object_counts()
        self.assertGreaterEqual(c["tables"] + c["views"] + c["procedures"] + c["functions"] + c["packages"] + c["triggers"]
                                + c["computed_columns"] + c["check_constraints"] + c["expression_indexes"], 10000)
        sql = seed.fb_schema_sql(s.scaled(0.1))
        self.assertIn("COMPUTED BY (UPPER(NAME))", sql)
        self.assertIn("FROM MON$STATEMENTS", sql)
        w = seed.fb_schema_workload(s)
        self.assertEqual(sorted(w), sorted(seed.FB_SCHEMA_USERS))
        self.assertTrue(all(st.count("?") == 1 for v in w.values() for st in v))
        with self.assertRaises(ValueError):
            s.scaled(9)
        self.assertEqual(seed.fb_schema_cut_ddl(s, 2).count("\n--\n"), 1)


if __name__ == "__main__":
    unittest.main()
