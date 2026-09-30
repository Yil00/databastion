"""Unit tests of seed.py (python3 -m unittest discover -s e2e/load -p 'test_*.py').

The MongoDB generator is also executed with Node.js when it is installed (a fake `c` connection
collects the documents); the SQL generators are checked for shape here, and against a real
PostgreSQL server by run.sh (and by hand with a throwaway cluster, see README)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import seed  # noqa: E402

IBAN_LENGTHS = {"FR": 27}


def iban_valid(compact: str) -> bool:
    """Port of agent/crates/classifiers/src/validate.rs iban_valid (ISO 7064 mod 97-10)."""
    if len(compact) < 15 or not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", compact):
        return False
    if IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rem = 0
    for ch in compact[4:] + compact[:4]:
        v = int(ch) if ch.isdigit() else ord(ch) - ord("A") + 10
        rem = (rem * 100 + v) % 97 if v >= 10 else (rem * 10 + v) % 97
    return rem == 1


class PlanTest(unittest.TestCase):
    def test_rows_sum_and_weights(self) -> None:
        p = seed.plan(40, 1_000_000)
        self.assertEqual(len(p), 40)
        self.assertEqual(sum(t.rows for t in p), 1_000_000)
        large = [t for t in p if t.index % 10 == 0]
        small = [t for t in p if t.index % 10 != 0]
        self.assertEqual(len(large), 4)
        self.assertTrue(all(t.rows > 10 * s.rows for t in large for s in small))
        self.assertEqual({t.kind for t in p}, set(seed.KINDS))

    def test_small_plans(self) -> None:
        p = seed.plan(1, 100)
        self.assertEqual([(t.index, t.rows) for t in p], [(1, 100)])
        p = seed.plan(3, 1000)
        self.assertEqual(sum(t.rows for t in p), 1000)
        self.assertTrue(all(t.rows >= seed.MIN_ROWS for t in p))

    def test_invalid(self) -> None:
        for args in ((0, 1000), (1000, 1_000_000), (10, 999)):
            with self.assertRaises(ValueError):
                seed.plan(*args)

    def test_names(self) -> None:
        p = seed.plan(12, 12_000)
        self.assertEqual(p[0].pg_name, "load_a.t001")
        self.assertEqual(p[4].pg_name, "load_a.t005")
        self.assertEqual(p[5].pg_name, "load_b.t006")
        self.assertEqual(p[11].mariadb_name, "load_t012")
        self.assertEqual(p[11].mongo_name, "load_c012")
        self.assertEqual(len({t.pg_name for t in p}), 12)


class ValuesTest(unittest.TestCase):
    def test_iban(self) -> None:
        self.assertTrue(iban_valid("FR7630006000011234567890189"))  # classifier test vector
        for t in (1, 7, 40, 99):
            for g in (1, 2, 96, 97, 12345, 199_999, 99_999_999_999):
                b = seed.bban(t, g)
                self.assertEqual(len(b), 23)
                self.assertTrue(iban_valid(seed.fr_iban(b)), (t, g))
        with self.assertRaises(ValueError):
            seed.fr_iban("123")

    def test_email_and_phone_shapes(self) -> None:
        for g in (1, 19, 20, 399, 400, 25_000):
            e = seed.email(3, g)
            self.assertRegex(e, r"^[a-z]+\.[a-z]+[0-9]+@[a-z]+\.example\.(org|net|com|fr)$")
            self.assertRegex(seed.phone(3, g), r"^\+33 6( [0-9]{2}){4}$")

    def test_row_values(self) -> None:
        t = seed.Table(4, 100, "mixed")
        v = seed.row_values(t, 42)
        self.assertEqual(set(v), {"id", "status", "note", "email", "phone", "iban"})
        self.assertTrue(iban_valid(str(v["iban"])))


class SqlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.p = seed.plan(8, 4000)

    def test_pg(self) -> None:
        sql = seed.pg_sql(self.p)
        self.assertEqual(sql.count("CREATE TABLE "), 8)
        self.assertEqual(sql.count("INSERT INTO "), 8)
        self.assertIn("GRANT SELECT ON ALL TABLES IN SCHEMA load_a, load_b, load_c, load_d TO databastion_agent, load_app;", sql)
        self.assertIn("VACUUM (ANALYZE) ", sql)
        for t in self.p:
            self.assertIn(f"generate_series(1, {t.rows})", sql)
        # Balanced parentheses per statement (cheap syntax guard).
        for stmt in sql.split(";\n"):
            self.assertEqual(stmt.count("("), stmt.count(")"), stmt[:80])

    def test_mariadb(self) -> None:
        sql = seed.mariadb_sql(self.p)
        self.assertTrue(sql.startswith("USE support;"))
        self.assertEqual(sql.count("CREATE TABLE load_t"), 8)
        for t in self.p:
            self.assertIn(f"FROM seq_1_to_{t.rows})", sql)
        self.assertIn("ANALYZE TABLE load_t001, ", sql)
        for stmt in sql.split(";\n"):
            self.assertEqual(stmt.count("("), stmt.count(")"), stmt[:80])

    def test_pgbench_scripts(self) -> None:
        s = seed.pgbench_scripts(self.p)
        self.assertEqual(len(s), 8)
        self.assertEqual(s["pg_t002.sql"],
                         f"\\set id random(1, {self.p[1].rows})\nSELECT * FROM load_b.t002 WHERE id = :id;\n")

    def test_sysbench(self) -> None:
        lua = seed.sysbench_lua(self.p)
        self.assertEqual(lua.count('{"load_t'), 8)
        self.assertIn("con:query(string.format(", lua)

    def test_cli(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(seed.main(["pgbench", "--tables", "4", "--rows", "400", "--out", d]), 0)
            self.assertEqual(sorted(os.listdir(d)), ["pg_t001.sql", "pg_t002.sql", "pg_t003.sql", "pg_t004.sql"])
        with tempfile.TemporaryDirectory() as d:
            # The workload reads the first tables only (pgbench: at most 128 scripts).
            self.assertEqual(seed.main(["pgbench", "--tables", "400", "--rows", "400000", "--out", d]), 0)
            self.assertEqual(len(os.listdir(d)), 40)
            self.assertEqual(seed.main(["pgbench", "--tables", "400", "--rows", "400000", "--out", d,
                                        "--workload-tables", "101"]), 2)
        self.assertEqual(seed.main(["pg", "--tables", "0", "--rows", "400"]), 2)

    def test_large_plan(self) -> None:
        p = seed.plan(400, 1_000_000)
        self.assertEqual(sum(t.rows for t in p), 1_000_000)
        self.assertEqual(p[-1].pg_name, "load_d.t400")
        self.assertEqual(len(seed.workload_tables(p, 40)), 40)
        self.assertEqual(seed.mariadb_sql(p).count("CREATE TABLE "), 400)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class MongoJsTest(unittest.TestCase):
    def test_runs_and_matches_python(self) -> None:
        p = seed.plan(4, 900)
        prelude = """
const docs = {};
const c = {getSiblingDB: (db) => ({getCollection: (n) => ({
  insertMany: (d, o) => { if (db !== "app" || o.ordered !== false) throw new Error("bad call");
    (docs[n] = docs[n] || []).push(...d); },
  estimatedDocumentCount: () => docs[n].length})})};
const print = (x) => console.error(String(x));
"""
        epilogue = "\nconsole.log(JSON.stringify(docs));\n"
        out = subprocess.run(["node", "-e", prelude + seed.mongo_js(p, batch=100) + epilogue],
                             capture_output=True, text=True, timeout=60, check=True)
        docs = json.loads(out.stdout)
        self.assertEqual(out.stderr.strip(), "900 documents")
        self.assertEqual(sorted(docs), [t.mongo_name for t in p])
        for t in p:
            got = docs[t.mongo_name]
            self.assertEqual(len(got), t.rows)
            self.assertEqual([d["_id"] for d in got], list(range(1, t.rows + 1)))
            for d in (got[0], got[-1]):
                ref = seed.row_values(t, d["_id"])
                for k in ("email", "phone", "iban", "status", "note"):
                    if k in ref:
                        self.assertEqual(d[k], ref[k], (t.mongo_name, k))


if __name__ == "__main__":
    unittest.main()
