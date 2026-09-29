"""Unit tests of e2e/i2_check.py (run: python3 -m unittest discover -s e2e -p 'test_*.py')."""

from __future__ import annotations

import io
import json
import os
import tempfile
import sys
import unittest
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # also runs from the repository root

import i2_check  # noqa: E402

REPO = os.path.dirname(HERE)
GROUND_TRUTH = os.path.join(REPO, "dev", "ground-truth.json")
SEED_PG = os.path.join(REPO, "dev", "seed", "out", "postgres.sql")
SEED_MYSQL = os.path.join(REPO, "dev", "seed", "out", "mysql.sql")
SEED_MARIADB = os.path.join(REPO, "dev", "seed", "out", "mariadb.sql")

# A small ground truth with the shapes of dev/ground-truth.json (fake values).
GT = {
    "locations": [
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "email", "expected_classifiers": ["pii.email"], "name_contains_value": False,
         "negative_control": False, "values": ["manon.bernard@example.com"]},
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "last_name", "expected_classifiers": ["pii.person_name"],
         "name_contains_value": False, "negative_control": False,
         "values": ["Lefèvre", "Martin", "Müller", "O'Connor", "Ava"]},
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "first_name", "expected_classifiers": ["pii.person_name"],
         "name_contains_value": False, "negative_control": False, "values": ["Chloé"]},
        {"engine": "postgresql", "database": "shop", "container": "billing",
         "object": "payment_methods", "field": "card_number",
         "expected_classifiers": ["pii.card_number"], "name_contains_value": False,
         "negative_control": False, "values": ["4111 1101 9561 4578"]},
        {"engine": "postgresql", "database": "shop", "container": "billing",
         "object": "payment_methods", "field": "iban", "expected_classifiers": ["pii.iban"],
         "name_contains_value": False, "negative_control": False,
         "values": ["DE09 9994 2494 8715 2904 85"]},
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "phone", "expected_classifiers": ["pii.phone"], "name_contains_value": False,
         "negative_control": False, "values": ["01 99 00 27 59", "+33 6 39 98 78 79",
                                                "+44 7700 900404", "+1 202 555 0125"]},
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "nir", "expected_classifiers": ["pii.nir"], "name_contains_value": False,
         "negative_control": False, "values": ["1 01 09 59 805 802 78"]},
        {"engine": "postgresql", "database": "shop", "container": "crm", "object": "customers",
         "field": "birth_date", "expected_classifiers": ["pii.birth_date"],
         "name_contains_value": False, "negative_control": False, "values": ["1950-12-01"]},
        {"engine": "postgresql", "database": "shop", "container": "crm",
         "object": "export_client_0639988384", "field": "email",
         "expected_classifiers": ["pii.email"], "expected_normalized_name": "*",
         "name_contains_value": True, "name_value_classifiers": ["pii.phone"],
         "name_values": ["0639988384"], "negative_control": False,
         "values": ["jean.dubois@example.com"]},
        {"engine": "postgresql", "database": "shop", "container": "crm",
         "object": "archive_lucas_martin", "field": "amount_cents", "expected_classifiers": [],
         "expected_normalized_name": "*", "name_contains_value": True,
         "name_value_classifiers": ["pii.person_name"], "name_values": ["lucas", "martin"],
         "negative_control": True},
        {"engine": "mysql", "database": "hr", "container": None, "object": "employees",
         "field": "email", "expected_classifiers": ["pii.email"], "name_contains_value": False,
         "negative_control": False, "values": ["other.engine@example.org"]},
    ]
}

# What the console legitimately holds: masked samples in the documented formats
# (agent/crates/classifiers/src/masking.rs), normalized names, timestamps, UUIDs, hashes.
CLEAN = "\n".join([
    "COPY public.findings (id, object_name, field_name, classifier) FROM stdin;",
    "3f2a9c1e-5b7d-4e2a-9c1e-5b7d4e2a9c1e\t*\temail\tpii.email",
    "masked: m***@e***.com j***@e***.com",
    "masked: L*** M*** O*** C*** M***",
    "masked: **** **** **** 4578",
    "masked: DE** **** **** **** **** 85",
    "masked: ** ** ** ** 59  +33 * ** ** ** 79  +44 **** ****04  +1 *** *** **25",
    "masked: * ** ** ** *** *** **  ****-**-**",
    "ts: 2026-09-28T20:54:01.123Z 2026-09-28 20:54:01.123456+00 1759092841123",
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "names: Martinez Lucasfilm AVA-7 ava available",
    "other engine: other.engine@example.org",
    "\\.",
])

PLANTED = {
    "plain email": ("x manon.bernard@example.com y", "L0.v0"),
    "upper case, accents dropped": ("holder: LEFEVRE", "L1.v0"),
    "NFD": ("name=" + unicodedata.normalize("NFD", "Lefèvre"), "L1.v0"),
    "NFC upper with accent": ("MÜLLER", "L1.v2"),
    "json escape": ('{"n":"Chlo\\u00e9"}', "L2.v0"),
    "html entity": ("<td>O&#x27;Connor</td>", "L1.v3"),
    "card with dashes": ("pan=4111-1101-9561-4578;", "L3.v0"),
    "card digits only": ("pan=4111110195614578", "L3.v0"),
    "iban compact lower": ("iban de09999424948715290485", "L4.v0"),
    "phone digits": ("tel 0199002759", "L5.v0"),
    "phone international form of a national number": ("tel +33 1 99 00 27 59", "L5.v0"),
    "phone national form of an international number": ("tel 06.39.98.78.79", "L5.v1"),
    "uk phone national": ("07700 900404", "L5.v2"),
    "us phone without country code": ("(202) 555-0125", "L5.v3"),
    "nir compact": ("nir=101095980580278", "L6.v0"),
    "birth date": ("born 1950-12-01", "L7.v0"),
    "value-bearing table name": ("relation crm.export_client_0639988384", "L8.object"),
    "value-bearing name digits": ("table *_0639988384", "L8.n0"),
    "url-encoded": ("GET /x?q=manon.bernard%40example.com", "L0.v0"),
    "person name in a name": ("object archive_lucas_martin", "L9.object"),
    "person name alone": ("user martin logged in", "L1.v1"),
    "phone national significant number": ("msisdn=639987879", "L5.v1"),
    "uk phone national significant number": ("uk:7700900404", "L5.v2"),
    "iban bban": ("bban=99942494871529048 5", "L4.v0"),
    "e-mail local part": ("login manon.bernard failed", "L0.v0.local"),
}

# pg_dump COPY text format: backslashes doubled, jsonb with \uXXXX escapes (as text produced by
# JSON.stringify of an escaped string), SQL literals with doubled quotes in function bodies.
PG_DUMP_EXCERPT = "\n".join([
    "COPY public.audit_log (id, action, details) FROM stdin;",
    '1\tscan\t{"note": "Chlo\\u00e9 Lef\\u00e8vre", "tel": "01 99 00 27 59"}',
    "\\.",
    "CREATE FUNCTION public.f() RETURNS text LANGUAGE sql AS $$ SELECT 'O''Connor' $$;",
])

# Next.js React Server Components payload: JSON-escaped strings inside self.__next_f.push.
RSC_EXCERPT = (
    '<script>self.__next_f.push([1,"5:[\\"$\\",\\"li\\",\\"0\\",'
    '{\\"children\\":\\"4111 1101 9561 4578\\"}]\\n6:[\\"$\\",\\"td\\",null,'
    '{\\"children\\":\\"M\\u00fcller \\u0026 manon.bernard\\u0040example.com\\"}]\\n"])</script>'
)


def run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    rc = i2_check.main(argv, out=buf)
    return rc, buf.getvalue()


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.gt = os.path.join(self.tmp.name, "gt.json")
        with open(self.gt, "w", encoding="utf-8") as f:
            json.dump(GT, f)

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmp.name, "files", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def scan(self, *paths: str, extra: list[str] | None = None) -> tuple[int, str]:
        return run(["scan", "--ground-truth", self.gt, "--engine", "postgresql",
                    *(extra or []), *paths])


class FoldTest(unittest.TestCase):
    def test_nfc_nfd_case_accents(self) -> None:
        nfc = unicodedata.normalize("NFC", "Lefèvre")
        nfd = unicodedata.normalize("NFD", "Lefèvre")
        self.assertNotEqual(nfc, nfd)
        self.assertEqual(i2_check.fold(nfc), i2_check.fold(nfd))
        self.assertEqual(i2_check.fold("LEFÈVRE"), "lefevre")
        self.assertEqual(i2_check.fold("Straße"), "strasse")

    def test_phone_variants(self) -> None:
        self.assertEqual(i2_check.phone_variants("01 99 00 27 59"),
                         {"0199002759", "33199002759", "199002759"})
        self.assertEqual(i2_check.phone_variants("+33 6 39 98 78 79"),
                         {"33639987879", "0639987879", "639987879"})
        self.assertEqual(i2_check.phone_variants("+44 7700 900404"),
                         {"447700900404", "07700900404", "7700900404"})
        self.assertEqual(i2_check.phone_variants("+1 202 555 0125"), {"12025550125", "2025550125"})

    def test_iban_bban_and_email_local_part(self) -> None:
        self.assertEqual(i2_check.iban_bban("DE09 9994 2494 8715 2904 85"), "999424948715290485")
        self.assertIsNone(i2_check.iban_bban("1234 5678"))
        self.assertEqual(i2_check.email_local_part("Manon.Bernard@example.com"), "manon.bernard")
        self.assertIsNone(i2_check.email_local_part("ava.li@example.com"))  # < 8 alphanumerics


class PlanTest(Base):
    def test_exclusions_and_kinds(self) -> None:
        plan = i2_check.build_plan(GT, "postgresql")
        ids = {n.id for n in plan.needles}
        self.assertEqual(plan.excluded, {"short": 1, "common": 0})  # "Ava"
        self.assertNotIn("L1.v4", ids)
        for nid in ("L8.object", "L8.n0", "L9.object", "L9.n0", "L9.n1"):
            self.assertIn(nid, ids)
        self.assertFalse(any(n.location == 10 for n in plan.needles))  # other engine

    def test_common_words_rule(self) -> None:
        old = dict(i2_check.COMMON_WORDS)
        self.addCleanup(lambda: (i2_check.COMMON_WORDS.clear(), i2_check.COMMON_WORDS.update(old)))
        i2_check.COMMON_WORDS["martin"] = "test"
        plan = i2_check.build_plan(GT, "postgresql")
        self.assertEqual(plan.excluded["common"], 2)  # L1.v1 and L9.n1


class ScanTest(Base):
    def test_clean_dump_with_masked_samples(self) -> None:
        rc, out = self.scan(self.write("dump.sql", CLEAN))
        self.assertEqual(rc, 0, out)
        self.assertIn("no ground-truth value in clear text", out)
        self.assertIn("excluded: short 1, common 0", out)

    def test_each_planted_form_is_detected(self) -> None:
        for label, (text, needle_id) in PLANTED.items():
            with self.subTest(label):
                path = self.write(f"{label}.log", CLEAN + "\n" + text + "\n")
                rc, out = self.scan(path)
                self.assertEqual(rc, 1, f"{label}: {out}")
                self.assertIn(f"LEAK {needle_id} ", out)

    def test_output_never_holds_a_value(self) -> None:
        path = self.write("all.log", CLEAN + "\n" + "\n".join(t for t, _ in PLANTED.values()))
        rc, out = self.scan(path)
        self.assertEqual(rc, 1)
        folded_out = i2_check.fold(out)
        plan = i2_check.build_plan(GT, "postgresql")
        for n in plan.needles:
            self.assertNotIn(n.plain, folded_out, n.id)
            for c in n.compacts:
                self.assertNotIn(c, i2_check.compact(folded_out), n.id)
        self.assertIn("<value-bearing name>", out)

    def test_word_boundaries_for_short_needles(self) -> None:
        rc, out = self.scan(self.write("a.log", "Martinez lucasfilm xmartin martin2"))
        self.assertEqual(rc, 0, out)
        rc, out = self.scan(self.write("b.log", "archive_lucas_martin"))
        self.assertEqual(rc, 1, out)

    def test_no_partial_match_inside_longer_digit_runs(self) -> None:
        rc, out = self.scan(self.write("a.log", "id 90199002759 and 01990027591 and 141111101956145780"))
        self.assertEqual(rc, 0, out)
        # The national significant number keeps the digit guard: not inside a longer run.
        rc, out = self.scan(self.write("b.log", "id 5639987879 and 77009004041"))
        self.assertEqual(rc, 0, out)

    def test_email_local_part_is_bounded(self) -> None:
        rc, out = self.scan(self.write("a.log", "xmanon.bernardx manon.bernard2"))
        self.assertEqual(rc, 0, out)

    def test_pg_dump_copy_excerpt(self) -> None:
        rc, out = self.scan(self.write("dump.sql", CLEAN + "\n" + PG_DUMP_EXCERPT))
        self.assertEqual(rc, 1, out)
        for nid, view in (("L2.v0", "json-escapes"), ("L1.v0", "json-escapes"),
                          ("L5.v0", "raw"), ("L1.v3", "sql-quotes")):
            self.assertRegex(out, rf"LEAK {nid} .* view={view} ", nid)

    def test_rsc_payload_excerpt(self) -> None:
        rc, out = self.scan(self.write("page.html", CLEAN + "\n" + RSC_EXCERPT))
        self.assertEqual(rc, 1, out)
        for nid in ("L3.v0", "L1.v2", "L0.v0"):
            self.assertIn(f"LEAK {nid} ", out)

    def test_masked_mixed_with_separators_do_not_join(self) -> None:
        # A masked card next to the kept digits of another sample: `*` breaks the projection.
        rc, out = self.scan(self.write("a.log", "4111 **** **** 4578 4111 1101 **** 4578"))
        self.assertEqual(rc, 0, out)

    def test_directory_and_exclude(self) -> None:
        self.write("dir/web.log", CLEAN)
        self.write("dir/target-pg.log", "manon.bernard@example.com")
        d = os.path.join(self.tmp.name, "files", "dir")
        rc, out = self.scan(d, extra=["--exclude", "target-pg.log"])
        self.assertEqual(rc, 0, out)
        rc, out = self.scan(d)
        self.assertEqual(rc, 1, out)
        self.assertIn("file=target-pg.log", out)

    def test_nothing_to_scan_is_an_error(self) -> None:
        rc, out = self.scan(self.write("empty.log", ""))
        self.assertEqual(rc, 2, out)
        rc, out = self.scan(os.path.join(self.tmp.name, "missing"))
        self.assertEqual(rc, 2, out)


class CoverageTest(Base):
    def test_coverage_fails_when_a_needle_is_missing(self) -> None:
        rc, out = run(["coverage", "--ground-truth", self.gt, "--engine", "postgresql",
                       self.write("partial.sql", "manon.bernard@example.com")])
        self.assertEqual(rc, 1, out)
        self.assertIn("NOT found", out)

    @unittest.skipUnless(os.path.exists(SEED_PG), "committed seed not found")
    def test_every_postgres_value_is_visible_in_the_committed_seed(self) -> None:
        # Positive control on the real data: the scanner sees every searchable PostgreSQL value of
        # dev/ground-truth.json, and every value-bearing name, in dev/seed/out/postgres.sql.
        rc, out = run(["coverage", "--ground-truth", GROUND_TRUTH, "--engine", "postgresql", SEED_PG])
        self.assertEqual(rc, 0, out)

    @unittest.skipUnless(os.path.exists(SEED_MYSQL) and os.path.exists(SEED_MARIADB),
                         "committed seeds not found")
    def test_every_mysql_and_mariadb_value_is_visible_in_the_committed_seeds(self) -> None:
        for engine, seed in (("mysql", SEED_MYSQL), ("mariadb", SEED_MARIADB)):
            with self.subTest(engine=engine):
                rc, out = run(["coverage", "--ground-truth", GROUND_TRUTH, "--engine", engine, seed])
                self.assertEqual(rc, 0, out)


class FindingsTest(Base):
    ROWS = [
        {"database_name": "shop", "schema_name": "crm", "object_name": "customers",
         "field_name": "email", "classifier": "pii.email"},
        {"database_name": "shop", "schema_name": "crm", "object_name": "*",
         "field_name": "email", "classifier": "pii.email"},
        {"database_name": "shop", "schema_name": "billing", "object_name": "payment_methods",
         "field_name": "card_number", "classifier": "pii.card_number"},
    ]

    def check(self, rows: list[dict], required: list[str] | None = None) -> tuple[int, str]:
        path = self.write("rows.json", json.dumps(rows))
        argv = ["findings", "--ground-truth", self.gt, "--engine", "postgresql"]
        for c in required or []:
            argv += ["--require-classifier", c]
        return run(argv + [path])

    def test_ok(self) -> None:
        rc, out = self.check(self.ROWS, ["pii.email", "pii.card_number"])
        self.assertEqual(rc, 0, out)
        self.assertIn("expected normalized name '*'", out)
        self.assertIn("found: 2/", out)

    def test_no_findings(self) -> None:
        rc, out = self.check([])
        self.assertEqual(rc, 1, out)

    def test_missing_required_classifier(self) -> None:
        rc, out = self.check(self.ROWS, ["pii.iban"])
        self.assertEqual(rc, 1, out)

    def test_raw_value_bearing_name_is_an_error_and_not_printed(self) -> None:
        rows = self.ROWS + [{"database_name": "shop", "schema_name": "crm",
                             "object_name": "export_client_0639988384", "field_name": "email",
                             "classifier": "pii.email"}]
        rc, out = self.check(rows)
        self.assertEqual(rc, 1, out)
        self.assertNotIn("0639988384", out)

    def test_normalized_name_missing(self) -> None:
        rc, out = self.check([r for r in self.ROWS if r["object_name"] != "*"])
        self.assertEqual(rc, 1, out)
        self.assertIn("expected normalized name", out)


# MySQL / MariaDB shapes: no container (schema), a value-bearing table name as a negative control.
GT_MY = {
    "locations": [
        {"engine": "mariadb", "database": "support", "container": None, "object": "tickets",
         "field": "requester_email", "expected_classifiers": ["pii.email"],
         "name_contains_value": False, "negative_control": False, "values": ["a.b@example.com"]},
        {"engine": "mariadb", "database": "support", "container": None, "object": "tickets",
         "field": "body", "expected_classifiers": ["pii.card_number", "pii.iban"],
         "name_contains_value": False, "negative_control": False, "values": []},
        {"engine": "mariadb", "database": "support", "container": None, "object": "tickets",
         "field": "status", "expected_classifiers": [], "name_contains_value": False,
         "negative_control": True, "values": []},
        {"engine": "mariadb", "database": "support", "container": None,
         "object": "escalations_jean.richard@example.com", "field": "reason",
         "expected_classifiers": [], "expected_normalized_name": "*", "name_contains_value": True,
         "name_value_classifiers": ["pii.email"], "name_values": ["jean.richard@example.com"],
         "negative_control": True},
        {"engine": "mysql", "database": "hr", "container": None, "object": "employees",
         "field": "nir", "expected_classifiers": ["pii.nir"], "name_contains_value": False,
         "negative_control": False, "values": []},
    ]
}


class FindingsMySqlTest(Base):
    ROWS = [
        {"database_name": "support", "schema_name": None, "object_name": "tickets",
         "field_name": "requester_email", "classifier": "pii.email"},
        {"database_name": "support", "schema_name": None, "object_name": "tickets",
         "field_name": "body", "classifier": "pii.card_number"},
        {"database_name": "support", "schema_name": None, "object_name": "tickets",
         "field_name": "body", "classifier": "pii.iban"},
    ]

    def check(self, rows: list[dict], *flags: str) -> tuple[int, str]:
        gt = self.write("gt-my.json", json.dumps(GT_MY))
        path = self.write("rows.json", json.dumps(rows))
        return run(["findings", "--ground-truth", gt, "--engine", "mariadb", *flags, path])

    def test_expected_classifiers_of_the_engine_only(self) -> None:
        self.assertEqual(i2_check.expected_classifiers(GT_MY, "mariadb"),
                         ["pii.card_number", "pii.email", "pii.iban"])
        rc, out = self.check(self.ROWS, "--require-expected-classifiers",
                             "--forbid-negative-controls")
        self.assertEqual(rc, 0, out)
        self.assertIn("found: 2/2", out)

    def test_missing_expected_classifier(self) -> None:
        rc, out = self.check(self.ROWS[:2], "--require-expected-classifiers")
        self.assertEqual(rc, 1, out)
        self.assertIn("expected classifier pii.iban has no finding", out)
        # Without the flag, nothing is required.
        rc, out = self.check(self.ROWS[:2])
        self.assertEqual(rc, 0, out)

    def test_engine_without_expected_classifier(self) -> None:
        gt = self.write("gt-empty.json", json.dumps({"locations": GT_MY["locations"][2:4]}))
        path = self.write("rows.json", json.dumps(self.ROWS))
        rc, out = run(["findings", "--ground-truth", gt, "--engine", "mariadb",
                       "--require-expected-classifiers", path])
        self.assertEqual(rc, 1, out)

    def test_negative_control_finding(self) -> None:
        rows = self.ROWS + [{"database_name": "support", "schema_name": None,
                             "object_name": "tickets", "field_name": "status",
                             "classifier": "pii.person_name"}]
        rc, out = self.check(rows, "--forbid-negative-controls")
        self.assertEqual(rc, 1, out)
        self.assertIn("negative control has finding(s): pii.person_name", out)
        rc, out = self.check(rows)
        self.assertEqual(rc, 0, out)

    def test_negative_control_under_the_normalized_name(self) -> None:
        rows = self.ROWS + [{"database_name": "support", "schema_name": None, "object_name": "*",
                             "field_name": "reason", "classifier": "pii.email"}]
        rc, out = self.check(rows, "--forbid-negative-controls")
        self.assertEqual(rc, 1, out)
        self.assertIn("under the normalized name '*'", out)

    def test_raw_or_partially_normalized_value_bearing_name(self) -> None:
        for name in ("escalations_jean.richard@example.com", "x_JEAN.RICHARD@example.com_y"):
            with self.subTest(name=name):
                rows = self.ROWS + [{"database_name": "support", "schema_name": None,
                                     "object_name": name, "field_name": "reason",
                                     "classifier": "pii.email"}]
                rc, out = self.check(rows)
                self.assertEqual(rc, 1, out)
                self.assertIn("stores the raw value-bearing name", out)
                self.assertNotIn("richard", out.lower())


def page(rows: list[tuple[str, list[str] | str]]) -> str:
    """A findings page shaped like console/src/components/console/findings-table.tsx."""
    head = ("<table><thead><tr><th>Agent</th><th>Target</th><th>Classifier</th></tr></thead>"
            "<tbody><tr><td>e2e</td><td>pg-e2e</td><td>pii.email</td></tr></tbody></table>")
    cols = ["Target", "Location", "Classifier", "Confidence", "Matched / sampled", "Est. rows",
            "Masked samples", "Fingerprints", "Last seen", ""]
    out = [head, "<table><thead><tr>", "".join(f"<th>{c}</th>" for c in cols), "</tr></thead><tbody>"]
    for cls, samples in rows:
        if isinstance(samples, str):
            cell = f'<span class="text-muted-foreground">{samples}</span>'
        else:
            cell = '<ul class="font-mono text-xs">' + "".join(f"<li>{x}</li>" for x in samples) + "</ul>"
        out.append(f"<tr><td>e2e / pg-e2e<div>postgres</div></td><td>shop / crm / t / c</td>"
                   f"<td>{cls}<!-- --></td><td>0.90</td><td>9 / 10</td><td>10</td><td>{cell}</td>"
                   f"<td>3</td><td>1 min</td><td><button>Mark</button></td></tr>")
    out.append("</tbody></table>")
    return "".join(out)


class PageTest(Base):
    GOOD = [
        ("pii.card_number", ["**** **** **** 4578", "**** **** **** 0484"]),
        ("pii.iban", ["DE** **** **** **** **28 82"]),
        ("pii.phone", ["+33 * ** ** ** 79", "+1 *** *** **25", "** ** ** ** 59"]),
        ("pii.nir", ["* ** ** ** *** *** **"]),
        ("pii.email", ["m***@e***.com"]),
        ("pii.postal_address", "none"),
    ]

    def check(self, rows, expected: int | None, min_sampled: int) -> tuple[int, str]:
        path = self.write("findings.html", page(rows))
        argv = ["page", "--min-sampled-rows", str(min_sampled)]
        if expected is not None:
            argv += ["--expected-rows", str(expected)]
        return run(argv + [path])

    def test_ok(self) -> None:
        rc, out = self.check(self.GOOD, 6, 5)
        self.assertEqual(rc, 0, out)
        self.assertIn("6 row(s), 5 with rendered samples, 8 sample(s)", out)

    def test_partial_masking_regression(self) -> None:
        # 8 of 16 card digits kept: no full value, so the value search cannot see it.
        planted = "4111 1101 **** 4578"
        rows = self.GOOD + [("pii.card_number", [planted])]
        rc, out = self.check(rows, 7, 6)
        self.assertEqual(rc, 1, out)
        self.assertIn("1 masked sample(s) of pii.card_number keep more than 4 digits", out)
        self.assertNotIn("4111", out)
        rc, out = self.check(self.GOOD + [("pii.phone", ["+33 6 39 ** ** 79"])], 7, 6)
        self.assertEqual(rc, 1, out)

    def test_unavailable_samples(self) -> None:
        rc, out = self.check(self.GOOD + [("pii.iban", "unavailable")], 7, 5)
        self.assertEqual(rc, 1, out)
        self.assertIn("'unavailable'", out)

    def test_vacuous_page(self) -> None:
        rc, out = self.check(self.GOOD, 7, 5)  # a row missing (e.g. listing cap)
        self.assertEqual(rc, 1, out)
        rc, out = self.check(self.GOOD, 6, 6)  # fewer rows with samples than stored
        self.assertEqual(rc, 1, out)
        rc, out = self.check([("pii.email", "none")], 1, 0)  # nothing to scan
        self.assertEqual(rc, 1, out)

    def test_not_a_findings_page(self) -> None:
        rc, out = run(["page", "--min-sampled-rows", "1", self.write("x.html", "<p>login</p>")])
        self.assertEqual(rc, 2, out)


if __name__ == "__main__":
    unittest.main()


class NeedleFilterTest(Base):
    def test_scan_restricted_to_the_given_needles(self) -> None:
        # Another ground-truth value is present, but only L0.v0 (and its local part) is searched.
        path = self.write("log.txt", "x LEFEVRE y manon.bernard z")
        rc, out = self.scan(path, extra=["--needle", "L0.v0"])
        self.assertEqual(rc, 1, out)
        self.assertIn("LEAK L0.v0.local ", out)
        self.assertNotIn("L1.v0", out)
        self.assertIn("2 needles from 1 locations", out)
        rc, out = self.scan(self.write("clean.txt", "x LEFEVRE y"), extra=["--needle", "L0.v0"])
        self.assertEqual(rc, 0, out)

    def test_unknown_or_excluded_needle_is_a_usage_error(self) -> None:
        path = self.write("log.txt", "x")
        for bad in ("L99.v0", "L1.v4"):  # L1.v4 = "Ava": excluded as too short
            rc, out = self.scan(path, extra=["--needle", bad])
            self.assertEqual(rc, 2, out)
            self.assertIn(bad, out)


class AuditTest(Base):
    EVENTS = [
        {"db_user": "e2e_exporter", "action": "read", "source": "pgaudit", "rows": 150,
         "objects": [{"database": "shop", "schema": "crm", "object": "customers"}],
         "signals": ["signature.pg_dump", "shape.full_table_copy"]},
        {"db_user": "e2e_exporter", "action": "read", "source": "pgaudit", "rows": 1,
         "objects": [{"database": "shop", "schema": "crm", "object": "*"}],
         "signals": ["signature.pg_dump"]},
        {"db_user": "e2e_analyst", "action": "read", "source": "pgaudit", "rows": 1,
         "objects": [{"database": "shop", "schema": "crm", "object": "customers"}], "signals": []},
    ]
    INCIDENTS = [
        {"policy_name": "e2e pg_dump", "principal": "e2e_exporter", "event_signals": ["signature.pg_dump"]},
        {"policy_name": "e2e reads", "principal": "e2e_analyst", "event_signals": []},
    ]

    def check(self, events: list[dict], incidents: list[dict], extra: list[str] | None = None) -> tuple[int, str]:
        ev = self.write("events.json", json.dumps(events))
        inc = self.write("incidents.json", json.dumps(incidents))
        return run(["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                    "--agent-account", "databastion_agent", "--events", ev, "--incidents", inc,
                    *(extra or [])])

    REQUIRED = ["--require-event", "e2e_exporter:signature.pg_dump", "--require-event", "e2e_analyst",
                "--require-incident", "e2e pg_dump:e2e_exporter:signature.pg_dump",
                "--require-incident", "e2e reads:e2e_analyst"]

    def test_ok(self) -> None:
        rc, out = self.check(self.EVENTS, self.INCIDENTS, self.REQUIRED)
        self.assertEqual(rc, 0, out)
        self.assertIn("event objects named '*' (masked or unknown): 1", out)

    def test_empty(self) -> None:
        rc, out = self.check([], [])
        self.assertEqual(rc, 1, out)
        self.assertIn("no access event was stored", out)
        self.assertIn("no incident was opened", out)

    def test_agent_own_events_and_incidents(self) -> None:
        own = {"db_user": "databastion_agent", "action": "read", "source": "pgaudit", "rows": 100,
               "objects": [{"database": "shop", "schema": "crm", "object": "customers"}], "signals": []}
        rc, out = self.check(self.EVENTS + [own], self.INCIDENTS)
        self.assertEqual(rc, 1, out)
        self.assertIn("1 access event(s) of the agent's own account", out)
        rc, out = self.check(self.EVENTS, self.INCIDENTS + [
            {"policy_name": "e2e reads", "principal": "databastion_agent", "event_signals": []}])
        self.assertEqual(rc, 1, out)
        self.assertIn("1 incident(s) attributed to the agent's own account", out)

    def test_missing_requirements(self) -> None:
        rc, out = self.check(self.EVENTS[2:], self.INCIDENTS[1:], self.REQUIRED)
        self.assertEqual(rc, 1, out)
        self.assertIn("no access event of principal 'e2e_exporter' with signature.pg_dump", out)
        self.assertIn("no incident of policy 'e2e pg_dump', principal 'e2e_exporter', signal signature.pg_dump", out)
        # The signal must be on the incident, not only somewhere else.
        inc = [{"policy_name": "e2e pg_dump", "principal": "e2e_exporter", "event_signals": []}]
        rc, out = self.check(self.EVENTS, inc, ["--require-incident", "e2e pg_dump:e2e_exporter:signature.pg_dump"])
        self.assertEqual(rc, 1, out)

    def test_raw_value_bearing_name_in_an_event_object(self) -> None:
        for obj in ({"database": "shop", "schema": "crm", "object": "export_client_0639988384"},
                    {"database": "shop", "schema": "crm", "object": "export_*_0639988384"},
                    {"database": "shop", "schema": "crm", "object": "archive_lucas_*"}):
            ev = [{"db_user": "e2e_exporter", "action": "read", "source": "pgaudit",
                   "objects": [obj], "signals": []}]
            rc, out = self.check(self.EVENTS + ev, self.INCIDENTS)
            self.assertEqual(rc, 1, out)
            self.assertIn("hold the raw value-bearing name", out)
            self.assertNotIn("0639988384", out)
            self.assertNotIn("lucas", out)

    def test_not_an_array(self) -> None:
        ev = self.write("events.json", json.dumps({"events": []}))
        inc = self.write("incidents.json", "[]")
        rc, out = run(["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                       "--agent-account", "a", "--events", ev, "--incidents", inc])
        self.assertEqual(rc, 2, out)
