"""Unit tests of e2e/i2_check.py (run: python3 -m unittest discover -s e2e -p 'test_*.py')."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import unicodedata

import i2_check

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GROUND_TRUTH = os.path.join(REPO, "dev", "ground-truth.json")
SEED_PG = os.path.join(REPO, "dev", "seed", "out", "postgres.sql")

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
    "masked: ** ** ** ** 59  +33 * ** ** ** 79  +44 **** ***404  +1 *** *** 0125",
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
}


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
        self.assertEqual(i2_check.phone_variants("01 99 00 27 59"), {"0199002759", "33199002759"})
        self.assertEqual(i2_check.phone_variants("+33 6 39 98 78 79"), {"33639987879", "0639987879"})
        self.assertEqual(i2_check.phone_variants("+1 202 555 0125"), {"12025550125", "2025550125"})


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


if __name__ == "__main__":
    unittest.main()
