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
SEED_MONGO = os.path.join(REPO, "dev", "seed", "out", "mongo.json")
SEED_LDAP = os.path.join(REPO, "dev", "seed", "out", "openldap.ldif")

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

    @unittest.skipUnless(os.path.exists(SEED_MONGO) and os.path.exists(SEED_LDAP),
                         "committed seeds not found")
    def test_every_mongodb_and_openldap_value_is_visible_in_the_committed_seeds(self) -> None:
        # The LDIF seed base64-encodes its non-ASCII values: the `ldif` view decodes them.
        for engine, seed in (("mongodb", SEED_MONGO), ("openldap", SEED_LDAP)):
            with self.subTest(engine=engine):
                rc, out = run(["coverage", "--ground-truth", GROUND_TRUTH, "--engine", engine, seed])
                self.assertEqual(rc, 0, out)


class LdifViewTest(Base):
    def test_base64_and_folded_values_are_decoded(self) -> None:
        # "Lefèvre" base64-encoded, and an e-mail folded over two lines.
        b64 = "TGVmw6h2cmU="
        for text in (f"dn: uid=x,dc=example,dc=org\nsn:: {b64}\n",
                     "dn: uid=x,dc=example,dc=org\nreqFilter: (mail=manon.ber\n nard@example.com)\n"):
            with self.subTest(text=text):
                rc, out = self.scan(self.write("accesslog.ldif", text))
                self.assertEqual(rc, 1, out)
                self.assertIn("view=ldif", out)

    def test_only_for_ldif_and_bad_base64_is_kept(self) -> None:
        # Not LDIF (no dn: line): no join, no decoding; bad base64 does not fail the scan.
        rc, out = self.scan(self.write("a.log", "sn:: TGVmw6h2cmU=\nmanon.ber\n nard@example.com\n"))
        self.assertEqual(rc, 0, out)
        rc, out = self.scan(self.write("b.ldif", "dn: x=y\nsn:: !!!notbase64\n"))
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



class SecretScanTest(Base):
    """`scan --secret-file` / `--literal-file`: ad-hoc secrets (DCL passwords, unkeyed hashes)."""

    SECRET = "4f9c2e7a1b3d5f60a8c4e2b9d7f1a3c5e6b8d0f2a4c6e8b1"  # 48 hex, like rand_hex 24

    def secret(self, name: str, value: str) -> str:
        path = os.path.join(self.tmp.name, "secrets", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(value + "\n")  # as run.sh writes them (printf '%s\\n')
        return path

    def scan_secret(self, text: str, *extra: str, name: str = "dcl_password_1") -> tuple[int, str]:
        return run(["scan", "--secret-file", self.secret(name, self.SECRET), *extra,
                    self.write("out.txt", text)])

    def test_forms_are_detected_and_never_printed(self) -> None:
        import base64
        s = self.SECRET
        forms = {
            "plain": f"x {s} y",
            "upper case": f"x {s.upper()} y",
            "16-character window": f"prefix{s[20:36]}suffix",
            "json escapes": "".join(f"\\u{ord(c):04x}" for c in s),
            # Every character escaped / split: no 16-character window in the raw text.
            "url escapes": "".join(f"%{ord(c):02X}" for c in s),
            "hex": s.encode().hex(),
        }
        for o in range(3):
            for p in range(3):
                raw = b"k" * p + s.encode() + b"z" * o
                forms[f"base64, {p} byte(s) before"] = base64.b64encode(raw).decode()
                forms[f"base64url, {p} byte(s) before"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        for label, text in forms.items():
            with self.subTest(label):
                rc, out = self.scan_secret(text)
                self.assertEqual(rc, 1, out)
                self.assertIn("LEAK S.dcl_password_1", out)
                self.assertIn("(secret) S dcl_password_1 ", out)
                self.assertNotIn(s, out)
                self.assertNotIn(s[20:36], out)

    def test_whole_secret_has_its_own_id(self) -> None:
        rc, out = self.scan_secret(f"x {self.SECRET} y")
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"(?m)^LEAK S\.dcl_password_1 \(secret\)")
        rc, out = self.scan_secret(f"x {self.SECRET[:30]} y")
        self.assertEqual(rc, 1, out)
        self.assertNotRegex(out, r"(?m)^LEAK S\.dcl_password_1 ")  # a window only

    def test_clean_text_and_short_fragments(self) -> None:
        rc, out = self.scan_secret(CLEAN + "\n" + self.SECRET[:15] + " " + self.SECRET[-15:])
        self.assertEqual(rc, 0, out)
        self.assertIn("no secret in clear text", out)

    def test_short_secret_is_a_usage_error(self) -> None:
        rc, out = run(["scan", "--secret-file", self.secret("short", "0123456789abcde"),
                       self.write("out.txt", "x")])
        self.assertEqual(rc, 2, out)
        self.assertIn("short: shorter than 16 characters", out)
        self.assertNotIn("0123456789abcde", out)

    def test_literal_file_is_searched_whole_only(self) -> None:
        lit = self.secret("dn_sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        rc, out = run(["scan", "--literal-file", lit,
                       self.write("out.txt", "x 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08")])
        self.assertEqual(rc, 1, out)
        self.assertIn("LEAK S.dn_sha256 (secret) S dn_sha256 ", out)
        rc, out = run(["scan", "--literal-file", lit, self.write("out.txt", "x 9f86d081884c7d659a2feaa0c55ad015")])
        self.assertEqual(rc, 0, out)

    def test_with_the_ground_truth_and_usage_errors(self) -> None:
        rc, out = self.scan(self.write("both.txt", f"manon.bernard@example.com {self.SECRET}"),
                            extra=["--secret-file", self.secret("dcl_password_2", self.SECRET)])
        self.assertEqual(rc, 1, out)
        self.assertIn("LEAK L0.v0 ", out)
        self.assertIn("LEAK S.dcl_password_2 ", out)
        rc, out = run(["scan", self.write("x.txt", "x")])
        self.assertEqual(rc, 2, out)
        rc, out = run(["scan", "--needle", "L0.v0", "--secret-file", self.secret("a", self.SECRET),
                       self.write("x.txt", "x")])
        self.assertEqual(rc, 2, out)


# MongoDB and OpenLDAP shapes: the value-bearing part is the field (dynamic keys) or the container.
GT_NOSQL = {
    "locations": [
        {"engine": "mongodb", "database": "app", "container": None, "object": "users",
         "field": "email", "expected_classifiers": ["pii.email"], "name_contains_value": False,
         "negative_control": False, "values": ["a.b@example.com"]},
        {"engine": "mongodb", "database": "app", "container": None, "object": "address_books",
         "field": "contacts.<email>.phone", "expected_classifiers": ["pii.phone"],
         "expected_normalized_name": "contacts.*.phone", "name_contains_value": True,
         "name_value_classifiers": ["pii.email"], "name_values": ["mia.nielsen@example.net"],
         "negative_control": False, "values": ["+33 6 39 98 78 79"]},
        {"engine": "mongodb", "database": "app", "container": None, "object": "daily_stats",
         "field": "hourly.<hour>", "expected_classifiers": [], "expected_normalized_name": "hourly.*",
         "name_contains_value": False, "negative_control": True},
        {"engine": "openldap", "database": "dc=example,dc=org",
         "container": "ou=Oliver O'Connor,ou=teams,dc=example,dc=org", "object": "inetOrgPerson",
         "field": "mail", "expected_classifiers": ["pii.email"],
         "expected_normalized_name": "ou=*,ou=teams,dc=example,dc=org", "name_contains_value": True,
         "name_value_classifiers": ["pii.person_name"], "name_values": ["Oliver O'Connor"],
         "negative_control": False, "values": ["o.oconnor@example.com"]},
    ]
}


class FindingsNoSqlTest(Base):
    MONGO = [
        {"database_name": "app", "schema_name": None, "object_name": "users", "field_name": "email",
         "classifier": "pii.email"},
        {"database_name": "app", "schema_name": None, "object_name": "address_books",
         "field_name": "contacts.*.phone", "classifier": "pii.phone"},
    ]
    LDAP = [
        {"database_name": "dc=example,dc=org", "schema_name": "ou=*,ou=teams,dc=example,dc=org",
         "object_name": "inetOrgPerson", "field_name": "mail", "classifier": "pii.email"},
    ]

    def check(self, engine: str, rows: list[dict]) -> tuple[int, str]:
        gt = self.write("gt-nosql.json", json.dumps(GT_NOSQL))
        path = self.write("rows.json", json.dumps(rows))
        return run(["findings", "--ground-truth", gt, "--engine", engine,
                    "--require-expected-classifiers", "--forbid-negative-controls", path])

    def test_value_part(self) -> None:
        self.assertEqual([i2_check.value_part(loc) for loc in GT_NOSQL["locations"]],
                         ["object", "field", "field", "container"])

    def test_ok(self) -> None:
        rc, out = self.check("mongodb", self.MONGO)
        self.assertEqual(rc, 0, out)
        self.assertIn("expected normalized name 'contacts.*.phone'", out)
        rc, out = self.check("openldap", self.LDAP)
        self.assertEqual(rc, 0, out)
        self.assertIn("expected normalized name 'ou=*,ou=teams,dc=example,dc=org'", out)

    def test_field_not_normalized_or_raw(self) -> None:
        rc, out = self.check("mongodb", [self.MONGO[0], dict(self.MONGO[1], field_name="contacts.phone")])
        self.assertEqual(rc, 1, out)
        self.assertIn("no finding stored under the expected normalized name", out)
        rc, out = self.check("mongodb", self.MONGO + [
            dict(self.MONGO[1], field_name="contacts.mia.nielsen@example.net.phone")])
        self.assertEqual(rc, 1, out)
        self.assertIn("stores the raw value-bearing name", out)
        self.assertNotIn("nielsen", out)

    def test_placeholder_negative_control(self) -> None:
        rc, out = self.check("mongodb", self.MONGO + [
            {"database_name": "app", "schema_name": None, "object_name": "daily_stats",
             "field_name": "hourly.*", "classifier": "pii.phone"}])
        self.assertEqual(rc, 1, out)
        self.assertIn("negative control has finding(s): pii.phone", out)

    def test_raw_container(self) -> None:
        rc, out = self.check("openldap", self.LDAP + [
            dict(self.LDAP[0], schema_name="ou=oliver o'connor,ou=teams,dc=example,dc=org")])
        self.assertEqual(rc, 1, out)
        self.assertIn("stores the raw value-bearing name", out)
        self.assertNotIn("oliver", out.lower())


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


    def test_required_action(self) -> None:
        dcl = {"db_user": "e2e_admin", "action": "dcl", "source": "pgaudit", "objects": [],
               "signals": [], "aggregated_count": 2}
        rc, out = self.check(self.EVENTS + [dcl], self.INCIDENTS, ["--require-action", "e2e_admin:dcl"])
        self.assertEqual(rc, 0, out)
        self.assertIn("1 event(s) (2 statement(s)) of principal 'e2e_admin' with action dcl", out)
        rc, out = self.check(self.EVENTS, self.INCIDENTS, ["--require-action", "e2e_admin:dcl"])
        self.assertEqual(rc, 1, out)
        rc, out = self.check(self.EVENTS, self.INCIDENTS, ["--require-action", "e2e_admin"])
        self.assertEqual(rc, 1, out)
        self.assertIn("bad --require-action", out)


class AuditFingerprintTest(Base):
    FP1, FP2 = "a" * 64, "b" * 64
    DN = "cn=manon bernard,ou=services,dc=example,dc=org"

    def events(self) -> list[dict]:
        obj = [{"database": "dc=example,dc=org", "schema": "ou=people,dc=example,dc=org", "object": "*"}]
        return [
            {"db_user": None, "db_user_fingerprint": self.FP1, "action": "read", "objects": obj,
             "signals": ["shape.bulk_search"], "source": "openldap_accesslog"},
            {"db_user": None, "db_user_fingerprint": self.FP1, "action": "connect", "objects": [],
             "signals": [], "source": "openldap_accesslog"},
            {"db_user": None, "db_user_fingerprint": self.FP2, "action": "read", "objects": obj,
             "signals": [], "source": "openldap_accesslog"},
        ]

    INCIDENTS = [
        {"policy_name": "e2e dump signature", "principal": "a" * 64, "event_signals": ["shape.bulk_search"]},
        {"policy_name": "e2e reads", "principal": "a" * 64, "event_signals": ["shape.bulk_search"]},
    ]
    REQUIRED = ["--fingerprinted-only", "--min-fingerprints", "2",
                "--require-event", "@fingerprint:shape.bulk_search",
                "--require-incident", "e2e dump signature:@fingerprint:shape.bulk_search",
                "--require-incident", "e2e reads:@fingerprint"]

    def check(self, events: list[dict], incidents: list[dict]) -> tuple[int, str]:
        ev = self.write("events.json", json.dumps(events))
        inc = self.write("incidents.json", json.dumps(incidents))
        return run(["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                    "--agent-account", "cn=databastion,ou=services,dc=example,dc=org",
                    "--events", ev, "--incidents", inc, *self.REQUIRED])

    def test_ok(self) -> None:
        rc, out = self.check(self.events(), self.INCIDENTS)
        self.assertEqual(rc, 0, out)
        self.assertIn("every principal is a fingerprint", out)
        self.assertIn("2 distinct fingerprinted principal(s) read", out)

    def test_principal_in_clear_is_counted_never_printed(self) -> None:
        ev = self.events()
        ev[2] = dict(ev[2], db_user=self.DN, db_user_fingerprint=None)
        rc, out = self.check(ev, self.INCIDENTS + [
            {"policy_name": "e2e reads", "principal": self.DN, "event_signals": []}])
        self.assertEqual(rc, 1, out)
        self.assertIn("1 access event(s) carry a principal that is not a fingerprint", out)
        self.assertIn("1 incident(s) name a principal that is not a fingerprint", out)
        self.assertIn("1 distinct fingerprinted principal(s) read, at least 2 expected", out)
        self.assertNotIn("manon", out)

    def test_fingerprint_requirements(self) -> None:
        ev = [e for e in self.events() if "shape.bulk_search" not in e["signals"]]
        inc = [dict(i, principal="not-a-fingerprint") for i in self.INCIDENTS]
        rc, out = self.check(ev, inc)
        self.assertEqual(rc, 1, out)
        self.assertIn("no access event of principal '@fingerprint' with shape.bulk_search", out)
        self.assertIn("no incident of policy 'e2e reads', principal '@fingerprint'", out)


    def test_at_most_the_test_clients_fingerprints(self) -> None:
        extra = ["--max-fingerprints", "2"]
        rc, out = run(["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                       "--agent-account", "cn=databastion,ou=services,dc=example,dc=org",
                       "--events", self.write("events.json", json.dumps(self.events())),
                       "--incidents", self.write("incidents.json", json.dumps(self.INCIDENTS)),
                       *self.REQUIRED, *extra])
        self.assertEqual(rc, 0, out)
        self.assertIn("2 distinct fingerprinted principal(s) over the events and incidents", out)
        # A third fingerprint (e.g. the agent's own read, not filtered), even on a connect event.
        ev = self.events() + [{"db_user": None, "db_user_fingerprint": "c" * 64, "action": "connect",
                               "objects": [], "signals": [], "source": "openldap_accesslog"}]
        rc, out = run(["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                       "--agent-account", "cn=databastion,ou=services,dc=example,dc=org",
                       "--events", self.write("events.json", json.dumps(ev)),
                       "--incidents", self.write("incidents.json", json.dumps(self.INCIDENTS)),
                       *self.REQUIRED, *extra])
        self.assertEqual(rc, 1, out)
        self.assertIn("3 distinct fingerprinted principal(s) over the events and incidents", out)
        self.assertNotIn("c" * 64, out)

    def test_principal_without_the_dump_signal(self) -> None:
        analyst = "@fingerprint!shape.bulk_search"
        req = ["--require-event", analyst, "--require-incident", f"e2e reads:{analyst}"]
        # The reads incident is the exporter's (FP1, which has a bulk search): not the analyst's.
        rc, out = self.check(self.events(), self.INCIDENTS)
        self.assertEqual(rc, 0, out)
        ev = self.write("events.json", json.dumps(self.events()))
        base = ["audit", "--ground-truth", self.gt, "--engine", "postgresql",
                "--agent-account", "cn=databastion,ou=services,dc=example,dc=org", "--events", ev]
        rc, out = run([*base, "--incidents", self.write("incidents.json", json.dumps(self.INCIDENTS)),
                       *req])
        self.assertEqual(rc, 1, out)
        self.assertIn(f"no incident of policy 'e2e reads', principal '{analyst}'", out)
        self.assertIn(f"1 event(s) of principal '{analyst}'", out)
        inc = self.INCIDENTS + [{"policy_name": "e2e reads", "principal": self.FP2, "event_signals": []}]
        rc, out = run([*base, "--incidents", self.write("incidents.json", json.dumps(inc)), *req])
        self.assertEqual(rc, 0, out)
        # Only the exporter left: no principal without the signal.
        only = self.write("events.json", json.dumps(self.events()[:2]))
        rc, out = run([*base[:-1], only, "--incidents", self.write("incidents.json", json.dumps(inc)),
                       *req])
        self.assertEqual(rc, 1, out)
        self.assertIn(f"no access event of principal '{analyst}'", out)


class HtmlTextViewTest(Base):
    def test_value_split_by_react_comments_and_tags(self) -> None:
        # React text nodes separated by <!-- -->, a value across inline tags, entities.
        for text in ("<td>manon.bernard<!-- -->@example.com</td>",
                     "<td>Lef<!-- -->&#xE8;vre</td>",
                     "<td><span>manon.bernard</span>@<b>example.com</b></td>"):
            path = self.write("page.html", text)
            rc, out = self.scan(path)
            self.assertEqual(rc, 1, (text, out))
            self.assertIn("view=html-text", out)

    def test_tags_do_not_join_adjacent_cells(self) -> None:
        path = self.write("page.html", "<td>Lef</td><td>evre</td>")
        rc, out = self.scan(path)
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
