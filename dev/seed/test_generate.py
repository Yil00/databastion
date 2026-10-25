"""Tests of the dev seed generator. Run with `make test-dev` (python3 -m unittest discover -s dev/seed)."""

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate as g  # noqa: E402

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
ALLOWED_DOMAINS = set(g.EMAIL_DOMAINS)


def digest(files: dict) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode() + b"\0" + files[name].encode() + b"\0")
    return h.hexdigest()


class Validators(unittest.TestCase):
    def test_luhn_known(self):
        self.assertTrue(g.luhn_valid("4111 1111 1111 1111"))
        self.assertTrue(g.luhn_valid("5555555555554444"))
        self.assertFalse(g.luhn_valid("4111111111111112"))
        self.assertFalse(g.luhn_valid("not a number"))

    def test_iban_known(self):
        # ISO 13616 / ECBS reference examples.
        self.assertTrue(g.iban_valid("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(g.iban_valid("FR14 2004 1010 0505 0001 3M02 606"))
        self.assertFalse(g.iban_valid("GB82 WEST 1234 5698 7654 33"))

    def test_nir_key_known(self):
        # Example commonly used in the NIR documentation: 2 55 08 14 168 025, key 38.
        self.assertEqual(g.nir_key("2550814168025"), "38")
        self.assertTrue(g.nir_valid("2 55 08 14 168 025 38"))
        self.assertFalse(g.nir_valid("2 55 08 14 168 025 39"))

    def test_generated_values_are_valid(self):
        f = g.Fake(1)
        for _ in range(500):
            self.assertTrue(g.luhn_valid(f.card()[1]))
            iban = f.fr_iban()
            self.assertTrue(g.iban_valid(iban), iban)
            self.assertTrue(iban.replace(" ", "")[4:6] == "99", "fictitious FR bank code")
            self.assertTrue(g.iban_valid(f.de_iban()))
            self.assertTrue(g.nir_valid(f.nir(2, 1987, 6)))
            self.assertFalse(g.luhn_valid(f.not_luhn()))
            card = f.card()[1].replace(" ", "")
            self.assertTrue(card.startswith(("411111", "555555")))
            access, secret = f.aws_key_pair()
            self.assertIn("EXAMPLE", access)
            self.assertIn("EXAMPLE", secret)
            self.assertTrue(f.fr_phone().replace(" ", "")[:6] in
                            {p.replace(" ", "") for p in g.FR_FICTION_PREFIXES})


class Outputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = g.build()
        cls.truth = json.loads(cls.files["ground-truth.json"])

    def test_deterministic(self):
        self.assertEqual(digest(self.files), digest(g.build()))
        self.assertNotEqual(digest(self.files), digest(g.build(g.SEED + 1)))

    def test_committed_outputs_up_to_date(self):
        for rel, content in self.files.items():
            path = g.DEV_DIR / rel
            self.assertTrue(path.exists(), f"{rel} missing: run `make seed`")
            self.assertEqual(path.read_text(encoding="utf-8"), content, f"{rel} stale: run `make seed`")

    def test_only_reserved_email_domains(self):
        for name, content in self.files.items():
            for m in EMAIL_RE.finditer(content):
                self.assertIn(m.group(1).lower(), ALLOWED_DOMAINS, f"{name}: {m.group(0)}")

    def test_total_size_bounded(self):
        self.assertLess(sum(len(c.encode()) for c in self.files.values()), 2 * 1024 * 1024)

    def test_ground_truth_shape(self):
        locs = self.truth["locations"]
        engines = {loc["engine"] for loc in locs}
        self.assertEqual(engines, {"postgresql", "mysql", "mariadb", "mongodb", "openldap", "cas",
                                   "sqlserver", "valkey", "redis", "sqlite"})
        for loc in locs:
            for key in ("engine", "database", "object", "expected_classifiers", "negative_control",
                        "name_contains_value"):
                self.assertIn(key, loc)
            if loc["negative_control"]:
                self.assertEqual(loc["expected_classifiers"], [])
            if loc["expected_classifiers"]:
                self.assertTrue(loc.get("values"), loc)
            if loc["name_contains_value"]:
                self.assertTrue(loc["name_values"] and loc["name_value_classifiers"], loc)
            if loc.get("never_sampled"):
                # A credential: no classifier, not a negative control, its values listed (I2).
                self.assertEqual(loc["expected_classifiers"], [], loc["field"])
                self.assertFalse(loc["negative_control"])
                self.assertTrue(loc.get("values"), loc["field"])
        self.assertTrue(any(loc["negative_control"] for loc in locs))

    def test_value_bearing_names_present(self):
        vb = [loc for loc in self.truth["locations"] if loc["name_contains_value"]]
        kinds = {(loc["engine"], loc["name_value_classifiers"][0]) for loc in vb}
        self.assertIn(("mongodb", "pii.email"), kinds, "Mongo dynamic keys that are e-mails")
        self.assertIn(("mongodb", "pii.phone"), kinds, "Mongo digit-only keys that are phone numbers")
        self.assertIn(("openldap", "pii.person_name"), kinds, "LDAP ou= named after a person")
        self.assertTrue(any(loc["engine"] in ("postgresql", "mysql", "mariadb") for loc in vb),
                        "SQL table name containing a value")
        self.assertTrue(any(v.isdigit() for loc in vb for v in loc["name_values"]), "digit-only names")
        # Every value-bearing name really is in the seed files.
        seeds = "".join(v for k, v in self.files.items() if k.startswith("seed/out/"))
        for loc in vb:
            for v in loc["name_values"]:
                if loc["engine"] == "openldap":
                    continue  # may be base64-encoded in LDIF
                self.assertIn(v, seeds)

    def test_positive_values_are_in_seed_files(self):
        seed_file = {"postgresql": "postgres.sql", "mysql": "mysql.sql", "mariadb": "mariadb.sql",
                     "mongodb": "mongo.json", "sqlserver": "sqlserver.sql", "valkey": "redis.txt",
                     "redis": "redis.txt"}
        for loc in self.truth["locations"]:
            if loc["engine"] == "sqlite":
                content = self.files[f"seed/out/sqlite-{loc['file'][:-3]}.sql"]
            elif loc["engine"] not in seed_file:
                continue  # LDIF: non-ASCII values are base64-encoded
            else:
                content = self.files["seed/out/" + seed_file[loc["engine"]]]
            for v in loc.get("values", []):
                if loc["engine"] == "mongodb":
                    needle = v
                elif loc["engine"] in g.REDIS_ENGINES:
                    needle = v.replace("\\", "\\\\").replace('"', '\\"')
                else:
                    needle = v.replace("'", "''")
                if needle not in content:
                    self.fail(f"{loc['engine']} {loc['object']}.{loc['field']}: value not in seed file")

class SqlServerAndRedis(unittest.TestCase):
    """The opt-in SQL Server, Valkey and Redis seeds (ADR-0051 decision 9, ADR-0052 decision 13)."""

    @classmethod
    def setUpClass(cls):
        cls.files = g.build()
        cls.truth = json.loads(cls.files["ground-truth.json"])

    def test_sqlserver_two_schemas_and_fixtures(self):
        locs = [loc for loc in self.truth["locations"] if loc["engine"] == "sqlserver"]
        pii = {loc["container"] for loc in locs if loc["expected_classifiers"]}
        self.assertEqual(pii, {"crm", "finance"})
        sql = self.files["seed/out/sqlserver.sql"]
        for fixture in ("MASKED WITH", "ENCRYPTED WITH", "SYSTEM_VERSIONING = ON", "CREATE SECURITY POLICY",
                        "AS finance.fn_iban_prefix", "CREATE SYNONYM", "archive.invalid", "cas.cas_tickets"):
            self.assertIn(fixture, sql)
        # No batch of the seed may exceed SQL Server's 1000-row VALUES limit.
        self.assertTrue(all(chunk.count("\n  (") < 1000 for chunk in sql.split("INSERT INTO")))

    def test_redis_types_and_names(self):
        for engine in g.REDIS_ENGINES:
            locs = [loc for loc in self.truth["locations"] if loc["engine"] == engine]
            self.assertEqual({loc["container"] for loc in locs},
                             {"string", "hash", "set", "zset", "list", "stream"})
            named = [v for loc in locs if loc["name_contains_value"] for v in loc["name_values"]]
            self.assertTrue(any("@" in v for v in named) and any(v.isdigit() for v in named))
        text = self.files["seed/out/redis.txt"]
        commands = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertTrue(all(line.startswith('"') for line in commands))
        for name in ("SET", "HSET", "SADD", "ZADD", "RPUSH", "XADD", "SELECT"):
            self.assertIn(f'"{name}" ', text)


class Sqlite(unittest.TestCase):
    """The opt-in SQLite seed (ADR-0059 decision 10) and dev/sqlite/build.py."""

    @classmethod
    def setUpClass(cls):
        cls.files = g.build()
        cls.truth = json.loads(cls.files["ground-truth.json"])
        cls.manifest = json.loads(cls.files["seed/out/sqlite.json"])
        cls.locs = [loc for loc in cls.truth["locations"] if loc["engine"] == "sqlite"]
        sys.path.insert(0, str(g.DEV_DIR / "sqlite"))
        import build  # noqa: E402

        cls.build = build

    def test_manifest_and_targets(self):
        files = {e["file"]: e for e in self.manifest["files"]}
        self.assertEqual(self.truth["targets"]["sqlite"]["files"],
                         {name: e["target"] for name, e in files.items()})
        self.assertEqual({e["journal_mode"] for e in files.values()}, {"delete", "wal"})
        self.assertIn("UTF-16le", {e["encoding"] for e in files.values()})
        for e in files.values():
            self.assertIn("seed/out/" + e["sql"], self.files)
        for loc in self.locs:
            self.assertEqual(loc["database"], "main")
            self.assertIsNone(loc["container"])
            self.assertIn(loc["file"], files)

    def test_fixtures(self):
        sql = "".join(v for k, v in self.files.items() if k.startswith("seed/out/sqlite-"))
        for fixture in ("WITHOUT ROWID", ") STRICT", "CREATE VIEW", "VIRTUAL", "STORED", "USING fts5",
                        "AS BLOB", "zeroblob(", "INTEGER NOT NULL"):
            self.assertIn(fixture, sql)
        named = [loc for loc in self.locs if loc["name_contains_value"]]
        self.assertTrue(any(loc["object"] != "escalation_contacts" for loc in named), "table name")
        self.assertTrue(any(loc["object"] == "escalation_contacts" for loc in named), "column name")
        fts = [loc for loc in self.locs if loc.get("requires") == "fts5"]
        self.assertEqual({(loc["object"], bool(loc["expected_classifiers"])) for loc in fts},
                         {("support_notes_content", True), ("support_notes", False)})

    def test_requires_blocks(self):
        crm = self.files["seed/out/sqlite-crm.sql"]
        stripped, kept = self.build.strip_blocks(crm, {"fts5"})
        self.assertNotIn("fts5", stripped)
        self.assertEqual(kept, set())
        full, kept = self.build.strip_blocks(crm, set())
        self.assertEqual(kept, {"fts5"})
        self.assertNotIn("databastion:", full)
        with self.assertRaises(ValueError):
            self.build.strip_blocks("-- databastion:requires fts5\nx;\n", set())
        with self.assertRaises(ValueError):
            self.build.strip_blocks("-- databastion:requires rtree\nx;\n-- databastion:end\n", set())

    def test_builder_writes_every_variant(self):
        import sqlite3
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            man = Path(d) / "m"
            man.mkdir()
            for name, content in self.files.items():
                if name.startswith("seed/out/sqlite"):
                    (man / name.rsplit("/", 1)[1]).write_text(content, encoding="utf-8")
            out = Path(d) / "out"
            out.mkdir()
            without = [] if self.build.has_module("fts5") else ["--without", "fts5"]
            self.assertEqual(self.build.main(["build", "--manifest", str(man / "sqlite.json"),
                                              "--out", str(out), *without]), 0)
            for e in self.manifest["files"]:
                h = self.build.header(out / e["file"])
                self.assertEqual(h[18] == 2, e["journal_mode"] == "wal")
            con = sqlite3.connect(f"file:{out / 'intl.db'}?mode=ro", uri=True)
            self.assertEqual(con.execute("PRAGMA encoding").fetchone()[0], "UTF-16le")
            con.close()
            # Never over an existing file.
            with self.assertRaises(FileExistsError):
                self.build.main(["build", "--manifest", str(man / "sqlite.json"), "--out", str(out), *without])
            self.assertEqual(self.build.main(["build", "--manifest", str(man / "sqlite.json"), "--out", str(out),
                                              "--if-missing", *without]), 0)
            self.assertEqual([p.name for p in self.build.wal_files(out)], ["app.db"])


class CasRegistry(unittest.TestCase):
    """dev/cas/services (opt-in CAS dev service) against the ground truth and the CAS config."""

    @classmethod
    def setUpClass(cls):
        cls.files = g.build()
        cls.truth = json.loads(cls.files["ground-truth.json"])
        cls.services = {k: json.loads(v) for k, v in cls.files.items()
                        if k.startswith(g.CAS_SERVICES + "/")}
        cls.cas = [loc for loc in cls.truth["locations"] if loc["engine"] == "cas"]

    def test_definitions(self):
        self.assertGreaterEqual(len(self.services), 5)
        kinds = set()
        for path, d in self.services.items():
            self.assertEqual(path, f"{g.CAS_SERVICES}/{d['name']}-{d['id']}.json")
            self.assertIn(d["@class"], g.CAS_CLASS.values(), path)
            self.assertTrue(d["serviceId"], path)
            kinds.add(d["@class"])
        self.assertEqual(kinds, set(g.CAS_CLASS.values()))
        self.assertEqual(len({d["id"] for d in self.services.values()}), len(self.services))

    def test_registry_directory_holds_definitions_only(self):
        # connector-cas refuses a registry directory holding CAS configuration or key material.
        committed = sorted(p.name for p in (g.DEV_DIR / g.CAS_SERVICES).iterdir())
        self.assertEqual(committed, sorted(p.rsplit("/", 1)[1] for p in self.services))

    def test_values_are_in_the_definitions(self):
        text = "".join(self.files[p] for p in self.services)
        for loc in self.cas:
            if loc["database"] != "service_registry":
                continue
            for v in loc.get("values", []):
                self.assertIn(json.dumps(v, ensure_ascii=False)[1:-1], text, loc["field"])

    def test_secrets_are_dev_only_and_listed(self):
        secrets = [v for loc in self.cas if loc.get("never_sampled") for v in loc["values"]]
        self.assertEqual(len(secrets), 3)
        for v in secrets:
            if v.startswith("Basic "):
                import base64
                v = base64.b64decode(v[len("Basic "):]).decode()
            self.assertTrue(v.startswith(("dev-only-", "{cipher}")), "not marked as fake")
        forms = {d.get("clientSecret", "")[:8] for d in self.services.values() if "clientSecret" in d}
        self.assertEqual(forms, {"dev-only", "{cipher}"})

    def test_logins_match_the_cas_configuration(self):
        props = (g.DEV_DIR / "cas" / "config" / "cas.properties").read_text(encoding="utf-8")
        line = next(l for l in props.splitlines() if l.startswith("cas.authn.accept.users="))
        logins = [u.split("::", 1)[0] for u in line.split("=", 1)[1].split(",")]
        self.assertEqual(sorted(logins), sorted([*g.CAS_USERS, g.CAS_SERVICE_USER]))
        who = [loc for loc in self.cas if loc["database"] == "audit_trail"]
        self.assertEqual(len(who), 1)
        self.assertEqual(who[0]["values"], sorted(g.CAS_USERS))


if __name__ == "__main__":
    unittest.main()
