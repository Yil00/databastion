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
        self.assertEqual(engines, {"postgresql", "mysql", "mariadb", "mongodb", "openldap", "cas"})
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
                     "mongodb": "mongo.json"}
        for loc in self.truth["locations"]:
            if loc["engine"] not in seed_file:
                continue  # LDIF: non-ASCII values are base64-encoded
            content = self.files["seed/out/" + seed_file[loc["engine"]]]
            for v in loc.get("values", []):
                needle = v if loc["engine"] == "mongodb" else v.replace("'", "''")
                if needle not in content:
                    self.fail(f"{loc['engine']} {loc['object']}.{loc['field']}: value not in seed file")

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
