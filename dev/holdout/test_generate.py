"""Tests of the holdout corpus generator. Run with `python3 -m unittest discover -s dev/holdout`."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate as g  # noqa: E402


class Validators(unittest.TestCase):
    def test_luhn_known(self):
        self.assertTrue(g.check_luhn("4111 1111 1111 1111"))
        self.assertTrue(g.check_luhn("3782-822463-10005"))  # Amex test number
        self.assertFalse(g.check_luhn("4111111111111112"))
        self.assertTrue(g.check_luhn("732 829 320 00074"))  # SIRET documentation example
        self.assertTrue(g.check_luhn("490154203237518"))  # IMEI documentation example

    def test_iban_known(self):
        self.assertTrue(g.check_iban("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(g.check_iban("fr1420041010050500013m02606"))
        self.assertFalse(g.check_iban("GB82 WEST 1234 5698 7654 33"))

    def test_nir_known(self):
        self.assertTrue(g.check_nir("2 55 08 14 168 025 38"))
        self.assertFalse(g.check_nir("2 55 08 14 168 025 39"))
        # Corsica: the key is computed with 2A -> 19 and 2B -> 18.
        body = "1850320004123"  # "20" placeholder, replaced below
        for dept, sub in (("2A", "19"), ("2B", "18")):
            first13 = body[:5] + dept + body[7:]
            key = 97 - int(body[:5] + sub + body[7:]) % 97
            self.assertTrue(g.check_nir(f"{first13}{key:02d}"))
            self.assertFalse(g.check_nir(f"{first13}{(key % 97) + 1:02d}"))

    def test_builders_agree_with_checkers(self):
        gen = g.Gen(7)
        for _ in range(300):
            self.assertTrue(g.check_nir(gen.nir_raw(corsica=True)))
            self.assertTrue(g.check_nir(gen.nir_raw(dom=True)))
            for country in g.IBAN_LENGTHS:
                self.assertTrue(g.check_iban(gen.iban(country, "odd")))
            for brand in g.Gen.CARD_BRANDS:
                self.assertTrue(g.check_luhn(gen.card_raw(brand)))


class Corpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus, cls.labels = g.build()

    def test_deterministic(self):
        c2, l2 = g.build()
        self.assertEqual(g.dump(self.corpus), g.dump(c2))
        self.assertEqual(g.dump(self.labels), g.dump(l2))

    def test_seed_differs_from_dev_seed(self):
        self.assertNotEqual(g.SEED, 20260928)

    def test_validation_passes(self):
        self.assertEqual(g.validate(self.corpus, self.labels), [])

    def test_committed_labels_up_to_date(self):
        # corpus.json is git-ignored; its SHA-256 is pinned in the committed labels.json.
        self.assertEqual(g.LABELS_PATH.read_text(encoding="utf-8"), g.dump(self.labels))
        committed = g.json.loads(g.LABELS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(committed["corpus_sha256"], g.corpus_sha256(self.corpus))

    def test_counts(self):
        pos, _, _, negatives = g.counts(self.labels)
        for cls in g.CLASSIFIERS:
            # 60 columns is the smallest size where a single miss still clears Wilson LB >= 0.90.
            self.assertGreaterEqual(pos[cls], 60, cls)
        positive_columns = sum(1 for x in self.labels["locations"]
                               if x["expected_classifiers"] and not x["ambiguous"])
        self.assertGreaterEqual(negatives, positive_columns)

    def test_misleading_negatives_present(self):
        fields = {(x["field"].split(".")[-1].lower(), bool(x["expected_classifiers"]))
                  for x in self.labels["locations"]}
        self.assertIn(("email_opt_in", False), fields)
        self.assertIn(("phone_country", False), fields)


if __name__ == "__main__":
    unittest.main()
