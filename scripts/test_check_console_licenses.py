"""Unit tests of scripts/check_console_licenses.py
(run: python3 -m unittest discover -s scripts -p 'test_*.py')."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_console_licenses as ccl  # noqa: E402

ALLOWED = {"Apache-2.0", "Apache-2.0 WITH LLVM-exception", "MIT", "BSD-2-Clause", "BSD-3-Clause",
           "ISC", "Unicode-3.0", "Zlib", "CC0-1.0"}


class ExpressionTest(unittest.TestCase):
    def ok(self, expr: str) -> None:
        self.assertTrue(ccl.expression_allowed(expr, ALLOWED), expr)

    def ko(self, expr: str) -> None:
        self.assertFalse(ccl.expression_allowed(expr, ALLOWED), expr)

    def test_single_ids(self) -> None:
        for e in ("MIT", "Apache-2.0", "ISC", "BSD-3-Clause", " MIT "):
            self.ok(e)
        for e in ("GPL-3.0-only", "LGPL-3.0-or-later", "CC-BY-4.0", "0BSD", "mit", "BSD"):
            self.ko(e)

    def test_or_needs_one_allowed_side(self) -> None:
        self.ok("(MIT OR CC0-1.0)")
        self.ok("GPL-2.0-only OR MIT")
        self.ok("MIT or GPL-3.0-only")
        self.ko("GPL-2.0-only OR LGPL-3.0-only")

    def test_and_needs_both_sides(self) -> None:
        self.ok("MIT AND ISC")
        self.ko("MIT AND CC-BY-4.0")
        self.ko("(MIT AND GPL-3.0-only) OR LGPL-2.1-only")
        self.ok("(MIT AND GPL-3.0-only) OR ISC")

    def test_precedence_and_binds_tighter(self) -> None:
        # MIT OR (GPL AND GPL) -> allowed; (MIT OR GPL) AND GPL would not be.
        self.ok("MIT OR GPL-3.0-only AND GPL-2.0-only")
        self.ko("(MIT OR GPL-3.0-only) AND GPL-2.0-only")

    def test_with_exception_must_be_listed_whole(self) -> None:
        self.ok("Apache-2.0 WITH LLVM-exception")
        self.ko("GPL-2.0-only WITH Classpath-exception-2.0")
        self.ko("MIT WITH Some-exception")

    def test_or_later(self) -> None:
        self.ok("Apache-2.0+")
        self.ko("GPL-2.0+")

    def test_aliases(self) -> None:
        self.ok("Apache 2.0")
        self.ok("MIT License")
        self.ko("Apache License 2.0 or whatever")

    def test_unparseable_or_unknown_is_refused(self) -> None:
        for e in ("", "   ", "UNKNOWN", "Unknown", "UNLICENSED", "SEE LICENSE IN LICENSE.md",
                  "LicenseRef-Proprietary", "(MIT", "MIT)", "MIT OR", "AND MIT", "MIT ISC",
                  "MIT/X11", "MIT WITH", "MIT, ISC", None):
            self.ko(e)  # type: ignore[arg-type]


def run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    return ccl.main(argv, out=buf), buf.getvalue()


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.deny = self.write("deny.toml", '[licenses]\nallow = ["MIT", "Apache-2.0", "ISC"]\n')

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def licenses(self, data: dict) -> str:
        return self.write("licenses.json", json.dumps(data))

    def exceptions(self, entries: list[dict]) -> str:
        return self.write("exceptions.json", json.dumps({"exceptions": entries}))

    def check(self, data: dict, entries: list[dict] | None = None) -> tuple[int, str]:
        argv = ["--deny-toml", self.deny, "--exceptions",
                self.exceptions(entries or []), self.licenses(data)]
        return run(argv)

    @staticmethod
    def pkg(name: str, lic: str, version: str = "1.0.0") -> dict:
        return {"name": name, "versions": [version], "license": lic, "paths": ["/x"]}

    def test_ok(self) -> None:
        rc, out = self.check({"MIT": [self.pkg("a", "MIT")], "(MIT OR CC0-1.0)": [
            self.pkg("b", "(MIT OR CC0-1.0)")]})
        self.assertEqual(rc, 0, out)
        self.assertIn("2 production package(s)", out)

    def test_violation(self) -> None:
        rc, out = self.check({"MIT": [self.pkg("a", "MIT")],
                              "GPL-3.0-only": [self.pkg("evil", "GPL-3.0-only", "2.1.0")]})
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL evil@2.1.0: 'GPL-3.0-only'", out)

    def test_exception_matches_name_glob_and_exact_license(self) -> None:
        entries = [{"package": "@img/sharp-libvips-*", "license": "LGPL-3.0-or-later",
                    "reason": "pending decision"}]
        data = {"LGPL-3.0-or-later": [self.pkg("@img/sharp-libvips-linux-x64", "LGPL-3.0-or-later")]}
        rc, out = self.check(data, entries)
        self.assertEqual(rc, 0, out)
        self.assertIn("excepted @img/sharp-libvips-linux-x64", out)
        # A license change of the excepted package fails again.
        rc, out = self.check({"GPL-3.0-only": [self.pkg("@img/sharp-libvips-linux-x64",
                                                        "GPL-3.0-only")]}, entries)
        self.assertEqual(rc, 1, out)
        # Another package with the same license is not covered.
        rc, out = self.check({"LGPL-3.0-or-later": [self.pkg("other", "LGPL-3.0-or-later")]},
                             entries)
        self.assertEqual(rc, 1, out)

    def test_unused_exception_is_a_warning(self) -> None:
        rc, out = self.check({"MIT": [self.pkg("a", "MIT")]},
                             [{"package": "gone", "license": "0BSD", "reason": "was used"}])
        self.assertEqual(rc, 0, out)
        self.assertIn("unused exception gone", out)

    def test_exception_needs_a_reason(self) -> None:
        for entry in ({"package": "a", "license": "0BSD", "reason": "  "},
                      {"package": "a", "license": "0BSD"},
                      {"package": "a", "license": "0BSD", "reason": "x", "extra": 1}):
            rc, out = self.check({"MIT": [self.pkg("a", "MIT")]}, [entry])
            self.assertEqual(rc, 2, out)

    def test_per_package_license_is_used(self) -> None:
        # The entry's own license wins over the grouping key.
        rc, out = self.check({"MIT": [self.pkg("a", "GPL-3.0-only")]})
        self.assertEqual(rc, 1, out)

    def test_bad_inputs(self) -> None:
        self.assertEqual(self.check({})[0], 2)
        self.assertEqual(run(["--deny-toml", self.deny, self.write("l.json", "[]")])[0], 2)
        self.assertEqual(run(["--deny-toml", self.write("d.toml", "[bans]\n"),
                              self.licenses({"MIT": [self.pkg("a", "MIT")]})])[0], 2)
        self.assertEqual(run(["--deny-toml", self.deny, os.path.join(self.tmp.name, "nope")])[0], 2)

    def test_repository_allow_list_is_deny_toml(self) -> None:
        allowed = ccl.load_allow_list(ccl.DEFAULT_DENY_TOML)
        self.assertEqual(allowed, ALLOWED)

    def test_repository_exceptions_file_is_valid(self) -> None:
        entries = ccl.load_exceptions(ccl.DEFAULT_EXCEPTIONS)
        for e in entries:
            self.assertFalse(ccl.expression_allowed(e.license, ALLOWED),
                             f"{e.package}: exception for an allowed license")
            self.assertGreaterEqual(len(e.reason), 40, f"{e.package}: reason too short")


if __name__ == "__main__":
    unittest.main()
