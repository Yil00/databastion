"""Unit tests of e2e/cas_scenario.py (no CAS, no network): the parsers, the value registry and the
load schedule. Run: python3 -m unittest discover -s e2e -p 'test_*.py'."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import cas_scenario as cs

SERVICE = "https://intranet.example.org/login"


class Parsers(unittest.TestCase):
    def test_execution_field(self) -> None:
        html = '<form><input type="hidden" name="execution" value="abc-123_x=="/></form>'
        self.assertEqual(cs.execution_of(html), "abc-123_x==")
        with self.assertRaises(cs.ScenarioError):
            cs.execution_of("<form></form>")

    def test_ticket_of_redirect(self) -> None:
        st = "ST-12-AbCdEf0123456789-cas"
        self.assertEqual(cs.ticket_of(f"{SERVICE}?ticket={st}", SERVICE), st)

    def test_ticket_refusals_never_echo_the_value(self) -> None:
        st = "ST-12-AbCdEf0123456789-cas"
        for location in (f"https://evil.example/login?ticket={st}",       # another place
                         f"{SERVICE}?ticket={st}&ticket={st}",           # two tickets
                         f"{SERVICE}?ticket=TGT-1-abc",                  # not a service ticket
                         f"{SERVICE}?ticket=ST-x",                       # not ticket-shaped
                         SERVICE):
            with self.assertRaises(cs.ScenarioError) as e:
                cs.ticket_of(location, SERVICE)
            self.assertNotIn("ST-", str(e.exception))
            self.assertNotIn("TGT-", str(e.exception))

    def test_validated_user(self) -> None:
        ok = ('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess>'
              "<cas:user>camille.martin@example.org</cas:user></cas:authenticationSuccess></cas:serviceResponse>")
        self.assertEqual(cs.validated_user(ok), "camille.martin@example.org")
        ko = ('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">'
              '<cas:authenticationFailure code="INVALID_TICKET"/></cas:serviceResponse>')
        self.assertIsNone(cs.validated_user(ko))
        self.assertIsNone(cs.validated_user("not xml"))

    def test_ticket_shape(self) -> None:
        for good in ("ST-1-abc-cas", "TGT-22-x.y_z-host", "OC-3-q"):
            self.assertTrue(cs.TICKET_RE.match(good), good)
        for bad in ("ST-abc", "st-1-abc", "ST-1-", "X-1-abc"):
            self.assertFalse(cs.TICKET_RE.match(bad), bad)


class Registry(unittest.TestCase):
    def test_ticket_values_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            st = "ST-1-AbC-cas"
            cs.record_ticket(d, 0, st, "eyJcookie")
            self.assertEqual(sorted(os.listdir(d)), ["st_0", "st_0_sha256", "st_0_sha512", "tgc_0"])
            def read(n: str) -> str:
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    return f.read()

            self.assertEqual(read("st_0"), st + "\n")
            self.assertEqual(read("st_0_sha256"), hashlib.sha256(st.encode()).hexdigest() + "\n")
            self.assertEqual(read("st_0_sha512"), hashlib.sha512(st.encode()).hexdigest() + "\n")
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "st_0")).st_mode), 0o600)
            self.assertEqual(cs.next_index(d, "st_"), 1)
            self.assertEqual(cs.next_index(d, "name_"), 0)

    def test_value_files_refuse_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.symlink(os.path.join(d, "elsewhere"), os.path.join(d, "st_0"))
            with self.assertRaises(OSError):
                cs.write_value(d, "st_0", "ST-1-x")


class Load(unittest.TestCase):
    def test_schedule(self) -> None:
        self.assertEqual(cs.schedule(2, 2), [0.0, 0.5, 1.0, 1.5])
        self.assertEqual(cs.schedule(0, 10), [])
        self.assertEqual(len(cs.schedule(10, 600)), 6000)

    def test_percentile(self) -> None:
        self.assertIsNone(cs.percentile([], 95))
        self.assertEqual(cs.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(cs.percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(cs.percentile([5], 99), 5)

    def test_load_counts_and_output(self) -> None:
        def fake_login(base, user, password, service, first=False):
            if service:
                return cs.Login(302, ticket="ST-1-a-cas", tgc=None, post_ms=10.0)
            return cs.Login(401, post_ms=5.0)

        with tempfile.TemporaryDirectory() as d:
            pw = os.path.join(d, "pw")
            with open(pw, "w", encoding="utf-8") as f:
                f.write("x")
            out = os.path.join(d, "out.json")
            with mock.patch.object(cs, "login", fake_login), \
                    mock.patch.object(cs, "validate", lambda b, s, t: "u@example.org"):
                code = cs.main(["load", "--base", "http://127.0.0.1:1/cas", "--password-file", pw,
                                "--user", "u@example.org", "--service", SERVICE, "--rate", "20",
                                "--fail-rate", "10", "--duration", "0.5", "--out", out])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as f:
                r = json.load(f)
            self.assertEqual((r["planned_logins"], r["logins"]), (10, 10))
            self.assertEqual((r["planned_failures"], r["failed_logins"]), (5, 5))
            self.assertEqual(r["errors"], {})
            self.assertEqual(r["post_ms"]["p95"], 10.0)
            self.assertNotIn("ST-1", json.dumps(r))


class Main(unittest.TestCase):
    def test_only_a_loopback_cas(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cs.main(["failures", "--base", "https://cas.example.org/cas", "--count", "1",
                                      "--patterns", "/nonexistent", "--names", "/nonexistent"]), 2)

    def test_failures_record_names_and_passwords_only_in_files(self) -> None:
        seen = []

        def fake_login(base, user, password, service, first=False):
            seen.append((user, password))
            return cs.Login(401)

        with tempfile.TemporaryDirectory() as p, tempfile.TemporaryDirectory() as n:
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(cs, "login", fake_login), redirect_stdout(out), redirect_stderr(err):
                code = cs.main(["failures", "--base", "http://127.0.0.1:1/cas", "--count", "20",
                                "--patterns", p, "--names", n])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue()), {"distinct_names": 20, "failed_logins": 20})
            self.assertEqual(len(os.listdir(n)), 20)
            self.assertEqual(len(os.listdir(p)), 20)
            self.assertEqual(len({u for u, _ in seen}), 20)
            for user, password in seen:
                self.assertNotIn(user, out.getvalue() + err.getvalue())
                self.assertNotIn(password, out.getvalue() + err.getvalue())
            # One typed name is password-like (not an e-mail).
            self.assertEqual(sum(1 for u, _ in seen if "@" not in u), 1)

    def test_a_refused_step_fails_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as p, tempfile.TemporaryDirectory() as n:
            err = io.StringIO()
            with mock.patch.object(cs, "login", lambda *a, **k: cs.Login(200)), redirect_stderr(err):
                code = cs.main(["failures", "--base", "http://127.0.0.1:1/cas", "--count", "2",
                                "--patterns", p, "--names", n])
            self.assertEqual(code, 1)
            self.assertIn("HTTP 200", err.getvalue())
            self.assertNotIn("@example.invalid", err.getvalue())


if __name__ == "__main__":
    unittest.main()
