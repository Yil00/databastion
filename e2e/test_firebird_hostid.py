"""Unit tests of e2e/firebird_hostid.py: the agent's identity-file grammar and the uid rules of the
e2e-firebird preconditions (ADR-0060 R45 item 7, R47, R48, R52 item 2). Run with
`python3 -m unittest discover -s e2e -p 'test_firebird*.py'`."""

import io
import os
import tempfile
import unittest
from unittest import mock

import firebird_hostid as h

PASSWD = (b"root:x:0:0:root:/root:/bin/bash\n"
          b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          b"runner:x:1001:1001:GitHub runner:/home/runner:/bin/bash\n")
GROUP = b"root:x:0:\nrunner:x:1001:\ndocker:x:118:runner\n"
NSS_RUNNER = (b"# /etc/nsswitch.conf\n"
              b"passwd:         files systemd\n"
              b"group:          files systemd\n"
              b"shadow:         files systemd\n"
              b"hosts:          files mdns4_minimal [NOTFOUND=return] dns\n")
SUBUID = b"runner:100000:65536\n"


class Grammar(unittest.TestCase):
    def test_passwd_strict(self):
        self.assertEqual([(n, u) for n, u, _ in h.parse_passwd(PASSWD)],
                         [(b"root", 0), (b"daemon", 1), (b"runner", 1001)])
        for bad in (b"# comment\n", b"+nis::0:0:::\n", b"a b:x:1:1:::\n", b"a:x:1:1::\n",
                    b"a:x:-1:1:::\n", b"a:x:4294967295:1:::\n"):
            with self.assertRaises(h.Malformed, msg=bad):
                h.parse_passwd(bad)
        self.assertEqual(h.parse_passwd(b"\n\nroot:x:0:0:::\n"), [(b"root", 0, 0)])

    def test_group_strict(self):
        self.assertEqual(h.parse_group(GROUP)[2], (118, [b"runner"]))
        for bad in (b"#x:x:1:\n", b"g:x:1:a b\n", b"g:x:1\n", b"g:x:z:\n"):
            with self.assertRaises(h.Malformed, msg=bad):
                h.parse_group(bad)

    def test_nsswitch(self):
        n = h.parse_nsswitch(NSS_RUNNER)
        self.assertEqual(n["passwd"], ["files", "systemd"])
        self.assertEqual(n["group"], ["files", "systemd"])
        self.assertNotIn("initgroups", n)
        for bad in (b"passwd: files\npasswd: files\n", b"passwd files\n", b"passwd:\n",
                    b"hosts: files [NOTFOUND=return dns\n", b"hosts: files [a]b\n",
                    b"passwd: fi$les\n"):
            with self.assertRaises(h.Malformed, msg=bad):
                h.parse_nsswitch(bad)
        # Names are compared exactly: `Passwd:` is another database.
        self.assertNotIn("passwd", h.parse_nsswitch(b"Passwd: files\n"))

    def test_subid(self):
        self.assertEqual(h.parse_subid(SUBUID), [(100000, 65536)])
        with self.assertRaises(h.Malformed):
            h.parse_subid(b"runner:100000\n")


class Check(unittest.TestCase):
    def run_check(self, files, uids=(84, 10001), present=1001):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "etc"))
            for name, content in files.items():
                with open(os.path.join(d, "etc", name), "wb") as f:
                    f.write(content)

            def problem(path, bound):
                if not os.path.exists(path):
                    return "missing", b""
                with open(path, "rb") as f:
                    return None, f.read()

            with mock.patch.object(h, "file_problem", problem):
                return h.check(d, list(uids), present, io.StringIO())

    def runner_files(self, **extra):
        files = {"passwd": PASSWD, "group": GROUP, "nsswitch.conf": NSS_RUNNER, "subuid": SUBUID,
                 "subgid": SUBUID}
        files.update(extra)
        return {k: v for k, v in files.items() if v is not None}

    def test_runner_layout_holds(self):
        errors, mounts = self.run_check(self.runner_files())
        self.assertEqual(errors, [])
        self.assertEqual(mounts, ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/subuid",
                                  "/etc/subgid"])

    def test_without_subordinate_files(self):
        errors, mounts = self.run_check(self.runner_files(subuid=None, subgid=None))
        self.assertEqual(errors, [])
        self.assertEqual(mounts, ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"])

    def test_uid_present_fails(self):
        errors, _ = self.run_check(self.runner_files(
            passwd=PASSWD + b"firebird:x:84:84::/nonexistent:/usr/sbin/nologin\n"))
        self.assertTrue(any(e.startswith("uid 84: present") for e in errors), errors)

    def test_uid_in_subordinate_range_fails(self):
        errors, _ = self.run_check(self.runner_files(subuid=b"runner:10000:65536\n"))
        self.assertTrue(any("uid 10001: inside a subordinate" in e for e in errors), errors)

    def test_subid_other_source_floor(self):
        errors, _ = self.run_check(self.runner_files(
            **{"nsswitch.conf": NSS_RUNNER + b"subid: sss\n"}), uids=(84, 100001))
        self.assertTrue(any("uid 100001: inside a subordinate" in e for e in errors), errors)

    def test_systemd_and_reserved(self):
        errors, _ = self.run_check(self.runner_files(), uids=(61184, 65534))
        self.assertTrue(any("61184: inside a systemd range" in e for e in errors), errors)
        self.assertTrue(any("65534: reserved" in e for e in errors), errors)

    def test_passwd_line_other_source_fails(self):
        errors, _ = self.run_check(self.runner_files(
            **{"nsswitch.conf": b"passwd: files sss\ngroup: files\n"}))
        self.assertTrue(any("host_identity_nss" in e for e in errors), errors)

    def test_missing_group_line_fails(self):
        errors, _ = self.run_check(self.runner_files(**{"nsswitch.conf": b"passwd: files\n"}))
        self.assertTrue(any("no group: line" in e for e in errors), errors)

    def test_collision_uid_must_be_present(self):
        errors, _ = self.run_check(self.runner_files(), present=1002)
        self.assertTrue(any(e.startswith("uid 1002: absent") for e in errors), errors)

    def test_malformed_passwd_fails(self):
        errors, _ = self.run_check(self.runner_files(passwd=PASSWD + b"+::::::\n"))
        self.assertTrue(any("malformed" in e for e in errors), errors)

    def test_missing_required_file_fails(self):
        errors, _ = self.run_check(self.runner_files(group=None))
        self.assertIn("/etc/group: missing", errors)


class FileRules(unittest.TestCase):
    def test_owner_mode_links(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f")
            with open(p, "wb") as f:
                f.write(b"x\n")
            os.chmod(p, 0o644)
            why, _ = h.file_problem(p, 100)
            self.assertEqual(why, None if os.geteuid() == 0 else "owner")
            os.chmod(p, 0o664)
            self.assertEqual(h.file_problem(p, 100)[0],
                             "mode" if os.geteuid() == 0 else "owner")
            os.chmod(p, 0o644)
            os.link(p, p + ".2")
            self.assertEqual(h.file_problem(p, 100)[0], "links")
            self.assertEqual(h.file_problem(os.path.join(d, "none"), 100)[0], "missing")


class Main(unittest.TestCase):
    def test_list_refused_with_another_root(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit) as e, \
                mock.patch("sys.stderr", io.StringIO()):
            h.main(["check", "--root", d, "--list", os.path.join(d, "out")])
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
