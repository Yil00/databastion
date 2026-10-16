"""Unit tests of e2e/redis_scenario.py (no server, no network): the RESP encoder and reader, the
SYNC payload reader, the keys file and the load schedule. Run:
python3 -m unittest discover -s e2e -p 'test_*.py'."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import redis_scenario as rs


def source(data: bytes, chunk: int = 3):
    """A recv() over `data` in small chunks (exercises the reader's buffering)."""
    buf = io.BytesIO(data)

    def recv(_n: int) -> bytes:
        return buf.read(chunk)
    return recv


class Resp(unittest.TestCase):
    def test_encode(self) -> None:
        self.assertEqual(rs.encode("GET", "k"), b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
        self.assertEqual(rs.encode("SET", "é", b"\x00"), b"*3\r\n$3\r\nSET\r\n$2\r\n\xc3\xa9\r\n$1\r\n\x00\r\n")

    def test_replies(self) -> None:
        data = (b"+OK\r\n:42\r\n$5\r\nhello\r\n$-1\r\n*2\r\n$1\r\na\r\n*1\r\n:1\r\n*-1\r\n$0\r\n\r\n")
        r = rs.Reader(source(data))
        self.assertEqual(r.reply(), "OK")
        self.assertEqual(r.reply(), 42)
        self.assertEqual(r.reply(), b"hello")
        self.assertIsNone(r.reply())
        self.assertEqual(r.reply(), [b"a", [1]])
        self.assertIsNone(r.reply())
        self.assertEqual(r.reply(), b"")

    def test_error_keeps_the_first_word_only(self) -> None:
        r = rs.Reader(source(b"-NOPERM this user has no permissions to access the 'secret:k' key\r\n"))
        with self.assertRaises(rs.ServerError) as e:
            r.reply()
        self.assertEqual(str(e.exception), "server error NOPERM")
        self.assertNotIn("secret", str(e.exception))

    def test_protocol_errors(self) -> None:
        for data in (b"?x\r\n", b"$3\r\nabcd\r\n", b"\r\n"):
            with self.assertRaises(rs.ScenarioError):
                rs.Reader(source(data)).reply()
        with self.assertRaises(rs.ScenarioError):
            rs.Reader(source(b"$5\r\nab")).reply()  # closed early


class Sync(unittest.TestCase):
    def test_length_prefixed_payload(self) -> None:
        payload = b"REDIS0011" + bytes(range(200))
        r = rs.Reader(source(b"\n\n$%d\r\n" % len(payload) + payload, chunk=7))
        self.assertEqual(rs.read_rdb(r, deadline=float("inf")), len(payload))

    def test_eof_marked_payload(self) -> None:
        mark = b"m" * 39 + b"!"
        payload = b"REDIS0011" + b"x" * 1000
        for chunk in (1, 7, 41, 4096):
            r = rs.Reader(source(b"\n$EOF:" + mark + b"\r\n" + payload + mark, chunk=chunk))
            self.assertEqual(rs.read_rdb(r, deadline=float("inf")), len(payload), chunk)

    def test_bad_replies(self) -> None:
        with self.assertRaises(rs.ScenarioError):
            rs.read_rdb(rs.Reader(source(b"+FULLRESYNC x 0\r\n")), deadline=float("inf"))
        with self.assertRaises(rs.ScenarioError):
            rs.read_rdb(rs.Reader(source(b"$EOF:short\r\n")), deadline=float("inf"))


class KeysFile(unittest.TestCase):
    def write(self, text: str) -> str:
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_parse(self) -> None:
        p = self.write("0\thash\tuser:a@example.org:profile\n\n1\tstring\tphone:+33 6 00\n")
        self.assertEqual(rs.parse_keys_file(p), [(0, "hash", "user:a@example.org:profile"),
                                                 (1, "string", "phone:+33 6 00")])

    def test_refusals_name_the_line_never_the_key(self) -> None:
        for text in ("0\tblob\tsecret-key\n", "x\tstring\tsecret-key\n", "0\tstring\n", ""):
            with self.assertRaises(rs.ScenarioError) as e:
                rs.parse_keys_file(self.write(text))
            self.assertNotIn("secret-key", str(e.exception))

    def test_main_never_prints_a_key(self) -> None:
        p = self.write("9\tunknown\tuser:leak@example.org:profile\n")
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            rc = rs.main(["queries", "--port", "1", "--ca", "/nonexistent", "--user", "u",
                          "--password-file", "/nonexistent", "--keys-file", p])
        self.assertEqual(rc, 1)
        self.assertNotIn("leak@example.org", err.getvalue() + out.getvalue())


class Load(unittest.TestCase):
    def test_schedule(self) -> None:
        self.assertEqual(rs.schedule(4, 1), [0.0, 0.25, 0.5, 0.75])
        self.assertEqual(len(rs.schedule(300, 600)), 180000)
        self.assertEqual(rs.schedule(0, 10), [])

    def test_percentile(self) -> None:
        self.assertIsNone(rs.percentile([], 95))
        self.assertEqual(rs.percentile([3, 1, 2, 4], 50), 2)
        self.assertEqual(rs.percentile(list(range(1, 101)), 95), 95)


if __name__ == "__main__":
    unittest.main()
