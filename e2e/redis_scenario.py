#!/usr/bin/env python3
"""Redis / Valkey client traffic of the end-to-end and load runs (ROADMAP P9-D, ADR-0052 decision 13).
Python standard library only; unit tests in test_redis_scenario.py.

A minimal RESP2 client over TLS (the server certificate verified against --ca, host name or address
checked). The end-to-end run (e2e/redis.sh) runs it in the one-shot `redis-client` container on the
internal agent-net, against the targets' network aliases (e2e/docker-compose.redis.yml); the load run
(e2e/load/redis.sh) runs it on the host, against the port its overlay publishes on 127.0.0.1. Every connection authenticates with `AUTH <user> <password>`, the
password read from --password-file. A connection waits --settle seconds after its AUTH before its
first command and stays open --linger seconds after its last one: the agent attributes a slow-log
entry to a user only through the connection still open at its poll, and only when the connection
is older than the entry (docs/08-engine-capabilities.md, "Redis / Valkey Audit", Principals).

Subcommands
  sweep     A dump-like read of the whole keyspace: per database of --db, `KEYS *` (a keyspace
            enumeration: `shape.keyspace_enumeration`), then per key its TYPE and its whole value
            (GET, HGETALL, LRANGE 0 -1, SMEMBERS, ZRANGE 0 -1, XRANGE - +).
  queries   Reads of the keys listed in --keys-file (`<db> <type> <key>` per line, tab-separated:
            key names may embed ground-truth values, so they never go on a command line).
  sync      A full synchronization as `redis-cli --rdb` does it (`SYNC`): reads the RDB payload
            (counted, discarded) and closes; the server's INFO `sync_full` grows by one.
  load      Fixed-rate GETs for --duration seconds: --rate commands per second over --clients
            connections (opened, authenticated and settled before the schedule starts), keys taken
            in turn from --keys-file (`<key>` per line, database 0). Writes --out (JSON): commands,
            errors, late starts, latency from the scheduled start (p50 / p95 / p99, ms) and service
            time (p95, ms).

Output: one JSON object of counts on stdout. Never a key name, a value or a password: the CI log
must not become the leak.
"""

from __future__ import annotations

import argparse
import json
import math
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field

MAX_BULK = 64 * 1024 * 1024  # a reply larger than this is a protocol error here
READERS = {
    "string": ("GET",),
    "hash": ("HGETALL",),
    "list": ("LRANGE", "0", "-1"),
    "set": ("SMEMBERS",),
    "zset": ("ZRANGE", "0", "-1"),
    "stream": ("XRANGE", "-", "+"),
}


class ScenarioError(Exception):
    """A failure of the scenario; its message never holds a key, a value or a password."""


class ServerError(ScenarioError):
    """An error reply (`-ERR ...`): only its first word is kept (NOPERM, WRONGTYPE, ...)."""


# ------------------------------------------------------------------------------------------ RESP
def encode(*args: str | bytes) -> bytes:
    """A RESP2 command: an array of bulk strings."""
    out = [b"*%d\r\n" % len(args)]
    for a in args:
        b = a.encode("utf-8") if isinstance(a, str) else a
        out.append(b"$%d\r\n%s\r\n" % (len(b), b))
    return b"".join(out)


class Reader:
    """Incremental RESP2 reader over a byte source (`recv(n) -> bytes`, b"" at the end)."""

    def __init__(self, recv) -> None:  # noqa: ANN001
        self.recv = recv
        self.buf = b""

    def _fill(self) -> None:
        chunk = self.recv(65536)
        if not chunk:
            raise ScenarioError("connection closed by the server")
        self.buf += chunk

    def line(self) -> bytes:
        while True:
            i = self.buf.find(b"\r\n")
            if i >= 0:
                line, self.buf = self.buf[:i], self.buf[i + 2:]
                return line
            if len(self.buf) > 1024 * 1024:
                raise ScenarioError("protocol: line too long")
            self._fill()

    def exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def reply(self):  # noqa: ANN201
        line = self.line()
        if not line:
            raise ScenarioError("protocol: empty line")
        kind, rest = line[:1], line[1:]
        if kind == b"+":
            return rest.decode("utf-8", "replace")
        if kind == b"-":
            word = rest.split(b" ", 1)[0].decode("ascii", "replace")
            raise ServerError(f"server error {word}")
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            if n < 0:
                return None
            if n > MAX_BULK:
                raise ScenarioError("protocol: bulk too large")
            data = self.exact(n + 2)
            if data[-2:] != b"\r\n":
                raise ScenarioError("protocol: bad bulk terminator")
            return data[:-2]
        if kind == b"*":
            n = int(rest)
            if n < 0:
                return None
            return [self.reply() for _ in range(n)]
        raise ScenarioError("protocol: unknown reply type")


def read_password(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        pw = f.read().strip()
    if not pw:
        raise ScenarioError("empty password file")
    return pw


class Client:
    """One TLS connection, authenticated as a named ACL user."""

    def __init__(self, host: str, port: int, ca: str, user: str, password: str,
                 timeout: float = 30.0) -> None:
        ctx = ssl.create_default_context(cafile=ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError):
            raw.close()
            raise
        self.reader = Reader(self.sock.recv)
        self.call("AUTH", user, password)

    def send(self, *args: str | bytes) -> None:
        self.sock.sendall(encode(*args))

    def call(self, *args: str | bytes):  # noqa: ANN201
        self.send(*args)
        return self.reader.reply()

    def close(self) -> None:
        try:
            self.sock.sendall(encode("QUIT"))
            self.reader.reply()
        except (OSError, ScenarioError):
            pass
        finally:
            self.sock.close()


def connect(args: argparse.Namespace, password: str) -> Client:
    c = Client(args.host, args.port, args.ca, args.user, password)
    if args.settle > 0:
        time.sleep(args.settle)
    return c


def finish(c: Client, args: argparse.Namespace) -> None:
    if args.linger > 0:
        time.sleep(args.linger)
    c.close()


def type_of(reply: object) -> str:
    return reply.decode("ascii", "replace") if isinstance(reply, bytes) else str(reply)


def read_value(c: Client, key: bytes, kind: str) -> int:
    """Reads a key whole; returns the number of commands sent (the value is discarded)."""
    reader = READERS.get(kind)
    if reader is None:
        return 0
    c.call(reader[0], key, *reader[1:])
    return 1


# ------------------------------------------------------------------------------------- commands
def cmd_sweep(args: argparse.Namespace) -> dict:
    c = connect(args, read_password(args.password_file))
    keys = commands = 0
    try:
        for db in args.db:
            c.call("SELECT", str(db))
            names = c.call("KEYS", "*") or []
            commands += 2
            for k in names:
                kind = type_of(c.call("TYPE", k))
                commands += 1 + read_value(c, k, kind)
                keys += 1
    finally:
        finish(c, args)
    return {"databases": len(args.db), "keys": keys, "commands": commands}


def parse_keys_file(path: str) -> list[tuple[int, str, str]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not parts[0].isdigit() or parts[1] not in READERS or not parts[2]:
                raise ScenarioError(f"keys file: bad line {n}")
            out.append((int(parts[0]), parts[1], parts[2]))
    if not out:
        raise ScenarioError("keys file: no key")
    return out


def cmd_queries(args: argparse.Namespace) -> dict:
    plan = parse_keys_file(args.keys_file)
    c = connect(args, read_password(args.password_file))
    commands = 0
    db = None
    try:
        for want_db, kind, key in plan:
            if want_db != db:
                c.call("SELECT", str(want_db))
                db = want_db
            commands += read_value(c, key.encode("utf-8"), kind)
    finally:
        finish(c, args)
    return {"reads": commands}


def read_rdb(reader: Reader, deadline: float) -> int:
    """The payload of a SYNC reply: `$<len>` then the bytes, or `$EOF:<40 bytes>` then the bytes up
    to the same 40-byte mark (diskless replication); leading newlines are keepalives."""
    while True:
        while not reader.buf:
            reader._fill()
        if reader.buf[:1] == b"\n":
            reader.buf = reader.buf[1:]
            continue
        break
    head = reader.line()
    if not head.startswith(b"$"):
        raise ScenarioError("sync: unexpected reply")
    if head.startswith(b"$EOF:"):
        mark = head[5:]
        if len(mark) != 40:
            raise ScenarioError("sync: bad EOF mark")
        total = 0
        tail = b""
        while True:
            if time.monotonic() > deadline:
                raise ScenarioError("sync: timeout")
            data, reader.buf = reader.buf, b""
            if not data:
                reader._fill()
                continue
            window = tail + data
            if mark in window:
                # The bytes before the mark; those of `tail` were counted already.
                return total + window.index(mark) - len(tail)
            total += len(data)
            tail = window[-40:]
    n = int(head[1:])
    if n < 0 or n > 1024 * MAX_BULK:
        raise ScenarioError("sync: bad length")
    got = 0
    while got < n:
        if time.monotonic() > deadline:
            raise ScenarioError("sync: timeout")
        if not reader.buf:
            reader._fill()
        take = min(n - got, len(reader.buf))
        reader.buf = reader.buf[take:]
        got += take
    return n


def cmd_sync(args: argparse.Namespace) -> dict:
    c = connect(args, read_password(args.password_file))
    try:
        c.send("SYNC")
        size = read_rdb(c.reader, time.monotonic() + args.timeout)
    finally:
        c.sock.close()
    return {"rdb_bytes": size}


# ----------------------------------------------------------------------------------------- load
def percentile(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile (p in 0..100), None without values."""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil(p / 100.0 * len(s)) - 1))
    return s[k]


def schedule(rate: float, duration: float) -> list[float]:
    """Offsets (s) of a fixed-rate schedule: `rate` per second over `duration` seconds."""
    if rate <= 0 or duration <= 0:
        return []
    n = int(rate * duration)
    return [i / rate for i in range(n)]


@dataclass
class LoadStats:
    ok: int = 0
    errors: dict[str, int] = field(default_factory=dict)
    latency_ms: list[float] = field(default_factory=list)
    service_ms: list[float] = field(default_factory=list)
    late: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def error(self, kind: str) -> None:
        with self.lock:
            self.errors[kind] = self.errors.get(kind, 0) + 1


def cmd_load(args: argparse.Namespace) -> dict:
    password = read_password(args.password_file)
    with open(args.keys_file, encoding="utf-8") as f:
        keys = [line.rstrip("\n") for line in f if line.strip()]
    if not keys:
        raise ScenarioError("keys file: no key")
    clients = [Client(args.host, args.port, args.ca, args.user, password) for _ in range(args.clients)]
    time.sleep(max(args.settle, 0))
    plan = schedule(args.rate, args.duration)
    stats = LoadStats()
    start = time.monotonic() + 1.0

    def worker(w: int) -> None:
        c = clients[w]
        for i in range(w, len(plan), len(clients)):
            due = start + plan[i]
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            elif delay < -1.0:
                with stats.lock:
                    stats.late += 1
            t0 = time.monotonic()
            try:
                c.call("GET", keys[i % len(keys)])
            except ServerError as e:
                stats.error(str(e).split()[-1])
                continue
            except (OSError, ScenarioError) as e:
                stats.error(type(e).__name__)
                return
            t1 = time.monotonic()
            with stats.lock:
                stats.ok += 1
                stats.latency_ms.append((t1 - due) * 1000.0)
                stats.service_ms.append((t1 - t0) * 1000.0)

    threads = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(len(clients))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    if args.linger > 0:
        time.sleep(args.linger)
    for c in clients:
        c.close()

    def r(v: float | None) -> float | None:
        return None if v is None else round(v, 3)

    out = {
        "planned": len(plan),
        "commands": stats.ok,
        "errors": dict(sorted(stats.errors.items())),
        "late_starts": stats.late,
        "elapsed_s": round(elapsed, 1),
        "latency_ms": {"p50": r(percentile(stats.latency_ms, 50)), "p95": r(percentile(stats.latency_ms, 95)),
                       "p99": r(percentile(stats.latency_ms, 99))},
        "service_p95_ms": r(percentile(stats.service_ms, 95)),
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=True)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    parsers = {}
    for name in ("sweep", "queries", "sync", "load"):
        s = sub.add_parser(name)
        s.add_argument("--host", default="127.0.0.1")
        s.add_argument("--port", type=int, required=True)
        s.add_argument("--ca", required=True)
        s.add_argument("--user", required=True)
        s.add_argument("--password-file", required=True)
        s.add_argument("--settle", type=float, default=3.0)
        s.add_argument("--linger", type=float, default=0.0)
        parsers[name] = s
    parsers["sweep"].add_argument("--db", type=int, action="append", default=None)
    parsers["queries"].add_argument("--keys-file", required=True)
    parsers["sync"].add_argument("--timeout", type=float, default=60.0)
    ld = parsers["load"]
    ld.add_argument("--keys-file", required=True)
    ld.add_argument("--rate", type=float, required=True)
    ld.add_argument("--duration", type=float, required=True)
    ld.add_argument("--clients", type=int, default=4)
    ld.add_argument("--out")
    args = p.parse_args(argv)
    if args.cmd == "sweep" and not args.db:
        args.db = [0]
    handler = {"sweep": cmd_sweep, "queries": cmd_queries, "sync": cmd_sync, "load": cmd_load}[args.cmd]
    try:
        out = handler(args)
    except (ScenarioError, OSError, ssl.SSLError, ValueError) as e:
        # The class, and for a server error its first word only: never a key or a value.
        msg = str(e) if isinstance(e, ScenarioError) else type(e).__name__
        print(f"redis_scenario {args.cmd}: {msg}", file=sys.stderr)
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
