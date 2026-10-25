#!/usr/bin/env python3
"""The application of the SQLite load run (e2e/load/sqlite.sh, ADR-0059 decision 10 "Load").
Python standard library only; runs in the writer container as the application's account.

Subcommands
  seed --out FILE --size-mb N [--tables T] --journal-mode wal|delete|truncate|persist
      A database of about N MiB: T tables `load_t<NN>` (id, email, phone, note: fake values,
      `example.com` addresses and fiction-range phone numbers) and `load_writes`, the workload's
      table (10 000 rows). Written under a temporary name, then renamed. Prints one JSON line.
  hold FILE [--ready F]
      Keeps FILE open (a WAL database's -wal and -shm exist while it runs), until SIGTERM.
  run --db FILE --rate R --duration S --busy-timeout-ms B --records CSV --wal CSV [--stop-file F]
      The fixed workload: R transactions per second on a fixed schedule, each `BEGIN IMMEDIATE`,
      one INSERT and one UPDATE of `load_writes`, `COMMIT`, with `PRAGMA busy_timeout = B`. Until S
      seconds passed or F exists. Per transaction, a CSV line `start,latency_ms,ok,busy`: the
      commit latency (BEGIN to the end of COMMIT), whether it committed, and where SQLITE_BUSY /
      SQLITE_LOCKED was returned (`begin`, `write`, `commit` or empty; the transaction is then
      rolled back and counted failed). Every second, `time,bytes` of the -wal file. Prints a JSON
      summary (counts only).

Every database file is created with umask 027 (the directory's setgid group, 0640): the agent's
account reads it through its group and can write none of it. The CSV files are 0644 (read by the
harness on the host). Nothing printed is a value.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sqlite3
import sys
import time
from pathlib import Path

BUSY_CODES = {5, 6}  # SQLITE_BUSY, SQLITE_LOCKED (and their extended codes, & 0xff)
WRITES_ROWS = 10_000
FR_FICTION = ("019900", "026191", "035301", "046571", "053649", "063998", "097210")


def is_busy(e: sqlite3.Error) -> bool:
    code = getattr(e, "sqlite_errorcode", None)
    if code is not None:
        return (code & 0xFF) in BUSY_CODES
    msg = str(e).lower()
    return "locked" in msg or "busy" in msg


def cmd_seed(args: argparse.Namespace) -> int:
    os.umask(0o027)
    out = Path(args.out)
    if out.exists():
        print(json.dumps({"seeded": False, "reason": "exists", "bytes": out.stat().st_size}))
        return 0
    tmp = out.with_name(f".{out.name}.seeding")
    for p in (tmp, Path(f"{tmp}-journal"), Path(f"{tmp}-wal"), Path(f"{tmp}-shm")):
        if p.exists():
            p.unlink()
    r = random.Random(args.seed)
    t0 = time.time()
    con = sqlite3.connect(tmp, isolation_level=None)
    con.execute("PRAGMA page_size = 4096")
    if con.execute(f"PRAGMA journal_mode = {args.journal_mode}").fetchone()[0] != args.journal_mode:
        raise RuntimeError("journal mode not set")
    # The bulk load only: a crash midway leaves the temporary file, never the declared one.
    con.execute("PRAGMA synchronous = OFF")
    row_bytes = 1024
    rows = max(1, args.size_mb * 1024 * 1024 // row_bytes // args.tables)
    filler = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor "
    for t in range(1, args.tables + 1):
        name = f"load_t{t:02d}"
        con.execute(f"CREATE TABLE {name} (id INTEGER PRIMARY KEY, email TEXT NOT NULL, phone TEXT NOT NULL, "
                    "note TEXT NOT NULL)")
        batch = []
        for i in range(rows):
            p = r.choice(FR_FICTION) + f"{r.randrange(10_000):04d}"
            note = (filler * 12)[: row_bytes - 120] + f" {i}"
            batch.append((f"load{t}.{i}@example.com", " ".join(p[k:k + 2] for k in range(0, 10, 2)), note))
            if len(batch) == 10_000:
                con.execute("BEGIN")
                con.executemany(f"INSERT INTO {name} (email, phone, note) VALUES (?, ?, ?)", batch)
                con.execute("COMMIT")
                batch = []
        if batch:
            con.execute("BEGIN")
            con.executemany(f"INSERT INTO {name} (email, phone, note) VALUES (?, ?, ?)", batch)
            con.execute("COMMIT")
    con.execute("CREATE TABLE load_writes (id INTEGER PRIMARY KEY, k INTEGER NOT NULL, v TEXT NOT NULL)")
    con.execute("BEGIN")
    con.executemany("INSERT INTO load_writes (k, v) VALUES (?, ?)", ((i, "x" * 64) for i in range(WRITES_ROWS)))
    con.execute("COMMIT")
    con.execute("ANALYZE")
    con.close()
    os.rename(tmp, out)
    print(json.dumps({"seeded": True, "bytes": out.stat().st_size, "tables": args.tables, "rows_per_table": rows,
                      "journal_mode": args.journal_mode, "seconds": round(time.time() - t0, 1),
                      "sqlite_version": sqlite3.sqlite_version}))
    return 0


def cmd_hold(args: argparse.Namespace) -> int:
    stop: list[int] = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    con = sqlite3.connect(args.file, isolation_level=None)
    con.execute("SELECT count(*) FROM sqlite_schema").fetchone()
    if args.ready:
        Path(args.ready).write_text("ready\n", encoding="utf-8")
    print(f"[sqlite-load] holding the database open (SQLite {sqlite3.sqlite_version})", file=sys.stderr, flush=True)
    while not stop:
        time.sleep(0.2)
    con.close()
    return 0


def open_csv(path: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.fchmod(fd, 0o644)
    return os.fdopen(fd, "w", encoding="utf-8", buffering=1 << 16)


def cmd_run(args: argparse.Namespace) -> int:
    os.umask(0o027)
    stop: list[int] = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    con = sqlite3.connect(args.db, isolation_level=None)
    con.execute(f"PRAGMA busy_timeout = {int(args.busy_timeout_ms)}")
    journal = con.execute("PRAGMA journal_mode").fetchone()[0]
    wal_path = f"{args.db}-wal"
    r = random.Random(args.seed)
    rec = open_csv(args.records)
    wal = open_csv(args.wal)
    issued = committed = busy = failed = late = 0
    busy_at = {"begin": 0, "write": 0, "commit": 0}
    start = time.time() + 1.0
    period = 1.0 / args.rate
    next_wal = start
    k = 0
    while not stop:
        due = start + k * period
        now = time.time()
        if now - start >= args.duration or (args.stop_file and os.path.exists(args.stop_file)):
            break
        if now >= next_wal:
            try:
                size = os.stat(wal_path).st_size
            except FileNotFoundError:
                size = 0
            wal.write(f"{now:.3f},{size}\n")
            next_wal += 1.0
        if due > now:
            time.sleep(min(due - now, 0.05))
            continue
        if now - due > 0.1:
            late += 1
        k += 1
        issued += 1
        stage = "begin"
        t0 = time.time()
        ok = 0
        try:
            con.execute("BEGIN IMMEDIATE")
            stage = "write"
            con.execute("INSERT INTO load_writes (k, v) VALUES (?, ?)", (k, "y" * 64))
            con.execute("UPDATE load_writes SET v = ? WHERE id = ?", ("z" * 64, r.randrange(1, WRITES_ROWS + 1)))
            stage = "commit"
            con.execute("COMMIT")
            ok = 1
            stage = ""
            committed += 1
        except sqlite3.OperationalError as e:
            if not is_busy(e):
                raise
            busy += 1
            busy_at[stage] += 1
            failed += 1
            if con.in_transaction:
                con.execute("ROLLBACK")
        lat_ms = (time.time() - t0) * 1000.0
        rec.write(f"{t0:.4f},{lat_ms:.3f},{ok},{stage}\n")
    try:
        size = os.stat(wal_path).st_size
    except FileNotFoundError:
        size = 0
    wal.write(f"{time.time():.3f},{size}\n")
    rec.close()
    wal.close()
    con.close()
    print(json.dumps({"issued": issued, "committed": committed, "busy": busy, "failed": failed, "busy_at": busy_at,
                      "late_starts": late, "journal_mode": journal, "busy_timeout_ms": int(args.busy_timeout_ms),
                      "rate": args.rate, "elapsed_s": round(time.time() - start, 3),
                      "sqlite_version": sqlite3.sqlite_version}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--out", required=True)
    s.add_argument("--size-mb", type=int, required=True)
    s.add_argument("--tables", type=int, default=8)
    s.add_argument("--journal-mode", choices=("wal", "delete", "truncate", "persist"), required=True)
    s.add_argument("--seed", type=int, default=20261025)
    h = sub.add_parser("hold")
    h.add_argument("file")
    h.add_argument("--ready")
    r = sub.add_parser("run")
    r.add_argument("--db", required=True)
    r.add_argument("--rate", type=float, required=True)
    r.add_argument("--duration", type=float, required=True)
    r.add_argument("--busy-timeout-ms", type=int, required=True)
    r.add_argument("--records", required=True)
    r.add_argument("--wal", required=True)
    r.add_argument("--stop-file")
    r.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    if args.cmd == "seed" and (args.size_mb < 1 or args.tables < 1):
        ap.error("--size-mb and --tables must be positive")
    if args.cmd == "run" and (args.rate <= 0 or args.duration <= 0 or args.busy_timeout_ms < 0):
        ap.error("--rate and --duration must be positive, --busy-timeout-ms not negative")
    return {"seed": cmd_seed, "hold": cmd_hold, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
