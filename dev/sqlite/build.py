#!/usr/bin/env python3
"""Writes and holds the dev SQLite databases (ADR-0059 decision 10). Python standard library only.

The files are written by the SQLite library of the Python that runs this script (`sqlite3`), so
the same committed content (dev/seed/out/sqlite.json and its SQL scripts, from dev/seed/generate.py)
can be written by several SQLite versions: the dev and e2e sidecar (the pinned Python image), the
engine matrix's writers (the Python images of the supported distributions, the runner's
python3). The agent reads every file with its own bundled library, never this one.

Subcommands
  build  --manifest M --out DIR [--journal-mode J] [--page-size N] [--auto-vacuum A]
         [--without MODULE]... [--if-missing]
      Writes every file of the manifest into DIR, with the journal mode and encoding of the
      manifest unless overridden. A file is written under a temporary name, then renamed, so that a
      writer killed midway never leaves a partial database under the declared name.
  matrix --manifest M --out DIR [--without MODULE]... [--hold] [--ready FILE]
      The engine matrix's variants: every file of the manifest in each journal mode (DELETE,
      TRUNCATE, PERSIST, WAL), page size (512, 4096, 65536) and `auto_vacuum` (NONE, FULL), as
      `<stem>-<journal>-p<page size>-av<0|1>.db`, and DIR/variants.json describing them. With --hold,
      then holds the WAL files open (as `hold`).
  hold   DIR [--ready FILE] [--write-every S]
      The application: keeps every WAL-mode database of DIR open (so its `-wal` and `-shm` exist, as
      with a running application; ADR-0059 decision 3), writes FILE once they are all open, and with
      --write-every inserts a row into `writer_heartbeat` of each held file that has that table
      every S seconds. Runs until SIGTERM / SIGINT.
  serve  --manifest M --out DIR [--ready FILE] [--write-every S]
      `build --if-missing`, then `hold`: the dev and e2e sidecar (Compose profile `sqlite`).
  truncate-shm FILE
      Truncates the `-shm` of FILE to 0 bytes (the e2e run's "truncated -shm during a scan": every
      process mapping it, the agent's reader included, gets SIGBUS at its next access).

Every file is created with umask 027 (0640, the group of the directory when it has the setgid bit):
the agent's account reads them through its group and can write none of them (ADR-0059 decision 2).
Nothing is printed but counts, names of files and versions: never a value.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path

JOURNAL_MODES = ("delete", "truncate", "persist", "wal")
PAGE_SIZES = (512, 4096, 65536)
AUTO_VACUUM = ("none", "full")
ENCODINGS = ("UTF-8", "UTF-16le", "UTF-16be")
REQUIRES = "-- databastion:requires "
REQUIRES_END = "-- databastion:end"
HEARTBEAT_TABLE = "writer_heartbeat"


def log(msg: str) -> None:
    print(f"[sqlite-dev] {msg}", file=sys.stderr, flush=True)


def has_module(module: str) -> bool:
    """Whether this Python's SQLite has the module (FTS5 only, today)."""
    if module != "fts5":
        return False
    con = sqlite3.connect(":memory:")
    try:
        return bool(con.execute("SELECT sqlite_compileoption_used('ENABLE_FTS5')").fetchone()[0])
    finally:
        con.close()


def strip_blocks(sql: str, without: set[str]) -> tuple[str, set[str]]:
    """The script without its `requires` blocks of the modules in `without`; and the modules of the
    blocks it keeps. An unknown module, a missing end marker or a nested block is an error."""
    out: list[str] = []
    kept: set[str] = set()
    current: str | None = None
    for line in sql.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(REQUIRES):
            if current is not None:
                raise ValueError("nested requires block")
            current = stripped[len(REQUIRES):].strip()
            if current != "fts5":
                raise ValueError(f"unknown module {current!r}")
            continue
        if stripped == REQUIRES_END:
            if current is None:
                raise ValueError("end marker outside a block")
            if current not in without:
                kept.add(current)
            current = None
            continue
        if current is None or current not in without:
            out.append(line)
    if current is not None:
        raise ValueError("requires block not closed")
    return "".join(out), kept


def load_manifest(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    if m.get("version") != 1:
        raise ValueError("unsupported manifest version")
    files = m["files"]
    for e in files:
        name = e["file"]
        if "/" in name or not name.endswith(".db") or name.startswith("."):
            raise ValueError(f"bad file name {name!r}")
        if e["journal_mode"] not in JOURNAL_MODES or e["encoding"] not in ENCODINGS:
            raise ValueError(f"{name}: bad journal mode or encoding")
        e["sql_text"] = (path.parent / e["sql"]).read_text(encoding="utf-8")
    return files


def header(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(100)


def write_db(path: Path, sql: str, journal_mode: str, encoding: str, page_size: int,
             auto_vacuum: str) -> None:
    """Writes one database under a temporary name, then renames it to `path`."""
    if journal_mode not in JOURNAL_MODES or page_size not in PAGE_SIZES or auto_vacuum not in AUTO_VACUUM \
            or encoding not in ENCODINGS:
        raise ValueError("bad pragma value")
    tmp = path.with_name(f".{path.name}.building")
    for p in (tmp, Path(f"{tmp}-journal"), Path(f"{tmp}-wal"), Path(f"{tmp}-shm")):
        if p.exists():
            p.unlink()
    con = sqlite3.connect(tmp, isolation_level=None)
    try:
        # Before the first table: the page size, auto_vacuum and the text encoding are fixed then.
        con.execute(f"PRAGMA page_size = {page_size}")
        con.execute(f"PRAGMA auto_vacuum = {auto_vacuum}")
        con.execute(f"PRAGMA encoding = '{encoding}'")
        got = con.execute(f"PRAGMA journal_mode = {journal_mode}").fetchone()[0]
        if got != journal_mode:
            raise RuntimeError(f"journal mode {journal_mode} not set ({got})")
        con.executescript(sql)
        if con.execute("PRAGMA page_size").fetchone()[0] != page_size:
            raise RuntimeError("page size not applied")
        if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("integrity check failed")
    finally:
        con.close()
    # A rollback-mode connection leaves its -journal in TRUNCATE (0 bytes) and PERSIST (zeroed header)
    # modes: renamed with the file, as an application's would be there.
    for suffix in ("-journal",):
        side = Path(f"{tmp}{suffix}")
        if side.exists():
            os.rename(side, Path(f"{path}{suffix}"))
    os.rename(tmp, path)
    h = header(path)
    if h[:16] != b"SQLite format 3\0" or (h[18] == 2) != (journal_mode == "wal"):
        raise RuntimeError(f"{path.name}: unexpected header")


def cmd_build(args: argparse.Namespace) -> int:
    files = load_manifest(Path(args.manifest))
    out = Path(args.out)
    without = set(args.without)
    for m in without:
        if m != "fts5":
            raise ValueError(f"unknown module {m!r}")
    for e in files:
        path = out / e["file"]
        if path.exists() and args.if_missing:
            log(f"{e['file']}: present, kept")
            continue
        if path.exists():
            raise FileExistsError(f"{e['file']} exists (use another directory)")
        sql, kept = strip_blocks(e["sql_text"], without)
        for module in kept:
            if not has_module(module):
                raise RuntimeError(f"{e['file']}: this SQLite has no {module} (pass --without {module})")
        write_db(path, sql, args.journal_mode or e["journal_mode"], e["encoding"], args.page_size,
                 args.auto_vacuum)
        log(f"{e['file']}: written ({args.journal_mode or e['journal_mode']}, {e['encoding']}, "
            f"page size {args.page_size}, auto_vacuum {args.auto_vacuum}, SQLite {sqlite3.sqlite_version})")
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    files = load_manifest(Path(args.manifest))
    out = Path(args.out)
    without = set(args.without)
    variants = []
    for e, jm, ps, av in itertools.product(files, JOURNAL_MODES, PAGE_SIZES, AUTO_VACUUM):
        name = f"{e['file'][:-3]}-{jm}-p{ps}-av{AUTO_VACUUM.index(av)}.db"
        sql, kept = strip_blocks(e["sql_text"], without)
        for module in kept:
            if not has_module(module):
                raise RuntimeError(f"this SQLite has no {module} (pass --without {module})")
        write_db(out / name, sql, jm, e["encoding"], ps, av)
        variants.append({"file": name, "base": e["file"], "journal_mode": jm, "page_size": ps,
                         "auto_vacuum": av, "encoding": e["encoding"], "modules": sorted(kept)})
    doc = {"version": 1, "sqlite_version": sqlite3.sqlite_version,
           "python": sys.version.split()[0], "variants": variants}
    tmp = out / ".variants.json.tmp"
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.rename(tmp, out / "variants.json")
    log(f"{len(variants)} variant file(s) written by SQLite {sqlite3.sqlite_version}")
    if args.hold:
        return hold(out, args.ready, 0.0)
    return 0


def wal_files(directory: Path) -> list[Path]:
    out = []
    for p in sorted(directory.iterdir()):
        if p.suffix != ".db" or not p.is_file() or p.name.startswith("."):
            continue
        h = header(p)
        if len(h) == 100 and h[:16] == b"SQLite format 3\0" and h[18] == 2:
            out.append(p)
    return out


def hold(directory: Path, ready: str | None, write_every: float) -> int:
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    cons: list[tuple[Path, sqlite3.Connection, bool]] = []
    for p in wal_files(directory):
        con = sqlite3.connect(p, isolation_level=None, timeout=5.0)
        # A read creates the -wal and the -shm and takes the -shm's DMS lock until the connection
        # closes.
        con.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        beats = con.execute("SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?",
                            (HEARTBEAT_TABLE,)).fetchone()[0] == 1
        cons.append((p, con, beats))
    log(f"holding {len(cons)} WAL database(s) open (SQLite {sqlite3.sqlite_version})")
    if ready:
        Path(ready).write_text("ready\n", encoding="utf-8")
    n = 0
    next_beat = time.monotonic() + write_every
    while not stop:
        time.sleep(0.2)
        if write_every > 0 and time.monotonic() >= next_beat:
            n += 1
            for _, con, beats in cons:
                if beats:
                    con.execute(f"INSERT INTO {HEARTBEAT_TABLE} (beat) VALUES (?)", (n,))
            next_beat += write_every
    for _, con, _ in cons:
        con.close()
    log(f"stopped after {n} heartbeat write(s)")
    return 0


def cmd_hold(args: argparse.Namespace) -> int:
    return hold(Path(args.dir), args.ready, args.write_every)


def cmd_serve(args: argparse.Namespace) -> int:
    args.if_missing = True
    args.journal_mode = None
    args.page_size = 4096
    args.auto_vacuum = "none"
    args.without = []
    cmd_build(args)
    return hold(Path(args.out), args.ready, args.write_every)


def cmd_truncate_shm(args: argparse.Namespace) -> int:
    shm = Path(f"{args.file}-shm")
    os.truncate(shm, 0)
    log(f"{shm.name}: truncated to 0 bytes")
    return 0


def main(argv: list[str] | None = None) -> int:
    os.umask(0o027)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--manifest", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--journal-mode", choices=JOURNAL_MODES)
    b.add_argument("--page-size", type=int, choices=PAGE_SIZES, default=4096)
    b.add_argument("--auto-vacuum", choices=AUTO_VACUUM, default="none")
    b.add_argument("--without", action="append", default=[], choices=["fts5"])
    b.add_argument("--if-missing", action="store_true")
    m = sub.add_parser("matrix")
    m.add_argument("--manifest", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--without", action="append", default=[], choices=["fts5"])
    m.add_argument("--hold", action="store_true")
    m.add_argument("--ready")
    h = sub.add_parser("hold")
    h.add_argument("dir")
    h.add_argument("--ready")
    h.add_argument("--write-every", type=float, default=0.0)
    s = sub.add_parser("serve")
    s.add_argument("--manifest", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--ready")
    s.add_argument("--write-every", type=float, default=0.0)
    t = sub.add_parser("truncate-shm")
    t.add_argument("file")
    args = ap.parse_args(argv)
    return {"build": cmd_build, "matrix": cmd_matrix, "hold": cmd_hold, "serve": cmd_serve,
            "truncate-shm": cmd_truncate_shm}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
