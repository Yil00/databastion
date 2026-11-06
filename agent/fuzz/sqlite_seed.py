"""Writes two seed inputs of the sqlite_file fuzz target (ADR-0059), fake values only:

- OUT: a small SQLite file in rollback mode, as the target's first length-prefixed part;
- OUT-wal: a WAL file set (the main file, its -wal and the start of its -shm, saved while a
  connection holds them open), small enough for -max_len=4096: page size 512, and the -shm
  cut after its header and first page-number entries (the harness pads it with zeros to a
  whole region; the cut hash table finds no frame, so pages come from the main file). The
  target runs it on the heap WAL index and on the reliable -shm path (its helper holds the
  DMS lock).

    python3 -I sqlite_seed.py OUT
"""

import os
import sqlite3
import sys
import tempfile


def main(out: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "seed.db")
        c = sqlite3.connect(path)
        c.executescript(
            """
            PRAGMA journal_mode = DELETE;
            CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, phone INTEGER);
            CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;
            CREATE VIEW v AS SELECT email FROM clients;
            INSERT INTO clients (email, phone) VALUES ('fake@example.com', 33600000000);
            INSERT INTO kv VALUES ('a', 'b');
            """
        )
        c.commit()
        c.close()
        data = open(path, "rb").read()
    with open(out, "wb") as f:
        f.write(part(data))
    with open(out + "-wal", "wb") as f:
        f.write(wal_set())


# The -shm bytes kept: the two copies of the WAL index header and the checkpoint info (136
# bytes), then the page numbers of the first frames.
SHM_KEPT = 256


def part(data: bytes) -> bytes:
    return len(data).to_bytes(3, "big") + data


def wal_set() -> bytes:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "wal.db")
        c = sqlite3.connect(path, isolation_level=None)
        c.executescript(
            """
            PRAGMA page_size = 512;
            PRAGMA journal_mode = WAL;
            PRAGMA wal_autocheckpoint = 0;
            CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT);
            INSERT INTO t (email) VALUES ('fake@example.com');
            PRAGMA wal_checkpoint(TRUNCATE);
            INSERT INTO t (email) VALUES ('other@example.org');
            """
        )
        c.execute("SELECT count(*) FROM t").fetchone()
        files = [open(path + suffix, "rb").read() for suffix in ("", "-wal", "-shm")]
        c.close()
    files[2] = files[2][:SHM_KEPT]
    return b"".join(part(f) for f in files)


if __name__ == "__main__":
    main(sys.argv[1])
