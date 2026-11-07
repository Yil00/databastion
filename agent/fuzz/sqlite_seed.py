"""Writes seven seed inputs of the sqlite_file fuzz target (ADR-0059), fake values only:

- OUT: a small SQLite file in rollback mode, as the target's first length-prefixed part;
- OUT-wal: a WAL file set (the main file, its -wal and the start of its -shm, saved while a
  connection holds them open), small enough for -max_len=4096: page size 512, and the -shm
  cut after its header and first page-number entries (the harness pads it with zeros to a
  whole region; the cut hash table finds no frame, so pages come from the main file). The
  target runs it on the heap WAL index and on the reliable -shm path (its helper holds the
  DMS lock).
- OUT-wal-page-size-zero: the regression input of the heap-buffer over-read SQLite 3.54.1
  fixed in walDecodeFrame (bundled SQLite 3.53.2, found by this target): a WAL-mode main
  file, an empty -shm, and a -wal whose header has an invalid magic and a zero salt (bytes
  16..24), then a frame with page number 1 and a zero salt. With nobody holding the DMS
  lock, the heap WAL index recovered from it has szPage = 0, and 3.53.2 checksummed a
  frame buffer of 24 bytes as if it held a page (crates/connector-sqlite/tests/
  wal_page_size_zero.rs builds the same set).
- OUT-names: a small file whose schema text names its INTEGER PRIMARY KEY column with a byte
  that is not valid UTF-8 (fuzz nightly run 42322811219: rusqlite's authorizer conversion
  panicked on that name when a statement named the rowid).
- OUT-exprs: a small file whose columns have DEFAULT and STORED generated expressions, listed
  (lower, CURRENT_TIMESTAMP) and not (randomblob), which SQLite 3.54 sends to the authorizer
  when a sampling statement reads them (ADR-0059 refinement of 2026-11-07).
- OUT-stored-names: a STORED generated column whose expression names a function that is not
  valid UTF-8 (SQLite does not report it while it parses the schema; security review M1 of
  #425).
- OUT-stat1: a crafted sqlite_stat1 whose stat column has a DEFAULT naming such a function
  (security review M1 of #425).

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
    with open(out + "-wal-page-size-zero", "wb") as f:
        f.write(wal_page_size_zero())
    with open(out + "-names", "wb") as f:
        f.write(part(non_utf8_names()))
    with open(out + "-exprs", "wb") as f:
        f.write(part(schema_exprs()))
    with open(out + "-stored-names", "wb") as f:
        f.write(part(rewritten_schema(
            "",
            "t",
            b"CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT GENERATED ALWAYS AS (g\xe4(a)) STORED)",
        )))
    with open(out + "-stat1", "wb") as f:
        f.write(part(rewritten_schema(
            "ANALYZE;",
            "sqlite_stat1",
            b"CREATE TABLE sqlite_stat1(tbl,idx,stat DEFAULT (g\xe4(1)))",
        )))


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


def wal_page_size_zero() -> bytes:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "zero.db")
        c = sqlite3.connect(path, isolation_level=None)
        c.executescript(
            """
            PRAGMA page_size = 512;
            PRAGMA journal_mode = WAL;
            CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT);
            INSERT INTO t (email) VALUES ('fake@example.com');
            PRAGMA wal_checkpoint(TRUNCATE);
            """
        )
        c.close()
        main = open(path, "rb").read()
    # The -wal header: an invalid magic, then zeros (format version, page size, checkpoint
    # sequence, the salt at bytes 16..24 and the checksum).
    wal = bytes.fromhex("deadbeef") + bytes(28)
    # One frame: page number 1, a zero commit size and a zero salt, a zero checksum, and a
    # page of zeros.
    wal += (1).to_bytes(4, "big") + bytes(20) + bytes(512)
    return part(main) + part(wal) + part(b"")


def non_utf8_names() -> bytes:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "names.db")
        c = sqlite3.connect(path, isolation_level=None)
        c.executescript(
            """
            PRAGMA page_size = 512;
            PRAGMA journal_mode = DELETE;
            CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT);
            INSERT INTO t (email) VALUES ('fake@example.com');
            PRAGMA writable_schema = ON;
            """
        )
        c.execute(
            "UPDATE sqlite_schema SET sql = CAST(? AS TEXT) WHERE name = 't'",
            (b"CREATE TABLE t (i\xff INTEGER PRIMARY KEY, email TEXT)",),
        )
        c.execute("PRAGMA writable_schema = OFF")
        c.close()
        return open(path, "rb").read()



def schema_exprs() -> bytes:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "exprs.db")
        c = sqlite3.connect(path, isolation_level=None)
        c.executescript(
            """
            PRAGMA page_size = 512;
            PRAGMA journal_mode = DELETE;
            CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT,
                low TEXT GENERATED ALWAYS AS (lower(email)) STORED,
                created TEXT DEFAULT CURRENT_TIMESTAMP,
                token TEXT DEFAULT (hex(randomblob(4))));
            INSERT INTO t (email) VALUES ('Fake@Example.com');
            """
        )
        c.close()
        return open(path, "rb").read()


def rewritten_schema(extra: str, name: str, schema: bytes) -> bytes:
    """A small file with a table t of two rows, then `extra` (a script), then the schema text
    of `name` replaced by `schema` (bytes, possibly not valid UTF-8): a hostile file."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "rewritten.db")
        c = sqlite3.connect(path, isolation_level=None)
        c.executescript(
            "PRAGMA page_size = 512; PRAGMA journal_mode = DELETE; "
            "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT); "
            "INSERT INTO t (a, b) VALUES ('x@example.com', 'y@example.org'); " + extra
        )
        c.execute("PRAGMA writable_schema = ON")
        c.execute(
            "UPDATE sqlite_schema SET sql = CAST(? AS TEXT) WHERE name = ?", (schema, name)
        )
        c.execute("PRAGMA writable_schema = OFF")
        c.close()
        return open(path, "rb").read()

if __name__ == "__main__":
    main(sys.argv[1])
