"""Writes one seed input of the sqlite_file fuzz target (ADR-0059): a small SQLite file in
rollback mode with fake values only, as the target's first length-prefixed part.

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
        f.write(len(data).to_bytes(3, "big") + data)


if __name__ == "__main__":
    main(sys.argv[1])
