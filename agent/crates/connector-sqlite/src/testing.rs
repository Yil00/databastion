//! Test support (this crate's tests, and other crates' tests through the
//! `test-support` feature; never the agent binary): seeded SQLite files and
//! a writer that keeps a WAL database open, as an application would. Uses
//! `rusqlite` read-write, which the connector itself never does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use rusqlite::Connection;

/// A seeded file: personal data in TEXT and INTEGER
/// columns, a `WITHOUT ROWID` and a `STRICT` table, a view, generated
/// columns, a table declaring `rowid`, a value above 64 KiB and one above
/// `SQLITE_LIMIT_LENGTH`.
pub fn seed(path: &Path, wal: bool) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(if wal {
        "PRAGMA journal_mode = WAL;"
    } else {
        "PRAGMA journal_mode = DELETE;"
    })
    .unwrap();
    c.execute_batch(
        "CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, phone INTEGER, note BLOB, score REAL,
             initial TEXT GENERATED ALWAYS AS (substr(email, 1, 1)) VIRTUAL,
             domain TEXT GENERATED ALWAYS AS (substr(email, instr(email, '@') + 1)) STORED);
         CREATE TABLE contacts (email TEXT PRIMARY KEY, iban TEXT) WITHOUT ROWID;
         CREATE TABLE strict_t (k INTEGER PRIMARY KEY, mail TEXT) STRICT;
         CREATE TABLE odd (rowid TEXT, _rowid_ TEXT, mail TEXT);
         CREATE TABLE big (v TEXT);
         CREATE VIEW v_clients AS SELECT email FROM clients;
         CREATE INDEX clients_email ON clients(email);",
    )
    .unwrap();
    for i in 0..50 {
        c.execute(
            "INSERT INTO clients (email, phone, note, score) VALUES (?1, ?2, ?3, 1.5)",
            rusqlite::params![
                format!("user{i}@example.com"),
                33_612_345_000_i64 + i,
                b"\x00blob".to_vec()
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO contacts VALUES (?1, 'FR7630006000011234567890189')",
            [format!("c{i:02}@example.org")],
        )
        .unwrap();
        c.execute(
            "INSERT INTO strict_t (mail) VALUES (?1)",
            [format!("s{i}@example.net")],
        )
        .unwrap();
        c.execute(
            "INSERT INTO odd VALUES ('a', 'b', ?1)",
            [format!("o{i}@example.net")],
        )
        .unwrap();
    }
    c.execute("INSERT INTO big VALUES (?1)", ["x".repeat(70_000)])
        .unwrap();
    c.execute("INSERT INTO big VALUES (?1)", ["y".repeat(2_000_000)])
        .unwrap();
    c.execute("INSERT INTO big VALUES ('z@example.com')", [])
        .unwrap();
    c.execute_batch("ANALYZE;").unwrap();
}

/// A writer that keeps a database open (its `-wal` and `-shm` exist in WAL
/// mode) and writes rows on demand.
pub struct Writer(Connection);

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

impl Writer {
    /// Opens `path` read-write.
    #[must_use]
    pub fn open(path: &Path) -> Self {
        Self(Connection::open(path).unwrap())
    }

    /// Inserts one row into `clients`.
    pub fn insert_email(&self, email: &str) {
        self.0
            .execute("INSERT INTO clients (email) VALUES (?1)", [email])
            .unwrap();
    }
}
