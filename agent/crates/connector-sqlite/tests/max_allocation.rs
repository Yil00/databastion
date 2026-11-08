//! `SQLITE_MAX_ALLOCATION_SIZE` by behaviour (ADR-0059 decision 1): the
//! option is not printed by `PRAGMA compile_options`, so it is checked by
//! what it does. Its own test binary (its own process): the heap limit the
//! reader sets (`hard_heap_limit`) is process-wide, and the other tests'
//! sessions set it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusqlite::Connection;

/// With `SQLITE_LIMIT_LENGTH` at its default (1e9), materializing a value
/// of 32 MiB + 1 byte fails with `SQLITE_NOMEM`; one 1 KiB under 32 MiB
/// does not.
#[test]
fn single_allocations_are_capped_at_32_mib() {
    let c = Connection::open_in_memory().unwrap();
    for f in ["randomblob", "zeroblob"] {
        let over = c
            .query_row(
                &format!("SELECT octet_length(CAST({f}(33554433) AS BLOB) || x'00')"),
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_err();
        assert!(
            matches!(
                over,
                rusqlite::Error::SqliteFailure(ref e, _) if e.extended_code == 7
            ),
            "{f}: not SQLITE_NOMEM"
        );
        let under: i64 = c
            .query_row(
                &format!("SELECT octet_length(CAST({f}(33553408) AS BLOB) || x'00')"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(under, 33_553_409, "{f}");
    }
}
