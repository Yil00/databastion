//! Regression test of a heap-buffer over-read in the bundled SQLite 3.53.2,
//! found by the `sqlite_file` fuzz target under AddressSanitizer:
//! `walChecksumBytes` <- `walDecodeFrame` <- `walBeginShmUnreliable`.
//!
//! The file set: a WAL-mode main file, an empty `-shm` that nobody holds
//! (the reader opens it `readonly_shm=1`, so SQLite builds its heap copy of
//! the WAL index from the `-wal`), and a `-wal` whose header has an invalid
//! magic and a zero salt, followed by a frame with a non-zero page number
//! and a zero salt. Recovery leaves the heap WAL index with `szPage = 0`;
//! 3.53.2 then allocated a 24-byte frame buffer and checksummed a page past
//! it. SQLite 3.54.1 returns early from `walDecodeFrame` when the page size
//! is 0. Without AddressSanitizer the over-read is silent, so this test
//! asserts the linked version and the reader's result; the same input is a
//! seed of the fuzz target (`agent/fuzz/sqlite_seed.py`), which the nightly
//! campaign runs under AddressSanitizer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use databastion_connector_sqlite::files::{Policy, side_path};
use databastion_connector_sqlite::ipc::{OpenRequest, Request, Response};
use databastion_connector_sqlite::reader::Session;

/// A private directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "databastion-sqlite-walzero-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The main file (WAL mode, one row), then the hostile `-wal` and the
/// empty `-shm`.
fn write_set(main: &Path) {
    let c = rusqlite::Connection::open(main).unwrap();
    c.execute_batch(
        "PRAGMA page_size = 512; PRAGMA journal_mode = WAL;
         CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT);
         INSERT INTO t (email) VALUES ('fake@example.com');
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
    drop(c);
    let header = std::fs::read(main).unwrap();
    assert_eq!(header.get(18..20), Some(&[2u8, 2][..]), "not a WAL file");
    // The -wal header: an invalid magic, then zeros (the salt at 16..24
    // among them).
    let mut wal = vec![0xde, 0xad, 0xbe, 0xef];
    wal.resize(32, 0);
    // One frame: page number 1, the rest of its header zero (salt
    // included), and a page of zeros.
    wal.extend_from_slice(&1u32.to_be_bytes());
    wal.resize(32 + 24 + 512, 0);
    std::fs::write(side_path(main, "-wal"), &wal).unwrap();
    std::fs::write(side_path(main, "-shm"), b"").unwrap();
}

#[test]
fn the_bundled_sqlite_has_the_wal_page_size_fix() {
    let version = databastion_connector_sqlite::db::expected().version;
    let parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap()).collect();
    assert!(parts >= vec![3, 54, 1], "SQLite {version} < 3.54.1");
}

#[test]
fn a_heap_wal_index_with_page_size_zero_is_read_without_its_frames() {
    let d = Dir::new("reader");
    let main = d.0.join("zero.db");
    write_set(&main);
    let req = OpenRequest {
        path: zeroize::Zeroizing::new(databastion_connector_sqlite::files::path_bytes(&main)),
        max_statement_ms: 1_000,
        rollback_read: true,
    };
    // The test's own files: the writability and read-only mount rules
    // cannot hold here (as in the fuzz harness); everything else is the
    // production pipeline.
    let policy = Policy {
        refuse_agent_writable: false,
        require_read_only_fs: false,
        exact_descriptor_set: false,
        open_no_links: true,
    };
    let (mut s, _) = Session::open(&req, policy, None).expect("open");
    // The invalid -wal holds no valid frame: the catalog and the row come
    // from the main file.
    let Response::Catalog(rows, false) = s.handle(&Request::Catalog) else {
        panic!("catalog failed");
    };
    assert!(rows.iter().any(|r| r.name.as_slice() == b"t" && !r.view));
    let Response::Bounds(Some((1, 1))) = s.handle(&Request::Bounds(
        zeroize::Zeroizing::new(b"t".to_vec()),
        databastion_connector_sqlite::ipc::RowidAlias::Rowid,
    )) else {
        panic!("bounds");
    };
    assert!(matches!(s.handle(&Request::Close), Response::Closed));
    // Nothing was written next to the files.
    assert_eq!(
        std::fs::metadata(side_path(&main, "-shm")).unwrap().len(),
        0
    );
}

/// The same set through the fuzz entry point, as the seed of
/// `agent/fuzz/sqlite_seed.py` (the heap WAL index pass only: without a
/// `-shm` helper, the reliable `-shm` pass is not run; the heap pass is
/// the one that over-read).
#[cfg(feature = "fuzzing")]
#[test]
fn the_fuzz_entry_point_takes_the_set() {
    let d = Dir::new("fuzz");
    let main = d.0.join("seed.db");
    write_set(&main);
    let mut input = Vec::new();
    for f in [
        main.clone(),
        side_path(&main, "-wal"),
        side_path(&main, "-shm"),
    ] {
        let bytes = std::fs::read(f).unwrap();
        let len = u32::try_from(bytes.len()).unwrap().to_be_bytes();
        input.extend_from_slice(&len[1..]);
        input.extend_from_slice(&bytes);
    }
    databastion_connector_sqlite::fuzz::file(&input, None);
}
