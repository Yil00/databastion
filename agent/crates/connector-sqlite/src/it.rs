//! In-process integration tests of the reader's session (ADR-0059
//! decisions 2, 3, 5 and 6) against real SQLite files created by the tests
//! themselves, read through `reader::Session` with the relaxed test policy
//! (every file a test creates is its own; tests may run as root). The
//! reader process itself (sandbox, IPC, `SIGKILL`, `SIGBUS`), the strict
//! policy on a read-only mount and the writer in another process are
//! tested by `crates/agent/tests/sqlite_reader.rs` with the agent binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::files::Policy;
use crate::ipc::{
    Code, OpenRequest, Request, Response, RowidAlias, SampleRange, SampleRequest, Sampled,
};
use crate::reader::Session;

/// A private directory for one test, removed on drop.
pub(crate) struct Dir(pub(crate) PathBuf);

impl Dir {
    pub(crate) fn new(name: &str) -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "databastion-sqlite-it-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    pub(crate) fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn z(b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b.to_vec())
}

fn open_req(path: &Path, rollback_read: bool) -> OpenRequest {
    OpenRequest {
        path: z(path.as_os_str().as_encoded_bytes()),
        max_statement_ms: 500,
        rollback_read,
    }
}

fn session(path: &Path) -> Session {
    Session::open(&open_req(path, true), Policy::TESTS, None)
        .unwrap()
        .0
}

fn open_code(path: &Path, rollback_read: bool, policy: Policy) -> Code {
    match Session::open(&open_req(path, rollback_read), policy, None) {
        Ok(_) => panic!("opened"),
        Err(f) => f.code,
    }
}

pub(crate) use crate::testing::seed;

fn catalog(s: &mut Session) -> Vec<(bool, String, i64)> {
    match s.handle(&Request::Catalog) {
        Response::Catalog(rows, false) => rows
            .into_iter()
            .map(|r| {
                (
                    r.view,
                    String::from_utf8(r.name.to_vec()).unwrap(),
                    r.rootpage,
                )
            })
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn columns(s: &mut Session, t: &str) -> Vec<(String, i64)> {
    match s.handle(&Request::Columns(z(t.as_bytes()))) {
        Response::Columns(c) => c
            .into_iter()
            .map(|c| (String::from_utf8(c.name.to_vec()).unwrap(), c.hidden))
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn sample(
    s: &mut Session,
    t: &str,
    alias: Option<RowidAlias>,
    cols: &[&str],
    range: SampleRange,
    limit: u32,
) -> Response {
    s.handle(&Request::Sample(SampleRequest {
        table: z(t.as_bytes()),
        alias,
        columns: cols.iter().map(|c| z(c.as_bytes())).collect(),
        range,
        limit,
    }))
}

fn sampled(r: Response) -> Sampled {
    match r {
        Response::Sample(s) => s,
        other => panic!("{other:?}"),
    }
}

fn texts(s: &Sampled, col: usize) -> Vec<Option<String>> {
    s.values[col]
        .iter()
        .map(|v| v.as_ref().map(|b| String::from_utf8(b.to_vec()).unwrap()))
        .collect()
}

#[test]
fn a_rollback_file_is_read_with_the_opt_in_only() {
    let d = Dir::new("rollback");
    let p = d.path("crm.db");
    seed(&p, false);
    assert_eq!(open_code(&p, false, Policy::TESTS), Code::RollbackNotRead);
    let mut s = session(&p);
    let cat = catalog(&mut s);
    let names: Vec<&str> = cat.iter().map(|(_, n, _)| n.as_str()).collect();
    for n in [
        "clients",
        "contacts",
        "strict_t",
        "odd",
        "big",
        "v_clients",
        "sqlite_stat1",
    ] {
        assert!(names.contains(&n), "{n} in {names:?}");
    }
    assert!(cat.iter().any(|(view, n, _)| *view && n == "v_clients"));
    // The generated columns: VIRTUAL hidden 2, STORED hidden 3.
    let cols = columns(&mut s, "clients");
    assert!(cols.contains(&("initial".to_owned(), 2)));
    assert!(cols.contains(&("domain".to_owned(), 3)));
    // Rowid bounds, then a sample from a start key and the wrap-around.
    let r = s.handle(&Request::Bounds(z(b"clients"), RowidAlias::Rowid));
    assert_eq!(r, Response::Bounds(Some((1, 50))));
    let a = sampled(sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email", "phone", "note", "score", "domain"],
        SampleRange::From(41),
        1000,
    ));
    assert_eq!(a.rows, 10);
    assert_eq!(a.last_rowid, Some(50));
    assert_eq!(texts(&a, 0)[0].as_deref(), Some("user40@example.com"));
    // INTEGER values as decimal text; BLOB and REAL not sampled.
    assert_eq!(texts(&a, 1)[0].as_deref(), Some("33612345040"));
    assert!(texts(&a, 2).iter().all(Option::is_none));
    assert!(texts(&a, 3).iter().all(Option::is_none));
    assert_eq!(texts(&a, 4)[0].as_deref(), Some("example.com"));
    let b = sampled(sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email"],
        SampleRange::Below(41),
        1000,
    ));
    assert_eq!(b.rows, 40);
    let c = sampled(sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email"],
        SampleRange::Between(10, 12),
        1000,
    ));
    assert_eq!(c.rows, 2);
    // WITHOUT ROWID: no rowid, then the plain read in both orders.
    let r = s.handle(&Request::Bounds(z(b"contacts"), RowidAlias::Rowid));
    assert!(
        matches!(r, Response::Failed(f) if f.code == Code::NoRowid),
        "{r:?}"
    );
    let fwd = sampled(sample(
        &mut s,
        "contacts",
        None,
        &["email"],
        SampleRange::Plain { reverse: false },
        2,
    ));
    let rev = sampled(sample(
        &mut s,
        "contacts",
        None,
        &["email"],
        SampleRange::Plain { reverse: true },
        2,
    ));
    assert_eq!(fwd.rows, 2);
    assert_ne!(texts(&fwd, 0), texts(&rev, 0));
    // A table declaring `rowid` and `_rowid_`: addressed as `oid`.
    let r = s.handle(&Request::Bounds(z(b"odd"), RowidAlias::Oid));
    assert_eq!(r, Response::Bounds(Some((1, 50))));
    // Values above 64 KiB, and above SQLITE_LIMIT_LENGTH (1 MiB), are
    // skipped without failing the statement: typeof() and octet_length()
    // do not load them (ADR-0059 "to verify").
    let big = sampled(sample(
        &mut s,
        "big",
        Some(RowidAlias::Rowid),
        &["v"],
        SampleRange::From(1),
        10,
    ));
    assert_eq!(
        texts(&big, 0),
        [None, None, Some("z@example.com".to_owned())]
    );
    // A view is never sampled: ENABLE_VIEW is off.
    let r = sample(
        &mut s,
        "v_clients",
        None,
        &["email"],
        SampleRange::Plain { reverse: false },
        1,
    );
    assert!(
        matches!(r, Response::Failed(f) if f.code == Code::ViewProhibited),
        "{r:?}"
    );
    let Response::Stats(stats) = s.handle(&Request::Stats) else {
        panic!()
    };
    assert!(
        stats
            .iter()
            .any(|r| r.name.as_slice() == b"strict_t" && r.rows == 50)
    );
    let Response::Pragmas(p) = s.handle(&Request::Pragmas) else {
        panic!()
    };
    assert!(!p.wal);
    assert_eq!(p.encoding, 1);
    assert_eq!(s.handle(&Request::Close), Response::Closed);
}

#[test]
fn a_wal_file_is_read_while_its_writer_holds_it_open() {
    let d = Dir::new("wal");
    let p = d.path("app.db");
    seed(&p, true);
    // The writer keeps the database open (its -wal and -shm exist) and
    // writes after the reader opened.
    let writer = Connection::open(&p).unwrap();
    writer
        .execute(
            "INSERT INTO clients (email) VALUES ('late@example.com')",
            [],
        )
        .unwrap();
    assert!(crate::files::side_path(&p, "-wal").exists());
    let (mut s, info) = Session::open(&open_req(&p, false), Policy::TESTS, None).unwrap();
    assert!(info.wal);
    let _ = catalog(&mut s);
    let a = sampled(sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email"],
        SampleRange::From(51),
        10,
    ));
    assert_eq!(texts(&a, 0), [Some("late@example.com".to_owned())]);
    writer
        .execute(
            "INSERT INTO clients (email) VALUES ('later@example.com')",
            [],
        )
        .unwrap();
    let b = sampled(sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email"],
        SampleRange::From(52),
        10,
    ));
    assert_eq!(texts(&b, 0), [Some("later@example.com".to_owned())]);
    drop(s);
    drop(writer);
    // The last connection closed cleanly: no -wal / -shm, not readable.
    assert!(!crate::files::side_path(&p, "-wal").exists());
    assert_eq!(open_code(&p, false, Policy::TESTS), Code::WalNotReadable);
}

/// A read changes nothing in the directory (rollback mode; the WAL case,
/// whose `-shm` a writer of the same process would share read-write, is
/// tested across processes in `crates/agent/tests/sqlite_reader.rs`).
#[test]
fn the_directory_is_unchanged_by_a_read() {
    let d = Dir::new("unchanged");
    let p = d.path("app.db");
    seed(&p, false);
    let snapshot = || {
        let mut v: Vec<(String, Vec<u8>, std::time::SystemTime)> = std::fs::read_dir(&d.0)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                    m.modified().unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let before = snapshot();
    let mut s = session(&p);
    let _ = catalog(&mut s);
    let _ = sample(
        &mut s,
        "clients",
        Some(RowidAlias::Rowid),
        &["email"],
        SampleRange::From(1),
        100,
    );
    let _ = s.handle(&Request::Close);
    drop(s);
    let after = snapshot();
    assert!(before == after, "the directory changed");
}

#[test]
fn files_that_are_not_sqlite_are_refused_before_the_library() {
    let d = Dir::new("formats");
    // A crafted header, an encrypted-looking file, a 0-byte file.
    let p = d.path("garbage.db");
    let mut h = b"SQLite format 3\0".to_vec();
    h.resize(4096, 0xff);
    std::fs::write(&p, &h).unwrap();
    assert_eq!(open_code(&p, true, Policy::TESTS), Code::UnrecognizedFormat);
    let p = d.path("cipher.db");
    std::fs::write(&p, [0xa7; 8192]).unwrap();
    assert_eq!(open_code(&p, true, Policy::TESTS), Code::UnrecognizedFormat);
    let p = d.path("empty.db");
    std::fs::write(&p, b"").unwrap();
    assert_eq!(open_code(&p, true, Policy::TESTS), Code::UnrecognizedFormat);
    let p = d.path("missing.db");
    assert_eq!(open_code(&p, true, Policy::TESTS), Code::NotFound);
}

#[test]
fn path_rules_are_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let d = Dir::new("paths");
    let real = d.path("real.db");
    seed(&real, false);
    // A symlink as the final component, and in a parent component.
    let link = d.path("link.db");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(open_code(&link, true, Policy::TESTS), Code::PathRefused);
    let sub = d.path("sub");
    std::fs::create_dir(&sub).unwrap();
    seed(&sub.join("x.db"), false);
    let sublink = d.path("sublink");
    std::os::unix::fs::symlink(&sub, &sublink).unwrap();
    assert_eq!(
        open_code(&sublink.join("x.db"), true, Policy::TESTS),
        Code::PathRefused
    );
    // A second hard link.
    let hard = d.path("hard.db");
    std::fs::hard_link(&real, &hard).unwrap();
    assert_eq!(open_code(&real, true, Policy::TESTS), Code::PathRefused);
    std::fs::remove_file(&hard).unwrap();
    // Not canonical.
    let odd = PathBuf::from(format!("{}/./real.db", d.0.display()));
    assert_eq!(open_code(&odd, true, Policy::TESTS), Code::PathRefused);
    // Not a regular file.
    assert_eq!(open_code(&sub, true, Policy::TESTS), Code::PathRefused);
    // A world-writable directory without the sticky bit.
    let open = d.path("open");
    std::fs::create_dir(&open).unwrap();
    let inside = open.join("x.db");
    seed(&inside, false);
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(open_code(&inside, true, Policy::TESTS), Code::PathRefused);
    // The real file still opens.
    let _ = session(&real);
}

/// Decision 3 layers 1 and 2: a file the agent's account can write (its
/// own, in these tests, whether they run as root or not), and a file on a
/// file system that is not mounted read-only, are refused. The positive
/// case of the strict policy needs another owner and a read-only mount:
/// `crates/agent/tests/sqlite_reader.rs`.
#[test]
fn writable_files_and_mounts_are_refused() {
    let d = Dir::new("writable");
    let p = d.path("own.db");
    seed(&p, false);
    assert_eq!(open_code(&p, true, Policy::STRICT), Code::Writable);
    let read_only_fs_only = Policy {
        refuse_agent_writable: false,
        require_read_only_fs: true,
        exact_descriptor_set: false,
    };
    assert_eq!(open_code(&p, true, read_only_fs_only), Code::NotReadOnlyFs);
}

/// A hot journal: the file and its `-journal` copied in the middle of a
/// write transaction. Reported, never rolled back.
#[test]
fn a_hot_journal_is_reported_not_rolled_back() {
    let d = Dir::new("hot");
    let src = d.path("src.db");
    seed(&src, false);
    let c = Connection::open(&src).unwrap();
    c.execute_batch(
        "CREATE TABLE filler (v TEXT);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000)
         INSERT INTO filler SELECT printf('%0200d', i) FROM n;",
    )
    .unwrap();
    // `synchronous = OFF`: the journal header is written at once (a synced
    // journal's header stays zero until its first sync).
    c.execute_batch(
        "PRAGMA synchronous = OFF; PRAGMA cache_size = 1; BEGIN; UPDATE filler SET v = v || 'x';",
    )
    .unwrap();
    let j = std::fs::read(crate::files::side_path(&src, "-journal")).unwrap();
    assert!(
        j.len() > 512 && j[0] != 0,
        "journal {} bytes, first {:?}",
        j.len(),
        j.get(..8)
    );
    let dst = d.path("hot.db");
    std::fs::copy(&src, &dst).unwrap();
    std::fs::copy(
        crate::files::side_path(&src, "-journal"),
        crate::files::side_path(&dst, "-journal"),
    )
    .unwrap();
    c.execute_batch("ROLLBACK").unwrap();
    let journal = std::fs::read(crate::files::side_path(&dst, "-journal")).unwrap();
    let mut s = session(&dst);
    match s.handle(&Request::Catalog) {
        Response::Failed(f) => assert_eq!(f.code, Code::HotJournal),
        other => panic!("{other:?}"),
    }
    drop(s);
    assert_eq!(
        std::fs::read(crate::files::side_path(&dst, "-journal")).unwrap(),
        journal
    );
}

/// Writes schema rows directly (a hostile file) and closes the writer.
fn hostile(path: &Path, rows: &[(&str, &str, i64, &str)]) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = DELETE; CREATE TABLE base (a TEXT); \
         INSERT INTO base VALUES ('a@example.com');",
    )
    .unwrap();
    c.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
        .unwrap();
    c.execute_batch("PRAGMA writable_schema = ON").unwrap();
    for (kind, name, rootpage, sql) in rows {
        c.execute(
            "INSERT INTO sqlite_schema (type, name, tbl_name, rootpage, sql) \
             VALUES (?1, ?2, ?2, ?3, ?4)",
            rusqlite::params![kind, name, rootpage, sql],
        )
        .unwrap();
    }
    c.execute_batch("PRAGMA writable_schema = OFF").unwrap();
}

/// Decision 5: a virtual table per compiled-in module (and modules not
/// compiled in or unknown), and views using them, parse (SQLite never
/// connects a module while it reads the schema: verified on 3.53.2) and
/// are never executed: the module rows are counted as virtual tables, the
/// views are refused when sampled.
#[test]
fn virtual_tables_and_views_are_never_executed() {
    let d = Dir::new("modules");
    let p = d.path("h.db");
    hostile(
        &p,
        &[
            ("table", "vj", 0, "CREATE VIRTUAL TABLE vj USING json_each"),
            (
                "table",
                "vjt",
                0,
                "CREATE VIRTUAL TABLE vjt USING json_tree",
            ),
            (
                "table",
                "vjb",
                0,
                "CREATE VIRTUAL TABLE vjb USING jsonb_each",
            ),
            (
                "table",
                "vjbt",
                0,
                "CREATE VIRTUAL TABLE vjbt USING jsonb_tree",
            ),
            (
                "table",
                "vp",
                0,
                "CREATE VIRTUAL TABLE vp USING pragma_table_info",
            ),
            ("table", "vf", 0, "CREATE VIRTUAL TABLE vf USING fts5(a)"),
            (
                "table",
                "vr",
                0,
                "CREATE VIRTUAL TABLE vr USING rtree(id, x0, x1)",
            ),
            (
                "table",
                "vx",
                0,
                "CREATE VIRTUAL TABLE vx USING nosuchmodule(a)",
            ),
            (
                "view",
                "vjson",
                0,
                "CREATE VIEW vjson AS SELECT key FROM json_each('[1,2]') \
                 UNION ALL SELECT name FROM pragma_table_info('base')",
            ),
        ],
    );
    let mut s = session(&p);
    let cat = catalog(&mut s);
    assert_eq!(
        cat.iter()
            .filter(|(view, _, root)| !*view && *root == 0)
            .count(),
        8,
        "{cat:?}"
    );
    assert!(cat.iter().any(|(view, n, _)| *view && n == "vjson"));
    // Even when asked directly, sampling the view is refused (ENABLE_VIEW
    // off), and so is reading a module.
    for t in ["vjson", "vj", "vp"] {
        let r = sample(
            &mut s,
            t,
            None,
            &["key"],
            SampleRange::Plain { reverse: false },
            5,
        );
        assert!(matches!(r, Response::Failed(_)), "{t}: {r:?}");
    }
    // The ordinary table is still read.
    let a = sampled(sample(
        &mut s,
        "base",
        Some(RowidAlias::Rowid),
        &["a"],
        SampleRange::From(1),
        5,
    ));
    assert_eq!(a.rows, 1);
}

/// A view whose schema row claims `type = 'table'` (with a root page or
/// without): SQLite 3.53.2 refuses such a schema as malformed when it
/// loads it, so the whole file is `coverage.unrecognized_file_format`
/// before any view is compiled (the ADR expected `table_xinfo` to compile
/// the view; the library is stricter).
#[test]
fn a_view_posing_as_a_table_refuses_the_schema() {
    let d = Dir::new("posing");
    for (file, rootpage) in [("root.db", 2), ("noroot.db", 0)] {
        let p = d.path(file);
        hostile(
            &p,
            &[(
                "table",
                "vposing",
                rootpage,
                "CREATE VIEW vposing AS SELECT key FROM json_each('[1,2]') \
                 UNION ALL SELECT name FROM pragma_table_info('base')",
            )],
        );
        let mut s = session(&p);
        match s.handle(&Request::Catalog) {
            Response::Failed(f) => assert_eq!(f.code, Code::UnrecognizedFormat, "{file}"),
            other => panic!("{file}: {other:?}"),
        }
    }
}

/// Decision 5, security review L3: `SQLITE_LIMIT_LENGTH` and
/// `SQLITE_LIMIT_SQL_LENGTH` apply when the schema is read; an
/// unparseable schema fails only after the descriptor binding (the open
/// succeeds, the first statement fails).
#[test]
fn schemas_over_the_limits_or_unparseable_are_refused_after_the_binding() {
    let d = Dir::new("limits");
    let cases = [
        // A sqlite_schema.sql value above LENGTH (1 MiB).
        (
            "length.db",
            format!("CREATE TABLE t2 (a) /* {} */", "x".repeat(1_100_000)),
        ),
        // A statement above SQL_LENGTH (1 000 000) but below LENGTH.
        (
            "sql_length.db",
            format!("CREATE TABLE t2 (a) /* {} */", "x".repeat(1_010_000)),
        ),
        ("unparseable.db", "CREATE TABLE t2 (a,, b".to_owned()),
    ];
    for (file, sql) in cases {
        let p = d.path(file);
        hostile(&p, &[("table", "t2", 3, sql.as_str())]);
        let mut s = session(&p);
        match s.handle(&Request::Catalog) {
            Response::Failed(f) => assert_eq!(f.code, Code::UnrecognizedFormat, "{file}"),
            other => panic!("{file}: {other:?}"),
        }
    }
    // A schema just under both limits loads.
    let p = d.path("under.db");
    let under = format!("CREATE TABLE t2 (a) /* {} */", "x".repeat(900_000));
    hostile(&p, &[("table", "t2", 3, under.as_str())]);
    let mut s = session(&p);
    let _ = catalog(&mut s);
}

/// The limits kept at their defaults do not refuse a legitimate schema:
/// many columns, a deep expression, a compound select in a view, and an
/// old schema with a double-quoted string literal (`DQS_DDL` keeps its
/// default).
#[test]
fn legitimate_schemas_still_load() {
    let d = Dir::new("legit");
    let p = d.path("legit.db");
    let c = Connection::open(&p).unwrap();
    let cols: Vec<String> = (0..1500).map(|i| format!("c{i} TEXT")).collect();
    c.execute_batch(&format!("CREATE TABLE wide ({});", cols.join(", ")))
        .unwrap();
    let deep = (0..200).fold("1".to_owned(), |acc, _| format!("({acc} + 1)"));
    let compound = (0..400)
        .map(|i| format!("SELECT {i}"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    c.execute_batch(&format!(
        "CREATE TABLE deep (a INTEGER CHECK ({deep} > 0));
         CREATE VIEW many AS {compound};
         CREATE TABLE dqs (a TEXT DEFAULT \"legacy\");"
    ))
    .unwrap();
    drop(c);
    let mut s = session(&p);
    let names: Vec<String> = catalog(&mut s).into_iter().map(|(_, n, _)| n).collect();
    assert!(names.contains(&"wide".to_owned()) && names.contains(&"dqs".to_owned()));
    assert_eq!(columns(&mut s, "wide").len(), 1500);
}

#[test]
fn utf16_files_are_read_as_utf8() {
    let d = Dir::new("utf16");
    let p = d.path("u16.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA encoding = 'UTF-16le'; PRAGMA journal_mode = DELETE;
         CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('élodie@example.fr');",
    )
    .unwrap();
    drop(c);
    let mut s = session(&p);
    let _ = catalog(&mut s);
    let a = sampled(sample(
        &mut s,
        "t",
        Some(RowidAlias::Rowid),
        &["v"],
        SampleRange::From(1),
        5,
    ));
    assert_eq!(texts(&a, 0), [Some("élodie@example.fr".to_owned())]);
    let Response::Pragmas(p) = s.handle(&Request::Pragmas) else {
        panic!()
    };
    assert_eq!(p.encoding, 2);
}
