//! Integration tests of the phase 8 follow-ups of lot F against a
//! PostgreSQL server, on every available source (the pgaudit log files,
//! then `pg_stat_statements`):
//!
//! - statements that wrap a query (ADR-0048, refinement of 2026-10-12): a
//!   cursor (`DECLARE … CURSOR FOR` then `FETCH`, as psql's `FETCH_COUNT`
//!   sends up to PostgreSQL 16), `EXPLAIN`, `EXPLAIN ANALYZE` and a
//!   prepared statement's `EXECUTE`s, from another role and from the
//!   agent's role, are reads of the relations their query names;
//! - failed reads whose error quotes the value read (security review of
//!   #197, L1): what the server logs and what the agent reports today, with
//!   `pgaudit.log_rows = on` (the dev setting, needed for Full) and off.
//!
//! Same prerequisites as `it.rs`. The fixtures are tables of `crm` and
//! test roles, dropped at the end; nothing is added to `dev/`.

#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::{AuditLevel, Connector};
use futures_util::StreamExt as _;

use super::it::{
    Logs, SERIAL, TempDir, admin, admin_url, agent_url, audit_logs, audit_target, collect_until,
    describe, raw_client, start_audit_with,
};
use crate::PostgresConnector;

/// A role that reads through the wrappers.
const WRAP_ROLE: &str = "databastion_it_wrap";
/// A role whose failed reads are logged with `pgaudit.log_rows = on` (the
/// server's setting), and one with `pgaudit.log_rows = off`.
const FAIL_ROLE: &str = "databastion_it_fail";
const FAIL_NOROWS_ROLE: &str = "databastion_it_fail_norows";
const WRAP_PASSWORD: &str = "dev-only-it-wrap-FAKE";
/// Marker in the values of the fixtures: never in an event or a log (I2).
const WRAP_MARK: &str = "Wr9Qz-it-wrap";

/// The sources of the test server: the pgaudit log files, then
/// `pg_stat_statements`.
fn sources() -> Vec<(String, Option<(PathBuf, &'static str)>)> {
    let mut out: Vec<(String, Option<(PathBuf, &'static str)>)> = audit_logs()
        .into_iter()
        .map(|(p, f)| (format!("pgaudit {f}"), Some((p, f))))
        .collect();
    out.push(("pg_stat_statements".to_owned(), None));
    out
}

fn names(e: &MaskedEvent) -> Vec<String> {
    e.objects()
        .iter()
        .map(|o| {
            format!(
                "{}.{}",
                o.schema().map_or("", |s| s.as_str()),
                o.object().as_str()
            )
        })
        .collect()
}

fn names_table(e: &MaskedEvent, table: &str) -> bool {
    names(e).iter().any(|n| n == &format!("crm.{table}"))
}

/// A read event of `user` naming `crm.<table>`.
fn read_of<'a>(ev: &'a [MaskedEvent], user: &str, table: &str) -> Option<&'a MaskedEvent> {
    ev.iter().find(|e| {
        e.principal().account_name() == user
            && e.action() == EventAction::Read
            && names_table(e, table)
    })
}

/// Tables `crm.<name>` of 60 rows with marked values, readable by `roles`
/// (and by the agent through the default privileges of `crm`).
async fn tables(a: &tokio_postgres::Client, list: &[&str], roles: &[&str]) {
    for t in list {
        a.batch_execute(&format!(
            "DROP TABLE IF EXISTS crm.{t}; \
             CREATE TABLE crm.{t} AS SELECT g AS id, \
               'user' || g || '-{WRAP_MARK}@example.test' AS email \
               FROM generate_series(1, 60) g;"
        ))
        .await
        .unwrap();
        for r in roles {
            a.batch_execute(&format!("GRANT SELECT ON crm.{t} TO {r}"))
                .await
                .unwrap();
        }
    }
}

async fn create_role(a: &tokio_postgres::Client, role: &str, db: &str) {
    a.batch_execute(&format!(
        "SET log_min_error_statement = panic; \
         DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
           CREATE ROLE {role} LOGIN PASSWORD '{WRAP_PASSWORD}'; END IF; END $$; \
         GRANT CONNECT ON DATABASE \"{db}\" TO {role}; \
         GRANT USAGE ON SCHEMA crm TO {role};"
    ))
    .await
    .unwrap();
}

async fn drop_role(a: &tokio_postgres::Client, role: &str, db: &str) {
    a.batch_execute(&format!(
        "REVOKE ALL ON SCHEMA crm FROM {role}; \
         REVOKE ALL ON DATABASE \"{db}\" FROM {role}; \
         DROP ROLE IF EXISTS {role};"
    ))
    .await
    .unwrap();
}

/// Runs `statement` with the simple query protocol (as psql does) and
/// returns the SQLSTATE of its error, if any.
async fn run(c: &tokio_postgres::Client, statement: &str) -> Option<String> {
    c.simple_query(statement)
        .await
        .err()
        .and_then(|e| e.code().map(|s| s.code().to_owned()))
}

/// ADR-0048, refinement of 2026-10-12 (security review of #199, L3): a
/// cursor, an explain, an explain that runs its query and the executions of
/// a prepared statement are reads of the relations their query names, on
/// every source; explains and cursors always reported with no row count;
/// the agent's role through them is reported (it sends none); `FETCH` and
/// `MOVE` add no event of their own.
#[tokio::test]
async fn wrapped_queries_are_reads_of_their_query() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    create_role(&a, WRAP_ROLE, &u.dbname).await;
    let all = [
        "it_wrap_cursor",
        "it_wrap_explain",
        "it_wrap_analyze",
        "it_wrap_prepared",
        "it_wrap_agent",
    ];
    tables(&a, &all[..4], &[WRAP_ROLE]).await;
    tables(&a, &all[4..], &[]).await;
    for (i, (label, log)) in sources().into_iter().enumerate() {
        let (_dir, t) = audit_target(
            &u,
            &format!("pg-wrap-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        if log.is_none() && health.audit_level != AuditLevel::Limited {
            super::it::skip("pss", "pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        // The tailers open the log; the first poll takes the baseline.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let w = raw_client(&adm, WRAP_ROLE, WRAP_PASSWORD, &u.dbname).await;
        // What psql sends for `\set FETCH_COUNT` (up to PostgreSQL 16).
        for s in [
            "BEGIN",
            "DECLARE _psql_cursor NO SCROLL CURSOR FOR SELECT email FROM crm.it_wrap_cursor",
            "FETCH FORWARD 25 FROM _psql_cursor",
            "FETCH FORWARD 25 FROM _psql_cursor",
            "MOVE 5 IN _psql_cursor",
            "CLOSE _psql_cursor",
            "COMMIT",
            "EXPLAIN SELECT email FROM crm.it_wrap_explain WHERE id = 7",
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT email FROM crm.it_wrap_analyze WHERE id < 40",
            "PREPARE it_wrap_p (integer) AS SELECT email FROM crm.it_wrap_prepared WHERE id = $1",
            "EXECUTE it_wrap_p(3)",
            "EXECUTE it_wrap_p(4)",
            "DEALLOCATE it_wrap_p",
        ] {
            assert_eq!(run(&w, s).await, None, "{label}: {s}");
        }
        // The agent's role (another application: never its own anyway on
        // pgaudit; on `pg_stat_statements` only the role is seen).
        let g = raw_client(&adm, &u.user, &u.password, &u.dbname).await;
        for s in [
            "BEGIN",
            "DECLARE c CURSOR FOR SELECT email FROM crm.it_wrap_agent",
            "FETCH 60 FROM c",
            "COMMIT",
            "EXPLAIN SELECT email FROM crm.it_wrap_agent WHERE id = 1",
        ] {
            assert_eq!(run(&g, s).await, None, "{label}: {s}");
        }
        let done = |ev: &[MaskedEvent]| {
            all[..4].iter().all(|t| read_of(ev, WRAP_ROLE, t).is_some())
                && read_of(ev, &u.user, "it_wrap_agent").is_some()
        };
        let mut events = Vec::new();
        collect_until(&mut rx, &mut events, Duration::from_secs(30), done).await;
        collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
        task.abort();
        drop(w);
        drop(g);
        let described: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{label} events ({}):\n{}",
            described.len(),
            described.join("\n")
        );
        assert!(done(&events), "{label}: {described:#?}");
        // Explains and cursors: always reported, no row count (none is
        // sent by the statement the source counts).
        for t in ["it_wrap_cursor", "it_wrap_explain", "it_wrap_analyze"] {
            let e = read_of(&events, WRAP_ROLE, t).unwrap();
            assert!(e.always_report(), "{label} {t}: {described:#?}");
            assert_eq!(e.rows(), None, "{label} {t}");
        }
        // A prepared statement's executions keep their row count (with
        // pgaudit, the `PREPARE` itself gets a `READ` record of 0 rows: it
        // checks the privileges, runs nothing, and is reported as such).
        assert!(
            events.iter().any(|e| {
                e.principal().account_name() == WRAP_ROLE
                    && names_table(e, "it_wrap_prepared")
                    && e.rows().is_some_and(|r| r >= 1)
            }),
            "{label}: {described:#?}"
        );
        // The agent's role through a cursor and an explain: reported.
        let e = read_of(&events, &u.user, "it_wrap_agent").unwrap();
        assert!(e.always_report(), "{label}");
        // Every event of the reader names one of its tables: `FETCH`,
        // `MOVE`, `CLOSE` and `DEALLOCATE` add no event (no `*`), and
        // nothing is written.
        for e in events
            .iter()
            .filter(|e| e.principal().account_name() == WRAP_ROLE)
        {
            assert_eq!(e.action(), EventAction::Read, "{label}: {described:#?}");
            assert!(
                all[..4].iter().any(|t| names_table(e, t)),
                "{label}: {described:#?}"
            );
            assert!(!names(e).iter().any(|n| n.ends_with('*')), "{label}");
        }
        assert!(!described.iter().any(|d| d.contains(WRAP_MARK)), "{label}");
    }
    for t in all {
        a.batch_execute(&format!("DROP TABLE IF EXISTS crm.{t}"))
            .await
            .unwrap();
    }
    drop_role(&a, WRAP_ROLE, &u.dbname).await;
    let text = logs.text();
    assert!(!text.contains(WRAP_MARK), "a value reached the logs");
}

/// The error lines the server wrote for `statement` since `from` in its
/// jsonlog: (SQLSTATE, whether the message quotes `mark`, whether the
/// `statement` field is the statement). The message is never printed.
async fn error_lines(
    path: &std::path::Path,
    from: u64,
    statement: &str,
    mark: &str,
    want: usize,
) -> Vec<(String, bool)> {
    use std::io::{Read as _, Seek as _};
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut f = std::fs::File::open(path).unwrap();
        f.seek(std::io::SeekFrom::Start(from)).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        let out: Vec<(String, bool)> = buf
            .split(|b| *b == b'\n')
            .filter_map(|l| serde_json::from_slice::<serde_json::Value>(l).ok())
            .filter(|v| {
                v.get("error_severity").and_then(|s| s.as_str()) == Some("ERROR")
                    && v.get("statement").and_then(|s| s.as_str()) == Some(statement)
            })
            .map(|v| {
                (
                    v.get("state_code")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    v.get("message")
                        .and_then(|s| s.as_str())
                        .is_some_and(|m| m.contains(mark)),
                )
            })
            .collect();
        if out.len() >= want || std::time::Instant::now() > deadline {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// The pgaudit records (`AUDIT:` lines) of `statement` since `from`.
fn audit_records(path: &std::path::Path, from: u64, statement: &str) -> usize {
    use std::io::{Read as _, Seek as _};
    let mut f = std::fs::File::open(path).unwrap();
    f.seek(std::io::SeekFrom::Start(from)).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf.split(|b| *b == b'\n')
        .filter_map(|l| {
            crate::audit::records::parse_record(crate::audit::records::Format::Jsonlog, l, "LOG")
        })
        .filter(|r| r.audit.statement.as_str() == statement)
        .count()
}

/// Rows a client received of `statement` before its error, and the
/// error's SQLSTATE (extended protocol, rows streamed as they come).
async fn streamed(c: &tokio_postgres::Client, statement: &str) -> (usize, Option<String>) {
    let stream = c.query_raw(statement, std::iter::empty::<i32>()).await;
    let stream = match stream {
        Ok(s) => s,
        Err(e) => return (0, e.code().map(|s| s.code().to_owned())),
    };
    let mut stream = std::pin::pin!(stream);
    let mut rows = 0;
    while let Some(r) = stream.next().await {
        match r {
            Ok(_) => rows += 1,
            Err(e) => return (rows, e.code().map(|s| s.code().to_owned())),
        }
    }
    (rows, None)
}

/// Security review of #197, L1: a failed read whose error quotes the value
/// it read (`invalid input syntax for type integer: "<value>"`, SQLSTATE
/// 22P02), from another role and from the agent's role, and a read that
/// streams its rows to the client before failing on purpose on the last
/// one (22012), and a read cancelled by its `statement_timeout` (57014).
/// What the server writes, and what the agent reports today:
///
/// - with `pgaudit.log_rows = on` (needed for Full), pgaudit writes its
///   record when the statement ends, so a failed statement leaves **no**
///   `AUDIT:` record, only the server's `ERROR` line, whose message holds
///   the value and whose `statement` field holds the text: **no event**,
///   from any role, for the failed cast, the rows streamed before the
///   error, nor the cancelled read;
/// - with `pgaudit.log_rows = off`, the record is written when the
///   statement starts: the failed read is reported (no row count);
/// - `pg_stat_statements` counts no failed statement: no event.
///
/// The proposed fix is in ADR-0037's refinement of 2026-10-12 (proposed).
#[tokio::test]
async fn failed_reads_and_what_is_reported() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    let log_rows: Option<String> = a
        .query_one("SELECT current_setting('pgaudit.log_rows', true)", &[])
        .await
        .unwrap()
        .get(0);
    create_role(&a, FAIL_ROLE, &u.dbname).await;
    create_role(&a, FAIL_NOROWS_ROLE, &u.dbname).await;
    let pgaudit_loaded = log_rows.is_some();
    if pgaudit_loaded {
        a.batch_execute(&format!(
            "ALTER ROLE {FAIL_NOROWS_ROLE} SET pgaudit.log_rows = off"
        ))
        .await
        .unwrap();
    }
    tables(&a, &["it_fail", "it_fail_control"], &[FAIL_ROLE]).await;
    tables(&a, &["it_fail_norows"], &[FAIL_NOROWS_ROLE]).await;
    let cast = |t: &str, id: u32| format!("SELECT email::integer FROM crm.{t} WHERE id = {id}");
    let late = |t: &str| {
        format!("SELECT id, email, CASE WHEN id = 60 THEN 1 / (id - 60) END FROM crm.{t}")
    };
    let slow_read = |t: &str| format!("SELECT id, email, pg_sleep(0.05) FROM crm.{t}");
    let jsonlog = audit_logs()
        .into_iter()
        .find(|(_, f)| *f == "jsonlog")
        .map(|(p, _)| p);
    for (i, (label, log)) in sources().into_iter().enumerate() {
        let pgaudit = log.is_some();
        let (_dir, t) = audit_target(
            &u,
            &format!("pg-fail-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        if !pgaudit && health.audit_level != AuditLevel::Limited {
            super::it::skip("pss", "pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let from = jsonlog
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        let f = raw_client(&adm, FAIL_ROLE, WRAP_PASSWORD, &u.dbname).await;
        let n = raw_client(&adm, FAIL_NOROWS_ROLE, WRAP_PASSWORD, &u.dbname).await;
        let g = raw_client(&adm, &u.user, &u.password, &u.dbname).await;
        // The failed cast quotes the value; the client gets it in the
        // error message (not printed here).
        let failing = [
            (&f, FAIL_ROLE, cast("it_fail", 1)),
            (&g, u.user.as_str(), cast("it_fail", 2)),
            (&n, FAIL_NOROWS_ROLE, cast("it_fail_norows", 3)),
        ];
        for (c, who, s) in &failing {
            let err = c.simple_query(s).await.unwrap_err();
            assert_eq!(err.code().map(|c| c.code()), Some("22P02"), "{label} {who}");
            assert!(
                err.as_db_error()
                    .is_some_and(|d| d.message().contains(WRAP_MARK)),
                "{label} {who}: the error quotes the value"
            );
        }
        // Rows streamed to the client, then an error on purpose.
        let (rows_f, code_f) = streamed(&f, &late("it_fail")).await;
        let (rows_g, code_g) = streamed(&g, &late("it_fail")).await;
        assert_eq!(code_f.as_deref(), Some("22012"), "{label}");
        assert_eq!(code_g.as_deref(), Some("22012"), "{label}");
        assert_eq!((rows_f, rows_g), (59, 59), "{label}: rows received");
        // A read cancelled by its `statement_timeout` (57014).
        let slow = slow_read("it_fail");
        f.batch_execute("SET statement_timeout = 500")
            .await
            .unwrap();
        assert_eq!(run(&f, &slow).await.as_deref(), Some("57014"), "{label}");
        f.batch_execute("RESET statement_timeout").await.unwrap();
        // A control read, so that the stream is known to report.
        assert_eq!(
            run(&f, "SELECT id FROM crm.it_fail_control WHERE id = 5").await,
            None
        );
        let control = |ev: &[MaskedEvent]| read_of(ev, FAIL_ROLE, "it_fail_control").is_some();
        let mut events = Vec::new();
        collect_until(&mut rx, &mut events, Duration::from_secs(30), control).await;
        collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
        task.abort();
        let described: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{label} events ({}):\n{}",
            described.len(),
            described.join("\n")
        );
        assert!(control(&events), "{label}: {described:#?}");
        // The server's log (jsonlog): an `ERROR` line with the statement
        // and a message that quotes the value; no pgaudit record of a
        // statement that failed with `log_rows = on`, one with `off`.
        if let (true, Some(path)) = (pgaudit_loaded, jsonlog.as_ref()) {
            for (_, who, s) in &failing {
                let lines = error_lines(path, from, s, WRAP_MARK, 1).await;
                assert_eq!(lines, [("22P02".to_owned(), true)], "{label} {who}");
            }
            let lines = error_lines(path, from, &late("it_fail"), WRAP_MARK, 2).await;
            assert_eq!(lines.len(), 2, "{label}: {lines:?}");
            assert!(lines.iter().all(|(c, quoted)| c == "22012" && !quoted));
            let lines = error_lines(path, from, &slow, WRAP_MARK, 1).await;
            assert_eq!(lines, [("57014".to_owned(), false)], "{label}");
            if log_rows.as_deref() == Some("on") {
                for s in [
                    cast("it_fail", 1),
                    cast("it_fail", 2),
                    late("it_fail"),
                    slow.clone(),
                ] {
                    assert_eq!(audit_records(path, from, &s), 0, "{label}: {s}");
                }
            }
            assert!(
                audit_records(path, from, &cast("it_fail_norows", 3)) > 0,
                "{label}: log_rows = off writes the record at the start"
            );
        }
        // What the agent reports today: nothing of the failed reads with
        // `log_rows = on` or on `pg_stat_statements` (no record, no
        // counter), from any role, the rows streamed before the error
        // included; with `log_rows = off` on pgaudit, a read with no row
        // count.
        assert!(
            !events.iter().any(|e| names_table(e, "it_fail")),
            "{label}: {described:#?}"
        );
        let norows = read_of(&events, FAIL_NOROWS_ROLE, "it_fail_norows");
        if pgaudit && pgaudit_loaded {
            let e = norows.unwrap_or_else(|| panic!("{label}: {described:#?}"));
            assert_eq!(e.rows(), None, "{label}");
        } else {
            assert!(norows.is_none(), "{label}: {described:#?}");
        }
        assert!(!described.iter().any(|d| d.contains(WRAP_MARK)), "{label}");
    }
    if pgaudit_loaded {
        a.batch_execute(&format!("ALTER ROLE {FAIL_NOROWS_ROLE} RESET ALL"))
            .await
            .unwrap();
    }
    for t in ["it_fail", "it_fail_control", "it_fail_norows"] {
        a.batch_execute(&format!("DROP TABLE IF EXISTS crm.{t}"))
            .await
            .unwrap();
    }
    drop_role(&a, FAIL_ROLE, &u.dbname).await;
    drop_role(&a, FAIL_NOROWS_ROLE, &u.dbname).await;
    let text = logs.text();
    assert!(!text.contains(WRAP_MARK), "a value reached the logs");
}
