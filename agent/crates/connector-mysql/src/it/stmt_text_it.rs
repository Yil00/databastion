//! Statement-text tables (ADR-0045 part (a)) against the dev servers.
//!
//! - The drift test (decision 5): every `information_schema`,
//!   `performance_schema` and `sys` column with a statement-text name, or
//!   a name ending in `_query` / `_statement`, belongs to a listed table
//!   of that flavor (`audit::events::STATEMENT_TEXT_TABLES`) or to the
//!   commented exceptions below. A new server version that adds such a
//!   table fails the engine matrix instead of being missed.
//! - Reads of these tables by a second account are named read events,
//!   always reported; the agent's own probes and polls produce none, seen
//!   by its own stream and by the stream of a second target on the same
//!   server; a read of a listed table with the agent's credentials is
//!   reported.

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{collect_until, describe, percona, start_audit};
use super::*;
use crate::audit::events::{STATEMENT_TEXT_TABLES, statement_text_table};

/// The column names that hold statement text (ADR-0045 decision 5), and
/// `LOCK_DATA` (maintainer's answer to open question 1), upper case.
const TEXT_COLUMNS: [&str; 12] = [
    "SQL_TEXT",
    "QUERY_SAMPLE_TEXT",
    "INFO",
    "INFO_BINARY",
    "PROCESSLIST_INFO",
    "TRX_QUERY",
    "STATEMENT_TEXT",
    "CURRENT_STATEMENT",
    "LAST_STATEMENT",
    "WAITING_QUERY",
    "BLOCKING_QUERY",
    "LOCK_DATA",
];

/// Columns the query finds that hold no statement text of another
/// session: (schema, table, column), compared ASCII-case-insensitively.
const NOT_STATEMENT_TEXT: [(&str, &str, &str); 3] = [
    // Trigger bodies: catalog definitions, like `ROUTINES` and `VIEWS`.
    ("information_schema", "TRIGGERS", "ACTION_STATEMENT"),
    // A number (temporary tables per statement); the `query` column of
    // these views is a digest.
    (
        "sys",
        "statements_with_temp_tables",
        "avg_tmp_tables_per_query",
    ),
    (
        "sys",
        "x$statements_with_temp_tables",
        "avg_tmp_tables_per_query",
    ),
];

/// Columns of the system schemas whose name is a statement-text name.
fn text_columns_query() -> String {
    let names = TEXT_COLUMNS
        .iter()
        .map(|c| format!("'{c}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT LOWER(TABLE_SCHEMA), TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS \
         WHERE LOWER(TABLE_SCHEMA) IN ('information_schema', 'performance_schema', 'sys') \
         AND (UPPER(COLUMN_NAME) IN ({names}) OR LOWER(COLUMN_NAME) LIKE '%\\_query' \
         OR LOWER(COLUMN_NAME) LIKE '%\\_statement') \
         ORDER BY 1, 2, 3"
    )
}

fn not_statement_text(db: &str, table: &str, column: &str) -> bool {
    NOT_STATEMENT_TEXT.iter().any(|(d, t, c)| {
        d.eq_ignore_ascii_case(db)
            && t.eq_ignore_ascii_case(table)
            && c.eq_ignore_ascii_case(column)
    })
}

/// ADR-0045 decision 5: the list matches the server.
#[tokio::test]
async fn statement_text_tables_match_the_server() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            skip(
                &format!("{}-admin", server.name),
                "admin URL not set (statement-text drift test)",
            );
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        let rows = a.query(Stage::Check, &text_columns_query()).await.unwrap();
        assert!(!rows.is_empty(), "{version}: no column found");
        let mut tables: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for r in rows {
            let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
            let (db, table, column) = (get(0), get(1), get(2));
            if not_statement_text(&db, &table, &column) {
                continue;
            }
            tables.entry((db, table)).or_default().push(column);
        }
        let flavor = server.flavor();
        let found: Vec<String> = tables
            .iter()
            .map(|((d, t), c)| format!("{d}.{t} ({})", c.join(", ")))
            .collect();
        eprintln!(
            "{} {version}: statement-text tables:\n  {}",
            server.name,
            found.join("\n  ")
        );
        let missing: Vec<&String> = tables
            .keys()
            .zip(&found)
            .filter(|((d, t), _)| statement_text_table(Some(flavor), d, t).is_none())
            .map(|(_, f)| f)
            .collect();
        assert!(
            missing.is_empty(),
            "{} {version}: tables with statement text not in STATEMENT_TEXT_TABLES (add them, \
             or to NOT_STATEMENT_TEXT with a reason): {missing:#?}",
            server.name
        );
        // Listed tables this server does not have (a plugin not loaded, a
        // table of the other flavor): noted, not a failure.
        let existing: Vec<(String, String)> = a
            .query(
                Stage::Check,
                "SELECT LOWER(TABLE_SCHEMA), TABLE_NAME FROM information_schema.TABLES \
                 WHERE LOWER(TABLE_SCHEMA) IN ('information_schema', 'performance_schema', 'sys')",
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| {
                let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
                (get(0), get(1))
            })
            .collect();
        let absent: Vec<String> = STATEMENT_TEXT_TABLES
            .iter()
            .filter(|(d, t, _)| statement_text_table(Some(flavor), d, t).is_some())
            .filter(|(d, t, _)| {
                !existing
                    .iter()
                    .any(|(x, y)| x.eq_ignore_ascii_case(d) && y.eq_ignore_ascii_case(t))
            })
            .map(|(d, t, _)| format!("{d}.{t}"))
            .collect();
        eprintln!("{} {version}: listed, not found: {absent:?}", server.name);
    }
}

/// The agent's account of the test, with the Audit grant.
const STX_AGENT: &str = "databastion_it_stx";
/// A monitoring-like reader: `PROCESS` and `SELECT` on
/// `performance_schema`.
const STX_READER: &str = "databastion_it_reader";

fn named(e: &MaskedEvent, db: &str, table: &str) -> bool {
    e.action() == EventAction::Read
        && e.always_report()
        && e.objects()
            .iter()
            .any(|o| o.database().as_str() == db && o.object().as_str() == table)
}

/// ADR-0045 tests, part (a), on the `performance_schema` source: a second
/// account reads `events_statements_history_long` and
/// `information_schema.PROCESSLIST` and gets named, always-reported read
/// events; the agent's own probes (`check()`) and polls (two targets on
/// the same server, each stream seeing the other's polls) produce none; a
/// read of a listed table with the agent's credentials is reported.
#[tokio::test]
async fn statement_text_reads_are_named_and_the_agents_own_are_not() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        for (user, grants) in [
            (
                STX_AGENT,
                vec![
                    format!(
                        "GRANT SELECT ON {}.* TO '{STX_AGENT}'@'%'",
                        server.url.dbname
                    ),
                    format!("GRANT SELECT ON performance_schema.* TO '{STX_AGENT}'@'%'"),
                ],
            ),
            (
                STX_READER,
                vec![
                    format!("GRANT PROCESS ON *.* TO '{STX_READER}'@'%'"),
                    format!("GRANT SELECT ON performance_schema.* TO '{STX_READER}'@'%'"),
                ],
            ),
        ] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
            exec(
                &mut a,
                &format!("CREATE USER '{user}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
            )
            .await;
            for g in grants {
                exec(&mut a, &g).await;
            }
        }
        let (_d1, t1) = target(&server, STX_AGENT, IT_PASSWORD);
        let (_d2, mut t2) = target(&server, STX_AGENT, IT_PASSWORD);
        t2.id = "my-it-2".to_owned();
        let connector = Arc::new(MysqlConnector::new());
        for t in [&t1, &t2] {
            let health = connector.check(t).await;
            assert_eq!(
                health.audit_level,
                AuditLevel::Partial,
                "{}: {health:?}",
                server.name
            );
            assert_eq!(
                connector.audit_source(t),
                Some(EventSource::PerformanceSchema)
            );
        }
        // Statements of earlier tests' ended sessions (no account) stay
        // out of the streams' first overlap window (2 s).
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (s1, s2) = (TempDir::new(), TempDir::new());
        let (task1, mut rx1) = start_audit(Arc::clone(&connector), &t1, &s1.0);
        let (task2, mut rx2) = start_audit(Arc::clone(&connector), &t2, &s2.0);
        // First polls place the cursors at the newest statement.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        // The agent's probes, on heartbeat sessions both streams see.
        for _ in 0..3 {
            for t in [&t1, &t2] {
                assert!(connector.check(t).await.reachable, "{}", server.name);
            }
        }
        // The monitoring-like reader.
        let (_dr, tr) = target(&server, STX_READER, IT_PASSWORD);
        let mut r = Session::connect(&tr, Timeouts::new(Duration::from_secs(30)))
            .await
            .unwrap();
        for statement in [
            "SELECT COUNT(*) FROM performance_schema.events_statements_history_long",
            "SELECT ID, USER FROM information_schema.PROCESSLIST",
            "SHOW FULL PROCESSLIST",
        ] {
            r.query(Stage::Check, statement).await.unwrap();
        }
        // A read with the agent's credentials from the agent's address
        // (a stolen credential): reported, never charged.
        let (_da, ta) = target(&server, STX_AGENT, IT_PASSWORD);
        let mut stolen = Session::connect(&ta, Timeouts::new(Duration::from_secs(30)))
            .await
            .unwrap();
        stolen
            .query(
                Stage::Check,
                "SELECT THREAD_ID FROM performance_schema.events_statements_history_long LIMIT 1",
            )
            .await
            .unwrap();
        let reader_done = |ev: &[MaskedEvent]| {
            let of = |db: &str, t: &str| {
                ev.iter()
                    .filter(|e| e.principal().account_name() == STX_READER && named(e, db, t))
                    .count()
            };
            of("performance_schema", "events_statements_history_long") >= 1
                && of("information_schema", "PROCESSLIST") >= 2
                && ev.iter().any(|e| {
                    e.principal().account_name() == STX_AGENT
                        && named(e, "performance_schema", "events_statements_history_long")
                })
        };
        let mut ev1: Vec<MaskedEvent> = Vec::new();
        let mut ev2: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx1, &mut ev1, Duration::from_secs(30), reader_done).await;
        collect_until(&mut rx2, &mut ev2, Duration::from_secs(30), reader_done).await;
        // A few more polls of each stream (each sees the other's polls),
        // and more probes.
        for _ in 0..2 {
            for t in [&t1, &t2] {
                assert!(connector.check(t).await.reachable, "{}", server.name);
            }
        }
        collect_until(&mut rx1, &mut ev1, Duration::from_secs(5), |_| false).await;
        collect_until(&mut rx2, &mut ev2, Duration::from_secs(1), |_| false).await;
        for (label, ev) in [("stream 1", &ev1), ("stream 2", &ev2)] {
            let all: Vec<String> = ev.iter().map(describe).collect();
            eprintln!(
                "{} {label} events ({}):\n{}",
                server.name,
                all.len(),
                all.join("\n")
            );
            assert!(reader_done(ev), "{} {label}: {all:#?}", server.name);
            // The agent's account: exactly the stolen-credential read.
            let own: Vec<&MaskedEvent> = ev
                .iter()
                .filter(|e| e.principal().account_name() == STX_AGENT)
                .collect();
            assert_eq!(own.len(), 1, "{} {label}: {all:#?}", server.name);
            // No other principal names a statement-text table: the
            // heartbeat sessions of `check()` end before the poll (no
            // account), and their readability probes are `EXPLAIN`s.
            assert!(
                ev.iter()
                    .filter(|e| {
                        e.objects().iter().any(|o| {
                            statement_text_table(
                                Some(server.flavor()),
                                o.database().as_str(),
                                o.object().as_str(),
                            )
                            .is_some()
                        })
                    })
                    .all(|e| [STX_AGENT, STX_READER].contains(&e.principal().account_name())),
                "{} {label}: {all:#?}",
                server.name
            );
            assert!(
                ev.iter()
                    .all(|e| e.source() == EventSource::PerformanceSchema)
            );
        }
        task1.abort();
        task2.abort();
        drop(r);
        drop(stolen);
        let text = logs.text();
        assert!(
            !text.contains("SELECT THREAD_ID"),
            "statement text in the logs"
        );
        for user in [STX_AGENT, STX_READER] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
    }
}

/// Security review of #186, H1: every constant own `performance_schema`
/// text runs on the server after the poll's `SET`, and the server-side
/// `SQL_TEXT` threshold equals the Rust one for the server's settings.
#[tokio::test]
async fn own_performance_schema_texts_run_and_their_threshold_is_the_rust_one() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            skip(
                &format!("{}-admin", server.name),
                "admin URL not set (own performance_schema texts)",
            );
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        exec(&mut a, &crate::sql::ps_poll_variables(0)).await;
        for (text, _) in crate::sql::own_performance_schema_reads() {
            if let Err(e) = a.query(Stage::Check, &text).await {
                panic!("{} {version}: {e:?}: {text}", server.name);
            }
        }
        let limit = |v: Option<String>| {
            v.and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1024)
                .min(crate::audit::pfs::MAX_TEXT_BYTES)
        };
        let ps = limit(scalar(&mut a, crate::sql::PS_DIGEST_LIMIT).await);
        let parser = limit(scalar(&mut a, crate::sql::MAX_DIGEST_LIMIT).await);
        let server_value = scalar(
            &mut a,
            &format!("SELECT {}", crate::sql::ps_sql_text_from_expr()),
        )
        .await
        .and_then(|v| v.parse::<usize>().ok());
        let rust = crate::audit::pfs::sql_text_from(ps.min(parser));
        eprintln!(
            "{} {version}: digest limits {ps} / {parser}, SQL_TEXT from {server_value:?} (Rust {rust})",
            server.name
        );
        assert_eq!(server_value, Some(rust), "{} {version}", server.name);
    }
}
