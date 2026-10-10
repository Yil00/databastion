//! Statistics tables that hold column values (ADR-0048) against the dev
//! servers, on the three sources: `performance_schema` (MySQL 8.4 and
//! MariaDB 11.4), the MariaDB `server_audit` log (`QUERY_DML` and `TABLE`
//! records) and the Percona `audit_log_filter` JSON log.
//!
//! A table is analyzed so that its statistics hold values (MySQL:
//! `ANALYZE TABLE … UPDATE HISTOGRAM`, `information_schema.COLUMN_STATISTICS`;
//! MariaDB: `ANALYZE TABLE … PERSISTENT FOR ALL`, `mysql.column_stats`). A
//! second account reads the statistics table, whole-row and through a
//! column that holds no value, and gets read events naming it (as
//! listed), always reported. On MariaDB, `FLUSH TABLES` then a plain
//! `SELECT` of the application table (the server loads its statistics
//! under the reader's account, which `server_audit` logs as `READ` records
//! of `mysql.column_stats`) gives no statistics object. The agent's own
//! probes give none on any source. No seeded value reaches an event or a
//! log.

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{audit_target, collect_until, describe, env_path, percona, start_audit};
use super::*;
use crate::audit::events::statistics_table;

/// Test database.
const ST_DB: &str = "databastion_stats_it";
/// The account that reads the statistics.
const ST_USER: &str = "databastion_it_stats";
/// The agent's account of the `performance_schema` test.
const ST_AGENT: &str = "databastion_it_st_agent";
/// Seeded values: never in an event or a log line (I2).
const ST_MARK: &str = "7Qz";

/// The statistics table of the server's flavor, as listed.
fn stats_table(flavor: Flavor) -> (&'static str, &'static str) {
    match flavor {
        Flavor::Mysql => ("information_schema", "COLUMN_STATISTICS"),
        Flavor::Mariadb => ("mysql", "column_stats"),
    }
}

/// The fixture: an analyzed table whose statistics hold its values, and
/// the reading account.
async fn st_fixture(a: &mut Session, flavor: Flavor) {
    let rows: Vec<String> = (1..=12)
        .map(|n| {
            format!(
                "({n}, 'user{n}-{ST_MARK}@example.test', '{}')",
                if n % 2 == 0 {
                    format!("Lille{ST_MARK}")
                } else {
                    format!("Nantes{ST_MARK}")
                }
            )
        })
        .collect();
    for statement in [
        format!("DROP DATABASE IF EXISTS {ST_DB}"),
        format!("CREATE DATABASE {ST_DB}"),
        // No unique index on the analyzed columns: MySQL refuses a
        // histogram on a column covered by a single-part unique index.
        format!(
            "CREATE TABLE {ST_DB}.customers (id INT PRIMARY KEY, email VARCHAR(200), \
             city VARCHAR(100)) ENGINE=InnoDB"
        ),
        format!("INSERT INTO {ST_DB}.customers VALUES {}", rows.join(", ")),
        format!("DROP USER IF EXISTS '{ST_USER}'@'%'"),
        format!("CREATE USER '{ST_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        format!("GRANT SELECT ON {ST_DB}.* TO '{ST_USER}'@'%'"),
        // `performance_schema` names a statement's account from its
        // session's thread (the reader's own row).
        format!("GRANT SELECT ON performance_schema.threads TO '{ST_USER}'@'%'"),
    ] {
        exec(a, &statement).await;
    }
    let (analyze, filled) = match flavor {
        Flavor::Mysql => (
            format!(
                "ANALYZE TABLE {ST_DB}.customers UPDATE HISTOGRAM ON email, city WITH 8 BUCKETS"
            ),
            format!(
                "SELECT COUNT(*) FROM information_schema.COLUMN_STATISTICS \
                 WHERE SCHEMA_NAME = '{ST_DB}'"
            ),
        ),
        Flavor::Mariadb => {
            exec(
                a,
                &format!("GRANT SELECT ON mysql.column_stats TO '{ST_USER}'@'%'"),
            )
            .await;
            (
                format!("ANALYZE TABLE {ST_DB}.customers PERSISTENT FOR ALL"),
                format!("SELECT COUNT(*) FROM mysql.column_stats WHERE db_name = '{ST_DB}'"),
            )
        }
    };
    let out = a.query(Stage::Check, &analyze).await.unwrap();
    // Columns: Table, Op, Msg_type, Msg_text.
    assert!(
        out.iter().all(|r| !r
            .get(2)
            .cloned()
            .flatten()
            .unwrap_or_default()
            .eq_ignore_ascii_case("error")),
        "ANALYZE failed"
    );
    let n: i64 = scalar(a, &filled)
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(n >= 2, "the statistics were not filled ({n})");
}

/// The reader's statements of the statistics table: whole-row, and
/// through columns that hold no value (ADR-0048 open question 4).
fn st_reads(flavor: Flavor) -> Vec<String> {
    match flavor {
        Flavor::Mysql => vec![
            format!(
                "SELECT HISTOGRAM FROM information_schema.COLUMN_STATISTICS \
                 WHERE SCHEMA_NAME = '{ST_DB}' AND TABLE_NAME = 'customers'"
            ),
            "SELECT * FROM information_schema.COLUMN_STATISTICS".to_owned(),
            format!(
                "SELECT COLUMN_NAME FROM information_schema.column_statistics \
                 WHERE SCHEMA_NAME = '{ST_DB}'"
            ),
        ],
        Flavor::Mariadb => vec![
            format!(
                "SELECT column_name, min_value, max_value FROM mysql.column_stats \
                 WHERE db_name = '{ST_DB}'"
            ),
            "SELECT * FROM mysql.column_stats".to_owned(),
            format!("SELECT nulls_ratio FROM `mysql`.`column_stats` s WHERE s.db_name = '{ST_DB}'"),
        ],
    }
}

/// The reading session, kept open until the events are collected.
struct Held {
    _dir: TempDir,
    _session: Session,
}

/// The second account's traffic: the statistics reads, then (MariaDB) a
/// plain read of the application table after `FLUSH TABLES`, which loads
/// its statistics under the reader's account.
async fn st_traffic(server: &Server, admin: &mut Session) -> Held {
    let flavor = server.flavor();
    let (dir, t) = target(server, ST_USER, IT_PASSWORD);
    let mut s = Session::connect(&t, Timeouts::new(Duration::from_secs(30)))
        .await
        .unwrap();
    for statement in st_reads(flavor) {
        let rows = s.query(Stage::Check, &statement).await.unwrap();
        assert!(!rows.is_empty(), "{}: no statistics row", server.name);
    }
    if flavor == Flavor::Mariadb {
        exec(admin, "FLUSH TABLES").await;
        s.query(
            Stage::Check,
            &format!("SELECT id FROM {ST_DB}.customers WHERE id = 1"),
        )
        .await
        .unwrap();
    }
    Held {
        _dir: dir,
        _session: s,
    }
}

/// A read event of the reader naming the statistics table, always
/// reported.
fn stats_read(e: &MaskedEvent, flavor: Flavor) -> bool {
    let (db, t) = stats_table(flavor);
    e.principal().account_name() == ST_USER
        && e.action() == EventAction::Read
        && e.always_report()
        && e.objects()
            .iter()
            .any(|o| o.database().as_str() == db && o.object().as_str() == t)
}

/// The reader's plain read of the application table (MariaDB).
fn plain_read(e: &MaskedEvent) -> bool {
    e.principal().account_name() == ST_USER
        && e.action() == EventAction::Read
        && e.objects()
            .iter()
            .any(|o| o.database().as_str() == ST_DB && o.object().as_str() == "customers")
}

fn names_statistics(e: &MaskedEvent) -> bool {
    e.objects()
        .iter()
        .any(|o| statistics_table(o.database().as_str(), o.object().as_str()).is_some())
}

fn st_done(flavor: Flavor) -> impl Fn(&[MaskedEvent]) -> bool {
    move |ev: &[MaskedEvent]| {
        ev.iter().filter(|e| stats_read(e, flavor)).count() >= st_reads(flavor).len()
            && (flavor == Flavor::Mysql || ev.iter().any(plain_read))
    }
}

/// Checks the events and logs of one source: a statistics read per
/// statement of the reader, no statistics object in any other event but
/// the administrator's fixture checks (an audit log may still hold them
/// when the stream starts; the plain read after `FLUSH TABLES` names the
/// application table only, the agent's probes give none), and no seeded
/// value anywhere.
fn st_check(label: &str, flavor: Flavor, admin: &str, ev: &[MaskedEvent], logs: &Logs) {
    let all: Vec<String> = ev.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    assert!(st_done(flavor)(ev), "{label}: {all:#?}");
    assert!(
        ev.iter()
            .filter(|e| names_statistics(e) && e.principal().account_name() != admin)
            .all(|e| stats_read(e, flavor)),
        "{label}: a statistics object outside the reader's reads: {all:#?}"
    );
    if flavor == Flavor::Mariadb {
        assert!(
            ev.iter()
                .filter(|e| plain_read(e))
                .all(|e| !names_statistics(e) && e.objects().len() == 1),
            "{label}: the statistics load named a statistics table: {all:#?}"
        );
    }
    let joined = all.join("\n");
    for leak in [ST_MARK, "example.test", "Lille", "Nantes"] {
        assert!(!joined.contains(leak), "{label}: {leak} in an event");
        assert!(!logs.text().contains(leak), "{label}: {leak} in the logs");
    }
}

/// ADR-0048 on the `performance_schema` source (MySQL and MariaDB).
#[tokio::test]
async fn statistics_reads_on_performance_schema() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let flavor = server.flavor();
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        st_fixture(&mut a, flavor).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{ST_AGENT}'@'%'")).await;
        exec(
            &mut a,
            &format!("CREATE USER '{ST_AGENT}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        exec(
            &mut a,
            &format!("GRANT SELECT ON performance_schema.* TO '{ST_AGENT}'@'%'"),
        )
        .await;
        let (_d, t) = target(&server, ST_AGENT, IT_PASSWORD);
        let connector = Arc::new(MysqlConnector::new());
        let health = connector.check(&t).await;
        assert_eq!(
            health.audit_level,
            AuditLevel::Partial,
            "{}: {health:?}",
            server.name
        );
        assert_eq!(
            connector.audit_source(&t),
            Some(EventSource::PerformanceSchema)
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        for _ in 0..3 {
            assert!(connector.check(&t).await.reachable, "{}", server.name);
        }
        let held = st_traffic(&server, &mut a).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), st_done(flavor)).await;
        for _ in 0..2 {
            assert!(connector.check(&t).await.reachable, "{}", server.name);
        }
        collect_until(&mut rx, &mut ev, Duration::from_secs(4), |_| false).await;
        task.abort();
        drop(held);
        st_check(
            &format!("{} performance_schema", server.name),
            flavor,
            &admin.user,
            &ev,
            &logs,
        );
        for user in [ST_AGENT, ST_USER] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {ST_DB}")).await;
    }
}

/// ADR-0048 on the audit log files: MariaDB `server_audit` (with the
/// `READ` records of the server's statistics loads) and the Percona
/// `audit_log_filter` JSON log (no `table_access` record for
/// `information_schema`).
#[tokio::test]
async fn statistics_reads_on_audit_logs() {
    let _serial = SERIAL.lock().await;
    let mariadb = servers()
        .into_iter()
        .find(|s| s.name == "mariadb")
        .and_then(|s| {
            let log = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit")?;
            Some((s, log, "server_audit", EventSource::MariadbServerAudit))
        });
    let percona = percona().and_then(|s| {
        let log = env_path("DATABASTION_TEST_PERCONA_AUDIT_LOG", "percona-audit")?;
        Some((s, log, "json", EventSource::MysqlAuditLog))
    });
    for (server, log, format, source) in mariadb.into_iter().chain(percona) {
        let Some(admin) = server.admin.clone() else {
            continue;
        };
        let flavor = server.flavor();
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        st_fixture(&mut a, flavor).await;
        let (_d, t) = audit_target(
            &server,
            &server.url.user,
            &server.url.password,
            Some((&log, format)),
        );
        let connector = Arc::new(MysqlConnector::new());
        assert!(connector.check(&t).await.reachable, "{format}");
        assert_eq!(connector.audit_source(&t), Some(source));
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        for _ in 0..3 {
            assert!(connector.check(&t).await.reachable, "{format}");
        }
        let held = st_traffic(&server, &mut a).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), st_done(flavor)).await;
        // Records are grouped until the connection's next record: its
        // disconnection.
        drop(held);
        collect_until(&mut rx, &mut ev, Duration::from_secs(4), |_| false).await;
        task.abort();
        st_check(
            &format!("{} {format}", server.name),
            flavor,
            &admin.user,
            &ev,
            &logs,
        );
        exec(&mut a, &format!("DROP USER IF EXISTS '{ST_USER}'@'%'")).await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {ST_DB}")).await;
    }
}

/// Columns of the system schemas found by the drift test that hold no
/// value of an application column: (schema, table), compared
/// ASCII-case-insensitively.
const NOT_VALUE_STATISTICS: [(&str, &str); 3] = [
    // `MIN_VALUE` / `MAX_VALUE`: the bounds of each system variable.
    ("performance_schema", "variables_info"),
    // The same, MySQL 9.x.
    ("performance_schema", "variables_metadata"),
    // `max_value`: the largest value of an auto-increment column's type.
    ("sys", "schema_auto_increment_columns"),
];

/// ADR-0048 drift test: every relation of `information_schema`,
/// `performance_schema`, `sys` and `mysql` with a column named
/// `HISTOGRAM`, `min_value` or `max_value` is listed
/// (`STATISTICS_TABLES`) or a commented exception above. Checked on
/// MySQL 8.0.46, 8.4.11 and 9.7.2, Percona 8.4.11-11 and MariaDB 10.11.19,
/// 11.4.13 and 11.8.9 (the engine matrix).
#[tokio::test]
async fn statistics_tables_match_the_server() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            skip(
                &format!("{}-admin", server.name),
                "admin URL not set (statistics drift test)",
            );
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        let rows = a
            .query(
                Stage::Check,
                "SELECT DISTINCT LOWER(TABLE_SCHEMA), TABLE_NAME FROM information_schema.COLUMNS \
                 WHERE LOWER(TABLE_SCHEMA) IN ('information_schema', 'performance_schema', \
                 'sys', 'mysql') AND LOWER(COLUMN_NAME) IN ('histogram', 'min_value', \
                 'max_value') ORDER BY 1, 2",
            )
            .await
            .unwrap();
        let found: Vec<(String, String)> = rows
            .into_iter()
            .map(|r| {
                let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
                (get(0), get(1))
            })
            .collect();
        eprintln!("{} {version}: statistics columns in {found:?}", server.name);
        assert!(
            found.iter().any(|(d, t)| statistics_table(d, t).is_some()),
            "{} {version}: no statistics table found",
            server.name
        );
        let missing: Vec<&(String, String)> = found
            .iter()
            .filter(|(d, t)| {
                statistics_table(d, t).is_none()
                    && !NOT_VALUE_STATISTICS
                        .iter()
                        .any(|(x, y)| x.eq_ignore_ascii_case(d) && y.eq_ignore_ascii_case(t))
            })
            .collect();
        assert!(
            missing.is_empty(),
            "{} {version}: relations with statistics columns not in STATISTICS_TABLES (add \
             them, or to NOT_VALUE_STATISTICS with a reason): {missing:?}",
            server.name
        );
    }
}

/// The server facts ADR-0048 rests on, one assertion each (counts only,
/// never a value): MySQL histograms are visible per table, not per column,
/// keep strings base64-encoded with their type, and their data dictionary
/// table is refused to every account; MariaDB keeps `min_value` in clear,
/// needs `SELECT` on `mysql.column_stats`, and logs the server's own
/// statistics loads as `server_audit` `READ` records of the reader.
#[tokio::test]
async fn statistics_server_facts() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            continue;
        };
        let flavor = server.flavor();
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        st_fixture(&mut a, flavor).await;
        let label = format!("{} {version}", server.name);
        match flavor {
            Flavor::Mysql => {
                // A column-only account reads the histogram of a column it
                // cannot `SELECT`.
                exec(&mut a, &format!("DROP USER IF EXISTS '{ST_AGENT}'@'%'")).await;
                exec(
                    &mut a,
                    &format!(
                        "CREATE USER '{ST_AGENT}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"
                    ),
                )
                .await;
                exec(
                    &mut a,
                    &format!("GRANT SELECT (id) ON {ST_DB}.customers TO '{ST_AGENT}'@'%'"),
                )
                .await;
                let (_d, t) = target(&server, ST_AGENT, IT_PASSWORD);
                let mut c = Session::connect(&t, Timeouts::new(Duration::from_secs(30)))
                    .await
                    .unwrap();
                let denied = c
                    .query(
                        Stage::Check,
                        &format!("SELECT email FROM {ST_DB}.customers LIMIT 1"),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(denied.errno, Some(1143), "{label}");
                let n = scalar(
                    &mut c,
                    &format!(
                        "SELECT COUNT(*) FROM information_schema.COLUMN_STATISTICS \
                         WHERE SCHEMA_NAME = '{ST_DB}' AND COLUMN_NAME = 'email'"
                    ),
                )
                .await;
                assert_eq!(n.as_deref(), Some("1"), "{label}: per-table visibility");
                drop(c);
                let n = scalar(
                    &mut a,
                    &format!(
                        "SELECT COUNT(*) FROM information_schema.COLUMN_STATISTICS \
                         WHERE SCHEMA_NAME = '{ST_DB}' AND COLUMN_NAME = 'email' \
                         AND CAST(HISTOGRAM AS CHAR) LIKE '%base64:type%'"
                    ),
                )
                .await;
                assert_eq!(n.as_deref(), Some("1"), "{label}: base64 strings");
                let e = a
                    .query(Stage::Check, "SELECT COUNT(*) FROM mysql.column_statistics")
                    .await
                    .unwrap_err();
                assert_eq!(e.errno, Some(3554), "{label}: data dictionary table");
                exec(&mut a, &format!("DROP USER IF EXISTS '{ST_AGENT}'@'%'")).await;
            }
            Flavor::Mariadb => {
                let n = scalar(
                    &mut a,
                    &format!(
                        "SELECT COUNT(*) FROM mysql.column_stats WHERE db_name = '{ST_DB}' \
                         AND column_name = 'email' AND min_value LIKE '%{ST_MARK}%'"
                    ),
                )
                .await;
                assert_eq!(n.as_deref(), Some("1"), "{label}: min_value in clear");
                exec(
                    &mut a,
                    &format!("REVOKE SELECT ON mysql.column_stats FROM '{ST_USER}'@'%'"),
                )
                .await;
                let (_d, t) = target(&server, ST_USER, IT_PASSWORD);
                let mut c = Session::connect(&t, Timeouts::new(Duration::from_secs(30)))
                    .await
                    .unwrap();
                let e = c
                    .query(Stage::Check, "SELECT COUNT(*) FROM mysql.column_stats")
                    .await
                    .unwrap_err();
                assert_eq!(e.errno, Some(1142), "{label}: SELECT on column_stats");
                // The server's own statistics loads, logged under the
                // reader's account.
                if let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit") {
                    exec(&mut a, "FLUSH TABLES").await;
                    c.query(
                        Stage::Check,
                        &format!("SELECT id FROM {ST_DB}.customers WHERE id = 2"),
                    )
                    .await
                    .unwrap();
                    let needle = format!(",{ST_USER},");
                    let mut seen = false;
                    for _ in 0..20 {
                        let text = std::fs::read(&log).unwrap_or_default();
                        seen = text.split(|b| *b == b'\n').any(|l| {
                            let l = String::from_utf8_lossy(l);
                            l.contains(&needle) && l.contains(",READ,mysql,column_stats")
                        });
                        if seen {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    assert!(seen, "{label}: no statistics load record");
                }
            }
        }
        exec(&mut a, &format!("DROP USER IF EXISTS '{ST_USER}'@'%'")).await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {ST_DB}")).await;
    }
}
