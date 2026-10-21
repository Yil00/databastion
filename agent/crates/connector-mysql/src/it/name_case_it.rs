//! Names kept as written (ADR-0055 decision 3, security review H1) against
//! the dev servers: with `lower_case_table_names = 0` (the Linux default,
//! the dev servers' setting) `Customers` and `customers` are two tables,
//! and each Audit source (`server_audit` on MariaDB, `audit_log_filter` on
//! Percona Server, `performance_schema` on MySQL and MariaDB) names the
//! table each read was written with, unquoted or backquoted, never the
//! other one. A server with another `lower_case_table_names` is skipped
//! with a message (never a failure, also under `DATABASTION_TEST_REQUIRE`).

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{audit_target, collect_until, describe, env_path, percona, start_audit};
use super::*;

/// Test database (dropped and recreated).
const CASE_DB: &str = "databastion_case_it";
/// Test account of the `performance_schema` source (the Audit grant).
const CASE_PFS_USER: &str = "databastion_it_case";
/// The two tables, one name in two cases.
const TABLES: [&str; 2] = ["Customers", "customers"];

/// Whether the server compares table names with case; a skip message
/// otherwise.
async fn compares_with_case(label: &str, a: &mut Session) -> bool {
    let value = scalar(a, "SELECT @@GLOBAL.lower_case_table_names").await;
    if value.as_deref() == Some("0") {
        return true;
    }
    eprintln!(
        "skipped: {label}: lower_case_table_names is {value:?}, not 0 (names kept as written)"
    );
    false
}

async fn case_fixture(a: &mut Session) {
    exec(a, &format!("DROP DATABASE IF EXISTS {CASE_DB}")).await;
    exec(a, &format!("CREATE DATABASE {CASE_DB}")).await;
    for t in TABLES {
        exec(a, &format!("CREATE TABLE {CASE_DB}.{t} (id INT)")).await;
        exec(a, &format!("INSERT INTO {CASE_DB}.{t} VALUES (1), (2)")).await;
    }
}

/// A read by `user` naming exactly `CASE_DB`.`table`, a whole-table read
/// (`shape.full_table_read`) or not.
fn read_of(e: &MaskedEvent, user: &str, table: &str, whole: bool) -> bool {
    e.action() == EventAction::Read
        && e.principal().account_name() == user
        && e.objects().len() == 1
        && e.objects()[0].database().as_str() == CASE_DB
        && e.objects()[0].object().as_str() == table
        && e.signals()
            .iter()
            .any(|s| s.as_str() == "shape.full_table_read")
            == whole
}

/// Reads each table unquoted (whole table) and backquoted (one row), then
/// checks the events of `source`: one of each per table, and no object of
/// the test database spelled otherwise.
async fn reads_are_named_as_written(
    label: &str,
    a: &mut Session,
    admin_user: &str,
    connector: Arc<MysqlConnector>,
    t: &TargetConfig,
    source: EventSource,
) {
    let state = TempDir::new();
    let (task, mut rx) = start_audit(connector, t, &state.0);
    // The tailer opens the log, the first poll places the cursor.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    for table in TABLES {
        a.query(Stage::Check, &format!("SELECT * FROM {CASE_DB}.{table}"))
            .await
            .unwrap();
        a.query(
            Stage::Check,
            &format!("SELECT id FROM `{CASE_DB}`.`{table}` WHERE id = 1"),
        )
        .await
        .unwrap();
    }
    let done = |ev: &[MaskedEvent]| {
        TABLES.iter().all(|table| {
            [true, false]
                .iter()
                .all(|whole| ev.iter().any(|e| read_of(e, admin_user, table, *whole)))
        })
    };
    let mut events: Vec<MaskedEvent> = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(30), done).await;
    collect_until(&mut rx, &mut events, Duration::from_secs(2), |_| false).await;
    task.abort();
    let all: Vec<String> = events.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    assert!(done(&events), "{label}: {all:#?}");
    for e in &events {
        assert_eq!(e.source(), source, "{label}: {all:#?}");
        for o in e.objects() {
            if o.database().as_str().eq_ignore_ascii_case(CASE_DB) {
                assert_eq!(o.database().as_str(), CASE_DB, "{label}: {all:#?}");
                assert!(
                    TABLES.contains(&o.object().as_str()) || o.object().as_str() == "*",
                    "{label}: {all:#?}"
                );
            }
        }
    }
    exec(a, &format!("DROP DATABASE IF EXISTS {CASE_DB}")).await;
}

/// The log-file sources: `server_audit` (MariaDB) and `audit_log_filter`
/// (Percona Server).
#[tokio::test]
async fn audit_logs_name_tables_as_written() {
    let _serial = SERIAL.lock().await;
    let mut runs: Vec<(Server, Url, PathBuf, &str, EventSource)> = Vec::new();
    if let Some(server) = servers().into_iter().find(|s| s.name == "mariadb")
        && let Some(admin) = server.admin()
        && let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit")
    {
        runs.push((
            server,
            admin,
            log,
            "server_audit",
            EventSource::MariadbServerAudit,
        ));
    }
    if let Some(server) = percona() {
        if let Some(admin) = server.admin.clone() {
            if let Some(log) = env_path("DATABASTION_TEST_PERCONA_AUDIT_LOG", "percona-audit") {
                runs.push((server, admin, log, "json", EventSource::MysqlAuditLog));
            }
        } else {
            skip("percona", "DATABASTION_TEST_PERCONA_ADMIN_URL is not set");
        }
    }
    for (server, admin, log, format, source) in runs {
        let label = source.as_str();
        let mut a = admin_session(&server, &admin).await;
        if !compares_with_case(label, &mut a).await {
            continue;
        }
        case_fixture(&mut a).await;
        let (_d, t) = audit_target(
            &server,
            &server.url.user,
            &server.url.password,
            Some((&log, format)),
        );
        let connector = Arc::new(MysqlConnector::new());
        let health = connector.check(&t).await;
        assert!(health.reachable, "{label}: {health:?}");
        assert_eq!(connector.audit_source(&t), Some(source), "{label}");
        reads_are_named_as_written(label, &mut a, &admin.user, connector, &t, source).await;
    }
}

/// The `performance_schema` source (texts and digests), on MySQL and
/// MariaDB, with a test account holding the Audit grant.
#[tokio::test]
async fn performance_schema_names_tables_as_written() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let label = server.name;
        let mut a = admin_session(&server, &admin).await;
        if !compares_with_case(label, &mut a).await {
            continue;
        }
        case_fixture(&mut a).await;
        exec(
            &mut a,
            &format!("DROP USER IF EXISTS '{CASE_PFS_USER}'@'%'"),
        )
        .await;
        exec(
            &mut a,
            &format!("CREATE USER '{CASE_PFS_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        for grant in [
            format!(
                "GRANT SELECT ON {}.* TO '{CASE_PFS_USER}'@'%'",
                server.url.dbname
            ),
            format!("GRANT SELECT ON performance_schema.* TO '{CASE_PFS_USER}'@'%'"),
        ] {
            exec(&mut a, &grant).await;
        }
        let (_d, t) = audit_target(&server, CASE_PFS_USER, IT_PASSWORD, None);
        let connector = Arc::new(MysqlConnector::new());
        let health = connector.check(&t).await;
        assert_eq!(
            health.audit_level,
            AuditLevel::Partial,
            "{label}: {health:?}"
        );
        assert_eq!(
            connector.audit_source(&t),
            Some(EventSource::PerformanceSchema),
            "{label}"
        );
        reads_are_named_as_written(
            label,
            &mut a,
            &admin.user,
            connector,
            &t,
            EventSource::PerformanceSchema,
        )
        .await;
        exec(
            &mut a,
            &format!("DROP USER IF EXISTS '{CASE_PFS_USER}'@'%'"),
        )
        .await;
    }
}

/// ADR-0055 decisions 2 and 4: `check()` reports how the server compares
/// names, from `lower_case_table_names` read with the agent's own account
/// (0, the dev servers' setting: `sensitive`; 1 or 2, an engine-matrix
/// entry initialized so: `insensitive`), and a later check that fails
/// (here: a wrong password) keeps that value. Also run against a server
/// with another setting, where the expectation follows its value.
#[tokio::test]
async fn check_reports_the_name_case_of_the_server() {
    use databastion_core::name_case::{NameCase, NameCaseReport};
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let (_dir, t) = agent_target(&server);
        let mut s = Session::connect(&t, Timeouts::new(Duration::from_secs(10)))
            .await
            .unwrap();
        let value = scalar(&mut s, "SELECT @@GLOBAL.lower_case_table_names").await;
        s.close().await;
        let want = match value.as_deref() {
            Some("0") => NameCase::Sensitive,
            Some("1" | "2") => NameCase::Insensitive,
            other => panic!("{}: lower_case_table_names {other:?}", server.name),
        };
        eprintln!(
            "{}: lower_case_table_names {value:?}: name case {want:?}",
            server.name
        );
        let connector = MysqlConnector::new();
        assert_eq!(connector.name_case(&t), None, "nothing read yet");
        let health = connector.check(&t).await;
        assert!(health.reachable, "{}: {health:?}", server.name);
        let detail = health.detail.unwrap_or_default();
        assert!(
            detail.contains("lower_case_table_names"),
            "{}: {detail}",
            server.name
        );
        assert_eq!(
            connector.name_case(&t),
            Some(NameCaseReport::uniform(want)),
            "{}",
            server.name
        );
        // The same connector, the target's password now wrong: the check
        // fails and the value read on this server run is kept (M1).
        let (_dir2, bad) = target(&server, &server.url.user, "wrong-password-FAKE");
        assert_eq!(bad.id, t.id);
        let health = connector.check(&bad).await;
        assert!(!health.reachable);
        assert_eq!(
            connector.name_case(&bad),
            Some(NameCaseReport::uniform(want)),
            "{}",
            server.name
        );
    }
}
