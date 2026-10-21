//! Names kept as written (ADR-0055 decision 3, security review H1) against
//! the dev servers: with `lower_case_table_names = 0` (the Linux default,
//! the dev servers' setting) `Customers` and `customers` are two tables,
//! and each Audit source (`server_audit` on MariaDB, `audit_log_filter` on
//! Percona Server, `performance_schema` on MySQL and MariaDB) names the
//! table each read was written with, unquoted or backquoted, never the
//! other one. A server with another `lower_case_table_names` is skipped
//! with a message (never a failure, also under `DATABASTION_TEST_REQUIRE`).
//!
//! Also (the #300 review and follow-up): a common table expression hides
//! only a table named as it is written, and the servers' system-schema
//! rules, `Performance_Schema` and `Information_Schema` refused in any
//! case, `SYS` and `MySQL` user databases that Discovery samples. And
//! (ADR-0055 decision 10) the reported value against the setting the
//! engine matrix initialized the server with,
//! `DATABASTION_TEST_<S>_LOWER_CASE_TABLE_NAMES` (`dev/agent-it.sh`).

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
}

/// The #300 review: a common table expression hides only the relation
/// named exactly as it (`classifiers::query`, MySQL: under
/// `lower_case_table_names = 0` the servers resolve `FROM Customers` to the
/// table `Customers`, not to a CTE `customers`; a CTE named in another
/// case is reported as a read, fail closed). Each statement, unqualified
/// in the test database, on a stream of its own:
/// - `WITH customers AS (SELECT 9 AS id) SELECT id FROM Customers`: when
///   the server read the table (no row `9`), an event names `Customers`;
/// - `WITH customers AS (SELECT id FROM Customers) SELECT id FROM
///   customers`: an event names `Customers`, the table read in the CTE.
///
/// Neither names the table `customers`, which neither statement reads.
async fn ctes_follow_the_server_case_rule(
    label: &str,
    a: &mut Session,
    admin_user: &str,
    connector: &Arc<MysqlConnector>,
    t: &TargetConfig,
    source: EventSource,
) {
    exec(a, &format!("USE {CASE_DB}")).await;
    let names_table = |e: &MaskedEvent| {
        e.action() == EventAction::Read
            && e.principal().account_name() == admin_user
            && e.objects()
                .iter()
                .any(|o| o.database().as_str() == CASE_DB && o.object().as_str() == "Customers")
    };
    for (i, text) in [
        "WITH customers AS (SELECT 9 AS id) SELECT id FROM Customers",
        "WITH customers AS (SELECT id FROM Customers) SELECT id FROM customers",
    ]
    .into_iter()
    .enumerate()
    {
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(connector), t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let rows = a.query(Stage::Check, text).await.unwrap();
        let from_cte = rows
            .iter()
            .any(|r| r.first().and_then(|v| v.as_deref()) == Some("9"));
        let table_read = i == 1 || !from_cte;
        eprintln!(
            "[it] name_case: {label}: `{text}` read {}",
            if from_cte {
                "the CTE"
            } else {
                "the table Customers"
            }
        );
        let done = |ev: &[MaskedEvent]| ev.iter().any(&names_table);
        let mut events: Vec<MaskedEvent> = Vec::new();
        let wait = if table_read { 30 } else { 10 };
        collect_until(&mut rx, &mut events, Duration::from_secs(wait), done).await;
        collect_until(&mut rx, &mut events, Duration::from_secs(2), |_| false).await;
        task.abort();
        let all: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{label} `{text}` events ({}):\n{}",
            all.len(),
            all.join("\n")
        );
        if table_read {
            assert!(done(&events), "{label}: `{text}`: {all:#?}");
        }
        for e in &events {
            assert_eq!(e.source(), source, "{label}: {all:#?}");
            if e.principal().account_name() != admin_user {
                continue;
            }
            for o in e.objects() {
                if o.database().as_str().eq_ignore_ascii_case(CASE_DB) {
                    assert!(
                        ["Customers", "*"].contains(&o.object().as_str()),
                        "{label}: `{text}`: {all:#?}"
                    );
                }
            }
        }
    }
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
        reads_are_named_as_written(
            label,
            &mut a,
            &admin.user,
            Arc::clone(&connector),
            &t,
            source,
        )
        .await;
        ctes_follow_the_server_case_rule(label, &mut a, &admin.user, &connector, &t, source).await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {CASE_DB}")).await;
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
            Arc::clone(&connector),
            &t,
            EventSource::PerformanceSchema,
        )
        .await;
        ctes_follow_the_server_case_rule(
            label,
            &mut a,
            &admin.user,
            &connector,
            &t,
            EventSource::PerformanceSchema,
        )
        .await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {CASE_DB}")).await;
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
        // The setting the dev service was started with (the engine
        // matrix's `lower_case_table_names = 1` entries, decision 10): the
        // server must run with it.
        let var = format!(
            "DATABASTION_TEST_{}_LOWER_CASE_TABLE_NAMES",
            server.name.to_uppercase()
        );
        if let Some(expected) = std::env::var(&var).ok().filter(|v| !v.is_empty()) {
            assert_eq!(
                value.as_deref(),
                Some(expected.as_str()),
                "{}: {var}",
                server.name
            );
        }
        let want = match value.as_deref() {
            Some("0") => NameCase::Sensitive,
            Some("1" | "2") => NameCase::Insensitive,
            other => panic!("{}: lower_case_table_names {other:?}", server.name),
        };
        eprintln!(
            "[it] name_case: {}: lower_case_table_names {value:?}: name case {want:?}",
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

/// The #300 review: the servers refuse a database named
/// `performance_schema` or `information_schema` in another case, whatever
/// `lower_case_table_names` (they compare those names without case), so
/// that the agent may recognize them in any case (`audit::events`,
/// `sql::is_system_schema`) without hiding a user database.
#[tokio::test]
async fn system_schemas_in_another_case_are_refused() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let label = server.name;
        let mut a = admin_session(&server, &admin).await;
        for name in [
            "Performance_Schema",
            "PERFORMANCE_SCHEMA",
            "Information_Schema",
        ] {
            let created = a
                .exec(Stage::Check, &format!("CREATE DATABASE `{name}`"))
                .await;
            eprintln!(
                "[it] name_case: {label}: CREATE DATABASE `{name}`: {}",
                match &created {
                    Ok(_) => "accepted".to_owned(),
                    Err(e) => format!("refused (errno {:?})", e.errno),
                }
            );
            if created.is_ok() {
                // A database of that spelling now exists: removed (by the
                // same spelling) before the failure.
                let _ = a
                    .exec(Stage::Check, &format!("DROP DATABASE `{name}`"))
                    .await;
                panic!("{label}: a database `{name}` was created");
            }
            let n = count(
                &mut a,
                &format!(
                    "SELECT COUNT(*) FROM information_schema.SCHEMATA \
                     WHERE CAST(SCHEMA_NAME AS BINARY) = '{name}'"
                ),
            )
            .await;
            assert_eq!(n, 0, "{label}: {name}");
        }
    }
}

/// Fake e-mail addresses of the `SYS` / `MySQL` user databases.
const SYSTEM_LIKE_ROWS: u32 = 40;
/// Discovery account of [`user_databases_named_like_system_schemas_are_sampled`].
const SYSTEM_LIKE_USER: &str = "databastion_it_case_scan";

/// The #300 follow-up: under `lower_case_table_names = 0` the user
/// databases `SYS` and `MySQL` are not the system schemas `sys` and
/// `mysql`, and Discovery samples them (its table list compares `mysql`
/// and `sys` as bytes, as the server does). A database the server refuses
/// to create in that case is left out with a message. A server with
/// another setting is skipped.
#[tokio::test]
async fn user_databases_named_like_system_schemas_are_sampled() {
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
        exec(
            &mut a,
            &format!("DROP USER IF EXISTS '{SYSTEM_LIKE_USER}'@'%'"),
        )
        .await;
        let plugin = match server.flavor() {
            Flavor::Mysql => "IDENTIFIED WITH caching_sha2_password BY",
            Flavor::Mariadb => "IDENTIFIED BY",
        };
        exec(
            &mut a,
            &format!("CREATE USER '{SYSTEM_LIKE_USER}'@'%' {plugin} '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        let mut made = Vec::new();
        for db in ["SYS", "MySQL"] {
            let _ = a
                .exec(Stage::Check, &format!("DROP DATABASE IF EXISTS `{db}`"))
                .await;
            if let Err(e) = a
                .exec(Stage::Check, &format!("CREATE DATABASE `{db}`"))
                .await
            {
                eprintln!(
                    "[it] name_case: {label}: CREATE DATABASE `{db}` refused (errno {:?}): \
                     not tested",
                    e.errno
                );
                continue;
            }
            for statement in [
                format!("CREATE TABLE `{db}`.people (id INT PRIMARY KEY, email VARCHAR(120))"),
                format!(
                    "INSERT INTO `{db}`.people (id, email) \
                     WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n \
                     WHERE i < {SYSTEM_LIKE_ROWS}) \
                     SELECT i, CONCAT('case.user', i, '@example.com') FROM n"
                ),
                format!("GRANT SELECT ON `{db}`.* TO '{SYSTEM_LIKE_USER}'@'%'"),
            ] {
                exec(&mut a, &statement).await;
            }
            made.push(db);
        }
        let (_dir, t) = target(&server, SYSTEM_LIKE_USER, IT_PASSWORD);
        let (r, findings) = scan(&t).await;
        r.unwrap();
        let found = located(&findings);
        eprintln!(
            "[it] name_case: {label}: user databases {made:?}: findings in {:?}",
            found.iter().map(|k| k.0.as_str()).collect::<BTreeSet<_>>()
        );
        for db in &made {
            let want = key_of(normalize(db).as_str(), "people", "email", "pii.email");
            assert!(found.contains(&want), "{label}: {db}: {found:?}");
        }
        for k in &found {
            assert!(
                !["mysql", "sys", "information_schema", "performance_schema"]
                    .contains(&k.0.as_str()),
                "{label}: {k:?}"
            );
        }
        for db in &made {
            exec(&mut a, &format!("DROP DATABASE IF EXISTS `{db}`")).await;
        }
        exec(
            &mut a,
            &format!("DROP USER IF EXISTS '{SYSTEM_LIKE_USER}'@'%'"),
        )
        .await;
    }
}
