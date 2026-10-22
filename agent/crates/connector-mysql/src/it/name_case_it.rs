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

/// Fake ticket ids of a user database spelled like a system schema (never
/// valid anywhere).
const PFS_LIKE_TICKETS: [&str; 2] = [
    "TGT-7-FakeCaseTgtValueAaaaaaaaaaaaa-cas01",
    "ST-8-FakeCaseStValueBbbbbbbbbbbbbbb-cas01",
];
/// Test account of [`system_schemas_in_another_case_follow_the_server`].
const PFS_LIKE_USER: &str = "databastion_it_case_pfs";

/// The #300 review, corrected by the CI runs of PR #308: which spellings
/// of the system schemas a user may create, per engine. MySQL refuses
/// `information_schema` and `performance_schema` in any other ASCII case
/// (1044) but lets a user create tables in `performance_ſchema` (U+017F);
/// both servers refuse `Information_Schema`; MariaDB accepts `CREATE
/// DATABASE Performance_Schema` under `lower_case_table_names = 0` but
/// refuses a table in it (1142), and reads the system schema through that
/// spelling. For each spelling accepted, either a table can be created
/// there, and the database is sampled, guarded and its reads reported, or
/// none can, and nothing from a system object (engine
/// `PERFORMANCE_SCHEMA`, `SYSTEM VIEW`) is sampled, as the agent account
/// too.
#[tokio::test]
async fn system_schemas_in_another_case_follow_the_server() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let label = server.name;
        let mut a = admin_session(&server, &admin).await;
        let lctn = scalar(&mut a, "SELECT @@GLOBAL.lower_case_table_names").await;
        for name in [
            "Performance_Schema",
            "PERFORMANCE_SCHEMA",
            "Information_Schema",
            "INFORMATION_SCHEMA",
            // The servers fold these names with `utf8mb3_general_ci`,
            // where `ſ` is `S` and `ı` is `I` (security review L8).
            "performance_\u{17F}chema",
            "\u{131}nformation_\u{17F}chema",
        ] {
            // By name, Discovery skips the ASCII spellings only.
            assert_eq!(
                crate::sql::is_system_schema(name),
                name.is_ascii(),
                "{name}"
            );
            let created = a
                .exec(Stage::Check, &format!("CREATE DATABASE `{name}`"))
                .await;
            eprintln!(
                "[it] name_case: {label}: lower_case_table_names {lctn:?}: CREATE DATABASE \
                 `{name}`: {}",
                match &created {
                    Ok(_) => "accepted".to_owned(),
                    Err(e) => format!("refused (errno {:?})", e.errno),
                }
            );
            // 1007: left by an earlier run whose drop the server refused.
            if created.as_ref().is_err_and(|e| e.errno != Some(1007)) {
                let n = count(
                    &mut a,
                    &format!(
                        "SELECT COUNT(*) FROM information_schema.SCHEMATA \
                         WHERE CAST(SCHEMA_NAME AS BINARY) = '{name}'"
                    ),
                )
                .await;
                assert_eq!(n, 0, "{label}: {name}");
                continue;
            }
            // In a task of its own: whatever its outcome, the database and
            // the test account are dropped before a failure is raised.
            let checked = tokio::spawn(accepted_spelling_holds_nothing(
                server.clone(),
                admin.clone(),
                name.to_owned(),
            ))
            .await;
            let dropped = a
                .exec(Stage::Check, &format!("DROP DATABASE `{name}`"))
                .await;
            let _ = a
                .exec(
                    Stage::Check,
                    &format!("DROP USER IF EXISTS '{PFS_LIKE_USER}'@'%'"),
                )
                .await;
            match checked {
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) => panic!("{label}: {name}: {e}"),
                Ok(()) => {}
            }
            // Measured, not asserted: the server may refuse to drop a
            // spelling it resolves to the system schema (a leftover empty
            // database holds nothing, and the CI volumes are fresh).
            eprintln!(
                "[it] name_case: {label}: DROP DATABASE `{name}`: {}",
                match &dropped {
                    Ok(_) => "accepted".to_owned(),
                    Err(e) => format!("refused (errno {:?})", e.errno),
                }
            );
            // The ASCII spellings, measured: MySQL refuses them (1044).
            if name.is_ascii() {
                assert_eq!(
                    server.flavor(),
                    Flavor::Mariadb,
                    "{label}: MySQL accepted `{name}`"
                );
            }
            assert!(
                !name.eq_ignore_ascii_case("information_schema"),
                "{label}: `{name}` accepted: Audit leaves its reads out in any case"
            );
        }
    }
}

/// A database `name` (spelled like a system schema) the server accepted:
/// when a table can be created in it, a user database
/// ([`table_database_is_covered`]); otherwise (MariaDB `Performance_Schema`)
/// what
/// reading through that spelling does and what the catalog lists under it
/// are measured, a Discovery account granted on it samples nothing there
/// nor in any system schema (MariaDB 11.8 lists the system tables under
/// that spelling), and on MariaDB with the `server_audit` log a read of a
/// statement-text table through that spelling, when the server answers
/// it, is reported (Audit leaves out reads of `performance_schema` only as
/// written). The caller drops the database and the test account.
async fn accepted_spelling_holds_nothing(server: Server, admin: Url, name: String) {
    let (server, name) = (&server, name.as_str());
    let mut admin_s = admin_session(server, &admin).await;
    let a = &mut admin_s;
    let label = server.name;
    let u = format!("'{PFS_LIKE_USER}'@'%'");
    exec(a, &format!("DROP USER IF EXISTS {u}")).await;
    exec(
        a,
        &format!("CREATE USER {u} IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
    )
    .await;
    let table = a
        .exec(
            Stage::Check,
            &format!("CREATE TABLE `{name}`.people (id INT PRIMARY KEY, email VARCHAR(120))"),
        )
        .await;
    eprintln!(
        "[it] name_case: {label}: CREATE TABLE in `{name}` as the administrator: {}",
        match &table {
            Ok(_) => "accepted".to_owned(),
            Err(e) => format!("refused (errno {:?})", e.errno),
        }
    );
    if table.is_ok() {
        table_database_is_covered(server, a, name).await;
        return;
    }
    let probe = format!("SELECT COUNT(*) FROM `{name}`.events_statements_current");
    let answered = match a.query(Stage::Check, &probe).await {
        Ok(rows) => {
            eprintln!(
                "[it] name_case: {label}: `{probe}` answered ({} row(s)): the spelling reads \
                 the system schema",
                rows.len()
            );
            true
        }
        Err(e) => {
            eprintln!(
                "[it] name_case: {label}: `{probe}` refused (errno {:?})",
                e.errno
            );
            false
        }
    };
    let tables = count(
        a,
        &format!(
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE CAST(TABLE_SCHEMA AS BINARY) = '{name}'"
        ),
    )
    .await;
    // MariaDB 10.11 and 11.4 list none, 11.8 lists the system tables
    // (CI runs of PR #308): measured, not asserted, with their engines and
    // types.
    eprintln!("[it] name_case: {label}: tables listed in `{name}`: {tables}");
    let kinds = a
        .query(
            Stage::Check,
            &format!(
                "SELECT COALESCE(ENGINE, 'NULL'), TABLE_TYPE, COUNT(*) \
                 FROM information_schema.TABLES WHERE CAST(TABLE_SCHEMA AS BINARY) = '{name}' \
                 GROUP BY 1, 2"
            ),
        )
        .await
        .unwrap();
    for row in &kinds {
        eprintln!("[it] name_case: {label}: `{name}` lists engine / type / count {row:?}");
    }
    let granted = a
        .exec(Stage::Check, &format!("GRANT SELECT ON `{name}`.* TO {u}"))
        .await;
    eprintln!(
        "[it] name_case: {label}: GRANT SELECT ON `{name}`.*: {}",
        match &granted {
            Ok(_) => "accepted".to_owned(),
            Err(e) => format!("refused (errno {:?})", e.errno),
        }
    );
    // Discovery while the alias exists, as the test account granted on it
    // and as the dev agent account (security review L9): no table of a
    // system schema, under any spelling the servers fold to it, sampled.
    let (_dir, granted_t) = target(server, PFS_LIKE_USER, IT_PASSWORD);
    let (_dir2, agent_t) = agent_target(server);
    for (who, t) in [("granted account", &granted_t), ("agent account", &agent_t)] {
        let mut s = Session::connect(t, Timeouts::new(Duration::from_secs(10)))
            .await
            .unwrap();
        let seen = count(
            &mut s,
            &format!(
                "SELECT COUNT(*) FROM information_schema.TABLES \
                 WHERE CAST(TABLE_SCHEMA AS BINARY) = '{name}'"
            ),
        )
        .await;
        s.close().await;
        let (r, findings) = scan(t).await;
        r.unwrap();
        let found = located(&findings);
        eprintln!(
            "[it] name_case: {label}: {who}: tables listed in `{name}`: {seen}; findings in {:?}",
            found.iter().map(|k| k.0.as_str()).collect::<BTreeSet<_>>()
        );
        let alias = normalize(name);
        for k in &found {
            assert!(
                !crate::sql::is_system_schema(&k.0) && k.0 != alias.as_str(),
                "{label}: {name}: {who}: a system object sampled: {k:?}"
            );
        }
    }
    if !answered || server.flavor() != Flavor::Mariadb {
        return;
    }
    let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit") else {
        return;
    };
    let admin_user = server
        .admin
        .as_ref()
        .map(|u| u.user.clone())
        .unwrap_or_default();
    let (_d, t) = audit_target(
        server,
        &server.url.user,
        &server.url.password,
        Some((&log, "server_audit")),
    );
    let connector = Arc::new(MysqlConnector::new());
    let health = connector.check(&t).await;
    assert!(health.reachable, "{label}: {health:?}");
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let read = format!("SELECT SQL_TEXT FROM {name}.events_statements_current LIMIT 1");
    a.query(Stage::Check, &read).await.unwrap();
    let reported = |ev: &[MaskedEvent]| {
        ev.iter().any(|e| {
            e.principal().account_name() == admin_user
                && e.always_report()
                && e.objects().iter().any(|o| {
                    o.object()
                        .as_str()
                        .eq_ignore_ascii_case("events_statements_current")
                })
        })
    };
    let mut events: Vec<MaskedEvent> = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(30), reported).await;
    task.abort();
    let all: Vec<String> = events.iter().map(describe).collect();
    eprintln!(
        "[it] name_case: {label}: `{read}` events ({}): {}",
        all.len(),
        all.join(" | ")
    );
    assert!(reported(&events), "{label}: {name}: {all:#?}");
}

/// A database `name` spelled like a system schema in which the server let
/// the administrator create a table (`people`, created by the caller): a
/// user database (MySQL `performance_ſchema`, CI run of PR #308). Its fake
/// e-mail addresses are sampled by Discovery, a CAS ticket table in it is
/// counted and never sampled, `check()` reports it readable, and on
/// MariaDB with the `server_audit` log its reads are reported under its
/// name.
async fn table_database_is_covered(server: &Server, a: &mut Session, name: &str) {
    let label = server.name;
    let [t0, t1] = PFS_LIKE_TICKETS;
    let u = format!("'{PFS_LIKE_USER}'@'%'");
    for statement in [
        format!(
            "INSERT INTO `{name}`.people (id, email) \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n \
             WHERE i < {SYSTEM_LIKE_ROWS}) \
             SELECT i, CONCAT('pfs.case.user', i, '@example.com') FROM n"
        ),
        format!(
            "CREATE TABLE `{name}`.cas_tickets (id varchar(255), parent_id varchar(255), \
             body text, type varchar(255), principal_id varchar(255))"
        ),
        format!(
            "INSERT INTO `{name}`.cas_tickets VALUES \
             ('{t0}', NULL, '{{}}', 'org.apereo.cas.ticket.TicketGrantingTicketImpl', 'x'), \
             ('{t1}', '{t0}', '{{}}', 'org.apereo.cas.ticket.ServiceTicketImpl', 'x')"
        ),
        format!("GRANT SELECT ON `{name}`.* TO {u}"),
    ] {
        exec(a, &statement).await;
    }
    let db = normalize(name);
    let (_dir, t) = target(server, PFS_LIKE_USER, IT_PASSWORD);
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(100_000);
    MysqlConnector::new().discover(&job, &sink).await.unwrap();
    drop(sink);
    let mut findings = Vec::new();
    while let Some(f) = rx.recv().await {
        findings.push(f);
    }
    let found = located(&findings);
    eprintln!(
        "[it] name_case: {label}: user database `{name}`: {} registries, findings {found:?}",
        job.cas_guard().registries()
    );
    assert!(
        found.contains(&key_of(db.as_str(), "people", "email", "pii.email")),
        "{label}: {name}: {found:?}"
    );
    assert_eq!(job.cas_guard().registries(), 1, "{label}: {name}");
    for k in &found {
        assert_ne!(k.1, "cas_tickets", "{label}: {name}: {k:?}");
        // ADR-0009 NFKC: `performance_ſchema` reaches the console as
        // `performance_schema` (the normalization-marker follow-up); only
        // its own `people` table may carry that name here.
        assert!(
            (k.0 == db.as_str() && k.1 == "people")
                || !["mysql", "sys", "information_schema", "performance_schema"]
                    .contains(&k.0.as_str()),
            "{label}: {name}: a system schema sampled: {k:?}"
        );
    }
    let text = format!("{findings:?}");
    for v in PFS_LIKE_TICKETS {
        assert!(!text.contains(v), "{label}: {v} leaked");
    }
    let health = MysqlConnector::new().check(&t).await;
    assert!(health.reachable, "{label}: {health:?}");
    let readable = health
        .notes
        .iter()
        .find(|n| n.code() == NoteCode::PrivilegeTicketCredentialsReadable)
        .map(|n| n.count().unwrap_or(0));
    assert_eq!(readable, Some(1), "{label}: {name}: {:?}", health.notes);
    // Audit: reads of the user database by the administrator, unquoted
    // and backquoted, reported under its name (server_audit table records
    // and texts).
    if server.flavor() != Flavor::Mariadb {
        return;
    }
    let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit") else {
        return;
    };
    let admin_user = server
        .admin
        .as_ref()
        .map(|u| u.user.clone())
        .unwrap_or_default();
    let (_d, t) = audit_target(
        server,
        &server.url.user,
        &server.url.password,
        Some((&log, "server_audit")),
    );
    let connector = Arc::new(MysqlConnector::new());
    let health = connector.check(&t).await;
    assert!(health.reachable, "{label}: {health:?}");
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    for text in [
        format!("SELECT * FROM {name}.people"),
        format!("SELECT email FROM `{name}`.`people` WHERE id = 1"),
    ] {
        a.query(Stage::Check, &text).await.unwrap();
    }
    let reads = |ev: &[MaskedEvent]| {
        ev.iter()
            .filter(|e| {
                e.action() == EventAction::Read
                    && e.principal().account_name() == admin_user
                    && e.objects().iter().any(|o| {
                        o.database().as_str() == db.as_str() && o.object().as_str() == "people"
                    })
            })
            .count()
    };
    let mut events: Vec<MaskedEvent> = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(30), |ev| {
        reads(ev) >= 2
    })
    .await;
    task.abort();
    let all: Vec<String> = events.iter().map(describe).collect();
    eprintln!(
        "{label} `{name}` events ({}):\n{}",
        all.len(),
        all.join("\n")
    );
    assert!(reads(&events) >= 2, "{label}: {name}: {all:#?}");
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

/// Test account of [`folded_system_spellings_are_user_databases`].
const FOLDED_USER: &str = "databastion_it_case_fold";
/// Fake e-mail rows of its user databases.
const FOLDED_ROWS: u32 = 30;

/// #308 final review N7: databases spelled like `mysql` and `sys` through
/// the Unicode case fold the servers use to compare names (`MYſQL`,
/// `ſys`, U+017F; `'mysql' = 'MYſQL'` holds on both servers), each with
/// the system table that proves an alias (`user`, `version`) and the
/// listed table a user may create there (`column_stats`, ADR-0048;
/// `processlist`, ADR-0045). Measured with `lower_case_table_names = 0`
/// (a server with another setting is skipped): whether the server accepts
/// the database, and whether `SELECT 1 FROM <spelling>.<system table>`
/// reads the system schema. An alias fails the test, closed: Discovery
/// would sample the system tables listed under that spelling, and Audit
/// would leave out none of their reads but name them as a user location.
/// Otherwise the database is a user database: Discovery samples it under
/// its own name, and a read of its tables is reported under that name on
/// the `performance_schema` source (and on MariaDB's `server_audit` log),
/// its listed table both as written and under the listed name, always
/// reported (#308 final review L10).
#[tokio::test]
async fn folded_system_spellings_are_user_databases() {
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
        let u = format!("'{FOLDED_USER}'@'%'");
        exec(&mut a, &format!("DROP USER IF EXISTS {u}")).await;
        let plugin = match server.flavor() {
            Flavor::Mysql => "IDENTIFIED WITH caching_sha2_password BY",
            Flavor::Mariadb => "IDENTIFIED BY",
        };
        exec(
            &mut a,
            &format!("CREATE USER {u} {plugin} '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        let mut made: Vec<(&str, &str, &str)> = Vec::new();
        for (name, system, proof, listed) in [
            ("MY\u{17F}QL", "mysql", "user", "column_stats"),
            ("\u{17F}ys", "sys", "version", "processlist"),
        ] {
            let _ = a
                .exec(Stage::Check, &format!("DROP DATABASE IF EXISTS `{name}`"))
                .await;
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
            if created.is_err() {
                continue;
            }
            let listed_n = count(
                &mut a,
                &format!(
                    "SELECT COUNT(*) FROM information_schema.TABLES \
                     WHERE CAST(TABLE_SCHEMA AS BINARY) = '{name}'"
                ),
            )
            .await;
            let probe = format!("SELECT 1 FROM `{name}`.`{proof}` LIMIT 1");
            let alias = a.query(Stage::Check, &probe).await;
            eprintln!(
                "[it] name_case: {label}: empty `{name}`: {listed_n} table(s) listed; `{probe}`: {}",
                match &alias {
                    Ok(rows) => format!("answered ({} row(s)): an alias of `{system}`", rows.len()),
                    Err(e) => format!("refused (errno {:?}): not an alias of `{system}`", e.errno),
                }
            );
            // Only "unknown table" proves the spelling is not an alias; any
            // other refusal could hide one (#318 review L2).
            if let Err(e) = &alias {
                assert_eq!(
                    e.errno,
                    Some(1146),
                    "{label}: `{probe}` refused for another reason than an unknown table"
                );
            }
            if alias.is_ok() || listed_n != 0 {
                let _ = a
                    .exec(Stage::Check, &format!("DROP DATABASE `{name}`"))
                    .await;
                let _ = a
                    .exec(Stage::Check, &format!("DROP USER IF EXISTS {u}"))
                    .await;
                panic!(
                    "{label}: `{name}` reads or lists the system schema `{system}`: Discovery and \
                     Audit must treat that spelling as `{system}` (#308 final review N7)"
                );
            }
            for statement in [
                format!("CREATE TABLE `{name}`.people (id INT PRIMARY KEY, email VARCHAR(120))"),
                format!(
                    "CREATE TABLE `{name}`.`{listed}` (id INT PRIMARY KEY, email VARCHAR(120))"
                ),
                format!("GRANT SELECT ON `{name}`.* TO {u}"),
            ] {
                exec(&mut a, &statement).await;
            }
            for table in ["people", listed] {
                exec(
                    &mut a,
                    &format!(
                        "INSERT INTO `{name}`.`{table}` (id, email) \
                         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n \
                         WHERE i < {FOLDED_ROWS}) \
                         SELECT i, CONCAT('fold.user', i, '@example.com') FROM n"
                    ),
                )
                .await;
            }
            made.push((name, system, listed));
        }
        // Discovery as the test account: both tables of each database,
        // under its own name, nothing under a system schema's.
        let (_dir, t) = target(&server, FOLDED_USER, IT_PASSWORD);
        let (r, findings) = scan(&t).await;
        r.unwrap();
        let found = located(&findings);
        eprintln!(
            "[it] name_case: {label}: user databases {:?}: findings {found:?}",
            made.iter().map(|m| m.0).collect::<Vec<_>>()
        );
        for (name, _, listed) in &made {
            for table in ["people", listed] {
                let want = key_of(normalize(name).as_str(), table, "email", "pii.email");
                assert!(found.contains(&want), "{label}: {name}.{table}: {found:?}");
            }
        }
        // ADR-0009 NFKC: `ſys` reaches the console as `sys` (measured; the
        // ADR-0056 marker on names altered by normalization, #308 final
        // review N8); only the user database's own tables may carry a
        // system schema's name here.
        for k in &found {
            assert!(
                made.iter()
                    .any(|(name, _, listed)| k.0 == normalize(name).as_str()
                        && (k.1 == "people" || k.1 == *listed))
                    || !["mysql", "sys", "information_schema", "performance_schema"]
                        .contains(&k.0.as_str()),
                "{label}: a system schema sampled: {k:?}"
            );
        }
        // Audit: the `performance_schema` source as the test account, then
        // MariaDB's `server_audit` log.
        exec(
            &mut a,
            &format!("GRANT SELECT ON performance_schema.* TO {u}"),
        )
        .await;
        let admin_user = admin.user.clone();
        let mut sources = vec![(
            audit_target(&server, FOLDED_USER, IT_PASSWORD, None),
            EventSource::PerformanceSchema,
        )];
        if server.flavor() == Flavor::Mariadb
            && let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit")
        {
            sources.push((
                audit_target(
                    &server,
                    &server.url.user,
                    &server.url.password,
                    Some((&log, "server_audit")),
                ),
                EventSource::MariadbServerAudit,
            ));
        }
        for ((_d, t), source) in sources {
            folded_reads_are_named_as_written(label, &mut a, &admin_user, &t, source, &made).await;
        }
        for (name, _, _) in &made {
            exec(&mut a, &format!("DROP DATABASE IF EXISTS `{name}`")).await;
        }
        exec(&mut a, &format!("DROP USER IF EXISTS {u}")).await;
    }
}

/// The administrator reads each table of the [`made`] user databases;
/// `source` reports `people` under the database's name, and the listed
/// table as written and under the listed name, always reported (#308
/// final review L10).
async fn folded_reads_are_named_as_written(
    label: &str,
    a: &mut Session,
    admin_user: &str,
    t: &TargetConfig,
    source: EventSource,
    made: &[(&str, &str, &str)],
) {
    let connector = Arc::new(MysqlConnector::new());
    let health = connector.check(t).await;
    assert!(health.reachable, "{label}: {health:?}");
    assert_eq!(connector.audit_source(t), Some(source), "{label}");
    let state = TempDir::new();
    let (task, mut rx) = start_audit(Arc::clone(&connector), t, &state.0);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    for (name, _, listed) in made {
        for table in ["people", listed] {
            a.query(Stage::Check, &format!("SELECT * FROM `{name}`.`{table}`"))
                .await
                .unwrap();
        }
    }
    let names = |e: &MaskedEvent, db: &str, table: &str| {
        e.objects()
            .iter()
            .any(|o| o.database().as_str() == db && o.object().as_str() == table)
    };
    let done = |ev: &[MaskedEvent]| {
        made.iter().all(|(name, system, listed)| {
            let db = normalize(name);
            let by_admin = |e: &&MaskedEvent| {
                e.action() == EventAction::Read && e.principal().account_name() == admin_user
            };
            ev.iter()
                .filter(by_admin)
                .any(|e| names(e, db.as_str(), "people"))
                && ev.iter().filter(by_admin).any(|e| {
                    e.always_report() && names(e, db.as_str(), listed) && names(e, system, listed)
                })
        })
    };
    let mut events: Vec<MaskedEvent> = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(30), done).await;
    task.abort();
    let all: Vec<String> = events.iter().map(describe).collect();
    eprintln!(
        "[it] name_case: {label}: {} reads of {:?} ({} events):\n{}",
        source.as_str(),
        made.iter().map(|m| m.0).collect::<Vec<_>>(),
        all.len(),
        all.join("\n")
    );
    assert!(done(&events), "{label}: {}: {all:#?}", source.as_str());
}
