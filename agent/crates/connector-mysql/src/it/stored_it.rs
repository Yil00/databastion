//! Reads into variables (#195 review M2) and `CREATE … AS SELECT` sources
//! (#186 review L4) against the dev servers, on the three sources:
//! `performance_schema` (MySQL 8.4 and MariaDB 11.4), the MariaDB
//! `server_audit` log (`QUERY_DML` and `TABLE` records) and the Percona
//! `audit_log_filter` JSON log.
//!
//! A second account walks a table with `SELECT email INTO @v FROM t WHERE
//! id = n` (classic and trailing `INTO`) and `SET @x = (SELECT …)`: each
//! is a read event naming the table, always reported (never dropped by
//! `min_rows`), with the one row the servers count as sent for `INTO`
//! (`ROWS_SENT` 1 on MySQL 8.4.11 and MariaDB 11.4.13) or, for the `SET`,
//! no row count. Its `CREATE TABLE copy AS SELECT * FROM t` and `CREATE
//! VIEW v AS SELECT … FROM t` name `t`, always reported. No seeded value
//! reaches an event or a log.

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{audit_target, collect_until, describe, env_path, percona, start_audit};
use super::*;

/// Test database.
const ST_DB: &str = "databastion_stored_it";
/// The account that reads into variables and creates from a query.
const ST_USER: &str = "databastion_it_storer";
/// The agent's account of the `performance_schema` test.
const ST_AGENT: &str = "databastion_it_st_agent";
/// Seeded values: never in an event or a log line (I2).
const ST_EMAIL: &str = "stored-it-9Qz@example.test";
/// Reads of the walk per form (one per primary key).
const WALK: u64 = 3;
/// Stored reads of the traffic: two walks and the session `SET`.
const STORED: usize = 2 * WALK as usize + 1;

/// The fixture: a table with seeded rows, and the account.
async fn st_fixture(a: &mut Session) {
    for statement in [
        format!("DROP DATABASE IF EXISTS {ST_DB}"),
        format!("CREATE DATABASE {ST_DB}"),
        format!(
            "CREATE TABLE {ST_DB}.customers (id INT PRIMARY KEY, email VARCHAR(200) UNIQUE, \
             name VARCHAR(100)) ENGINE=InnoDB"
        ),
        format!(
            "INSERT INTO {ST_DB}.customers VALUES (1, '1{ST_EMAIL}', 'Alice 9Qz'), \
             (2, '2{ST_EMAIL}', 'Bob 9Qz'), (3, '3{ST_EMAIL}', 'Carol 9Qz')"
        ),
        format!("DROP USER IF EXISTS '{ST_USER}'@'%'"),
        format!("CREATE USER '{ST_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        format!(
            "GRANT SELECT, INSERT, CREATE, CREATE VIEW, SHOW VIEW, DROP ON {ST_DB}.* \
             TO '{ST_USER}'@'%'"
        ),
    ] {
        exec(a, &statement).await;
    }
}

/// The account's session, kept open until the events are collected
/// (`performance_schema` names a statement's account from its session's
/// thread).
struct Held {
    _dir: TempDir,
    _session: Session,
}

/// The second account's traffic.
async fn st_traffic(server: &Server) -> Held {
    let (dir, t) = target(server, ST_USER, IT_PASSWORD);
    // Not the agent's read-only session: the account creates a table and
    // a view.
    let mut s = Session::connect_admin(&t, Timeouts::new(Duration::from_secs(30)))
        .await
        .unwrap();
    let mut statements = Vec::new();
    for n in 1..=WALK {
        statements.push(format!(
            "SELECT email INTO @v FROM {ST_DB}.customers WHERE id = {n}"
        ));
        statements.push(format!(
            "SELECT email FROM {ST_DB}.customers WHERE id = {n} INTO @w"
        ));
    }
    statements.extend([
        format!("SET @x = (SELECT name FROM {ST_DB}.customers WHERE id = 2)"),
        format!("CREATE TABLE {ST_DB}.copy AS SELECT * FROM {ST_DB}.customers"),
        format!("CREATE VIEW {ST_DB}.v AS SELECT id, name FROM {ST_DB}.customers"),
        // No table: no event.
        "SELECT @v".to_owned(),
    ]);
    for statement in &statements {
        s.query(Stage::Check, statement).await.unwrap();
    }
    Held {
        _dir: dir,
        _session: s,
    }
}

/// Whether `e` names `ST_DB.<table>`.
fn names(e: &MaskedEvent, table: &str) -> bool {
    e.objects()
        .iter()
        .any(|o| o.database().as_str() == ST_DB && o.object().as_str() == table)
}

/// A stored read: a read of the table (and possibly `*`, for a `SET`
/// that `server_audit` with `QUERY_DML` shows by its table records only),
/// always reported, with no signal, and no row count when it sent no row.
/// MySQL 8.4 `performance_schema` counts the row of a `SELECT … INTO @v`
/// as sent (`ROWS_SENT` 1); a `SET` sends none.
fn stored_read(e: &MaskedEvent) -> bool {
    e.principal().account_name() == ST_USER
        && e.action() == EventAction::Read
        && e.always_report()
        && e.rows().is_none_or(|r| r == 1)
        && e.signals().is_empty()
        && names(e, "customers")
        && e.objects()
            .iter()
            .all(|o| o.object().as_str() == "customers" || o.object().as_str() == "*")
}

fn stored_reads(ev: &[MaskedEvent]) -> usize {
    ev.iter().filter(|e| stored_read(e)).count()
}

/// The event of a `CREATE … AS SELECT` creating `target`: it names the
/// target and the source, always reported. A DDL event where the source
/// logs the statement; `server_audit` with `QUERY_DML` logs DDL by its
/// table records only (a read of them and of `*`, ADR-0045 refinement).
fn create_event(e: &MaskedEvent, target: &str) -> bool {
    e.principal().account_name() == ST_USER
        && e.always_report()
        && names(e, target)
        && names(e, "customers")
}

fn st_done(ev: &[MaskedEvent], ddl: bool) -> bool {
    if ddl {
        stored_reads(ev) >= STORED
            && ev.iter().any(|e| create_event(e, "copy"))
            && ev.iter().any(|e| create_event(e, "v"))
    } else {
        stored_reads(ev) > STORED && ev.iter().any(|e| create_event(e, "copy"))
    }
}

/// Checks the events and logs of one source.
fn st_check(label: &str, ev: &[MaskedEvent], logs: &Logs, ddl: bool) {
    let all: Vec<String> = ev.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    if ddl {
        assert_eq!(stored_reads(ev), STORED, "{label}: {all:#?}");
        for target in ["copy", "v"] {
            let creates: Vec<&MaskedEvent> =
                ev.iter().filter(|e| create_event(e, target)).collect();
            assert_eq!(creates.len(), 1, "{label} {target}: {all:#?}");
            assert_eq!(creates[0].action(), EventAction::Ddl, "{label} {target}");
        }
    } else {
        // `server_audit` with `QUERY_DML`: no DDL statement record. The
        // table records of `CREATE TABLE … AS SELECT` (`CREATE` of the copy,
        // `READ` of the source) are a read of both and of `*`; `CREATE
        // VIEW` writes only the `READ` record of its source, so it is a read
        // of the source and of `*`, counted with the stored reads.
        assert_eq!(stored_reads(ev), STORED + 1, "{label}: {all:#?}");
        let creates: Vec<&MaskedEvent> = ev.iter().filter(|e| create_event(e, "copy")).collect();
        assert_eq!(creates.len(), 1, "{label}: {all:#?}");
    }
    assert!(
        ev.iter()
            .filter(|e| e.principal().account_name() == ST_USER)
            .all(|e| stored_read(e)
                || create_event(e, "copy")
                || create_event(e, "v")
                || e.action() == EventAction::Connect),
        "{label}: an unexpected event: {all:#?}"
    );
    let joined = all.join("\n");
    for leak in ["9Qz", "Alice", "example.test"] {
        assert!(!joined.contains(leak), "{label}: {leak} in an event");
        assert!(!logs.text().contains(leak), "{label}: {leak} in the logs");
    }
}

/// On the `performance_schema` source (MySQL and MariaDB).
#[tokio::test]
async fn stored_reads_and_creates_on_performance_schema() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        st_fixture(&mut a).await;
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
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let held = st_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            st_done(e, true)
        })
        .await;
        collect_until(&mut rx, &mut ev, Duration::from_secs(3), |_| false).await;
        task.abort();
        drop(held);
        st_check(
            &format!("{} performance_schema", server.name),
            &ev,
            &logs,
            true,
        );
        for user in [ST_AGENT, ST_USER] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {ST_DB}")).await;
    }
}

/// On the audit log files: MariaDB `server_audit` and the Percona
/// `audit_log_filter` JSON log.
#[tokio::test]
async fn stored_reads_and_creates_on_audit_logs() {
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
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        st_fixture(&mut a).await;
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
        // `server_audit` with `QUERY_DML` logs no DDL statement.
        let ddl = source != EventSource::MariadbServerAudit;
        let held = st_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            st_done(e, ddl)
        })
        .await;
        // Table records without a statement record are grouped until the
        // connection's next record: its disconnection.
        drop(held);
        collect_until(&mut rx, &mut ev, Duration::from_secs(4), |_| false).await;
        task.abort();
        st_check(&format!("{} {format}", server.name), &ev, &logs, ddl);
        exec(&mut a, &format!("DROP USER IF EXISTS '{ST_USER}'@'%'")).await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {ST_DB}")).await;
    }
}
