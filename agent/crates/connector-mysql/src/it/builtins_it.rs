//! Unqualified calls of names that are not built in (ADR-0045 part (b))
//! against the dev servers.
//!
//! - The drift test of decision 11, both directions, on each image (the
//!   engine matrix runs it on MySQL 8.0, 8.4 and 9.7, MariaDB 10.11, 11.4
//!   and 11.8, and Percona Server 8.4):
//!   - every function name of `mysql.help_topic` (identifier-shaped, in the
//!     function help categories) is on the server's list or on the
//!     commented [`NOT_BUILT_IN`] list, and those resolve to a stored
//!     function (error 1305 or 1630) or do not parse (1064);
//!   - every listed name, called with no argument in an empty schema, does
//!     not resolve to a stored function, in each form its list accepts
//!     (plain; backquoted when native; with a space before `(` unless it
//!     is a keyword function of `sql_functions`), and does in the forms it
//!     does not accept (the list is exact, so a server change fails here).
//! - A stored function reading a table its caller cannot read, called as
//!   `SELECT f()`, `DO f()` and `SET @x = f()`, is a read of `*`, always
//!   reported, on every source; a table-less built-in mix gives no event.

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{audit_target, collect_until, describe, env_path, percona, start_audit};
use super::*;
use crate::builtins::{BuiltinList, Form, for_server};

/// The empty schema of the drift test.
const BUILTINS_DB: &str = "databastion_probe_builtins";
/// The schema of the stored function test.
const UC_DB: &str = "databastion_probe_uc";
/// The agent's account of the `performance_schema` source.
const UC_AGENT: &str = "databastion_it_uc_agent";
/// An application account holding only `EXECUTE` on [`UC_DB`].
const UC_CALLER: &str = "databastion_it_uc_caller";
/// An application account that calls built-ins only.
const UC_PLAIN: &str = "databastion_it_uc_plain";
/// Seeded fake e-mail addresses: never in an event or a log line.
const UC_EMAIL: &str = "uc-it-7Qw@example.test";

/// Help topics that are not on a list, with the reason: each must resolve
/// to a stored function or not parse (checked).
const NOT_BUILT_IN: [(&str, &str); 16] = [
    // Not callable names (help pages).
    ("parentheses", "an operator page"),
    ("_rowid", "a column alias"),
    // MariaDB: geometry constructors resolve by argument count (`POINT(1,
    // 2)` is built in, `POINT(1)` a stored function), so they are not
    // listed (fail closed).
    ("point", "MariaDB constructor"),
    ("linestring", "MariaDB constructor"),
    ("polygon", "MariaDB constructor"),
    ("multipoint", "MariaDB constructor"),
    ("multilinestring", "MariaDB constructor"),
    ("multipolygon", "MariaDB constructor"),
    ("geometrycollection", "MariaDB constructor"),
    // MariaDB: a table function in a table list only; a stored function
    // elsewhere (the analysis tells the table list apart).
    ("json_table", "MariaDB table function"),
    // MariaDB: the Spider engine's loadable functions (not installed by
    // default).
    ("spider_direct_sql", "loadable"),
    ("spider_bg_direct_sql", "loadable"),
    ("spider_copy_tables", "loadable"),
    ("spider_flush_table_mon_cache", "loadable"),
    // MySQL 9.7: `MD5`, `SHA1` and `DISTANCE` are documented but not
    // built in (error 1305); MariaDB 10.11: `TRUNC` is documented for
    // 11.x.
    ("md5", "MySQL 9.7: removed"),
    ("trunc", "MariaDB 10.11: documented ahead"),
];
/// Also not built in (same rule): `SHA1`, `DISTANCE` (MySQL 9.7).
const NOT_BUILT_IN_MORE: [&str; 2] = ["sha1", "distance"];

fn not_built_in(name: &str) -> bool {
    NOT_BUILT_IN
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(name))
        || NOT_BUILT_IN_MORE
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
}

/// The server's errno of a statement (`None`: it ran).
async fn errno(s: &mut Session, statement: &str) -> Option<u16> {
    match s.query(Stage::Check, statement).await {
        Ok(_) => None,
        Err(e) => {
            assert!(!e.fatal, "{e:?}: {statement}");
            Some(e.errno.unwrap_or(0))
        }
    }
}

/// The server resolved the name to a stored function of the default
/// database: "FUNCTION … does not exist" (1305), or the same for a name
/// that collides with a built-in (1630).
fn stored(code: Option<u16>) -> bool {
    matches!(code, Some(1305 | 1630))
}

/// ADR-0045 decision 11: the list of the server's series matches the
/// server, both directions.
#[tokio::test]
async fn builtin_lists_match_the_server() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            skip(
                &format!("{}-admin", server.name),
                "admin URL not set (built-in list drift test)",
            );
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        let (flavor, v) = crate::conn::parse_version(&version).unwrap();
        let list: &BuiltinList = for_server(flavor, v);
        assert_eq!(
            (list.flavor, list.series),
            (flavor, (v.0, v.1)),
            "{version}: no built-in list for this series: add it (builtins/extract.py) in the \
             PR that adds the series to the engine matrix"
        );
        // No `IGNORE_SPACE`, no `ANSI_QUOTES`, no `ORACLE`.
        exec(&mut a, "SET SESSION sql_mode = 'STRICT_TRANS_TABLES'").await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {BUILTINS_DB}")).await;
        exec(&mut a, &format!("CREATE DATABASE {BUILTINS_DB}")).await;
        exec(&mut a, &format!("USE {BUILTINS_DB}")).await;
        // Listed names, in every form.
        let mut wrong: Vec<String> = Vec::new();
        for (name, form) in list.names() {
            let plain = errno(&mut a, &format!("SELECT {name}()")).await;
            let quoted = errno(&mut a, &format!("SELECT `{name}`()")).await;
            let spaced = errno(&mut a, &format!("SELECT {name} ()")).await;
            let quoted_ok = form == Form::Native;
            let spaced_ok = form != Form::KeywordAdjacent;
            if stored(plain) {
                wrong.push(format!("{name}: not built in (plain {plain:?})"));
            }
            if stored(quoted) == quoted_ok {
                wrong.push(format!("{name} ({form:?}): backquoted {quoted:?}"));
            }
            if stored(spaced) == spaced_ok {
                wrong.push(format!("{name} ({form:?}): spaced {spaced:?}"));
            }
        }
        // Help topics of the function categories.
        let rows = a
            .query(
                Stage::Check,
                "SELECT DISTINCT t.name FROM mysql.help_topic t JOIN mysql.help_category c \
                 ON c.help_category_id = t.help_category_id \
                 WHERE (c.name LIKE '%Function%' OR c.name LIKE '%Operator%' \
                 OR c.name IN ('Geometry Constructors', 'MBR', 'WKT', 'XML')) \
                 AND c.name NOT IN ('Enterprise Encryption Functions', 'Loadable Functions')",
            )
            .await
            .unwrap();
        let help: Vec<String> = rows
            .into_iter()
            .filter_map(|r| r.into_iter().next().flatten())
            .filter(|n| {
                n.bytes().next().is_some_and(|b| !b.is_ascii_digit())
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .collect();
        assert!(help.len() > 200, "{version}: {} help topics", help.len());
        for name in &help {
            if list.form(name.as_bytes()).is_some() {
                continue;
            }
            let plain = errno(&mut a, &format!("SELECT {name}()")).await;
            if !not_built_in(name) {
                wrong.push(format!(
                    "{name}: in the help, not on the list (plain {plain:?}): regenerate the \
                     list, or add it to NOT_BUILT_IN with a reason"
                ));
            } else if !stored(plain) && plain != Some(1064) {
                wrong.push(format!("{name}: on NOT_BUILT_IN but built in ({plain:?})"));
            }
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {BUILTINS_DB}")).await;
        eprintln!(
            "{} {version}: {} listed names, {} help topics, list {:?}",
            server.name,
            list.len(),
            help.len(),
            list.series
        );
        assert!(wrong.is_empty(), "{} {version}: {wrong:#?}", server.name);
    }
}

/// ADR-0045 residuals to verify: a loadable function cannot take a
/// built-in's name (the server refuses it before loading any library),
/// and a stored function named after a keyword function is what a call
/// with a space before `(` runs.
#[tokio::test]
async fn builtin_names_cannot_hide_a_routine() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin.clone() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        exec(&mut a, "SET SESSION sql_mode = 'STRICT_TRANS_TABLES'").await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {BUILTINS_DB}")).await;
        exec(&mut a, &format!("CREATE DATABASE {BUILTINS_DB}")).await;
        exec(&mut a, &format!("USE {BUILTINS_DB}")).await;
        // A loadable function under a native name: refused, whatever the
        // library (none exists here).
        let udf = errno(
            &mut a,
            "CREATE FUNCTION concat RETURNS STRING SONAME 'databastion_none.so'",
        )
        .await;
        assert!(udf.is_some(), "{version}: loadable CONCAT created");
        let exists = scalar(
            &mut a,
            "SELECT COUNT(*) FROM mysql.func WHERE name = 'concat'",
        )
        .await;
        assert_eq!(exists.as_deref(), Some("0"), "{version}");
        // A stored function named after a keyword function: a call with a
        // space before `(` (or backquoted) runs it.
        exec(
            &mut a,
            &format!("CREATE FUNCTION {BUILTINS_DB}.now() RETURNS INT DETERMINISTIC RETURN 42"),
        )
        .await;
        for (call, want) in [
            ("SELECT now ()", Some("42")),
            ("SELECT `now`()", Some("42")),
            ("SELECT now() = 42", Some("0")),
        ] {
            let got = scalar(&mut a, call).await;
            assert_eq!(got.as_deref(), want, "{version}: {call}");
        }
        eprintln!(
            "{} {version}: loadable CONCAT refused ({udf:?}); `now ()` runs the stored function",
            server.name
        );
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {BUILTINS_DB}")).await;
    }
}

/// The stored function fixture: a table the caller cannot read, a
/// `SQL SECURITY DEFINER` function that reads it, the caller (`EXECUTE`
/// only) and a built-in-only account.
async fn uc_fixture(a: &mut Session) {
    for statement in [
        format!("DROP DATABASE IF EXISTS {UC_DB}"),
        format!("CREATE DATABASE {UC_DB}"),
        format!("CREATE TABLE {UC_DB}.customers (id INT PRIMARY KEY, email VARCHAR(200))"),
        format!(
            "INSERT INTO {UC_DB}.customers VALUES (1, '1{UC_EMAIL}'), (2, '2{UC_EMAIL}'), \
             (3, '3{UC_EMAIL}')"
        ),
        format!(
            "CREATE FUNCTION {UC_DB}.get_customer_email(n INT) RETURNS VARCHAR(200) \
             READS SQL DATA SQL SECURITY DEFINER \
             RETURN (SELECT email FROM {UC_DB}.customers WHERE id = n)"
        ),
    ] {
        exec(a, &statement).await;
    }
    for user in [UC_CALLER, UC_PLAIN] {
        exec(a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        exec(
            a,
            &format!("CREATE USER '{user}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
    }
    exec(
        a,
        &format!("GRANT EXECUTE ON {UC_DB}.* TO '{UC_CALLER}'@'%'"),
    )
    .await;
}

/// The application traffic: the built-in mix first (it must give no
/// event), then the three calls.
async fn uc_traffic(server: &Server) {
    let (_dp, tp) = target(server, UC_PLAIN, IT_PASSWORD);
    let mut p = Session::connect(&tp, Timeouts::new(Duration::from_secs(30)))
        .await
        .unwrap();
    for statement in [
        "SELECT NOW()",
        "SELECT LAST_INSERT_ID()",
        "SELECT DATABASE()",
        "SELECT CONNECTION_ID(), VERSION(), USER(), CURRENT_USER()",
        "SELECT @@session.auto_increment_increment AS auto_increment_increment, \
         @@character_set_client AS character_set_client, @@max_allowed_packet",
        "SET NAMES utf8mb4",
        "SELECT UTC_TIMESTAMP(), UNIX_TIMESTAMP(), CONCAT('a', 'b'), IFNULL(NULL, 1)",
        "SELECT COUNT(*), MAX(1), SUBSTRING('abc', 1, 2), CAST(1 AS CHAR(4))",
    ] {
        p.query(Stage::Check, statement).await.unwrap();
    }
    let (_dc, tc) = target(server, UC_CALLER, IT_PASSWORD);
    let mut c = Session::connect(&tc, Timeouts::new(Duration::from_secs(30)))
        .await
        .unwrap();
    // The caller cannot read the table.
    let denied = c
        .query(
            Stage::Check,
            &format!("SELECT email FROM {UC_DB}.customers"),
        )
        .await;
    assert!(
        denied.is_err(),
        "{}: the caller reads the table",
        server.name
    );
    exec(&mut c, &format!("USE {UC_DB}")).await;
    for statement in [
        "SELECT get_customer_email(1)",
        "DO get_customer_email(2)",
        "SET @x = get_customer_email(3)",
    ] {
        c.query(Stage::Check, statement).await.unwrap();
    }
}

/// Reads of `*` by the caller, always reported.
fn caller_star(ev: &[MaskedEvent]) -> usize {
    ev.iter()
        .filter(|e| {
            e.principal().account_name() == UC_CALLER
                && e.action() == EventAction::Read
                && e.always_report()
                && e.objects().iter().any(|o| o.object().as_str() == "*")
        })
        .count()
}

/// Checks the events and logs of one source.
fn uc_check(label: &str, ev: &[MaskedEvent], logs: &Logs) {
    let all: Vec<String> = ev.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    assert!(caller_star(ev) >= 3, "{label}: {all:#?}");
    assert!(
        ev.iter().all(|e| e.principal().account_name() != UC_PLAIN),
        "{label}: the built-in mix gave events: {all:#?}"
    );
    let joined = all.join("\n");
    for leak in ["get_customer_email", "7Qw"] {
        assert!(!joined.contains(leak), "{label}: {leak} in an event");
        assert!(!logs.text().contains(leak), "{label}: {leak} in the logs");
    }
}

/// ADR-0045 part (b) on the `performance_schema` source (MySQL and
/// MariaDB).
#[tokio::test]
async fn unknown_calls_are_reported_on_performance_schema() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        uc_fixture(&mut a).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{UC_AGENT}'@'%'")).await;
        exec(
            &mut a,
            &format!("CREATE USER '{UC_AGENT}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        exec(
            &mut a,
            &format!("GRANT SELECT ON performance_schema.* TO '{UC_AGENT}'@'%'"),
        )
        .await;
        let (_d, t) = target(&server, UC_AGENT, IT_PASSWORD);
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
        uc_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            caller_star(e) >= 3
        })
        .await;
        collect_until(&mut rx, &mut ev, Duration::from_secs(3), |_| false).await;
        task.abort();
        uc_check(&format!("{} performance_schema", server.name), &ev, &logs);
        for user in [UC_AGENT, UC_CALLER, UC_PLAIN] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {UC_DB}")).await;
    }
}

/// ADR-0045 part (b) on the audit log files: MariaDB `server_audit` and
/// the Percona `audit_log_filter` JSON log.
#[tokio::test]
async fn unknown_calls_are_reported_on_audit_logs() {
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
        uc_fixture(&mut a).await;
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
        uc_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            caller_star(e) >= 3
        })
        .await;
        collect_until(&mut rx, &mut ev, Duration::from_secs(3), |_| false).await;
        task.abort();
        uc_check(&format!("{} {format}", server.name), &ev, &logs);
        for user in [UC_CALLER, UC_PLAIN] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {UC_DB}")).await;
    }
}
