//! Unit tests of the failed and cancelled statements (ADR-0037, refinement
//! of 2026-10-12): parsing (I2), classes, the events, item 4 and the
//! agent's own account.

#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

use super::*;
use crate::audit::records::{Format, LogEntry, parse_entry, parse_error_line};
use databastion_core::audit::own::SharedOwnUsage;

/// A marked value: never in an event, a log line or a `Debug` output.
const MARK: &str = "Zq7-secret-value-4711@example.test";

fn own_at(budget: u64) -> PgOwn {
    PgOwn::new(
        OwnAccount::new(
            "databastion",
            Some(crate::conn::APPLICATION_NAME),
            ClientAddr::parse("192.0.2.14"),
            budget,
            SharedOwnUsage::default(),
        ),
        SharedOwnStatements::default(),
    )
}

fn builder() -> PgauditEvents {
    let mut b = PgauditEvents::new(own_at(1000));
    let mut c = Catalogs::default();
    c.insert(
        "shop",
        DbCatalog {
            pss_schema: Some("public".to_owned()),
            pgaudit_log_catalog: Some(true),
        },
    );
    c.prove_error_lines("shop");
    b.set_catalogs(c);
    b
}

/// One jsonlog line (as PostgreSQL 16 writes it).
struct Line<'a> {
    severity: &'a str,
    code: &'a str,
    user: &'a str,
    app: &'a str,
    session: &'a str,
    vxid: &'a str,
    statement: Option<&'a str>,
    context: bool,
}

impl Default for Line<'_> {
    fn default() -> Self {
        Self {
            severity: "ERROR",
            code: "22P02",
            user: "backup",
            app: "psql",
            session: "6abadffb.3ef",
            vxid: "3/56",
            statement: None,
            context: false,
        }
    }
}

impl Line<'_> {
    fn json(&self) -> String {
        let mut v = serde_json::json!({
            "timestamp": "2026-10-12 08:00:01.000 UTC", "user": self.user, "dbname": "shop",
            "pid": 1007, "remote_host": "192.0.2.14", "remote_port": 42682,
            "session_id": self.session, "line_num": 5, "ps": "SELECT",
            "session_start": "2026-10-12 08:00:00 UTC", "vxid": self.vxid, "txid": 0,
            "error_severity": self.severity, "state_code": self.code,
            "message": format!("invalid input syntax for type integer: \"{MARK}\""),
            "detail": format!("Key (email)=({MARK}) already exists."),
            "hint": format!("hint {MARK}"),
            "internal_query": format!("SELECT '{MARK}'"),
            "application_name": self.app, "backend_type": "client backend",
            "query_id": 0,
        });
        if self.context {
            v["context"] = serde_json::Value::from(format!(
                "PL/pgSQL function f(text) line 3 at RAISE: {MARK}"
            ));
        }
        if let Some(s) = self.statement {
            v["statement"] = serde_json::Value::from(s);
        }
        v.to_string()
    }

    fn csv(&self) -> String {
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let context = if self.context {
            q(&format!(
                "PL/pgSQL function f(text) line 3 at RAISE: {MARK}"
            ))
        } else {
            String::new()
        };
        [
            "2026-10-12 08:00:01.000 UTC".to_owned(),
            q(self.user),
            q("shop"),
            "1007".to_owned(),
            q("192.0.2.14:42682"),
            self.session.to_owned(),
            "5".to_owned(),
            q("SELECT"),
            "2026-10-12 08:00:00 UTC".to_owned(),
            self.vxid.to_owned(),
            "0".to_owned(),
            self.severity.to_owned(),
            self.code.to_owned(),
            q(&format!(
                "invalid input syntax for type integer: \"{MARK}\""
            )),
            q(&format!("Key (email)=({MARK}) already exists.")),
            q(&format!("hint {MARK}")),
            q(&format!("SELECT '{MARK}'")),
            "1".to_owned(),
            context,
            self.statement.map(q).unwrap_or_default(),
            String::new(),
            String::new(),
            q(self.app),
            q("client backend"),
            String::new(),
            "0".to_owned(),
        ]
        .join(",")
    }
}

fn entry(format: Format, line: &Line<'_>) -> LogEntry {
    let raw = match format {
        Format::Jsonlog => line.json(),
        Format::Csvlog => line.csv(),
    };
    parse_entry(format, raw.as_bytes(), "LOG").unwrap()
}

fn events(b: &mut PgauditEvents, entries: Vec<LogEntry>) -> Vec<MaskedEvent> {
    b.convert_entries(entries, SystemTime::now())
}

fn one(format: Format, line: &Line<'_>) -> Vec<MaskedEvent> {
    events(&mut builder(), vec![entry(format, line)])
}

fn objects(e: &MaskedEvent) -> Vec<String> {
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

const FORMATS: [Format; 2] = [Format::Jsonlog, Format::Csvlog];

/// Item 2: the message, detail, hint, context and internal query quote a
/// marked value; it is in no event, no log line and no `Debug` output.
#[test]
fn values_quoted_by_the_line_never_leave_it() {
    let logs = crate::it::Logs::default();
    let _guard = logs.capture();
    for format in FORMATS {
        for context in [false, true] {
            let line = Line {
                statement: Some("SELECT email::integer FROM crm.customers WHERE id = 1"),
                context,
                ..Line::default()
            };
            let raw = match format {
                Format::Jsonlog => line.json(),
                Format::Csvlog => line.csv(),
            };
            assert!(raw.contains(MARK));
            let parsed = parse_error_line(format, raw.as_bytes()).unwrap().unwrap();
            assert_eq!(parsed.has_context, context, "{format:?}");
            assert_eq!(
                parsed.sqlstate.map(|c| c.as_str().to_owned()).as_deref(),
                Some("22P02")
            );
            let debug = format!("{parsed:?}");
            assert!(!debug.contains(MARK), "{debug}");
            assert!(!debug.contains("customers"), "{debug}");
            // Every kept field.
            for kept in [
                &parsed.user,
                &parsed.database,
                &parsed.application,
                &parsed.session,
                &parsed.vxid,
            ] {
                assert!(!kept.contains(MARK));
            }
            assert!(!parsed.statement.as_deref().unwrap().contains(MARK));
            let mut b = builder();
            let ev = events(&mut b, vec![LogEntry::Error(parsed)]);
            assert_eq!(ev.len(), 1, "{format:?}");
            let shown = format!("{ev:?}");
            assert!(!shown.contains(MARK), "{shown}");
            assert_eq!(objects(&ev[0]), ["crm.customers"]);
            // The core's view of the line, after `parse_entry`.
            let entry = parse_entry(format, raw.as_bytes(), "LOG").unwrap();
            assert!(!format!("{entry:?}").contains(MARK));
        }
        // The csvlog picker never copies the skipped columns.
        if format == Format::Csvlog {
            let line = Line {
                statement: Some("SELECT 1"),
                context: true,
                ..Line::default()
            };
            let csv = line.csv();
            let p = crate::audit::records::csv_pick(
                &csv,
                &[0, 1, 2, 4, 5, 9, 11, 12, 19, 22, 23],
                Some(19),
            )
            .unwrap();
            assert!(p.picked.iter().all(|f| !f.contains(MARK)));
            assert!(p.present[18], "context present");
            assert!(p.present[13] && p.present[14] && p.present[15] && p.present[16]);
        }
    }
    let text = logs.text();
    assert!(!text.contains(MARK), "{text}");
    assert!(!text.contains("customers"), "statement text logged: {text}");
}

/// A pgaudit `AUDIT:` message raised as an `ERROR` is read as an error
/// line (pgaudit never logs at `ERROR`), never as a record.
#[test]
fn error_lines_are_never_pgaudit_records() {
    let raw = serde_json::json!({
        "timestamp": "2026-10-12 08:00:01.000 UTC", "user": "backup", "dbname": "shop",
        "error_severity": "ERROR", "state_code": "P0001", "session_id": "s", "vxid": "3/1",
        "message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,crm.fake,select 1,<not logged>,5",
        "context": "PL/pgSQL function inline_code_block line 1 at RAISE",
        "statement": "DO $$ BEGIN RAISE EXCEPTION 'AUDIT: …'; END $$",
        "application_name": "psql", "backend_type": "client backend",
    })
    .to_string();
    assert!(matches!(
        parse_entry(Format::Jsonlog, raw.as_bytes(), "LOG"),
        Ok(LogEntry::Error(_))
    ));
    // Lines of other backends are not read.
    let auto = raw.replace("client backend", "autovacuum worker");
    assert!(matches!(
        parse_entry(Format::Jsonlog, auto.as_bytes(), "LOG"),
        Err(crate::audit::records::Skip::NotAudit)
    ));
    // A damaged line of that severity is counted, not silently lost.
    assert!(matches!(
        parse_entry(Format::Jsonlog, br#"{"error_severity":"ERROR","x":"#, "LOG"),
        Err(crate::audit::records::Skip::Damaged)
    ));
    // Other severities are not read.
    let warning = raw.replace("\"ERROR\"", "\"WARNING\"");
    assert!(parse_error_line(Format::Jsonlog, warning.as_bytes()).is_err());
    assert!(
        parse_error_line(Format::Jsonlog, auto.as_bytes())
            .unwrap()
            .is_none()
    );
}

/// Item 3: telling and quiet failures are reported, by SQLSTATE class;
/// the rows streamed before the error, the timeout, the client's cancel
/// and the connection lost mid-result included.
#[test]
fn failures_are_reported_by_class() {
    for format in FORMATS {
        let read = |code: &str, severity: &str, text: &str| {
            let ev = one(
                format,
                &Line {
                    severity,
                    code,
                    statement: Some(text),
                    ..Line::default()
                },
            );
            assert_eq!(ev.len(), 1, "{format:?} {code} {text}: {ev:?}");
            let e = ev.into_iter().next().unwrap();
            assert_eq!(e.action(), EventAction::Read, "{code} {text}");
            assert_eq!(e.rows(), None, "{code}");
            assert!(e.always_report(), "{code} {text}");
            assert_eq!(e.source(), EventSource::Pgaudit);
            e
        };
        let late = "SELECT id, email, CASE WHEN id = 60 THEN 1 / (id - 60) END FROM crm.customers";
        for (code, severity) in [
            ("22P02", "ERROR"),
            ("22012", "ERROR"),
            ("57014", "ERROR"),
            ("08006", "FATAL"),
            ("57P01", "FATAL"),
            ("42P01", "ERROR"),
            ("42501", "ERROR"),
            ("XX000", "ERROR"),
            ("P0001", "ERROR"),
            ("ZZ999", "ERROR"),
        ] {
            let e = read(code, severity, late);
            assert_eq!(objects(&e), ["crm.customers"], "{code}");
            assert!(
                e.signals().contains(&Signal::FullTableRead),
                "{code}: the shape of the statement"
            );
        }
        // Run-time class 42 errors raised per row after rows were sent
        // (security review A1): quiet, reported.
        let e = read(
            "42883",
            "ERROR",
            "SELECT (name || 'x()')::regprocedure FROM crm.customers",
        );
        assert_eq!(objects(&e), ["crm.customers"]);
        // A table-less read: `*`.
        let e = read("22012", "ERROR", "SELECT 1 / 0");
        assert_eq!(objects(&e), [".*"]);
        // Without a statement text (item 5): a read of `*`.
        let e = one(format, &Line::default());
        assert_eq!(e.len(), 1);
        assert_eq!(objects(&e[0]), [".*"]);
        assert!(e[0].always_report());
        // A `FATAL` line without a statement: an idle session ended
        // (proposed item 9).
        for code in ["57P01", "57P05", "25P03", "08006"] {
            assert!(
                one(
                    format,
                    &Line {
                        severity: "FATAL",
                        code,
                        ..Line::default()
                    }
                )
                .is_empty(),
                "{code}"
            );
        }
        // Statements that read nothing.
        for text in ["BEGIN", "SET statement_timeout = 'x'", "COMMIT", "SHOW x"] {
            assert!(
                one(
                    format,
                    &Line {
                        code: "22023",
                        statement: Some(text),
                        ..Line::default()
                    }
                )
                .is_empty(),
                "{text}"
            );
        }
        // Code or rows the text does not name: `*` next to the relations.
        for text in [
            "FETCH 10 FROM c",
            "CALL p()",
            "EXECUTE p(1)",
            "DO $$ BEGIN PERFORM 1; END $$",
        ] {
            let e = read("22012", "ERROR", text);
            assert!(objects(&e).contains(&".*".to_owned()), "{text}");
        }
        // Catalogs only: no application data, as when it succeeds.
        assert!(
            one(
                format,
                &Line {
                    code: "22P02",
                    statement: Some("SELECT setting::integer FROM pg_catalog.pg_settings"),
                    ..Line::default()
                }
            )
            .is_empty()
        );
        // A statistics relation: named, always reported (ADR-0048).
        let e = read(
            "22P02",
            "ERROR",
            "SELECT most_common_vals::text::integer FROM pg_catalog.pg_stats",
        );
        assert_eq!(objects(&e), ["pg_catalog.pg_stats"]);
        // User code next to catalogs only (ADR-0049 decision 8): `*`.
        let e = read(
            "22012",
            "ERROR",
            "SELECT crm.leak(oid) FROM pg_catalog.pg_class",
        );
        assert!(objects(&e).contains(&".*".to_owned()));
        // A wrapped query (ADR-0048, refinement of 2026-10-12).
        let e = read(
            "57014",
            "ERROR",
            "EXPLAIN ANALYZE SELECT email FROM crm.customers",
        );
        assert_eq!(objects(&e), ["crm.customers"]);
        let e = read(
            "57014",
            "ERROR",
            "DECLARE c CURSOR FOR SELECT email FROM crm.customers",
        );
        assert_eq!(objects(&e), ["crm.customers"]);
    }
}

/// Item 3: writes and DDL.
#[test]
fn failed_writes_and_ddl() {
    for format in FORMATS {
        let ev = |code: &str, text: &str| {
            let ev = one(
                format,
                &Line {
                    code,
                    statement: Some(text),
                    ..Line::default()
                },
            );
            assert_eq!(ev.len(), 1, "{code} {text}");
            ev.into_iter().next().unwrap()
        };
        // A plain `INSERT … VALUES` (its message quotes its own values):
        // an ordinary write, under the filters.
        let e = ev(
            "23505",
            "INSERT INTO crm.customers (email) VALUES ('a@b.c')",
        );
        assert_eq!(e.action(), EventAction::Write);
        assert!(!e.always_report());
        assert_eq!(objects(&e), ["crm.customers"]);
        // Writes that read: always reported.
        for text in [
            "INSERT INTO crm.copy SELECT * FROM crm.customers",
            "INSERT INTO crm.customers SELECT * FROM crm.customers",
            "INSERT INTO crm.customers (email) VALUES ('x') RETURNING email",
            "INSERT INTO crm.customers (email) VALUES ('x') ON CONFLICT (email) DO UPDATE SET email = crm.customers.email",
            "INSERT INTO crm.customers (email) VALUES (crm.f())",
            "UPDATE crm.customers SET email = email || 'x'",
            "DELETE FROM crm.customers WHERE email = 'x'",
            "MERGE INTO crm.a USING crm.customers c ON true WHEN MATCHED THEN DO NOTHING",
        ] {
            let e = ev("23505", text);
            assert_eq!(e.action(), EventAction::Write, "{text}");
            assert!(e.always_report(), "{text}");
        }
        // A quiet failure of a write is a read of its relations.
        let e = ev("57014", "UPDATE crm.customers SET email = email || 'x'");
        assert_eq!(e.action(), EventAction::Read);
        assert!(e.always_report());
        // DDL keeps its action, always reported.
        let e = ev(
            "22012",
            "CREATE TABLE crm.t2 AS SELECT 1 / 0 FROM crm.customers",
        );
        assert_eq!(e.action(), EventAction::Ddl);
        assert!(e.always_report());
        let e = ev("42P07", "CREATE TABLE crm.t2 (id integer)");
        assert_eq!(e.action(), EventAction::Ddl);
    }
}

/// Item 3 (F1): the refusals, and what keeps a line.
#[test]
fn refusals_and_the_context() {
    for format in FORMATS {
        let count = |code: &str, context: bool, statement: Option<&str>, severity: &str| {
            one(
                format,
                &Line {
                    code,
                    context,
                    statement,
                    severity,
                    ..Line::default()
                },
            )
            .len()
        };
        // A genuine 25P02: a statement sent in an aborted transaction.
        assert_eq!(
            count(
                "25P02",
                false,
                Some("SELECT email FROM crm.customers"),
                "ERROR"
            ),
            0
        );
        assert_eq!(count("25P02", false, Some("select 42;"), "ERROR"), 0);
        assert_eq!(count("25P02", false, None, "ERROR"), 0);
        // Forged by a function after rows were sent: it has a context.
        assert_eq!(
            count("25P02", true, Some("SELECT * FROM crm.v"), "ERROR"),
            1
        );
        assert_eq!(count("25P02", true, None, "ERROR"), 1);
        // Without a context but calling code that is not built in: kept.
        assert_eq!(
            count(
                "25P02",
                false,
                Some("SELECT crm.f(id) FROM crm.customers"),
                "ERROR"
            ),
            1
        );
        assert_eq!(
            count(
                "25P02",
                false,
                Some("SELECT it_f(g) FROM generate_series(1, 5) g"),
                "ERROR"
            ),
            1
        );
        // A text that cannot be scanned keeps it too.
        assert_eq!(count("25P02", false, Some("SELECT 'abc"), "ERROR"), 1);
        // A genuine 42601: the text does not lex, and holds no call,
        // cast or operator.
        assert_eq!(count("42601", false, Some("select 'abc\n;"), "ERROR"), 0);
        assert_eq!(count("42601", false, Some("select \"abc"), "ERROR"), 0);
        // Forged (a context), or a text that lexes, or one that could
        // hold code: kept.
        assert_eq!(
            count("42601", true, Some("SELECT * FROM crm.v"), "ERROR"),
            1
        );
        assert_eq!(count("42601", false, Some("selec 1"), "ERROR"), 1);
        assert_eq!(
            count("42601", false, Some("SELECT f() || 'abc"), "ERROR"),
            1
        );
        // Connection-level lines without a statement.
        for code in ["28P01", "28000", "3D000"] {
            assert_eq!(count(code, false, None, "FATAL"), 0, "{code}");
            assert_eq!(count(code, false, None, "ERROR"), 0, "{code}");
            // With a statement: telling.
            assert_eq!(
                count(
                    code,
                    false,
                    Some("SELECT email FROM crm.customers"),
                    "ERROR"
                ),
                1,
                "{code}"
            );
        }
    }
}

/// Item 4: a line that repeats its session's last pgaudit record (written
/// when the statement started, no row count) is not reported twice.
#[test]
fn not_twice() {
    let text = "SELECT email::integer FROM crm.customers WHERE id = 1";
    let record = |rows: Option<&str>| {
        let line = serde_json::json!({
            "timestamp": "2026-10-12 08:00:00.900 UTC", "user": "backup", "dbname": "shop",
            "error_severity": "LOG", "remote_host": "192.0.2.14", "session_id": "6abadffb.3ef",
            "vxid": "3/56", "application_name": "psql", "backend_type": "client backend",
            "message": format!(
                "AUDIT: SESSION,7,1,READ,SELECT,TABLE,crm.customers,{text},<not logged>{}",
                rows.map(|r| format!(",{r}")).unwrap_or_default()
            ),
        });
        parse_entry(Format::Jsonlog, line.to_string().as_bytes(), "LOG").unwrap()
    };
    let line = || {
        entry(
            Format::Jsonlog,
            &Line {
                statement: Some(text),
                ..Line::default()
            },
        )
    };
    // `log_rows = off`: one event (the record's).
    let ev = events(&mut builder(), vec![record(None), line()]);
    assert_eq!(ev.len(), 1, "{ev:?}");
    // Across two reads of the log too.
    let mut b = builder();
    assert_eq!(events(&mut b, vec![record(None)]).len(), 1);
    assert!(events(&mut b, vec![line()]).is_empty());
    // A record with a row count ended an earlier statement: two events.
    let ev = events(&mut builder(), vec![record(Some("1")), line()]);
    assert_eq!(ev.len(), 2, "{ev:?}");
    // The `LOG` 08006 line is not read; the `FATAL` one is, once.
    let log_08006 = serde_json::json!({
        "error_severity": "LOG", "state_code": "08006", "user": "backup", "dbname": "shop",
        "message": "could not send data to client: Broken pipe", "statement": text,
        "backend_type": "client backend",
    })
    .to_string();
    assert!(matches!(
        parse_entry(Format::Jsonlog, log_08006.as_bytes(), "LOG"),
        Err(crate::audit::records::Skip::NotAudit)
    ));
}

/// The agent's own account: telling failures are never its own; quiet
/// ones from its identity are charged the whole budget, like an unknown
/// row count.
#[test]
fn the_agents_own_failures() {
    let text = "SELECT \"email\" FROM \"crm\".\"customers\" LIMIT 1000";
    let agent = |code: &'static str| Line {
        code,
        user: "databastion",
        app: crate::conn::APPLICATION_NAME,
        statement: Some(text),
        ..Line::default()
    };
    // Telling: reported.
    let mut b = builder();
    let ev = events(&mut b, vec![entry(Format::Jsonlog, &agent("22P02"))]);
    assert_eq!(ev.len(), 1);
    assert!(ev[0].always_report());
    // Quiet (the agent cancels its own sampling statements at the byte
    // budget): the first is left out, charged the whole budget; the next
    // read of that relation is reported.
    let mut b = builder();
    assert!(events(&mut b, vec![entry(Format::Jsonlog, &agent("57014"))]).is_empty());
    assert_eq!(
        events(&mut b, vec![entry(Format::Jsonlog, &agent("57014"))]).len(),
        1
    );
    // Its role from another application: reported.
    let other = Line {
        app: "psql",
        ..agent("57014")
    };
    assert_eq!(one(Format::Jsonlog, &other).len(), 1);
    // A forged 25P02 from its identity: reported (quiet `*` next to the
    // view).
    let forged = Line {
        code: "25P02",
        context: true,
        statement: Some("SELECT * FROM crm.v"),
        ..agent("25P02")
    };
    let mut b = PgauditEvents::new(own_at(0));
    assert_eq!(
        events(&mut b, vec![entry(Format::Jsonlog, &forged)]).len(),
        1
    );
}

/// A line whose conversion panics is dropped alone and counted.
#[test]
fn a_panicking_line_is_dropped_alone() {
    let mut b = builder();
    let bad = Line {
        user: TEST_POISON_USER,
        statement: Some("SELECT 1 / 0"),
        ..Line::default()
    };
    let good = Line {
        statement: Some("SELECT 1 / 0"),
        session: "other",
        ..Line::default()
    };
    let ev = events(
        &mut b,
        vec![entry(Format::Jsonlog, &bad), entry(Format::Jsonlog, &good)],
    );
    assert_eq!(ev.len(), 1);
    assert_eq!(b.panicked, 1);
}

/// Load: a storm of the same failure (a `42P01` from an application
/// looping on a missing table) gives one event per line here, and the
/// core's aggregator merges them per principal, action and objects into
/// one event per window. Each line costs one analysis of its text, as an
/// `AUDIT:` record does.
#[test]
fn a_storm_of_one_failure_merges() {
    let mut b = builder();
    let line = Line {
        code: "42P01",
        statement: Some("SELECT * FROM crm.missing WHERE id = 1"),
        ..Line::default()
    };
    let entries: Vec<LogEntry> = (0..2000).map(|_| entry(Format::Jsonlog, &line)).collect();
    let ev = events(&mut b, entries);
    assert_eq!(ev.len(), 2000);
    let keys: HashSet<_> = ev.iter().map(MaskedEvent::group_key).collect();
    assert_eq!(keys.len(), 1);
}

/// Load (run by hand: `cargo test --release -p databastion-connector-postgres
/// --lib -- --ignored error_line_throughput --nocapture`): the cost per
/// line of parsing and converting `ERROR` lines, against `AUDIT:` records
/// of the same statement.
#[test]
#[ignore = "measurement, run by hand"]
fn error_line_throughput() {
    const N: usize = 100_000;
    let text = "SELECT id, email FROM crm.missing_table WHERE id = 42";
    let error_raw = Line {
        code: "42P01",
        statement: Some(text),
        ..Line::default()
    }
    .json();
    // One statement per record (statement ids 1, 2…), as a loop does.
    let audit_raw = |i: usize| {
        serde_json::json!({
            "timestamp": "2026-10-12 08:00:00.900 UTC", "user": "backup", "dbname": "shop",
            "error_severity": "LOG", "remote_host": "192.0.2.14", "session_id": "6abadffb.3ef",
            "vxid": "3/56", "application_name": "psql", "backend_type": "client backend",
            "message": format!(
                "AUDIT: SESSION,{i},1,READ,SELECT,TABLE,crm.customers,\"{text}\",<not logged>,1"
            ),
        })
        .to_string()
    };
    let other_raw = r#"{"timestamp":"2026-10-12 08:00:00.900 UTC","user":"backup","dbname":"shop","error_severity":"LOG","message":"connection authorized: user=backup database=shop","backend_type":"client backend"}"#;
    let audit: Vec<String> = (1..=N).map(audit_raw).collect();
    for (label, raw) in [
        ("ERROR 42P01", vec![error_raw.as_str(); N]),
        ("AUDIT", audit.iter().map(String::as_str).collect()),
        ("other LOG", vec![other_raw; N]),
    ] {
        let started = std::time::Instant::now();
        let entries: Vec<LogEntry> = raw
            .iter()
            .filter_map(|r| parse_entry(Format::Jsonlog, r.as_bytes(), "LOG").ok())
            .collect();
        let parsed = started.elapsed();
        let mut b = builder();
        let ev = events(&mut b, entries);
        let total = started.elapsed();
        eprintln!(
            "{label}: {N} lines, parse {:.2} µs/line, parse + convert {:.2} µs/line, {} events",
            parsed.as_secs_f64() * 1e6 / N as f64,
            total.as_secs_f64() * 1e6 / N as f64,
            ev.len()
        );
    }
}

/// Security review of #214, M1: a `FATAL` line without a statement gives
/// no event only where `check()`'s probe proved the log settings for its
/// database; elsewhere it is a read of `*`, always reported (item 5).
#[test]
fn a_statementless_fatal_needs_the_settings_proven() {
    for format in FORMATS {
        let fatal = Line {
            severity: "FATAL",
            code: "57P01",
            ..Line::default()
        };
        // Proven for `shop` (the builder's catalogs).
        assert!(one(format, &fatal).is_empty());
        // Not proven: no probe of the database, or a probe that failed.
        let mut b = PgauditEvents::new(own_at(1000));
        let ev = events(&mut b, vec![entry(format, &fatal)]);
        assert_eq!(ev.len(), 1, "{format:?}");
        assert_eq!(objects(&ev[0]), [".*"]);
        assert!(ev[0].always_report());
        assert_eq!(ev[0].rows(), None);
        let mut c = Catalogs::default();
        c.prove_error_lines("other");
        b.set_catalogs(c);
        assert_eq!(events(&mut b, vec![entry(format, &fatal)]).len(), 1);
        // A connection-level line stays refused either way.
        let refused = Line {
            severity: "FATAL",
            code: "28P01",
            ..Line::default()
        };
        assert!(events(&mut b, vec![entry(format, &refused)]).is_empty());
    }
}

/// Security review of #214, L1: only a closed list of the server's own
/// processes is not read; `walsender`, an unknown type and a missing one
/// are read (fail closed).
#[test]
fn only_the_servers_own_processes_are_skipped() {
    let raw = Line {
        statement: Some("SELECT email::integer FROM crm.customers"),
        ..Line::default()
    }
    .json();
    for skipped in [
        "autovacuum launcher",
        "autovacuum worker",
        "parallel worker",
        "checkpointer",
        "background writer",
        "walwriter",
        "startup",
        "archiver",
        "logger",
        "logical replication apply worker",
    ] {
        let line = raw.replace("client backend", skipped);
        assert!(
            parse_error_line(Format::Jsonlog, line.as_bytes())
                .unwrap()
                .is_none(),
            "{skipped}"
        );
    }
    for read in [
        "client backend",
        "walsender",
        "pg_cron scheduler",
        "something new",
    ] {
        let line = raw.replace("client backend", read);
        assert!(
            parse_error_line(Format::Jsonlog, line.as_bytes())
                .unwrap()
                .is_some(),
            "{read}"
        );
    }
    let missing = raw.replace(",\"backend_type\":\"client backend\"", "");
    assert_ne!(missing, raw);
    assert!(
        parse_error_line(Format::Jsonlog, missing.as_bytes())
            .unwrap()
            .is_some()
    );
    // csvlog: the same list, and a record without the column (before
    // PostgreSQL 13) is read.
    let csv = Line {
        statement: Some("SELECT 1"),
        ..Line::default()
    }
    .csv();
    let auto = csv.replace("\"client backend\"", "\"autovacuum worker\"");
    assert!(
        parse_error_line(Format::Csvlog, auto.as_bytes())
            .unwrap()
            .is_none()
    );
    let sender = csv.replace("\"client backend\"", "walsender");
    assert!(
        parse_error_line(Format::Csvlog, sender.as_bytes())
            .unwrap()
            .is_some()
    );
    let short: Vec<&str> = csv.split(',').take(23).collect();
    assert!(
        parse_error_line(Format::Csvlog, short.join(",").as_bytes())
            .unwrap()
            .is_some()
    );
}

/// Security review of #214, L2: the statement's buffer never grows (its
/// capacity is reserved before any character is pushed), and a jsonlog
/// statement, escapes or not, is read into a zeroizing buffer.
#[test]
fn the_statement_buffer_is_reserved_and_zeroizing() {
    let text = "SELECT \"email\", 'a,b' FROM crm.customers -- long enough to grow a buffer";
    let csv = Line {
        statement: Some(text),
        ..Line::default()
    }
    .csv();
    let p = crate::audit::records::csv_pick(&csv, &[19, 22], Some(19)).unwrap();
    assert_eq!(p.picked[0].as_str(), text);
    assert_eq!(p.picked[0].capacity(), csv.len(), "grown: reallocated");
    let line = parse_error_line(Format::Csvlog, csv.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(line.statement.as_deref().map(String::as_str), Some(text));
    for t in [text, "plain", "tab\there \u{e9}"] {
        let json = Line {
            statement: Some(t),
            ..Line::default()
        }
        .json();
        let line = parse_error_line(Format::Jsonlog, json.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(line.statement.as_deref().map(String::as_str), Some(t));
    }
    let null = Line::default()
        .json()
        .replace("\"query_id\":0", "\"query_id\":0,\"statement\":null");
    let line = parse_error_line(Format::Jsonlog, null.as_bytes())
        .unwrap()
        .unwrap();
    assert!(line.statement.is_none());
}

/// ADR-0012 refinement of 2026-10-12, item 4: a `FATAL` line without a
/// statement from a role whose `log_min_error_statement` is overridden
/// above `error` is item 5's read of `*`; from another role, quiet; any
/// role's while the stream has seen an `ALTER ROLE` (or `ALTER DATABASE`,
/// a function's `SET` clause) since the last probes.
#[test]
fn item_4_overriding_roles_and_stale_marks() {
    use crate::audit::overrides::{
        DbProof, LogOverridesHandle, Probe, Read, RoleRow, STATEMENT_KEY, SharedLogOverrides, lock,
    };
    for format in FORMATS {
        let shared = SharedLogOverrides::default();
        let proof = DbProof::evaluate(
            Read::Rows(vec![RoleRow {
                every_role: false,
                role: Some("hider".to_owned()),
                setting: Some(STATEMENT_KEY.to_owned()),
                level: Some("panic".to_owned()),
            }]),
            Read::Rows(vec![]),
            None,
            1000,
        );
        lock(&shared).store("shop", std::time::Instant::now(), Probe::Done(proof));
        let mut c = Catalogs::default()
            .with_log_overrides(LogOverridesHandle::new(std::sync::Arc::clone(&shared)));
        c.insert(
            "shop",
            DbCatalog {
                pss_schema: Some("public".to_owned()),
                pgaudit_log_catalog: Some(true),
            },
        );
        c.prove_error_lines("shop");
        let mut b = PgauditEvents::new(own_at(1000));
        b.set_catalogs(c);
        let fatal = |user: &'static str| Line {
            severity: "FATAL",
            code: "57P01",
            user,
            ..Line::default()
        };
        assert!(events(&mut b, vec![entry(format, &fatal("backup"))]).is_empty());
        let ev = events(&mut b, vec![entry(format, &fatal("hider"))]);
        assert_eq!(ev.len(), 1, "{format:?}");
        assert_eq!(objects(&ev[0]), [".*"]);
        assert!(ev[0].always_report());
        // A line with its statement is judged by its text, as before.
        let with_text = Line {
            severity: "FATAL",
            code: "57P01",
            user: "hider",
            statement: Some("SELECT c.relname FROM pg_catalog.pg_class c"),
            ..Line::default()
        };
        assert!(events(&mut b, vec![entry(format, &with_text)]).is_empty());
        // An `ALTER ROLE … SET` record: every role's line is a read of `*`
        // until two probes that start later.
        let alter = {
            let line = serde_json::json!({
                "timestamp": "2026-10-12 08:00:01.000 UTC", "user": "admin", "dbname": "shop",
                "error_severity": "LOG", "remote_host": "192.0.2.14",
                "session_id": "6abadffb.3f0", "application_name": "psql",
                "message": "AUDIT: SESSION,1,1,ROLE,ALTER ROLE,,,ALTER ROLE app SET log_min_messages = fatal,<not logged>",
            });
            crate::audit::records::parse_entry(Format::Jsonlog, line.to_string().as_bytes(), "LOG")
                .unwrap()
        };
        let ev = events(&mut b, vec![alter, entry(format, &fatal("backup"))]);
        let reads: Vec<&MaskedEvent> = ev
            .iter()
            .filter(|e| e.action() == EventAction::Read)
            .collect();
        assert_eq!(reads.len(), 1, "{format:?}");
        assert_eq!(objects(reads[0]), [".*"]);
        for _ in 0..2 {
            std::thread::sleep(std::time::Duration::from_millis(2));
            lock(&shared).store(
                "shop",
                std::time::Instant::now(),
                Probe::Done(DbProof::default()),
            );
        }
        assert!(events(&mut b, vec![entry(format, &fatal("backup"))]).is_empty());
        // Not proven (the read failed): every role.
        lock(&shared).store(
            "shop",
            std::time::Instant::now(),
            Probe::Done(DbProof::not_proven("test")),
        );
        assert_eq!(
            events(&mut b, vec![entry(format, &fatal("backup"))]).len(),
            1
        );
    }
}
