//! Tests of the configuration readers and the proofs (ADR-0060 decision 6,
//! R2, R8 item 6, R9, R21, R27 item 2), on the dev trace configuration and
//! synthesized files (the images' own files are not copied here: they are
//! the images', never redistributed).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use super::trace_conf::*;
use databastion_core::{NoteCode, TargetNote};

const DEV_TRACE: &str = include_str!("../../../../dev/firebird/fbtrace.conf");
const LOG: &str = "/var/lib/firebird/audit/audit.log";
const CRM: &str = "/var/lib/firebird/data/crm.fdb";
const ROOT: &str = "/opt/firebird";

fn crm() -> Vec<DeclaredDb<'static>> {
    vec![DeclaredDb {
        label: "crm",
        resolved: Some(CRM),
        alias: None,
    }]
}

fn eval(trace: &str, map: Option<&AliasMap>, dbs: &[DeclaredDb<'_>]) -> Verdict {
    let t = parse_trace_conf(trace.as_bytes()).expect("parses");
    evaluate(&Inputs {
        trace: &t,
        aliases: map,
        databases: dbs,
        log: LOG,
        root: ROOT,
        longest_own_text: 900,
    })
}

fn empty_map() -> AliasMap {
    parse_databases_conf(b"", ROOT).unwrap()
}

fn labels(notes: &[TargetNote], code: NoteCode) -> Vec<String> {
    notes
        .iter()
        .filter(|n| n.code() == code)
        .flat_map(|n| n.labels().iter().map(|l| l.as_str()))
        .collect()
}

fn codes(notes: &[TargetNote]) -> Vec<NoteCode> {
    notes.iter().map(TargetNote::code).collect()
}

/// The dev configuration meets every proof (obligation of R36: the dev
/// trace configuration has every required setting).
#[test]
fn the_dev_configuration_proves_partial() {
    let v = eval(DEV_TRACE, Some(&empty_map()), &crm());
    assert!(v.partial, "{:?}", v.notes);
    assert!(v.notes.is_empty(), "{:?}", v.notes);
    assert_eq!(v.max_sql_length, 65_000);
    assert!(v.log_connections);
}

/// Without the alias map, aliases are not evaluated (R2 rule 2).
#[test]
fn without_the_map_aliases_are_not_evaluated() {
    let v = eval(DEV_TRACE, None, &crm());
    assert!(!v.partial);
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated),
        ["databases_conf"]
    );
}

fn without(key: &str) -> String {
    DEV_TRACE
        .lines()
        .filter(|l| !l.trim_start().starts_with(&format!("{key} ")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Proof 4 and R21: each missing setting is a label, in rank order.
#[test]
fn each_missing_setting_is_a_label() {
    for key in [
        "log_connections",
        "log_transactions",
        "log_statement_finish",
        "log_procedure_finish",
        "log_function_finish",
        "log_trigger_finish",
        "log_blr_requests",
        "log_errors",
        "log_initfini",
        "log_sweep",
        "print_perf",
        "time_threshold",
    ] {
        let v = eval(&without(key), Some(&empty_map()), &crm());
        assert!(!v.partial, "{key}");
        let l = labels(&v.notes, NoteCode::AuditTraceSettingsMissing);
        assert!(l.contains(&key.to_owned()), "{key}: {l:?}");
    }
    // `enabled = false` and another log.
    let off = DEV_TRACE.replacen("enabled = true", "enabled = false", 1);
    let v = eval(&off, Some(&empty_map()), &crm());
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceSettingsMissing),
        ["enabled"]
    );
    let other = DEV_TRACE.replacen(
        "log_filename = /var/lib/firebird/audit/audit.log",
        "log_filename = /tmp/other.log",
        1,
    );
    let v = eval(&other, Some(&empty_map()), &crm());
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceSettingsMissing),
        ["log_filename"]
    );
    // Filters, a connection filter, a threshold, GDS-code filters.
    for (line, label) in [
        ("include_filter = \"%SELECT%\"", "include_filter"),
        ("exclude_filter = x", "exclude_filter"),
        ("connection_id = 7", "connection_id"),
        ("exclude_gds_codes = 335544794", "log_errors"),
    ] {
        let key = line.split(' ').next().unwrap();
        let t = without(key).replacen(
            "\tmax_sql_length = 65000",
            &format!("\tmax_sql_length = 65000\n\t{line}"),
            1,
        );
        let v = eval(&t, Some(&empty_map()), &crm());
        assert!(
            labels(&v.notes, NoteCode::AuditTraceSettingsMissing).contains(&label.to_owned()),
            "{line}"
        );
    }
    let t = DEV_TRACE.replace("time_threshold = 0", "time_threshold = 100");
    let v = eval(&t, Some(&empty_map()), &crm());
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceSettingsMissing),
        ["time_threshold"]
    );
}

/// R2 rule 4: effective settings are the default's, overridden by the
/// first matching named section's; a later section is never reached.
#[test]
fn first_match_over_the_default() {
    let t = format!(
        "database\n{{\n\tenabled = false\n\tlog_connections = true\n\tlog_transactions = true\n\
         \tlog_statement_finish = true\n\tlog_procedure_finish = true\n\tlog_function_finish = true\n\
         \tlog_trigger_finish = true\n\tlog_blr_requests = true\n\tlog_errors = true\n\
         \tlog_initfini = true\n\tlog_sweep = true\n\tprint_perf = true\n\ttime_threshold = 0\n\
         \tmax_sql_length = 8192\n}}\ndatabase = {CRM}\n{{\n\tenabled = true\n\tlog_filename = {LOG}\n}}\n\
         database = {CRM}\n{{\n\tenabled = false\n}}\n\
         services\n{{\n\tenabled = true\n\tlog_filename = {LOG}\n\tlog_services = true\n}}\n"
    );
    let v = eval(&t, Some(&empty_map()), &crm());
    assert!(v.partial, "{:?}", v.notes);
    assert_eq!(v.max_sql_length, 8192);
    // A disabled first match: nothing is logged.
    let t2 = t.replacen(
        "\tenabled = true\n\tlog_filename",
        "\tenabled = false\n\tlog_filename",
        1,
    );
    assert!(!eval(&t2, Some(&empty_map()), &crm()).partial);
}

/// Proof 3 (open question 12) and R2 rule 4: a `SIMILAR TO` pattern, or a
/// plain file name, before the first match caps the level; after it, not.
#[test]
fn patterns_the_agent_cannot_evaluate() {
    for pattern in [
        "%[\\\\/]crm.fdb",
        "crm.fdb",
        "/var/lib/firebird/data/c_m.fdb",
    ] {
        let t = DEV_TRACE.replacen(
            &format!("database = {CRM}"),
            &format!("database = {pattern}\n{{\n\tenabled = true\n}}\n\ndatabase = {CRM}"),
            1,
        );
        let v = eval(&t, Some(&empty_map()), &crm());
        assert!(!v.partial, "{pattern}");
        assert!(
            labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated)
                .contains(&"similar_to_pattern".to_owned()),
            "{pattern}"
        );
        let after = format!("{DEV_TRACE}\ndatabase = {pattern}\n{{\n\tenabled = false\n}}\n");
        let v = eval(&after, Some(&empty_map()), &crm());
        assert!(v.partial, "{pattern}: {:?}", v.notes);
    }
    // A declared database whose path holds `_` cannot match a plain
    // section (proof 3): Limited.
    let db = [DeclaredDb {
        label: "app",
        resolved: Some("/var/lib/firebird/data/app_db.fdb"),
        alias: None,
    }];
    let t = DEV_TRACE.replace(CRM, "/var/lib/firebird/data/app_db.fdb");
    assert!(!eval(&t, Some(&empty_map()), &db).partial);
}

/// Proof 11: the default section logs elsewhere or is disabled; every
/// named section writing the declared log names a declared database.
#[test]
fn the_declared_log_holds_only_declared_databases() {
    let t = DEV_TRACE.replacen(
        "database\n{\n\tenabled = false\n}",
        &format!("database\n{{\n\tenabled = true\n\tlog_filename = {LOG}\n}}"),
        1,
    );
    let v = eval(&t, Some(&empty_map()), &crm());
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated),
        ["foreign_databases_logged"]
    );
    // The default section writing another file is allowed.
    let t = DEV_TRACE.replacen(
        "database\n{\n\tenabled = false\n}",
        "database\n{\n\tenabled = true\n\tlog_filename = /var/log/other.log\n}",
        1,
    );
    assert!(eval(&t, Some(&empty_map()), &crm()).partial);
    // Another database's section writing the declared log.
    let t = format!(
        "{DEV_TRACE}\ndatabase = /var/lib/firebird/data/other.fdb\n{{\n\tenabled = true\n\tlog_filename = {LOG}\n}}\n"
    );
    let v = eval(&t, Some(&empty_map()), &crm());
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated),
        ["foreign_databases_logged"]
    );
    // `\N` substitutions are not evaluated (review L-d).
    let t = DEV_TRACE.replacen(
        "log_filename = /var/lib/firebird/audit/audit.log",
        "log_filename = \\1.log",
        1,
    );
    let v = eval(&t, Some(&empty_map()), &crm());
    assert!(
        labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated)
            .contains(&"similar_to_pattern".to_owned())
    );
    // A relative log name is resolved against the root; one with a `..`
    // component is not evaluated (review of part 1, L2).
    let t = DEV_TRACE.replace(
        "log_filename = /var/lib/firebird/audit/audit.log",
        "log_filename = ../../var/lib/firebird/audit/audit.log",
    );
    assert!(!eval(&t, Some(&empty_map()), &crm()).partial);
    let rel = DEV_TRACE.replace(
        "log_filename = /var/lib/firebird/audit/audit.log",
        "log_filename = audit.log",
    );
    let t = parse_trace_conf(rel.as_bytes()).unwrap();
    let v = evaluate(&Inputs {
        trace: &t,
        aliases: Some(&empty_map()),
        databases: &crm(),
        log: "/opt/firebird/audit.log",
        root: ROOT,
        longest_own_text: 900,
    });
    assert!(v.partial, "{:?}", v.notes);
}

/// Proof 6 and R27 item 2: the services section, required for Partial.
#[test]
fn the_services_section_is_required() {
    let t = DEV_TRACE.replace("\tlog_services = true\n", "");
    let v = eval(&t, Some(&empty_map()), &crm());
    assert!(!v.partial);
    assert_eq!(
        codes(&v.notes),
        [
            NoteCode::AuditServicesNotAudited,
            NoteCode::AuditTraceSettingsMissing
        ]
    );
    assert_eq!(
        labels(&v.notes, NoteCode::AuditTraceSettingsMissing),
        ["log_services"]
    );
    let none = &DEV_TRACE[..DEV_TRACE.find("services\n").unwrap()];
    assert!(!eval(none, Some(&empty_map()), &crm()).partial);
}

/// Proof 5 and R8 item 6.
#[test]
fn statement_text_limits() {
    let t = DEV_TRACE.replace("max_sql_length = 65000", "max_sql_length = 2048");
    let v = eval(&t, Some(&empty_map()), &crm());
    // Above the longest own text (900 here), below 4096: a note, no cap.
    assert!(v.partial);
    assert_eq!(codes(&v.notes), [NoteCode::AuditStatementTextLimitLow]);
    let t = DEV_TRACE.replace("max_sql_length = 65000", "max_sql_length = 512");
    let v = eval(&t, Some(&empty_map()), &crm());
    assert!(!v.partial);
    assert_eq!(codes(&v.notes), [NoteCode::AuditStatementTextLimitLow]);
    let t = DEV_TRACE.replace("\tmax_sql_length = 65000\n", "");
    assert_eq!(eval(&t, Some(&empty_map()), &crm()).max_sql_length, 300);
}

/// R2 rule 4: every alias mapping to the database is evaluated; differing
/// effective settings are Limited.
#[test]
fn aliases_are_evaluated_with_the_path() {
    let map = parse_databases_conf(format!("crmalias = {CRM}\n").as_bytes(), ROOT).unwrap();
    let dbs = [DeclaredDb {
        label: "crm",
        resolved: Some(CRM),
        alias: Some("crmalias"),
    }];
    // The alias matches no named section: the default section (disabled)
    // applies to it, which differs from the path's.
    let v = eval(DEV_TRACE, Some(&map), &dbs);
    assert!(!v.partial);
    assert!(
        labels(&v.notes, NoteCode::AuditTraceConfigNotEvaluated)
            .contains(&"databases_conf".to_owned())
    );
    // A section for the alias with the same settings: proven.
    let body = &DEV_TRACE[DEV_TRACE.find(&format!("database = {CRM}")).unwrap()..];
    let body = &body[..body.find("services\n").unwrap()];
    let t = format!("{DEV_TRACE}\n{}", body.replacen(CRM, "crmalias", 1));
    let v = eval(&t, Some(&map), &dbs);
    assert!(v.partial, "{:?}", v.notes);
}

#[test]
fn firebird_conf_grammar() {
    let c = parse_firebird_conf(
        b"# comment\nAuditTraceConfigFile = /databastion/fbtrace.conf # trailing\n\
          servermode = SuperClassic\nWireCrypt = Required\n",
    )
    .unwrap();
    assert_eq!(
        c.audit_trace_config_file.as_deref(),
        Some("/databastion/fbtrace.conf")
    );
    assert_eq!(c.server_mode, ServerMode::SuperClassic);
    assert!(c.trace_plugin_default);
    assert!(binds_trace_config(&c, ROOT, "/databastion/fbtrace.conf"));
    assert!(!binds_trace_config(&c, ROOT, "/opt/firebird/fbtrace.conf"));
    let rel = parse_firebird_conf(b"AuditTraceConfigFile = fbtrace.conf\n").unwrap();
    assert!(binds_trace_config(&rel, ROOT, "/opt/firebird/fbtrace.conf"));
    let mac = parse_firebird_conf(b"AuditTraceConfigFile = $(ROOT)/a/../fbtrace.conf\n").unwrap();
    // A `..` component is refused (review of part 1, L2).
    assert!(!binds_trace_config(
        &mac,
        ROOT,
        "/opt/firebird/fbtrace.conf"
    ));
    let mac = parse_firebird_conf(b"AuditTraceConfigFile = $(ROOT)/./fbtrace.conf\n").unwrap();
    assert!(binds_trace_config(&mac, ROOT, "/opt/firebird/fbtrace.conf"));
    let unknown_macro = parse_firebird_conf(b"AuditTraceConfigFile = $(dir_udf)/x\n").unwrap();
    assert!(!binds_trace_config(
        &unknown_macro,
        ROOT,
        "/opt/firebird/udf/x"
    ));
    let plugin = parse_firebird_conf(b"TracePlugin = other\nAuditTraceConfigFile = /x\n").unwrap();
    assert!(!binds_trace_config(&plugin, ROOT, "/x"));
    assert_eq!(
        parse_firebird_conf(b"ServerMode = Classic\n")
            .unwrap()
            .server_mode,
        ServerMode::Classic
    );
    assert_eq!(
        parse_firebird_conf(b"").unwrap().server_mode,
        ServerMode::Super
    );
    for (bad, e) in [
        (&b"NoSuchKey = 1\n"[..], ConfError::UnknownKey),
        (b"include other.conf\n", ConfError::Include),
        (
            b"ServerMode = Super\nServerMode = Classic\n",
            ConfError::Duplicate,
        ),
        (b"ServerMode = Hybrid\n", ConfError::Value),
        (b"WireCrypt = \"Required\n", ConfError::Value),
        (b"\xff = 1\n", ConfError::Encoding),
        (b"= 1\n", ConfError::Syntax),
        (b"{\n", ConfError::Syntax),
    ] {
        assert_eq!(
            parse_firebird_conf(bad),
            Err(e),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        parse_firebird_conf(&vec![b'#'; MAX_CONF_BYTES + 1]),
        Err(ConfError::TooLarge)
    );
}

#[test]
fn databases_conf_grammar() {
    let m = parse_databases_conf(
        b"# aliases\nemployee.fdb = $(dir_sampleDb)/employee.fdb\n\
          security.db = $(dir_secDb)/security5.fdb\n{\n\tRemoteAccess = false\n}\n\
          crm = /var/lib/firebird/data/crm.fdb\n\
          selfsec = /data/self.fdb {\n\tSecurityDatabase = selfsec\n}\n\
          rel = data/rel.fdb\n",
        ROOT,
    )
    .unwrap();
    assert_eq!(m.get("employee.fdb").unwrap().path, None);
    assert_eq!(
        m.get("security.db").unwrap().path.as_deref(),
        Some("/opt/firebird/security5.fdb")
    );
    assert_eq!(m.aliases_of(CRM).collect::<Vec<_>>(), ["crm"]);
    assert_eq!(
        m.get("rel").unwrap().path.as_deref(),
        Some("/opt/firebird/data/rel.fdb")
    );
    assert_eq!(
        m.get("selfsec").unwrap().security_database.as_deref(),
        Some("selfsec")
    );
    for bad in [
        &b"a = /x\na = /y\n"[..],
        b"a = /x\n{\n\tNoSuchKey = 1\n}\n",
        b"a = /x\n{\n\tGCPolicy = cooperative\n\tGCPolicy = background\n}\n",
        b"{\n}\n",
        b"a = /x\n{\n",
        b"include more.conf\n",
        b"a /x\n",
    ] {
        assert!(
            parse_databases_conf(bad, ROOT).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// R9 rule 3: a database whose entry names itself as its security
/// database (or whose entry cannot be evaluated) is excluded.
#[test]
fn own_security_database_from_the_map() {
    let m = parse_databases_conf(
        b"selfsec = /data/self.fdb {\n\tSecurityDatabase = selfsec\n}\n\
          secdb = /data/secdb.fdb {\n\tSecurityDatabase = secdb\n}\n\
          othersec = /data/osec.fdb {\n\tSecurityDatabase = secdb\n}\n\
          bypath = /data/p.fdb {\n\tSecurityDatabase = /data/p.fdb\n}\n\
          macro = $(dir_udf)/m.fdb\n\
          app = /data/app.fdb\n",
        ROOT,
    )
    .unwrap();
    let db = |alias: Option<&'static str>, resolved: &'static str| DeclaredDb {
        label: "x",
        resolved: Some(resolved),
        alias,
    };
    assert_eq!(
        own_security_database(Some(&m), &db(Some("selfsec"), "/data/self.fdb"), ROOT),
        Some(true)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(None, "/data/self.fdb"), ROOT),
        Some(true)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(None, "/data/secdb.fdb"), ROOT),
        Some(true)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(None, "/data/osec.fdb"), ROOT),
        Some(false)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(None, "/data/p.fdb"), ROOT),
        Some(true)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(Some("macro"), "/x/m.fdb"), ROOT),
        Some(true)
    );
    assert_eq!(
        own_security_database(Some(&m), &db(None, "/data/app.fdb"), ROOT),
        Some(false)
    );
    assert_eq!(
        own_security_database(None, &db(None, "/data/app.fdb"), ROOT),
        None
    );
}

#[test]
fn trace_conf_grammar() {
    let t = parse_trace_conf(DEV_TRACE.as_bytes()).unwrap();
    assert_eq!(t.sections.len(), 3);
    // Both forms of a value, quotes, a brace on the header line, `{{`.
    let t = parse_trace_conf(
        b"database = (%[\\\\/](e[[:DIGIT:]]{{2}}).fdb) {\n\tlog_filename 'a b.log'\n\tenabled = yes\n}\n",
    )
    .unwrap();
    assert_eq!(
        t.sections[0].kind,
        SectionKind::Database(Some("(%[\\\\/](e[[:DIGIT:]]{2}).fdb)".to_owned()))
    );
    for bad in [
        &b"database\n{\n\tno_such_key = true\n}\n"[..],
        b"database\n{\n\tenabled = maybe\n}\n",
        b"database\n{\n\tenabled = true\n\tenabled = false\n}\n",
        b"database\n{\n}\ndatabase\n{\n}\n",
        b"database\n{\n\ttime_threshold = -1\n}\n",
        b"services\n{\n\tlog_statement_finish = true\n}\n",
        b"<database>\n</database>\n",
        b"database\n",
        b"database\n{\n",
        b"include x.conf\n",
        b"database = a{b\n{\n}\n",
        // Review of part 1, L3: exact-case keys, unquoted booleans.
        b"database\n{\n\tEnabled = true\n}\n",
        b"database\n{\n\tenabled = \"true\"\n}\n",
        b"database\n{\n\ttime_threshold = '0'\n}\n",
    ] {
        assert!(
            parse_trace_conf(bad).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn binding_notes() {
    let n = not_evaluated("config_changed_since_start");
    assert_eq!(n.code(), NoteCode::AuditTraceConfigNotEvaluated);
    assert_eq!(n.labels()[0].as_str(), "config_changed_since_start");
}

#[test]
fn macros_and_paths() {
    assert_eq!(
        resolve("$(root)/x", ROOT).as_deref(),
        Some("/opt/firebird/x")
    );
    assert_eq!(
        resolve("$(DIR_CONF)/x", ROOT).as_deref(),
        Some("/opt/firebird/x")
    );
    assert_eq!(resolve("/a//b/./c", ROOT).as_deref(), Some("/a/b/c"));
    assert_eq!(resolve("/a/b/../d", ROOT), None);
    assert_eq!(resolve("/..", ROOT), None);
    assert_eq!(resolve("$(dir_plugins)/x", ROOT), None);
    assert_eq!(resolve("$(root", ROOT), None);
    assert_eq!(resolve("C:\\x", ROOT), None);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Arbitrary input never panics, in any parser.
    #[test]
    fn arbitrary_files_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_firebird_conf(&bytes);
        let _ = parse_databases_conf(&bytes, ROOT);
        if let Ok(t) = parse_trace_conf(&bytes) {
            let _ = evaluate(&Inputs {
                trace: &t,
                aliases: None,
                databases: &crm(),
                log: LOG,
                root: ROOT,
                longest_own_text: 900,
            });
        }
    }

    /// Any line added to the dev configuration either keeps it parsing or
    /// makes it fail closed; it never makes an unproven configuration
    /// proven.
    #[test]
    fn added_lines_never_prove_more(line in "[a-z_ =\t{}%/.0-9#'\"]{0,40}") {
        let t = DEV_TRACE.replacen("\tmax_sql_length = 65000\n", &format!("\tmax_sql_length = 65000\n{line}\n"), 1)
            .replace("\tprint_perf = true\n", "");
        if let Ok(conf) = parse_trace_conf(t.as_bytes()) {
            let v = evaluate(&Inputs {
                trace: &conf,
                aliases: Some(&empty_map()),
                databases: &crm(),
                log: LOG,
                root: ROOT,
                longest_own_text: 900,
            });
            prop_assert!(!v.partial || line.contains("print_perf"));
        }
    }
}
