//! Unit tests of ADR-0050 (credential- and value-bearing catalogs as
//! reads): the closed list in every form, the no-secret shape and each of
//! its conditions broken one at a time, the pgaudit relation-record rule,
//! the always-reported mark, and the agent's own reads (the connector's
//! statements quiet, its two-key reads left out on pgaudit only by exact
//! text and identity).

#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

use super::*;
use crate::audit::records::{Format, parse_record};
use databastion_core::audit::own::SharedOwnUsage;

const AGENT_APP: &str = crate::conn::APPLICATION_NAME;
const AGENT_ADDR: &str = "192.0.2.14";

/// One pgaudit record (jsonlog), with its relation record when `object`
/// is given (`object_type`: `TABLE`, `VIEW`…).
#[allow(clippy::too_many_arguments)]
fn record(
    sub: u64,
    class: &str,
    command: &str,
    object: &str,
    object_type: &str,
    text: &str,
    user: &str,
    app: &str,
    remote: &str,
) -> AuditRecord {
    let text = text.replace('"', "\"\"");
    let line = serde_json::json!({
        "timestamp": "2026-10-12 08:00:01.000 UTC", "user": user, "dbname": "shop",
        "error_severity": "LOG",
        "remote_host": remote, "session_id": "6abadffb.3ef", "application_name": app,
        "message": format!(
            "AUDIT: SESSION,1,{sub},{class},{command},{},{object},\"{text}\",<not logged>,1",
            if object.is_empty() { "" } else { object_type }
        ),
    });
    parse_record(Format::Jsonlog, line.to_string().as_bytes(), "LOG").unwrap()
}

fn own_with(usage: SharedOwnUsage) -> PgOwn {
    PgOwn::new(
        OwnAccount::new(
            "databastion",
            Some(AGENT_APP),
            ClientAddr::parse(AGENT_ADDR),
            1000,
            usage,
        ),
        SharedOwnStatements::default(),
    )
}

fn catalogs(log_catalog: Option<bool>) -> Catalogs {
    let mut c = Catalogs::default();
    c.insert(
        "shop",
        DbCatalog {
            pss_schema: Some("public".to_owned()),
            pgaudit_log_catalog: log_catalog,
        },
    );
    c
}

fn objects_of(e: &MaskedEvent) -> Vec<String> {
    e.objects()
        .iter()
        .map(|o| {
            format!(
                "{}.{}.{}",
                o.database().as_str(),
                o.schema().map_or("", |s| s.as_str()),
                o.object().as_str()
            )
        })
        .collect()
}

fn charged(u: &SharedOwnUsage) -> bool {
    !u.lock().unwrap().budgeted_objects().is_empty()
}

/// Events of `records` on pgaudit.
fn pgaudit(
    records: Vec<AuditRecord>,
    log_catalog: Option<bool>,
    usage: &SharedOwnUsage,
) -> Vec<MaskedEvent> {
    let mut b = PgauditEvents::new(own_with(usage.clone()));
    b.set_catalogs(catalogs(log_catalog));
    b.convert(records, SystemTime::now())
}

/// Events of `text` (one record, no relation record) on pgaudit, from the
/// agent's identity (`agent`) or `backup` through `psql`.
fn pgaudit_text(
    text: &str,
    class: &str,
    command: &str,
    agent: bool,
    log_catalog: Option<bool>,
    usage: &SharedOwnUsage,
) -> Vec<MaskedEvent> {
    let (user, app) = if agent {
        ("databastion", AGENT_APP)
    } else {
        ("backup", "psql")
    };
    pgaudit(
        vec![record(
            1, class, command, "", "", text, user, app, AGENT_ADDR,
        )],
        log_catalog,
        usage,
    )
}

/// Events of `text` on `pg_stat_statements` from `user`.
fn pss(
    text: &str,
    user: &str,
    cut: bool,
    own_text: bool,
    usage: &SharedOwnUsage,
) -> Vec<MaskedEvent> {
    let c = catalogs(None);
    let a = analyze_pss(text, cut);
    let none = HashSet::new();
    let reads = text_reads(text, &a, c.rule("shop", true, &none), cut);
    let deltas = [StatementDelta {
        reads: &reads,
        own_text,
        user,
        database: "shop",
        analysis: &a,
        calls: 3,
        rows: 2,
    }];
    let t0 = SystemTime::UNIX_EPOCH;
    pss_events(&deltas, &mut own_with(usage.clone()), &c, t0, t0)
}

fn class_of(text: &str) -> (&'static str, &'static str) {
    let lower = text.trim_start().to_ascii_lowercase();
    if lower.starts_with("create") {
        ("DDL", "CREATE TABLE AS")
    } else if lower.starts_with("copy") {
        ("READ", "COPY")
    } else if lower.starts_with("insert") {
        ("WRITE", "INSERT")
    } else {
        ("READ", "SELECT")
    }
}

/// `text` is a secret read naming every object of `want`, always
/// reported, on pgaudit (every `log_catalog` setting, the agent's identity
/// and another account) and on `pg_stat_statements` (unless `pss` is
/// false), never left out nor charged to the agent.
fn assert_secret(text: &str, want: &[&str], pss_too: bool) {
    let (class, command) = class_of(text);
    for log_catalog in [Some(true), Some(false), None] {
        for agent in [true, false] {
            let usage = SharedOwnUsage::default();
            let ev = pgaudit_text(text, class, command, agent, log_catalog, &usage);
            assert!(!ev.is_empty(), "{agent} {log_catalog:?}: {text}");
            let all: Vec<String> = ev.iter().flat_map(objects_of).collect();
            for w in want {
                assert!(
                    all.contains(&(*w).to_owned()),
                    "{agent} {log_catalog:?}: {text}: {all:?}"
                );
            }
            let secret = ev
                .iter()
                .find(|e| {
                    want.iter()
                        .any(|w| objects_of(e).contains(&(*w).to_owned()))
                })
                .unwrap();
            assert!(secret.always_report(), "{text}");
            assert!(!charged(&usage), "{agent}: {text}");
        }
    }
    if pss_too {
        for user in ["app", "databastion"] {
            for own_text in [false, true] {
                let usage = SharedOwnUsage::default();
                let ev = pss(text, user, false, own_text, &usage);
                assert_eq!(ev.len(), 1, "{user}: {text}");
                let objects = objects_of(&ev[0]);
                for w in want {
                    assert!(
                        objects.contains(&(*w).to_owned()),
                        "{user}: {text}: {objects:?}"
                    );
                }
                assert!(ev[0].always_report(), "{user}: {text}");
                assert!(!charged(&usage), "{user}: {text}");
            }
        }
    }
}

/// `text` gives no event naming a secret-list object on either source
/// (pgaudit with `log_catalog` on or unknown, the text deciding), from
/// any account.
fn assert_quiet(text: &str) {
    let secret = |ev: &[MaskedEvent]| {
        ev.iter().any(|e| {
            e.objects().iter().any(|o| {
                is_secret_object(&RelationName {
                    schema: o.schema().map(|s| s.as_str().to_owned()),
                    name: o.object().as_str().to_owned(),
                })
            })
        })
    };
    let (class, command) = class_of(text);
    for log_catalog in [Some(true), None] {
        for agent in [true, false] {
            let ev = pgaudit_text(
                text,
                class,
                command,
                agent,
                log_catalog,
                &SharedOwnUsage::default(),
            );
            assert!(
                !secret(&ev),
                "{agent} {log_catalog:?}: {text}: {:?}",
                ev.iter().map(objects_of).collect::<Vec<_>>()
            );
        }
    }
    for user in ["app", "databastion"] {
        let ev = pss(text, user, false, false, &SharedOwnUsage::default());
        assert!(!secret(&ev), "{user}: {text}");
    }
}

/// The shaped entries with a column that is not secret.
const SHAPED: [(&str, &str); 10] = [
    ("pg_authid", "rolname"),
    ("pg_shadow", "usename"),
    ("pg_roles", "rolname"),
    ("pg_user", "usename"),
    ("pg_db_role_setting", "setrole"),
    ("pg_user_mapping", "umuser"),
    ("pg_user_mappings", "srvname"),
    ("pg_foreign_server", "srvname"),
    ("pg_subscription", "subname"),
    ("pg_proc", "proname"),
];

fn entry_of(name: &str) -> &'static SecretEntry {
    SECRET_RELATIONS
        .iter()
        .find(|e| e.name == name && !e.function)
        .unwrap()
}

/// Decision 1: the list, its objects and its secret columns.
#[test]
fn the_closed_list() {
    assert_eq!(SECRET_RELATIONS.iter().filter(|e| e.shape).count(), 10);
    for (n, _) in SHAPED {
        assert!(entry_of(n).shape, "{n}");
        assert!(!entry_of(n).columns.is_empty(), "{n}");
    }
    assert_eq!(entry_of("pg_roles").columns, ["rolconfig"]);
    assert_eq!(entry_of("pg_proc").columns, ["proconfig"]);
    assert_eq!(entry_of("pg_shadow").columns, ["passwd", "useconfig"]);
    for n in ["pg_largeobject", "pg_file_settings", "pg_hba_file_rules"] {
        assert!(!entry_of(n).shape, "{n}");
    }
    let r = |s: Option<&str>, n: &str| RelationName {
        schema: s.map(str::to_owned),
        name: n.to_owned(),
    };
    let (_, o) = secret_entry(&r(None, "pg_authid"), false).unwrap();
    assert_eq!(o, r(Some("pg_catalog"), "pg_authid"));
    let (_, o) = secret_entry(&r(None, "pg_show_all_file_settings"), true).unwrap();
    assert_eq!(o, r(Some("pg_catalog"), "pg_file_settings"));
    let (_, o) = secret_entry(&r(Some("pg_catalog"), "pg_hba_file_rules"), true).unwrap();
    assert_eq!(o, r(Some("pg_catalog"), "pg_hba_file_rules"));
    let (_, o) = secret_entry(&r(None, "user_mapping_options"), false).unwrap();
    assert_eq!(o, r(None, "user_mapping_options"));
    assert!(secret_entry(&r(Some("public"), "pg_authid"), false).is_none());
    assert!(secret_entry(&r(None, "PG_AUTHID"), false).is_none());
    assert!(secret_entry(&r(Some("pg_catalog"), "user_mapping_options"), false).is_none());
    // A relation followed by `(` (`COPY pg_authid (rolname)`).
    assert!(secret_entry(&r(None, "pg_authid"), true).is_some());
    assert!(secret_entry(&r(None, "pg_largeobject_metadata"), false).is_none());
}

/// Decisions 1, 2 and 4: each shaped entry, qualified, unqualified or
/// `U&`-escaped, with a secret column in every position, or any construct
/// that can read it unnamed, is a secret read naming the entry, always
/// reported, in every action class; read without, it is quiet.
#[test]
fn shaped_entries_in_every_form() {
    for (name, plain) in SHAPED {
        let entry = entry_of(name);
        let object = format!("shop.pg_catalog.{name}");
        let want = [object.as_str()];
        let escaped = format!("U&\"\\0070{}\"", &name[1..]);
        for form in [format!("pg_catalog.{name}"), name.to_owned(), escaped] {
            assert_quiet(&format!(
                "SELECT x.{plain} FROM {form} x WHERE x.{plain} IS NOT NULL"
            ));
            assert_quiet(&format!("SELECT count(*) FROM {form}"));
            for column in entry.columns {
                for text in [
                    format!("SELECT x.{column} FROM {form} x"),
                    format!("SELECT {column} FROM {form}"),
                    format!("SELECT \"{column}\" FROM {form}"),
                    format!("SELECT 1 FROM {form} x WHERE x.{column} IS NOT NULL"),
                    format!("SELECT x.{plain} FROM {form} x ORDER BY x.{column}"),
                    format!("SELECT 1 FROM {form} a JOIN {form} b USING ({column})"),
                    format!("SELECT x.{plain} AS {column} FROM {form} x"),
                    format!("SELECT (SELECT x.{column} FROM {form} x LIMIT 1)"),
                    format!("WITH s AS (SELECT x.{column} FROM {form} x) SELECT 1 FROM s"),
                    format!("COPY (SELECT x.{column} FROM {form} x) TO STDOUT"),
                    format!("CREATE TABLE t AS SELECT x.{column} FROM {form} x"),
                    format!("INSERT INTO t SELECT x.{column} FROM {form} x"),
                ] {
                    assert_secret(&text, &want, true);
                }
            }
            for text in [
                format!("SELECT * FROM {form}"),
                format!("SELECT x.* FROM {form} x"),
                format!("SELECT row_to_json(x) FROM {form} x"),
                format!("SELECT x::text FROM {form} x"),
                format!("SELECT (x).* FROM {form} x"),
                format!("SELECT x FROM {form} x"),
                format!("SELECT x.a FROM {form} x (a)"),
                format!("SELECT b.{plain} FROM {form} a NATURAL JOIN {form} b"),
                format!("TABLE {form}"),
                format!("SELECT x.{plain}, public.f() FROM {form} x"),
                format!("SELECT x.{plain} FROM {form} x, crm.customer c"),
                format!("COPY {form} TO STDOUT"),
                format!("COPY {form} ({plain}) TO STDOUT"),
            ] {
                assert_secret(&text, &want, true);
            }
        }
        // The bare name as a whole row.
        assert_secret(&format!("SELECT {name} FROM {name}"), &want, true);
        // A cut text (`pg_stat_statements` at its read bound).
        for user in ["app", "databastion"] {
            let ev = pss(
                &format!("SELECT x.{plain} FROM {name} x WHERE x.{plain} = $1"),
                user,
                true,
                false,
                &SharedOwnUsage::default(),
            );
            assert!(objects_of(&ev[0]).contains(&object), "{name}");
            assert!(ev[0].always_report());
        }
        // Look-alikes are ordinary relations.
        for text in [
            format!("SELECT x.{} FROM public.{name} x", entry.columns[0]),
            format!(
                "SELECT x.{} FROM \"{}\" x",
                entry.columns[0],
                name.to_uppercase()
            ),
        ] {
            assert_quiet(&text);
        }
    }
}

/// Decisions 1 and 2: entries without a shape exemption are secret reads
/// whatever their columns; the function forms are named by their view;
/// `information_schema` entries are named as the text gives them.
#[test]
fn unshaped_entries_are_always_secret_reads() {
    for (text, want) in [
        (
            "SELECT l.loid FROM pg_largeobject l",
            "shop.pg_catalog.pg_largeobject",
        ),
        (
            "SELECT count(*) FROM pg_catalog.pg_largeobject",
            "shop.pg_catalog.pg_largeobject",
        ),
        (
            "SELECT f.name FROM pg_file_settings f",
            "shop.pg_catalog.pg_file_settings",
        ),
        (
            "SELECT s.name FROM pg_catalog.pg_show_all_file_settings() s",
            "shop.pg_catalog.pg_file_settings",
        ),
        (
            "SELECT r.type FROM pg_hba_file_rules r",
            "shop.pg_catalog.pg_hba_file_rules",
        ),
        (
            "SELECT r.options FROM pg_hba_file_rules() r",
            "shop.pg_catalog.pg_hba_file_rules",
        ),
        (
            "SELECT o.option_name FROM information_schema.user_mapping_options o",
            "shop.information_schema.user_mapping_options",
        ),
        (
            "SELECT o.option_name FROM user_mapping_options o",
            "shop..user_mapping_options",
        ),
        (
            "SELECT m.srvname FROM information_schema._pg_user_mappings m",
            "shop.information_schema._pg_user_mappings",
        ),
        (
            "SELECT o.option_name FROM information_schema.foreign_server_options o",
            "shop.information_schema.foreign_server_options",
        ),
        (
            "SELECT s.srvname FROM information_schema._pg_foreign_servers s",
            "shop.information_schema._pg_foreign_servers",
        ),
    ] {
        assert_secret(text, &[want], true);
    }
}

/// Decision 2: the common reads the shape covers are quiet; `proconfig`
/// read from `pg_proc` is not.
#[test]
fn common_reads_are_quiet() {
    for text in [
        "SELECT r.rolname FROM pg_roles r WHERE r.rolsuper",
        "SELECT r.rolname AS \"Role name\", r.rolsuper, r.rolinherit, r.rolcreaterole, \
         r.rolcreatedb, r.rolcanlogin, r.rolconnlimit, r.rolvaliduntil, r.rolreplication, \
         r.rolbypassrls FROM pg_catalog.pg_roles r WHERE r.rolname !~ '^pg_' ORDER BY 1",
        "SELECT subname, subenabled FROM pg_subscription",
        "SELECT srvname FROM pg_foreign_server",
        "SELECT p.proname, p.prorettype FROM pg_proc p",
        "SELECT p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n \
         ON n.oid = p.pronamespace WHERE n.nspname = 'public'",
        "SELECT rolname FROM pg_roles",
        "SELECT count(*) FROM pg_authid",
    ] {
        assert_quiet(text);
    }
    assert_secret(
        "SELECT p.proname, p.proconfig FROM pg_proc p",
        &["shop.pg_catalog.pg_proc"],
        true,
    );
    // PgBouncer's default `auth_query`.
    assert_secret(
        "SELECT usename, passwd FROM pg_shadow WHERE usename=$1",
        &["shop.pg_catalog.pg_shadow"],
        true,
    );
}

/// Decision 2 with ADR-0049 decision 8: an unqualified user function next
/// to an entry read in the shape makes it a secret read (the collision
/// probe found `length`).
#[test]
fn user_code_next_to_a_shaped_entry() {
    let names =
        super::super::user_code::ProbeNames::from_rows([("f".to_owned(), "length".to_owned())])
            .unwrap();
    let shared = super::super::user_code::SharedUserCode::default();
    super::super::user_code::lock(&shared).store(
        "shop",
        std::time::Instant::now(),
        160_013,
        Some(names),
    );
    let mut c =
        catalogs(Some(true)).with_user_code(super::super::user_code::UserCodeHandle::new(shared));
    let text = "SELECT r.rolname, length(42) FROM pg_roles r";
    let mut b = PgauditEvents::new(own_with(SharedOwnUsage::default()));
    b.set_catalogs(c.clone());
    let ev = b.convert(
        vec![record(
            1, "READ", "SELECT", "", "", text, "backup", "psql", AGENT_ADDR,
        )],
        SystemTime::now(),
    );
    let objects = objects_of(&ev[0]);
    assert!(
        objects.contains(&"shop.pg_catalog.pg_roles".to_owned()),
        "{objects:?}"
    );
    assert!(objects.contains(&"shop..*".to_owned()), "{objects:?}");
    assert!(ev[0].always_report());
    // Without the collision: quiet.
    c = catalogs(Some(true));
    let mut b = PgauditEvents::new(own_with(SharedOwnUsage::default()));
    b.set_catalogs(c);
    assert!(
        b.convert(
            vec![record(
                1, "READ", "SELECT", "", "", text, "backup", "psql", AGENT_ADDR
            )],
            SystemTime::now(),
        )
        .is_empty()
    );
}

/// Decision 3, as seen on PostgreSQL 16 with pgaudit 16.0 and
/// `log_relation = on`.
#[test]
fn relation_records_of_secret_entries() {
    let rec = |object: &str, kind: &str, text: &str| {
        record(
            1, "READ", "SELECT", object, kind, text, "backup", "psql", AGENT_ADDR,
        )
    };
    let usage = SharedOwnUsage::default();
    // `pg_roles` read without a secret column: its records name the tables
    // behind the view: quiet.
    let text = "SELECT rolname FROM pg_roles";
    let roles = |text: &str| {
        vec![
            rec("pg_catalog.pg_roles", "VIEW", text),
            rec("pg_catalog.pg_authid", "TABLE", text),
            rec("pg_catalog.pg_db_role_setting", "TABLE", text),
        ]
    };
    assert!(pgaudit(roles(text), Some(true), &usage).is_empty());
    // The same records, with `rolconfig`: a secret read naming `pg_roles`
    // only (the records behind it are not enough alone).
    let ev = pgaudit(roles("SELECT rolconfig FROM pg_roles"), Some(true), &usage);
    assert_eq!(objects_of(&ev[0]), ["shop.pg_catalog.pg_roles"]);
    assert!(ev[0].always_report());
    // A `pg_stat_activity` read gets a `pg_authid` record: not a secret
    // read.
    let text = "SELECT a.pid FROM pg_stat_activity a";
    assert!(
        pgaudit(
            vec![
                rec("pg_catalog.pg_stat_activity", "VIEW", text),
                rec("pg_catalog.pg_database", "TABLE", text),
                rec("pg_catalog.pg_authid", "TABLE", text),
            ],
            Some(true),
            &usage
        )
        .is_empty()
    );
    // A user view over `pg_authid` (`public.v_pw AS SELECT rolname,
    // rolpassword AS p FROM pg_authid`): a secret read naming `pg_authid`.
    let text = "SELECT p FROM public.v_pw";
    let ev = pgaudit(
        vec![
            rec("public.v_pw", "VIEW", text),
            rec("pg_catalog.pg_authid", "TABLE", text),
        ],
        Some(true),
        &usage,
    );
    let objects = objects_of(&ev[0]);
    assert!(
        objects.contains(&"shop.pg_catalog.pg_authid".to_owned()),
        "{objects:?}"
    );
    assert!(
        objects.contains(&"shop.public.v_pw".to_owned()),
        "{objects:?}"
    );
    assert!(ev[0].always_report());
    // With `log_catalog = off` only the view's record: an event naming the
    // view, under the filters (decision 6).
    let ev = pgaudit(vec![rec("public.v_pw", "VIEW", text)], Some(false), &usage);
    assert_eq!(objects_of(&ev[0]), ["shop.public.v_pw"]);
    assert!(!ev[0].always_report());
    // A user view over `pg_roles` without a secret column: the accepted
    // over-report (security review of PR #215, L2).
    let text = "SELECT rolname FROM public.v";
    let mut recs = vec![rec("public.v", "VIEW", text)];
    recs.extend(roles(text));
    let ev = pgaudit(recs, Some(true), &usage);
    let objects = objects_of(&ev[0]);
    for o in [
        "shop.pg_catalog.pg_roles",
        "shop.pg_catalog.pg_authid",
        "shop.pg_catalog.pg_db_role_setting",
        "shop.public.v",
    ] {
        assert!(objects.contains(&o.to_owned()), "{objects:?}");
    }
    assert!(ev[0].always_report());
    // A text that names no relation (`EXECUTE` of a prepared read) with a
    // record of an entry: a secret read.
    let ev = pgaudit(
        vec![record(
            1,
            "READ",
            "SELECT",
            "pg_catalog.pg_authid",
            "TABLE",
            "EXECUTE p",
            "backup",
            "psql",
            AGENT_ADDR,
        )],
        Some(true),
        &usage,
    );
    assert!(objects_of(&ev[0]).contains(&"shop.pg_catalog.pg_authid".to_owned()));
    assert!(ev[0].always_report());
    // A function body's own substatement with its text.
    let body = "SELECT rolpassword FROM pg_catalog.pg_authid";
    let ev = pgaudit(
        vec![
            record(
                1,
                "READ",
                "SELECT",
                "",
                "",
                "SELECT public.f()",
                "backup",
                "psql",
                AGENT_ADDR,
            ),
            record(
                2,
                "READ",
                "SELECT",
                "pg_catalog.pg_authid",
                "TABLE",
                body,
                "backup",
                "psql",
                AGENT_ADDR,
            ),
        ],
        Some(true),
        &usage,
    );
    let all: Vec<String> = ev.iter().flat_map(objects_of).collect();
    assert!(
        all.contains(&"shop.pg_catalog.pg_authid".to_owned()),
        "{all:?}"
    );
    assert!(!charged(&usage));
}

/// Decision 5: the connector's statements that name an entry read it in
/// the no-secret shape, from any account.
#[test]
fn the_connectors_statements_are_quiet() {
    for s in [
        sql::ROLE_ATTRIBUTES,
        sql::MEMBERSHIPS,
        sql::OWNERSHIP,
        sql::OWN_OIDS,
        sql::PARAMETER_GRANTS,
        sql::POLICY_REFS_REJECTED,
        sql::PSS_FUNCTION_SCHEMA,
        sql::USER_CODE_PROBE,
        sql::INTROSPECT,
    ] {
        assert_quiet(s);
        assert_quiet(&pss_form(s).unwrap());
    }
}

/// Decision 5: the two-key reads are left out uncharged on pgaudit only,
/// on their exact text from the agent's identity with no record of
/// another entry; reported with one byte changed, from another role,
/// application or address, next to another entry's record, and always on
/// `pg_stat_statements`.
#[test]
fn the_two_key_reads_on_each_source() {
    for (text, entry) in [
        (sql::ROLE_LOG_OVERRIDES, "pg_db_role_setting"),
        (sql::FUNCTION_LOG_OVERRIDES, "pg_proc"),
    ] {
        let object = format!("shop.pg_catalog.{entry}");
        let other_catalog = if entry == "pg_proc" {
            "pg_catalog.pg_namespace"
        } else {
            "pg_catalog.pg_database"
        };
        let records = |text: &str, user: &str, app: &str, remote: &str| {
            vec![
                record(
                    1,
                    "READ",
                    "SELECT",
                    &format!("pg_catalog.{entry}"),
                    "TABLE",
                    text,
                    user,
                    app,
                    remote,
                ),
                record(
                    1,
                    "READ",
                    "SELECT",
                    other_catalog,
                    "TABLE",
                    text,
                    user,
                    app,
                    remote,
                ),
            ]
        };
        for log_catalog in [Some(true), Some(false), None] {
            let usage = SharedOwnUsage::default();
            // Exactly, from the agent: left out, not charged (with and
            // without relation records).
            assert!(
                pgaudit(
                    records(text, "databastion", AGENT_APP, AGENT_ADDR),
                    log_catalog,
                    &usage
                )
                .is_empty()
            );
            assert!(pgaudit_text(text, "READ", "SELECT", true, log_catalog, &usage).is_empty());
            assert!(!charged(&usage));
            let changed_keys = text.replace("log_min_messages", "app.jwt_secret");
            let changed_byte = text.replace("LIMIT 1001", "LIMIT 1002");
            for (t, user, app, remote) in [
                (changed_keys.as_str(), "databastion", AGENT_APP, AGENT_ADDR),
                (changed_byte.as_str(), "databastion", AGENT_APP, AGENT_ADDR),
                (text, "backup", "psql", AGENT_ADDR),
                (text, "databastion", "psql", AGENT_ADDR),
                (text, "databastion", AGENT_APP, "198.51.100.7"),
                (text, "backup", AGENT_APP, AGENT_ADDR),
            ] {
                let ev = pgaudit(records(t, user, app, remote), log_catalog, &usage);
                assert_eq!(ev.len(), 1, "{user} {app} {remote}");
                assert!(
                    objects_of(&ev[0]).contains(&object),
                    "{:?}",
                    objects_of(&ev[0])
                );
                assert!(ev[0].always_report());
            }
            // A record of another entry in the same statement.
            let mut recs = records(text, "databastion", AGENT_APP, AGENT_ADDR);
            recs.push(record(
                1,
                "READ",
                "SELECT",
                "pg_catalog.pg_authid",
                "TABLE",
                text,
                "databastion",
                AGENT_APP,
                AGENT_ADDR,
            ));
            assert_eq!(pgaudit(recs, log_catalog, &usage).len(), 1);
            assert!(!charged(&usage));
        }
        // `pg_stat_statements`: its stored text (constants as `$n`) is
        // reported, whoever ran it, even admitted as the agent's slot.
        let stored = pss_form(text).unwrap();
        assert!(stored.contains("$"), "{stored}");
        for user in ["databastion", "app"] {
            for own_text in [false, true] {
                let usage = SharedOwnUsage::default();
                let ev = pss(&stored, user, false, own_text, &usage);
                assert_eq!(ev.len(), 1);
                assert_eq!(objects_of(&ev[0]), [object.as_str()]);
                assert!(ev[0].always_report());
                assert!(!charged(&usage));
            }
        }
    }
}

/// I2: the analysis keeps names only; a fake secret in a literal of a
/// secret read reaches no event and no `Debug` output.
#[test]
fn no_value_leaves_with_a_secret_read() {
    const MARK: &str = "fake-jwt-secret-Sx7Q";
    let text = format!(
        "SELECT s.setconfig FROM pg_db_role_setting s WHERE s.setconfig::text LIKE '%{MARK}%'"
    );
    let usage = SharedOwnUsage::default();
    let ev = pgaudit_text(&text, "READ", "SELECT", false, Some(true), &usage);
    let mut out = format!("{ev:?}");
    out.push_str(&format!(
        "{:?}",
        text_reads(
            &text,
            &analyze_pss(&text, false),
            catalogs(None).rule("shop", true, &HashSet::new()),
            false
        )
    ));
    out.push_str(&format!("{:?}", pss(&text, "app", false, false, &usage)));
    assert!(!out.contains(MARK));
    assert!(objects_of(&ev[0]).contains(&"shop.pg_catalog.pg_db_role_setting".to_owned()));
}
