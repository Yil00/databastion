//! Property tests of the MySQL / MariaDB dialect of the query normalizer
//! (ADR-0007, ADR-0012 obligation 5 applied to MySQL by ADR-0018, ROADMAP
//! P4-D): no literal, comment or password content survives in the
//! normalized text, the extracted relation names or the leading words, for
//! every MySQL literal form, every comment form, backslash escapes read
//! under any `sql_mode`, double quotes read as strings or as `ANSI_QUOTES`
//! identifiers, password-bearing statements, and truncated input.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::query::{AnalyzeOptions, MAX_NORMALIZED_CHARS, analyze};
use proptest::prelude::*;

/// A secret marker: never an identifier of the generated statements.
fn marker() -> impl Strategy<Value = String> {
    "[A-Z]{6}".prop_map(|s| format!("Zq{s}"))
}

/// Digits-only marker (numeric literals).
fn digits() -> impl Strategy<Value = String> {
    "[1-9][0-9]{8,12}"
}

/// A literal or comment hiding `m` (or the digits `d`).
fn hiding(m: &str, d: &str) -> Vec<String> {
    vec![
        format!("'{m}'"),
        format!("'it''s {m}'"),
        format!("'a\\'{m}'"),
        format!("\"{m}\""),
        format!("\"it\"\"s {m}\""),
        format!("\"a\\\"{m}\""),
        format!("N'{m}'"),
        format!("n'{m}'"),
        format!("X'{m}'"),
        format!("b'{m}'"),
        format!("_utf8mb4'{m}'"),
        format!("_binary\"{m}\""),
        format!("_latin1 X'{m}'"),
        format!("/* {m} */ 1"),
        format!("/*+ {m} */ 1"),
        format!("1 # {m}\n"),
        format!("2 -- {m}\n"),
        format!("3 --\t{m}\n"),
        format!("/*!50000 '{m}' */"),
        format!("/*M!100500 '{m}' */"),
        format!("/*! \"{m}\" */"),
        d.to_owned(),
        format!("{d}.5e-3"),
        format!("0x{d}"),
        format!("0b{d}"),
        format!("DATE '{m}'"),
        format!("@'{m}'"),
        // Backslashes read differently with NO_BACKSLASH_ESCAPES, double
        // quotes differently with ANSI_QUOTES.
        format!("'x\\' from {m}_t where \\'"),
        format!("'{m}\\'"),
        format!("'a\\' , {m} , '"),
        format!("\"x\\\" from {m}_t where \\\""),
        format!("\"a\\\" , {m} , \""),
        // A string running past the end of an executable comment.
        format!("/*! 'a */ {m} '"),
        // Password masks written by the servers.
        "<secret>".to_owned(),
        "*****".to_owned(),
    ]
}

fn statement() -> impl Strategy<Value = (String, String, String)> {
    (
        marker(),
        digits(),
        prop::collection::vec(0usize..64, 1..6),
        prop::sample::select(vec![
            "select a, {} from hr.t where b = {}",
            "select * from t where c in ({}, {})",
            "insert into t (a, b) values ({}, {})",
            "replace into t set a = {}, b = {}",
            "update t set a = {} where b = {}",
            "delete from t where a = {} or b = {}",
            "select {} into outfile {} from t",
            "select {} from t limit {}, {}",
            "select /*!40001 sql_no_cache */ {} from `t` where x = {}",
            "create user u identified by {} password expire interval {} day",
            "alter user u identified by {}; select {}",
            "set password for u = password({}); select {}",
            "change master to master_password = {}, master_host = {}",
            "change replication source to source_password = {}, source_host = {}",
            "grant select on hr.* to u identified by {}; select {}",
            "create server s foreign data wrapper mysql options (password {}, host {})",
            "call p({}, {})",
            "show tables like {}; set @v = {}",
            "handler t read idx = ({}) where a = {}",
            "lock tables t read; select {} from t where a = {}",
            // Syntax errors are logged too: a literal where a name goes.
            "select a from {} join hr.{} on true",
            "show create table {}; handler {} read first",
            "lock tables {} read, {} write",
        ]),
    )
        .prop_map(|(m, d, picks, template)| {
            let pieces = hiding(&m, &d);
            let mut out = template.to_owned();
            let mut k = 0;
            while let Some(pos) = out.find("{}") {
                let piece = &pieces[picks[k % picks.len()] % pieces.len()];
                out.replace_range(pos..pos + 2, piece);
                k += 1;
            }
            (out, m, d)
        })
}

fn leaks(text: &str, m: &str, d: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(&m.to_ascii_lowercase()) || text.contains(d)
}

fn check(text: &str, m: &str, d: &str, truncated: bool) -> Result<(), TestCaseError> {
    let a = analyze(text, AnalyzeOptions::mysql().truncated(truncated));
    if let Some(n) = a.normalized() {
        prop_assert!(
            !leaks(n.as_str(), m, d),
            "normalized {:?} of {:?}",
            n.as_str(),
            text
        );
        prop_assert!(n.as_str().chars().count() <= MAX_NORMALIZED_CHARS);
    }
    for r in a
        .relations()
        .iter()
        .chain(a.parts().iter().flat_map(|p| p.relations.iter()))
    {
        prop_assert!(!leaks(&r.name, m, d), "relation from {text:?}");
        if let Some(s) = &r.schema {
            prop_assert!(!leaks(s, m, d), "schema from {text:?}");
        }
    }
    for p in a.parts() {
        for w in &p.lead {
            prop_assert!(!leaks(w, m, d), "lead word from {text:?}");
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn no_literal_survives((text, m, d) in statement()) {
        check(&text, &m, &d, false)?;
    }

    /// Input cut anywhere (the `server_audit` and `performance_schema`
    /// texts are cut at a byte limit, possibly inside a literal), whether
    /// or not the caller knows it was cut.
    #[test]
    fn no_literal_survives_truncation((text, m, d) in statement(), cut in 0usize..400) {
        let mut end = cut.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let prefix = &text[..end];
        check(prefix, &m, &d, false)?;
        check(prefix, &m, &d, true)?;
    }

    /// Arbitrary input never panics and stays bounded.
    #[test]
    fn arbitrary_text_is_bounded(text in "\\PC{0,300}") {
        let a = analyze(&text, AnalyzeOptions::mysql());
        if let Some(n) = a.normalized() {
            prop_assert!(n.as_str().chars().count() <= MAX_NORMALIZED_CHARS);
        }
        prop_assert!(a.relations().len() <= 16);
    }

    /// Arbitrary text made of MySQL's special characters never panics.
    #[test]
    fn lexer_special_characters(text in "[a-z '\"`#/*!M0-9\\\\;,()?@_xnbN\n-]{0,200}") {
        let a = analyze(&text, AnalyzeOptions::mysql());
        prop_assert!(a.relations().len() <= 16);
    }

    /// Non-DML statements never keep text, whatever follows.
    #[test]
    fn utility_statements_keep_no_text(
        head in prop::sample::select(vec![
            "alter", "create", "drop", "set", "grant", "revoke", "change", "start", "load",
            "handler", "call", "show", "flush", "lock", "install", "rename", "purge", "kill",
            "execute", "prepare", "do", "explain", "help", "use", "reset", "analyze", "xa",
        ]),
        tail in "[a-z '()=,;0-9`\"]{0,80}",
    ) {
        let a = analyze(&format!("{head} {tail}"), AnalyzeOptions::mysql());
        prop_assert!(a.normalized().is_none());
    }
}

#[test]
fn passwords_never_survive_in_logged_forms() {
    // As written by clients and as the servers log them (`server_audit`
    // masks with `*****`, MySQL and Percona with `<secret>`; MariaDB's
    // performance_schema keeps the clear text).
    for q in [
        "CREATE USER 'u'@'%' IDENTIFIED BY 'ZqPASSWD'",
        "ALTER USER 'u'@'%' IDENTIFIED WITH caching_sha2_password BY 'ZqPASSWD'",
        "SET PASSWORD FOR 'u'@'%' = PASSWORD('ZqPASSWD')",
        "GRANT SELECT ON hr.* TO 'u'@'%' IDENTIFIED BY 'ZqPASSWD'",
        "CREATE USER 'u'@'%' IDENTIFIED VIA mysql_native_password USING PASSWORD('ZqPASSWD')",
        "CHANGE MASTER TO MASTER_HOST='h', MASTER_USER='r', MASTER_PASSWORD='ZqPASSWD'",
        "CHANGE REPLICATION SOURCE TO SOURCE_PASSWORD = \"ZqPASSWD\"",
        "START REPLICA USER='r' PASSWORD='ZqPASSWD'",
        "CREATE USER u IDENTIFIED/**/BY'ZqPASSWD'",
        "create server s foreign data wrapper mysql options (password 'ZqPASSWD')",
        "CREATE USER 'u'@'%' IDENTIFIED BY 'ZqPASSWD",
        "select 1; CREATE USER u IDENTIFIED BY 'ZqPASSWD'",
    ] {
        let a = analyze(q, AnalyzeOptions::mysql());
        assert!(a.normalized().is_none(), "{q}");
        assert!(
            a.relations()
                .iter()
                .all(|r| !r.name.contains("ZqPASSWD") && r.schema.is_none()),
            "{q}"
        );
        for p in a.parts() {
            assert!(p.lead.iter().all(|w| !w.contains("zqpasswd")), "{q}");
        }
    }
}
