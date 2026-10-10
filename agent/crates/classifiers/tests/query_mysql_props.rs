//! Property tests of the MySQL / MariaDB dialect of the query normalizer
//! (ADR-0007, ADR-0012 obligation 5 applied to MySQL by ADR-0018, ROADMAP
//! P4-D): no literal, comment or password content survives in the
//! normalized text, the extracted relation names or the leading words, for
//! every MySQL literal form, every comment form, backslash escapes read
//! under any `sql_mode`, double quotes read as strings or as `ANSI_QUOTES`
//! identifiers, password-bearing statements, and truncated input.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::query::{
    AnalyzeOptions, BuiltinFunctions, CallForm, MAX_NORMALIZED_CHARS, QueryAnalysis, analyze,
    analyze_raw,
};
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

/// A two-byte character whose trail byte is `\` (0x5c) or a backtick
/// (0x60), as gbk / gb18030 (lead 0x81..=0xfe) and sjis / cp932 (lead
/// 0x81..=0x9f or 0xe0..=0xfc) encode them.
fn multibyte_char() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![0x81u8..=0xfe, 0x81u8..=0x9f, 0xe0u8..=0xfc],
        prop::sample::select(vec![0x5cu8, 0x60]),
    )
        .prop_map(|(lead, trail)| vec![lead, trail])
}

fn raw_leaks(a: &QueryAnalysis, m: &str) -> bool {
    let m = m.to_ascii_lowercase();
    a.relations()
        .iter()
        .chain(a.parts().iter().flat_map(|p| p.relations.iter()))
        .any(|r| {
            r.name.to_ascii_lowercase().contains(&m)
                || r.schema
                    .as_deref()
                    .is_some_and(|s| s.to_ascii_lowercase().contains(&m))
        })
        || a.parts()
            .iter()
            .any(|p| p.lead.iter().any(|w| w.contains(&m)))
        || a.normalized()
            .is_some_and(|n| n.as_str().to_ascii_lowercase().contains(&m))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// gbk / sjis texts where a trail byte would close or escape a quote
    /// or a backtick for this lexer, but not for the server: the text after
    /// it (the server's literal, holding the marker as a would-be name)
    /// never becomes a name, whether analyzed from the raw bytes or from
    /// the same character re-encoded as UTF-8.
    #[test]
    fn multibyte_trail_bytes_never_expose_names(
        ch in multibyte_char(),
        m in marker(),
        template in prop::sample::select(vec![
            ("select '", "' , 1 from t where x = ' from payroll.", " '"),
            ("select `", "` from t where x = ` from payroll.", " `"),
            ("select \"", "\" , 1 from t where x = \" from payroll.", " \""),
            ("select * from t where a = '", "' or b = ' join ", " on 1 '"),
        ]),
    ) {
        let (head, mid, tail) = template;
        let mut raw = head.as_bytes().to_vec();
        raw.extend_from_slice(&ch);
        raw.extend_from_slice(mid.as_bytes());
        raw.extend_from_slice(m.as_bytes());
        raw.extend_from_slice(tail.as_bytes());
        let a = analyze_raw(&raw, AnalyzeOptions::mysql());
        prop_assert!(!raw_leaks(&a, &m), "{:?}", String::from_utf8_lossy(&raw));
        // The same with the lead byte as a UTF-8 character (a server
        // configured for utf8mb4 cannot hold it, but the text may be
        // re-encoded on its way): a byte >= 0x80 before 0x5c / 0x60.
        let mut utf8 = head.to_owned();
        utf8.push('\u{e9}');
        utf8.push(char::from(ch[1]));
        utf8.push_str(mid);
        utf8.push_str(&m);
        utf8.push_str(tail);
        let a = analyze(&utf8, AnalyzeOptions::mysql());
        prop_assert!(!raw_leaks(&a, &m), "{utf8:?}");
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

/// Every name is built in, in every form.
struct All;
impl BuiltinFunctions for All {
    fn is_builtin(&self, _: &[u8], _: CallForm) -> bool {
        true
    }
}
/// No name is built in.
struct NoName;
impl BuiltinFunctions for NoName {
    fn is_builtin(&self, _: &[u8], _: CallForm) -> bool {
        false
    }
}
static ALL: All = All;
static NO_NAME: NoName = NoName;

/// A statement with calls in many positions and quotings.
fn calls() -> impl Strategy<Value = String> {
    let call = prop::sample::select(vec![
        "f()",
        "f (1)",
        "`f`(a)",
        "\"f\"(1)",
        "now()",
        "count (*)",
        "hr.f()",
        "1f()",
        "f/**/()",
        "/*!50700 f*/()",
        "CAST(a AS DECIMAL(4, 2))",
        "JSON_TABLE('[]', '$' COLUMNS (a INT PATH '$'))",
    ]);
    (
        prop::collection::vec(call, 1..4),
        prop::sample::select(vec![
            "select {} from hr.t join hr.u on {} where a = {}",
            "insert into hr.t (a, b) values ({}, {}); select {}",
            "update hr.t set a = {} where b in (select {} from hr.u where c = {})",
            "delete from hr.t where a = {} or b = {} or c = {}",
            "set @x = {}, @y = {}; do {}",
            "call hr.p({}, {}, {})",
            "with x (a) as (select {} from hr.t) select {}, {} from x",
            "select * from {} , hr.t where {} = {}",
        ]),
    )
        .prop_map(|(picks, template)| {
            let mut out = template.to_owned();
            let mut k = 0;
            while let Some(pos) = out.find("{}") {
                out.replace_range(pos..pos + 2, picks[k % picks.len()]);
                k += 1;
            }
            out
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// ADR-0045 part (b): the unknown-call analysis never removes an
    /// object nor changes a kind (whatever the list says, the relations
    /// and the statement kinds are the same), and a smaller list only
    /// finds more unknown calls.
    #[test]
    fn unknown_calls_never_remove_an_object(text in calls(), truncated in any::<bool>()) {
        let base = AnalyzeOptions::mysql().truncated(truncated);
        let all = analyze(&text, base.builtins(&ALL));
        let none = analyze(&text, base.builtins(&NO_NAME));
        let plain = analyze(&text, base);
        for a in [&all, &none] {
            prop_assert_eq!(a.relations(), plain.relations(), "{}", text);
            prop_assert_eq!(a.kind(), plain.kind(), "{}", text);
            prop_assert_eq!(a.parts().len(), plain.parts().len(), "{}", text);
            for (p, q) in a.parts().iter().zip(plain.parts()) {
                prop_assert_eq!(&p.relations, &q.relations, "{}", text);
                prop_assert_eq!(p.kind, q.kind, "{}", text);
                prop_assert_eq!(p.routine_call, q.routine_call, "{}", text);
                prop_assert_eq!(p.dquoted_name, q.dquoted_name, "{}", text);
            }
        }
        prop_assert!(!all.unknown_call() || none.unknown_call(), "{}", text);
        // Without a list, every call is unknown, like with an empty one.
        prop_assert_eq!(plain.unknown_call(), none.unknown_call(), "{}", text);
    }

    /// Arbitrary text with an unknown-call list never panics.
    #[test]
    fn unknown_call_analysis_is_total(text in "[a-z '\"`#/*!M0-9\\\\;,()?@_.\n-]{0,200}") {
        let _ = analyze(&text, AnalyzeOptions::mysql().builtins(&NO_NAME));
        let _ = analyze(&text, AnalyzeOptions::mysql().builtins(&ALL).digest(true));
        let _ = analyze_raw(text.as_bytes(), AnalyzeOptions::mysql().builtins(&ALL));
    }
}

/// Every name is built in but `f`.
struct AllButF;
impl BuiltinFunctions for AllButF {
    fn is_builtin(&self, name: &[u8], _: CallForm) -> bool {
        !name.eq_ignore_ascii_case(b"f")
    }
}
static ALL_BUT_F: AllButF = AllButF;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Security review of #188, H1: an alias after a call (`f() AS x`, in
    /// any quoting, in any position) never clears the unknown call.
    #[test]
    fn an_alias_never_hides_an_unknown_call(
        call in prop::sample::select(vec!["f()", "f (1)", "`f`(a)", "\"f\"(1)", "F(1, 2)", "1f()"]),
        alias in prop::sample::select(vec![" AS x", " AS `x`", " AS \"x\"", " AS (x)", " as x", " AS x, 1"]),
        template in prop::sample::select(vec![
            "SELECT {}",
            "SELECT a, {} FROM hr.t",
            "SELECT CAST({} AS CHAR)",
            "INSERT INTO hr.t SELECT {}",
            "SET @x = (SELECT {})",
            "DO (SELECT {})",
            "CREATE TABLE x AS SELECT {} FROM hr.t",
            "WITH c AS (SELECT {}) SELECT * FROM c",
            "WITH c (a) AS (SELECT 1) SELECT {} FROM c",
            "SELECT * FROM hr.t WHERE a IN (SELECT {})",
        ]),
    ) {
        let opts = AnalyzeOptions::mysql().builtins(&ALL_BUT_F);
        let bare = template.replacen("{}", call, 1);
        let with = template.replacen("{}", &format!("{call}{alias}"), 1);
        prop_assert!(analyze(&bare, opts).unknown_call(), "{}", bare);
        prop_assert!(analyze(&with, opts).unknown_call(), "{}", with);
    }
}
