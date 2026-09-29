//! Property tests of the query normalizer (ADR-0007, ADR-0012 obligation
//! 5): no literal or comment content survives in the normalized text or in
//! the extracted relation names, for every literal form, dollar quoting
//! with arbitrary tags, nested comments, and truncated input (any prefix).

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

/// A literal, comment or quoted-identifier-free fragment hiding `m`.
fn hiding(m: String, d: String, tag: String) -> Vec<String> {
    vec![
        format!("'{m}'"),
        format!("'it''s {m}'"),
        format!("E'{m}\\' more'"),
        format!("e'\\\\{m}'"),
        format!("U&'{m}'"),
        format!("N'{m}'"),
        format!("B'{m}'"),
        format!("X'{m}'"),
        format!("${tag}${m} ' \" -- $x$ ${tag}$"),
        format!("$${m}$$"),
        format!("/* {m} */ 1"),
        format!("/* a /* {m} */ b */ 2"),
        format!("3 -- {m}\n"),
        d.clone(),
        format!("{d}.5e-3"),
        format!("0x{d}"),
        format!("DATE '{m}'"),
        format!("interval '{m}'"),
        // Plain literals with backslashes: read differently when
        // standard_conforming_strings is off.
        format!("'x\\' from {m}_t where \\'"),
        format!("'{m}\\'"),
        format!("'a\\' , {m} , '"),
    ]
}

fn statement() -> impl Strategy<Value = (String, String, String)> {
    (
        marker(),
        digits(),
        "[a-z_][a-z0-9_]{0,5}",
        prop::collection::vec(0usize..21, 1..6),
        prop::sample::select(vec![
            "select a, {} from crm.t where b = {}",
            "select * from t where c in ({}, {})",
            "insert into t (a, b) values ({}, {})",
            "update t set a = {} where b = {}",
            "delete from t where a = {} or b = {}",
            "with x as (select {} as v) select * from x where v = {}",
            "copy (select {} from t where a = {}) to stdout",
            "alter role r password {} valid until {}",
            "select {}; select {}",
            "select {}; alter system set x = {}",
            "do $zq$ begin perform a, {} from crm.t where b = {}; end $zq$",
            "do $zq$ begin perform {}, {} from crm.t; end $zq$",
            "select {}; copy (select {} from t) to program 'x'",
        ]),
    )
        .prop_map(|(m, d, tag, picks, template)| {
            let pieces = hiding(m.clone(), d.clone(), tag);
            let mut out = template.to_owned();
            let mut k = 0;
            while let Some(pos) = out.find("{}") {
                let piece = &pieces[picks[k % picks.len()]];
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
    let a = analyze(text, AnalyzeOptions::new().truncated(truncated));
    if let Some(n) = a.normalized() {
        prop_assert!(
            !leaks(n.as_str(), m, d),
            "normalized {:?} of {:?}",
            n.as_str(),
            text
        );
        prop_assert!(n.as_str().chars().count() <= MAX_NORMALIZED_CHARS);
    }
    for r in a.relations() {
        prop_assert!(!leaks(&r.name, m, d), "relation from {text:?}");
        if let Some(s) = &r.schema {
            prop_assert!(!leaks(s, m, d), "schema from {text:?}");
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn no_literal_survives((text, m, d) in statement()) {
        check(&text, &m, &d, false)?;
    }

    /// Input cut anywhere (a literal cut before its closing quote, a
    /// comment cut before its end), whether or not the caller knows it was
    /// cut.
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
        let a = analyze(&text, AnalyzeOptions::new());
        if let Some(n) = a.normalized() {
            prop_assert!(n.as_str().chars().count() <= MAX_NORMALIZED_CHARS);
        }
        prop_assert!(a.relations().len() <= 16);
    }

    /// Utility statements never keep text, whatever follows.
    #[test]
    fn utility_statements_keep_no_text(
        head in prop::sample::select(vec![
            "alter", "create", "drop", "set", "reset", "copy", "do", "comment", "security",
            "prepare", "execute", "import", "grant", "revoke", "explain", "vacuum", "call",
        ]),
        tail in "[a-z '()=,;$0-9]{0,80}",
    ) {
        let a = analyze(&format!("{head} {tail}"), AnalyzeOptions::new());
        prop_assert!(a.normalized().is_none());
    }
}

#[test]
fn every_dollar_tag_form_is_replaced() {
    for tag in ["", "a", "tag_1", "é", "x$"] {
        let text = format!("select ${tag}$ ZqSECRET $$ ${tag}$ from t");
        let a = analyze(&text, AnalyzeOptions::new());
        if let Some(n) = a.normalized() {
            assert!(!n.as_str().contains("ZqSECRET"), "{tag}: {}", n.as_str());
        }
    }
}
