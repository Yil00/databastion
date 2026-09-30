//! Column-level recall / precision against the dev ground truth, offline.
//!
//! Reads the committed seed outputs (`dev/seed/out/*.sql`, `mongo.json`,
//! `openldap.ldif`), groups the values per location (engine, database,
//! container, object, field) as a connector would see them, runs the column
//! classifier on each location and compares the reported classifiers with
//! `dev/ground-truth.json`. A location not listed in the ground truth is
//! expected to produce no finding.
//!
//! Exclusions (reported as ground-truth gaps, not as errors):
//! - LDAP `userpassword`: not readable by the agent's service DN;
//! - LDAP attributes other than `mail` under the team container
//!   `ou=<person name>,ou=teams,…`: the ground truth only labels `mail` there
//!   although `cn`, `sn`, `telephonenumber`… hold the same kind of data as
//!   under `ou=people`.
//!
//! Phase 2 exit criterion: recall ≥ 90 % and precision ≥ 85 % per
//! classifier. Run with `--nocapture` to see the per-classifier table
//! (counts only, never a value).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The metrics table is the purpose of this test; it carries counts only.
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use databastion_classifiers::column::classify_column;
use databastion_classifiers::masking::{ClassifierId, RawSample};
use databastion_classifiers::names::{normalize_ldap_dn, normalize_path};

type Key = (String, String, Option<String>, String, String);

fn dev_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../dev")
}

fn read(rel: &str) -> String {
    let path = dev_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------- SQL seed

/// Parses one SQL literal at `s[i..]`; returns (value, next index).
fn sql_literal(s: &[char], mut i: usize, backslash: bool) -> (Option<String>, usize) {
    if s[i] == '\'' {
        let mut out = String::new();
        i += 1;
        loop {
            match s[i] {
                '\'' if s.get(i + 1) == Some(&'\'') => {
                    out.push('\'');
                    i += 2;
                }
                '\'' => return (Some(out), i + 1),
                '\\' if backslash => {
                    out.push(s[i + 1]);
                    i += 2;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
    }
    let start = i;
    while !matches!(s[i], ',' | ')') {
        i += 1;
    }
    let raw: String = s[start..i].iter().collect::<String>().trim().to_owned();
    match raw.as_str() {
        "NULL" => (None, i),
        "TRUE" => (Some("true".to_owned()), i),
        "FALSE" => (Some("false".to_owned()), i),
        _ => (Some(raw), i),
    }
}

fn load_sql(
    file: &str,
    engine: &str,
    database: &str,
    backslash: bool,
    out: &mut BTreeMap<Key, Vec<String>>,
) {
    let text = read(file);
    for stmt in text.split("INSERT INTO ").skip(1) {
        let (table, rest) = if let Some(quoted) = stmt.strip_prefix('`') {
            let end = quoted.find('`').unwrap();
            (quoted[..end].to_owned(), &quoted[end + 1..])
        } else {
            let end = stmt.find(" (").unwrap();
            (stmt[..end].to_owned(), &stmt[end..])
        };
        let (container, object) = match (engine, table.split_once('.')) {
            ("postgresql", Some((schema, t))) => (Some(schema.to_owned()), t.to_owned()),
            _ => (None, table),
        };
        let open = rest.find('(').unwrap();
        let close = rest.find(") VALUES").unwrap();
        let columns: Vec<String> = rest[open + 1..close]
            .split(',')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        let chars: Vec<char> = rest[close + ") VALUES".len()..].chars().collect();
        let mut i = 0;
        loop {
            while i < chars.len() && chars[i].is_whitespace() || chars.get(i) == Some(&',') {
                i += 1;
            }
            if i >= chars.len() || chars[i] == ';' {
                break;
            }
            assert_eq!(chars[i], '(');
            i += 1;
            for col in &columns {
                while chars[i] == ' ' {
                    i += 1;
                }
                let (value, next) = sql_literal(&chars, i, backslash);
                i = next;
                if chars[i] == ',' {
                    i += 1;
                }
                let key = (
                    engine.to_owned(),
                    database.to_owned(),
                    container.clone(),
                    object.clone(),
                    col.clone(),
                );
                let entry = out.entry(key).or_default();
                if let Some(v) = value {
                    entry.push(v);
                }
            }
            assert_eq!(chars[i], ')');
            i += 1;
        }
    }
}

// ------------------------------------------------------------ MongoDB seed

fn dynamic_key(k: &str) -> bool {
    k.contains('@') || (!k.is_empty() && k.chars().all(|c| c.is_ascii_digit()))
}

fn walk(v: &serde_json::Value, path: &str, out: &mut BTreeMap<String, Vec<String>>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                let seg = if dynamic_key(k) { "*" } else { k.as_str() };
                let p = if path.is_empty() {
                    seg.to_owned()
                } else {
                    format!("{path}.{seg}")
                };
                walk(child, &p, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk(item, &format!("{path}[]"), out);
            }
        }
        serde_json::Value::Null => {
            out.entry(path.to_owned()).or_default();
        }
        serde_json::Value::String(s) => out.entry(path.to_owned()).or_default().push(s.clone()),
        other => out
            .entry(path.to_owned())
            .or_default()
            .push(other.to_string()),
    }
}

fn load_mongo(out: &mut BTreeMap<Key, Vec<String>>) {
    let doc: serde_json::Value = serde_json::from_str(&read("seed/out/mongo.json")).unwrap();
    let collections = doc["collections"].as_object().unwrap();
    for (name, docs) in collections {
        let mut fields = BTreeMap::new();
        for d in docs.as_array().unwrap() {
            walk(d, "", &mut fields);
        }
        for (field, values) in fields {
            let key = (
                "mongodb".to_owned(),
                "app".to_owned(),
                None,
                name.clone(),
                field,
            );
            out.entry(key).or_default().extend(values);
        }
    }
}

// ------------------------------------------------------------ OpenLDAP seed

fn base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
        }
    }
    out
}

const LDAP_SUFFIX: &str = "dc=example,dc=org";
const TEAM_CONTAINER: &str = "ou=Oliver O'Connor,ou=teams,dc=example,dc=org";

fn load_ldap(out: &mut BTreeMap<Key, Vec<String>>) {
    let text = read("seed/out/openldap.ldif");
    for entry in text.split("\n\n") {
        let mut attrs: Vec<(String, String)> = Vec::new();
        for line in entry.lines().filter(|l| !l.starts_with('#')) {
            if let Some((name, value)) = line.split_once(":: ") {
                let decoded = String::from_utf8(base64_decode(value)).unwrap();
                attrs.push((name.to_owned(), decoded));
            } else if let Some((name, value)) = line.split_once(": ") {
                attrs.push((name.to_owned(), value.to_owned()));
            }
        }
        let Some(dn) = attrs
            .iter()
            .find(|(n, _)| n == "dn")
            .map(|(_, v)| v.clone())
        else {
            continue;
        };
        let container = dn
            .split_once(',')
            .map_or(String::new(), |(_, c)| c.to_owned());
        let class = attrs
            .iter()
            .filter(|(n, _)| n == "objectClass")
            .map(|(_, v)| v.clone())
            .next_back()
            .unwrap_or_default();
        for (name, value) in attrs {
            if name == "dn" {
                continue;
            }
            let key = (
                "openldap".to_owned(),
                LDAP_SUFFIX.to_owned(),
                Some(container.clone()),
                class.clone(),
                name.to_ascii_lowercase(),
            );
            out.entry(key).or_default().push(value);
        }
    }
}

// ------------------------------------------------------------ Ground truth

struct Truth {
    expected: BTreeMap<Key, BTreeSet<String>>,
}

fn load_truth() -> Truth {
    let doc: serde_json::Value = serde_json::from_str(&read("ground-truth.json")).unwrap();
    let mut expected = BTreeMap::new();
    for loc in doc["locations"].as_array().unwrap() {
        let s = |k: &str| loc[k].as_str().map(str::to_owned);
        let field = s("field").unwrap();
        // Mongo dynamic keys: `contacts.<email>.phone` is seen as `contacts.*.phone`.
        let field = if field.contains('<') {
            s("expected_normalized_name").unwrap()
        } else {
            field
        };
        let key = (
            s("engine").unwrap(),
            s("database").unwrap(),
            s("container"),
            s("object").unwrap(),
            field,
        );
        let ids: BTreeSet<String> = loc["expected_classifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        expected.insert(key, ids);
    }
    Truth { expected }
}

fn excluded(key: &Key) -> bool {
    key.0 == "openldap"
        && (key.4 == "userpassword"
            || (key.2.as_deref() == Some(TEAM_CONTAINER) && key.4 != "mail"))
}

/// A location for the report, with normalized names (seed names can embed
/// values: `export_client_<phone>`, `escalations_<email>`).
fn shown(key: &Key) -> String {
    let container = key.2.as_deref().map_or_else(String::new, |c| {
        if key.0 == "openldap" {
            normalize_ldap_dn(c).as_str().to_owned()
        } else {
            normalize_path(c).as_str().to_owned()
        }
    });
    format!(
        "{}/{}/{}/{}/{}",
        key.0,
        key.1,
        container,
        normalize_path(&key.3).as_str(),
        normalize_path(&key.4).as_str()
    )
}

#[derive(Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
}

#[test]
fn every_ground_truth_id_is_a_frozen_classifier_id() {
    let truth = load_truth();
    for ids in truth.expected.values() {
        for id in ids {
            assert!(ClassifierId::parse(id).is_some(), "unknown id {id}");
        }
    }
}

fn load_columns() -> BTreeMap<Key, Vec<String>> {
    let mut columns: BTreeMap<Key, Vec<String>> = BTreeMap::new();
    load_sql(
        "seed/out/postgres.sql",
        "postgresql",
        "shop",
        false,
        &mut columns,
    );
    load_sql("seed/out/mysql.sql", "mysql", "hr", true, &mut columns);
    load_sql(
        "seed/out/mariadb.sql",
        "mariadb",
        "support",
        true,
        &mut columns,
    );
    load_mongo(&mut columns);
    load_ldap(&mut columns);
    columns
}

/// Evaluates every seed location, the column name given by `name`.
/// Returns the per-classifier counts and the error lines (locations only).
fn evaluate(
    truth: &Truth,
    columns: &BTreeMap<Key, Vec<String>>,
    name: &dyn Fn(usize, &Key) -> String,
) -> (BTreeMap<ClassifierId, Counts>, Vec<String>, usize) {
    let mut counts: BTreeMap<ClassifierId, Counts> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut evaluated = 0;
    for (i, (key, values)) in columns.iter().enumerate() {
        if excluded(key) {
            continue;
        }
        evaluated += 1;
        let raws: Vec<RawSample<'_>> = values.iter().map(|v| RawSample::new(v)).collect();
        let got: BTreeSet<ClassifierId> = classify_column(&name(i, key), &raws)
            .iter()
            .map(|f| f.classifier())
            .collect();
        let want: BTreeSet<ClassifierId> = truth
            .expected
            .get(key)
            .map(|ids| ids.iter().filter_map(|i| ClassifierId::parse(i)).collect())
            .unwrap_or_default();
        for c in ClassifierId::ALL {
            let e = counts.entry(c).or_default();
            match (got.contains(&c), want.contains(&c)) {
                (true, true) => e.tp += 1,
                (true, false) => {
                    e.fp += 1;
                    errors.push(format!("FP {c} at {}", shown(key)));
                }
                (false, true) => {
                    e.fn_ += 1;
                    errors.push(format!("FN {c} at {}", shown(key)));
                }
                (false, false) => {}
            }
        }
    }
    (counts, errors, evaluated)
}

/// Prints the table; returns the classifiers below the exit criterion.
fn report(counts: &BTreeMap<ClassifierId, Counts>, errors: &[String]) -> Vec<&'static str> {
    eprintln!(
        "{:<22} {:>4} {:>4} {:>4} {:>8} {:>10}",
        "classifier", "TP", "FP", "FN", "recall", "precision"
    );
    let mut failed = Vec::new();
    let (mut tp, mut fp, mut fn_) = (0, 0, 0);
    for (c, k) in counts {
        let recall = f64::from(k.tp) / f64::from((k.tp + k.fn_).max(1));
        let precision = f64::from(k.tp) / f64::from((k.tp + k.fp).max(1));
        eprintln!(
            "{:<22} {:>4} {:>4} {:>4} {:>7.1}% {:>9.1}%",
            c.as_str(),
            k.tp,
            k.fp,
            k.fn_,
            recall * 100.0,
            precision * 100.0
        );
        if recall < 0.90 || precision < 0.85 {
            failed.push(c.as_str());
        }
        tp += k.tp;
        fp += k.fp;
        fn_ += k.fn_;
    }
    eprintln!(
        "{:<22} {tp:>4} {fp:>4} {fn_:>4} {:>7.1}% {:>9.1}%",
        "overall (micro)",
        f64::from(tp) / f64::from((tp + fn_).max(1)) * 100.0,
        f64::from(tp) / f64::from((tp + fp).max(1)) * 100.0
    );
    for e in errors {
        // Locations only (names are seed metadata), never values.
        eprintln!("{e}");
    }
    failed
}

#[test]
fn recall_and_precision_meet_the_phase_2_exit_criterion() {
    let truth = load_truth();
    let columns = load_columns();

    // Every labelled location must exist in the seed (catches parser drift).
    for key in truth.expected.keys() {
        assert!(
            columns.contains_key(key) || excluded(key),
            "ground-truth location missing from the seed: {}",
            shown(key)
        );
    }

    let (counts, errors, evaluated) = evaluate(&truth, &columns, &|_, key| key.4.clone());
    eprintln!("evaluated locations: {evaluated}");
    let failed = report(&counts, &errors);
    assert!(
        failed.is_empty(),
        "below the exit criterion: {failed:?}\n{}",
        errors.join("\n")
    );
}

/// The same seed values under opaque column names (`col_17`): values alone
/// must carry the decision (the names only lower thresholds).
#[test]
fn values_alone_meet_the_exit_criterion_under_opaque_names() {
    let truth = load_truth();
    let columns = load_columns();
    let (counts, errors, evaluated) = evaluate(&truth, &columns, &|i, _| format!("col_{i}"));
    eprintln!("evaluated locations (opaque names): {evaluated}");
    let failed = report(&counts, &errors);
    assert!(
        failed.is_empty(),
        "below the exit criterion: {failed:?}\n{}",
        errors.join("\n")
    );
}
