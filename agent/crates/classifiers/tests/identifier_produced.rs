//! The contract `IdentifierProduced` (ADR-0057 decision 1,
//! `shared/protocol/identifier-produced.schema.json`) against the agent:
//!
//! - the schema file holds the agent's rule patterns verbatim and refines
//!   the `Identifier` of `openapi.yaml`;
//! - the agent's check ([`names::is_identifier_produced`], the `regex`
//!   crate) accepts exactly what the contract accepts (the generated
//!   `Identifier` type, its `not` rule and the producer rules compiled with
//!   `regress` in ECMAScript `u` mode, as the console's Ajv);
//! - the measurement of ADR-0057 decision 2 item 4: the rules run over the
//!   names of the dev ground truth, the dev seeds and init scripts (which
//!   the engine matrix and the end-to-end runs load), the CAS fixtures and
//!   the `load` seed's names, counted per rule. Counts only, never a name
//!   (I2). Run with `--nocapture` to see the table.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The measurement table is the purpose of one test; it carries counts only.
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::LazyLock;

use databastion_classifiers::names::{
    self, IDENTIFIER_PRODUCED_RULES, NormalizedName, PathPart, normalize_field_path,
    normalize_ldap_attribute, normalize_ldap_dn, normalize_path,
};
use databastion_protocol::Identifier;
use databastion_protocol_codegen::{default_openapi_path, json_schema_from_openapi};
use proptest::prelude::*;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read(rel: &str) -> String {
    let path = repo().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn schema() -> serde_json::Value {
    serde_json::from_str(&read("shared/protocol/identifier-produced.schema.json")).unwrap()
}

/// (rule id, pattern) of the schema file's `not.anyOf`, the id from its
/// `title` (`rule <id>`).
fn schema_rules() -> Vec<(String, String)> {
    schema()["not"]["anyOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let title = r["title"].as_str().unwrap();
            (
                title.strip_prefix("rule ").unwrap().to_owned(),
                r["pattern"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

struct Contract {
    identifier_not: regress::Regex,
    rules: Vec<(String, regress::Regex)>,
}

static CONTRACT: LazyLock<Contract> = LazyLock::new(|| {
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    let doc = json_schema_from_openapi(&yaml).unwrap();
    let not = doc["$defs"]["Identifier"]["not"]["pattern"]
        .as_str()
        .unwrap();
    Contract {
        identifier_not: regress::Regex::with_flags(not, "u").unwrap(),
        rules: schema_rules()
            .into_iter()
            .map(|(id, p)| (id, regress::Regex::with_flags(&p, "u").unwrap()))
            .collect(),
    }
});

/// What the contract accepts: the generated `Identifier` type, its `not`
/// rule, then every producer rule (`regress`).
fn contract_accepts(s: &str) -> bool {
    let c = &*CONTRACT;
    Identifier::try_from(s).is_ok()
        && c.identifier_not.find(s).is_none()
        && c.rules.iter().all(|(_, re)| re.find(s).is_none())
}

/// The contract's rule ids `s` violates (`regress`).
fn contract_violations(s: &str) -> Vec<String> {
    CONTRACT
        .rules
        .iter()
        .filter(|(_, re)| re.find(s).is_some())
        .map(|(id, _)| id.clone())
        .collect()
}

#[test]
fn schema_file_holds_the_agent_rules_and_refines_identifier() {
    let s = schema();
    assert_eq!(s["title"], "IdentifierProduced");
    assert_eq!(s["type"], "string");
    assert_eq!(s["allOf"][0]["$ref"], "schemas.json#/$defs/Identifier");
    assert_eq!(s["allOf"].as_array().unwrap().len(), 1);
    let want: Vec<(String, String)> = IDENTIFIER_PRODUCED_RULES
        .iter()
        .map(|(id, p)| ((*id).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(schema_rules(), want);
    // The file is not part of openapi.yaml: nothing the generators read.
    let yaml = std::fs::read_to_string(default_openapi_path()).unwrap();
    assert!(!yaml.contains("IdentifierProduced"));
}

/// The ADR's examples, refused (with the rule) or kept.
#[test]
fn the_adr_examples() {
    for (s, rule) in [
        ("06.12.34.56.78", "2"),
        ("06_12_34_56_78", "2"),
        ("tel_06_12_34_56_78", "2"),
        ("1_2_3_4_5", "2"),
        ("v1-2-3-4-5", "2"),
        ("a1-2.3-4.5b", "2"),
        ("06\u{a0}12\u{a0}34\u{a0}56\u{a0}78", "2"),
        ("06\u{2010}12\u{2010}34\u{2010}56\u{2010}78", "2"),
        ("06\u{ff0e}12\u{ff0e}34\u{ff0e}56\u{ff0e}78", "2"),
        ("_________", "1"),
        ("a.1_2_3_4_5.b", "1"),
        ("ou=123456789,dc=x", "1"),
        ("host.10.0.0.1", "3-ipv4"),
        ("10.0.0.1", "3-ipv4"),
        ("ou=10.0.0.1,dc=x", "3-ipv4"),
        ("00-1a-2b-3c-4d-5e", "3-mac-dashed"),
        ("device_00-1a-2b-3c-4d-5e", "3-mac-dashed"),
        ("001a.2b3c.4d5e", "3-mac-dotted"),
        ("device.001a.2b3c.4d5e.port", "3-mac-dotted"),
        ("ou=001a.2b3c.4d5e,dc=x", "3-mac-dotted"),
        ("%41", "4"),
        ("x.name%u00e9", "4"),
        ("%u0041", "4"),
        ("a%U00E9", "4"),
        ("a1234567", "5-run"),
        (
            "a\u{0663}\u{0664}\u{0665}\u{0666}\u{0667}\u{0668}\u{0669}",
            "5-run",
        ),
        ("a12.b34.c56.d78.e9", "5-total"),
        ("ou=1234,dc=56789", "5-total"),
        (
            "x\u{2165}\u{2166}\u{2167}\u{2168}\u{2169}\u{216a}\u{216b}",
            "5-run",
        ),
    ] {
        let got = names::produced_violations(s);
        assert!(got.contains(&rule), "{s:?}: {got:?}");
        assert!(contract_violations(s).iter().any(|r| r == rule), "{s:?}");
        assert!(!names::is_identifier_produced(s), "{s:?}");
        assert!(!contract_accepts(s), "{s:?}");
    }
    for s in [
        "face.cafe.beef",
        "dead.beef.cafe",
        "orders",
        "orders[].email",
        "*",
        "*.phone",
        "v2.users",
        "events_2024_09",
        "orders_2024",
        "first_name",
        "1.2",
        "a.1.2.3",
        "matrix[][]",
        "ou=people,dc=example,dc=org",
        "第一名",
        "sales.一月",
        "%zz",
        "%u00",
        "a-b-c-d-e-f",
        "ab-cd",
        "v1.2.3",
        "abcd.ef01",
    ] {
        assert!(
            names::produced_violations(s).is_empty(),
            "{s:?}: {:?}",
            names::produced_violations(s)
        );
        assert!(names::is_identifier_produced(s), "{s:?}");
        assert!(contract_accepts(s), "{s:?}");
    }
}

/// The agent's rule ids are the contract's on every input of the alphabet
/// (rule by rule), and its check accepts exactly what the contract accepts.
fn alphabet() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "a", "b", "f", "E", "z", "0", "1", "9", "42", "001a", "2b3c", "face", ".", ".", "-", "_",
        "+", " ", "%", "%4", "%u", "u", "*", "[]", "ou=", "dc=", ",", "@", "\u{ff10}", "\u{ff0e}",
        "\u{a0}", "\u{2010}", "\u{200b}", "\u{663}", "\u{2165}", "\u{3007}", "一", "é",
    ]);
    prop::collection::vec(pieces, 0..24).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn agent_check_is_the_contract(s in alphabet()) {
        let agent: Vec<String> = names::produced_violations(&s)
            .into_iter()
            .filter(|r| *r != names::UNASSIGNED_RULE)
            .map(str::to_owned)
            .collect();
        prop_assert_eq!(agent, contract_violations(&s), "{:?}", s);
        prop_assert_eq!(names::is_identifier_produced(&s), contract_accepts(&s), "{:?}", s);
    }
}

// ------------------------------------------------------------ Measurement

/// Which normalizer a raw name goes through, as the connectors use them.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Raw {
    /// `normalize_path`: databases, schemas, tables, columns, collections.
    Path(String),
    /// `normalize_field_path`: MongoDB field paths with their real keys
    /// (`None` is an array level).
    Field(Vec<Option<String>>),
    /// `normalize_ldap_dn`: suffixes and entry DNs (reduced to containers).
    Dn(String),
    /// `normalize_ldap_attribute`.
    Attribute(String),
}

impl Raw {
    fn normalize(&self) -> NormalizedName {
        match self {
            Self::Path(s) => normalize_path(s),
            Self::Dn(s) => normalize_ldap_dn(s),
            Self::Attribute(s) => normalize_ldap_attribute(s),
            Self::Field(parts) => {
                let parts: Vec<PathPart<'_>> = parts
                    .iter()
                    .map(|p| p.as_deref().map_or(PathPart::Index, PathPart::Key))
                    .collect();
                normalize_field_path(&parts)
            }
        }
    }
}

type Corpus = BTreeMap<&'static str, BTreeSet<Raw>>;

fn add_path(c: &mut Corpus, source: &'static str, name: &str) {
    let name = name
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '`' | '\'' | '[' | ']'));
    if !name.is_empty() && !name.contains(['{', '}', '\\']) {
        c.entry(source)
            .or_default()
            .insert(Raw::Path(name.to_owned()));
    }
}

/// A possibly qualified SQL name (`schema.table`, `[db].[dbo].[t]`), each
/// part on its own, as the connectors read them from the catalogs.
fn add_qualified(c: &mut Corpus, source: &'static str, name: &str) {
    for part in name.split('.') {
        add_path(c, source, part);
    }
}

const SQL_KEYWORDS: [&str; 12] = [
    "PRIMARY",
    "UNIQUE",
    "CONSTRAINT",
    "FOREIGN",
    "CHECK",
    "KEY",
    "INDEX",
    "PERIOD",
    "FULLTEXT",
    "SPATIAL",
    "LIKE",
    "EXCLUDE",
];

/// The body of the parenthesis opening at `open` (byte index of `(`).
fn paren_body(s: &str, open: usize) -> Option<&str> {
    let mut depth = 0usize;
    for (i, ch) in s[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Top-level comma-separated items of a parenthesized body.
fn top_level_items(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, ch) in body.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&body[start..]);
    out
}

/// Object and column names of the SQL statements in `text` (seeds, init
/// scripts): `CREATE TABLE / VIEW / SCHEMA / DATABASE` names, the columns
/// of `CREATE TABLE` bodies and of `INSERT INTO … (columns)` lists.
fn add_sql(c: &mut Corpus, source: &'static str, text: &str) {
    static CREATE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?(TABLE|VIEW|SCHEMA|DATABASE)\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(;]+)"#,
        )
        .unwrap()
    });
    static INSERT: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"(?i)\bINSERT\s+INTO\s+([^\s(;]+)\s*\("#).unwrap());
    for m in CREATE.captures_iter(text) {
        let kind = m[1].to_ascii_uppercase();
        add_qualified(c, source, &m[2]);
        if kind != "TABLE" {
            continue;
        }
        let end = m.get(0).unwrap().end();
        let rest = &text[end..];
        let Some(open) = rest.find(|ch: char| !ch.is_whitespace()) else {
            continue;
        };
        if !rest[open..].starts_with('(') {
            continue;
        }
        if let Some(body) = paren_body(rest, open) {
            for item in top_level_items(body) {
                let first = item.split_whitespace().next().unwrap_or("");
                if !SQL_KEYWORDS.contains(&first.to_ascii_uppercase().as_str()) {
                    add_path(c, source, first);
                }
            }
        }
    }
    for m in INSERT.captures_iter(text) {
        add_qualified(c, source, &m[1]);
        let open = m.get(0).unwrap().end() - 1;
        if let Some(body) = paren_body(text, open) {
            for item in top_level_items(body) {
                let col = item.trim();
                // A column list, not a VALUES tuple.
                if !col.is_empty()
                    && col.chars().all(|ch| {
                        ch.is_alphanumeric() || matches!(ch, '_' | '"' | '`' | '[' | ']' | '$')
                    })
                {
                    add_path(c, source, col);
                }
            }
        }
    }
}

fn files(dir: &str, exts: &[&str]) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(repo().join(dir)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.contains(&e))
        })
        .map(|p| {
            p.strip_prefix(repo())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    out.sort();
    out
}

fn walk_mongo(v: &serde_json::Value, path: &mut Vec<Option<String>>, out: &mut BTreeSet<Raw>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                path.push(Some(k.clone()));
                out.insert(Raw::Field(path.clone()));
                walk_mongo(child, path, out);
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            path.push(None);
            for item in items {
                walk_mongo(item, path, out);
            }
            path.pop();
        }
        _ => {}
    }
}

fn json_keys(v: &serde_json::Value, c: &mut Corpus, source: &'static str) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                add_path(c, source, k);
                json_keys(child, c, source);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| json_keys(i, c, source)),
        _ => {}
    }
}

/// The `load` seed's names (`e2e/load/seed.py`: `PG_SCHEMAS`, `Table.pg_name`,
/// `mariadb_name`, `mongo_name`, `mssql_name`, `columns`, up to
/// `MAX_TABLES` = 999 tables).
fn add_load(c: &mut Corpus) {
    const SOURCE: &str = "load seed";
    for s in [
        "load_a",
        "load_b",
        "load_c",
        "load_d",
        "support",
        "app",
        "retail",
        "load",
        "shop",
        "id",
        "created_at",
        "status",
        "note",
        "email",
        "phone",
        "iban",
        "amount",
        "quantity",
    ] {
        add_path(c, SOURCE, s);
    }
    for i in 1..=999 {
        add_path(c, SOURCE, &format!("t{i:03}"));
        add_path(c, SOURCE, &format!("load_t{i:03}"));
        add_path(c, SOURCE, &format!("load_c{i:03}"));
    }
}

fn corpus() -> Corpus {
    let mut c = Corpus::new();
    // Ground truth: every location's names and the targets' databases.
    let gt: serde_json::Value = serde_json::from_str(&read("dev/ground-truth.json")).unwrap();
    for loc in gt["locations"].as_array().unwrap() {
        let s = |k: &str| loc[k].as_str().map(str::to_owned);
        let engine = s("engine").unwrap_or_default();
        let ldap = engine == "openldap";
        let keys = engine == "redis" || engine == "valkey";
        for (k, value) in [
            ("database", s("database")),
            ("container", s("container")),
            ("object", s("object")),
            ("field", s("field")),
            ("expected_normalized_name", s("expected_normalized_name")),
        ] {
            let Some(v) = value else { continue };
            // Placeholders of dynamic keys (`contacts.<email>.phone`), and
            // Redis / Valkey objects (key patterns, not `Identifier`s).
            if v.contains('<') || (keys && k == "object") {
                continue;
            }
            let raw = match (ldap, k) {
                (true, "database" | "container") => Raw::Dn(v),
                (true, "field") => Raw::Attribute(v),
                _ => Raw::Path(v),
            };
            c.entry("ground truth").or_default().insert(raw);
        }
    }
    for (engine, t) in gt["targets"].as_object().unwrap() {
        for db in t["databases"].as_array().unwrap() {
            let db = db.as_str().unwrap().to_owned();
            c.entry("ground truth")
                .or_default()
                .insert(if engine == "openldap" {
                    Raw::Dn(db)
                } else {
                    Raw::Path(db)
                });
        }
    }
    // Dev seeds (dev, e2e and the engine matrix load them).
    for f in files("dev/seed/out", &["sql"]) {
        add_sql(&mut c, "dev seeds", &read(&f));
    }
    let mongo: serde_json::Value = serde_json::from_str(&read("dev/seed/out/mongo.json")).unwrap();
    for (name, docs) in mongo["collections"].as_object().unwrap() {
        add_path(&mut c, "dev seeds", name);
        let mut fields = BTreeSet::new();
        for d in docs.as_array().unwrap() {
            walk_mongo(d, &mut Vec::new(), &mut fields);
        }
        c.entry("dev seeds").or_default().extend(fields);
    }
    for entry in read("dev/seed/out/openldap.ldif").split("\n\n") {
        for line in entry.lines().filter(|l| !l.starts_with('#')) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim_start_matches(':').trim();
            match name {
                "dn" if !line.starts_with("dn::") => {
                    c.entry("dev seeds")
                        .or_default()
                        .insert(Raw::Dn(value.to_owned()));
                }
                "objectClass" => add_path(&mut c, "dev seeds", value),
                _ => {
                    c.entry("dev seeds")
                        .or_default()
                        .insert(Raw::Attribute(name.to_owned()));
                }
            }
        }
    }
    // Init scripts of the dev services, the end-to-end and load targets
    // (the engine matrix runs the connectors' integration tests on the dev
    // services).
    for dir in [
        "dev/postgres/initdb",
        "dev/mysql/initdb",
        "dev/mariadb/initdb",
        "dev/percona/initdb",
        "dev/sqlserver/initdb",
        "dev/cas",
        "e2e/target-initdb",
        "e2e/load/initdb",
    ] {
        for f in files(dir, &["sql", "sh", "js"]) {
            add_sql(&mut c, "init scripts", &read(&f));
        }
    }
    // The tables the connectors' integration tests create (the engine
    // matrix runs them on every listed version); format placeholders
    // (`{table}`) left out.
    for dir in [
        "agent/crates/connector-postgres/src",
        "agent/crates/connector-mysql/src",
        "agent/crates/connector-sqlserver/src",
    ] {
        for f in files(dir, &["rs"]) {
            if f.rsplit('/').next().is_some_and(|n| n.starts_with("it")) {
                add_sql(&mut c, "connector integration tests", &read(&f));
            }
        }
    }
    // CAS service registries (keys become field names) and audit records.
    for dir in [
        "dev/cas/services",
        "agent/crates/connector-cas/fixtures/registry",
    ] {
        for f in files(dir, &["json"]) {
            let v: serde_json::Value = serde_json::from_str(&read(&f)).unwrap();
            json_keys(&v, &mut c, "cas fixtures");
        }
    }
    for line in read("agent/crates/connector-cas/fixtures/cas-8.0.2-oauth-oidc-audit.jsonl").lines()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            json_keys(&v, &mut c, "cas fixtures");
        }
    }
    add_load(&mut c);
    c
}

/// ADR-0057 decision 2 item 4: of the names the agent keeps (not `*`),
/// how many the rules refuse, per rule, and none of them after the change
/// (the agent masks them). Counts only (I2).
#[test]
fn measurement_over_the_dev_corpus() {
    let corpus = corpus();
    let mut total = 0usize;
    let mut kept = 0usize;
    let mut by_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut refused = 0usize;
    eprintln!("ADR-0057 measurement (distinct raw names per source; counts only)");
    for (source, raws) in &corpus {
        let mut s_kept = 0usize;
        let mut s_refused = 0usize;
        for raw in raws {
            let out = raw.normalize();
            let out = out.as_str();
            if out == "*" {
                continue;
            }
            s_kept += 1;
            let v = names::produced_violations(out);
            if !v.is_empty() {
                s_refused += 1;
                for r in v {
                    *by_rule.entry(r).or_default() += 1;
                }
            }
        }
        eprintln!(
            "  {source}: {} names, {s_kept} kept (not `*`), {s_refused} refused by the rules",
            raws.len()
        );
        total += raws.len();
        kept += s_kept;
        refused += s_refused;
    }
    eprintln!("  total: {total} names, {kept} kept, {refused} refused");
    for (r, n) in &by_rule {
        eprintln!("    rule {r}: {n}");
    }
    assert!(total > 1000, "the corpus is too small: {total}");
}
