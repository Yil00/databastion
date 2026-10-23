//! The measurement of ADR-0057 decision 2 item 4: the `IdentifierProduced`
//! rules over the names of the dev ground truth, the dev seeds and init
//! scripts (which the engine matrix and the end-to-end runs load), the
//! tables the connectors' integration tests create, the CAS fixtures and
//! the `load` seed, per source and per rule, on the raw names (inputs) and
//! on the names the normalizer emits (outputs). Counts only, never a name
//! (I2). Run with `--nocapture` to see the table.
//!
//! The rules come from `shared/protocol/identifier-produced.schema.json`
//! (compiled with `regress`), and this file uses only the normalizers'
//! entry points, so it also runs against a `names.rs` from before ADR-0057:
//! the first commit of this lot's PR measured the normalizer of `dev` at
//! `03d3956` that way. To reproduce:
//!
//! ```sh
//! git checkout 03d3956 -- agent/crates/classifiers/src/names.rs
//! DATABASTION_MEASURE_OUT=/tmp/before.tsv cargo test -p databastion-classifiers \
//!   --test identifier_produced_measure -- --nocapture
//! git checkout HEAD -- agent/crates/classifiers/src/names.rs
//! DATABASTION_MEASURE_OUT=/tmp/after.tsv cargo test -p databastion-classifiers \
//!   --test identifier_produced_measure -- --nocapture
//! diff /tmp/before.tsv /tmp/after.tsv | grep -c '^>'   # names whose output changed
//! ```
//!
//! `DATABASTION_MEASURE_OUT` writes one line per name: its source, its
//! index and a SHA-256 prefix of the emitted name (never the name).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The measurement table is the purpose of this test; it carries counts only.
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::LazyLock;

use databastion_classifiers::names::{
    NormalizedName, PathPart, normalize_field_path, normalize_ldap_attribute, normalize_ldap_dn,
    normalize_path,
};
use sha2::{Digest, Sha256};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read(rel: &str) -> String {
    let path = repo().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// (rule id, compiled pattern) of the schema file's `not.anyOf`.
static RULES: LazyLock<Vec<(String, regress::Regex)>> = LazyLock::new(|| {
    let schema: serde_json::Value =
        serde_json::from_str(&read("shared/protocol/identifier-produced.schema.json")).unwrap();
    schema["not"]["anyOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let id = r["title"].as_str().unwrap().strip_prefix("rule ").unwrap();
            let re = regress::Regex::with_flags(r["pattern"].as_str().unwrap(), "u").unwrap();
            (id.to_owned(), re)
        })
        .collect()
});

fn violations(s: &str) -> Vec<String> {
    RULES
        .iter()
        .filter(|(_, re)| re.find(s).is_some())
        .map(|(id, _)| id.clone())
        .collect()
}

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
    /// The name as the normalizer reads it: a field path's keys joined
    /// with `.` (an array level as `#`, as the normalizer blanks it).
    fn input(&self) -> String {
        match self {
            Self::Path(s) | Self::Dn(s) | Self::Attribute(s) => s.clone(),
            Self::Field(parts) => parts
                .iter()
                .map(|p| p.as_deref().unwrap_or("#"))
                .collect::<Vec<_>>()
                .join("."),
        }
    }

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

fn sha_prefix(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .take(8)
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Per source: the names, those kept (not `*`), the raw names a rule
/// refuses (by rule), and the emitted names a rule refuses (none since the
/// normalizer applies the rules; also none before it did). Counts only.
#[test]
fn measurement_over_the_dev_corpus() {
    let corpus = corpus();
    let mut dump = String::new();
    let (mut total, mut kept, mut in_refused, mut out_refused) = (0usize, 0, 0, 0);
    let mut in_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut out_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    eprintln!("ADR-0057 measurement (distinct raw names per source; counts only)");
    for (source, raws) in &corpus {
        let (mut s_kept, mut s_in, mut s_out) = (0usize, 0usize, 0usize);
        for (i, raw) in raws.iter().enumerate() {
            let input = violations(&raw.input());
            if !input.is_empty() {
                s_in += 1;
                for r in input {
                    *in_by_rule.entry(r).or_default() += 1;
                }
            }
            let out = raw.normalize();
            let out = out.as_str();
            let _ = writeln!(dump, "{source}\t{i}\t{}", sha_prefix(out));
            if out == "*" {
                continue;
            }
            s_kept += 1;
            let v = violations(out);
            if !v.is_empty() {
                s_out += 1;
                for r in v {
                    *out_by_rule.entry(r).or_default() += 1;
                }
            }
        }
        eprintln!(
            "  {source}: {} names, {s_kept} kept (not `*`), {s_in} refused on input, {s_out} kept and refused on output",
            raws.len()
        );
        total += raws.len();
        kept += s_kept;
        in_refused += s_in;
        out_refused += s_out;
    }
    eprintln!(
        "  total: {total} names, {kept} kept, {in_refused} refused on input, {out_refused} kept and refused on output"
    );
    eprintln!("  input, by rule: {in_by_rule:?}");
    eprintln!("  output, by rule: {out_by_rule:?}");
    if let Ok(path) = std::env::var("DATABASTION_MEASURE_OUT") {
        std::fs::write(path, dump).unwrap();
    }
    assert!(total > 1000, "the corpus is too small: {total}");
    assert_eq!(
        out_refused, 0,
        "kept names refused by the rules: {out_by_rule:?}"
    );
}
