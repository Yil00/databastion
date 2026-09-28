//! Held-out classifier evaluation (ROADMAP P2-F, phase 2 exit criterion).
//!
//! Scores the column classifier on the independent holdout corpus
//! (`dev/holdout/`, see its `README.md`) and gates on the Wilson 95 % lower
//! bound: recall ≥ 0.90 and precision ≥ 0.85 for every classifier.
//!
//! `#[ignore]`d so that a plain `cargo test` stays offline and fast: the
//! corpus (about 8 MB) is not committed and must be generated first. Run it
//! explicitly (this is what CI does):
//!
//! ```sh
//! python3 dev/holdout/generate.py
//! cd agent && cargo test -p databastion-classifiers --test holdout -- --ignored --nocapture
//! ```
//!
//! When run, it never skips: a missing corpus is a failure. Paths default to
//! `dev/holdout/{corpus,labels}.json` and can be overridden with
//! `DATABASTION_HOLDOUT_CORPUS` / `DATABASTION_HOLDOUT_LABELS`.
//!
//! Scoring follows `dev/holdout/README.md` ("Scoring method") exactly: per
//! classifier, at column level, over the non-ambiguous columns; each column
//! is classified as a Discovery scan would (all classifiers, agent key set,
//! target phone region unset, first [`SAMPLE_ROWS`] values).
//!
//! Output: aggregates only. Misclassified columns are listed by id and tags,
//! never by value (holdout independence rule; no values in CI logs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The metrics table is the purpose of this test; it carries counts only.
#![allow(clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use databastion_classifiers::column::ColumnClassifier;
use databastion_classifiers::masking::{ClassifierId, HmacKey, RawSample};
use sha2::{Digest, Sha256};

/// Default `sample_rows` of a Discovery scan (console `SCAN_DEFAULTS`); the
/// agent examines at most this many values per column (`Job::classify`).
const SAMPLE_ROWS: usize = 200;
/// z for a two-sided 95 % interval.
const Z: f64 = 1.96;
/// Gate on the Wilson lower bound of recall.
const MIN_RECALL_LB: f64 = 0.90;
/// Gate on the Wilson lower bound of precision.
const MIN_PRECISION_LB: f64 = 0.85;
/// Minimum non-ambiguous positive columns per classifier
/// (`dev/holdout/README.md`, "Sample size"): below that the recall gate
/// tolerates no miss, and a shrunk corpus must not pass silently.
const MIN_POSITIVES: u32 = 62;

fn holdout_path(var: &str, file: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../dev/holdout")
                .join(file)
        },
        PathBuf::from,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

/// Wilson score interval lower bound (README formula, z = 1.96). `n = 0`
/// gives 0 (nothing observed: the gate fails).
fn wilson_lower(k: u32, n: u32) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let (k, n) = (f64::from(k), f64::from(n));
    let p = k / n;
    let z2 = Z * Z;
    (p + z2 / (2.0 * n) - Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / (1.0 + z2 / n)
}

fn ratio(k: u32, n: u32) -> f64 {
    if n == 0 {
        0.0
    } else {
        f64::from(k) / f64::from(n)
    }
}

#[derive(Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
    /// (kind, column id, tags) of each error. Never a value.
    errors: Vec<(&'static str, String, String)>,
}

struct Label {
    ambiguous: bool,
    expected: BTreeSet<ClassifierId>,
    tags: Vec<String>,
}

#[test]
fn wilson_lower_matches_the_readme_table() {
    // dev/holdout/README.md, "Sample size": LB at 100 % recall.
    for (n, lb) in [
        (30, 0.886),
        (35, 0.901),
        (50, 0.929),
        (62, 0.942),
        (78, 0.953),
    ] {
        assert!((wilson_lower(n, n) - lb).abs() < 0.0005, "n = {n}");
    }
    // Tolerated misses: 62 -> 1, 78 -> 2, 100 -> 4.
    for (n, misses) in [(62, 1), (78, 2), (100, 4)] {
        assert!(wilson_lower(n - misses, n) >= MIN_RECALL_LB, "n = {n}");
        assert!(wilson_lower(n - misses - 1, n) < MIN_RECALL_LB, "n = {n}");
    }
    // Precision: TP = 62 tolerates 4 FP, TP = 78 tolerates 6 FP.
    for (tp, fps) in [(62, 4), (78, 6)] {
        assert!(wilson_lower(tp, tp + fps) >= MIN_PRECISION_LB, "tp = {tp}");
        assert!(
            wilson_lower(tp, tp + fps + 1) < MIN_PRECISION_LB,
            "tp = {tp}"
        );
    }
    assert!(wilson_lower(0, 0) < MIN_PRECISION_LB);
}

#[test]
#[ignore = "needs the generated holdout corpus: python3 dev/holdout/generate.py, then --ignored"]
fn holdout_gate() {
    let corpus_path = holdout_path("DATABASTION_HOLDOUT_CORPUS", "corpus.json");
    let labels_path = holdout_path("DATABASTION_HOLDOUT_LABELS", "labels.json");
    let corpus_bytes = std::fs::read(&corpus_path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (generate it with `python3 dev/holdout/generate.py`)",
            corpus_path.display()
        )
    });
    let labels: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&labels_path).unwrap_or_else(|e| panic!("{}: {e}", labels_path.display())),
    )
    .unwrap();

    // The labels pin the exact corpus they were written for.
    let digest = hex(&Sha256::digest(&corpus_bytes));
    let pinned = labels["corpus_sha256"]
        .as_str()
        .expect("labels.json corpus_sha256");
    assert_eq!(
        digest, pinned,
        "corpus.json SHA-256 differs from labels.json corpus_sha256: regenerate with \
         `python3 dev/holdout/generate.py` (and never edit either file by hand)"
    );

    // The labelled classifier set is exactly the agent's.
    let listed: Vec<&str> = labels["classifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let ours: Vec<&str> = ClassifierId::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        listed, ours,
        "labels.json classifiers differ from ClassifierId::ALL"
    );

    let mut by_id: BTreeMap<String, Label> = BTreeMap::new();
    for loc in labels["locations"].as_array().unwrap() {
        let id = loc["id"].as_str().unwrap().to_owned();
        let expected = loc["expected_classifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let s = c.as_str().unwrap();
                ClassifierId::parse(s).unwrap_or_else(|| panic!("{id}: unknown classifier {s}"))
            })
            .collect();
        let tags = loc["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        let label = Label {
            ambiguous: loc["ambiguous"].as_bool().unwrap(),
            expected,
            tags,
        };
        assert!(
            by_id.insert(id.clone(), label).is_none(),
            "duplicate label id {id}"
        );
    }

    let corpus: serde_json::Value = serde_json::from_slice(&corpus_bytes).unwrap();
    drop(corpus_bytes);
    let key_bytes = [0x5a_u8; 32];
    let key = HmacKey::new(&key_bytes).unwrap();
    // As `Job::column_classifier` builds it for a scan without a classifier
    // filter and without `phone_region` in agent.yaml.
    let classifier = ColumnClassifier::new().with_key(&key);

    let mut counts: BTreeMap<ClassifierId, Counts> = ClassifierId::ALL
        .iter()
        .map(|&c| (c, Counts::default()))
        .collect();
    let mut seen = BTreeSet::new();
    let (mut scored, mut excluded) = (0_u32, 0_u32);
    for col in corpus["columns"].as_array().unwrap() {
        let id = col["id"].as_str().unwrap();
        let label = by_id
            .get(id)
            .unwrap_or_else(|| panic!("corpus column {id} has no label"));
        assert!(seen.insert(id.to_owned()), "duplicate corpus column {id}");
        if label.ambiguous {
            excluded += 1;
            continue;
        }
        scored += 1;
        let field = col["field"].as_str().unwrap();
        let values: Vec<&str> = col["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let raws: Vec<RawSample<'_>> = values
            .iter()
            .take(SAMPLE_ROWS)
            .map(|v| RawSample::new(v))
            .collect();
        let predicted: BTreeSet<ClassifierId> = classifier
            .classify(field, &raws)
            .iter()
            .map(|f| f.classifier())
            .collect();
        for c in ClassifierId::ALL {
            let e = counts.get_mut(&c).unwrap();
            let kind = match (predicted.contains(&c), label.expected.contains(&c)) {
                (true, true) => {
                    e.tp += 1;
                    continue;
                }
                (true, false) => {
                    e.fp += 1;
                    "FP"
                }
                (false, true) => {
                    e.fn_ += 1;
                    "FN"
                }
                (false, false) => continue,
            };
            e.errors.push((kind, id.to_owned(), label.tags.join(",")));
        }
    }
    let missing: Vec<&String> = by_id.keys().filter(|id| !seen.contains(*id)).collect();
    assert!(
        missing.is_empty(),
        "labels without a corpus column: {missing:?}"
    );

    eprintln!(
        "holdout: {scored} columns scored, {excluded} ambiguous excluded, sample_rows {SAMPLE_ROWS}"
    );
    eprintln!(
        "{:<22} {:>4} {:>4} {:>4} {:>7} {:>7} {:>9} {:>7}  result",
        "classifier", "TP", "FP", "FN", "recall", "rec_LB", "precision", "prec_LB"
    );
    let mut failed = Vec::new();
    for (c, e) in &counts {
        let pos = e.tp + e.fn_;
        let pred = e.tp + e.fp;
        let (rec_lb, prec_lb) = (wilson_lower(e.tp, pos), wilson_lower(e.tp, pred));
        let mut why = Vec::new();
        if pos < MIN_POSITIVES {
            why.push(format!("only {pos} positive columns (< {MIN_POSITIVES})"));
        }
        if rec_lb < MIN_RECALL_LB {
            why.push(format!("recall LB {rec_lb:.3} < {MIN_RECALL_LB}"));
        }
        if prec_lb < MIN_PRECISION_LB {
            why.push(format!("precision LB {prec_lb:.3} < {MIN_PRECISION_LB}"));
        }
        eprintln!(
            "{:<22} {:>4} {:>4} {:>4} {:>7.3} {:>7.3} {:>9.3} {:>7.3}  {}",
            c.as_str(),
            e.tp,
            e.fp,
            e.fn_,
            ratio(e.tp, pos),
            rec_lb,
            ratio(e.tp, pred),
            prec_lb,
            if why.is_empty() { "pass" } else { "FAIL" }
        );
        if !why.is_empty() {
            failed.push((*c, why));
        }
    }

    for (c, why) in &failed {
        eprintln!("\n{} fails: {}", c.as_str(), why.join("; "));
        for (kind, id, tags) in &counts[c].errors {
            eprintln!("  {kind} {id} [{tags}]");
        }
    }
    assert!(
        failed.is_empty(),
        "holdout gate failed for: {}",
        failed
            .iter()
            .map(|(c, _)| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}
