#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;

use databastion_classifiers::masking::{
    ClassifierId, FindingLocation, MaskedFinding, RawSample, mask,
};
use databastion_classifiers::names::normalize_path;
use databastion_protocol::{ClassifiersVersion, Engine, TargetId, Uuid};

use super::*;
use crate::config::SpoolConfig;
use crate::fsutil::test_dir::TempDir;
use crate::uplink::{MaskedResults, to_batches};

pub(crate) fn masked(n: usize, field: &str) -> Vec<MaskedFinding> {
    (0..n)
        .map(|_| {
            MaskedFinding::new(
                ClassifierId::PII_EMAIL,
                vec![mask(&RawSample::new("a@b.c"))],
            )
            .with_location(FindingLocation {
                database: normalize_path("crm"),
                schema: Some(normalize_path("public")),
                object: normalize_path("clients"),
                field: normalize_path(field),
            })
            .with_counts(10, 5, 0.9)
        })
        .collect()
}

pub(crate) fn batches(n: usize) -> Vec<ResultBatch> {
    let version = ClassifiersVersion::try_from("2026.09.1").unwrap();
    let target = TargetId::try_from("pg-main").unwrap();
    let findings = masked(n, "email");
    to_batches(MaskedResults::Findings {
        job_id: Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        classifiers_version: &version,
        target_id: &target,
        engine: Engine::Postgres,
        findings: &findings,
    })
    .batches
}

/// An events batch (a spooled body parsed back, as after a restart).
pub(crate) fn events_batch() -> ResultBatch {
    let body = serde_json::json!({
        "batch_id": databastion_protocol::new_batch_id(),
        "events": [crate::sanitize::tests::event("read", 1)],
    });
    ResultBatch::parse(false, serde_json::to_vec(&body).unwrap()).unwrap()
}

fn config(max_bytes: u64, max_batches: u32) -> SpoolConfig {
    SpoolConfig {
        max_bytes,
        max_batches,
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn conversion_caps_items_and_drops_invalid_ones() {
    let b = batches(450);
    assert_eq!(
        b.iter().map(ResultBatch::len).collect::<Vec<_>>(),
        [200, 200, 50]
    );
    let ids: std::collections::HashSet<_> = b.iter().map(|x| x.batch_id()).collect();
    assert_eq!(ids.len(), 3);
    for x in &b {
        assert!(x.bytes().len() <= MAX_BATCH_BYTES);
    }
    // No location, sampled 0, matched > sampled: dropped and counted.
    let version = ClassifiersVersion::try_from("2026.09.1").unwrap();
    let target = TargetId::try_from("pg-main").unwrap();
    let mut findings = masked(1, "users.0612345678.phone");
    findings.push(MaskedFinding::new(ClassifierId::PII_EMAIL, Vec::new()));
    findings.extend(masked(1, "x").into_iter().map(|f| f.with_counts(0, 0, 0.5)));
    findings.extend(masked(1, "x").into_iter().map(|f| f.with_counts(5, 6, 0.5)));
    let built = to_batches(MaskedResults::Findings {
        job_id: Uuid::try_from("01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a").unwrap(),
        classifiers_version: &version,
        target_id: &target,
        engine: Engine::Postgres,
        findings: &findings,
    });
    assert_eq!(built.dropped_items, 3);
    let body = String::from_utf8(built.batches[0].bytes().to_vec()).unwrap();
    assert!(body.contains(r#""field":"users.*.phone""#), "{body}");
    assert!(!body.contains("0612345678"));
}

#[test]
fn files_are_private_and_fifo_survives_restart() {
    let dir = TempDir::new();
    let b = batches(3 * 200);
    {
        let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
        for x in &b {
            spool.push(x).unwrap();
        }
    }
    let sdir = dir.path().join("spool");
    assert_eq!(mode(&sdir), 0o700);
    for e in fs::read_dir(&sdir).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            assert_eq!(mode(&p), 0o600);
        }
    }
    // Stale temporary file from a crash.
    fs::write(sdir.join(".00000000000000000009-f.json.tmp"), b"partial").unwrap();
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    assert!(!sdir.join(".00000000000000000009-f.json.tmp").exists());
    assert_eq!(spool.len(), 3);
    for x in &b {
        let (key, front) = spool.front().unwrap();
        assert_eq!(front.batch_id(), x.batch_id());
        spool.remove(&key);
    }
    assert!(spool.front().is_none());
    let status = spool.status();
    assert_eq!((status.batches.0, status.bytes.0), (0, 0));
}

#[test]
fn oldest_batches_are_dropped_first_when_full() {
    let dir = TempDir::new();
    let b = batches(5 * 200);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 3)).unwrap();
    for x in &b {
        spool.push(x).unwrap();
    }
    assert_eq!(spool.len(), 3);
    assert_eq!(spool.counters.dropped_batches, 2);
    assert_eq!(spool.counters.dropped_items, 400);
    assert_eq!(spool.front().unwrap().1.batch_id(), b[2].batch_id());
    // Byte bound.
    let one = b[0].bytes().len() as u64;
    let dir2 = TempDir::new();
    let mut spool = Spool::open(dir2.path(), &config(one * 2 + 10, 100)).unwrap();
    for x in &b {
        spool.push(x).unwrap();
    }
    assert_eq!(spool.len(), 2);
    let status = spool.status();
    assert!(status.bytes.0 as u64 <= one * 2 + 10);
    assert_eq!(status.dropped_batches.unwrap().0, 3);
}

#[test]
fn corrupt_files_are_quarantined() {
    let dir = TempDir::new();
    let b = batches(2 * 200);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    spool.push(&b[0]).unwrap();
    spool.push(&b[1]).unwrap();
    drop(spool);
    let sdir = dir.path().join("spool");
    crate::fsutil::write_private_atomic(&sdir.join(file_name(&[0], true)), b"{not json").unwrap();
    crate::fsutil::write_private_atomic(&sdir.join("garbage"), b"x").unwrap();
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    assert_eq!(spool.counters.quarantined, 2);
    assert_eq!(spool.front().unwrap().1.batch_id(), b[1].batch_id());
    assert_eq!(fs::read_dir(sdir.join("quarantine")).unwrap().count(), 2);
    // Corrupted after load: skipped on read.
    let (key, _) = spool.front().unwrap();
    crate::fsutil::write_private_atomic(&sdir.join(file_name(&key, true)), b"[]").unwrap();
    assert!(spool.front().is_none());
    assert_eq!(spool.counters.quarantined, 3);
}

#[test]
fn replacement_keeps_its_place_with_new_ids() {
    let dir = TempDir::new();
    let b = batches(2 * 200);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    spool.push(&b[0]).unwrap();
    spool.push(&b[1]).unwrap();
    let (key, front) = spool.front().unwrap();
    let rest = front.without(&[0, 5, 199]).unwrap().unwrap();
    assert_eq!(rest.len(), 197);
    assert_ne!(rest.batch_id(), front.batch_id());
    let (h1, h2) = rest.halves().unwrap().unwrap();
    assert_eq!((h1.len(), h2.len()), (98, 99));
    spool.replace(&key, &[h1.clone(), h2.clone()], 3).unwrap();
    assert_eq!(spool.counters.dropped_items, 3);
    drop(spool);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    let order: Vec<_> = std::iter::from_fn(|| {
        let (k, x) = spool.front()?;
        spool.remove(&k);
        Some(x.batch_id())
    })
    .collect();
    assert_eq!(order, [h1.batch_id(), h2.batch_id(), b[1].batch_id()]);
}

#[test]
fn stored_bytes_are_sent_verbatim() {
    let dir = TempDir::new();
    let b = batches(3);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    spool.push(&b[0]).unwrap();
    drop(spool);
    // Same content, different formatting: parsed for metadata only.
    let mut pretty = b" ".to_vec();
    pretty.extend_from_slice(b[0].bytes());
    pretty.extend_from_slice(b"\n");
    let file = dir.path().join("spool").join(file_name(&[0], true));
    crate::fsutil::write_private_atomic(&file, &pretty).unwrap();
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    let (_, front) = spool.front().unwrap();
    assert_eq!(front.bytes(), pretty.as_slice());
    assert_eq!(front.batch_id(), b[0].batch_id());
}

#[test]
fn replacement_keys_never_collide_with_crash_leftovers() {
    let dir = TempDir::new();
    let b = batches(2 * 200);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    spool.push(&b[0]).unwrap();
    spool.push(&b[1]).unwrap();
    let (key, front) = spool.front().unwrap();
    let (h1, h2) = front.halves().unwrap().unwrap();
    // Crash after writing the children but before removing the parent.
    let sdir = dir.path().join("spool");
    crate::fsutil::write_private_atomic(&sdir.join(file_name(&[0, 0], true)), h1.bytes()).unwrap();
    drop(spool);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    assert_eq!(spool.len(), 3);
    spool.replace(&key, &[h1.clone(), h2.clone()], 7).unwrap();
    assert_eq!(spool.counters.dropped_items, 7);
    let keys: Vec<_> = spool.entries.iter().map(|e| e.key.clone()).collect();
    assert_eq!(keys, vec![vec![0, 0], vec![0, 1], vec![0, 2], vec![1]]);
    drop(spool);
    let spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    assert_eq!(spool.len(), 4);
}

#[test]
fn refused_and_non_utf8_files_are_quarantined() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new();
    let b = batches(3);
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    spool.push(&b[0]).unwrap();
    drop(spool);
    let sdir = dir.path().join("spool");
    let file = sdir.join(file_name(&[0], true));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(
        sdir.join(std::ffi::OsStr::from_bytes(b"bad-\xff-name")),
        b"x",
    )
    .unwrap();
    let spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    assert_eq!(spool.len(), 0);
    assert_eq!(spool.counters.quarantined, 2);
    let names: Vec<_> = fs::read_dir(&sdir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("quarantine")]);
}

#[test]
fn front_where_skips_a_parked_endpoint_and_keeps_each_fifo() {
    let dir = TempDir::new();
    let f = batches(2 * 200);
    let e = [events_batch(), events_batch()];
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    // Queue order: e0, f0, e1, f1.
    spool.push(&e[0]).unwrap();
    spool.push(&f[0]).unwrap();
    spool.push(&e[1]).unwrap();
    spool.push(&f[1]).unwrap();
    // `/events` parked: the findings are served in their own order.
    let findings_only = |findings: bool| findings;
    for x in &f {
        let (key, front) = spool.front_where(findings_only).unwrap();
        assert!(front.is_findings());
        assert_eq!(front.batch_id(), x.batch_id());
        spool.remove(&key);
    }
    assert!(spool.front_where(findings_only).is_none());
    // The parked batches are kept, still in order.
    assert_eq!(spool.len(), 2);
    assert_eq!(spool.counters.dropped_batches, 0);
    for x in &e {
        let (key, front) = spool.front().unwrap();
        assert!(!front.is_findings());
        assert_eq!(front.batch_id(), x.batch_id());
        spool.remove(&key);
    }
    assert!(spool.front().is_none());
}

#[test]
fn findings_pending_tracks_a_sequence_range_through_replacements() {
    let dir = TempDir::new();
    let mut spool = Spool::open(dir.path(), &config(8 << 20, 100)).unwrap();
    // An earlier job's batch, then an events batch and two batches of the
    // job under watch.
    spool.push(&batches(1)[0]).unwrap();
    let first = spool.next_seq();
    spool.push(&events_batch()).unwrap();
    let job = batches(400);
    for b in &job {
        spool.push(b).unwrap();
    }
    let seqs = first..spool.next_seq();
    assert_eq!(spool.findings_pending(&seqs), 2);
    // Events and older findings never count.
    assert_eq!(spool.findings_pending(&(0..first)), 1);
    // A split keeps the first key part: still pending.
    let key = vec![first + 1];
    let (a, b) = job[0].halves().unwrap().unwrap();
    spool.replace(&key, &[a, b], 0).unwrap();
    assert_eq!(spool.findings_pending(&seqs), 3);
    // Acknowledged or dropped batches are no longer pending.
    spool.remove(&[first + 1, 0]);
    spool.drop_batch(&[first + 1, 1]);
    spool.remove(&[first + 2]);
    assert_eq!(spool.findings_pending(&seqs), 0);
    assert_eq!(spool.findings_pending(&(0..first)), 1);
    assert_eq!(spool.len(), 2);
}
