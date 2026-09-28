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
use crate::uplink::{MaskedResults, pack_events, to_batches};

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
        assert!(x.to_bytes().unwrap().len() <= MAX_BATCH_BYTES);
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
    let body = String::from_utf8(built.batches[0].to_bytes().unwrap()).unwrap();
    assert!(body.contains(r#""field":"users.*.phone""#), "{body}");
    assert!(!body.contains("0612345678"));
}

#[test]
fn event_packing_respects_the_byte_cap() {
    let event = crate::sanitize::tests::event("read", 16);
    let events: Vec<_> = (0..2000).map(|_| event.clone()).collect();
    let built = pack_events(events);
    assert!(built.batches.len() >= 4);
    for b in &built.batches {
        assert!(b.len() <= 500);
        assert!(b.to_bytes().unwrap().len() <= MAX_BATCH_BYTES);
    }
    assert_eq!(built.dropped_items, 0);
    assert_eq!(
        pack_events(vec![crate::sanitize::tests::event("read", 0)]).dropped_items,
        1
    );
    assert!(matches!(
        to_batches(MaskedResults::Events(&[])).batches.as_slice(),
        []
    ));
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
    let one = b[0].to_bytes().unwrap().len() as u64;
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
    let rest = front.without(&[0, 5, 199]).unwrap();
    assert_eq!(rest.len(), 197);
    assert_ne!(rest.batch_id(), front.batch_id());
    let (h1, h2) = rest.halves().unwrap();
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
