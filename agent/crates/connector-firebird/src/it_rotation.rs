//! A measurement, not a check (ADR-0060 obligation 6, the rotation part):
//! what the agent's Audit stream does when the server rotates its log
//! under the user guide's layout (named-user ACLs, a default ACL on the
//! directory for the next file). `dev/firebird/it.sh` restarts the main
//! server with `max_log_size = 1`, runs this test as the agent's uid
//! (10001, no supplementary group) in the background, then writes more
//! than 1 MiB of trace. The test tails the log as the stream does (its
//! framing, its open check and a cursor store) and prints what it saw;
//! it asserts only that the first file was read. The modes and ACLs of
//! the files are printed by the script.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use databastion_core::audit::CursorStore;
use databastion_core::audit::tail::Tailer;

#[test]
fn the_stream_across_a_server_rotation() {
    if !super::enabled() {
        return;
    }
    let (Ok(log), Ok(ready)) = (
        std::env::var("FIREBIRD_IT_ROTATION_LOG"),
        std::env::var("FIREBIRD_IT_ROTATION_READY"),
    ) else {
        return;
    };
    let log = PathBuf::from(log);
    let ready = PathBuf::from(ready);
    let cursors = ready.with_extension("cursors");
    std::fs::create_dir_all(&cursors).expect("cursor dir");
    let store = CursorStore::new(&cursors, "rotation", "fb");
    let mut t = Tailer::new(log.clone(), crate::audit::FRAMING, store)
        .with_open_check(crate::audit::open_check(log.clone()));
    let first = t.poll();
    eprintln!(
        "[measure] rotation: first open of the log as uid {}: {}",
        rustix::process::geteuid().as_raw(),
        match &first {
            Ok(_) => "readable".to_owned(),
            Err(e) => format!("{e:?}"),
        }
    );
    assert!(first.is_ok(), "the prepared log must be readable");
    std::fs::write(&ready, b"ready").expect("ready");
    let deadline = Instant::now() + Duration::from_secs(90);
    let (mut lines, mut errors, mut first_error) = (0usize, 0u64, None);
    let mut lines_at_rotation = None;
    let mut polls_after_error = 0;
    while Instant::now() < deadline {
        match t.poll() {
            Ok(p) => {
                lines += p.records.len();
                if t.rotations > 0 && lines_at_rotation.is_none() {
                    lines_at_rotation = Some(lines);
                }
            }
            Err(e) => {
                errors += 1;
                if first_error.is_none() {
                    first_error = Some((format!("{e:?}"), t.rotations, lines));
                }
                polls_after_error += 1;
                if polls_after_error >= 10 {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[measure] rotation: lines read {lines}, rotations seen {}, lines read when the first \
         rotation was seen {lines_at_rotation:?}, failed polls {errors}",
        t.rotations
    );
    match &first_error {
        Some((e, rotations, at)) => eprintln!(
            "[measure] rotation: first failed poll: {e} (after {rotations} rotation(s), {at} lines)"
        ),
        None => eprintln!("[measure] rotation: no failed poll"),
    }
    eprintln!(
        "[measure] rotation: check() open check of the new log (proof 1): {:?}",
        crate::fsread::check_file(&log)
    );
    // Every file of the directory, opened for reading as this uid.
    if let Some(dir) = log.parent()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        let mut names: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        names.sort();
        for p in names {
            let open = std::fs::File::open(&p).map(|_| ()).map_err(|e| e.kind());
            eprintln!(
                "[measure] rotation: open as the agent: {}: {open:?}",
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            );
        }
    }
}
