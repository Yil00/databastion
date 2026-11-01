//! Tests of the parser checkpoint through the runner (ADR-0060 R25 items 7
//! and 9, R39 (a), R42 item 4, the restart residual of the implementation
//! note of 2026-10-31 c): each [`Proc`] is one agent process on the same
//! state directory and log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::LocalTagKey;
use databastion_core::audit::CursorStore;

use super::*;
use crate::audit_ckpt::{Checkpointer, CkptCounts};
use crate::own::Ledger;
use crate::stream::{Counts, Emitted};
use crate::stream_tests::{APP, HEAD, attach, attach_as, now_head, select, stmt};

const AGENT: &str = "DATABASTION_AGENT";
const RUN: Run = Run {
    pid: 24,
    start: Some(4242),
};

fn key() -> Arc<LocalTagKey> {
    Arc::new(
        databastion_classifiers::masking::HmacKey::new(&[7; 32])
            .unwrap()
            .local_tag_key("databastion.audit.cursor")
            .unwrap(),
    )
}

fn settings() -> Settings {
    Settings {
        databases: vec![DeclaredNames {
            label: "app".to_owned(),
            resolved: Some(APP.to_owned()),
            alias: None,
            excluded: false,
            attach: APP.to_owned(),
            read_at: None,
        }],
        aliases: Some(AliasMap::default()),
        proof11: true,
        account: AGENT.to_owned(),
        parse: ParseOptions {
            max_sql_length: Some(65_000),
            series: Series::V5,
        },
        superserver: true,
    }
}

fn temp(name: &str) -> std::path::PathBuf {
    databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
    crate::fsread::allow_own_files_for_tests();
    let dir = std::env::temp_dir().join(format!("fbck-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("audit.log"), b"").unwrap();
    dir
}

fn append(dir: &std::path::Path, text: &str) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("audit.log"))
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

fn checkpoint_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("t.fbck.checkpoint")
}

fn objects(out: &[Emitted]) -> Vec<String> {
    out.iter()
        .flat_map(|(_, e)| e.objects().iter().map(|o| o.object().as_str().to_owned()))
        .collect()
}

/// One agent process: its runner, machine and ledger, the sink's counts.
struct Proc {
    r: Runner,
    m: Machine,
    submitted: u64,
    durable: u64,
    out: Vec<Emitted>,
}

impl Proc {
    fn start(dir: &std::path::Path, ledger: Arc<Ledger>) -> Self {
        Self::start_with(dir, ledger, settings(), RUN)
    }

    fn start_with(dir: &std::path::Path, ledger: Arc<Ledger>, s: Settings, run: Run) -> Self {
        let k = key();
        let log = dir.join("audit.log");
        let store = CursorStore::new(dir, "t", "fb").map(|s| s.with_tag_key(Arc::clone(&k)));
        let mut ck = Checkpointer::open(
            CursorStore::checkpoint(dir, "t", "fbck").map(|s| s.with_tag_key(Arc::clone(&k))),
            CursorStore::counters(dir, "t", "fblg"),
            &ledger,
        )
        .unwrap();
        ck.tune_for_tests(
            Duration::ZERO,
            databastion_core::audit::MAX_CHECKPOINT_BYTES,
        );
        let mut m = Machine::new(s, Arc::clone(&ledger));
        m.enable_checkpoint(ck.key());
        m.confirm_run(run);
        let r = Runner {
            ckpt: Some(ck),
            shed: 0,
            tailer: Tailer::new(log.clone(), FRAMING, store).with_open_check(open_check(log)),
            asm: Assembler::new(),
            record_start: None,
            file: None,
            last_growth: Instant::now(),
            reread_end: None,
            expect: None,
            reset: false,
            last_end: None,
            lost_in: None,
            ended: None,
        };
        Self {
            r,
            m,
            submitted: 0,
            durable: 0,
            out: Vec::new(),
        }
    }

    /// Hands `out` to the "core" as `poll_and_deliver` does.
    fn deliver(&mut self, out: Vec<Emitted>) {
        let keys = self.m.take_keys();
        assert_eq!(keys.len(), out.len(), "a position per event");
        let mut sent = Vec::new();
        for (i, _) in out.iter().enumerate() {
            self.submitted += 1;
            sent.push((keys[i].0, self.submitted, keys[i].1));
        }
        let held = self.m.held_keys();
        let suppressed = self.m.take_suppressed();
        let shed = std::mem::take(&mut self.r.shed);
        let c = self.r.ckpt.as_mut().unwrap();
        c.sent(&sent, &held, suppressed);
        if shed > 0 {
            c.shed(self.submitted, shed);
        }
        self.out.extend(out);
    }

    /// Reads what the log holds (no stable end of file).
    fn read(&mut self) {
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        loop {
            let mut out = Vec::new();
            let more = self.r.poll(&mut self.m, &cats, &mut out).unwrap();
            self.deliver(out);
            if !more {
                break;
            }
        }
    }

    /// Reading time passes (`after`): the bounds that run on it.
    fn expire(&mut self, after: Duration) {
        let classes = Classes::default();
        let cats: Vec<&dyn Catalog> = vec![&classes];
        let mut out = Vec::new();
        self.m.expire(Instant::now() + after, &cats, &mut out);
        self.deliver(out);
    }

    /// The core spooled everything submitted so far.
    fn spooled(&mut self) {
        self.durable = self.submitted;
    }

    /// The stream's commit: settle, checkpoint, cursor.
    fn commit(&mut self) -> Vec<(u64, databastion_core::audit::tail::RecordPos)> {
        let durable = Some(self.durable);
        self.r.ckpt.as_mut().unwrap().settle(durable);
        let held = self.r.commit(&self.m, (self.submitted, durable));
        self.r.tailer.commit_from(&held);
        held
    }

    fn counts(&self) -> (Counts, CkptCounts) {
        (self.m.counts, self.r.ckpt.as_ref().unwrap().counts)
    }
}

/// A first process on the empty log, committed.
fn first_start(dir: &std::path::Path) {
    let mut p = Proc::start(dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    p.commit();
}

fn detach_as(head: &str, token: &str, id: u64, user: &str) -> String {
    format!(
        "{head} ({token}) DETACH_DATABASE\n\t{APP} (ATT_{id}, {user}:NONE, UTF8, TCPv4:127.0.0.1/4{id:04})\n\t/usr/bin/app:28\n\n"
    )
}

fn fini(head: &str, token: &str) -> String {
    format!("{head} ({token}) TRACE_FINI\n\tSESSION_1 Firebird Audit\n\t\n\n")
}

/// R39 (a) test 1, with the checkpoint: a restart in the middle of a
/// record restores the state at that record, sends it once complete, and
/// sends nothing read before it again; the anchored binding of the record
/// is known, so it is not learned and not ambiguous.
#[test]
fn a_restart_mid_record_sends_the_record_in_progress_once() {
    let dir = temp("mid");
    first_start(&dir);
    let a = "24:0x7f0000000100";
    let b = "24:0x7f0000000200";
    let full = select(b, 4, 7, APP, "PAYROLL", 3);
    let cut = full.len() / 2;
    append(
        &dir,
        &format!(
            "{}{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            attach(b, 4, APP),
            &full[..cut]
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    p.commit();
    assert!(objects(&p.out).contains(&"CUSTOMERS".to_owned()));
    assert!(!objects(&p.out).contains(&"PAYROLL".to_owned()));
    assert_eq!(p.counts().1.written, 1);
    drop(p);
    append(&dir, &full[cut..]);
    append(&dir, &attach("24:0x7f0000000300", 5, APP));
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    let (c, k) = p.counts();
    assert_eq!(k.restored, 1, "{k:?}");
    assert!(c.reread > 0, "the record in progress was read again");
    assert_eq!(c.ambiguous, 0, "{:?}", p.m.why);
    let o = objects(&p.out);
    assert_eq!(o.iter().filter(|x| *x == "PAYROLL").count(), 1, "{o:?}");
    assert!(!o.contains(&"CUSTOMERS".to_owned()), "{o:?}");
    p.spooled();
    p.commit();
    drop(p);
    // Nothing new: a third process sends nothing.
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert!(p.out.is_empty(), "{:?}", objects(&p.out));
    assert_eq!(p.counts().0.ambiguous, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `a`'s transaction 5 starts, then a procedure record of it pends
/// (block-less, or with a block naming `SECRETS`).
fn pending_routine(block: bool) -> String {
    let a = "24:0x7f0000000100";
    let ctx = format!(
        "\t{APP} (ATT_3, APP:NONE, UTF8, TCPv4:127.0.0.1/40003)\n\t/usr/bin/app:28\n\t\t(TRA_5, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)\n"
    );
    let blk = if block {
        format!(
            "\n{:<35}   Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge\n{}\n{:<35}{:>10}{:>70}\n",
            "Table",
            "*".repeat(115),
            "SECRETS",
            5,
            ""
        )
    } else {
        String::new()
    };
    format!(
        "{HEAD} ({a}) START_TRANSACTION\n{ctx}\n{HEAD} ({a}) EXECUTE_PROCEDURE_FINISH\n{ctx}\nProcedure P1:\n      0 ms, 3 fetch(es)\n{blk}\n"
    )
}

/// R39 (a) test 2, with the checkpoint: a restart during a block-less
/// hold restores the state as it was before the record that started it
/// (the position held back there), re-reads it, and holds the other
/// binding's read again until the group's end decides it: sent once, after
/// the restart, never lost.
#[test]
fn a_restart_during_a_block_less_hold_holds_again_and_sends_once() {
    let dir = temp("hold");
    first_start(&dir);
    let b = "24:0x7f0000000200";
    let head = format!(
        "{}{}",
        attach("24:0x7f0000000100", 3, APP),
        attach(b, 4, APP)
    );
    append(&dir, &head);
    let routine_at = std::fs::metadata(dir.join("audit.log")).unwrap().len();
    append(
        &dir,
        &format!(
            "{}{}{}",
            pending_routine(false),
            select(b, 4, 7, APP, "PAYROLL", 3),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    let held = p.commit();
    assert!(!objects(&p.out).contains(&"PAYROLL".to_owned()), "held");
    // The position is the snapshot's: the `START_TRANSACTION` before the
    // block-less routine record is part of the state, the routine is not.
    let start = held[0].1.start;
    assert!(start > routine_at, "{start} {routine_at}");
    assert_eq!(p.counts().1.written, 1);
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert_eq!(p.counts().1.restored, 1);
    assert!(
        !objects(&p.out).contains(&"PAYROLL".to_owned()),
        "held again"
    );
    // The group's hold ends with its reading-time bound: the held read is
    // sent (ambiguous, R25 item 3), once.
    p.expire(Duration::from_secs(11));
    let o = objects(&p.out);
    assert_eq!(o.iter().filter(|x| *x == "PAYROLL").count(), 1, "{o:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// R39 (a) test 3, with the checkpoint: a block-ful pending group is part
/// of the state (the position is not held back to it), restored with its
/// relations, and sent when it ends after the restart.
#[test]
fn a_restart_with_a_pending_group_restores_the_group() {
    let dir = temp("group");
    first_start(&dir);
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach("24:0x7f0000000100", 3, APP),
            pending_routine(true),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    p.commit();
    assert!(!objects(&p.out).contains(&"SECRETS".to_owned()), "pending");
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    let (c, k) = p.counts();
    assert_eq!(k.restored, 1);
    assert_eq!(c.ambiguous, 0);
    // Only the record in progress is read again, the routine record is not:
    // nothing is sent until the group ends.
    assert!(p.out.is_empty());
    p.expire(Duration::from_secs(11));
    assert!(objects(&p.out).contains(&"SECRETS".to_owned()));
    // Not spooled when the process stops: the next one ends the group again
    // (sent again: a duplicate, never a loss).
    p.commit();
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.expire(Duration::from_secs(11));
    assert!(objects(&p.out).contains(&"SECRETS".to_owned()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// R39 (a) test 4 and the durability order (L11): a checkpoint is written
/// only once the events before it are spooled; meanwhile later records are
/// read and their events spooled too. A restart from that checkpoint
/// re-reads them and sends nothing for their positions (deduplication),
/// including an ambiguous record; an event not yet spooled is sent again.
#[test]
fn a_restart_sends_nothing_again_for_spooled_positions() {
    let dir = temp("dedup");
    first_start(&dir);
    let a = "24:0x7f0000000100";
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            attach("24:0x7f0000000200", 4, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert!(objects(&p.out).contains(&"CUSTOMERS".to_owned()));
    // Not spooled yet: the checkpoint is taken, not written, and the
    // cursor is not moved past the read not spooled.
    let held = p.commit();
    let starts: Vec<u64> = held.iter().map(|(_, r)| r.start).collect();
    assert_eq!(starts.len(), 2, "{held:?}");
    assert!(starts[1] < starts[0], "held back to the read: {held:?}");
    assert_eq!(p.counts().1.written, 0);
    assert!(!checkpoint_file(&dir).exists());
    // Later records: an ambiguous one (another pid) and a read.
    append(
        &dir,
        &format!(
            "{}{}{}",
            select("99:0x7f0000000900", 9, 9, APP, "LEDGER", 1),
            select(a, 3, 6, APP, "ORDERS", 4),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    p.read();
    assert!(p.m.counts.ambiguous > 0);
    p.spooled();
    // Now spooled: the checkpoint taken first is written, with the
    // positions sent since.
    p.commit();
    assert_eq!(p.counts().1.written, 1);
    let first = objects(&p.out);
    assert!(first.contains(&"LEDGER".to_owned()) && first.contains(&"ORDERS".to_owned()));
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    let (c, k) = p.counts();
    assert_eq!(k.restored, 1);
    assert!(c.reread > 0 || c.deduped > 0);
    assert!(c.deduped > 0, "{c:?}");
    assert!(p.out.is_empty(), "{:?}", objects(&p.out));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The durability order (L11): with nothing spooled, no checkpoint is
/// written, so a restart starts with no state and sends everything again
/// (never a loss); a later spool then writes it.
#[test]
fn nothing_spooled_no_checkpoint() {
    let dir = temp("nodurable");
    first_start(&dir);
    std::fs::remove_file(checkpoint_file(&dir)).ok();
    let a = "24:0x7f0000000100";
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.commit();
    assert!(!checkpoint_file(&dir).exists());
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert_eq!(p.counts().1.restored, 0);
    assert!(
        objects(&p.out).contains(&"CUSTOMERS".to_owned()),
        "sent again"
    );
    p.spooled();
    p.commit();
    assert!(checkpoint_file(&dir).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The agent's own work: an own attachment and a credited constant text
/// (`first`), a second one (`second`), then its detach and `TRACE_FINI`
/// and another client's attachment (`tail`).
fn own_work(head: &str) -> (String, String, String) {
    let a = "24:0x7f0000000100";
    let v = crate::sql::VERSION;
    let first = format!(
        "{}{}",
        attach_as(a, 3, AGENT),
        stmt(a, 3, 5, AGENT, v, 1, &[("RDB$DATABASE", 1)])
    )
    .replace(HEAD, head);
    let second = stmt(a, 3, 6, AGENT, v, 1, &[("RDB$DATABASE", 1)]).replace(HEAD, head);
    let tail = format!(
        "{}{}{}",
        detach_as(head, a, 3, AGENT),
        fini(head, a),
        attach("24:0x7f0000000300", 5, APP).replace(HEAD, head)
    );
    (first, second, tail)
}

fn own_credits(ledger: &Ledger, opened: std::time::SystemTime, n: usize) {
    use crate::conn::{FetchAccount, FetchEnd};
    for _ in 0..n {
        ledger.credit_at(
            APP,
            3,
            crate::sql::VERSION,
            FetchAccount {
                counted: 1,
                requested: 64,
                last: 64,
                largest: 64,
                end: FetchEnd::End,
                ..FetchAccount::default()
            },
            opened,
        );
    }
}

/// The phases of the restart residual's log: the agent's own work, cut
/// in its second record, then cut in the `TRACE_FINI` after its detach.
/// `keep`: the checkpoint is kept across restarts (otherwise removed, as
/// before it existed). The counts and events of each process.
fn own_restarts(name: &str, keep: bool) -> Vec<(Counts, CkptCounts, Vec<Emitted>)> {
    let dir = temp(name);
    first_start(&dir);
    let (head, opened) = now_head(3600);
    let ledger = Arc::new(Ledger::default());
    ledger.register_at(APP, 3, 40003, 24, opened);
    own_credits(&ledger, opened, 2);
    let (first, second, _) = own_work(&head);
    let a = "24:0x7f0000000100";
    let detach = detach_as(&head, a, 3, AGENT);
    let fin = fini(&head, a);
    let next = attach("24:0x7f0000000300", 5, APP).replace(HEAD, &head);
    let cut2 = second.len() / 2;
    // After the `TRACE_FINI` header line: the detach is read, the
    // `TRACE_FINI` is the record in progress.
    let cutf = fin.find('\n').unwrap() + 2;
    let phases = [
        format!("{first}{}", &second[..cut2]),
        format!("{}{detach}{}", &second[cut2..], &fin[..cutf]),
        format!("{}{next}", &fin[cutf..]),
    ];
    let mut out = Vec::new();
    let mut ledger = Some(ledger);
    for (i, text) in phases.iter().enumerate() {
        append(&dir, text);
        // Each phase is read by a new process (a new, empty ledger after
        // the first).
        let l = ledger.take().unwrap_or_default();
        let mut p = Proc::start(&dir, l);
        p.read();
        if i == 0 {
            assert_eq!(p.m.offset_for_tests(), Some(3600));
        }
        p.spooled();
        p.commit();
        out.push((p.m.counts, p.counts().1, std::mem::take(&mut p.out)));
        drop(p);
        if !keep {
            let _ = std::fs::remove_file(checkpoint_file(&dir));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// The restart residual (implementation note of 2026-10-31 c): a restart
/// in the middle of the agent's own record restores its binding, its
/// header token and its credits: the record is the agent's own (no event),
/// and a restart inside the `TRACE_FINI` of its token after the detach
/// does not make it ambiguous.
#[test]
fn a_restart_mid_own_record_reports_nothing_and_is_not_ambiguous() {
    let runs = own_restarts("own", true);
    for (i, (c, k, out)) in runs.iter().enumerate() {
        assert!(out.is_empty(), "phase {i}: {:?}", objects(out));
        assert_eq!(c.ambiguous, 0, "phase {i}");
        if i > 0 {
            assert_eq!(k.restored, 1, "phase {i}");
        }
    }
    assert!(runs[1].0.own >= 1, "the cut record is the agent's own");
}

/// The same without the checkpoint (as before it existed): the agent's own
/// record read again is not credited, and the `TRACE_FINI` of a token the
/// new process never saw is ambiguous (the residual the checkpoint fixes).
#[test]
fn without_the_checkpoint_the_residual_remains() {
    let runs = own_restarts("own-none", false);
    assert_eq!(runs[1].1.restored, 0);
    assert_eq!(runs[1].0.own, 0, "not credited");
    assert!(runs[2].0.ambiguous > 0, "the TRACE_FINI of an unseen token");
}

/// R42 item 4: the confirmed clock offset is back from the checkpoint
/// before any own attachment of the new process is read.
#[test]
fn the_confirmed_offset_is_kept_across_a_restart() {
    let dir = temp("offset");
    first_start(&dir);
    let (head, opened) = now_head(3600);
    let ledger = Arc::new(Ledger::default());
    ledger.register_at(APP, 3, 40003, 24, opened);
    own_credits(&ledger, opened, 1);
    let (first, _, _) = own_work(&head);
    append(&dir, &first);
    append(
        &dir,
        &attach("24:0x7f0000000300", 5, APP).replace(HEAD, &head),
    );
    let mut p = Proc::start(&dir, ledger);
    p.read();
    assert_eq!(p.m.offset_for_tests(), Some(3600));
    p.spooled();
    p.commit();
    drop(p);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    assert_eq!(p.m.offset_for_tests(), None);
    p.read();
    assert_eq!(p.m.offset_for_tests(), Some(3600));
    let _ = std::fs::remove_dir_all(&dir);
}

/// "Right after a check" (the e2e unquiesced restart): the credits of a
/// session that ended after the last checkpoint are in the ledger written
/// at the session's end, so the restarted stream credits its records.
#[test]
fn a_restart_right_after_a_check_finds_its_credits() {
    let dir = temp("aftercheck");
    first_start(&dir);
    let (head, opened) = now_head(3600);
    let ledger = Arc::new(Ledger::default());
    ledger.register_at(APP, 3, 40003, 24, opened);
    own_credits(&ledger, opened, 1);
    let (first, second, tail) = own_work(&head);
    append(&dir, &first);
    let mut p = Proc::start(&dir, Arc::clone(&ledger));
    // The first statement only (the second's record is not written yet).
    p.read();
    p.spooled();
    p.commit();
    // The check goes on after the checkpoint: one more execution, then its
    // session ends (the ledger is written then).
    own_credits(&ledger, opened, 1);
    ledger.close(APP, 3, false, Duration::from_secs(1));
    drop(p);
    drop(ledger);
    // The agent is killed: the server writes the rest afterwards.
    append(&dir, &format!("{second}{tail}"));
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    let (c, k) = p.counts();
    assert_eq!(k.restored, 1);
    assert!(p.out.is_empty(), "{:?}", objects(&p.out));
    assert_eq!(c.ambiguous, 0, "{:?}", p.m.why);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A checkpoint of another server run (same pid, another start time),
/// one sealed with another key or corrupted, and one of other declared
/// databases are never used: the stream starts with no state.
#[test]
fn foreign_or_corrupt_checkpoints_are_not_used() {
    let dir = temp("foreign");
    first_start(&dir);
    let a = "24:0x7f0000000100";
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    p.commit();
    drop(p);
    let good = std::fs::read(checkpoint_file(&dir)).unwrap();
    let cursor = std::fs::read(dir.join("t.fb.cursor")).unwrap();
    let restore = |bytes: &[u8]| {
        std::fs::write(checkpoint_file(&dir), bytes).unwrap();
        std::fs::write(dir.join("t.fb.cursor"), &cursor).unwrap();
    };
    // Another run.
    restore(&good);
    let mut p = Proc::start_with(
        &dir,
        Arc::new(Ledger::default()),
        settings(),
        Run {
            pid: 24,
            start: Some(4243),
        },
    );
    p.read();
    assert_eq!(p.counts().1.restored, 0);
    assert_eq!(p.counts().1.refused, 1);
    drop(p);
    // Other declared databases.
    restore(&good);
    let mut other = settings();
    other.databases[0].label = "other".to_owned();
    let mut p = Proc::start_with(&dir, Arc::new(Ledger::default()), other, RUN);
    p.read();
    assert_eq!(p.counts().1.refused, 1);
    drop(p);
    // Every flipped bit, and a cut.
    for i in (0..good.len()).step_by(good.len().div_ceil(64)) {
        let mut b = good.clone();
        b[i] ^= 0x10;
        restore(&b);
        let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
        p.read();
        assert_eq!(p.counts().1.restored, 0, "bit {i}");
    }
    restore(&good[..good.len() - 1]);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert_eq!(p.counts().1.restored, 0);
    drop(p);
    // The good one, bound to its position, is used.
    restore(&good);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert_eq!(p.counts().1.restored, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A checkpoint whose position is not the one the log resumes from (a
/// cursor of another position, a log rewritten while stopped) is not used.
#[test]
fn a_checkpoint_at_another_position_is_not_used() {
    let dir = temp("position");
    first_start(&dir);
    let a = "24:0x7f0000000100";
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    p.commit();
    drop(p);
    // The log rewritten in place while stopped (the tailer resets).
    let text = std::fs::read(dir.join("audit.log")).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(dir.join("audit.log"))
        .unwrap();
    f.write_all(
        &text
            .iter()
            .map(|c| if *c == b'7' { b'8' } else { *c })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    drop(f);
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    assert_eq!(p.counts().1.restored, 0);
    assert_eq!(p.counts().1.refused, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// R25 item 9: past the cap, the oldest pending groups end first (their
/// outputs sent before a checkpoint without them is written), and a
/// checkpoint is never written truncated; deduplication positions past the
/// cap are dropped (sent again after a restart).
#[test]
fn the_cap_ends_groups_first_and_never_truncates() {
    let dir = temp("cap");
    first_start(&dir);
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach("24:0x7f0000000100", 3, APP),
            pending_routine(true),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    p.spooled();
    let size = |p: &Proc| p.m.export(Instant::now()).unwrap().len();
    let with_group = size(&p);
    // A cap the state with its group does not fit in, without it does.
    let cap = 74 + with_group - 1;
    p.r.ckpt
        .as_mut()
        .unwrap()
        .tune_for_tests(Duration::ZERO, cap);
    p.commit();
    let k = p.counts().1;
    assert_eq!(k.written, 0, "never truncated");
    // The next poll ends the group (its relations sent); the checkpoint
    // without it waits until they are spooled.
    p.read();
    assert!(objects(&p.out).contains(&"SECRETS".to_owned()));
    assert_eq!(p.counts().1.shed, 1);
    p.commit();
    assert_eq!(
        p.counts().1.written,
        0,
        "the shed outputs are not spooled yet"
    );
    p.spooled();
    p.commit();
    assert_eq!(p.counts().1.written, 1);
    assert!(size(&p) <= cap);
    let _ = std::fs::remove_dir_all(&dir);
}

/// I2: the checkpoint and the ledger hold no statement text, parameter or
/// value: here neither the agent's text, nor the client's statement, nor
/// the database path, nor a marker value of a statement appear in them.
#[test]
fn the_files_hold_no_text_or_value() {
    let dir = temp("i2");
    first_start(&dir);
    let (head, opened) = now_head(3600);
    let ledger = Arc::new(Ledger::default());
    ledger.register_at(APP, 3, 40003, 24, opened);
    own_credits(&ledger, opened, 2);
    let (first, second, _) = own_work(&head);
    append(&dir, &format!("{first}{}", &second[..second.len() / 2]));
    let a = "24:0x7f0000000500";
    append(
        &dir,
        &format!(
            "{}{}{}",
            attach(a, 7, APP),
            select(a, 7, 9, APP, "CUSTOMERS", 2).replace("ID > 0", "NOTE = 'hunter2marker'"),
            attach("24:0x7f0000000600", 8, APP)
        ),
    );
    let mut p = Proc::start(&dir, Arc::clone(&ledger));
    p.read();
    p.spooled();
    p.commit();
    ledger.persist();
    let ck = std::fs::read(checkpoint_file(&dir)).unwrap();
    let lg = std::fs::read(dir.join("t.fblg.counters")).unwrap();
    for f in [&ck, &lg] {
        let s = String::from_utf8_lossy(f);
        for needle in [
            "SELECT",
            "hunter2marker",
            "ENGINE_VERSION",
            "app.fdb",
            "/var/lib",
            AGENT,
        ] {
            assert!(!s.contains(needle), "{needle} in a persisted file");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parser state survives a round trip exactly, and a body with any
/// byte changed is refused whole (never a partial restore).
#[test]
fn the_parser_state_round_trips_and_refuses_whole() {
    let dir = temp("roundtrip");
    first_start(&dir);
    let a = "24:0x7f0000000100";
    append(
        &dir,
        &format!(
            "{}{}{}{}{}",
            attach(a, 3, APP),
            select(a, 3, 5, APP, "CUSTOMERS", 2),
            pending_routine(true),
            select("99:0x7f0000000900", 9, 9, APP, "LEDGER", 1),
            attach("24:0x7f0000000300", 5, APP),
        ),
    );
    let mut p = Proc::start(&dir, Arc::new(Ledger::default()));
    p.read();
    let now = Instant::now();
    let body = p.m.export(now).unwrap();
    let mut q = Machine::new(settings(), Arc::new(Ledger::default()));
    q.enable_checkpoint(key());
    q.confirm_run(RUN);
    q.import(&body, now).unwrap();
    assert_eq!(q.export(now).unwrap(), body);
    // Another run: refused.
    let mut r = Machine::new(settings(), Arc::new(Ledger::default()));
    r.enable_checkpoint(key());
    r.confirm_run(Run {
        pid: 25,
        start: Some(4242),
    });
    assert!(r.import(&body, now).is_err());
    // Every truncation, and changed bytes: refused, nothing kept.
    for n in 0..body.len() {
        let mut q = Machine::new(settings(), Arc::new(Ledger::default()));
        q.enable_checkpoint(key());
        q.confirm_run(RUN);
        if q.import(&body[..n], now).is_ok() {
            panic!("a cut body at {n} was accepted");
        }
        assert_eq!(q.state_bytes(), 0, "nothing kept at {n}");
    }
    let mut longer = body.clone();
    longer.push(0);
    let mut q = Machine::new(settings(), Arc::new(Ledger::default()));
    q.enable_checkpoint(key());
    q.confirm_run(RUN);
    assert!(q.import(&longer, now).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
