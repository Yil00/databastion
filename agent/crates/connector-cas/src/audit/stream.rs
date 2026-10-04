//! Incremental reading of the CAS JSON audit log (ADR-0041 decision 7).
//!
//! The core tailer (`databastion_core::audit::tail`) follows the file: one
//! record per line ([`Framing::Lines`], at most 1 MiB per line, longer ones
//! dropped and counted), rotation and keyed truncation fingerprints,
//! persisted positions, refusal of a file the agent could write, and
//! `O_NOFOLLOW` on every (re)open. This crate's checks run as the tailer's
//! open check on the tailer's own handle after every (re)open (security
//! review of #138 L2): the declared path still resolves where it did at
//! load, a regular file with one hard link, not writable by the agent
//! (owner, mode, `faccessat`, ancestors), the path bound to the handle's
//! `(st_dev, st_ino)`. Before each poll, the same checks also run on the
//! path. Each record is parsed and converted under per-record panic
//! isolation (ADR-0032): a record that makes a parser panic costs that
//! record only.
//!
//! The async loop (`Connector::audit_stream`, [`crate::connector`]) wraps
//! [`AuditRunner::poll`] in `spawn_blocking`, submits the events as
//! `MaskedEvent`s and calls [`AuditRunner::commit`] after them.

use std::sync::Arc;
use std::time::SystemTime;

use databastion_core::audit::CursorStore;
use databastion_core::audit::tail::{Framing, TailError, Tailer};
use zeroize::Zeroizing;

use super::events::{Builder, CasEvent};
use super::level::Evidence;
use crate::config::{AuditLogSettings, CasSettings, UtcOffset};
use crate::fsread::{self, Policy, Refusal};
use crate::parse::record::{AuditRecord, RecordError, parse_record};
use crate::state::CasState;

/// Lines of one read, parsed.
#[derive(Debug, Default)]
pub(crate) struct Batch {
    pub(crate) records: Vec<AuditRecord>,
    pub(crate) evidence: Evidence,
    pub(crate) json: u64,
    pub(crate) non_json: u64,
    pub(crate) dropped: u64,
    pub(crate) headers: bool,
}

/// Parses lines, each under panic isolation. Blank lines are ignored.
pub(crate) fn parse_lines<L: AsRef<[u8]>>(
    lines: impl IntoIterator<Item = L>,
    zone: UtcOffset,
    now: SystemTime,
) -> Batch {
    let mut b = Batch::default();
    for line in lines {
        let line = line.as_ref();
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parsed = databastion_core::isolate(|| {
            #[cfg(test)]
            test_poison(line);
            parse_record(line, zone)
        });
        match parsed {
            Some(Ok(r)) => {
                b.json += 1;
                b.headers |= r.headers_logged;
                b.evidence.note(&r, now);
                b.records.push(r);
            }
            Some(Err(RecordError::Invalid)) => {
                b.json += 1;
                b.dropped += 1;
            }
            Some(Err(RecordError::NotJson)) => {
                b.non_json += 1;
                b.dropped += 1;
            }
            None => b.dropped += 1,
        }
    }
    b
}

/// Tests: a record holding this marker makes the parsing panic.
#[cfg(test)]
pub(crate) const TEST_POISON: &[u8] = b"TEST-PARSER-PANIC";

#[cfg(test)]
#[allow(clippy::panic)]
fn test_poison(line: &[u8]) {
    if line.windows(TEST_POISON.len()).any(|w| w == TEST_POISON) {
        panic!("parser bug on a record");
    }
}

/// The events of one poll.
#[derive(Debug, Default)]
pub struct Polled {
    /// Events, in log order (aggregates when their minute ended).
    pub events: Vec<CasEvent>,
    /// More data is waiting.
    pub more: bool,
}

/// Follows the audit log of one `cas` target.
pub struct AuditRunner {
    settings: AuditLogSettings,
    tailer: Tailer,
    builder: Builder,
    state: Arc<CasState>,
    /// Tailer counters (oversized, damaged) already reported.
    reported: (u64, u64),
    policy: Policy,
    /// Why the tailer's open check last refused the file.
    refused: Arc<std::sync::Mutex<Option<Refusal>>>,
}

impl std::fmt::Debug for AuditRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditRunner")
            .field("builder", &self.builder)
            .finish_non_exhaustive()
    }
}

impl AuditRunner {
    /// A runner for the target's audit log (`None` when it declares
    /// none), its cursor kept in `store`, its window tags made with
    /// `builder`'s key.
    #[must_use]
    pub fn new(
        settings: &CasSettings,
        store: Option<CursorStore>,
        builder: Builder,
        state: Arc<CasState>,
    ) -> Option<Self> {
        Self::with_policy(settings, store, builder, state, Policy::agent())
    }

    pub(crate) fn with_policy(
        settings: &CasSettings,
        store: Option<CursorStore>,
        builder: Builder,
        state: Arc<CasState>,
        policy: Policy,
    ) -> Option<Self> {
        let log = settings.audit_log.clone()?;
        let refused = Arc::new(std::sync::Mutex::new(None));
        let check = fsread::log_open_check(log.path.clone(), policy, Arc::clone(&refused));
        Some(Self {
            tailer: Tailer::new(log.path.path().to_path_buf(), Framing::Lines, store)
                .with_open_check(check),
            settings: log,
            builder,
            state,
            reported: (0, 0),
            policy,
            refused,
        })
    }

    /// Reads what was appended since the last poll and converts it.
    /// Blocking I/O: call from a blocking thread.
    ///
    /// # Errors
    /// [`Refusal`] when the log cannot be read or is refused.
    pub fn poll(&mut self, now: SystemTime) -> Result<Polled, Refusal> {
        if !self.settings.path.still_resolves() {
            return Err(Refusal::ResolvedChanged);
        }
        fsread::check_log(self.settings.path.path(), self.policy)?;
        // A refusal of the tailer's open check (on its own handle) is
        // reported as such; any other error of the tailer (an `EACCES` on
        // open, review of #138 I3, a symlink refused by `O_NOFOLLOW`) is
        // "not readable".
        let polled = self.tailer.poll().map_err(|TailError::Unreadable(_)| {
            self.refused
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or(Refusal::NotReadable)
        })?;
        let lines: Vec<Zeroizing<Vec<u8>>> = polled.records;
        let batch = parse_lines(&lines, self.settings.offset, now);
        drop(lines);
        let skipped = {
            let now_counts = (self.tailer.oversized, self.tailer.malformed());
            let d = now_counts
                .0
                .saturating_sub(self.reported.0)
                .saturating_add(now_counts.1.saturating_sub(self.reported.1));
            self.reported = now_counts;
            d
        };
        let mut events = Vec::new();
        let mut panicked = 0u64;
        for r in &batch.records {
            let builder = &mut self.builder;
            let out = &mut events;
            if databastion_core::isolate(|| builder.push(r, now, out)).is_none() {
                panicked += 1;
            }
        }
        self.builder.flush(now, false, &mut events);
        let dropped = batch
            .dropped
            .saturating_add(skipped)
            .saturating_add(panicked);
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "CAS audit records dropped (unparsable, oversized or internal error)"
            );
        }
        self.state.note_evidence(&batch.evidence);
        self.state
            .note_lines(batch.json, batch.non_json, dropped, batch.headers);
        Ok(Polled {
            events,
            more: polled.more,
        })
    }

    /// Emits every pending aggregate (the stream ends).
    pub fn finish(&mut self, now: SystemTime) -> Vec<CasEvent> {
        let mut out = Vec::new();
        self.builder.flush(now, true, &mut out);
        out
    }

    /// Saves the position after the events of the last poll were handed
    /// over. Blocking I/O.
    pub fn commit(&self) {
        self.tailer.commit();
    }

    /// The event builder (counters, service index).
    pub fn builder_mut(&mut self) -> &mut Builder {
        &mut self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::CasPrincipal;
    use crate::audit::events::tests_support::key;
    use crate::config::ClientAddrMode;
    use crate::fsread::tests::TempDir;
    use std::io::Write as _;

    fn settings(dir: &TempDir) -> CasSettings {
        CasSettings::from_yaml(
            &format!(
                "{{audit_log: {{path: {}/cas_audit.log}}}}",
                dir.path().display()
            ),
            &[],
        )
        .unwrap()
    }

    fn append(dir: &TempDir, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.path().join("cas_audit.log"))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn records_are_tailed_parsed_and_isolated() {
        databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
        let dir = TempDir::new("stream");
        append(
            &dir,
            "{\"action\": \"AUTHENTICATION_SUCCESS\", \"when\": 1}\n",
        );
        let s = settings(&dir);
        let state = Arc::new(CasState::default());
        let b = Builder::new(key(), &[], ClientAddrMode::Truncated, None);
        let mut r =
            AuditRunner::with_policy(&s, None, b, Arc::clone(&state), Policy::TESTS).unwrap();
        let now = SystemTime::now();
        // First start: at the end of the file, history not replayed.
        assert!(r.poll(now).unwrap().events.is_empty());
        let when = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        append(
            &dir,
            &format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"jane.doe@example.org\", \"when\": {when}, \"clientIpAddress\": \"192.0.2.5\"}}\n\
                 {{\"action\": \"AUTHENTICATION_FAILED\", \"who\": \"TEST-PARSER-PANIC\", \"when\": {when}}}\n\
                 WHO: jdoe\n\
                 {{\"action\": \"SERVICE_TICKET_CREATED\", \"who\": \"jdoe\", \"when\": {when}, \"what\": \"ST-9-FAKE for https://a.example.org/\", \"headers\": {{}}}}\n\
                 {{\"action\": \"AUTHENTICATION_FAILED\", \"who\": \"jdoe\", \"when\": {when}, \"who\": \"x\"}}\n"
            ),
        );
        let p = r.poll(now).unwrap();
        assert_eq!(p.events.len(), 2);
        assert!(matches!(&p.events[0].principal, CasPrincipal::Account(a) if !a.send_name()));
        r.commit();
        let snap = state.snapshot();
        assert_eq!(snap.dropped, 3, "panic, non-JSON line, duplicate key");
        assert!(snap.headers_logged);
        assert!(!snap.format_unsupported);
        assert_eq!(
            snap.evidence.level(now).0,
            databastion_core::AuditLevel::Partial
        );
    }

    #[test]
    fn a_symlink_or_hard_link_swapped_in_at_rotation_is_never_read() {
        databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
        let dir = TempDir::new("stream-swap");
        append(&dir, "");
        let s = settings(&dir);
        let state = Arc::new(CasState::default());
        let b = Builder::new(key(), &[], ClientAddrMode::Truncated, None);
        let mut r =
            AuditRunner::with_policy(&s, None, b, Arc::clone(&state), Policy::TESTS).unwrap();
        let now = SystemTime::now();
        assert!(r.poll(now).unwrap().events.is_empty());
        let when = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let other = dir.path().join("elsewhere.log");
        std::fs::write(
            &other,
            format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"planted\", \"when\": {when}}}\n"
            ),
        )
        .unwrap();
        let log = dir.path().join("cas_audit.log");
        // Rotation, then a symlink in place of the new file.
        std::fs::rename(&log, dir.path().join("cas_audit.log.1")).unwrap();
        std::os::unix::fs::symlink(&other, &log).unwrap();
        assert!(r.poll(now).is_err());
        // A hard link to another file in place of the new file.
        std::fs::remove_file(&log).unwrap();
        std::fs::hard_link(&other, &log).unwrap();
        assert_eq!(r.poll(now).err(), Some(Refusal::NotReadable));
        // A regular file again: read from its start.
        std::fs::remove_file(&log).unwrap();
        append(
            &dir,
            &format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"real\", \"when\": {when}}}\n"
            ),
        );
        let p = r.poll(now).unwrap();
        assert_eq!(p.events.len(), 1);
        assert!(!format!("{:?}", p.events).contains("planted"));
    }

    #[test]
    fn the_tailer_runs_the_crate_checks_on_its_own_handle() {
        databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
        let dir = TempDir::new("stream-hook");
        append(&dir, "");
        let s = settings(&dir);
        let log = s.audit_log.as_ref().unwrap().path.clone();
        let last = Arc::new(std::sync::Mutex::new(None));
        let check = fsread::log_open_check(log.clone(), Policy::TESTS, Arc::clone(&last));
        let mut t = Tailer::new(log.path().to_path_buf(), Framing::Lines, None)
            .with_open_check(Arc::clone(&check));
        assert!(t.poll().is_ok());
        assert_eq!(*last.lock().unwrap(), None);
        // Rotation to a hard-linked file: refused on the tailer's handle,
        // without any check of this crate before the poll.
        std::fs::rename(log.path(), dir.path().join("cas_audit.log.1")).unwrap();
        let other = dir.path().join("other.log");
        std::fs::write(&other, b"{}\n").unwrap();
        std::fs::hard_link(&other, log.path()).unwrap();
        assert!(t.poll().is_err());
        assert_eq!(*last.lock().unwrap(), Some(Refusal::NotReadable));
    }

    #[test]
    fn a_default_format_log_is_unsupported() {
        let lines = [
            "WHO: jdoe",
            "WHAT: TGT-1-FAKE",
            "ACTION: TICKET_GRANTING_TICKET_CREATED",
            "",
        ];
        let b = parse_lines(lines, UtcOffset(0), SystemTime::now());
        assert_eq!((b.json, b.non_json, b.dropped), (0, 3, 3));
    }
}
