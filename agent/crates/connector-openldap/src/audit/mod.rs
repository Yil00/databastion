//! OpenLDAP Audit (phase 6, ADR-0029 decisions 7 to 10): access events
//! from `cn=accesslog` (`slapo-accesslog`), read over LDAP with the
//! agent's connection.
//!
//! - Incremental by `entryCSN` (commit order), with a 10 s overlap and the
//!   CSNs already read, so log entries committed out of order are not
//!   missed; the cursor (a CSN) and the CSNs read within the overlap are
//!   persisted by the core, so the overlap holds across a restart too
//!   (end-of-phase-6 review L3).
//! - Each poll: one-level searches under the log base, `sizeLimit` 1000,
//!   repeated while the server cuts the result (at most 16 per poll).
//! - Only the attributes of [`records::LOG_ATTRIBUTES`] are requested;
//!   filters and DNs are reduced in memory to closed facts
//!   ([`records`], [`filter`]); events and signals by [`events`].
//! - The naming contexts and the agent's identity are re-read every 5
//!   minutes (re-probe), with the source check (`cn=accesslog` readable).
//! - Delivery is at most once, as for the other connectors.

pub(crate) mod events;
pub(crate) mod filter;
pub(crate) mod records;

use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::MaskedEvent;
use databastion_classifiers::names::normalize_ldap_dn;
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::OwnAccount;
use databastion_core::config::TargetConfig;
use databastion_core::{AuditConfig, ConnectorError, EventSink, FailureCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::catalog;
use crate::check::{self, CheckState};
use crate::conn::{Session, Timeouts};
use crate::error::{LdError, Stage};
use crate::proto::{Entry, Filter, Scope, Search};
use crate::time;
use events::{Context, EventBuilder};
use records::{Op, Record};

/// How often the source is re-probed while streaming.
const REPROBE: Duration = Duration::from_secs(300);
/// Log entries read per search.
pub(crate) const PAGE: u32 = 1000;
/// Searches per poll while the server cuts the result.
const MAX_ROUNDS: usize = 16;
/// Overlap of the first search of a poll, for entries committed out of
/// CSN order.
const OVERLAP: Duration = Duration::from_secs(10);
/// CSNs remembered for the overlap (the newest kept).
const MAX_SEEN: usize = 65_536;
/// First start: how far back the stream reads (no history replay).
const FIRST_START_BACK: Duration = Duration::from_secs(60);
/// Name of the persisted cursor.
pub(crate) const CURSOR: &str = "openldap_accesslog";
/// CSNs of the overlap window persisted at most (the newest): the file
/// stays well within the core's 64 KiB cursor bound. Past it, the newest
/// CSN left out becomes the floor (read, not reported again).
const MAX_PERSISTED_SEEN: usize = 1000;
/// First line of the persisted position (the cursor, a floor, and the
/// CSNs read within the overlap). A file without it is a bare CSN (the
/// phase-6 format).
const FORMAT_V2: &str = "v2";

fn internal() -> ConnectorError {
    LdError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

/// The read position: the newest CSN handed to the core, and the CSNs
/// read within the overlap.
#[derive(Debug, Default)]
pub(crate) struct Position {
    pub(crate) cursor: Option<String>,
    seen: BTreeSet<String>,
    /// Entries up to this CSN were handed over by a previous run and are
    /// not reported again after a restart: a cursor of the phase-6 format
    /// (a bare CSN, without the CSNs read), or the newest CSN left out of
    /// a persisted overlap past [`MAX_PERSISTED_SEEN`].
    floor: Option<String>,
    /// Log entries still to skip from the saved position: the core's
    /// request after the stream panicked repeatedly there
    /// (`CursorStore::skip_records`); counted as dropped.
    skip: u32,
    /// Isolation mode (`CursorStore::isolate`): entries still to hand over
    /// and save one by one (the first round of the session only).
    isolate_left: u32,
    /// Isolation mode: the entry being handed over, saved before its
    /// conversion. A skip request drops this exact entry only (PR #83
    /// re-review L-A).
    handing: Option<String>,
}

impl Position {
    /// From a persisted position (ignored unless its cursor is a CSN).
    /// The CSNs read within the overlap come back with it, so after a
    /// restart the overlap is read again and only the entries that were
    /// not read (committed out of CSN order just before the restart) are
    /// reported.
    pub(crate) fn load(store: Option<&CursorStore>) -> Self {
        let mut p = Self::load_saved(store);
        if p.cursor.is_some() {
            p.skip = store.map_or(0, CursorStore::skip_records);
        }
        if store.is_some_and(CursorStore::isolate) {
            p.isolate_left = PAGE;
        } else if p.skip == 0 {
            // Neither isolation nor a skip: a saved `handing` entry is read
            // like any other (never left out of `seen` again, never a
            // later skip's target).
            p.handing = None;
        }
        p
    }

    fn load_saved(store: Option<&CursorStore>) -> Self {
        let text = store
            .and_then(|s| match s.load() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "audit cursor unreadable: starting from now");
                    None
                }
            })
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let mut lines = text.lines();
        if lines.next() != Some(FORMAT_V2) {
            // The phase-6 format: a bare CSN. What was read in the overlap
            // is not known: nothing up to the cursor is reported again.
            let cursor = Some(text.trim().to_owned()).filter(|c| time::valid_csn(c));
            return Self {
                floor: cursor.clone(),
                cursor,
                ..Self::default()
            };
        }
        let mut p = Self::default();
        for line in lines {
            let Some((key, csn)) = line.split_once(' ') else {
                continue;
            };
            if !time::valid_csn(csn) {
                continue;
            }
            match key {
                "cursor" => p.cursor = Some(csn.to_owned()),
                "floor" => p.floor = Some(csn.to_owned()),
                "handing" => p.handing = Some(csn.to_owned()),
                "seen" if p.seen.len() < MAX_PERSISTED_SEEN => {
                    p.seen.insert(csn.to_owned());
                }
                _ => {}
            }
        }
        if p.cursor.is_none() {
            return Self::default();
        }
        p
    }

    /// The persisted form: the cursor, the floor, and the CSNs read from
    /// the start of the next overlap (at most [`MAX_PERSISTED_SEEN`], the
    /// newest; the newest one left out becomes the floor).
    pub(crate) fn encode(&self) -> Option<String> {
        let cursor = self.cursor.as_deref()?;
        let bound = time::csn_time(cursor)
            .map(|t| time::csn_at(t.checked_sub(OVERLAP).unwrap_or(t)))
            .unwrap_or_default();
        let window: Vec<&String> = self.seen.range(bound.clone()..).collect();
        let cut = window.len().saturating_sub(MAX_PERSISTED_SEEN);
        let mut floor = self.floor.clone().filter(|f| *f >= bound);
        if let Some(newest_left_out) = cut.checked_sub(1).and_then(|i| window.get(i)) {
            if floor.as_ref().is_none_or(|f| *newest_left_out > f) {
                floor = Some((*newest_left_out).clone());
            }
        }
        let mut out = format!("{FORMAT_V2}\ncursor {cursor}\n");
        if let Some(f) = floor {
            out.push_str(&format!("floor {f}\n"));
        }
        if let Some(h) = &self.handing {
            out.push_str(&format!("handing {h}\n"));
        }
        for csn in window.iter().skip(cut) {
            // The entry being handed over is not read yet: after a crash
            // it is read again (or skipped on the core's request).
            if self.handing.as_ref() == Some(*csn) {
                continue;
            }
            out.push_str("seen ");
            out.push_str(csn);
            out.push('\n');
        }
        Some(out)
    }

    /// Where the first search of a poll starts: the cursor minus the
    /// overlap, or the agent's clock minus a minute on a first start.
    fn from(&self, now: SystemTime) -> String {
        match self.cursor.as_deref().and_then(time::csn_time) {
            Some(t) => time::csn_at(t.checked_sub(OVERLAP).unwrap_or(t)),
            None => time::csn_at(now.checked_sub(FIRST_START_BACK).unwrap_or(now)),
        }
    }

    /// Whether `csn` was not read yet (nothing marked).
    fn unread(&self, csn: &str) -> bool {
        !self.seen.contains(csn) && self.floor.as_deref().is_none_or(|f| csn > f)
    }

    /// Whether `csn` is new; marks it read.
    fn fresh(&mut self, csn: &str) -> bool {
        if !self.unread(csn) {
            return false;
        }
        self.seen.insert(csn.to_owned());
        while self.seen.len() > MAX_SEEN {
            self.seen.pop_first();
        }
        true
    }

    /// Advances the cursor and forgets CSNs older than the overlap.
    fn advance(&mut self, csn: &str) {
        if self.cursor.as_deref().is_none_or(|c| csn > c) {
            self.cursor = Some(csn.to_owned());
        }
        if let Some(bound) = self
            .cursor
            .as_deref()
            .and_then(time::csn_time)
            .and_then(|t| t.checked_sub(OVERLAP * 2))
            .map(time::csn_at)
        {
            self.seen = self.seen.split_off(&bound);
        }
    }
}

/// One poll's worth of records, sorted by CSN, and what was dropped.
struct Polled {
    records: Vec<Record>,
    dropped: u64,
    /// The server cut the last search.
    more: bool,
    max_csn: Option<String>,
}

/// One search of the log from `from` (inclusive). Each entry is parsed in
/// isolation: one that makes the parser panic is dropped alone and
/// counted (phase-7 review H1).
async fn read_log<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    base: &str,
    from: &str,
) -> Result<Polled, LdError> {
    let search = Search {
        base,
        scope: Scope::One,
        size_limit: PAGE,
        time_limit: 0,
        types_only: false,
        filter: Filter::Ge("entryCSN", from.to_owned()),
        attributes: &records::LOG_ATTRIBUTES,
    };
    let mut out = Polled {
        records: Vec::new(),
        dropped: 0,
        more: false,
        max_csn: None,
    };
    let mut on_entry = |e: Entry| match databastion_core::isolate(|| {
        #[cfg(test)]
        test_poison(&e);
        records::parse(&e)
    }) {
        Some(Ok(r)) => out.records.push(r),
        Some(Err(())) | None => out.dropped += 1,
    };
    let outcome = s.search(Stage::Audit, &search, &mut on_entry).await?;
    if let Some(e) = outcome.error(Stage::Audit) {
        return Err(e);
    }
    out.more = outcome.cut();
    out.records.sort_by(|a, b| a.csn.cmp(&b.csn));
    out.max_csn = out.records.last().map(|r| r.csn.clone());
    Ok(out)
}

/// Tests: an entry whose `reqDN` holds this marker makes the parsing panic
/// (a parser bug on one log entry); one whose `reqDN` holds
/// [`TEST_CONVERT_POISON`] makes the event conversion panic.
#[cfg(test)]
pub(crate) const TEST_PARSE_POISON: &str = "cn=test-parser-panic";
/// See [`TEST_PARSE_POISON`].
#[cfg(test)]
pub(crate) const TEST_CONVERT_POISON: &str = "cn=test-convert-panic";

#[cfg(test)]
#[allow(clippy::panic)]
fn test_poison(e: &Entry) {
    if e.first_str("reqDN")
        .is_some_and(|d| d.contains(TEST_PARSE_POISON))
    {
        panic!("parser bug on a log entry");
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
fn test_convert_poison(r: &Record) {
    if r.target.contains(TEST_CONVERT_POISON) {
        panic!("conversion bug on a log entry");
    }
}

/// What the stream needs from the server, re-read at each re-probe.
struct Probe {
    contexts: Vec<Context>,
}

async fn probe<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    target: &TargetConfig,
) -> Result<Probe, LdError> {
    let base = target.openldap_settings().accesslog_base;
    let dse = catalog::root_dse(s, Stage::Audit).await?;
    if !check::base_readable(s, &base).await? {
        tracing::warn!(
            target_id = %target.id,
            "cn=accesslog not readable by the service DN: no Audit source"
        );
        return Err(LdError::new(FailureCode::Unsupported, Stage::Audit));
    }
    let contexts = check::data_contexts(&dse, &base)
        .into_iter()
        .map(|(raw, canon)| Context {
            canon,
            name: normalize_ldap_dn(&raw),
        })
        .collect();
    Ok(Probe { contexts })
}

/// `Connector::audit_stream` for OpenLDAP.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg.target().ok_or_else(internal)?;
    let _running = state.stream_started(&target.id);
    let timeouts = Timeouts::new(cfg.statement_timeout().min(Duration::from_secs(30)));
    let store = cfg.cursor(CURSOR);
    let mut position = Position::load(store.as_ref());
    let mut builder: Option<EventBuilder> = None;
    loop {
        let mut session = Session::connect(target, timeouts)
            .await
            .map_err(LdError::into_connector_error)?;
        let p = probe(&mut session, target)
            .await
            .map_err(LdError::into_connector_error)?;
        let b = builder.get_or_insert_with(|| {
            tracing::info!(target_id = %target.id, "audit source: cn=accesslog");
            EventBuilder::new(
                OwnAccount::new(
                    &session.identity,
                    None,
                    None,
                    u64::from(cfg.max_sample_rows()),
                    state.own_usage(&target.id),
                )
                .persisted(cfg),
                session.identity.clone(),
                u64::from(cfg.max_sample_rows()),
                cfg.sensitive_objects().to_vec(),
            )
        });
        b.set_contexts(p.contexts);
        b.set_clear_principals(&target.openldap_settings().clear_principals);
        run(
            cfg,
            target,
            sink,
            state,
            &mut session,
            b,
            &mut position,
            store.as_ref(),
        )
        .await?;
        session.close().await;
    }
}

/// Polls the log for up to [`REPROBE`].
#[allow(clippy::too_many_arguments)]
async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    cfg: &AuditConfig,
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    session: &mut Session<S>,
    builder: &mut EventBuilder,
    position: &mut Position,
    store: Option<&CursorStore>,
) -> Result<(), ConnectorError> {
    let base = target.openldap_settings().accesslog_base;
    let started = Instant::now();
    loop {
        poll(
            target, sink, state, session, builder, position, store, &base,
        )
        .await?;
        if started.elapsed() >= REPROBE {
            return Ok(());
        }
        tokio::time::sleep(cfg.poll_interval()).await;
    }
}

/// One poll: searches from the overlap, then from the newest CSN while
/// the server cuts the result.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll<S: AsyncRead + AsyncWrite + Unpin>(
    target: &TargetConfig,
    sink: &EventSink,
    state: &CheckState,
    session: &mut Session<S>,
    builder: &mut EventBuilder,
    position: &mut Position,
    store: Option<&CursorStore>,
    base: &str,
) -> Result<(), ConnectorError> {
    let mut from = position.from(SystemTime::now());
    for _ in 0..MAX_ROUNDS {
        let polled = read_log(session, base, &from)
            .await
            .map_err(LdError::into_connector_error)?;
        if polled.dropped > 0 {
            state.note_dropped(&target.id, polled.dropped);
            tracing::warn!(
                target_id = %target.id,
                dropped = polled.dropped,
                "accesslog entries that do not parse dropped"
            );
        }
        let mut fresh = Vec::with_capacity(polled.records.len());
        let mut proven: HashSet<String> = HashSet::new();
        let save = |position: &Position| {
            if let (Some(store), Some(c)) = (store, position.encode()) {
                if let Err(e) = store.save(c.as_bytes()) {
                    tracing::warn!(target_id = %target.id, error = %e, "audit cursor not saved");
                }
            }
        };
        for r in polled.records {
            if !position.fresh(&r.csn) {
                continue;
            }
            if position.skip > 0 && position.handing.as_deref() == Some(r.csn.as_str()) {
                // The core's request: the stream panicked repeatedly at
                // this exact position, in isolation mode, while handing
                // over this entry. Dropped, counted, and the position
                // saved past it.
                position.skip -= 1;
                position.handing = None;
                state.note_dropped(&target.id, 1);
                tracing::warn!(
                    target_id = %target.id,
                    "accesslog entry skipped: the stream failed on it repeatedly"
                );
                position.advance(&r.csn);
                save(position);
                continue;
            }
            if r.op == Op::Search {
                if let Some(c) = builder_context(builder, &r) {
                    // Proof of logged reads: a search that succeeded (or
                    // returned entries); a failed one that returned
                    // entries proves failures are logged too.
                    if r.result == 0 || r.entries.is_some_and(|n| n > 0) {
                        proven.insert(c.clone());
                    }
                    if r.result != 0 && r.entries.is_some_and(|n| n > 0) {
                        state.note_failures_logged(&target.id, &c, true);
                    }
                }
            }
            if position.isolate_left > 0 {
                // Isolation mode: handed over and saved one by one, so a
                // panic is at the exact entry at fault.
                position.isolate_left -= 1;
                let csn = r.csn.clone();
                position.handing = Some(csn.clone());
                save(position);
                for e in convert(builder, vec![r]) {
                    sink.submit(e).await?;
                }
                position.handing = None;
                position.advance(&csn);
                save(position);
                continue;
            }
            // Read outside isolation: no longer the entry being handed over.
            if position.handing.as_deref() == Some(r.csn.as_str()) {
                position.handing = None;
            }
            fresh.push(r);
        }
        for c in proven {
            state.note_search(&target.id, &c);
        }
        let events = convert(builder, fresh);
        for e in events {
            sink.submit(e).await?;
        }
        // Everything read so far was handed over: move the cursor.
        if let Some(max) = &polled.max_csn {
            position.advance(max);
            save(position);
        }
        // Isolation mode and a skip request last one round (PR #83
        // re-review L-B): past it, the entry at fault was handed over or
        // skipped, or the panic was elsewhere.
        position.isolate_left = 0;
        position.skip = 0;
        if !polled.more {
            return Ok(());
        }
        // Next round: from the newest CSN read (already seen, skipped).
        match (&polled.max_csn, position.cursor.as_deref()) {
            (Some(max), Some(cursor)) => from = max.clone().max(cursor.to_owned()),
            _ => return Ok(()),
        }
    }
    tracing::info!(
        target_id = %target.id,
        "accesslog backlog larger than one poll: continuing at the next poll"
    );
    Ok(())
}

/// The events of `records` (a panic here reaches the core's guard: the
/// core then restarts the stream in isolation mode, see
/// `CursorStore::isolate`).
fn convert(builder: &mut EventBuilder, records: Vec<Record>) -> Vec<MaskedEvent> {
    #[cfg(test)]
    for r in &records {
        test_convert_poison(r);
    }
    builder.convert(records, Instant::now())
}

/// The canonical naming context of a record's `reqDN`, if known.
fn builder_context(builder: &EventBuilder, r: &Record) -> Option<String> {
    builder.context_of(&r.target_canon).map(|c| c.canon.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_start_from_the_cursor_minus_the_overlap() {
        let mut p = Position::default();
        let now = time::parse_generalized("20260929202700Z").unwrap();
        assert_eq!(p.from(now), "20260929202600.000000Z#000000#000#000000");
        let a = "20260929202642.012954Z#000000#000#000000";
        assert!(p.fresh(a));
        assert!(!p.fresh(a));
        p.advance(a);
        assert_eq!(p.cursor.as_deref(), Some(a));
        assert_eq!(p.from(now), "20260929202632.012954Z#000000#000#000000");
        // An older CSN never moves the cursor back.
        p.advance("20260929202600.000000Z#000000#000#000000");
        assert_eq!(p.cursor.as_deref(), Some(a));
        // CSNs older than twice the overlap are forgotten.
        let later = "20260929203000.000000Z#000000#000#000000";
        p.advance(later);
        assert!(p.fresh(a));
    }

    /// End-of-phase-6 review L3: after a restart, the overlap is read
    /// again; the entries read before are not reported twice, and one
    /// committed out of CSN order just before the restart is reported.
    #[test]
    fn the_overlap_holds_across_a_restart() {
        let dir =
            std::env::temp_dir().join(format!("databastion-ldap-overlap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
        let a = "20260929202640.000000Z#000000#000#000000";
        let b = "20260929202642.000000Z#000000#000#000000";
        let late = "20260929202641.000000Z#000000#000#000000";
        let mut p = Position::default();
        assert!(p.fresh(a) && p.fresh(b));
        p.advance(b);
        store.save(p.encode().unwrap().as_bytes()).unwrap();
        // Restart.
        let mut p = Position::load(Some(&store));
        assert_eq!(p.cursor.as_deref(), Some(b));
        assert_eq!(
            p.from(SystemTime::now()),
            "20260929202632.000000Z#000000#000#000000"
        );
        assert!(!p.fresh(a) && !p.fresh(b));
        assert!(p.fresh(late), "an entry committed out of order was lost");
        // A long overlap: only the newest CSNs are kept, the newest one
        // left out becomes the floor (never reported twice).
        let mut p = Position::default();
        let csns: Vec<String> = (0..MAX_PERSISTED_SEEN + 5)
            .map(|i| format!("20260929202642.{i:06}Z#000000#000#000000"))
            .collect();
        for c in &csns {
            assert!(p.fresh(c));
        }
        p.advance(csns.last().unwrap());
        let encoded = p.encode().unwrap();
        assert!(encoded.len() < 64 * 1024);
        store.save(encoded.as_bytes()).unwrap();
        let mut p = Position::load(Some(&store));
        for c in &csns {
            assert!(!p.fresh(c), "{c} reported twice");
        }
        assert!(p.fresh("20260929202642.999999Z#000000#000#000000"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_cursors_must_be_csns() {
        let dir =
            std::env::temp_dir().join(format!("databastion-ldap-cursor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
        store.save(b"not a csn").unwrap();
        assert_eq!(Position::load(Some(&store)).cursor, None);
        store.save(b"v2\ncursor not a csn\nseen x\n").unwrap();
        assert_eq!(Position::load(Some(&store)).cursor, None);
        store
            .save(b"20260929202642.012954Z#000000#000#000000")
            .unwrap();
        let mut p = Position::load(Some(&store));
        assert!(p.cursor.is_some());
        // A cursor of the phase-6 format: after a restart, entries up to
        // it (read again in the overlap) are not reported twice.
        assert!(!p.fresh("20260929202642.012954Z#000000#000#000000"));
        assert!(!p.fresh("20260929202640.000000Z#000000#000#000000"));
        assert!(p.fresh("20260929202642.012955Z#000000#000#000000"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
