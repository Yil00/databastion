//! OpenLDAP Audit (phase 6, ADR-0029 decisions 7 to 10): access events
//! from `cn=accesslog` (`slapo-accesslog`), read over LDAP with the
//! agent's connection.
//!
//! - Incremental by `entryCSN` (commit order), with a 10 s overlap and the
//!   CSNs already read, so log entries committed out of order are not
//!   missed; the cursor (a CSN) is persisted by the core.
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

fn internal() -> ConnectorError {
    LdError::new(FailureCode::Internal, Stage::Audit).into_connector_error()
}

/// The read position: the newest CSN handed to the core, and the CSNs
/// read within the overlap.
#[derive(Debug, Default)]
pub(crate) struct Position {
    pub(crate) cursor: Option<String>,
    seen: BTreeSet<String>,
}

impl Position {
    /// From a persisted cursor (ignored unless it is a CSN).
    pub(crate) fn load(store: Option<&CursorStore>) -> Self {
        let cursor = store
            .and_then(|s| match s.load() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "audit cursor unreadable: starting from now");
                    None
                }
            })
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|c| time::valid_csn(c));
        Self {
            cursor,
            seen: BTreeSet::new(),
        }
    }

    /// Where the first search of a poll starts: the cursor minus the
    /// overlap, or the agent's clock minus a minute on a first start.
    fn from(&self, now: SystemTime) -> String {
        match self.cursor.as_deref().and_then(time::csn_time) {
            Some(t) => time::csn_at(t.checked_sub(OVERLAP).unwrap_or(t)),
            None => time::csn_at(now.checked_sub(FIRST_START_BACK).unwrap_or(now)),
        }
    }

    /// Whether `csn` is new; marks it read.
    fn fresh(&mut self, csn: &str) -> bool {
        if self.seen.contains(csn) {
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

/// One search of the log from `from` (inclusive).
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
    let mut on_entry = |e: Entry| match records::parse(&e) {
        Ok(r) => out.records.push(r),
        Err(()) => out.dropped += 1,
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
                ),
                session.identity.clone(),
                u64::from(cfg.max_sample_rows()),
                cfg.sensitive_objects().to_vec(),
            )
        });
        b.set_contexts(p.contexts);
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
        for r in polled.records {
            if !position.fresh(&r.csn) {
                continue;
            }
            if r.op == Op::Search {
                if let Some(c) = builder_context(builder, &r) {
                    proven.insert(c);
                }
            }
            fresh.push(r);
        }
        for c in proven {
            state.note_search(&target.id, &c);
        }
        let events = builder.convert(fresh, Instant::now());
        for e in events {
            sink.submit(e).await?;
        }
        // Everything read so far was handed over: move the cursor.
        if let Some(max) = &polled.max_csn {
            position.advance(max);
            if let (Some(store), Some(c)) = (store, position.cursor.as_deref()) {
                if let Err(e) = store.save(c.as_bytes()) {
                    tracing::warn!(target_id = %target.id, error = %e, "audit cursor not saved");
                }
            }
        }
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

    #[test]
    fn persisted_cursors_must_be_csns() {
        let dir =
            std::env::temp_dir().join(format!("databastion-ldap-cursor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
        store.save(b"not a csn").unwrap();
        assert_eq!(Position::load(Some(&store)).cursor, None);
        store
            .save(b"20260929202642.012954Z#000000#000#000000")
            .unwrap();
        assert!(Position::load(Some(&store)).cursor.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
