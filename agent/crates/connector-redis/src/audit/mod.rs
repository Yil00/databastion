//! Redis / Valkey Audit (ADR-0052 decision 8): Limited at best, from the
//! servers' own logs, polled over the stream's own connection.
//!
//! - **Sources**: `SLOWLOG GET 512` (Redis, Valkey before 8.1) or
//!   `COMMANDLOG GET 512 slow` (Valkey 8.1+, the same log) as
//!   `redis_slowlog`; `COMMANDLOG GET 512 large-reply` (Valkey 8.1+) as
//!   `redis_commandlog`, with the reply size as `bytes`; `ACL LOG 128` as
//!   `redis_acl_log`; `INFO stats` `sync_full` deltas as `redis_sync`.
//!   Each read is sent only when `ACL DRYRUN` says the account may run it
//!   (H3); on Redis 6.2 (no `DRYRUN`, opt-in only) a read refused once is
//!   not sent again by the stream.
//! - **Positions**: per log, the highest entry id read, persisted through
//!   the core; a gap between it and the oldest entry returned is counted
//!   in `audit.records_dropped`; a server restart (`run_id`, compared as a
//!   hash, never sent) resets them; the first start begins at the newest
//!   entry (no history replay).
//! - **Reduction at parse time** ([`entries`]): no argument value is kept;
//!   key arguments become learned patterns ([`commands`] gives their
//!   positions; `classifiers::keys::LearnedPatterns` the objects).
//! - **Attribution** (L2): `CLIENT LIST` maps an entry's `addr:port` to the
//!   user of the connection still open there, only when that connection is
//!   older than the entry; otherwise `account_not_recorded`.
//! - **The agent's own entries** ([`own`], H3): by connection id or by the
//!   `addr:port` of one of its connections within its lifetime, never by
//!   user or client name; left out only for its own command shapes and
//!   within the own-read budget. Each session records the address the
//!   server reports for it at connect time (`CLIENT LIST ID`), so a session
//!   closed before the stream's next `CLIENT LIST` is still recognized.
//! - Per-record panic isolation: each entry is parsed and converted under
//!   `databastion_core::isolate`; a failing entry is dropped and counted.

pub(crate) mod commands;
pub(crate) mod entries;
pub(crate) mod own;
pub(crate) mod state;

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::keys::LearnedPatterns;
use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::{self, NormalizedName};
use databastion_core::audit::CursorStore;
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::config::TargetConfig;
use databastion_core::{AuditConfig, ConnectorError, Engine, EventSink, FailureCode};

use crate::acl::AuditGrants;
use crate::check::CheckState;
use crate::cmd::{Cmd, CommandLog, InfoSection};
use crate::conn::Session;
use crate::error::{RdError, Stage};
use crate::info::{self, Server};
use crate::node::{self, Which};
use crate::resp::{ErrorWord, Value};
use entries::{AclEntry, Client, Context, LogEntry, OwnShape, Peer, Reason};

/// Timeout of each Audit poll command (decision 1).
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
/// Name of the cursor file.
const CURSOR: &str = "redis_audit";
/// Name of the learned-patterns file (counters: never part of the
/// position).
const LEARNED: &str = "learned_patterns";
/// A connection must be at least this much older than an entry to be
/// attributed with it (L2: a port reused by a newer connection is not).
const ATTRIBUTION_MARGIN_S: i64 = 2;
/// `ACL LOG` entries whose counts are remembered.
const MAX_ACL_COUNTS: usize = 256;

fn target_error(code: FailureCode) -> ConnectorError {
    ConnectorError::Target {
        engine: Engine::Redis,
        code,
        engine_code: None,
    }
}

/// The persisted position (numbers only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    /// Hash of the server's `run_id` (compared, never sent).
    pub(crate) run: Option<u64>,
    /// Highest entry id read per log (`None`: not started).
    pub(crate) slow: Option<i64>,
    pub(crate) large: Option<i64>,
    pub(crate) acl: Option<i64>,
    /// Last `sync_full`.
    pub(crate) sync: Option<u64>,
    /// `ACL LOG` entry id → count already reported.
    pub(crate) acl_counts: BTreeMap<i64, u64>,
}

impl Cursor {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let opt = |v: Option<i64>| v.map_or("-".to_owned(), |v| v.to_string());
        let mut out = format!(
            "v1\nrun {}\nslow {}\nlarge {}\nacl {}\nsync {}\n",
            self.run.map_or("-".to_owned(), |r| format!("{r:x}")),
            opt(self.slow),
            opt(self.large),
            opt(self.acl),
            self.sync.map_or("-".to_owned(), |v| v.to_string()),
        );
        for (id, c) in &self.acl_counts {
            out.push_str(&format!("c {id} {c}\n"));
        }
        out.into_bytes()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        if lines.next()? != "v1" {
            return None;
        }
        let mut c = Self::default();
        for l in lines {
            let mut parts = l.split(' ');
            let (k, v) = (parts.next()?, parts.next()?);
            let i = || -> Option<Option<i64>> {
                if v == "-" {
                    Some(None)
                } else {
                    v.parse().ok().map(Some)
                }
            };
            match k {
                "run" => {
                    c.run = if v == "-" {
                        None
                    } else {
                        Some(u64::from_str_radix(v, 16).ok()?)
                    };
                }
                "slow" => c.slow = i()?,
                "large" => c.large = i()?,
                "acl" => c.acl = i()?,
                "sync" => {
                    c.sync = if v == "-" {
                        None
                    } else {
                        Some(v.parse().ok()?)
                    }
                }
                "c" => {
                    if c.acl_counts.len() < MAX_ACL_COUNTS {
                        c.acl_counts
                            .insert(v.parse().ok()?, parts.next()?.parse().ok()?);
                    }
                }
                _ => return None,
            }
        }
        Some(c)
    }
}

/// The Audit level and notes of a target (decision 8; `check()` and the
/// stream use this rule).
pub(crate) fn level(
    state: &CheckState,
    target_id: &str,
    grants: Option<AuditGrants>,
    refused: bool,
) -> (
    databastion_core::AuditLevel,
    Vec<databastion_core::TargetNote>,
) {
    use databastion_core::{AuditLevel, NoteCode, TargetNote};
    let mut notes = Vec::new();
    let dropped = state.audit.dropped(target_id);
    let level = if refused {
        notes.push(TargetNote::new(NoteCode::AuditStreamNotAvailable));
        AuditLevel::None
    } else {
        // `None` grants (Redis 6.2): not evaluated, tried by the stream.
        let slow = grants.is_none_or(|g| g.slowlog != Some(false) || g.commandlog == Some(true));
        let acl = grants.is_none_or(|g| g.acl_log != Some(false));
        // A stream must run (Audit configured) and have read, in the last
        // 24 h, a new entry of another client (review L6).
        if !state.audit.is_running(target_id) {
            notes.push(TargetNote::new(NoteCode::AuditStreamNotAvailable));
            AuditLevel::None
        } else if slow && state.audit.recent_slow_record(target_id) {
            notes.push(TargetNote::new(NoteCode::AuditSlowOperationsOnly));
            AuditLevel::Limited
        } else if slow {
            notes.push(TargetNote::new(NoteCode::AuditLimitedPendingFirstRecord));
            notes.push(TargetNote::new(NoteCode::AuditSlowOperationsOnly));
            AuditLevel::None
        } else if acl {
            notes.push(TargetNote::new(NoteCode::AuditAclLogOnly));
            AuditLevel::None
        } else {
            notes.push(TargetNote::new(NoteCode::AuditLogNotReadable));
            AuditLevel::None
        }
    };
    if dropped > 0 {
        notes.push(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(dropped));
    }
    (level, notes)
}

/// Which slow-log read the stream sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlowRead {
    Slowlog,
    /// `COMMANDLOG GET … slow` (Valkey 8.1+, the same log).
    Commandlog,
}

/// Which reads the stream sends.
#[derive(Debug, Clone, Copy)]
struct Reads {
    slow: Option<SlowRead>,
    large: bool,
    acl: bool,
    client_list: bool,
}

fn reads_of(server: Server, grants: Option<AuditGrants>) -> Reads {
    // `None`: Redis 6.2, not evaluated: tried, and not sent again once
    // refused.
    let allowed = |v: Option<bool>| grants.is_none() || v == Some(true);
    let commandlog = server.has_commandlog() && grants.is_some_and(|g| g.commandlog == Some(true));
    let slow = if commandlog {
        Some(SlowRead::Commandlog)
    } else if allowed(grants.and_then(|g| g.slowlog)) {
        Some(SlowRead::Slowlog)
    } else {
        None
    };
    Reads {
        slow,
        large: commandlog,
        acl: allowed(grants.and_then(|g| g.acl_log)),
        client_list: allowed(grants.and_then(|g| g.client_list)),
    }
}

/// What one poll of `INFO` gave.
struct Infos {
    run: Option<u64>,
    /// Server time, Unix µs.
    now_us: Option<i64>,
    sync_full: Option<u64>,
    /// Databases holding keys.
    keyspace: Vec<u16>,
}

fn text(v: &Value) -> Option<&str> {
    v.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
}

async fn infos(s: &mut Session) -> Result<Infos, RdError> {
    let r = s
        .pipeline(
            &[
                Cmd::Info(InfoSection::Server),
                Cmd::Info(InfoSection::Stats),
                Cmd::Info(InfoSection::Keyspace),
            ],
            POLL_TIMEOUT,
            Stage::Introspection,
        )
        .await?;
    let [server, stats, keyspace] = r.as_slice() else {
        return Err(RdError::new(FailureCode::Unsupported, Stage::Introspection));
    };
    let server = text(server).unwrap_or_default();
    let stats = text(stats).unwrap_or_default();
    Ok(Infos {
        run: info::run_hash(server),
        now_us: info::field(server, "server_time_usec").and_then(|v| v.parse().ok()),
        sync_full: info::field(stats, "sync_full").and_then(|v| v.parse().ok()),
        keyspace: info::keyspace(text(keyspace).unwrap_or_default())
            .into_iter()
            .map(|(db, _)| db)
            .collect(),
    })
}

/// The addresses of the replicas `INFO replication` lists in a sync state
/// (`slaveN:ip=…,port=…,state=wait_bgsave|send_bulk`): an online replica
/// is not the one being fully synchronized (review L7).
fn syncing_replica_ips(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter(|l| {
            l.strip_prefix("slave")
                .and_then(|r| r.split_once(':'))
                .is_some_and(|(n, _)| n.bytes().all(|b| b.is_ascii_digit()) && !n.is_empty())
        })
        .filter_map(|l| {
            let fields = l.split_once(':')?.1.trim_end_matches('\r');
            let state = fields.split(',').find_map(|kv| kv.strip_prefix("state="))?;
            if !matches!(state, "wait_bgsave" | "send_bulk") {
                return None;
            }
            fields
                .split(',')
                .find_map(|kv| kv.strip_prefix("ip="))?
                .parse()
                .ok()
        })
        .take(64)
        .collect()
}

/// The database of slow-log entries (which record none): `db<index>` when
/// a single database holds keys, `*` otherwise; and the patterns usable
/// for it (that database's, or those learned in every database with keys).
fn log_database(
    learned: &state::Learned,
    keyspace: &[u16],
) -> (NormalizedName, Arc<LearnedPatterns>) {
    match keyspace {
        [db] => (
            names::normalize_path(&format!("db{db}")),
            learned.dbs.get(db).cloned().unwrap_or_default(),
        ),
        dbs => {
            let sets: Option<Vec<&LearnedPatterns>> = dbs
                .iter()
                .map(|d| learned.dbs.get(d).map(Arc::as_ref))
                .collect();
            let set = match sets {
                Some(s) if !s.is_empty() => LearnedPatterns::intersection(&s),
                _ => LearnedPatterns::default(),
            };
            (NormalizedName::wildcard(), Arc::new(set))
        }
    }
}

/// Reads one log; `Ok(None)` when the server refused it (Redis 6.2 without
/// the grant: not sent again).
async fn read_log(s: &mut Session, cmd: &Cmd<'_>) -> Result<Option<Vec<Value>>, RdError> {
    let v = s.call(cmd, POLL_TIMEOUT, Stage::Introspection).await?;
    match v {
        Value::Array(items) => Ok(Some(items)),
        Value::Error(ErrorWord::Noperm) => Ok(None),
        Value::Error(w) => Err(RdError::reply(w, Stage::Introspection)),
        _ => Err(RdError::new(FailureCode::Unsupported, Stage::Introspection)),
    }
}

/// Parses every entry of a log reply, each alone under panic isolation:
/// an entry that does not parse, or makes the parser panic, is dropped
/// and counted.
fn parse_logs(items: &[Value], ctx: &Context<'_>) -> (Vec<LogEntry>, u64) {
    let mut parsed = Vec::with_capacity(items.len());
    let mut malformed = 0u64;
    for v in items {
        match databastion_core::isolate(|| {
            #[cfg(test)]
            test_poison(v);
            entries::parse_log_entry(v, ctx)
        }) {
            Some(Ok(e)) => parsed.push(e),
            _ => malformed += 1,
        }
    }
    (parsed, malformed)
}

/// The entries of a log newer than `cursor`, oldest first, and how many
/// were lost before them (a gap in the ids).
fn new_entries(all: Vec<LogEntry>, cursor: Option<i64>) -> (Vec<LogEntry>, u64, Option<i64>) {
    let newest = all.iter().map(|e| e.id).max();
    let Some(c) = cursor else {
        // First start: from the newest entry, no history replay.
        return (Vec::new(), 0, newest.or(Some(-1)));
    };
    let mut fresh: Vec<LogEntry> = all.into_iter().filter(|e| e.id > c).collect();
    fresh.sort_by_key(|e| e.id);
    let lost = fresh
        .first()
        .map_or(0, |e| u64::try_from(e.id - c - 1).unwrap_or(0));
    let next = newest.map_or(Some(c), |n| Some(n.max(c)));
    (fresh, lost, next)
}

/// Attribution of a log entry from `CLIENT LIST` (L2).
fn attribute(clients: &[Client], peer: Peer, ts: i64, now_s: i64) -> Option<&Client> {
    clients.iter().find(|c| {
        c.peer == Some(peer)
            && c.age_s.is_some_and(|age| {
                now_s - i64::try_from(age).unwrap_or(i64::MAX / 2) + ATTRIBUTION_MARGIN_S <= ts
            })
    })
}

fn system_time(unix_s: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(unix_s).unwrap_or(0))
}

/// The stream's per-run state.
struct Stream<'a> {
    cfg: &'a AuditConfig,
    target: &'a TargetConfig,
    state: &'a CheckState,
    own: OwnAccount,
    store: Option<CursorStore>,
    cursor: Cursor,
    saved: Option<Vec<u8>>,
    /// Records the core asks to skip (isolation after panics).
    skip: u32,
    acl_ident_key: std::collections::hash_map::RandomState,
    /// `ACL LOG` counts by identity and position, for servers without
    /// entry ids.
    acl_idents: Option<HashMap<(u64, u32), u64>>,
    /// The server run of the current poll ([`info::run_hash`]).
    run: Option<u64>,
}

impl Stream<'_> {
    fn save(&mut self) {
        let Some(store) = &self.store else { return };
        let bytes = self.cursor.encode();
        if self.saved.as_ref() == Some(&bytes) {
            return;
        }
        match store.save(&bytes) {
            Ok(()) => self.saved = Some(bytes),
            Err(e) => tracing::warn!(error = %e, "Redis / Valkey Audit cursor not saved"),
        }
    }

    fn isolate_mode(&self) -> bool {
        self.store.as_ref().is_some_and(CursorStore::isolate)
    }

    /// Whether to skip this record (the core's request after panics at
    /// exactly this position).
    fn take_skip(&mut self) -> bool {
        if self.skip > 0 {
            self.skip -= 1;
            self.state.audit.note_dropped(&self.target.id, 1);
            return true;
        }
        false
    }

    /// The event of a slow-log or command-log entry; `None` when it gives
    /// none (an ignored command, or the agent's own routine entry).
    fn log_event(
        &mut self,
        e: &LogEntry,
        source: EventSource,
        database: &NormalizedName,
        clients: &[Client],
        now_s: i64,
        offset_s: i64,
    ) -> Option<MaskedEvent> {
        let ts = system_time(e.ts);
        // A Unix-socket peer is never attributed: every socket client has
        // the same address (review H1). A TCP peer is attributed through
        // `CLIENT LIST` (L2); the agent's own connection (H3) is the
        // attributed connection when there is one (its id, review M1),
        // else its address within its lifetime; never its user or client
        // name.
        let tcp = e.peer.filter(|p| p.socket().is_some());
        let attributed = tcp.and_then(|p| attribute(clients, p, e.ts, now_s));
        let own_conn = match attributed {
            Some(c) => {
                c.id.is_some_and(|id| own::is_own_open_id(&self.target.id, id, self.run))
            }
            None => tcp.and_then(Peer::socket).is_some_and(|a| {
                own::is_own_addr(&self.target.id, a, system_time(e.ts - offset_s), self.run)
            }),
        };
        // A new entry of another client proves the log is read (review
        // L6).
        if source == EventSource::RedisSlowlog && !own_conn {
            self.state.audit.note_slow_record(&self.target.id);
        }
        let action = e.action.event_action()?;
        let client = e.peer.map(|p| p.addr);
        let principal = match attributed.and_then(|c| c.user.as_ref()) {
            Some(user) => EventPrincipal::account(user),
            None if own_conn => EventPrincipal::account(&self.target.account),
            None => EventPrincipal::not_recorded(),
        }
        .with_client(client)
        .with_application(e.app.as_deref().unwrap_or(""));
        let mut ev = MaskedEvent::new(source, action, principal, ts);
        for o in &e.objects {
            ev = ev.with_object(EventObject::new(database.clone(), None, o.clone()));
        }
        for s in &e.signals {
            ev = ev.with_signal(*s);
        }
        if e.action == commands::Action::Script {
            ev = ev.with_always_report();
        }
        // The own-entry rule looks at the command, before the large-reply
        // signal of its source: the agent's own Audit reads (`SLOWLOG GET`,
        // `CLIENT LIST`…) have large replies by nature; its sampling
        // commands are bounded (decision 6).
        // A large reply above what the agent's client accepts for the
        // shape is never its routine (review L1).
        let over = source == EventSource::RedisCommandlog && e.size > e.own.max_reply();
        if own_conn && !over {
            // The attributed user, so the core's own-account rule applies
            // to it (review M1).
            let user = attributed
                .and_then(|c| c.user.as_ref())
                .map_or_else(|| self.target.account.clone(), |u| u.to_string());
            let routine = match e.own {
                OwnShape::No => false,
                OwnShape::Unkeyed { .. } => {
                    self.own
                        .routine_unbudgeted(&user, None, ClientSeen::NotRecorded, &ev)
                }
                OwnShape::Keyed { rows, .. } => {
                    let charged = ev.clone().with_rows(Some(rows));
                    self.own.routine(
                        &user,
                        None,
                        ClientSeen::NotRecorded,
                        &charged,
                        Instant::now(),
                    )
                }
            };
            if routine {
                return None;
            }
        }
        if source == EventSource::RedisCommandlog {
            ev = ev.with_signal(Signal::LargeReply).with_bytes(Some(e.size));
        }
        Some(ev)
    }

    /// The events of an `ACL LOG` entry (its count delta), if any.
    fn acl_event(&mut self, e: &AclEntry, delta: u64, offset_s: i64) -> Option<MaskedEvent> {
        if delta == 0 {
            return None;
        }
        let client = e.client.as_ref();
        // Entries of the agent's own connections (H3): a declaration that
        // does not match the ACL, reported by `check()`. The id must be of
        // the current server run and the entry within the connection's
        // lifetime (review M2).
        let at = e
            .updated_ms
            .map_or_else(SystemTime::now, |ms| system_time(ms / 1000 - offset_s));
        if client
            .and_then(|c| c.id)
            .is_some_and(|id| own::is_own_id_at(&self.target.id, id, self.run, at))
        {
            if e.reason != Reason::Auth {
                self.state.audit.note_own_denial(&self.target.id, delta);
            }
            return None;
        }
        let addr = client.and_then(|c| c.peer).map(|p| p.addr);
        let app = client.and_then(|c| c.app.as_deref()).unwrap_or("");
        let ts = e.updated_ms.map_or_else(SystemTime::now, |ms| {
            SystemTime::UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0))
        });
        let ev = if e.reason == Reason::Auth {
            // The name tried is always fingerprinted (core rule).
            MaskedEvent::new(
                EventSource::RedisAclLog,
                EventAction::AuthFailure,
                EventPrincipal::failed_account(&e.user)
                    .with_client(addr)
                    .with_application(app),
                ts,
            )
        } else {
            // Denials of other users: nothing was read, no event; the
            // agent's own user from another connection: someone using its
            // credentials.
            if e.user.as_str() != self.target.account {
                return None;
            }
            let action = e.action.event_action().unwrap_or(EventAction::Read);
            let database = client
                .and_then(|c| c.db)
                .map_or_else(NormalizedName::wildcard, |db| {
                    names::normalize_path(&format!("db{db}"))
                });
            let mut ev = MaskedEvent::new(
                EventSource::RedisAclLog,
                action,
                EventPrincipal::account(&e.user)
                    .with_client(addr)
                    .with_application(app),
                ts,
            )
            .with_object(EventObject::new(database, None, e.object.clone()));
            for s in &e.signals {
                ev = ev.with_signal(*s);
            }
            ev
        };
        Some(ev.with_aggregate(delta, ts))
    }
}

/// The count delta of each `ACL LOG` entry since the last poll, and the
/// entries lost (a gap in the ids). With entry ids (Redis 7.2+, Valkey):
/// a new id reports its whole count, a known one its growth; without
/// (Redis before 7.2): counts by identity, in memory. The first poll (an
/// empty log included) is the baseline: no history replay.
fn acl_deltas<'e>(
    cursor: &mut Cursor,
    idents: &mut Option<HashMap<(u64, u32), u64>>,
    acl: &'e [AclEntry],
) -> (Vec<(u64, &'e AclEntry)>, u64) {
    let mut events = Vec::new();
    let mut lost = 0;
    if acl.iter().any(|e| e.id.is_some()) {
        let first = cursor.acl.is_none();
        let from = cursor.acl.unwrap_or(-1);
        let mut new_ids: Vec<i64> = Vec::new();
        let mut counts = BTreeMap::new();
        for e in acl {
            let Some(id) = e.id else { continue };
            let delta = if first {
                0
            } else if id > from {
                new_ids.push(id);
                e.count
            } else {
                e.count
                    .saturating_sub(cursor.acl_counts.get(&id).copied().unwrap_or(e.count))
            };
            counts.insert(id, e.count);
            events.push((delta, e));
        }
        if !first && let Some(max) = new_ids.iter().max() {
            let expected = u64::try_from(max - from).unwrap_or(0);
            lost = expected.saturating_sub(new_ids.len() as u64);
        }
        let newest = counts.keys().max().copied();
        cursor.acl = Some(newest.map_or(from, |n| n.max(from)));
        while counts.len() > MAX_ACL_COUNTS {
            counts.pop_first();
        }
        cursor.acl_counts = counts;
    } else {
        if acl.is_empty() && cursor.acl.is_none() {
            cursor.acl = Some(-1);
        }
        // Redis groups identical denials for 60 s only: later ones are new
        // entries of the same identity. Each entry is keyed by its identity
        // and its position among the entries of that identity, counted from
        // the oldest (the log lists the newest first); a new position is a
        // new entry, reported with its whole count (review M3).
        let first = idents.is_none();
        let known = idents.get_or_insert_with(HashMap::new);
        let mut next = HashMap::new();
        let mut seen: HashMap<u64, u32> = HashMap::new();
        let mut keyed: Vec<(u64, &'e AclEntry)> = Vec::with_capacity(acl.len());
        for e in acl.iter().rev() {
            let pos = seen.entry(e.ident).or_insert(0);
            let key = (e.ident, *pos);
            *pos += 1;
            let delta = if first {
                0
            } else {
                e.count
                    .saturating_sub(known.get(&key).copied().unwrap_or(0))
            };
            next.insert(key, e.count);
            keyed.push((delta, e));
        }
        keyed.reverse();
        events.extend(keyed);
        *idents = Some(next);
    }
    (events, lost)
}

/// `Connector::audit_stream` for Redis / Valkey.
pub(crate) async fn audit_stream(
    cfg: &AuditConfig,
    sink: &EventSink,
    state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = cfg
        .target()
        .ok_or_else(|| target_error(FailureCode::Internal))?;
    let _running = state.audit.started(&target.id);
    // Sessions to the target's node learn their address only while this
    // stream reads its logs (ADR-0052 decision 4).
    let _reading = own::audit_started(&target.id);
    let settings = target.redis_settings();
    let (mut session, info) = node::open(target, Which::Target, POLL_TIMEOUT)
        .await
        .map_err(RdError::into_connector_error)?;
    let store = cfg.cursor(CURSOR);
    let cursor = match store.as_ref().map(CursorStore::load) {
        Some(Ok(Some(bytes))) => Cursor::decode(&bytes).unwrap_or_default(),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "Redis / Valkey Audit cursor not readable: starting at the newest entries");
            Cursor::default()
        }
        _ => Cursor::default(),
    };
    let skip = store.as_ref().map_or(0, CursorStore::skip_records);
    let learned_store = cfg.counters(LEARNED);
    let mut learned_saved = 0u64;
    let mut st = Stream {
        cfg,
        target,
        state,
        own: OwnAccount::new(
            &target.account,
            None,
            None,
            u64::from(cfg.max_sample_rows()),
            state.audit.own_usage(&target.id),
        )
        .persisted(cfg),
        store,
        cursor,
        saved: None,
        skip,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run: None,
    };
    let mut refused_reads: (bool, bool, bool) = (false, false, false);
    loop {
        // The account's evaluation (cached, at most every 10 minutes): the
        // refusal list stops Audit (decision 4).
        let report = state
            .reports
            .of_session(
                &mut session,
                target,
                Which::Target,
                info.server,
                POLL_TIMEOUT,
            )
            .await
            .map_err(RdError::into_connector_error)?;
        if let Some(r) = report.refusal(&settings, info.server) {
            session.close().await;
            return Err(target_error(match r {
                node::Refusal::Listed => FailureCode::PermissionDenied,
                _ => FailureCode::Unsupported,
            }));
        }
        let grants = info.server.has_dryrun().then_some(report.audit);
        let mut reads = reads_of(info.server, grants);
        if refused_reads.0 {
            reads.slow = None;
        }
        if refused_reads.1 {
            reads.acl = false;
        }
        if refused_reads.2 {
            reads.client_list = false;
        }
        if reads.slow.is_none() && !reads.acl {
            session.close().await;
            tracing::warn!(
                target_id = %target.id,
                "Redis / Valkey Audit: neither the slow log nor ACL LOG is readable \
                 (+slowlog|get, +acl|log): no Audit source"
            );
            return Err(target_error(FailureCode::PermissionDenied));
        }
        state
            .audit
            .sync_learned(&target.id, learned_store.as_ref(), &mut learned_saved);
        let r = poll(&mut st, &mut session, sink, reads, &mut refused_reads).await;
        if let Err(e) = r {
            session.close().await;
            return Err(e);
        }
        st.save();
        tokio::time::sleep(st.cfg.poll_interval()).await;
    }
}

/// One poll of every source.
async fn poll(
    st: &mut Stream<'_>,
    s: &mut Session,
    sink: &EventSink,
    reads: Reads,
    refused: &mut (bool, bool, bool),
) -> Result<(), ConnectorError> {
    let target_id = st.target.id.clone();
    let inf = infos(s).await.map_err(RdError::into_connector_error)?;
    if inf.run.is_some() && st.cursor.run.is_some() && inf.run != st.cursor.run {
        // A server restart: ids start over; entries since are new.
        tracing::info!(target_id = %target_id, "Redis / Valkey server restarted: Audit positions reset");
        st.cursor = Cursor {
            run: inf.run,
            slow: st.cursor.slow.map(|_| -1),
            large: st.cursor.large.map(|_| -1),
            acl: st.cursor.acl.map(|_| -1),
            sync: st.cursor.sync.map(|_| 0),
            acl_counts: BTreeMap::new(),
        };
        st.acl_idents = None;
    }
    st.cursor.run = inf.run.or(st.cursor.run);
    st.run = inf.run;
    let agent_now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let now_s = inf.now_us.map_or(agent_now, |us| us / 1_000_000);
    let offset_s = now_s - agent_now;
    let learned = st.state.audit.learned(&target_id);
    let (database, log_set) = log_database(&learned, &inf.keyspace);
    let stores = st.target.cas_stores();

    // Logs.
    let mut logs: Vec<(EventSource, Vec<LogEntry>)> = Vec::new();
    let mut sources: Vec<(EventSource, Cmd<'static>)> = Vec::new();
    match reads.slow {
        Some(SlowRead::Slowlog) => sources.push((EventSource::RedisSlowlog, Cmd::SlowlogGet)),
        Some(SlowRead::Commandlog) => sources.push((
            EventSource::RedisSlowlog,
            Cmd::CommandlogGet(CommandLog::Slow),
        )),
        None => {}
    }
    if reads.large {
        sources.push((
            EventSource::RedisCommandlog,
            Cmd::CommandlogGet(CommandLog::LargeReply),
        ));
    }
    for (source, cmd) in sources {
        let Some(items) = read_log(s, &cmd)
            .await
            .map_err(RdError::into_connector_error)?
        else {
            tracing::warn!(target_id = %target_id, "Redis / Valkey Audit: the slow log read was refused (NOPERM)");
            refused.0 = true;
            continue;
        };
        let ctx = Context {
            learned: &log_set,
            stores,
        };
        let (parsed, malformed) = parse_logs(&items, &ctx);
        drop(items);
        let cursor = if source == EventSource::RedisSlowlog {
            &mut st.cursor.slow
        } else {
            &mut st.cursor.large
        };
        let (fresh, lost, next) = new_entries(parsed, *cursor);
        *cursor = next;
        st.state.audit.note_dropped(&target_id, lost + malformed);
        if lost > 0 {
            tracing::warn!(target_id = %target_id, lost, "Redis / Valkey Audit: log entries overwritten between polls");
        }
        logs.push((source, fresh));
    }

    // ACL LOG.
    let mut acl: Vec<AclEntry> = Vec::new();
    if reads.acl {
        match read_log(s, &Cmd::AclLog)
            .await
            .map_err(RdError::into_connector_error)?
        {
            None => {
                tracing::warn!(target_id = %target_id, "Redis / Valkey Audit: ACL LOG read refused (NOPERM)");
                refused.1 = true;
            }
            Some(items) => {
                let empty = LearnedPatterns::default();
                let by_db = |db: Option<u16>| -> &LearnedPatterns {
                    db.and_then(|d| learned.dbs.get(&d))
                        .map_or(&empty, |a| a.as_ref())
                };
                let mut malformed = 0u64;
                for v in &items {
                    match databastion_core::isolate(|| {
                        entries::parse_acl_entry(v, &by_db, stores, &st.acl_ident_key)
                    }) {
                        Some(Ok(e)) => acl.push(e),
                        _ => malformed += 1,
                    }
                }
                st.state.audit.note_dropped(&target_id, malformed);
            }
        }
    }

    // Attribution: one `CLIENT LIST` when there is something to
    // attribute; the agent's own connections learn their server-side
    // address from it.
    // The server's time is read in the same pipeline (`INFO server`, as
    // `TIME` is not granted), so the connections' ages and the time they
    // are compared with are of one instant (review L4).
    let mut clients: Vec<Client> = Vec::new();
    let mut clients_now_s = now_s;
    if reads.client_list && logs.iter().any(|(_, l)| !l.is_empty()) {
        let r = s
            .pipeline(
                &[Cmd::Info(InfoSection::Server), Cmd::ClientList],
                POLL_TIMEOUT,
                Stage::Introspection,
            )
            .await
            .map_err(RdError::into_connector_error)?;
        if let [server, list] = r.as_slice() {
            match list.error() {
                Some(ErrorWord::Noperm) => {
                    refused.2 = true;
                    own::note_client_list(
                        &target_id,
                        st.run,
                        &st.target.account,
                        own::ClientList::Refused,
                    );
                }
                // The agent's other sessions may ask for their own line
                // (`own`).
                None => own::note_client_list(
                    &target_id,
                    st.run,
                    &st.target.account,
                    own::ClientList::Granted,
                ),
                Some(_) => {}
            }
            match text(server)
                .and_then(|t| info::field(t, "server_time_usec"))
                .and_then(|v| v.parse::<i64>().ok())
            {
                Some(us) => {
                    clients_now_s = us / 1_000_000;
                    clients = entries::parse_client_list(list);
                }
                // Without the server's time, no attribution.
                None => clients.clear(),
            }
        }
        for c in &clients {
            if let (Some(id), Some(addr)) = (c.id, c.peer.and_then(Peer::socket))
                && own::is_own_open_id(&target_id, id, st.run)
            {
                own::seen(&target_id, id, st.run, addr);
            }
        }
    }

    for (source, fresh) in logs {
        for e in fresh {
            if st.take_skip() {
                continue;
            }
            let ev = databastion_core::isolate(|| {
                st.log_event(&e, source, &database, &clients, clients_now_s, offset_s)
            });
            match ev {
                Some(Some(ev)) => sink.submit(ev).await?,
                Some(None) => {}
                None => st.state.audit.note_dropped(&target_id, 1),
            }
            if st.isolate_mode() {
                st.save();
            }
        }
    }

    // ACL LOG deltas.
    if !acl.is_empty() || reads.acl {
        let (events, lost) = acl_deltas(&mut st.cursor, &mut st.acl_idents, &acl);
        st.state.audit.note_dropped(&target_id, lost);
        for (delta, e) in events {
            if delta > 0 && st.take_skip() {
                continue;
            }
            match databastion_core::isolate(|| st.acl_event(e, delta, offset_s)) {
                Some(Some(ev)) => sink.submit(ev).await?,
                Some(None) => {}
                None => st.state.audit.note_dropped(&target_id, 1),
            }
        }
    }

    // Full synchronizations.
    if let Some(n) = inf.sync_full {
        let delta = st.cursor.sync.map_or(0, |prev| n.saturating_sub(prev));
        st.cursor.sync = Some(n);
        if delta > 0 {
            let repl = s
                .call(
                    &Cmd::Info(InfoSection::Replication),
                    POLL_TIMEOUT,
                    Stage::Introspection,
                )
                .await
                .map_err(RdError::into_connector_error)?;
            let declared = &st.target.redis_settings().replicas;
            // A guess (review L7): the one undeclared replica in a sync
            // state when the poll sees it; else no address. The transfer
            // may have ended before the poll (`redis-cli --rdb`).
            let unknown: Vec<IpAddr> = syncing_replica_ips(text(&repl).unwrap_or_default())
                .into_iter()
                .filter(|ip| !declared.contains(ip))
                .collect();
            let client = match unknown.as_slice() {
                [ip] => Some(ClientAddr::Ip(*ip)),
                _ => None,
            };
            let now = SystemTime::now();
            let ev = MaskedEvent::new(
                EventSource::RedisSync,
                EventAction::Read,
                EventPrincipal::not_recorded().with_client(client),
                now,
            )
            .with_object(EventObject::new(
                NormalizedName::wildcard(),
                None,
                NormalizedName::wildcard(),
            ))
            .with_signal(Signal::FullSync)
            .with_aggregate(delta, now);
            sink.submit(ev).await?;
        }
    }
    Ok(())
}

/// Tests: an entry holding this marker makes the parsing panic.
#[cfg(test)]
const TEST_POISON: &[u8] = b"TEST-PARSER-PANIC";

#[cfg(test)]
#[allow(clippy::panic)]
fn test_poison(v: &Value) {
    if let Value::Array(items) = v
        && let Some(Value::Array(args)) = items.get(3)
        && args.iter().any(|a| a.as_bytes() == Some(TEST_POISON))
    {
        panic!("parser bug on an entry");
    }
}

#[cfg(test)]
mod tests;
