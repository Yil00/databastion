//! The agent's own connections (ADR-0052 decision 8, security review H3
//! and L2): an Audit log entry is the agent's only when its connection is
//! one of the agent's own, recognized by the connection id (`HELLO`'s
//! `id`) or by the `addr:port` the server reports for it, within the
//! connection's lifetime; **never** by user or client name (any client can
//! name itself `databastion-agent`, and anyone holding the agent's
//! credentials uses its user).
//!
//! Every session the connector opens with the agent's account registers
//! here ([`register`]) with its id, its local TCP address and the server
//! run it was opened on (a truncated SHA-256 of `run_id`: ids start over
//! when the server restarts, so a registration only ever matches entries
//! of its own run; review M2, L3). The Audit stream records the address
//! the server reports for the agent's open connections (`CLIENT LIST`).
//! Address matches use that reported address only; the local address is
//! used for a connection not seen yet only once the server was seen to
//! report the agent's local addresses unchanged (no NAT or proxy between
//! them; review M1). The registry is per target, bounded, and forgets
//! connections closed more than a day ago.
//!
//! Slow-log and command-log entries carry no connection id, only the
//! address: a connection that runs commands and closes between two of the
//! stream's `CLIENT LIST` snapshots (a `check()` session, a report probe,
//! a short Discovery session) would never have its reported address
//! recorded, and its entries would come out as another client's
//! (`account_not_recorded`). So, while an Audit stream reads the target's
//! logs ([`audit_started`]), every session to the target's node asks the
//! server for its own line (`CLIENT LIST ID <own id>`) right after its
//! handshake, when the account is known to hold `+client|list`
//! ([`note_client_list`]: a refusal of a real call wins for the server
//! run), and records the address from it ([`seen`]); a closed connection
//! keeps that address for its whole lifetime (plus [`MARGIN`]) and
//! [`KEEP`] after.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime};

/// Connections remembered per target.
const MAX_CONNS: usize = 1024;
/// Closed connections are forgotten after this long.
const KEEP: Duration = Duration::from_secs(24 * 3600);
/// Margin around a connection's lifetime when matching an entry's time
/// (entry timestamps have a one-second granularity).
const MARGIN: Duration = Duration::from_secs(2);

/// One of the agent's connections.
#[derive(Debug, Clone)]
struct Conn {
    id: i64,
    /// The server run it was opened on (`None`: unknown, never matches).
    run: Option<u64>,
    local: Option<SocketAddr>,
    /// The address the server reported for it (`CLIENT LIST`).
    seen: Option<SocketAddr>,
    opened: SystemTime,
    closed: Option<SystemTime>,
}

impl Conn {
    fn within(&self, at: SystemTime) -> bool {
        self.opened.checked_sub(MARGIN).is_none_or(|o| o <= at)
            && self.closed.is_none_or(|t| at <= t + MARGIN)
    }
}

#[derive(Debug, Default)]
struct Target {
    conns: VecDeque<Conn>,
    /// The server reported one of the agent's connections at its local
    /// address (no NAT nor proxy): local addresses can stand for the
    /// reported ones.
    local_is_seen: bool,
    /// The account holds `+client|list` on the target's node: the latest
    /// `ACL DRYRUN` evaluation, or the stream's last `CLIENT LIST` answer.
    client_list: bool,
    /// A real `CLIENT LIST` call was refused (`NOPERM`) on this server run
    /// for this account: wins over `ACL DRYRUN` until another run or
    /// another account (a configuration change).
    refused: Option<(u64, String)>,
    /// `CLIENT LIST ID` failed otherwise (a renamed or disabled command, a
    /// timeout) on this server run: not sent again during it.
    unsupported: Option<u64>,
    /// Audit streams running for the target: sessions learn their address
    /// only while one reads the target's logs (ADR-0052 decision 4:
    /// `+client|list` is an Audit read).
    streams: usize,
}

type Registry = Mutex<HashMap<String, Target>>;

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<String, Target>> {
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A registered connection; marks it closed when dropped.
#[derive(Debug)]
pub(crate) struct Registration {
    target: String,
    id: i64,
    run: Option<u64>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let now = SystemTime::now();
        if let Some(t) = lock().get_mut(&self.target) {
            for c in t
                .conns
                .iter_mut()
                .filter(|c| c.id == self.id && c.run == self.run)
            {
                c.closed.get_or_insert(now);
            }
        }
    }
}

/// Registers a connection of the agent's own account to `target_id`,
/// opened at `opened` (before its first command) on the server run `run`.
pub(crate) fn register(
    target_id: &str,
    id: i64,
    local: Option<SocketAddr>,
    run: Option<u64>,
    opened: SystemTime,
) -> Registration {
    let now = SystemTime::now();
    let mut map = lock();
    let t = map.entry(target_id.to_owned()).or_default();
    t.conns.retain(|c| {
        c.closed
            .is_none_or(|x| now.duration_since(x).unwrap_or_default() < KEEP)
    });
    // Full: the oldest closed connection goes first; an open one (the Audit
    // stream's own, held for days) only when every remembered connection
    // is open.
    while t.conns.len() >= MAX_CONNS {
        match t.conns.iter().position(|c| c.closed.is_some()) {
            Some(i) => {
                t.conns.remove(i);
            }
            None => {
                t.conns.pop_front();
            }
        }
    }
    t.conns.push_back(Conn {
        id,
        run,
        local,
        seen: None,
        opened: opened.min(now),
        closed: None,
    });
    Registration {
        target: target_id.to_owned(),
        id,
        run,
    }
}

fn same_run(c: &Conn, run: Option<u64>) -> bool {
    run.is_some() && c.run == run
}

/// Whether `id`, seen open in `CLIENT LIST` on the server run `run`, is one
/// of the agent's connections still open (review M2).
pub(crate) fn is_own_open_id(target_id: &str, id: i64, run: Option<u64>) -> bool {
    lock().get(target_id).is_some_and(|t| {
        t.conns
            .iter()
            .any(|c| c.id == id && same_run(c, run) && c.closed.is_none())
    })
}

/// Whether `id`, logged at `at` (agent clock) on the server run `run`, was
/// one of the agent's connections then (`ACL LOG`; review M2).
pub(crate) fn is_own_id_at(target_id: &str, id: i64, run: Option<u64>, at: SystemTime) -> bool {
    lock().get(target_id).is_some_and(|t| {
        t.conns
            .iter()
            .any(|c| c.id == id && same_run(c, run) && c.within(at))
    })
}

/// An Audit stream reads the target's logs while this lives.
#[derive(Debug)]
pub(crate) struct AuditRunning {
    target: String,
}

impl Drop for AuditRunning {
    fn drop(&mut self) {
        if let Some(t) = lock().get_mut(&self.target) {
            t.streams = t.streams.saturating_sub(1);
        }
    }
}

/// Marks an Audit stream of `target_id` as running, until the guard drops.
pub(crate) fn audit_started(target_id: &str) -> AuditRunning {
    lock().entry(target_id.to_owned()).or_default().streams += 1;
    AuditRunning {
        target: target_id.to_owned(),
    }
}

/// What the agent learned about `CLIENT LIST` on the target's node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientList {
    /// `ACL DRYRUN` allows it, or a `CLIENT LIST` was answered.
    Granted,
    /// `ACL DRYRUN` denies it.
    Denied,
    /// A real call was refused (`NOPERM`): sticky for the server run and
    /// the account, whatever `ACL DRYRUN` says later.
    Refused,
    /// `CLIENT LIST ID` failed otherwise (an error other than `NOPERM`, a
    /// timeout, an unreadable reply): not sent again during the run.
    Unsupported,
}

/// Records what the agent learned about `CLIENT LIST` on the node of
/// `target_id` (the target's node, the one Audit reads), on the server run
/// `run`, for `account`.
pub(crate) fn note_client_list(target_id: &str, run: Option<u64>, account: &str, what: ClientList) {
    let mut map = lock();
    let t = map.entry(target_id.to_owned()).or_default();
    match what {
        ClientList::Granted => t.client_list = true,
        ClientList::Denied => t.client_list = false,
        ClientList::Refused => {
            t.client_list = false;
            if let Some(r) = run {
                t.refused = Some((r, account.to_owned()));
            }
        }
        ClientList::Unsupported => {
            if let Some(r) = run {
                t.unsupported = Some(r);
            }
        }
    }
}

/// Whether a session of `account` to `target_id`, on the server run `run`,
/// asks the server for its own line (`CLIENT LIST ID`): only while an
/// Audit stream reads the target's logs, with `+client|list` known to be
/// held, no refusal of a real call nor failure on this run, and a known
/// run (a registration without one never matches).
pub(crate) fn learns_addresses(target_id: &str, run: Option<u64>, account: &str) -> bool {
    let Some(r) = run else { return false };
    lock().get(target_id).is_some_and(|t| {
        t.streams > 0
            && t.client_list
            && t.unsupported != Some(r)
            && t.refused
                .as_ref()
                .is_none_or(|(rr, a)| *rr != r || a != account)
    })
}

/// Whether the session `id` of `account` should send `CLIENT LIST ID`
/// now: [`learns_addresses`], registered, and its address not recorded.
pub(crate) fn should_learn(target_id: &str, id: i64, run: Option<u64>, account: &str) -> bool {
    learns_addresses(target_id, run, account)
        && lock().get(target_id).is_some_and(|t| {
            t.conns
                .iter()
                .any(|c| c.id == id && same_run(c, run) && c.closed.is_none())
        })
        && !is_seen(target_id, id, run)
}

/// Records the answer to the session `id`'s `CLIENT LIST ID`: its address,
/// or what the error says about the command (fail closed: without an
/// address, its entries are reported).
pub(crate) fn record_own_line(
    target_id: &str,
    id: i64,
    run: Option<u64>,
    account: &str,
    reply: &crate::resp::Value,
) {
    match reply.error() {
        Some(crate::resp::ErrorWord::Noperm) => {
            note_client_list(target_id, run, account, ClientList::Refused);
        }
        Some(_) => note_client_list(target_id, run, account, ClientList::Unsupported),
        None => match super::entries::own_address(reply, id) {
            Some(addr) => seen(target_id, id, run, addr),
            // No TCP address in the reply (a Unix socket, whose peers are
            // never attributed, or a reply without the session's line):
            // nothing to learn on this run, not asked again.
            None => note_client_list(target_id, run, account, ClientList::Unsupported),
        },
    }
}

/// Whether the address of the open connection `id` is recorded already.
pub(crate) fn is_seen(target_id: &str, id: i64, run: Option<u64>) -> bool {
    lock().get(target_id).is_some_and(|t| {
        t.conns
            .iter()
            .any(|c| c.id == id && same_run(c, run) && c.closed.is_none() && c.seen.is_some())
    })
}

/// Records the address the server reports for one of the agent's open
/// connections (`CLIENT LIST`, or its own `CLIENT LIST ID` line).
pub(crate) fn seen(target_id: &str, id: i64, run: Option<u64>, addr: SocketAddr) {
    if let Some(t) = lock().get_mut(target_id) {
        let mut local_seen = false;
        for c in t
            .conns
            .iter_mut()
            .filter(|c| c.id == id && same_run(c, run) && c.closed.is_none())
        {
            c.seen = Some(addr);
            local_seen |= c.local == Some(addr);
        }
        t.local_is_seen |= local_seen;
    }
}

/// Whether an entry from `addr` at `at` (agent clock), on the server run
/// `run`, comes from one of the agent's connections: the address the
/// server reported for it (or, once the server was seen to report local
/// addresses unchanged, its local address when it was not seen yet), and
/// `at` within its lifetime (a port reused by another connection is not
/// taken for the agent's).
pub(crate) fn is_own_addr(
    target_id: &str,
    addr: SocketAddr,
    at: SystemTime,
    run: Option<u64>,
) -> bool {
    lock().get(target_id).is_some_and(|t| {
        t.conns.iter().any(|c| {
            let address = match c.seen {
                Some(seen) => seen == addr,
                None => t.local_is_seen && c.local == Some(addr),
            };
            address && same_run(c, run) && c.within(at)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_connections_by_id_and_address_within_their_lifetime() {
        let t = "own-test-target";
        let run = Some(7);
        let a: SocketAddr = "10.0.0.5:51000".parse().unwrap();
        let nat: SocketAddr = "172.17.0.1:40000".parse().unwrap();
        let before = SystemTime::now() - Duration::from_secs(60);
        let r = register(t, 42, Some(a), run, SystemTime::now());
        assert!(is_own_open_id(t, 42, run));
        assert!(!is_own_open_id(t, 43, run));
        assert!(!is_own_open_id("other", 42, run));
        // Another server run (a restart): the id means nothing (M2, L3).
        assert!(!is_own_open_id(t, 42, Some(8)));
        assert!(!is_own_open_id(t, 42, None));
        // Not seen yet: the local address is not trusted (M1).
        assert!(!is_own_addr(t, a, SystemTime::now(), run));
        seen(t, 42, run, nat);
        assert!(is_own_addr(t, nat, SystemTime::now(), run));
        assert!(!is_own_addr(t, a, SystemTime::now(), run));
        assert!(!is_own_addr(t, nat, SystemTime::now(), Some(8)));
        // Before the connection opened: another client on the same port.
        assert!(!is_own_addr(t, nat, before, run));
        assert!(is_own_id_at(t, 42, run, SystemTime::now()));
        assert!(!is_own_id_at(t, 42, run, before));
        drop(r);
        // Closed: no longer open for `CLIENT LIST`; entries right after
        // still match by time, later ones do not.
        assert!(!is_own_open_id(t, 42, run));
        assert!(is_own_addr(t, nat, SystemTime::now(), run));
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(!is_own_addr(t, nat, later, run));
        assert!(!is_own_id_at(t, 42, run, later));
    }

    #[test]
    fn local_addresses_count_once_the_server_reports_them_unchanged() {
        let t = "own-test-target-local";
        let run = Some(1);
        let a: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let _r1 = register(t, 1, Some(a), run, SystemTime::now());
        let _r2 = register(t, 2, Some(b), run, SystemTime::now());
        assert!(!is_own_addr(t, b, SystemTime::now(), run));
        // The server reports connection 1 at its local address: no NAT.
        seen(t, 1, run, a);
        assert!(is_own_addr(t, b, SystemTime::now(), run));
    }

    fn err(w: crate::resp::ErrorWord) -> crate::resp::Value {
        crate::resp::Value::Error(w)
    }

    /// Review M1(b), L2, L4(a): `CLIENT LIST ID` only while an Audit
    /// stream runs, with the grant known, once per session; a `NOPERM`
    /// wins over `ACL DRYRUN` for the run and the account; any other
    /// failure stops it for the run.
    #[test]
    fn own_line_requests_are_gated() {
        use crate::resp::ErrorWord;
        let t = "own-gate-t";
        let acct = "databastion";
        let (r3, r4, r5) = (Some(3), Some(4), Some(5));
        let _c10 = register(t, 10, None, r3, SystemTime::now());
        // No grant known, no stream.
        assert!(!should_learn(t, 10, r3, acct));
        note_client_list(t, None, acct, ClientList::Granted);
        // Granted, but no Audit stream reads the target's logs.
        assert!(!learns_addresses(t, r3, acct));
        assert!(!should_learn(t, 10, r3, acct));
        let stream = audit_started(t);
        assert!(should_learn(t, 10, r3, acct));
        drop(stream);
        assert!(!should_learn(t, 10, r3, acct));
        let _stream = audit_started(t);
        // An unknown run never matches: nothing to learn.
        assert!(!learns_addresses(t, None, acct));
        // Not registered, or closed: nothing to learn.
        assert!(!should_learn(t, 99, r3, acct));
        drop(register(t, 12, None, r3, SystemTime::now()));
        assert!(!should_learn(t, 12, r3, acct));
        // Recorded once: not asked again.
        let line = "id=10 addr=172.18.0.1:4000 user=databastion\n";
        let reply = crate::resp::decode_all(
            format!("${}\r\n{line}\r\n", line.len()).as_bytes(),
            crate::resp::Limits {
                bulk: 4096,
                items: 0,
                skip_oversized: true,
                reply: 8192,
            },
        )
        .unwrap()
        .unwrap();
        record_own_line(t, 10, r3, acct, &reply);
        assert!(is_seen(t, 10, r3));
        assert!(!should_learn(t, 10, r3, acct));
        let _c11 = register(t, 11, None, r3, SystemTime::now());
        assert!(should_learn(t, 11, r3, acct));
        // A refused real call: sticky over `ACL DRYRUN` for the run and
        // the account.
        record_own_line(t, 11, r3, acct, &err(ErrorWord::Noperm));
        assert!(!is_seen(t, 11, r3));
        assert!(!learns_addresses(t, r3, acct));
        note_client_list(t, None, acct, ClientList::Granted);
        assert!(!learns_addresses(t, r3, acct));
        assert!(!should_learn(t, 11, r3, acct));
        // Another server run, or another account (a configuration
        // change): asked again.
        assert!(learns_addresses(t, r4, acct));
        assert!(learns_addresses(t, r3, "other"));
        // `ACL DRYRUN` denies it: not asked.
        note_client_list(t, None, acct, ClientList::Denied);
        assert!(!learns_addresses(t, r4, acct));
        note_client_list(t, None, acct, ClientList::Granted);
        // Another error (a renamed or disabled command): stopped for the
        // run.
        let _c20 = register(t, 20, None, r4, SystemTime::now());
        record_own_line(t, 20, r4, acct, &err(ErrorWord::Err));
        assert!(!learns_addresses(t, r4, acct));
        assert!(learns_addresses(t, r5, acct));
        // A reply without a TCP address (a Unix socket): stopped for the
        // run, nothing recorded.
        let _c30 = register(t, 30, None, r5, SystemTime::now());
        record_own_line(t, 30, r5, acct, &crate::resp::Value::Null);
        assert!(!is_seen(t, 30, r5));
        assert!(!learns_addresses(t, r5, acct));
    }
}
