//! The agent's own connections (ADR-0052 decision 8, security review H3
//! and L2): an Audit log entry is the agent's only when its connection is
//! one of the agent's own, recognized by the connection id (`HELLO`'s
//! `id`, valid until the server restarts) or by the `addr:port` the server
//! reports for it, within the connection's lifetime; **never** by user or
//! client name (any client can name itself `databastion-agent`, and anyone
//! holding the agent's credentials uses its user).
//!
//! Every session the connector opens with the agent's account registers
//! here ([`register`]) with its id and local TCP address; the Audit stream
//! adds the address the server reports for the connections it sees open
//! in `CLIENT LIST` (behind NAT the two differ). The registry is per
//! target, bounded, and forgets connections closed more than a day ago.

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
    /// Local address, and the address the server reported (`CLIENT
    /// LIST`), when known.
    local: Option<SocketAddr>,
    seen: Option<SocketAddr>,
    opened: SystemTime,
    closed: Option<SystemTime>,
}

type Registry = Mutex<HashMap<String, VecDeque<Conn>>>;

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<String, VecDeque<Conn>>> {
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A registered connection; marks it closed when dropped.
#[derive(Debug)]
pub(crate) struct Registration {
    target: String,
    id: i64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let now = SystemTime::now();
        if let Some(conns) = lock().get_mut(&self.target) {
            for c in conns.iter_mut().filter(|c| c.id == self.id) {
                c.closed.get_or_insert(now);
            }
        }
    }
}

/// Registers a connection of the agent's own account to `target_id`.
pub(crate) fn register(target_id: &str, id: i64, local: Option<SocketAddr>) -> Registration {
    let now = SystemTime::now();
    let mut map = lock();
    let conns = map.entry(target_id.to_owned()).or_default();
    conns.retain(|c| {
        c.closed
            .is_none_or(|t| now.duration_since(t).unwrap_or_default() < KEEP)
    });
    while conns.len() >= MAX_CONNS {
        conns.pop_front();
    }
    conns.push_back(Conn {
        id,
        local,
        seen: None,
        opened: now,
        closed: None,
    });
    Registration {
        target: target_id.to_owned(),
        id,
    }
}

/// Whether `id` is one of the agent's connections to `target_id`.
pub(crate) fn is_own_id(target_id: &str, id: i64) -> bool {
    lock()
        .get(target_id)
        .is_some_and(|c| c.iter().any(|c| c.id == id))
}

/// Records the address the server reports for one of the agent's open
/// connections (`CLIENT LIST`).
pub(crate) fn seen(target_id: &str, id: i64, addr: SocketAddr) {
    if let Some(conns) = lock().get_mut(target_id) {
        for c in conns.iter_mut().filter(|c| c.id == id) {
            c.seen = Some(addr);
        }
    }
}

/// Forgets every connection id of `target_id` (the server restarted: ids
/// start over).
pub(crate) fn server_restarted(target_id: &str) {
    if let Some(conns) = lock().get_mut(target_id) {
        conns.retain(|c| c.closed.is_none());
        for c in conns.iter_mut() {
            // Ids of connections opened before the restart mean nothing
            // now; open ones were closed by the restart anyway.
            c.closed.get_or_insert(SystemTime::now());
            c.id = i64::MIN;
        }
    }
}

/// Whether an entry from `addr` at `at` (agent clock) comes from one of
/// the agent's connections: same address (as the server reported it, or
/// the local one), and `at` within the connection's lifetime (a port
/// reused by another connection is not taken for the agent's).
pub(crate) fn is_own_addr(target_id: &str, addr: SocketAddr, at: SystemTime) -> bool {
    lock().get(target_id).is_some_and(|conns| {
        conns.iter().any(|c| {
            (c.seen == Some(addr) || c.local == Some(addr))
                && c.opened.checked_sub(MARGIN).is_none_or(|o| o <= at)
                && c.closed.is_none_or(|t| at <= t + MARGIN)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_connections_by_id_and_address_within_their_lifetime() {
        let t = "own-test-target";
        let a: SocketAddr = "10.0.0.5:51000".parse().unwrap();
        let seen: SocketAddr = "172.17.0.1:40000".parse().unwrap();
        let before = SystemTime::now() - Duration::from_secs(60);
        let r = register(t, 42, Some(a));
        assert!(is_own_id(t, 42));
        assert!(!is_own_id(t, 43));
        assert!(!is_own_id("other", 42));
        assert!(is_own_addr(t, a, SystemTime::now()));
        // Before the connection opened: another client on the same port.
        assert!(!is_own_addr(t, a, before));
        assert!(!is_own_addr(t, seen, SystemTime::now()));
        self::seen(t, 42, seen);
        assert!(is_own_addr(t, seen, SystemTime::now()));
        drop(r);
        // Closed: entries right after still match, later ones do not.
        assert!(is_own_addr(t, seen, SystemTime::now()));
        assert!(!is_own_addr(
            t,
            seen,
            SystemTime::now() + Duration::from_secs(60)
        ));
        server_restarted(t);
        assert!(!is_own_id(t, 42));
    }
}
