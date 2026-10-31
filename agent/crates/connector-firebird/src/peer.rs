//! The listening peer and forwarder rules (ADR-0060 decision 3, security
//! reviews L1 and M2).
//!
//! - **Peer uid**: right after `connect()` returns and before `op_connect`
//!   is sent, the server-side socket of **this** connection is found in
//!   `/proc/net/tcp` and `/proc/net/tcp6` by its full 4-tuple (local = the
//!   declared address and port, remote = the agent's address and local
//!   port) in the `ESTABLISHED` or `SYN_RECV` state, IPv4-mapped IPv6
//!   addresses handled. Its owner must be the declared `peer_uid`. A
//!   missing entry, two entries, another uid or the overflow uid end the
//!   connection. Other rows are never logged or kept; the tables are read
//!   line by line with a bound on lines and on time. No privilege and no
//!   network traffic are needed (the tables are world-readable).
//! - **Forwarder**: once attached, the server's own view of the
//!   connection (`MON$REMOTE_PROTOCOL`, `MON$REMOTE_ADDRESS` of
//!   `CURRENT_CONNECTION`, the address and port in one field, measured)
//!   must be the agent's socket; a mismatch is a forwarder.

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::error::Detail;

/// Most lines read from one table.
const MAX_LINES: usize = 1 << 20;
/// Longest line considered (a row is about 150 bytes).
const MAX_LINE_BYTES: usize = 512;
/// Time bound of the whole peer check (every lookup and wait).
pub(crate) const LOOKUP_TIME: Duration = Duration::from_secs(2);
/// The overflow uid.
const OVERFLOW_UID: u32 = 65_534;

/// `ESTABLISHED` and `SYN_RECV` in `/proc/net/tcp*`.
const STATES: [&str; 2] = ["01", "03"];

/// The result of scanning the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Lookup {
    /// Rows matching the 4-tuple (server side).
    pub(crate) matches: u32,
    /// The owner uid of the first match.
    pub(crate) uid: Option<u32>,
    /// The bound on lines or time was reached before the end.
    pub(crate) cut: bool,
}

impl Lookup {
    /// The verdict for `peer_uid` (decision 3).
    pub(crate) fn verdict(&self, peer_uid: u32) -> Result<(), Detail> {
        match (self.matches, self.uid) {
            _ if self.cut => Err(Detail::PeerNotFound),
            (0, _) | (_, None) => Err(Detail::PeerNotFound),
            (1, Some(uid)) if uid == OVERFLOW_UID => Err(Detail::PeerOverflowUid),
            (1, Some(uid)) if uid == peer_uid => Ok(()),
            (1, Some(_)) => Err(Detail::PeerUidMismatch),
            _ => Err(Detail::PeerAmbiguous),
        }
    }
}

/// An address as `/proc/net/tcp*` prints it: IPv4 as one native-order
/// 32-bit word in hexadecimal, IPv6 as four, the port in hexadecimal.
fn parse_endpoint(text: &str) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if port == 0 && addr.chars().all(|c| c == '0') {
        // A listening row's remote end.
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(canonical(ip), port))
}

/// IPv4-mapped IPv6 addresses as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// Scans one table's text for the server-side socket of the connection
/// `server` <- `client`. Pure (the property test and the fuzz target call
/// it); `deadline` bounds the time.
pub(crate) fn scan(
    lines: impl Iterator<Item = String>,
    server: SocketAddr,
    client: SocketAddr,
    deadline: Option<Instant>,
    into: &mut Lookup,
) {
    let server = SocketAddr::new(canonical(server.ip()), server.port());
    let client = SocketAddr::new(canonical(client.ip()), client.port());
    for (i, line) in lines.enumerate() {
        if i >= MAX_LINES || (i % 4096 == 0 && deadline.is_some_and(|d| Instant::now() > d)) {
            into.cut = true;
            return;
        }
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let mut cols = line.split_whitespace();
        let (Some(_sl), Some(local), Some(remote), Some(state)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if !STATES.contains(&state) {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_endpoint(local), parse_endpoint(remote)) else {
            continue;
        };
        if local != server || remote != client {
            continue;
        }
        // tx_queue:rx_queue, tr:tm->when, retrnsmt, then the uid.
        let uid = cols.nth(3).and_then(|u| u.parse::<u32>().ok());
        into.matches = into.matches.saturating_add(1);
        if into.uid.is_none() {
            into.uid = uid;
        }
    }
}

/// Reads `/proc/net/tcp` and `/proc/net/tcp6` (both: a dual-stack
/// listener shows IPv4 connections in `tcp6`), bounded by lines and by
/// `deadline`, the end of the whole peer check (not of this read).
#[cfg(target_os = "linux")]
pub(crate) fn lookup(server: SocketAddr, client: SocketAddr, deadline: Instant) -> Lookup {
    let mut out = Lookup::default();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if Instant::now() > deadline {
            out.cut = true;
            break;
        }
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        let lines = BufReader::new(file)
            .split(b'\n')
            .map_while(Result::ok)
            .map(|l| String::from_utf8_lossy(&l).into_owned());
        scan(lines.skip(1), server, client, Some(deadline), &mut out);
        if out.cut {
            break;
        }
    }
    out
}

/// Off Linux there is no table to read: the check fails (decision 3).
#[cfg(not(target_os = "linux"))]
pub(crate) fn lookup(_server: SocketAddr, _client: SocketAddr, _deadline: Instant) -> Lookup {
    Lookup {
        cut: true,
        ..Lookup::default()
    }
}

/// Lookups of one connection, when one sees no row or two.
const LOOKUPS: u32 = 3;
/// The wait between two lookups.
const LOOKUP_RETRY: Duration = Duration::from_millis(20);

/// The peer rule of decision 3 for one connection. A lookup that sees no
/// matching row, or two, is repeated (at most [`LOOKUPS`] in all): while
/// the server completes the handshake, its socket can move from the
/// listener's `SYN_RECV` entry to an `ESTABLISHED` one during a read of
/// the table, which then shows both, or neither (seen on a forwarder that
/// accepts at once, 1 run in 4). The last lookup decides, so the rule
/// stays: exactly one row, owned by `peer_uid`. Every lookup and wait
/// shares one deadline, [`LOOKUP_TIME`] after the start (review L2).
pub(crate) async fn check(
    server: SocketAddr,
    client: SocketAddr,
    peer_uid: u32,
) -> Result<(), Detail> {
    if !cfg!(target_os = "linux") {
        return Err(Detail::PeerPlatform);
    }
    let deadline = Instant::now() + LOOKUP_TIME;
    check_until(deadline, peer_uid, move |d| lookup(server, client, d)).await
}

/// The retry loop of [`check`], with the lookup given (tests).
async fn check_until<F>(deadline: Instant, peer_uid: u32, read: F) -> Result<(), Detail>
where
    F: Fn(Instant) -> Lookup + Clone + Send + 'static,
{
    let mut attempt = 1;
    loop {
        let read = read.clone();
        let found = tokio::task::spawn_blocking(move || read(deadline))
            .await
            .map_err(databastion_core::resume_panic)
            .unwrap_or(Lookup {
                cut: true,
                ..Lookup::default()
            });
        let verdict = found.verdict(peer_uid);
        let transient =
            !found.cut && matches!(verdict, Err(Detail::PeerNotFound | Detail::PeerAmbiguous));
        if !transient || attempt >= LOOKUPS || Instant::now() + LOOKUP_RETRY >= deadline {
            return verdict;
        }
        attempt += 1;
        tokio::time::sleep(LOOKUP_RETRY).await;
    }
}

/// Whether the server's view of the connection (`MON$REMOTE_PROTOCOL`,
/// `MON$REMOTE_ADDRESS` as `<address>/<port>`) is the agent's socket
/// `local` (decision 3, M2).
pub(crate) fn same_as_server_view(protocol: &str, remote: &str, local: SocketAddr) -> bool {
    let Some((addr, port)) = remote.rsplit_once('/') else {
        return false;
    };
    let (Ok(addr), Ok(port)) = (addr.parse::<IpAddr>(), port.parse::<u16>()) else {
        return false;
    };
    let family_ok = match canonical(local.ip()) {
        IpAddr::V4(_) => protocol == "TCPv4" || protocol == "TCPv6",
        IpAddr::V6(_) => protocol == "TCPv6",
    };
    family_ok && canonical(addr) == canonical(local.ip()) && port == local.port()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn le_hex(ip: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(ip.octets()))
    }

    fn row(local: &str, remote: &str, state: &str, uid: u32) -> String {
        format!(
            "   7: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:>5}        0 4242 1 0000000000000000 20 4 30 10 -1"
        )
    }

    fn table(rows: &[String]) -> Vec<String> {
        rows.to_vec()
    }

    #[test]
    fn the_server_side_of_the_connection_is_found_by_its_4_tuple() {
        let lo = le_hex(Ipv4Addr::LOCALHOST);
        let server: SocketAddr = "127.0.0.1:3050".parse().unwrap();
        let client: SocketAddr = "127.0.0.1:41370".parse().unwrap();
        let rows = table(&[
            // The listener, the client's own end, another connection.
            row(&format!("{lo}:0BEA"), "00000000:0000", "0A", 0),
            row(&format!("{lo}:A19A"), &format!("{lo}:0BEA"), "01", 1000),
            row(&format!("{lo}:0BEA"), &format!("{lo}:A19B"), "01", 84),
            // The server side of this connection.
            row(&format!("{lo}:0BEA"), &format!("{lo}:A19A"), "01", 84),
        ]);
        let mut out = Lookup::default();
        scan(rows.into_iter(), server, client, None, &mut out);
        assert_eq!((out.matches, out.uid), (1, Some(84)));
        assert_eq!(out.verdict(84), Ok(()));
        assert_eq!(out.verdict(85), Err(Detail::PeerUidMismatch));
    }

    #[test]
    fn verdicts_fail_closed() {
        let l = |matches, uid, cut| Lookup { matches, uid, cut };
        assert_eq!(l(0, None, false).verdict(84), Err(Detail::PeerNotFound));
        assert_eq!(
            l(2, Some(84), false).verdict(84),
            Err(Detail::PeerAmbiguous)
        );
        assert_eq!(
            l(1, Some(65_534), false).verdict(65_534),
            Err(Detail::PeerOverflowUid)
        );
        assert_eq!(l(1, Some(84), true).verdict(84), Err(Detail::PeerNotFound));
        assert_eq!(l(1, None, false).verdict(84), Err(Detail::PeerNotFound));
    }

    #[test]
    fn ipv6_and_mapped_rows() {
        // `::1` is 0..01: the last word, in native order.
        let v6_lo = format!(
            "{:08X}{:08X}{:08X}{:08X}",
            0,
            0,
            0,
            u32::from_ne_bytes([0, 0, 0, 1])
        );
        let server: SocketAddr = "[::1]:3050".parse().unwrap();
        let client: SocketAddr = "[::1]:50000".parse().unwrap();
        let rows = vec![row(
            &format!("{v6_lo}:0BEA"),
            &format!("{v6_lo}:C350"),
            "03",
            84,
        )];
        let mut out = Lookup::default();
        scan(rows.into_iter(), server, client, None, &mut out);
        assert_eq!(out.verdict(84), Ok(()));
        // A dual-stack listener: an IPv4 connection as ::ffff:127.0.0.1.
        let mapped = format!(
            "{:08X}{:08X}{:08X}{:08X}",
            0,
            0,
            u32::from_ne_bytes([0, 0, 0xFF, 0xFF]),
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        let server: SocketAddr = "127.0.0.1:3050".parse().unwrap();
        let client: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let rows = vec![row(
            &format!("{mapped}:0BEA"),
            &format!("{mapped}:C350"),
            "01",
            84,
        )];
        let mut out = Lookup::default();
        scan(rows.into_iter(), server, client, None, &mut out);
        assert_eq!(out.verdict(84), Ok(()));
    }

    #[test]
    fn hostile_lines_are_skipped() {
        let server: SocketAddr = "127.0.0.1:3050".parse().unwrap();
        let client: SocketAddr = "127.0.0.1:41370".parse().unwrap();
        let rows = vec![
            String::new(),
            "garbage".into(),
            "  1: 0100007F:0BEA".into(),
            "  1: 0100007F:0BEA 0100007F:A19A 01".into(),
            "x".repeat(10_000),
            "  1: ZZZZZZZZ:0BEA 0100007F:A19A 01 0:0 0:0 0 84".into(),
        ];
        let mut out = Lookup::default();
        scan(rows.into_iter(), server, client, None, &mut out);
        // The row with a 4-tuple but no uid counts, with no uid: refused.
        assert_eq!(out.verdict(84), Err(Detail::PeerNotFound));
    }

    #[tokio::test]
    async fn every_retry_shares_one_deadline() {
        use std::sync::{Arc, Mutex};
        // Each lookup sees two rows (transient) and takes 30 ms.
        let seen: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let s = Arc::clone(&seen);
        let read = move |d: Instant| {
            s.lock().unwrap().push(d);
            std::thread::sleep(Duration::from_millis(30));
            Lookup {
                matches: 2,
                uid: Some(84),
                cut: false,
            }
        };
        let started = Instant::now();
        let deadline = started + Duration::from_millis(100);
        let verdict = check_until(deadline, 84, read).await;
        assert_eq!(verdict, Err(Detail::PeerAmbiguous));
        let seen = seen.lock().unwrap().clone();
        assert!(!seen.is_empty() && seen.len() <= LOOKUPS as usize);
        assert!(seen.iter().all(|d| *d == deadline), "one deadline for all");
        // Within the deadline plus at most one lookup's own time.
        assert!(started.elapsed() < Duration::from_millis(100 + 30 + 50));

        // A deadline too close for a retry: one lookup only.
        let count = Arc::new(Mutex::new(0u32));
        let c = Arc::clone(&count);
        let read = move |_d: Instant| {
            *c.lock().unwrap() += 1;
            Lookup::default()
        };
        let deadline = Instant::now() + Duration::from_millis(5);
        assert_eq!(
            check_until(deadline, 84, read).await,
            Err(Detail::PeerNotFound)
        );
        assert_eq!(*count.lock().unwrap(), 1);

        // A transient miss then the row: accepted, all within the deadline.
        let n = Arc::new(Mutex::new(0u32));
        let c = Arc::clone(&n);
        let read = move |_d: Instant| {
            let mut n = c.lock().unwrap();
            *n += 1;
            if *n == 1 {
                Lookup::default()
            } else {
                Lookup {
                    matches: 1,
                    uid: Some(84),
                    cut: false,
                }
            }
        };
        let deadline = Instant::now() + LOOKUP_TIME;
        assert_eq!(check_until(deadline, 84, read).await, Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_passed_deadline_cuts_the_lookup() {
        let server: SocketAddr = "127.0.0.1:3050".parse().unwrap();
        let client: SocketAddr = "127.0.0.1:41370".parse().unwrap();
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert!(lookup(server, client, past).cut);
    }

    #[test]
    fn the_server_view_must_be_the_agents_socket() {
        let local: SocketAddr = "127.0.0.1:59988".parse().unwrap();
        assert!(same_as_server_view("TCPv4", "127.0.0.1/59988", local));
        assert!(!same_as_server_view("TCPv4", "127.0.0.1/59989", local));
        assert!(!same_as_server_view("TCPv4", "10.0.0.2/59988", local));
        assert!(!same_as_server_view("XNET", "127.0.0.1/59988", local));
        assert!(!same_as_server_view("TCPv4", "127.0.0.1", local));
        assert!(!same_as_server_view("TCPv4", "", local));
        let v6: SocketAddr = "[::1]:50000".parse().unwrap();
        assert!(same_as_server_view("TCPv6", "::1/50000", v6));
        assert!(!same_as_server_view("TCPv4", "::1/50000", v6));
    }
}
