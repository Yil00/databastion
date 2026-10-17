//! Unit tests of the Audit stream's pieces (the integration tests are in
//! `crate::it`).

use super::*;
use crate::resp::{Limits, decode_all};

fn decode(bytes: &[u8]) -> Value {
    decode_all(
        bytes,
        Limits {
            bulk: 64 * 1024,
            items: 512,
            skip_oversized: true,
            reply: 4 * 1024 * 1024,
        },
    )
    .unwrap()
    .unwrap()
}

fn resp_entry(id: i64, ts: i64, args: &[&[u8]], peer: &str) -> Vec<u8> {
    let mut out = format!("*6\r\n:{id}\r\n:{ts}\r\n:15\r\n*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("${}\r\n{peer}\r\n$0\r\n\r\n", peer.len()).as_bytes());
    out
}

fn entry(id: i64, ts: i64, args: &[&[u8]], peer: &str) -> LogEntry {
    let learned = LearnedPatterns::new(["session:*"]);
    let ctx = Context {
        learned: &learned,
        stores: None,
        dbs: &[],
    };
    entries::parse_log_entry(&decode(&resp_entry(id, ts, args, peer)), &ctx).unwrap()
}

#[test]
fn cursors_round_trip() {
    let mut c = Cursor {
        run: Some(0xabc),
        slow: Some(41),
        large: None,
        acl: Some(-1),
        sync: Some(3),
        acl_counts: BTreeMap::new(),
    };
    c.acl_counts.insert(7, 2);
    assert_eq!(Cursor::decode(&c.encode()), Some(c));
    assert_eq!(Cursor::decode(b"v1\nbad 1\n"), None);
    assert_eq!(Cursor::decode(b"v0\n"), None);
}

#[test]
fn gaps_and_first_start() {
    let all = || {
        vec![
            entry(12, 1, &[b"GET", b"a"], "10.0.0.1:1"),
            entry(10, 1, &[b"GET", b"a"], "10.0.0.1:1"),
            entry(11, 1, &[b"GET", b"a"], "10.0.0.1:1"),
        ]
    };
    // First start: nothing replayed, the cursor at the newest entry.
    let (fresh, lost, next) = new_entries(all(), None);
    assert!(fresh.is_empty());
    assert_eq!((lost, next), (0, Some(12)));
    // From 7: 8 and 9 were overwritten.
    let (fresh, lost, next) = new_entries(all(), Some(7));
    assert_eq!(fresh.iter().map(|e| e.id).collect::<Vec<_>>(), [10, 11, 12]);
    assert_eq!((lost, next), (2, Some(12)));
    let (fresh, lost, _) = new_entries(all(), Some(11));
    assert_eq!((fresh.len(), lost), (1, 0));
    // An empty log keeps the cursor.
    assert_eq!(new_entries(Vec::new(), Some(5)).2, Some(5));
}

#[test]
fn a_parser_panic_drops_one_entry_only() {
    let learned = LearnedPatterns::default();
    let ctx = Context {
        learned: &learned,
        stores: None,
        dbs: &[],
    };
    let items = vec![
        decode(&resp_entry(1, 1, &[b"GET", b"a"], "10.0.0.1:1")),
        decode(&resp_entry(2, 1, &[b"GET", TEST_POISON], "10.0.0.1:1")),
        decode(&resp_entry(3, 1, &[b"GET", b"b"], "10.0.0.1:1")),
        decode(b"*1\r\n:4\r\n"),
    ];
    let (parsed, malformed) = parse_logs(&items, &ctx);
    assert_eq!(parsed.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 3]);
    assert_eq!(malformed, 2);
}

#[test]
fn attribution_needs_an_older_connection() {
    let list = "id=3 addr=10.0.0.9:5000 name=x age=100 db=0 user=alice\nid=4 addr=10.0.0.9:6000 age=1 user=bob";
    let clients =
        entries::parse_client_list(&decode(format!("${}\r\n{list}\r\n", list.len()).as_bytes()));
    assert_eq!(clients.len(), 2);
    let now = 1_000_000;
    let p = |port| Peer {
        addr: ClientAddr::Ip("10.0.0.9".parse().unwrap()),
        port,
    };
    // alice's connection opened 100 s ago: entries since are hers.
    assert!(attribute(&clients, p(5000), now - 10, now).is_some());
    // An entry older than the connection: the port was reused.
    assert!(attribute(&clients, p(5000), now - 200, now).is_none());
    // bob's connection opened 1 s ago: an entry 1 s ago is within the
    // margin, not attributed.
    assert!(attribute(&clients, p(6000), now - 1, now).is_none());
    assert!(attribute(&clients, p(7000), now, now).is_none());
}

#[test]
fn replicas_and_databases() {
    let repl = "role:master\r\nconnected_slaves:2\r\nslave0:ip=10.0.0.7,port=6379,state=online\r\nslave1:ip=10.0.0.8,port=6380,state=wait_bgsave\r\nmaster_replid:x\r\n";
    // Review L7: only replicas in a sync state.
    assert_eq!(
        syncing_replica_ips(repl),
        vec!["10.0.0.8".parse::<IpAddr>().unwrap()]
    );
    let mut l = state::Learned::default();
    l.dbs
        .insert(0, Arc::new(LearnedPatterns::new(["session:*", "user:*"])));
    l.dbs
        .insert(1, Arc::new(LearnedPatterns::new(["session:*"])));
    let (db, set) = log_database(&l, &[0]);
    assert_eq!((db.as_str(), set.len()), ("db0", 2));
    let (db, set) = log_database(&l, &[0, 1]);
    assert_eq!(
        (db.as_str(), set.patterns()),
        ("*", &["session:*".to_owned()][..])
    );
    // A database with keys but no learned set: nothing usable.
    let (_, set) = log_database(&l, &[0, 2]);
    assert!(set.is_empty());
}

#[test]
fn levels() {
    use databastion_core::{AuditLevel, NoteCode};
    let state = CheckState::default();
    let codes = |n: &[databastion_core::TargetNote]| n.iter().map(|n| n.code()).collect::<Vec<_>>();
    let all = AuditGrants {
        slowlog: Some(true),
        acl_log: Some(true),
        client_list: Some(true),
        commandlog: Some(false),
    };
    let (l, n) = level(&state, "t", Some(all), true);
    assert_eq!(
        (l, codes(&n)),
        (AuditLevel::None, vec![NoteCode::AuditStreamNotAvailable])
    );
    let (l, n) = level(&state, "t", Some(all), false);
    assert_eq!(
        (l, codes(&n)),
        (AuditLevel::None, vec![NoteCode::AuditStreamNotAvailable])
    );
    let running = state.audit.started("t");
    let (l, n) = level(&state, "t", Some(all), false);
    assert_eq!(l, AuditLevel::None);
    assert_eq!(
        codes(&n),
        vec![
            NoteCode::AuditLimitedPendingFirstRecord,
            NoteCode::AuditSlowOperationsOnly
        ]
    );
    let acl_only = AuditGrants {
        slowlog: Some(false),
        ..all
    };
    assert_eq!(
        codes(&level(&state, "t", Some(acl_only), false).1),
        vec![NoteCode::AuditAclLogOnly]
    );
    let nothing = AuditGrants {
        slowlog: Some(false),
        acl_log: Some(false),
        ..all
    };
    assert_eq!(
        codes(&level(&state, "t", Some(nothing), false).1),
        vec![NoteCode::AuditLogNotReadable]
    );
    state.audit.note_slow_record("t");
    state.audit.note_dropped("t", 3);
    let (l, n) = level(&state, "t", Some(all), false);
    assert_eq!(l, AuditLevel::Limited);
    assert_eq!(
        codes(&n),
        vec![
            NoteCode::AuditSlowOperationsOnly,
            NoteCode::AuditRecordsDropped
        ]
    );
    // Never Partial or Full.
    assert_eq!(level(&state, "t", None, false).0, AuditLevel::Limited);
    // Review L6: no stream running, no level, whatever was read before.
    drop(running);
    assert_eq!(level(&state, "t", Some(all), false).0, AuditLevel::None);
}

fn acl(id: Option<i64>, count: u64, ident: u64) -> AclEntry {
    AclEntry {
        id,
        count,
        reason: Reason::Auth,
        user: zeroize::Zeroizing::new("x".to_owned()),
        action: commands::Action::Read,
        object: NormalizedName::wildcard(),
        signals: Vec::new(),
        client: None,
        updated_ms: None,
        ident,
    }
}

#[test]
fn acl_log_deltas() {
    let deltas = |c: &mut Cursor, i: &mut Option<HashMap<(u64, u32), u64>>, e: &[AclEntry]| {
        let (d, lost) = acl_deltas(c, i, e);
        (d.iter().map(|(n, _)| *n).collect::<Vec<_>>(), lost)
    };
    // With ids: an empty log at the first poll is the baseline; entries
    // that appear later are new (the bug the integration test found).
    let (mut c, mut i) = (Cursor::default(), None);
    assert_eq!(deltas(&mut c, &mut i, &[]), (vec![], 0));
    assert_eq!(deltas(&mut c, &mut i, &[acl(Some(0), 1, 9)]), (vec![1], 0));
    // A grown count reports its growth; a new id after a gap counts the
    // lost ones.
    assert_eq!(
        deltas(&mut c, &mut i, &[acl(Some(0), 3, 9), acl(Some(3), 1, 8)]),
        (vec![2, 1], 2)
    );
    // A first poll on a non-empty log: no history replay.
    let (mut c, mut i) = (Cursor::default(), None);
    assert_eq!(deltas(&mut c, &mut i, &[acl(Some(5), 4, 1)]), (vec![0], 0));
    assert_eq!(deltas(&mut c, &mut i, &[acl(Some(5), 4, 1)]), (vec![0], 0));
    // Without ids (Redis before 7.2): by identity.
    let (mut c, mut i) = (Cursor::default(), None);
    assert_eq!(deltas(&mut c, &mut i, &[acl(None, 2, 7)]), (vec![0], 0));
    assert_eq!(
        deltas(&mut c, &mut i, &[acl(None, 5, 7), acl(None, 1, 8)]),
        (vec![3, 1], 0)
    );
    // Review M3: a second entry of the same identity (Redis groups for
    // 60 s only) is new, with its whole count; the older one keeps its
    // own count. The log lists the newest first.
    assert_eq!(
        deltas(
            &mut c,
            &mut i,
            &[acl(None, 4, 7), acl(None, 5, 7), acl(None, 1, 8)]
        ),
        (vec![4, 0, 0], 0)
    );
    assert_eq!(
        deltas(
            &mut c,
            &mut i,
            &[acl(None, 6, 7), acl(None, 5, 7), acl(None, 1, 8)]
        ),
        (vec![2, 0, 0], 0)
    );
}

fn stream_parts() -> (AuditConfig, TargetConfig, CheckState) {
    let target = databastion_core::AgentConfig::parse(
        "{console: {url: \"https://c.example\"}, state_dir: /s, targets: [{id: own-t, \
         engine: valkey, host: 127.0.0.1, account: databastion, secret: {env: X}, \
         redis: {tls: disable}}]}",
    )
    .unwrap()
    .targets[0]
        .clone();
    let cfg = AuditConfig::local(&target, 10, &databastion_core::config::Limits::default());
    (cfg, target, CheckState::default())
}

fn clients_of(list: &str) -> Vec<Client> {
    entries::parse_client_list(&decode(format!("${}\r\n{list}\r\n", list.len()).as_bytes()))
}

fn principal(ev: &MaskedEvent) -> (String, bool, Option<ClientAddr>) {
    let p = ev.principal();
    (p.account_name().to_owned(), p.is_not_recorded(), p.client())
}

/// Review H1, M1, L1: socket peers are never attributed nor taken for the
/// agent's; an attributed connection that is not the agent's is never
/// the agent's whatever its address; a large reply above the shape's
/// bound is reported.
#[test]
fn attribution_and_own_entries() {
    let (cfg, target, state) = stream_parts();
    let mut st = Stream {
        cfg: &cfg,
        target: &target,
        state: &state,
        own: OwnAccount::new(
            "databastion",
            None,
            None,
            1000,
            state.audit.own_usage("own-t"),
        ),
        store: None,
        cursor: Cursor::default(),
        saved: None,
        skip: 0,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run: Some(99),
    };
    let now = 2_000_000_000;
    let db = NormalizedName::wildcard();
    // The agent's own session (id 1) and a local user (id 2), both on the
    // socket.
    let _own = own::register("own-t", 1, None, Some(99), SystemTime::now());
    let socket = clients_of(
        "id=1 addr=/run/valkey.sock:0 age=100 user=databastion\nid=2 addr=/run/valkey.sock:0 age=100 user=alice",
    );
    let e = entry(
        5,
        now - 10,
        &[b"GETRANGE", b"session:x", b"0", b"4095"],
        "/run/valkey.sock:0",
    );
    let ev = st
        .log_event(&e, EventSource::RedisSlowlog, &db, &socket, now, 0)
        .expect("a socket entry is reported");
    assert_eq!(
        principal(&ev),
        (String::new(), true, Some(ClientAddr::Local))
    );

    // TCP: the agent's own connection (id 1), its own shape: left out.
    let _own3 = own::register("own-t", 3, None, Some(99), SystemTime::now());
    let tcp = clients_of(
        "id=3 addr=10.0.0.1:4000 age=100 user=databastion\nid=4 addr=10.0.0.2:5000 age=100 user=alice",
    );
    own::seen("own-t", 3, Some(99), "10.0.0.1:4000".parse().unwrap());
    let mine = entry(
        6,
        now - 10,
        &[b"GETRANGE", b"session:x", b"0", b"4095"],
        "10.0.0.1:4000",
    );
    assert!(
        st.log_event(&mine, EventSource::RedisSlowlog, &db, &tcp, now, 0)
            .is_none()
    );
    // The same address marked as the agent's (a spoofed or stale seen
    // address), but `CLIENT LIST` attributes it to another connection:
    // reported with that user (M1).
    own::seen("own-t", 3, Some(99), "10.0.0.2:5000".parse().unwrap());
    let theirs = entry(
        7,
        now - 10,
        &[b"GETRANGE", b"session:x", b"0", b"4095"],
        "10.0.0.2:5000",
    );
    let ev = st
        .log_event(&theirs, EventSource::RedisSlowlog, &db, &tcp, now, 0)
        .expect("another connection's entry is reported");
    assert_eq!(principal(&ev).0, "alice");
    // Another server run: the agent's id means nothing.
    st.run = Some(100);
    let ev = st.log_event(&mine, EventSource::RedisSlowlog, &db, &tcp, now, 0);
    assert_eq!(ev.map(|e| principal(&e).0), Some("databastion".to_owned()));
    st.run = Some(99);
    // L1: a large reply above the shape's bound is reported.
    let mut big = mine.clone();
    big.size = 1 << 30;
    let ev = st
        .log_event(&big, EventSource::RedisCommandlog, &db, &tcp, now, 0)
        .expect("a reply above the agent's bound is reported");
    assert_eq!(ev.bytes(), Some(1 << 30));
}

/// The engine-matrix flake of `audit_reports_slow_reads_and_never_the_agents_own`
/// (ADR-0052 decision 8, #237 review H3): a session of the agent behind NAT
/// (the server reports another address than its local one) runs commands
/// and closes before the stream's next `CLIENT LIST`. Its slow-log entries
/// carry no connection id, only that address, and `CLIENT LIST` no longer
/// lists it: unless the session recorded its reported address at connect
/// time (`CLIENT LIST ID`), they came out as another client's, with the
/// agent's client name.
#[test]
fn an_own_session_closed_before_the_next_poll_stays_the_agents() {
    let (cfg, target, state) = stream_parts();
    let run = Some(77);
    let mut st = Stream {
        cfg: &cfg,
        target: &target,
        state: &state,
        own: OwnAccount::new(
            "databastion",
            None,
            None,
            1000,
            state.audit.own_usage("own-t"),
        ),
        store: None,
        cursor: Cursor::default(),
        saved: None,
        skip: 0,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run,
    };
    let db = NormalizedName::wildcard();
    let now_s = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let opened = SystemTime::now() - Duration::from_secs(20);
    let named = |id: i64, ts: i64, peer: &str| {
        let mut e = entry(id, ts, &[b"SCAN", b"0", b"COUNT", b"500"], peer);
        e.app = entries::application(b"databastion-agent");
        e
    };
    // The poll's `CLIENT LIST`: both sessions are gone, another client is
    // connected.
    let clients = clients_of("id=90 addr=10.0.0.2:5000 age=100 user=alice");

    // A session that did not record its address (`+client|list` not
    // known to be granted) and that no `CLIENT LIST` saw open.
    let unseen = own::register(
        "own-t",
        22,
        Some("127.0.0.1:50501".parse().unwrap()),
        run,
        opened,
    );
    drop(unseen);
    let ev = st
        .log_event(
            &named(1, now_s - 5, "172.18.0.1:40113"),
            EventSource::RedisSlowlog,
            &db,
            &clients,
            now_s,
            0,
        )
        .expect("an address the agent never recorded is not the agent's");
    assert_eq!(
        principal(&ev),
        (
            String::new(),
            true,
            Some(ClientAddr::Ip("172.18.0.1".parse().unwrap()))
        )
    );

    // The fix: the session records the address the server reports for it
    // (its own `CLIENT LIST ID` line) before its first command, then
    // closes before the poll.
    let own_line = "id=21 addr=172.18.0.1:40112 laddr=172.18.0.2:6379 fd=9 name=databastion-agent age=0 db=0 user=databastion\n";
    let reply = decode(format!("${}\r\n{own_line}\r\n", own_line.len()).as_bytes());
    let session = own::register(
        "own-t",
        21,
        Some("127.0.0.1:50500".parse().unwrap()),
        run,
        opened,
    );
    let addr = entries::own_address(&reply, 21).expect("its own line");
    own::seen("own-t", 21, run, addr);
    drop(session);
    // Its entries, polled after it closed: the agent's routine, left out.
    for (id, ts) in [(2, now_s - 19), (3, now_s - 1), (4, now_s)] {
        assert!(
            st.log_event(
                &named(id, ts, "172.18.0.1:40112"),
                EventSource::RedisSlowlog,
                &db,
                &clients,
                now_s,
                0,
            )
            .is_none(),
            "entry {id}"
        );
    }
    // The same address before the session opened, or long after it closed
    // (a port reused by another client), is not the agent's, whatever its
    // client name.
    for ts in [now_s - 60, now_s + 60] {
        assert!(
            st.log_event(
                &named(5, ts, "172.18.0.1:40112"),
                EventSource::RedisSlowlog,
                &db,
                &clients,
                now_s,
                0,
            )
            .is_some()
        );
    }
    // Another server run: the recorded address means nothing.
    st.run = Some(78);
    assert!(
        st.log_event(
            &named(6, now_s - 1, "172.18.0.1:40112"),
            EventSource::RedisSlowlog,
            &db,
            &clients,
            now_s,
            0,
        )
        .is_some()
    );
}

/// The registry keeps the agent's open connections (the Audit stream's,
/// held for days) when it is full of closed ones.
#[test]
fn a_full_registry_forgets_closed_connections_first() {
    let t = "own-full-t";
    let run = Some(5);
    let held = own::register(t, 1, None, run, SystemTime::now());
    for id in 2..3000 {
        drop(own::register(t, id, None, run, SystemTime::now()));
    }
    assert!(own::is_own_open_id(t, 1, run));
    drop(held);
}

/// Review L4(c), L4(d): an own session's address counts from its connect
/// to 2 s after its close (entry times have a one-second granularity), not
/// before nor later: an entry 3 s after the close, or 3 s before the
/// connect, is reported (another client on the same address, or a reused
/// port).
#[test]
fn an_own_address_counts_within_the_sessions_lifetime_only() {
    let (cfg, target, state) = stream_parts();
    let run = Some(55);
    let mut st = Stream {
        cfg: &cfg,
        target: &target,
        state: &state,
        own: OwnAccount::new(
            "databastion",
            None,
            None,
            1000,
            state.audit.own_usage("own-t"),
        ),
        store: None,
        cursor: Cursor::default(),
        saved: None,
        skip: 0,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run,
    };
    let db = NormalizedName::wildcard();
    let secs = |t: SystemTime| {
        i64::try_from(t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()).unwrap()
    };
    // Connected 30 s ago, closed now.
    let connected = SystemTime::now() - Duration::from_secs(30);
    let r = own::register("own-t", 41, None, run, connected);
    own::seen("own-t", 41, run, "172.18.0.1:40141".parse().unwrap());
    let before_close = SystemTime::now();
    drop(r);
    let after_close = SystemTime::now();
    let mut ev = |ts: i64| {
        st.log_event(
            &entry(
                1,
                ts,
                &[b"SCAN", b"0", b"COUNT", b"500"],
                "172.18.0.1:40141",
            ),
            EventSource::RedisSlowlog,
            &db,
            &[],
            secs(after_close),
            0,
        )
    };
    // Close + 2 s (the entry's second is at or before the close's): own.
    assert!(ev(secs(before_close) + 2).is_none());
    // Close + 3 s (rounded up): reported.
    let late = ev(secs(after_close) + 4).expect("after the close's margin");
    assert!(principal(&late).1);
    assert!(ev(secs(after_close) + 3).is_some());
    // During the session: own.
    assert!(ev(secs(connected) + 1).is_none());
    // 3 s before the connect: reported.
    assert!(ev(secs(connected) - 3).is_some());
}

/// The P9-D end-to-end finding: with keys in two databases whose learned
/// patterns differ (`session:*` only in `db1`), slow-log entries, which
/// carry no database, are matched against the patterns learned in every
/// database: none, so every object is `*`. The own-read budget was then
/// charged on that one object for the whole scan, and the agent's own
/// sampling reads came back as one read of `*` once `max_sample_rows` rows
/// of all patterns together had been read. The budget is kept per pattern
/// (ADR-0052 decision 8): each own sampling read is charged on the pattern
/// its key matches in the databases where it does; the event's object
/// stays `*`, and a pattern's budget still runs out. The pattern budgets
/// are scaled by `PER_KEY_MAX` (ADR-0052 refinement of 2026-10-16), the
/// `*` fallback is not.
#[test]
fn own_reads_are_budgeted_per_pattern_when_the_database_is_unknown() {
    let (cfg, target, state) = stream_parts();
    let run = Some(4242);
    // `max_sample_rows` 2: 98 rows per pattern, 2 for `*`.
    let budget = 2;
    assert_eq!(budget * PER_KEY_MAX, 98);
    let mut st = Stream {
        cfg: &cfg,
        target: &target,
        state: &state,
        own: OwnAccount::new(
            "databastion",
            None,
            None,
            budget,
            state.audit.own_usage("own-t"),
        ),
        store: None,
        cursor: Cursor::default(),
        saved: None,
        skip: 0,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run,
    };
    let mut learned = state::Learned::default();
    learned.dbs.insert(
        0,
        Arc::new(LearnedPatterns::new([
            "customer:*",
            "events:*",
            "user:*:profile",
        ])),
    );
    learned.dbs.insert(
        1,
        Arc::new(LearnedPatterns::new(["session:*", "user:*:profile"])),
    );
    let (database, log_set) = log_database(&learned, &[0, 1]);
    assert_eq!(database.as_str(), "*");
    assert_eq!(log_set.patterns(), ["user:*:profile".to_owned()]);
    let sets: Vec<(u16, &LearnedPatterns)> =
        learned.dbs.iter().map(|(d, s)| (*d, s.as_ref())).collect();
    let parse = |id: i64, args: &[&[u8]], peer: &str, dbs: &[(u16, &LearnedPatterns)]| {
        let ctx = Context {
            learned: &log_set,
            stores: None,
            dbs,
        };
        entries::parse_log_entry(&decode(&resp_entry(id, 1, args, peer)), &ctx).unwrap()
    };
    let now_s = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    // The agent's Discovery session, its address recorded.
    let _own = own::register("own-t", 4201, None, run, SystemTime::now());
    own::seen("own-t", 4201, run, "10.0.42.1:4000".parse().unwrap());
    let mine = "10.0.42.1:4000";
    let left_out = |e: &mut LogEntry, st: &mut Stream<'_>| {
        e.ts = now_s;
        st.log_event(e, EventSource::RedisSlowlog, &database, &[], now_s, 0)
            .is_none()
    };
    // One scan's sampling: 5 hashes of `session:*` (16 rows each, and its
    // `TYPE`), 5 streams of `events:*` (16 rows each), 60 strings of
    // `customer:*`: 225 rows in all, at most 85 per pattern (within 98,
    // far over 2). Every entry's object is `*`; every entry is left out.
    let mut id = 0;
    let mut next = || {
        id += 1;
        id
    };
    for k in 0..5 {
        let key = format!("session:{k:032x}");
        let mut t = parse(next(), &[b"TYPE", key.as_bytes()], mine, &sets);
        assert!(left_out(&mut t, &mut st), "TYPE {k}");
        let mut e = parse(next(), &[b"HRANDFIELD", key.as_bytes(), b"17"], mine, &sets);
        assert_eq!(e.objects, [NormalizedName::wildcard()]);
        assert_eq!(e.budget.len(), 1);
        assert!(left_out(&mut e, &mut st), "HRANDFIELD {k}");
        let key = format!("events:{k}");
        let mut e = parse(
            next(),
            &[b"XREVRANGE", key.as_bytes(), b"+", b"-", b"COUNT", b"16"],
            mine,
            &sets,
        );
        assert!(left_out(&mut e, &mut st), "XREVRANGE {k}");
    }
    for k in 0..60 {
        let key = format!("customer:{}", 1000 + k);
        let mut e = parse(
            next(),
            &[b"GETRANGE", key.as_bytes(), b"0", b"4095"],
            mine,
            &sets,
        );
        assert!(left_out(&mut e, &mut st), "GETRANGE {k}");
    }
    let mut keys = state
        .audit
        .own_usage("own-t")
        .lock()
        .unwrap()
        .budgeted_objects();
    keys.sort();
    assert_eq!(
        keys,
        [
            "db0\u{0}\u{0}customer:*",
            "db0\u{0}\u{0}events:*",
            "db1\u{0}\u{0}session:*"
        ]
    );
    // A key whose pattern was learned in both databases is charged in
    // both (fail closed).
    let mut e = parse(
        next(),
        &[b"HRANDFIELD", b"user:jdupont:profile", b"17"],
        mine,
        &sets,
    );
    assert_eq!(e.budget.len(), 2);
    assert!(left_out(&mut e, &mut st));
    // A pattern's budget still runs out: the reads beyond it are
    // reported, under the event's object (`*`), never the pattern.
    let key = format!("session:{:032x}", 99);
    let mut e = parse(next(), &[b"HRANDFIELD", key.as_bytes(), b"17"], mine, &sets);
    assert!(!left_out(&mut e, &mut st));
    e.ts = now_s;
    let ev = st
        .log_event(&e, EventSource::RedisSlowlog, &database, &[], now_s, 0)
        .expect("over the pattern's budget");
    assert_eq!(principal(&ev).0, "databastion");
    assert_eq!(ev.objects().len(), 1);
    assert_eq!(ev.objects()[0].object().as_str(), "*");
    assert_eq!(ev.objects()[0].database().as_str(), "*");
    // A key no database's patterns match keeps the event's object as its
    // budget: `*`, shared by every such key, with the plain budget (not
    // scaled): two one-row reads, then reported.
    for k in 0..2 {
        let key = format!("unlearned:{k}");
        let mut e = parse(
            next(),
            &[b"GETRANGE", key.as_bytes(), b"0", b"4095"],
            mine,
            &sets,
        );
        assert!(e.budget.is_empty());
        assert!(left_out(&mut e, &mut st), "unlearned {k}");
    }
    let mut e = parse(
        next(),
        &[b"GETRANGE", b"unlearned:2", b"0", b"4095"],
        mine,
        &sets,
    );
    assert!(!left_out(&mut e, &mut st));
    // A 16-row read of an unlearned key is over the plain budget at once.
    let mut e = parse(next(), &[b"LRANGE", b"other:x", b"0", b"15"], mine, &sets);
    assert!(!left_out(&mut e, &mut st));
    // Another client's read of a learned key: reported as before, `*`.
    let theirs = parse(
        next(),
        &[b"HRANDFIELD", key.as_bytes(), b"17"],
        "10.0.42.9:5000",
        &sets,
    );
    let ev = st
        .log_event(&theirs, EventSource::RedisSlowlog, &database, &[], now_s, 0)
        .expect("another client's read");
    assert!(principal(&ev).1);
    assert_eq!(ev.objects()[0].object().as_str(), "*");
    // No database with learned patterns: the event's object.
    let one = parse(next(), &[b"HRANDFIELD", key.as_bytes(), b"17"], mine, &[]);
    assert!(one.budget.is_empty());
}

/// ADR-0052 refinement of 2026-10-16, condition 2: the rows the own-read
/// budget charges for one key's whole sampling sequence (its `TYPE` in the
/// walk, then the sampling commands as `discover` sends them, encoded by
/// the same `Cmd`), summed with the core's `charged_rows`, stay within
/// `PER_KEY_MAX` for every type, and the hash's is exactly it. A source
/// check of `discover.rs` fails when a command is added to the walk or the
/// sampling without updating this sequence, and so the factor.
#[test]
fn one_keys_sampling_sequence_fits_per_key_max() {
    use crate::cmd::{Cmd, MEMBERS_PER_KEY};
    use databastion_core::audit::own::charged_rows;

    // The commands `discover` sends (the source check below).
    let src = include_str!("../discover.rs");
    let mut used: Vec<&str> = src
        .match_indices("Cmd::")
        .map(|(i, _)| {
            let rest = &src[i + 5..];
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    used.sort_unstable();
    used.dedup();
    assert_eq!(
        used,
        [
            "ClientNoTouchOn",
            "GetRange",
            "HMGet",
            "HRandField",
            "HStrLen",
            "Info",
            "LRange",
            "ReadOnly",
            "SRandMember",
            "Scan",
            "Select",
            "Type",
            "XRevRange",
            "ZRandMember"
        ],
        "discover sends another command: add it to the sequences below and to PER_KEY_MAX"
    );
    let start = src.find("async fn sample_pattern(").unwrap();
    let body = &src[start..];
    let body = &body[..body.find("\nfn ").unwrap()];
    assert_eq!(
        (
            body.matches(".call(").count(),
            body.matches(".pipeline(").count()
        ),
        (5, 1),
        "the sampling sends another statement per key: update the sequences below and PER_KEY_MAX"
    );

    let learned = LearnedPatterns::new(["k:*"]);
    let ctx = Context {
        learned: &learned,
        stores: None,
        dbs: &[],
    };
    let rows_of = |cmd: &Cmd<'_>| -> u64 {
        let mut req = Vec::new();
        cmd.encode(&mut req);
        let Value::Array(args) = decode(&req) else {
            panic!("a request is an array")
        };
        let args: Vec<&[u8]> = args.iter().map(|a| a.as_bytes().unwrap()).collect();
        let e = entries::parse_log_entry(&decode(&resp_entry(1, 1, &args, "10.0.0.1:1")), &ctx)
            .unwrap();
        let OwnShape::Keyed { rows, .. } = e.own else {
            panic!("{cmd:?}: not one of the agent's sampling shapes")
        };
        let ev = MaskedEvent::new(
            EventSource::RedisSlowlog,
            EventAction::Read,
            EventPrincipal::account("databastion"),
            SystemTime::UNIX_EPOCH,
        )
        .with_rows(Some(rows));
        charged_rows(&ev, u64::MAX)
    };
    let key: &[u8] = b"k:1";
    let m = MEMBERS_PER_KEY as usize;
    let fields: Vec<Vec<u8>> = (0..m).map(|i| format!("f{i}").into_bytes()).collect();
    let names: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let mut hash = vec![Cmd::Type(key), Cmd::HRandField(key)];
    hash.extend(names.iter().map(|f| Cmd::HStrLen(key, f)));
    hash.push(Cmd::HMGet(key, &names));
    let sequences: [(&str, Vec<Cmd<'_>>); 6] = [
        ("string", vec![Cmd::Type(key), Cmd::GetRange(key)]),
        ("hash", hash),
        ("list", vec![Cmd::Type(key), Cmd::LRange(key)]),
        ("set", vec![Cmd::Type(key), Cmd::SRandMember(key)]),
        ("zset", vec![Cmd::Type(key), Cmd::ZRandMember(key)]),
        ("stream", vec![Cmd::Type(key), Cmd::XRevRange(key)]),
    ];
    for (kind, seq) in &sequences {
        let total = seq.iter().map(&rows_of).fold(0u64, u64::saturating_add);
        assert!(total <= PER_KEY_MAX, "{kind}: {total} > {PER_KEY_MAX}");
        if *kind == "hash" {
            assert_eq!(total, PER_KEY_MAX, "the factor is the hash's sequence");
        }
    }
    assert_eq!(PER_KEY_MAX, 49);
}

/// End-of-phase-9 review G7: an `MGET` of more distinct key patterns than
/// an event can name (16 harmless ones, then a sensitive one) does not
/// hide the last: the event names `*` and is always reported. A `SORT …
/// BY / GET` keeps its `*`.
#[test]
fn a_command_past_the_object_bound_names_star_and_is_always_reported() {
    let (cfg, target, state) = stream_parts();
    let mut st = Stream {
        cfg: &cfg,
        target: &target,
        state: &state,
        own: OwnAccount::new("databastion", None, None, 2, state.audit.own_usage("own-t")),
        store: None,
        cursor: Cursor::default(),
        saved: None,
        skip: 0,
        acl_ident_key: std::collections::hash_map::RandomState::new(),
        acl_idents: None,
        run: Some(4243),
    };
    let names: Vec<String> = (0..16u8)
        .map(|i| format!("harmless{}:*", char::from(b'a' + i)))
        .chain(["customer:*".to_owned()])
        .collect();
    let learned = LearnedPatterns::new(names.iter().map(String::as_str));
    let keys: Vec<String> = names.iter().map(|p| p.replace('*', "x")).collect();
    let mut args: Vec<&[u8]> = vec![b"MGET"];
    args.extend(keys.iter().map(|k| k.as_bytes()));
    let ctx = Context {
        learned: &learned,
        stores: None,
        dbs: &[],
    };
    let now_s = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut e = entries::parse_log_entry(&decode(&resp_entry(1, 1, &args, "10.0.42.9:5000")), &ctx)
        .unwrap();
    assert_eq!(
        e.objects.len(),
        17,
        "the connector keeps one past the bound"
    );
    e.ts = now_s;
    let database = NormalizedName::wildcard();
    let ev = st
        .log_event(&e, EventSource::RedisSlowlog, &database, &[], now_s, 0)
        .expect("another client's read");
    assert!(ev.objects_overflowed());
    assert!(ev.always_report());
    assert_eq!(ev.objects().len(), 16);
    assert!(ev.objects().iter().any(|o| o.object().as_str() == "*"));
    // `SORT … BY`: the patterns' keys are `*`, whatever the objects.
    let e = entries::parse_log_entry(
        &decode(&resp_entry(
            2,
            1,
            &[b"SORT", b"customer:x", b"BY", b"w_*"],
            "10.0.42.9:5000",
        )),
        &ctx,
    )
    .unwrap();
    let objects: Vec<&str> = e.objects.iter().map(NormalizedName::as_str).collect();
    assert_eq!(objects, ["customer:*", "*"]);
}
