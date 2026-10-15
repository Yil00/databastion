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
    assert_eq!(
        replica_ips(repl),
        vec![
            "10.0.0.7".parse::<IpAddr>().unwrap(),
            "10.0.0.8".parse().unwrap()
        ]
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
    drop(running);
    // Never Partial or Full.
    assert_eq!(level(&state, "t", None, false).0, AuditLevel::Limited);
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
    let deltas = |c: &mut Cursor, i: &mut Option<HashMap<u64, u64>>, e: &[AclEntry]| {
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
}
