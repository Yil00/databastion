//! Log entries reduced at parse time (ADR-0052 decision 8, security
//! review H1). From a `SLOWLOG` / `COMMANDLOG` entry the parser keeps the
//! command name (from the closed table, [`commands`]), the objects of the
//! key arguments at the table's positions (each matched against the
//! learned patterns, never kept as text), the `COUNT` of a `SCAN` when it
//! sets a signal, the client's address and name, the id, time and size.
//! From an `ACL LOG` entry: the reason, the command's action or the key's
//! object, the user name (needed for the core's own rules: fingerprinted
//! on failed authentications), the count, the ids and times, and its
//! `client-info` reduced to `id`, `addr`, `name`, `user` and `db`. Every
//! other argument (values, credentials, script bodies, channel names, the
//! globs of `KEYS` and `SCAN … MATCH`) is dropped here, never buffered
//! beyond the decoded reply (zeroized) and never logged.

use std::net::{IpAddr, SocketAddr};

use databastion_classifiers::keys::LearnedPatterns;
use databastion_classifiers::masking::{ClientAddr, Signal};
use databastion_classifiers::names::NormalizedName;
use databastion_core::cas_guard::CasStores;
use zeroize::Zeroizing;

use super::commands::{self, Action};
use crate::cmd::{
    ACL_LOG_ENTRIES, CLIENT_NAME, HASH_FIELDS_ASKED, LOG_ENTRIES, MEMBERS_PER_KEY, SCAN_COUNT,
    VALUE_BYTES,
};
use crate::guard;
use crate::resp::Value;

/// Contract `AccessEvent.objects.maxItems`.
const MAX_OBJECTS: usize = 16;
/// A `SCAN` with a `COUNT` above this sets `shape.keyspace_enumeration`.
pub(crate) const ENUMERATION_COUNT: u64 = 1000;
/// Longest user name kept (longer: cut, then fingerprinted by the core).
const MAX_USER_BYTES: usize = 1024;
/// Contract `Principal.application.maxLength`.
const MAX_APP_CHARS: usize = 64;
/// Most `CLIENT LIST` lines read.
const MAX_CLIENTS: usize = 100_000;

/// An entry that does not have the expected shape (dropped, counted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// A client address as the server logs it: the IP (or a Unix socket) and
/// the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) addr: ClientAddr,
    pub(crate) port: u16,
}

impl Peer {
    /// `ip:port`, `[ipv6]:port`, or a Unix socket path: `/…:0` in `CLIENT
    /// LIST`, `[/…:0]:0` in the slow log (measured on Valkey 9.0.6).
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        if text.starts_with('/') || text.starts_with("[/") {
            return Some(Self {
                addr: ClientAddr::Local,
                port: 0,
            });
        }
        let (ip, port) = if let Some(rest) = text.strip_prefix('[') {
            let (ip, port) = rest.split_once("]:")?;
            (ip, port)
        } else {
            text.rsplit_once(':')?
        };
        Some(Self {
            addr: ClientAddr::Ip(ip.parse::<IpAddr>().ok()?),
            port: port.parse().ok()?,
        })
    }

    /// The socket address, for a TCP peer.
    pub(crate) fn socket(self) -> Option<SocketAddr> {
        match self.addr {
            ClientAddr::Ip(ip) => Some(SocketAddr::new(ip, self.port)),
            ClientAddr::Local => None,
        }
    }
}

/// A client name reduced as the contract's `application` (every character
/// outside `[A-Za-z0-9 ._:/+-]` becomes `_`, at most 64): client names are
/// client-declared and may hold values (accepted residual risk, L6).
pub(crate) fn application(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let app: String = text
        .chars()
        .take(MAX_APP_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | ':' | '/' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    (!app.is_empty()).then_some(app)
}

/// Whether one of the agent's own command shapes (decision 6): the exact
/// commands and constant arguments the connector sends, with the largest
/// reply the agent's client accepts for it (`max_reply`, bytes: a
/// `large-reply` entry above it is not the agent's routine; review L1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnShape {
    No,
    /// A command without a key (a walk's `SCAN`, `INFO`, the Audit reads,
    /// the handshake): left out without a budget when it is the agent's.
    Unkeyed {
        max_reply: u64,
    },
    /// A sampling command, reading at most `rows` members.
    Keyed {
        rows: u64,
        max_reply: u64,
    },
}

impl OwnShape {
    /// The largest reply of the shape (`0` for [`Self::No`]).
    pub(crate) fn max_reply(self) -> u64 {
        match self {
            Self::No => 0,
            Self::Unkeyed { max_reply } | Self::Keyed { max_reply, .. } => max_reply,
        }
    }
}

/// The reply bound of a command the connector sends (`Cmd::limits`).
fn bound(cmd: &crate::cmd::Cmd<'_>) -> u64 {
    cmd.limits().reply as u64
}

/// What a slow-log or command-log entry is reduced to.
#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    pub(crate) id: i64,
    /// Unix seconds (server clock).
    pub(crate) ts: i64,
    /// Duration (µs) or size (bytes, `large-reply`).
    pub(crate) size: u64,
    pub(crate) action: Action,
    pub(crate) objects: Vec<NormalizedName>,
    pub(crate) signals: Vec<Signal>,
    pub(crate) peer: Option<Peer>,
    pub(crate) app: Option<String>,
    pub(crate) own: OwnShape,
}

/// What the parser needs to reduce key arguments.
pub(crate) struct Context<'a> {
    pub(crate) learned: &'a LearnedPatterns,
    pub(crate) stores: Option<&'a CasStores>,
}

fn int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Int(n) => Some(*n),
        Value::Str(b) => std::str::from_utf8(b.as_slice()).ok()?.parse().ok(),
        _ => None,
    }
}

/// The marker a server puts in place of the arguments past 32.
fn is_more_arguments(arg: &[u8]) -> bool {
    arg.starts_with(b"... (") && arg.ends_with(b" more arguments)")
}

/// An argument the server cut (`<first 128 bytes>... (N more bytes)`):
/// the kept bytes and `true`.
fn uncut(arg: &[u8]) -> (&[u8], bool) {
    const TAIL: &[u8] = b" more bytes)";
    if arg.ends_with(TAIL) {
        let body = arg.get(..arg.len() - TAIL.len()).unwrap_or_default();
        let digits = body.iter().rev().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0 {
            let before = body.get(..body.len() - digits).unwrap_or_default();
            if let Some(kept) = before.strip_suffix(b"... (") {
                return (kept, true);
            }
        }
    }
    (arg, false)
}

fn eq(a: Option<&[u8]>, b: &[u8]) -> bool {
    a.is_some_and(|a| a.eq_ignore_ascii_case(b))
}

fn num(a: Option<&[u8]>, n: impl ToString) -> bool {
    a == Some(n.to_string().as_bytes())
}

/// The own shape of `args` (decision 6; constants and reply bounds from
/// `cmd`).
fn own_shape(args: &[Option<&[u8]>]) -> OwnShape {
    use crate::cmd::{Cmd, CommandLog, InfoSection};
    const K: &[u8] = b"k";
    let a = |i: usize| args.get(i).copied().flatten();
    let n = args.len();
    let name = a(0);
    let keyed = |rows: u64, cmd: Cmd<'_>| OwnShape::Keyed {
        rows,
        max_reply: bound(&cmd),
    };
    if eq(name, b"type") && n == 2 {
        return keyed(0, Cmd::Type(K));
    }
    if eq(name, b"getrange") && n == 4 && num(a(2), 0) && num(a(3), VALUE_BYTES - 1) {
        return keyed(1, Cmd::GetRange(K));
    }
    let m = u64::from(MEMBERS_PER_KEY);
    // Field names, of which 16 are read (review L1: charged 16 rows).
    if eq(name, b"hrandfield") && n == 3 && num(a(2), HASH_FIELDS_ASKED) {
        return keyed(m, Cmd::HRandField(K));
    }
    if eq(name, b"hstrlen") && n == 3 {
        return keyed(0, Cmd::HStrLen(K, K));
    }
    if eq(name, b"hmget") && (3..=2 + MEMBERS_PER_KEY as usize).contains(&n) {
        return keyed(n as u64 - 2, Cmd::HMGet(K, &[]));
    }
    if eq(name, b"srandmember") && n == 3 && num(a(2), m) {
        return keyed(m, Cmd::SRandMember(K));
    }
    if eq(name, b"zrandmember") && n == 3 && num(a(2), m) {
        return keyed(m, Cmd::ZRandMember(K));
    }
    if eq(name, b"lrange") && n == 4 && num(a(2), 0) && num(a(3), m - 1) {
        return keyed(m, Cmd::LRange(K));
    }
    if eq(name, b"xrevrange")
        && n == 6
        && a(2) == Some(b"+")
        && a(3) == Some(b"-")
        && eq(a(4), b"count")
        && num(a(5), m)
    {
        return keyed(m, Cmd::XRevRange(K));
    }
    let unkeyed = |cmd: Cmd<'_>| OwnShape::Unkeyed {
        max_reply: bound(&cmd),
    };
    if eq(name, b"scan") && n == 4 && eq(a(2), b"count") && num(a(3), SCAN_COUNT) {
        return unkeyed(Cmd::Scan { cursor: 0 });
    }
    if eq(name, b"info") && n == 2 {
        return unkeyed(Cmd::Info(InfoSection::Server));
    }
    if eq(name, b"slowlog") && n == 3 && eq(a(1), b"get") && num(a(2), LOG_ENTRIES) {
        return unkeyed(Cmd::SlowlogGet);
    }
    if eq(name, b"commandlog")
        && n == 4
        && eq(a(1), b"get")
        && num(a(2), LOG_ENTRIES)
        && (eq(a(3), b"slow") || eq(a(3), b"large-reply"))
    {
        return unkeyed(Cmd::CommandlogGet(CommandLog::Slow));
    }
    if eq(name, b"acl") && n == 3 && eq(a(1), b"log") && num(a(2), ACL_LOG_ENTRIES) {
        return unkeyed(Cmd::AclLog);
    }
    if eq(name, b"client") && n == 2 && eq(a(1), b"list") {
        return unkeyed(Cmd::ClientList);
    }
    // A session's own line, at connect time (`own`).
    if eq(name, b"client")
        && n == 4
        && eq(a(1), b"list")
        && eq(a(2), b"id")
        && a(3)
            .and_then(|v| std::str::from_utf8(v).ok())
            .is_some_and(|v| v.parse::<i64>().is_ok())
    {
        return unkeyed(Cmd::ClientListId(0));
    }
    let small = (eq(name, b"select") && n == 2)
        || (eq(name, b"acl") && eq(a(1), b"dryrun"))
        || (eq(name, b"client") && n == 3 && eq(a(1), b"no-touch") && eq(a(2), b"on"))
        || (eq(name, b"readonly") && n == 1)
        || (eq(name, b"auth") && n == 3)
        || (eq(name, b"hello")
            && ((n == 2 && num(a(1), 3))
                || (n == 4
                    && num(a(1), 3)
                    && eq(a(2), b"setname")
                    && a(3) == Some(CLIENT_NAME.as_bytes()))));
    if small {
        unkeyed(Cmd::Hello)
    } else {
        OwnShape::No
    }
}

/// The objects of the keys at `indices` (H1): a key guarded by the CAS
/// store guard is `*`, with `signature.cas_ticket_read` on a name-guard or
/// strict-prefix match (N5); any other key its learned pattern, its
/// longest learned literal prefix then `*`, or `*`; an oversized one `*`.
fn objects_of(
    args: &[Option<&[u8]>],
    indices: &[usize],
    ctx: &Context<'_>,
    signals: &mut Vec<Signal>,
) -> Vec<NormalizedName> {
    let mut out: Vec<NormalizedName> = Vec::new();
    for i in indices {
        let obj = match args.get(*i).copied().flatten() {
            None => NormalizedName::wildcard(),
            Some(raw) => {
                let (key, cut) = uncut(raw);
                if guard::key_guarded(key, ctx.stores) {
                    if guard::ticket_read_signal(key, ctx.stores)
                        && !signals.contains(&Signal::CasTicketRead)
                    {
                        signals.push(Signal::CasTicketRead);
                    }
                    NormalizedName::wildcard()
                } else {
                    ctx.learned.object(key, cut)
                }
            }
        };
        if out.len() < MAX_OBJECTS && !out.contains(&obj) {
            out.push(obj);
        }
    }
    if out.is_empty() {
        out.push(NormalizedName::wildcard());
    }
    out
}

/// Reduces the arguments of a logged command.
fn reduce(
    args: &[Option<&[u8]>],
    ctx: &Context<'_>,
) -> (Action, Vec<NormalizedName>, Vec<Signal>, OwnShape) {
    let complete = match args.last().copied().flatten() {
        Some(last) if args.len() > 1 && is_more_arguments(last) => args.len() - 1,
        _ => args.len(),
    };
    // The list as logged, the server's marker included: a cut list fits
    // no range of keys (review M4).
    let logged: Vec<&[u8]> = args.iter().map(|a| a.unwrap_or(b"")).collect();
    let cut = complete < args.len();
    let args = args.get(..complete).unwrap_or_default();
    let Some(name) = args.first().copied().flatten() else {
        // An oversized command name: unknown, a read of `*`.
        return (
            Action::Read,
            vec![NormalizedName::wildcard()],
            Vec::new(),
            OwnShape::No,
        );
    };
    // The agent never sends a list long enough to be cut.
    let own = if cut { OwnShape::No } else { own_shape(args) };
    let (mut spec, _) = commands::lookup(name, args.get(1).copied().flatten());
    // `ACL LOG RESET` clears the log Audit reads (review L5).
    if eq(Some(name), b"acl")
        && eq(args.get(1).copied().flatten(), b"log")
        && eq(args.get(2).copied().flatten(), b"reset")
    {
        spec.action = Action::Ddl;
    }
    if spec.action == Action::Ignore {
        return (Action::Ignore, Vec::new(), Vec::new(), own);
    }
    let mut signals = Vec::new();
    // `SORT … BY / GET <pattern>` reads keys the patterns name (never
    // read here: `*`); `STORE` writes (review L5).
    let mut sort_patterns = false;
    if eq(Some(name), b"sort") || eq(Some(name), b"sort_ro") {
        for a in args.iter().skip(2) {
            if eq(*a, b"by") || eq(*a, b"get") {
                sort_patterns = true;
            }
            if eq(*a, b"store") {
                spec.action = Action::Write;
            }
        }
    }
    if eq(Some(name), b"keys") {
        signals.push(Signal::KeyspaceEnumeration);
    }
    if eq(Some(name), b"scan") {
        // `SCAN <cursor> [MATCH <glob>] [COUNT <n>] [TYPE <t>]`: only the
        // `COUNT` number is looked at; the glob is never read.
        let mut i = 2;
        while i + 1 < args.len() {
            let kw = args.get(i).copied().flatten();
            let val = args.get(i + 1).copied().flatten();
            if eq(kw, b"count")
                && let Some(n) = val
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.parse::<u64>().ok())
                && n > ENUMERATION_COUNT
            {
                signals.push(Signal::KeyspaceEnumeration);
            }
            i += 2;
        }
    }
    let objects = if spec.action == Action::Script {
        vec![NormalizedName::wildcard()]
    } else {
        // The positions are computed on the arguments as logged; an
        // oversized argument counts as present (its key becomes `*`).
        let mut objects = match commands::key_indices(spec.keys, &logged, complete) {
            Some(idx) => objects_of(args, &idx, ctx, &mut signals),
            None => vec![NormalizedName::wildcard()],
        };
        let star = NormalizedName::wildcard();
        if sort_patterns && !objects.contains(&star) && objects.len() < MAX_OBJECTS {
            objects.push(star);
        }
        objects
    };
    (spec.action, objects, signals, own)
}

/// Parses one `SLOWLOG GET` / `COMMANDLOG GET` entry: `[id, timestamp,
/// duration or size, [args…], peer, client name]`.
pub(crate) fn parse_log_entry(v: &Value, ctx: &Context<'_>) -> Result<LogEntry, Malformed> {
    let Value::Array(items) = v else {
        return Err(Malformed);
    };
    let id = int(items.first()).ok_or(Malformed)?;
    let ts = int(items.get(1)).ok_or(Malformed)?;
    let size = int(items.get(2)).ok_or(Malformed)?;
    let Some(Value::Array(raw_args)) = items.get(3) else {
        return Err(Malformed);
    };
    if raw_args.is_empty() {
        return Err(Malformed);
    }
    let mut args: Vec<Option<&[u8]>> = Vec::with_capacity(raw_args.len());
    for a in raw_args {
        match a {
            Value::Str(b) => args.push(Some(b.as_slice())),
            Value::Skipped => args.push(None),
            _ => return Err(Malformed),
        }
    }
    let (action, objects, signals, own) = reduce(&args, ctx);
    let peer = items.get(4).and_then(Value::as_bytes).and_then(Peer::parse);
    let app = items.get(5).and_then(Value::as_bytes).and_then(application);
    Ok(LogEntry {
        id,
        ts,
        size: u64::try_from(size).unwrap_or(0),
        action,
        objects,
        signals,
        peer,
        app,
        own,
    })
}

/// A `CLIENT LIST` line, or an `ACL LOG` `client-info`, reduced.
#[derive(Debug, Clone)]
pub(crate) struct Client {
    pub(crate) id: Option<i64>,
    pub(crate) peer: Option<Peer>,
    pub(crate) app: Option<String>,
    pub(crate) age_s: Option<u64>,
    pub(crate) db: Option<u16>,
    pub(crate) user: Option<Zeroizing<String>>,
}

/// Reduces one client line (`id=… addr=… name=… age=… db=… user=…`):
/// the other fields are dropped.
pub(crate) fn parse_client(line: &[u8]) -> Client {
    let mut c = Client {
        id: None,
        peer: None,
        app: None,
        age_s: None,
        db: None,
        user: None,
    };
    for field in line.split(|b| *b == b' ') {
        let Some(eqi) = field.iter().position(|b| *b == b'=') else {
            continue;
        };
        let (k, v) = (
            field.get(..eqi).unwrap_or_default(),
            field.get(eqi + 1..).unwrap_or_default(),
        );
        let text = || std::str::from_utf8(v).ok();
        match k {
            b"id" => c.id = text().and_then(|t| t.parse().ok()),
            b"addr" => c.peer = Peer::parse(v),
            b"name" => c.app = application(v),
            b"age" => c.age_s = text().and_then(|t| t.parse().ok()),
            b"db" => c.db = text().and_then(|t| t.parse().ok()),
            b"user" => {
                let v = v.get(..MAX_USER_BYTES.min(v.len())).unwrap_or_default();
                c.user = Some(Zeroizing::new(String::from_utf8_lossy(v).into_owned()));
            }
            _ => {}
        }
    }
    c
}

/// The connections of a `CLIENT LIST` reply (at most 100 000); empty when
/// the reply was over its cap (not attributed).
pub(crate) fn parse_client_list(v: &Value) -> Vec<Client> {
    let Some(text) = v.as_bytes() else {
        return Vec::new();
    };
    text.split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
        .take(MAX_CLIENTS)
        .map(parse_client)
        .collect()
}

/// The TCP address the server reports for the connection `id`, from its
/// `CLIENT LIST ID <id>` reply (a Unix-socket peer has none: socket peers
/// are never attributed).
pub(crate) fn own_address(v: &Value, id: i64) -> Option<SocketAddr> {
    parse_client_list(v)
        .into_iter()
        .find(|c| c.id == Some(id))
        .and_then(|c| c.peer)
        .and_then(Peer::socket)
}

/// Why an `ACL LOG` entry was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Reason {
    Auth,
    Command,
    Key,
    Channel,
    Db,
    Other,
}

/// An `ACL LOG` entry, reduced.
#[derive(Debug, Clone)]
pub(crate) struct AclEntry {
    /// `entry-id` (Redis 7.2+, Valkey).
    pub(crate) id: Option<i64>,
    pub(crate) count: u64,
    pub(crate) reason: Reason,
    /// The user (the name tried, for `auth`).
    pub(crate) user: Zeroizing<String>,
    /// The denied command's action (`command`), else a read.
    pub(crate) action: Action,
    /// The key's object (`key`), else `*`.
    pub(crate) object: NormalizedName,
    pub(crate) signals: Vec<Signal>,
    pub(crate) client: Option<Client>,
    /// `timestamp-last-updated`, ms (server clock).
    pub(crate) updated_ms: Option<i64>,
    /// A keyed hash of what identifies the entry on servers without
    /// `entry-id` (reason, context, object, user), in memory only.
    pub(crate) ident: u64,
}

/// Parses one `ACL LOG` entry (a map). `learned` gives the learned set of
/// a database (`None`: unknown).
pub(crate) fn parse_acl_entry<'a>(
    v: &Value,
    learned: &dyn Fn(Option<u16>) -> &'a LearnedPatterns,
    stores: Option<&CasStores>,
    ident_key: &std::collections::hash_map::RandomState,
) -> Result<AclEntry, Malformed> {
    use std::hash::{BuildHasher as _, Hash as _, Hasher as _};
    let pairs: Vec<(&[u8], &Value)> = match v {
        Value::Map(p) => p
            .iter()
            .filter_map(|(k, v)| Some((k.as_bytes()?, v)))
            .collect(),
        // RESP2-style flat arrays are not expected in RESP3.
        _ => return Err(Malformed),
    };
    let get = |name: &[u8]| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
    let bytes = |name: &[u8]| get(name).and_then(Value::as_bytes);
    let reason = match bytes(b"reason") {
        Some(b"auth") => Reason::Auth,
        Some(b"command") => Reason::Command,
        Some(b"key") => Reason::Key,
        Some(b"channel") => Reason::Channel,
        Some(b"db") => Reason::Db,
        Some(_) => Reason::Other,
        None => return Err(Malformed),
    };
    let count = int(get(b"count"))
        .and_then(|c| u64::try_from(c).ok())
        .ok_or(Malformed)?;
    let user_raw = bytes(b"username").unwrap_or_default();
    let user = Zeroizing::new(
        String::from_utf8_lossy(
            user_raw
                .get(..MAX_USER_BYTES.min(user_raw.len()))
                .unwrap_or_default(),
        )
        .into_owned(),
    );
    let client = bytes(b"client-info").map(parse_client);
    let object_raw = bytes(b"object");
    let mut h = ident_key.build_hasher();
    reason.hash(&mut h);
    bytes(b"context").hash(&mut h);
    object_raw.hash(&mut h);
    user_raw.hash(&mut h);
    let ident = h.finish();
    let mut signals = Vec::new();
    let (action, object) = match reason {
        Reason::Command => {
            // `object` is the command name (`get`, `config|set`): its
            // action; never a key.
            let name = object_raw.unwrap_or_default();
            let (cmd, sub) = match name.iter().position(|b| *b == b'|') {
                Some(i) => (name.get(..i).unwrap_or_default(), name.get(i + 1..)),
                None => (name, None),
            };
            let (spec, _) = commands::lookup(cmd, sub);
            let action = match spec.action {
                Action::Ignore => Action::Read,
                a => a,
            };
            (action, NormalizedName::wildcard())
        }
        Reason::Key => {
            let db = client.as_ref().and_then(|c| c.db);
            let object = match object_raw {
                Some(k) if guard::key_guarded(k, stores) => {
                    if guard::ticket_read_signal(k, stores) {
                        signals.push(Signal::CasTicketRead);
                    }
                    NormalizedName::wildcard()
                }
                Some(k) => learned(db).object(k, false),
                None => NormalizedName::wildcard(),
            };
            (Action::Read, object)
        }
        _ => (Action::Read, NormalizedName::wildcard()),
    };
    Ok(AclEntry {
        id: int(get(b"entry-id")),
        count,
        reason,
        user,
        action,
        object,
        signals,
        client,
        updated_ms: int(get(b"timestamp-last-updated")),
        ident,
    })
}

/// Test helpers shared with the integration tests.
#[cfg(test)]
pub(crate) mod tests_support {
    /// Whether an Audit object is a contract `KeyPattern` without any
    /// literal that looks like a record value (digits, `@`).
    pub(crate) fn is_learned_shape(o: &str) -> bool {
        databastion_classifiers::keys::is_key_pattern(o)
            && !o.contains('@')
            && !o.chars().any(|c| c.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::{Limits, decode_all};

    pub(crate) fn decode(bytes: &[u8]) -> Value {
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

    fn resp_entry(id: i64, args: &[&[u8]], peer: &str, name: &str) -> Vec<u8> {
        let mut out = format!(
            "*6\r\n:{id}\r\n:1760000000\r\n:15000\r\n*{}\r\n",
            args.len()
        )
        .into_bytes();
        for a in args {
            out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            out.extend_from_slice(a);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(
            format!("${}\r\n{peer}\r\n${}\r\n{name}\r\n", peer.len(), name.len()).as_bytes(),
        );
        out
    }

    fn entry(args: &[&[u8]]) -> LogEntry {
        let learned = LearnedPatterns::new(["user:*:email", "session:*"]);
        let ctx = Context {
            learned: &learned,
            stores: None,
        };
        parse_log_entry(&decode(&resp_entry(7, args, "10.0.0.9:51000", "app")), &ctx).unwrap()
    }

    fn objs(e: &LogEntry) -> Vec<&str> {
        e.objects.iter().map(NormalizedName::as_str).collect()
    }

    #[test]
    fn slow_log_entries_keep_no_argument_value() {
        let e = entry(&[b"HGETALL", b"session:jdupont"]);
        assert_eq!((e.id, e.ts, e.size), (7, 1_760_000_000, 15000));
        assert_eq!(e.action, Action::Read);
        assert_eq!(objs(&e), ["session:*"]);
        assert_eq!(e.peer.unwrap().port, 51000);
        assert_eq!(e.app.as_deref(), Some("app"));
        let e = entry(&[b"SET", b"user:42:email", b"jane.doe@example.com"]);
        assert_eq!((e.action, objs(&e)), (Action::Write, vec!["user:*:email"]));
        let e = entry(&[b"MGET", b"user:1:email", b"session:x", b"cart:jdupont"]);
        assert_eq!(objs(&e), ["user:*:email", "session:*", "*"]);
        // Globs of KEYS and SCAN MATCH are never read; the signal is set.
        let e = entry(&[b"KEYS", b"user:jdupont*"]);
        assert_eq!(
            (objs(&e), e.signals.clone()),
            (vec!["*"], vec![Signal::KeyspaceEnumeration])
        );
        let e = entry(&[b"SCAN", b"0", b"MATCH", b"user:jdupont*", b"COUNT", b"5000"]);
        assert_eq!(
            (objs(&e), e.signals.clone()),
            (vec!["*"], vec![Signal::KeyspaceEnumeration])
        );
        let e = entry(&[b"SCAN", b"0", b"COUNT", b"10"]);
        assert!(e.signals.is_empty());
        // Credentials and scripts: nothing read.
        let e = entry(&[b"AUTH", b"bob", b"hunter2-secret"]);
        assert_eq!(e.action, Action::Ignore);
        assert!(e.objects.is_empty());
        let e = entry(&[b"EVAL", b"return redis.call('get','user:1:email')", b"0"]);
        assert_eq!((e.action, objs(&e)), (Action::Script, vec!["*"]));
        let e = entry(&[b"CONFIG", b"SET", b"masterauth", b"s3cret"]);
        assert_eq!((e.action, objs(&e)), (Action::Ddl, vec!["*"]));
        // Unknown command: a read of `*`.
        let e = entry(&[b"JSON.GET", b"user:jdupont"]);
        assert_eq!((e.action, objs(&e)), (Action::Read, vec!["*"]));
        // A non-fitting command: `*`, no argument read.
        let e = entry(&[b"MSET", b"session:a", b"v", b"session:b"]);
        assert_eq!(objs(&e), ["*"]);
        // A cut key: complete units only.
        let e = entry(&[b"GET", b"session:jdupont... (12 more bytes)"]);
        assert_eq!(objs(&e), ["session:*"]);
        // CAS tickets: `*` with the signal on a strict prefix only.
        let e = entry(&[b"GET", b"cas:TGT-12-abcdef"]);
        assert_eq!(
            (objs(&e), e.signals.clone()),
            (vec!["*"], vec![Signal::CasTicketRead])
        );
        let e = entry(&[b"GET", b"orders:ABCD-12-x"]);
        assert_eq!((objs(&e), e.signals.clone()), (vec!["*"], vec![]));
    }

    #[test]
    fn the_agents_own_command_shapes() {
        let rows = |args: &[&[u8]]| match entry(args).own {
            OwnShape::Keyed { rows, .. } => Some(rows),
            _ => None,
        };
        let unkeyed = |args: &[&[u8]]| matches!(entry(args).own, OwnShape::Unkeyed { .. });
        assert!(matches!(
            entry(&[b"GETRANGE", b"k", b"0", b"4095"]).own,
            OwnShape::Keyed { rows: 1, max_reply } if max_reply == 4096 + 64
        ));
        assert_eq!(entry(&[b"GETRANGE", b"k", b"0", b"-1"]).own, OwnShape::No);
        assert_eq!(rows(&[b"LRANGE", b"k", b"0", b"15"]), Some(16));
        // Review L1: 16 field names are read.
        assert_eq!(rows(&[b"HRANDFIELD", b"k", b"17"]), Some(16));
        assert_eq!(rows(&[b"HMGET", b"k", b"a", b"b"]), Some(2));
        assert_eq!(
            rows(&[b"XREVRANGE", b"k", b"+", b"-", b"COUNT", b"16"]),
            Some(16)
        );
        assert!(unkeyed(&[b"SCAN", b"7", b"COUNT", b"500"]));
        assert!(unkeyed(&[b"SLOWLOG", b"GET", b"512"]));
        // A session's own line, asked at connect time.
        assert!(unkeyed(&[b"CLIENT", b"LIST", b"ID", b"1234"]));
        assert_eq!(
            entry(&[b"CLIENT", b"LIST", b"ID", b"1234", b"1235"]).own,
            OwnShape::No
        );
        assert_eq!(entry(&[b"CLIENT", b"LIST", b"ID", b"x"]).own, OwnShape::No);
        assert_eq!(entry(&[b"HGETALL", b"k"]).own, OwnShape::No);
        assert_eq!(entry(&[b"GET", b"k"]).own, OwnShape::No);
    }

    #[test]
    fn cut_lists_sort_and_acl_log_reset() {
        // Review M4: a list the server cut past 32 arguments fits no range.
        let mut args: Vec<&[u8]> = vec![b"MGET"];
        args.extend(std::iter::repeat_n(&b"session:x"[..], 31));
        args.push(b"... (5 more arguments)");
        assert_eq!(objs(&entry(&args)), ["*"]);
        let mut args: Vec<&[u8]> = vec![b"GET", b"session:x"];
        args.push(b"... (5 more arguments)");
        assert_eq!(objs(&entry(&args)), ["session:*"]);
        // Review L5: SORT patterns give `*`, STORE a write.
        let e = entry(&[b"SORT", b"session:a", b"BY", b"w_*", b"GET", b"user:*"]);
        assert_eq!((e.action, objs(&e)), (Action::Read, vec!["session:*", "*"]));
        let e = entry(&[b"SORT", b"session:a", b"STORE", b"dest"]);
        assert_eq!((e.action, objs(&e)), (Action::Write, vec!["session:*"]));
        assert_eq!(entry(&[b"ACL", b"LOG", b"RESET"]).action, Action::Ddl);
        assert_eq!(entry(&[b"ACL", b"LOG", b"10"]).action, Action::Read);
    }

    #[test]
    fn peers_and_clients() {
        assert_eq!(Peer::parse(b"[::1]:6000").unwrap().port, 6000);
        assert_eq!(
            Peer::parse(b"10.1.2.3:7")
                .unwrap()
                .socket()
                .unwrap()
                .to_string(),
            "10.1.2.3:7"
        );
        assert_eq!(
            Peer::parse(b"/tmp/redis.sock:0").unwrap().addr,
            ClientAddr::Local
        );
        assert_eq!(
            Peer::parse(b"[/tmp/redis.sock:0]:0").unwrap().addr,
            ClientAddr::Local
        );
        assert!(Peer::parse(b"host.example:1").is_none());
        let c = parse_client(b"id=5 addr=10.0.0.2:4000 laddr=10.0.0.1:6379 fd=8 name=my app age=12 idle=0 flags=N db=3 user=alice cmd=get");
        assert_eq!((c.id, c.age_s, c.db), (Some(5), Some(12), Some(3)));
        assert_eq!(c.user.as_deref().map(String::as_str), Some("alice"));
        assert_eq!(c.app.as_deref(), Some("my"));
        assert_eq!(application(b"a\x07b<x>").as_deref(), Some("a_b_x_"));
        // A session's own `CLIENT LIST ID` line: its server-side address,
        // only for its own id and a TCP peer.
        let bulk = |line: &str| decode(format!("${}\r\n{line}\r\n", line.len()).as_bytes());
        let v = bulk(
            "id=7 addr=172.18.0.1:40112 laddr=172.18.0.2:6379 fd=9 name=databastion-agent age=0 db=0 user=databastion\n",
        );
        assert_eq!(
            own_address(&v, 7),
            Some("172.18.0.1:40112".parse().unwrap())
        );
        assert_eq!(own_address(&v, 8), None);
        let sock = bulk("id=7 addr=/run/valkey.sock:0 user=databastion\n");
        assert_eq!(own_address(&sock, 7), None);
        assert_eq!(own_address(&Value::Null, 7), None);
    }

    #[test]
    fn acl_log_entries() {
        let learned = LearnedPatterns::new(["session:*"]);
        let key = std::collections::hash_map::RandomState::new();
        let map = |reason: &str, object: &str| {
            let fields: Vec<(String, String)> = vec![
                ("count".into(), ":2".into()),
                ("reason".into(), format!("${}\r\n{reason}", reason.len())),
                ("context".into(), "$8\r\ntoplevel".into()),
                ("object".into(), format!("${}\r\n{object}", object.len())),
                ("username".into(), "$5\r\nalice".into()),
                ("age-seconds".into(), ",1.5".into()),
                ("client-info".into(), {
                    let ci = "id=9 addr=10.0.0.3:5000 name= age=4 db=0 user=x";
                    format!("${}\r\n{ci}", ci.len())
                }),
                ("entry-id".into(), ":3".into()),
            ];
            let mut out = format!("%{}\r\n", fields.len());
            for (k, v) in fields {
                out.push_str(&format!("${}\r\n{k}\r\n{v}\r\n", k.len()));
            }
            decode(out.as_bytes())
        };
        let get = |_: Option<u16>| &learned;
        let e = parse_acl_entry(&map("key", "session:jdupont"), &get, None, &key).unwrap();
        assert_eq!((e.reason, e.count, e.id), (Reason::Key, 2, Some(3)));
        assert_eq!(e.object.as_str(), "session:*");
        assert_eq!(e.client.as_ref().unwrap().id, Some(9));
        let e = parse_acl_entry(&map("command", "config|set"), &get, None, &key).unwrap();
        assert_eq!((e.action, e.object.as_str()), (Action::Ddl, "*"));
        let e = parse_acl_entry(&map("auth", "AUTH"), &get, None, &key).unwrap();
        assert_eq!((e.reason, e.user.as_str()), (Reason::Auth, "alice"));
    }
}
