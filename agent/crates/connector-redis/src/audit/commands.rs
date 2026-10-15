//! The closed command table of Audit (ADR-0052 decision 8): each command
//! name (and subcommand, for container commands) maps to an action and to
//! the positions of its key arguments, taken from the servers' own key
//! specifications (`key_specs` in `src/commands/*.json` of Redis 7.0+ and
//! Valkey). A command missing from the table is a `read` of `*`; a command
//! whose arguments do not fit its specification gives the object `*` and
//! no argument is read (a wrong position would push a value through the
//! normalizer). Arguments are indexed from the command name (`args[0]`).

use databastion_classifiers::masking::EventAction;

/// What a command does, for Audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Read,
    Write,
    Ddl,
    Dcl,
    /// `EVAL*`, `FCALL*`: a `write` of `*`, always reported (their keys
    /// are not reliably known).
    Script,
    /// No data and no change (connection and introspection commands):
    /// no event. Their arguments are never read.
    Ignore,
}

impl Action {
    pub(crate) fn event_action(self) -> Option<EventAction> {
        match self {
            Self::Read => Some(EventAction::Read),
            Self::Write | Self::Script => Some(EventAction::Write),
            Self::Ddl => Some(EventAction::Ddl),
            Self::Dcl => Some(EventAction::Dcl),
            Self::Ignore => None,
        }
    }
}

/// Where a command's keys are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keys {
    /// No key argument: the object is `*`.
    None,
    /// Keys at these argument indices.
    At(&'static [usize]),
    /// Keys from `first` to the last argument but `back`, every `step`
    /// (`MGET k…`, `MSET k v …`, `BLPOP k… timeout`).
    Range {
        first: usize,
        step: usize,
        back: usize,
    },
    /// A count of keys at `at`, the keys right after it, plus the fixed
    /// keys `fixed` (`ZUNIONSTORE dest numkeys k…`).
    Counted { at: usize, fixed: &'static [usize] },
    /// `XREAD` / `XREADGROUP`: after the `STREAMS` keyword, the first half
    /// of the remaining arguments.
    Streams,
}

/// One row of the table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec {
    pub(crate) action: Action,
    pub(crate) keys: Keys,
}

const fn s(action: Action, keys: Keys) -> Spec {
    Spec { action, keys }
}

use Action::{Dcl, Ddl, Ignore, Read, Script, Write};

const K1: Keys = Keys::At(&[1]);
const K2: Keys = Keys::At(&[2]);
const K12: Keys = Keys::At(&[1, 2]);
const ALL: Keys = Keys::Range {
    first: 1,
    step: 1,
    back: 0,
};
const ALL_BUT_LAST: Keys = Keys::Range {
    first: 1,
    step: 1,
    back: 1,
};
const PAIRS: Keys = Keys::Range {
    first: 1,
    step: 2,
    back: 0,
};
const NUM1: Keys = Keys::Counted { at: 1, fixed: &[] };
const NUM2_DEST: Keys = Keys::Counted { at: 2, fixed: &[1] };
const NONE: Keys = Keys::None;

/// Commands without subcommands, lower case.
const COMMANDS: &[(&str, Spec)] = &[
    // Strings.
    ("get", s(Read, K1)),
    ("getrange", s(Read, K1)),
    ("substr", s(Read, K1)),
    ("strlen", s(Read, K1)),
    ("mget", s(Read, ALL)),
    ("getbit", s(Read, K1)),
    ("bitcount", s(Read, K1)),
    ("bitpos", s(Read, K1)),
    ("bitfield_ro", s(Read, K1)),
    ("lcs", s(Read, K12)),
    ("set", s(Write, K1)),
    ("setnx", s(Write, K1)),
    ("setex", s(Write, K1)),
    ("psetex", s(Write, K1)),
    ("getset", s(Write, K1)),
    ("getdel", s(Write, K1)),
    ("getex", s(Write, K1)),
    ("append", s(Write, K1)),
    ("incr", s(Write, K1)),
    ("incrby", s(Write, K1)),
    ("incrbyfloat", s(Write, K1)),
    ("decr", s(Write, K1)),
    ("decrby", s(Write, K1)),
    ("setrange", s(Write, K1)),
    ("setbit", s(Write, K1)),
    ("bitfield", s(Write, K1)),
    ("mset", s(Write, PAIRS)),
    ("msetnx", s(Write, PAIRS)),
    (
        "bitop",
        s(
            Write,
            Keys::Range {
                first: 2,
                step: 1,
                back: 0,
            },
        ),
    ),
    // Generic.
    ("exists", s(Read, ALL)),
    ("type", s(Read, K1)),
    ("ttl", s(Read, K1)),
    ("pttl", s(Read, K1)),
    ("expiretime", s(Read, K1)),
    ("pexpiretime", s(Read, K1)),
    ("dump", s(Read, K1)),
    ("touch", s(Read, ALL)),
    ("sort_ro", s(Read, K1)),
    // `SORT … BY / GET` take patterns, not keys; `STORE` writes: the
    // source key only, as a read (the patterns are never read).
    ("sort", s(Read, K1)),
    ("keys", s(Read, NONE)),
    ("scan", s(Read, NONE)),
    ("randomkey", s(Read, NONE)),
    ("del", s(Write, ALL)),
    ("unlink", s(Write, ALL)),
    ("expire", s(Write, K1)),
    ("pexpire", s(Write, K1)),
    ("expireat", s(Write, K1)),
    ("pexpireat", s(Write, K1)),
    ("persist", s(Write, K1)),
    ("rename", s(Write, K12)),
    ("renamenx", s(Write, K12)),
    ("copy", s(Write, K12)),
    ("move", s(Write, K1)),
    ("restore", s(Write, K1)),
    // `MIGRATE … KEYS k…` and its credentials: never read.
    ("migrate", s(Write, NONE)),
    ("flushdb", s(Write, NONE)),
    ("flushall", s(Write, NONE)),
    ("swapdb", s(Write, NONE)),
    // Hashes.
    ("hget", s(Read, K1)),
    ("hmget", s(Read, K1)),
    ("hgetall", s(Read, K1)),
    ("hkeys", s(Read, K1)),
    ("hvals", s(Read, K1)),
    ("hlen", s(Read, K1)),
    ("hexists", s(Read, K1)),
    ("hstrlen", s(Read, K1)),
    ("hrandfield", s(Read, K1)),
    ("hscan", s(Read, K1)),
    ("hset", s(Write, K1)),
    ("hsetnx", s(Write, K1)),
    ("hmset", s(Write, K1)),
    ("hdel", s(Write, K1)),
    ("hincrby", s(Write, K1)),
    ("hincrbyfloat", s(Write, K1)),
    // Lists.
    ("lrange", s(Read, K1)),
    ("lindex", s(Read, K1)),
    ("llen", s(Read, K1)),
    ("lpos", s(Read, K1)),
    ("lpush", s(Write, K1)),
    ("rpush", s(Write, K1)),
    ("lpushx", s(Write, K1)),
    ("rpushx", s(Write, K1)),
    ("lpop", s(Write, K1)),
    ("rpop", s(Write, K1)),
    ("linsert", s(Write, K1)),
    ("lset", s(Write, K1)),
    ("lrem", s(Write, K1)),
    ("ltrim", s(Write, K1)),
    ("lmove", s(Write, K12)),
    ("blmove", s(Write, K12)),
    ("rpoplpush", s(Write, K12)),
    ("brpoplpush", s(Write, K12)),
    ("blpop", s(Write, ALL_BUT_LAST)),
    ("brpop", s(Write, ALL_BUT_LAST)),
    ("lmpop", s(Write, NUM1)),
    ("blmpop", s(Write, Keys::Counted { at: 2, fixed: &[] })),
    // Sets.
    ("smembers", s(Read, K1)),
    ("sismember", s(Read, K1)),
    ("smismember", s(Read, K1)),
    ("scard", s(Read, K1)),
    ("srandmember", s(Read, K1)),
    ("sscan", s(Read, K1)),
    ("sunion", s(Read, ALL)),
    ("sinter", s(Read, ALL)),
    ("sdiff", s(Read, ALL)),
    ("sintercard", s(Read, NUM1)),
    ("sadd", s(Write, K1)),
    ("srem", s(Write, K1)),
    ("spop", s(Write, K1)),
    ("smove", s(Write, K12)),
    ("sunionstore", s(Write, ALL)),
    ("sinterstore", s(Write, ALL)),
    ("sdiffstore", s(Write, ALL)),
    // Sorted sets.
    ("zrange", s(Read, K1)),
    ("zrangebyscore", s(Read, K1)),
    ("zrangebylex", s(Read, K1)),
    ("zrevrange", s(Read, K1)),
    ("zrevrangebyscore", s(Read, K1)),
    ("zrevrangebylex", s(Read, K1)),
    ("zscore", s(Read, K1)),
    ("zmscore", s(Read, K1)),
    ("zcard", s(Read, K1)),
    ("zcount", s(Read, K1)),
    ("zlexcount", s(Read, K1)),
    ("zrank", s(Read, K1)),
    ("zrevrank", s(Read, K1)),
    ("zrandmember", s(Read, K1)),
    ("zscan", s(Read, K1)),
    ("zunion", s(Read, NUM1)),
    ("zinter", s(Read, NUM1)),
    ("zdiff", s(Read, NUM1)),
    ("zintercard", s(Read, NUM1)),
    ("zadd", s(Write, K1)),
    ("zrem", s(Write, K1)),
    ("zincrby", s(Write, K1)),
    ("zpopmin", s(Write, K1)),
    ("zpopmax", s(Write, K1)),
    ("bzpopmin", s(Write, ALL_BUT_LAST)),
    ("bzpopmax", s(Write, ALL_BUT_LAST)),
    ("zmpop", s(Write, NUM1)),
    ("bzmpop", s(Write, Keys::Counted { at: 2, fixed: &[] })),
    ("zremrangebyrank", s(Write, K1)),
    ("zremrangebyscore", s(Write, K1)),
    ("zremrangebylex", s(Write, K1)),
    ("zunionstore", s(Write, NUM2_DEST)),
    ("zinterstore", s(Write, NUM2_DEST)),
    ("zdiffstore", s(Write, NUM2_DEST)),
    ("zrangestore", s(Write, K12)),
    // Streams.
    ("xrange", s(Read, K1)),
    ("xrevrange", s(Read, K1)),
    ("xlen", s(Read, K1)),
    ("xread", s(Read, Keys::Streams)),
    ("xreadgroup", s(Write, Keys::Streams)),
    ("xadd", s(Write, K1)),
    ("xdel", s(Write, K1)),
    ("xtrim", s(Write, K1)),
    ("xack", s(Write, K1)),
    ("xclaim", s(Write, K1)),
    ("xautoclaim", s(Write, K1)),
    ("xsetid", s(Write, K1)),
    // HyperLogLog and geo.
    ("pfcount", s(Read, ALL)),
    ("pfadd", s(Write, K1)),
    ("pfmerge", s(Write, ALL)),
    ("geopos", s(Read, K1)),
    ("geodist", s(Read, K1)),
    ("geohash", s(Read, K1)),
    ("geosearch", s(Read, K1)),
    ("georadius_ro", s(Read, K1)),
    ("georadiusbymember_ro", s(Read, K1)),
    // `GEORADIUS … STORE k`: the source key as a write.
    ("georadius", s(Write, K1)),
    ("georadiusbymember", s(Write, K1)),
    ("geosearchstore", s(Write, K12)),
    ("geoadd", s(Write, K1)),
    // Scripts: a write of `*`, always reported.
    ("eval", s(Script, NONE)),
    ("evalsha", s(Script, NONE)),
    ("eval_ro", s(Script, NONE)),
    ("evalsha_ro", s(Script, NONE)),
    ("fcall", s(Script, NONE)),
    ("fcall_ro", s(Script, NONE)),
    // Server-wide reads that expose data: a read of `*`.
    ("monitor", s(Read, NONE)),
    ("sync", s(Read, NONE)),
    ("psync", s(Read, NONE)),
    // Administration.
    ("shutdown", s(Ddl, NONE)),
    ("replicaof", s(Ddl, NONE)),
    ("slaveof", s(Ddl, NONE)),
    ("failover", s(Ddl, NONE)),
    ("save", s(Ddl, NONE)),
    ("bgsave", s(Ddl, NONE)),
    ("bgrewriteaof", s(Ddl, NONE)),
    ("debug", s(Ddl, NONE)),
    // Connection and introspection: no event, no argument read (`AUTH`
    // and `HELLO … AUTH` credentials included, whatever the server's
    // redaction).
    ("auth", s(Ignore, NONE)),
    ("hello", s(Ignore, NONE)),
    ("ping", s(Ignore, NONE)),
    ("echo", s(Ignore, NONE)),
    ("quit", s(Ignore, NONE)),
    ("reset", s(Ignore, NONE)),
    ("select", s(Ignore, NONE)),
    ("info", s(Ignore, NONE)),
    ("time", s(Ignore, NONE)),
    ("lastsave", s(Ignore, NONE)),
    ("role", s(Ignore, NONE)),
    ("dbsize", s(Ignore, NONE)),
    ("command", s(Ignore, NONE)),
    ("readonly", s(Ignore, NONE)),
    ("readwrite", s(Ignore, NONE)),
    ("multi", s(Ignore, NONE)),
    ("exec", s(Ignore, NONE)),
    ("discard", s(Ignore, NONE)),
    ("watch", s(Ignore, NONE)),
    ("unwatch", s(Ignore, NONE)),
    ("wait", s(Ignore, NONE)),
    ("waitaof", s(Ignore, NONE)),
];

/// Container commands: (command, subcommand) → spec; any other subcommand
/// of a listed container gets the container's default (`DEFAULTS`).
const SUBCOMMANDS: &[(&str, &str, Spec)] = &[
    ("object", "encoding", s(Read, K2)),
    ("object", "freq", s(Read, K2)),
    ("object", "idletime", s(Read, K2)),
    ("object", "refcount", s(Read, K2)),
    ("object", "help", s(Ignore, NONE)),
    ("memory", "usage", s(Read, K2)),
    ("xinfo", "stream", s(Read, K2)),
    ("xinfo", "groups", s(Read, K2)),
    ("xinfo", "consumers", s(Read, K2)),
    ("xgroup", "help", s(Ignore, NONE)),
    ("config", "get", s(Read, NONE)),
    ("config", "set", s(Ddl, NONE)),
    ("config", "rewrite", s(Ddl, NONE)),
    ("config", "resetstat", s(Ddl, NONE)),
    ("acl", "setuser", s(Dcl, NONE)),
    ("acl", "deluser", s(Dcl, NONE)),
    ("acl", "load", s(Dcl, NONE)),
    ("acl", "save", s(Dcl, NONE)),
    ("acl", "getuser", s(Read, NONE)),
    ("acl", "list", s(Read, NONE)),
    ("acl", "log", s(Read, NONE)),
    ("acl", "whoami", s(Ignore, NONE)),
    ("acl", "dryrun", s(Ignore, NONE)),
    ("acl", "cat", s(Ignore, NONE)),
    ("acl", "users", s(Ignore, NONE)),
    ("acl", "genpass", s(Ignore, NONE)),
    ("acl", "help", s(Ignore, NONE)),
    ("client", "list", s(Read, NONE)),
    ("client", "info", s(Read, NONE)),
    ("client", "kill", s(Ddl, NONE)),
    ("client", "pause", s(Ddl, NONE)),
    ("client", "unpause", s(Ddl, NONE)),
    ("client", "unblock", s(Ddl, NONE)),
    ("slowlog", "get", s(Read, NONE)),
    ("slowlog", "reset", s(Ddl, NONE)),
    ("slowlog", "len", s(Ignore, NONE)),
    ("slowlog", "help", s(Ignore, NONE)),
    ("commandlog", "get", s(Read, NONE)),
    ("commandlog", "reset", s(Ddl, NONE)),
    ("commandlog", "len", s(Ignore, NONE)),
    ("commandlog", "help", s(Ignore, NONE)),
    ("module", "list", s(Ignore, NONE)),
    ("function", "list", s(Read, NONE)),
    ("function", "dump", s(Read, NONE)),
    ("function", "stats", s(Ignore, NONE)),
    ("script", "exists", s(Ignore, NONE)),
    ("memory", "stats", s(Ignore, NONE)),
    ("memory", "doctor", s(Ignore, NONE)),
    ("memory", "malloc-stats", s(Ignore, NONE)),
    ("cluster", "info", s(Ignore, NONE)),
    ("cluster", "nodes", s(Ignore, NONE)),
    ("cluster", "slots", s(Ignore, NONE)),
    ("cluster", "shards", s(Ignore, NONE)),
    ("cluster", "myid", s(Ignore, NONE)),
    ("cluster", "keyslot", s(Ignore, NONE)),
    ("latency", "latest", s(Ignore, NONE)),
    ("latency", "history", s(Ignore, NONE)),
    ("latency", "doctor", s(Ignore, NONE)),
];

/// The default of a container command's other subcommands. `CLIENT` with
/// another subcommand (`SETNAME`, `NO-TOUCH`, `ID`, `TRACKING`…) carries no
/// data and gives no event; that includes `CLIENT TRACKING ON BCAST
/// PREFIX …`, whose invalidation messages name keys of the prefixes as
/// they change (a documented gap, review L5: the prefixes are client
/// input, never read, and the keys travel as pushes, not as replies the
/// logs record). Every other unlisted subcommand fails closed.
const DEFAULTS: &[(&str, Spec)] = &[
    ("object", s(Read, NONE)),
    ("memory", s(Read, NONE)),
    ("xinfo", s(Read, NONE)),
    ("xgroup", s(Write, K2)),
    ("config", s(Ddl, NONE)),
    ("acl", s(Dcl, NONE)),
    ("client", s(Ignore, NONE)),
    ("slowlog", s(Read, NONE)),
    ("commandlog", s(Read, NONE)),
    ("module", s(Ddl, NONE)),
    ("function", s(Ddl, NONE)),
    ("script", s(Ddl, NONE)),
    ("cluster", s(Ddl, NONE)),
    ("latency", s(Ddl, NONE)),
];

/// Every row of the table whose key positions are read: (command,
/// subcommand), for the per-version check against the server's own
/// `COMMAND GETKEYS` (`crate::it`, review M4). The container defaults are
/// listed with the subcommands they serve.
#[cfg(test)]
pub(crate) fn keyed_rows() -> Vec<(&'static str, Option<&'static str>)> {
    let mut out: Vec<(&'static str, Option<&'static str>)> = COMMANDS
        .iter()
        .filter(|(_, s)| s.keys != Keys::None)
        .map(|(n, _)| (*n, None))
        .collect();
    out.extend(
        SUBCOMMANDS
            .iter()
            .filter(|(_, _, s)| s.keys != Keys::None)
            .map(|(n, sub, _)| (*n, Some(*sub))),
    );
    for (n, d) in DEFAULTS {
        if d.keys != Keys::None {
            out.push((n, Some("*")));
        }
    }
    out
}

/// An unknown command: a read of `*`, never dropped (fail closed).
pub(crate) const UNKNOWN: Spec = s(Read, NONE);

/// The spec of a command from its name and first argument (both compared
/// without case; `name` and `sub` as the server logged them).
pub(crate) fn lookup(name: &[u8], sub: Option<&[u8]>) -> (Spec, bool) {
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    if let Some((_, d)) = DEFAULTS.iter().find(|(n, _)| *n == name) {
        let sub = sub.map(|s| String::from_utf8_lossy(s).to_ascii_lowercase());
        let found = SUBCOMMANDS
            .iter()
            .find(|(n, s2, _)| *n == name && Some(*s2) == sub.as_deref())
            .map(|(_, _, spec)| *spec);
        return (found.unwrap_or(*d), true);
    }
    match COMMANDS.iter().find(|(n, _)| *n == name) {
        Some((_, spec)) => (*spec, true),
        None => (UNKNOWN, false),
    }
}

/// Largest `numkeys` accepted.
const MAX_NUMKEYS: usize = 1024;

/// The indices of the key arguments of `args` (`args[0]` the command
/// name) under `keys`; `None` when the arguments do not fit (the object
/// is then `*` and no argument is read). `complete`: how many leading
/// arguments the server kept (it cuts the list past 32); a key past them
/// does not fit.
pub(crate) fn key_indices(keys: Keys, args: &[&[u8]], complete: usize) -> Option<Vec<usize>> {
    let n = args.len().min(complete);
    let out: Vec<usize> = match keys {
        Keys::None => Vec::new(),
        Keys::At(at) => at.to_vec(),
        Keys::Range { first, step, back } => {
            // The whole list must have been kept, and fit the step.
            if complete < args.len() {
                return None;
            }
            let end = n.checked_sub(back)?;
            if end <= first || step == 0 || (end - first) % step != 0 {
                return None;
            }
            (first..end).step_by(step).collect()
        }
        Keys::Counted { at, fixed } => {
            let count = std::str::from_utf8(args.get(at)?)
                .ok()?
                .parse::<usize>()
                .ok()?;
            if count == 0 || count > MAX_NUMKEYS {
                return None;
            }
            let mut v = fixed.to_vec();
            v.extend(at + 1..at + 1 + count);
            v
        }
        Keys::Streams => {
            let kw = args
                .iter()
                .take(n)
                .position(|a| a.eq_ignore_ascii_case(b"streams"))?;
            if complete < args.len() {
                return None;
            }
            let rest = n.checked_sub(kw + 1)?;
            if rest == 0 || rest % 2 != 0 {
                return None;
            }
            (kw + 1..kw + 1 + rest / 2).collect()
        }
    };
    if out.iter().any(|i| *i == 0 || *i >= n) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_of(cmd: &[&str]) -> Option<Vec<usize>> {
        let args: Vec<&[u8]> = cmd.iter().map(|a| a.as_bytes()).collect();
        let (spec, _) = lookup(args[0], args.get(1).copied());
        key_indices(spec.keys, &args, args.len())
    }

    /// Every variable key position of the table, one by one (H1 tests).
    #[test]
    fn variable_key_positions() {
        assert_eq!(keys_of(&["GET", "k"]), Some(vec![1]));
        assert_eq!(keys_of(&["get"]), None);
        assert_eq!(keys_of(&["MGET", "a", "b", "c"]), Some(vec![1, 2, 3]));
        assert_eq!(keys_of(&["MSET", "a", "v", "b", "w"]), Some(vec![1, 3]));
        assert_eq!(keys_of(&["MSET", "a", "v", "b"]), None);
        assert_eq!(keys_of(&["BLPOP", "a", "b", "0"]), Some(vec![1, 2]));
        assert_eq!(
            keys_of(&["BITOP", "AND", "d", "a", "b"]),
            Some(vec![2, 3, 4])
        );
        assert_eq!(
            keys_of(&["ZUNIONSTORE", "d", "2", "a", "b", "WEIGHTS", "1", "2"]),
            Some(vec![1, 3, 4])
        );
        assert_eq!(keys_of(&["ZUNIONSTORE", "d", "3", "a", "b"]), None);
        assert_eq!(keys_of(&["ZUNION", "2", "a", "b"]), Some(vec![2, 3]));
        assert_eq!(keys_of(&["ZUNION", "x", "a"]), None);
        assert_eq!(keys_of(&["LMPOP", "2", "a", "b", "LEFT"]), Some(vec![2, 3]));
        assert_eq!(keys_of(&["BLMPOP", "0", "1", "a", "LEFT"]), Some(vec![3]));
        assert_eq!(keys_of(&["ZMPOP", "1", "a", "MIN"]), Some(vec![2]));
        assert_eq!(keys_of(&["SINTERCARD", "2", "a", "b"]), Some(vec![2, 3]));
        assert_eq!(
            keys_of(&["XREAD", "COUNT", "2", "STREAMS", "a", "b", "0", "0"]),
            Some(vec![4, 5])
        );
        assert_eq!(keys_of(&["XREAD", "STREAMS", "a", "b", "0"]), None);
        assert_eq!(
            keys_of(&["XREADGROUP", "GROUP", "g", "c", "STREAMS", "a", ">"]),
            Some(vec![5])
        );
        assert_eq!(keys_of(&["OBJECT", "ENCODING", "k"]), Some(vec![2]));
        assert_eq!(keys_of(&["MEMORY", "USAGE", "k"]), Some(vec![2]));
        assert_eq!(keys_of(&["XINFO", "STREAM", "k"]), Some(vec![2]));
        // SORT: BY / GET patterns and STORE are never read.
        assert_eq!(
            keys_of(&["SORT", "k", "BY", "w_*", "GET", "o_*"]),
            Some(vec![1])
        );
        assert_eq!(
            keys_of(&["MIGRATE", "h", "1", "", "0", "5", "KEYS", "a"]),
            Some(vec![])
        );
        assert_eq!(keys_of(&["EVAL", "return 1", "1", "k"]), Some(vec![]));
        assert_eq!(
            keys_of(&["GEORADIUS", "k", "0", "0", "1", "km", "STORE", "d"]),
            Some(vec![1])
        );
        // A list cut by the server (past 32 arguments) does not fit a
        // range.
        let args: Vec<&[u8]> = vec![b"MGET", b"a", b"b", b"... (3 more arguments)"];
        assert_eq!(key_indices(lookup(b"mget", None).0.keys, &args, 3), None);
        assert_eq!(key_indices(K1, &args, 3), Some(vec![1]));
    }

    #[test]
    fn actions() {
        assert_eq!(lookup(b"HGETALL", None).0.action, Action::Read);
        assert_eq!(lookup(b"FLUSHALL", None).0.action, Action::Write);
        assert_eq!(lookup(b"CONFIG", Some(b"SET")).0.action, Action::Ddl);
        assert_eq!(lookup(b"CONFIG", Some(b"other")).0.action, Action::Ddl);
        assert_eq!(lookup(b"ACL", Some(b"SETUSER")).0.action, Action::Dcl);
        assert_eq!(lookup(b"ACL", Some(b"DRYRUN")).0.action, Action::Ignore);
        assert_eq!(lookup(b"EVAL", None).0.action, Action::Script);
        assert_eq!(lookup(b"AUTH", None).0.action, Action::Ignore);
        let (spec, known) = lookup(b"JSON.GET", None);
        assert!(!known);
        assert_eq!((spec.action, spec.keys), (Action::Read, Keys::None));
        assert_eq!(lookup(b"MONITOR", None).0.action, Action::Read);
    }
}
