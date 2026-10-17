//! The account's evaluation without `ACL GETUSER` (ADR-0052 decision 4):
//! `ACL DRYRUN <own user> <command> <constant arguments>` over one closed
//! table of probes, from which the refusal list is derived (`refusal:
//! true`), so the two cannot drift. `DRYRUN` runs nothing and writes
//! nothing to `ACL LOG`.
//!
//! `OK`, or a key-, channel- or database-level denial, means the command is
//! allowed for some key or selector; only a command-level denial, by its
//! fixed text, is a denial; anything else is "not evaluated", which counts
//! as allowed for the refusal list (fail closed). The denial texts are the
//! same on every supported version (P9-D facts).

use crate::resp::Value;

/// What a probe tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Write,
    ReadBeyond,
    Admin,
    Scripting,
    Pubsub,
    /// A command the connector may use (`CLIENT NO-TOUCH`, `READONLY`):
    /// not an over-privilege.
    Feature,
}

/// One `ACL DRYRUN` probe: the command and constant arguments of the right
/// arity (`DRYRUN` checks it), its class, and whether it is on the refusal
/// list.
#[derive(Debug)]
pub(crate) struct Probe {
    pub(crate) args: &'static [&'static str],
    pub(crate) class: Class,
    pub(crate) refusal: bool,
}

const fn p(args: &'static [&'static str], class: Class, refusal: bool) -> Probe {
    Probe {
        args,
        class,
        refusal,
    }
}

/// The constant key and channel of the probes.
const K: &str = "databastion:probe";

/// Every probe (decision 4). The refusal list is the `refusal: true` rows.
pub(crate) const PROBES: &[Probe] = &[
    // Writes.
    p(&["set", K, "v"], Class::Write, false),
    p(&["del", K], Class::Write, false),
    p(&["unlink", K], Class::Write, false),
    p(&["hset", K, "f", "v"], Class::Write, false),
    p(&["lpush", K, "v"], Class::Write, false),
    p(&["sadd", K, "m"], Class::Write, false),
    p(&["zadd", K, "1", "m"], Class::Write, false),
    p(&["xadd", K, "*", "f", "v"], Class::Write, false),
    p(&["expire", K, "1"], Class::Write, false),
    p(&["rename", K, "databastion:probe2"], Class::Write, false),
    p(&["restore", K, "0", "x"], Class::Write, false),
    p(&["copy", K, "databastion:probe2"], Class::Write, false),
    p(&["move", K, "1"], Class::Write, false),
    p(&["flushdb"], Class::Write, false),
    p(&["flushall"], Class::Write, false),
    p(&["swapdb", "0", "1"], Class::Write, false),
    p(
        &["migrate", "127.0.0.1", "6379", K, "0", "1"],
        Class::Write,
        true,
    ),
    // Reads beyond Discovery.
    p(&["get", K], Class::ReadBeyond, false),
    p(&["mget", K], Class::ReadBeyond, false),
    p(&["hgetall", K], Class::ReadBeyond, false),
    p(&["hget", K, "f"], Class::ReadBeyond, false),
    p(&["smembers", K], Class::ReadBeyond, false),
    p(&["zrange", K, "0", "1"], Class::ReadBeyond, false),
    p(&["lpos", K, "e"], Class::ReadBeyond, false),
    p(&["xread", "streams", K, "0"], Class::ReadBeyond, false),
    p(&["dump", K], Class::ReadBeyond, false),
    p(&["keys", "x"], Class::ReadBeyond, false),
    p(&["sort", K], Class::ReadBeyond, false),
    // Administration.
    p(&["config", "get", "x"], Class::Admin, false),
    p(&["config", "set", "x", "y"], Class::Admin, true),
    p(&["debug", "x"], Class::Admin, true),
    p(&["module", "load", "x"], Class::Admin, true),
    p(&["module", "loadex", "x"], Class::Admin, true),
    p(&["module", "list"], Class::Admin, false),
    p(&["shutdown"], Class::Admin, false),
    p(&["replicaof", "no", "one"], Class::Admin, true),
    p(&["slaveof", "no", "one"], Class::Admin, true),
    p(&["failover"], Class::Admin, false),
    p(&["save"], Class::Admin, false),
    p(&["bgsave"], Class::Admin, false),
    p(&["client", "kill", "127.0.0.1:1"], Class::Admin, false),
    p(&["acl", "setuser", "x"], Class::Admin, true),
    p(&["acl", "deluser", "x"], Class::Admin, true),
    p(&["acl", "load"], Class::Admin, true),
    p(&["acl", "getuser", "x"], Class::Admin, false),
    p(&["acl", "list"], Class::Admin, false),
    p(&["slowlog", "reset"], Class::Admin, false),
    p(&["monitor"], Class::Admin, false),
    p(&["sync"], Class::Admin, false),
    p(&["psync", "x", "0"], Class::Admin, false),
    p(&["cluster", "meet", "127.0.0.1", "1"], Class::Admin, true),
    p(
        &["cluster", "setslot", "1", "node", "x"],
        Class::Admin,
        true,
    ),
    // Scripting.
    p(&["eval", "return 1", "0"], Class::Scripting, true),
    p(&["evalsha", "x", "0"], Class::Scripting, true),
    p(&["eval_ro", "return 1", "0"], Class::Scripting, true),
    p(&["evalsha_ro", "x", "0"], Class::Scripting, true),
    p(&["fcall", "x", "0"], Class::Scripting, true),
    p(&["fcall_ro", "x", "0"], Class::Scripting, true),
    p(&["function", "load", "x"], Class::Scripting, true),
    p(&["script", "load", "x"], Class::Scripting, false),
    // Pub/sub.
    p(&["publish", "databastion:probe", "m"], Class::Pubsub, false),
    p(&["subscribe", "databastion:probe"], Class::Pubsub, false),
    // Features the connector uses when allowed.
    p(&["client", "no-touch", "on"], Class::Feature, false),
    p(&["readonly"], Class::Feature, false),
];

/// An Audit read (decision 4): evaluated apart from [`PROBES`] (a missing
/// Audit grant is not an over-privilege nor "not evaluated"), so Audit
/// never sends a command the ACL refuses (H3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditRead {
    Slowlog,
    AclLog,
    ClientList,
    /// Valkey 8.1+ only.
    Commandlog,
}

impl AuditRead {
    pub(crate) const ALL: [Self; 4] = [
        Self::Slowlog,
        Self::AclLog,
        Self::ClientList,
        Self::Commandlog,
    ];

    /// The `ACL DRYRUN` arguments.
    pub(crate) const fn probe(self) -> &'static Probe {
        const SLOWLOG: Probe = p(&["slowlog", "get", "1"], Class::Feature, false);
        const ACL_LOG: Probe = p(&["acl", "log", "1"], Class::Feature, false);
        const CLIENT_LIST: Probe = p(&["client", "list"], Class::Feature, false);
        const COMMANDLOG: Probe = p(&["commandlog", "get", "1", "slow"], Class::Feature, false);
        match self {
            Self::Slowlog => &SLOWLOG,
            Self::AclLog => &ACL_LOG,
            Self::ClientList => &CLIENT_LIST,
            Self::Commandlog => &COMMANDLOG,
        }
    }
}

/// Which Audit reads the account may run (`None`: not evaluated: Redis
/// 6.2, or a `DRYRUN` answer not understood).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AuditGrants {
    pub(crate) slowlog: Option<bool>,
    pub(crate) acl_log: Option<bool>,
    pub(crate) client_list: Option<bool>,
    pub(crate) commandlog: Option<bool>,
}

impl AuditGrants {
    pub(crate) fn set(&mut self, read: AuditRead, v: Option<bool>) {
        match read {
            AuditRead::Slowlog => self.slowlog = v,
            AuditRead::AclLog => self.acl_log = v,
            AuditRead::ClientList => self.client_list = v,
            AuditRead::Commandlog => self.commandlog = v,
        }
    }
}

/// The answer to one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allowed,
    Denied,
    NotEvaluated,
}

/// Reads a `DRYRUN` reply. The denial text is compared in memory with the
/// fixed phrases and dropped (it names the user and the key).
pub(crate) fn verdict(reply: &Value) -> Verdict {
    let Some(text) = reply.as_bytes() else {
        return Verdict::NotEvaluated;
    };
    if text == b"OK" {
        return Verdict::Allowed;
    }
    let Ok(text) = std::str::from_utf8(text) else {
        return Verdict::NotEvaluated;
    };
    if !text.starts_with("User ") {
        return Verdict::NotEvaluated;
    }
    if text.contains(" has no permissions to run the '") && text.ends_with("' command") {
        return Verdict::Denied;
    }
    if text.contains(" has no permissions to access the '")
        && (text.ends_with("' key") || text.ends_with("' channel"))
    {
        return Verdict::Allowed;
    }
    if text.contains(" has no permissions to access database ") {
        return Verdict::Allowed;
    }
    Verdict::NotEvaluated
}

/// Whether a key or database declaration is readable: `OK` only; any
/// denial is "not readable"; anything else not evaluated (`None`).
pub(crate) fn readable(reply: &Value) -> Option<bool> {
    match verdict(reply) {
        Verdict::Allowed if reply.as_bytes() == Some(b"OK") => Some(true),
        Verdict::Allowed | Verdict::Denied => Some(false),
        Verdict::NotEvaluated => None,
    }
}

/// The evaluation of an account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) writes: u64,
    pub(crate) read_beyond: u64,
    pub(crate) admin: u64,
    pub(crate) scripting: u64,
    pub(crate) pubsub: u64,
    /// Probes not evaluated (counted in their class too when on the
    /// refusal list).
    pub(crate) not_evaluated: u64,
    /// Refusal-list commands allowed or not evaluated.
    pub(crate) refused: u64,
    pub(crate) no_touch: bool,
    pub(crate) readonly: bool,
}

impl Evaluation {
    /// The worse of two nodes' evaluations: every count at its highest,
    /// a feature only when both nodes grant it.
    pub(crate) fn worst(&self, other: &Self) -> Self {
        Self {
            writes: self.writes.max(other.writes),
            read_beyond: self.read_beyond.max(other.read_beyond),
            admin: self.admin.max(other.admin),
            scripting: self.scripting.max(other.scripting),
            pubsub: self.pubsub.max(other.pubsub),
            not_evaluated: self.not_evaluated.max(other.not_evaluated),
            refused: self.refused.max(other.refused),
            no_touch: self.no_touch && other.no_touch,
            readonly: self.readonly && other.readonly,
        }
    }

    /// Folds the verdicts of [`PROBES`], in order.
    pub(crate) fn of(verdicts: &[Verdict]) -> Self {
        let mut e = Self::default();
        for (probe, v) in PROBES.iter().zip(verdicts) {
            let counted = match v {
                Verdict::Allowed => true,
                Verdict::Denied => false,
                Verdict::NotEvaluated => {
                    e.not_evaluated += 1;
                    probe.refusal
                }
            };
            if probe.refusal && *v != Verdict::Denied {
                e.refused += 1;
            }
            if !counted {
                continue;
            }
            match probe.class {
                Class::Write => e.writes += 1,
                Class::ReadBeyond => e.read_beyond += 1,
                Class::Admin => e.admin += 1,
                Class::Scripting => e.scripting += 1,
                Class::Pubsub => e.pubsub += 1,
                Class::Feature => {
                    if probe.args == ["client", "no-touch", "on"] {
                        e.no_touch = *v == Verdict::Allowed;
                    } else if probe.args == ["readonly"] {
                        e.readonly = *v == Verdict::Allowed;
                    }
                }
            }
        }
        // Fewer verdicts than probes (a cut evaluation): the rest is not
        // evaluated, refusal-list rows included.
        for probe in PROBES.iter().skip(verdicts.len()) {
            e.not_evaluated += 1;
            if probe.refusal {
                e.refused += 1;
            }
        }
        e
    }

    /// Whether Discovery and Audit must not run (the refusal list).
    pub(crate) fn refuses(&self) -> bool {
        self.refused > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::{Bytes, ErrorWord};

    fn text(s: &str) -> Value {
        crate::resp::decode_all(
            format!("${}\r\n{s}\r\n", s.len()).as_bytes(),
            crate::resp::Limits {
                bulk: 1024,
                items: 0,
                skip_oversized: false,
                reply: 2048,
            },
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn refusal_list_is_the_adr_list_and_every_row_is_probed() {
        let refusal: Vec<String> = PROBES
            .iter()
            .filter(|p| p.refusal)
            .map(|p| match p.args {
                [cmd, sub, ..]
                    if matches!(*cmd, "config" | "module" | "acl" | "function" | "cluster") =>
                {
                    format!("{cmd}|{sub}")
                }
                [cmd, ..] => (*cmd).to_owned(),
                [] => String::new(),
            })
            .collect();
        let adr = [
            "config|set",
            "module|load",
            "module|loadex",
            "debug",
            "acl|setuser",
            "acl|deluser",
            "acl|load",
            "eval",
            "eval_ro",
            "evalsha",
            "evalsha_ro",
            "fcall",
            "fcall_ro",
            "function|load",
            "replicaof",
            "slaveof",
            "migrate",
            "cluster|meet",
            "cluster|setslot",
        ];
        let mut a: Vec<&str> = adr.to_vec();
        a.sort_unstable();
        let mut r: Vec<&str> = refusal.iter().map(String::as_str).collect();
        r.sort_unstable();
        assert_eq!(r, a);
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&text("OK")), Verdict::Allowed);
        assert_eq!(
            verdict(&text(
                "User databastion has no permissions to run the 'set' command"
            )),
            Verdict::Denied
        );
        assert_eq!(
            verdict(&text(
                "User databastion has no permissions to run the 'config|set' command"
            )),
            Verdict::Denied
        );
        assert_eq!(
            verdict(&text(
                "User databastion has no permissions to access the 'databastion:probe' key"
            )),
            Verdict::Allowed
        );
        assert_eq!(
            verdict(&text("User u has no permissions to access the 'c' channel")),
            Verdict::Allowed
        );
        assert_eq!(
            verdict(&text("User u has no permissions to access database 3")),
            Verdict::Allowed
        );
        assert_eq!(verdict(&text("Something new")), Verdict::NotEvaluated);
        assert_eq!(
            verdict(&Value::Error(ErrorWord::Err)),
            Verdict::NotEvaluated
        );
        assert_eq!(
            verdict(&Value::Str(Bytes::default())),
            Verdict::NotEvaluated
        );
        assert_eq!(readable(&text("OK")), Some(true));
        assert_eq!(
            readable(&text("User u has no permissions to access the 'k' key")),
            Some(false)
        );
        assert_eq!(readable(&Value::Error(ErrorWord::Noperm)), None);
    }

    #[test]
    fn not_evaluated_refusal_rows_refuse() {
        let all_denied = vec![Verdict::Denied; PROBES.len()];
        let e = Evaluation::of(&all_denied);
        assert!(!e.refuses());
        assert_eq!(e.writes + e.admin + e.scripting, 0);
        let mut v = all_denied.clone();
        let eval = PROBES
            .iter()
            .position(|p| p.args.first() == Some(&"eval"))
            .unwrap();
        v[eval] = Verdict::NotEvaluated;
        let e = Evaluation::of(&v);
        assert!(e.refuses());
        assert_eq!(e.scripting, 1);
        assert_eq!(e.not_evaluated, 1);
        // A cut evaluation refuses.
        assert!(Evaluation::of(&[]).refuses());
        let mut v = all_denied;
        let nt = PROBES
            .iter()
            .position(|p| p.args == ["client", "no-touch", "on"])
            .unwrap();
        v[nt] = Verdict::Allowed;
        let e = Evaluation::of(&v);
        assert!(e.no_touch && !e.refuses());
    }
}
