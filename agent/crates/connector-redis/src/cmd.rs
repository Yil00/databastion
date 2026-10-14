//! The closed set of commands the connector can send (ADR-0052 decisions
//! 1 and 4): the Discovery allow-list, the handshake and `check()`'s
//! `ACL DRYRUN` probes. There is no encoder for anything else, so the
//! connector is read-only by construction (I4). The arguments are key and
//! field names returned by the server, numbers and constants; nothing from
//! the console reaches a request.

use zeroize::Zeroize;

use crate::acl::Probe;
use crate::resp::{self, Limits, MAX_LINE, MAX_REPLY_BYTES};

/// The client name set by `HELLO … SETNAME`.
pub(crate) const CLIENT_NAME: &str = "databastion-agent";
/// Members, fields and entries read per key (decision 6).
pub(crate) const MEMBERS_PER_KEY: u32 = 16;
/// Bytes of a string read per key, and the largest hash value read.
pub(crate) const VALUE_BYTES: usize = 4096;
/// Longest key or field name kept; longer ones are read and discarded.
pub(crate) const MAX_NAME_BYTES: usize = 64 * 1024;
/// `SCAN … COUNT`.
pub(crate) const SCAN_COUNT: u32 = 500;
/// Slack over `COUNT` accepted in a `SCAN` reply.
const SCAN_SLACK: usize = 500;
/// Largest `INFO` section.
const INFO_BYTES: usize = 1024 * 1024;
/// Most elements of a `HELLO` reply aggregate (the `modules` array cap).
const HELLO_ITEMS: usize = 64;
/// Most fields of one stream entry read (an entry with more closes the
/// connection: counted as an error for its key).
const STREAM_FIELDS: usize = 512;

/// An `INFO` section the connector reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InfoSection {
    Server,
    Replication,
    Keyspace,
    Cluster,
}

impl InfoSection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Replication => "replication",
            Self::Keyspace => "keyspace",
            Self::Cluster => "cluster",
        }
    }
}

/// A key probe of `ACL DRYRUN` (decisions 4 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyProbe {
    /// `type <key>`: a declared pattern is readable.
    Type,
    /// `getrange <key> 0 1`: a CAS-guarded key could be read.
    GetRange,
}

/// A command of the closed set.
pub(crate) enum Cmd<'a> {
    /// `AUTH <user> <password>` (no grant needed, `no-auth`).
    Auth {
        user: &'a str,
        password: &'a str,
    },
    /// `HELLO 3 SETNAME databastion-agent`, without credentials (H2).
    Hello,
    /// `HELLO 3` alone, on the unauthenticated connection of the `default`
    /// user probe (decision 4).
    HelloProbe,
    Info(InfoSection),
    Select(u16),
    Scan {
        cursor: u64,
    },
    Type(&'a [u8]),
    /// `GETRANGE <key> 0 4095`.
    GetRange(&'a [u8]),
    /// `HRANDFIELD <key> 16`.
    HRandField(&'a [u8]),
    HStrLen(&'a [u8], &'a [u8]),
    HMGet(&'a [u8], &'a [&'a [u8]]),
    /// `SRANDMEMBER <key> 16`.
    SRandMember(&'a [u8]),
    /// `ZRANDMEMBER <key> 16` (members only).
    ZRandMember(&'a [u8]),
    /// `LRANGE <key> 0 15`.
    LRange(&'a [u8]),
    /// `XREVRANGE <key> + - COUNT 16`.
    XRevRange(&'a [u8]),
    /// `ACL DRYRUN <user> <probe>`: a constant probe of the table.
    DryRun {
        user: &'a str,
        probe: &'static Probe,
    },
    /// `ACL DRYRUN <user> type|getrange <key> …`.
    DryRunKey {
        user: &'a str,
        probe: KeyProbe,
        key: &'a [u8],
    },
    /// `ACL DRYRUN <user> select <db>`.
    DryRunSelect {
        user: &'a str,
        db: u16,
    },
    /// `CLIENT NO-TOUCH ON`.
    ClientNoTouchOn,
    /// `READONLY` (a Cluster replica).
    ReadOnly,
}

impl std::fmt::Debug for Cmd<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The command name only: never a key, a value or a credential.
        f.write_str(self.name())
    }
}

impl Cmd<'_> {
    /// The command's name, for logs.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Auth { .. } => "AUTH",
            Self::Hello | Self::HelloProbe => "HELLO",
            Self::Info(_) => "INFO",
            Self::Select(_) => "SELECT",
            Self::Scan { .. } => "SCAN",
            Self::Type(_) => "TYPE",
            Self::GetRange(_) => "GETRANGE",
            Self::HRandField(_) => "HRANDFIELD",
            Self::HStrLen(..) => "HSTRLEN",
            Self::HMGet(..) => "HMGET",
            Self::SRandMember(_) => "SRANDMEMBER",
            Self::ZRandMember(_) => "ZRANDMEMBER",
            Self::LRange(_) => "LRANGE",
            Self::XRevRange(_) => "XREVRANGE",
            Self::DryRun { .. } | Self::DryRunKey { .. } | Self::DryRunSelect { .. } => {
                "ACL DRYRUN"
            }
            Self::ClientNoTouchOn => "CLIENT NO-TOUCH",
            Self::ReadOnly => "READONLY",
        }
    }

    /// The bounds of this command's reply.
    pub(crate) fn limits(&self) -> Limits {
        let members = MEMBERS_PER_KEY as usize;
        match self {
            Self::Auth { .. }
            | Self::Select(_)
            | Self::Type(_)
            | Self::HStrLen(..)
            | Self::ClientNoTouchOn
            | Self::ReadOnly => Limits::SIMPLE,
            Self::Hello | Self::HelloProbe => Limits {
                bulk: MAX_LINE,
                items: HELLO_ITEMS,
                skip_oversized: false,
                reply: 64 * 1024,
            },
            Self::Info(_) => Limits {
                bulk: INFO_BYTES,
                items: 0,
                skip_oversized: false,
                reply: INFO_BYTES + 1024,
            },
            Self::Scan { .. } => Limits {
                bulk: MAX_NAME_BYTES,
                items: SCAN_COUNT as usize + SCAN_SLACK,
                skip_oversized: true,
                reply: MAX_REPLY_BYTES,
            },
            Self::GetRange(_) => Limits {
                bulk: VALUE_BYTES,
                items: 0,
                skip_oversized: false,
                reply: VALUE_BYTES + 64,
            },
            Self::HRandField(_) => Limits {
                bulk: MAX_NAME_BYTES,
                items: members,
                skip_oversized: true,
                reply: MAX_REPLY_BYTES,
            },
            Self::HMGet(_, fields) => Limits {
                bulk: VALUE_BYTES,
                items: fields.len(),
                skip_oversized: false,
                reply: MAX_REPLY_BYTES,
            },
            Self::SRandMember(_) | Self::ZRandMember(_) | Self::LRange(_) => Limits {
                bulk: MAX_REPLY_BYTES,
                items: members,
                skip_oversized: false,
                reply: MAX_REPLY_BYTES,
            },
            Self::XRevRange(_) => Limits {
                bulk: MAX_REPLY_BYTES,
                items: STREAM_FIELDS,
                skip_oversized: false,
                reply: MAX_REPLY_BYTES,
            },
            Self::DryRun { .. } | Self::DryRunKey { .. } | Self::DryRunSelect { .. } => Limits {
                bulk: 1024,
                items: 0,
                skip_oversized: false,
                reply: 2048,
            },
        }
    }

    /// Encodes the request into `out` (a zeroized buffer: `AUTH` writes the
    /// password into it).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let n = MEMBERS_PER_KEY.to_string();
        let last = (MEMBERS_PER_KEY - 1).to_string();
        let value_end = (VALUE_BYTES - 1).to_string();
        let count = SCAN_COUNT.to_string();
        match self {
            Self::Auth { user, password } => {
                resp::encode(&[b"AUTH", user.as_bytes(), password.as_bytes()], out);
            }
            Self::Hello => resp::encode(&[b"HELLO", b"3", b"SETNAME", CLIENT_NAME.as_bytes()], out),
            Self::HelloProbe => resp::encode(&[b"HELLO", b"3"], out),
            Self::Info(s) => resp::encode(&[b"INFO", s.as_str().as_bytes()], out),
            Self::Select(db) => resp::encode(&[b"SELECT", db.to_string().as_bytes()], out),
            Self::Scan { cursor } => resp::encode(
                &[
                    b"SCAN",
                    cursor.to_string().as_bytes(),
                    b"COUNT",
                    count.as_bytes(),
                ],
                out,
            ),
            Self::Type(k) => resp::encode(&[b"TYPE", k], out),
            Self::GetRange(k) => {
                resp::encode(&[b"GETRANGE", k, b"0", value_end.as_bytes()], out);
            }
            Self::HRandField(k) => resp::encode(&[b"HRANDFIELD", k, n.as_bytes()], out),
            Self::HStrLen(k, f) => resp::encode(&[b"HSTRLEN", k, f], out),
            Self::HMGet(k, fields) => {
                let mut args: Vec<&[u8]> = vec![b"HMGET", k];
                args.extend(fields.iter().copied());
                resp::encode(&args, out);
            }
            Self::SRandMember(k) => resp::encode(&[b"SRANDMEMBER", k, n.as_bytes()], out),
            Self::ZRandMember(k) => resp::encode(&[b"ZRANDMEMBER", k, n.as_bytes()], out),
            Self::LRange(k) => resp::encode(&[b"LRANGE", k, b"0", last.as_bytes()], out),
            Self::XRevRange(k) => {
                resp::encode(&[b"XREVRANGE", k, b"+", b"-", b"COUNT", n.as_bytes()], out);
            }
            Self::DryRun { user, probe } => {
                let mut args: Vec<&[u8]> = vec![b"ACL", b"DRYRUN", user.as_bytes()];
                args.extend(probe.args.iter().map(|a| a.as_bytes()));
                resp::encode(&args, out);
            }
            Self::DryRunKey { user, probe, key } => {
                let args: Vec<&[u8]> = match probe {
                    KeyProbe::Type => vec![b"ACL", b"DRYRUN", user.as_bytes(), b"type", key],
                    KeyProbe::GetRange => vec![
                        b"ACL",
                        b"DRYRUN",
                        user.as_bytes(),
                        b"getrange",
                        key,
                        b"0",
                        b"1",
                    ],
                };
                resp::encode(&args, out);
            }
            Self::DryRunSelect { user, db } => resp::encode(
                &[
                    b"ACL",
                    b"DRYRUN",
                    user.as_bytes(),
                    b"select",
                    db.to_string().as_bytes(),
                ],
                out,
            ),
            Self::ClientNoTouchOn => resp::encode(&[b"CLIENT", b"NO-TOUCH", b"ON"], out),
            Self::ReadOnly => resp::encode(&[b"READONLY"], out),
        }
    }
}

/// A request buffer zeroized on drop.
#[derive(Default)]
pub(crate) struct Request(pub(crate) Vec<u8>);

impl Drop for Request {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_arrays_of_bulk_strings() {
        let mut out = Vec::new();
        Cmd::Hello.encode(&mut out);
        assert_eq!(
            out,
            b"*4\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$7\r\nSETNAME\r\n$17\r\ndatabastion-agent\r\n"
        );
        // HELLO carries no credential (H2).
        assert!(!String::from_utf8_lossy(&out).contains("AUTH"));
        let mut out = Vec::new();
        Cmd::XRevRange(b"events:payments").encode(&mut out);
        assert!(out.ends_with(b"$5\r\nCOUNT\r\n$2\r\n16\r\n"));
        let mut out = Vec::new();
        Cmd::LRange(b"q").encode(&mut out);
        assert!(out.ends_with(b"$1\r\n0\r\n$2\r\n15\r\n"));
        assert_eq!(format!("{:?}", Cmd::Type(b"user:jane")), "TYPE");
        assert_eq!(
            format!(
                "{:?}",
                Cmd::Auth {
                    user: "u",
                    password: "SECRET"
                }
            ),
            "AUTH"
        );
    }
}
