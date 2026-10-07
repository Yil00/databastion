//! URL handling (ADR-0041 decisions 4 and 7, security review M2 and L2;
//! review of #138 M1 and L5).
//!
//! - [`strip_credentials`]: before a registry value is classified, every
//!   URL in it (any token holding `//`: `scheme://…` and protocol-relative
//!   `//…`) loses everything up to the **last** `@` (or `%40`) of the token
//!   (the userinfo, whatever characters the password holds: `/`, `?`,
//!   `#`, `:`, `%`), then its query string, fragment and `;` parameters
//!   (JDBC SQL Server `;password=…`, path parameters). A token without
//!   `//` loses everything up to its last `@` / `%40` when what precedes
//!   it holds `:`, `%3A`, `/`, `;` or `|` (`user:pass@host`, JDBC
//!   `scott/tiger@db`), then its query string and fragment, and its `;`
//!   parameters when it holds a `:` before them (`jdbc:…;password=…`).
//!   Over-stripping (a path holding `@`, a `?` of a regular expression
//!   `serviceId`) is accepted. The result is a zeroizing buffer. Residual
//!   forms are listed in the crate README.
//! - [`service_of`]: the audit record's `what` is reduced to the scheme and
//!   host of the first `http(s)://` URL it holds (searched without copying
//!   `what`), used only to select a registry entry; the ticket id, the
//!   userinfo, the path and the query string are dropped, and the host
//!   itself never leaves the agent. Only a literal `@` ends a userinfo; an
//!   authority holding `%` or `\`, or followed by an `@` before the next
//!   `/`, `?` or `#`, names no service (`*`).

use zeroize::Zeroizing;

/// Longest host kept, in bytes.
const MAX_HOST_BYTES: usize = 253;

/// Whether `b` ends a URL (blank or a delimiter that cannot be part of
/// one in logged text).
fn ends_url(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'`')
}

/// Index just after the last `@` or `%40` (any case) of `t`, or 0.
fn after_last_at(t: &str) -> usize {
    let b = t.as_bytes();
    let mut cut = 0;
    for (i, c) in b.iter().enumerate() {
        if *c == b'@' {
            cut = i + 1;
        } else if *c == b'%' && b.get(i + 1) == Some(&b'4') && b.get(i + 2) == Some(&b'0') {
            cut = i + 3;
        }
    }
    cut
}

/// Where the `//` of a URL starts in `t`, and its length: `//`, the
/// JSON-escaped `\/\/` or the percent-encoded `%2F%2F` (any case).
fn separator(t: &str) -> Option<(usize, usize)> {
    let b = t.as_bytes();
    (0..b.len()).find_map(|i| {
        let rest = b.get(i..)?;
        if rest.starts_with(b"//") {
            Some((i, 2))
        } else if rest.starts_with(b"\\/\\/") {
            Some((i, 4))
        } else if rest
            .get(..6)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"%2f%2f"))
        {
            Some((i, 6))
        } else {
            None
        }
    })
}

/// Index of the first `?`, `#`, `%3F` or `%23` (any case) of `t`, and of
/// the first `;` or `%3B` too with `params`.
fn query_start(t: &str, params: bool) -> usize {
    let b = t.as_bytes();
    (0..b.len())
        .find(|&i| {
            matches!(b.get(i), Some(b'?' | b'#'))
                || (params && b.get(i) == Some(&b';'))
                || b.get(i..i + 3).is_some_and(|w| {
                    w.eq_ignore_ascii_case(b"%3f")
                        || w.eq_ignore_ascii_case(b"%23")
                        || (params && w.eq_ignore_ascii_case(b"%3b"))
                })
        })
        .unwrap_or(b.len())
}

/// Whether the text before an `@` of a token without `//` is a userinfo
/// (or a JDBC `user/password`): it holds `:`, `%3A`, `/`, `;` or `|`. A
/// plain e-mail address's local part holds none of them.
fn looks_like_userinfo(head: &str) -> bool {
    head.contains([':', '/', ';', '|'])
        || head
            .as_bytes()
            .windows(3)
            .any(|w| w.eq_ignore_ascii_case(b"%3a"))
}

/// Appends one blank-free token, its URL credentials removed:
/// - with a `//` (any form): an `@` before it drops everything up to that
///   `@` (JDBC `thin:scott/tiger@//db`); after it, everything up to the
///   last `@` / `%40`, then the query, the fragment and the `;` parameters
///   (JDBC SQL Server `//db:1433;user=sa;password=…`);
/// - without one: an `@` preceded by a userinfo ([`looks_like_userinfo`]:
///   `user:pass@host`, `user%3Apass@host`, JDBC `scott/tiger@db:1521:SID`)
///   drops everything up to the last `@`; then the query and the fragment
///   go, and the `;` parameters when a `:` precedes them
///   (`jdbc:sqlserver:db;password=…`). A plain e-mail address (no
///   userinfo character before its `@`) is kept, so it can still be
///   classified.
fn push_token(out: &mut String, token: &str) {
    let Some((i, len)) = separator(token) else {
        let cut = after_last_at(token);
        let creds = cut > 0 && token.get(..cut).is_some_and(looks_like_userinfo);
        let rest = if creds {
            token.get(cut..).unwrap_or("")
        } else {
            token
        };
        let rest = rest.get(..query_start(rest, false)).unwrap_or("");
        let params = rest
            .find(';')
            .is_some_and(|semi| rest.get(..semi).is_some_and(|h| h.contains(':')));
        out.push_str(rest.get(..query_start(rest, params)).unwrap_or(""));
        return;
    };
    let head = token.get(..i).unwrap_or("");
    let head = head.get(after_last_at(head)..).unwrap_or("");
    out.push_str(head);
    out.push_str("//");
    let tail = token.get(i + len..).unwrap_or("");
    let tail = tail.get(after_last_at(tail)..).unwrap_or("");
    out.push_str(tail.get(..query_start(tail, true)).unwrap_or(""));
}

/// Removes the userinfo, query string and fragment of every URL in `s`
/// (see the module documentation). Text outside URLs is kept as is.
#[must_use]
pub fn strip_credentials(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut rest = s;
    while !rest.is_empty() {
        let start = rest
            .bytes()
            .position(|b| !ends_url(b))
            .unwrap_or(rest.len());
        let (delims, r) = rest.split_at(start);
        out.push_str(delims);
        let end = r.bytes().position(ends_url).unwrap_or(r.len());
        let (token, r) = r.split_at(end);
        push_token(&mut out, token);
        rest = r;
    }
    out
}

/// Scheme of a service URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

/// The scheme and host of a service URL (lowercase host, no userinfo,
/// no port). Used only to select a registry entry.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServiceHost {
    /// Scheme.
    pub scheme: Scheme,
    /// Host: a DNS name or an IP literal (`[…]` for IPv6).
    pub host: String,
}

impl std::fmt::Debug for ServiceHost {
    // The host is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceHost")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl ServiceHost {
    /// `scheme://host/`, the text matched against `serviceId` patterns.
    #[must_use]
    pub fn as_url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://{}/", self.host)
    }
}

fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > MAX_HOST_BYTES {
        return false;
    }
    if let Some(inner) = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    h.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with('.')
        && !h.starts_with('-')
}

/// The scheme and host of the first `http://` or `https://` URL in `what`
/// (case-insensitive scheme). `None` when there is none or its host is not
/// a plain DNS name or IP literal.
#[must_use]
pub fn service_of(what: &str) -> Option<ServiceHost> {
    let bytes = what.as_bytes();
    let find = |p: &[u8]| {
        bytes
            .windows(p.len())
            .position(|w| w.eq_ignore_ascii_case(p))
    };
    let (i, scheme, len) = [
        (&b"https://"[..], Scheme::Https),
        (&b"http://"[..], Scheme::Http),
    ]
    .iter()
    .filter_map(|(p, s)| find(p).map(|i| (i, *s, p.len())))
    .min_by_key(|(i, _, _)| *i)?;
    let tail = what.get(i + len..)?;
    // The authority ends at the first `/`, `?`, `#` (or a delimiter); the
    // host follows its last literal `@`. An `@` of the path or the query
    // is never read (an end user could otherwise choose the service); a
    // password holding `/` leaves garbage, which is not a valid host or
    // matches no service. Ambiguous forms name no service (review of #138
    // L1): an authority holding `%` (an encoded `@` or delimiter) or `\`,
    // or an `@` left after the authority before the next `/`, `?` or `#`
    // (a userinfo holding a delimiter such as `,` or `;`).
    let stop =
        |b: u8| matches!(b, b'/' | b'?' | b'#' | b',' | b';' | b')' | b'}' | b'|') || ends_url(b);
    let end = tail.bytes().position(stop).unwrap_or(tail.len());
    let authority = tail.get(..end)?;
    if authority.contains(['%', '\\']) {
        return None;
    }
    let rest = tail.get(end..)?;
    let next = rest
        .bytes()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    if rest.get(..next)?.contains('@') {
        return None;
    }
    let host_port = authority
        .rfind('@')
        .map_or(Some(authority), |at| authority.get(at + 1..))?;
    let host = if host_port.starts_with('[') {
        host_port.get(..=host_port.find(']')?)?
    } else {
        host_port.split(':').next()?
    };
    valid_host(host).then(|| ServiceHost {
        scheme,
        host: host.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_stripped_from_urls() {
        let cases = [
            ("https://app.example.org/x", "https://app.example.org/x"),
            (
                "https://user:hunter2-SECRET@app.example.org/x?token=abc&a=b#frag",
                "https://app.example.org/x",
            ),
            (
                "^https://.*\\.example\\.org/.*",
                "^https://.*\\.example\\.org/.*",
            ),
            (
                "see https://a@b.example.org?x=1 and ldap://u:p@dir/o?q then",
                "see https://b.example.org and ldap://dir/o then",
            ),
            ("no url here", "no url here"),
            (
                "https://svc:pa/ss@h.example.org/x",
                "https://h.example.org/x",
            ),
            (
                "https://svc:p?w#d@h.example.org/x?q",
                "https://h.example.org/x",
            ),
            ("//u:p@h.example.org/a", "//h.example.org/a"),
            ("https://u%3Ap%40h.example.org/a", "https://h.example.org/a"),
            ("https://u:p%40x@h.example.org/a", "https://h.example.org/a"),
            (
                "jdbc:oracle:thin:scott/tiger@//db.example.org:1521/svc",
                "//db.example.org:1521/svc",
            ),
            ("jdbc:oracle:thin:scott/tiger@db:1521:SID", "db:1521:SID"),
            ("svc:fake-pass@db.example.org", "db.example.org"),
            (
                "https:\\/\\/u:p@h.example.org\\/x?q",
                "https://h.example.org\\/x",
            ),
            (
                "https%3A%2f%2Fu%3Ap%40h.example.org%2Fx%3Fq",
                "https%3A//h.example.org%2Fx",
            ),
            (
                "contact jane.doe@example.org now",
                "contact jane.doe@example.org now",
            ),
            ("://@?#", "://"),
            ("é://é@é/é?é", "é://é/é"),
            // Review of #138 L-follow-ups: queries without `//`, `;`
            // parameters, other userinfo separators.
            ("svc:fake-pass@db.example.org?token=abc", "db.example.org"),
            (
                "jdbc:mysql:db.example.org?password=hunter2-SECRET",
                "jdbc:mysql:db.example.org",
            ),
            (
                "jdbc:sqlserver://db.example.org:1433;user=sa;password=hunter2-SECRET",
                "jdbc:sqlserver://db.example.org:1433",
            ),
            (
                "jdbc:sqlserver:db.example.org;password=hunter2-SECRET",
                "jdbc:sqlserver:db.example.org",
            ),
            (
                "https://h.example.org/app;jsessionid=FAKE0000",
                "https://h.example.org/app",
            ),
            ("https://u;p@h.example.org/a", "https://h.example.org/a"),
            ("u%3Ahunter2-SECRET@h.example.org", "h.example.org"),
            ("u;hunter2-SECRET@h.example.org", "h.example.org"),
            ("u|hunter2-SECRET@h.example.org", "h.example.org"),
            // Over-stripping accepted: a `;`-separated address list reads
            // as a userinfo.
            ("jane.doe@example.org;john.roe@example.org", "example.org"),
            (
                "jane.doe@example.org,john.roe@example.org",
                "jane.doe@example.org,john.roe@example.org",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(strip_credentials(input).as_str(), expected, "{input}");
        }
    }

    #[test]
    fn what_is_reduced_to_scheme_and_host() {
        let s = |w: &str| service_of(w).map(|h| h.as_url());
        assert_eq!(
            s("ST-1-FAKEfakeFAKE-cas01 for https://App.Example.org:8443/login?ticket=ST-2-x")
                .as_deref(),
            Some("https://app.example.org/")
        );
        assert_eq!(
            s("{service=http://u:hunter2-SECRET@intranet/path, principal=jdoe}").as_deref(),
            Some("http://intranet/")
        );
        assert_eq!(
            s("https://[2001:db8::1]:8443/x").as_deref(),
            Some("https://[2001:db8::1]/")
        );
        assert_ne!(
            s("ST-1 for https://svc:pa/ss@H.example.org/x").as_deref(),
            Some("https://h.example.org/")
        );
        // An `@` in the path or the query never chooses the host.
        for w in [
            "https://hr.example.org/app?login_hint=jane%40example.com",
            "https://hr.example.org/app?x=%40other.example.org",
            "https://hr.example.org/u@other.example.org/x",
            "https://hr.example.org#@other.example.org",
            "https://u:p@hr.example.org/x?y=@other.example.org",
        ] {
            assert_eq!(s(w).as_deref(), Some("https://hr.example.org/"), "{w}");
        }
        // Ambiguous authorities name no service (review of #138).
        for w in [
            "https://u%40evil.example.org@hr.example.org/",
            "https://evil.example.org%2F@hr.example.org/",
            "https://u\\@hr.example.org/",
            "https://u:p,w@hr.example.org/x",
            "https://u:p;w@hr.example.org/x",
            "https://u:p|w@hr.example.org/x",
        ] {
            assert_eq!(s(w), None, "{w}");
        }
        assert_eq!(s("TGT-9-FAKEfake-cas01"), None);
        assert_eq!(s("https://exa_mple.org/"), None);
        assert_eq!(s("https://"), None);
        assert_eq!(s("https://[zz]/"), None);
    }
}
